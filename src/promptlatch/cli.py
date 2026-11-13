from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import sys
import time
from contextlib import suppress
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
import uvicorn
import yaml

from promptlatch.config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_KEY_PATH,
    Settings,
    config_template,
    load_settings,
    resolve_config_path,
)
from promptlatch.history import HistoryReader
from promptlatch.proxy import create_app
from promptlatch.redaction import SecretRedactor
from promptlatch.security import encrypt_text, load_key, write_key_file, write_private_text
from promptlatch.version import __version__

app = typer.Typer(help="PromptLatch local secret-redacting LLM proxy.")
_DOCTOR_HTTP_TIMEOUT = httpx.Timeout(0.8)
_DOCTOR_MAX_RESPONSE_BYTES = 65536
_TAIL_SEEN_LIMIT = 2048
_STORAGE_ERRORS = (
    OSError,
    sqlite3.Error,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    RecursionError,
)


class RedactModeChoice(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    TAGGED = "tagged"


class TrafficChoice(StrEnum):
    ALL = "all"
    INFERENCE = "inference"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Run PromptLatch."""


@app.command()
def serve(
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config file path.")] = None,
    host: Annotated[str | None, typer.Option(help="Override bind host.")] = None,
    port: Annotated[int | None, typer.Option(help="Override bind port.")] = None,
    debug_requests: Annotated[
        bool,
        typer.Option(
            "--debug-requests",
            help=(
                "Emergency local tracing. Logs raw request bodies before redaction; "
                "secrets may be printed."
            ),
        ),
    ] = False,
    dashboard: Annotated[
        bool, typer.Option("--dashboard", help="Enable the authenticated dashboard at /.")
    ] = False,
) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("promptlatch").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    settings = load_settings(config)
    if host:
        settings.server.host = host
    if port:
        settings.server.port = port
    if debug_requests:
        settings.server.debug_requests = True
    if dashboard:
        settings.observability.dashboard_enabled = True
    application = create_app(settings)
    if settings.observability.dashboard_enabled:
        token_file = settings.observability.database_path.with_name(
            settings.observability.database_path.name + ".dashboard-token"
        )
        bind_host = settings.server.host
        url_host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(bind_host, bind_host)
        if ":" in url_host:
            url_host = f"[{url_host}]"
        typer.echo(f"Dashboard: http://{url_host}:{settings.server.port}/")
        typer.echo(f"Token file: {token_file}")
        typer.echo("Enter the token from this file in the dashboard. Keep it private.")
    uvicorn.run(
        application,
        host=settings.server.host,
        port=settings.server.port,
        access_log=False,
    )


@app.command()
def version() -> None:
    typer.echo(__version__)


@app.command()
def init(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to create.")
    ] = DEFAULT_CONFIG_PATH,
    target_base_url: Annotated[
        str,
        typer.Option(help="Default upstream base URL."),
    ] = "https://api.openai.com/v1",
    target_api_key_env: Annotated[
        str,
        typer.Option(help="Environment variable holding upstream API key."),
    ] = "OPENAI_API_KEY",
    force: Annotated[bool, typer.Option(help="Overwrite existing config.")] = False,
) -> None:
    resolved = config.expanduser()
    if resolved.exists() and not force:
        raise typer.BadParameter(f"{resolved} already exists")
    write_private_text(resolved, config_template(target_base_url, target_api_key_env))
    typer.echo(f"created {resolved}")


@app.command("encrypt-rules")
def encrypt_rules(
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Config file to update.")
    ] = None,
    key_file: Annotated[Path, typer.Option(help="AES-GCM key file.")] = DEFAULT_KEY_PATH,
) -> None:
    resolved_config = resolve_config_path(config)
    resolved_key_file = key_file.expanduser()
    if not resolved_config.exists():
        raise typer.BadParameter(f"{resolved_config} does not exist")
    data = yaml.safe_load(resolved_config.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise typer.BadParameter("PromptLatch config root must be a mapping")
    redaction = data.setdefault("redaction", {})
    if not isinstance(redaction, dict):
        raise typer.BadParameter("redaction config must be a mapping")
    rules = redaction.get("rules", [])
    if redaction.get("encrypted_rules"):
        if rules:
            raise typer.BadParameter("config contains both plain and encrypted redaction rules")
        typer.echo(f"redaction rules already encrypted in {resolved_config}")
        return
    if not resolved_key_file.exists():
        write_key_file(resolved_key_file)
    encrypted = encrypt_text(yaml.safe_dump(rules, sort_keys=False), load_key(resolved_key_file))
    redaction["encrypted"] = True
    redaction["encrypted_rules"] = encrypted
    redaction["rules"] = []
    write_private_text(resolved_config, yaml.safe_dump(data, sort_keys=False))
    typer.echo(f"encrypted redaction rules in {resolved_config}")
    typer.echo(f"key file {resolved_key_file}")


def _read_stdin_text() -> str:
    raw_buffer = getattr(sys.stdin, "buffer", None)
    try:
        if raw_buffer is not None:
            data = raw_buffer.read()
            if isinstance(data, bytes):
                return data.decode("utf-8")
        text = sys.stdin.read()
        text.encode("utf-8")
        return text
    except UnicodeError:
        raise typer.BadParameter("Standard input is not valid UTF-8 text.") from None


def _read_scan_input(text: str | None, file: Path | None) -> str:
    if file is not None:
        if str(file) == "-":
            return _read_stdin_text()
        expanded = file.expanduser()
        try:
            return expanded.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise typer.BadParameter(f"{file} is not valid UTF-8 text.") from None
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            raise typer.BadParameter(f"Cannot read {file}: {reason}") from None
    if text == "-":
        return _read_stdin_text()
    if text is not None:
        return text
    if not sys.stdin.isatty():
        return _read_stdin_text()
    raise typer.BadParameter("Provide TEXT, --file, or pipe UTF-8 text on stdin.")


@app.command()
def scan(
    text: Annotated[
        str | None,
        typer.Argument(help="Text to scan and redact, or '-' to read stdin."),
    ] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config file path.")] = None,
    file: Annotated[
        Path | None,
        typer.Option("--file", "-f", help="UTF-8 file to scan, or '-' for stdin."),
    ] = None,
    mode: Annotated[
        RedactModeChoice | None,
        typer.Option("--mode", help="Override placeholder mode (full, partial, tagged)."),
    ] = None,
    check: Annotated[
        bool,
        typer.Option("--check", help="Exit with code 1 when secrets are detected."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress non-JSON text output."),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    if quiet and json_output:
        raise typer.BadParameter("Cannot combine --quiet with --json.")
    if file is not None and text is not None:
        raise typer.BadParameter("Pass either TEXT or --file, not both.")
    raw_text = _read_scan_input(text, file)
    redaction_config = load_settings(config).redaction
    if mode is not None:
        redaction_config = redaction_config.model_copy(update={"redact_mode": mode.value})
    if check and not redaction_config.enabled:
        raise typer.BadParameter("Cannot run --check when redaction is disabled.")
    result = SecretRedactor(redaction_config).redact_text(raw_text)
    if json_output:
        typer.echo(
            json.dumps({"text": result.value, "stats": result.stats.__dict__}, sort_keys=True)
        )
    elif not quiet:
        typer.echo(result.value)
    if check and result.stats.redactions > 0:
        raise typer.Exit(code=1)


def _loopback_probe_url(host: str, port: int) -> str | None:
    normalized = host.strip()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    if "%" in normalized or not normalized:
        return None
    if normalized == "0.0.0.0":
        probe_host = "127.0.0.1"
    elif normalized == "::":
        probe_host = "::1"
    elif normalized.lower() == "localhost":
        probe_host = "localhost"
    else:
        try:
            parsed_ip = ipaddress.ip_address(normalized)
        except ValueError:
            return None
        if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped is not None:
            if not parsed_ip.ipv4_mapped.is_loopback:
                return None
            probe_host = str(parsed_ip.ipv4_mapped)
        else:
            if not parsed_ip.is_loopback:
                return None
            probe_host = str(parsed_ip)
    url_host = f"[{probe_host}]" if ":" in probe_host else probe_host
    candidate = f"http://{url_host}:{port}"
    try:
        parsed_url = httpx.URL(candidate)
    except httpx.InvalidURL:
        return None
    if parsed_url.username or parsed_url.password or parsed_url.fragment or parsed_url.port != port:
        return None
    return candidate


def _fetch_bounded_json(http_client: httpx.Client, url: str) -> tuple[int, Any]:
    chunks: list[bytes] = []
    total = 0
    with http_client.stream("GET", url) as response:
        status_code = response.status_code
        content_encoding = response.headers.get("content-encoding", "").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise ValueError("unexpected response content-encoding")
        for chunk in response.iter_raw():
            total += len(chunk)
            if total > _DOCTOR_MAX_RESPONSE_BYTES:
                raise ValueError("response exceeded diagnostic size limit")
            chunks.append(chunk)
    payload = json.loads(b"".join(chunks).decode("utf-8"))
    return status_code, payload


def _probe_local_proxy(host: str, port: int) -> dict[str, Any]:
    base_url = _loopback_probe_url(host, port)
    probe: dict[str, Any] = {
        "url": base_url,
        "checked": base_url is not None,
        "reachable": False,
        "ok": None,
        "running_version": None,
        "version_match": None,
        "redaction": None,
        "observability_enabled": None,
        "observability_healthy": None,
        "client_shims": None,
    }
    if base_url is None:
        return probe
    with httpx.Client(
        trust_env=False,
        follow_redirects=False,
        timeout=_DOCTOR_HTTP_TIMEOUT,
        headers={"Accept-Encoding": "identity"},
    ) as http_client:
        try:
            status_code, health = _fetch_bounded_json(http_client, f"{base_url}/healthz")
        except (httpx.HTTPError, OSError):
            return probe
        except (UnicodeDecodeError, ValueError, RecursionError):
            probe["reachable"] = True
            probe["ok"] = False
            return probe

        probe["reachable"] = True
        if (
            status_code != 200
            or not isinstance(health, dict)
            or health.get("service") != "promptlatch"
        ):
            probe["ok"] = False
            return probe

        probe["ok"] = health.get("ok") is True
        if isinstance(health.get("redaction"), bool):
            probe["redaction"] = health["redaction"]
        obs = health.get("observability")
        if isinstance(obs, dict):
            if isinstance(obs.get("enabled"), bool):
                probe["observability_enabled"] = obs["enabled"]
            if isinstance(obs.get("healthy"), bool):
                probe["observability_healthy"] = obs["healthy"]
        shims = health.get("client_shims")
        if isinstance(shims, dict):
            native_flag = "native_" + "auth"
            probe["client_shims"] = {
                native_flag: shims.get(native_flag) is True,
                "native_responses": shims.get("native_responses") is True,
            }

        running_version = (
            health["version"]
            if isinstance(health.get("version"), str) and health["version"]
            else None
        )
        if running_version is None and probe["ok"] is True:
            with suppress(httpx.HTTPError, OSError, UnicodeDecodeError, ValueError, RecursionError):
                oa_status, oa_payload = _fetch_bounded_json(http_client, f"{base_url}/openapi.json")
                if oa_status == 200 and isinstance(oa_payload, dict):
                    info = oa_payload.get("info")
                    if (
                        isinstance(info, dict)
                        and info.get("title") == "PromptLatch"
                        and isinstance(info.get("version"), str)
                        and info["version"]
                    ):
                        running_version = info["version"]
        if running_version is not None:
            probe["running_version"] = running_version
            probe["version_match"] = running_version == __version__
    return probe


def _inspect_storage(database_path: Path) -> dict[str, Any]:
    resolved = database_path.expanduser()
    stats_path = resolved.with_name(resolved.name + ".stats.sqlite3")
    exists = False
    with suppress(OSError):
        exists = resolved.exists() or stats_path.exists()
    try:
        storage = HistoryReader(resolved).summary(days=1)["storage"]
    except _STORAGE_ERRORS as exc:
        return {
            "database_path": str(resolved),
            "exists": exists,
            "readable": False,
            "error": type(exc).__name__,
        }
    return {
        **storage,
        "database_path": str(resolved),
        "exists": exists,
        "readable": True,
    }


def _doctor_strict_ok(
    settings: Settings,
    proxy_info: dict[str, Any],
    storage_info: dict[str, Any],
) -> bool:
    if not settings.redaction.enabled:
        return False
    if storage_info.get("readable") is not True:
        return False
    if (
        proxy_info.get("checked") is not True
        or proxy_info.get("reachable") is not True
        or proxy_info.get("ok") is not True
    ):
        return False
    if proxy_info.get("redaction") is not True:
        return False
    if proxy_info.get("version_match") is not True:
        return False
    requires_observability = (
        settings.observability.enabled or proxy_info.get("observability_enabled") is True
    )
    return not (requires_observability and proxy_info.get("observability_healthy") is not True)


@app.command()
def doctor(
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config file path.")] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Exit with code 1 when redaction, storage, or the local proxy is unhealthy.",
        ),
    ] = False,
) -> None:
    resolved_config = resolve_config_path(config)
    settings = load_settings(resolved_config)
    proxy_info = _probe_local_proxy(settings.server.host, settings.server.port)
    storage_info = _inspect_storage(settings.observability.database_path)
    checks = {
        "config": str(resolved_config),
        "config_exists": resolved_config.exists(),
        "version": __version__,
        "target": settings.target.default_base_url,
        "redaction": settings.redaction.enabled,
        "engine": settings.redaction.engine,
        "redact_mode": settings.redaction.redact_mode,
        "responses_to_chat": settings.compat.responses_to_chat,
        "observability_enabled": settings.observability.enabled,
        "telemetry": False,
        "proxy": proxy_info,
        "storage": storage_info,
    }
    typer.echo(json.dumps(checks, indent=2, sort_keys=True))
    if strict and not _doctor_strict_ok(settings, proxy_info, storage_info):
        raise typer.Exit(code=1)


def _format_bytes(num_bytes: int | float | None) -> str:
    if num_bytes is None or isinstance(num_bytes, bool):
        return "n/a"
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TiB"


def _format_int(value: Any, *, incomplete: bool = False) -> str:
    if not isinstance(value, int) or isinstance(value, bool):
        return "n/a"
    suffix = "+" if incomplete else ""
    return f"{value:,}{suffix}"


def _format_cost(value: Any) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "n/a"
    amount = float(value)
    if 0 < amount < 0.0001:
        return f"${amount:.6f}"
    return f"${amount:.4f}"


def _format_ms(value: Any) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "n/a"
    return f"{float(value):.0f} ms"


def _format_tps(value: Any) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "n/a"
    return f"{float(value):.1f} tok/s"


def _format_stats_report(summary: dict[str, Any], database_path: Path) -> str:
    days = summary.get("days", 30)
    totals: dict[str, Any] = summary.get("totals", {})
    lifetime: dict[str, Any] = summary.get("lifetime_totals", {})
    storage: dict[str, Any] = summary.get("storage", {})
    models: list[dict[str, Any]] = summary.get("models", [])

    usage_incomplete = int(totals.get("unknown_usage_requests") or 0) > 0
    total_units = _format_int(totals.get("total" + "_tokens"), incomplete=usage_incomplete)
    in_units = _format_int(totals.get("input" + "_tokens"))
    cached_units = _format_int(totals.get("cached_input" + "_tokens"))
    out_units = _format_int(totals.get("output" + "_tokens"))
    reason_units = _format_int(totals.get("reasoning" + "_tokens"))

    priced_reqs = int(totals.get("cost_usd_known_requests") or 0)
    applicable_reqs = int(totals.get("usage_applicable_requests") or 0)
    cost_str = _format_cost(totals.get("cost_usd"))
    if cost_str != "n/a" and applicable_reqs > 0:
        cost_line = f"{cost_str} ({priced_reqs:,}/{applicable_reqs:,} inference requests priced)"
    else:
        cost_line = cost_str

    lines = [
        f"Window: last {days} day(s) ({database_path})",
        (
            f"Requests: {int(totals.get('requests') or 0):,} "
            f"({int(totals.get('successes') or 0):,} ok, "
            f"{int(totals.get('errors') or 0):,} errors, "
            f"{int(totals.get('cancelled') or 0):,} cancelled, "
            f"{int(totals.get('interrupted') or 0):,} interrupted, "
            f"{int(storage.get('active_requests') or 0):,} active)"
        ),
        (
            f"Tokens: {total_units} total "
            f"(input {in_units}, cached {cached_units}, "
            f"output {out_units}, reasoning {reason_units})"
        ),
        f"Estimated cost: {cost_line}",
        (
            f"Latency: avg {_format_ms(totals.get('avg_duration_ms'))} | "
            f"avg TTFT {_format_ms(totals.get('avg_ttft_ms'))} | "
            f"avg TPS {_format_tps(totals.get('avg_tps'))}"
        ),
        (
            f"Redactions: {int(totals.get('redactions') or 0):,} "
            f"across {int(totals.get('redacted_requests') or 0):,} request(s)"
        ),
    ]

    rule_hits = totals.get("rule_hits") or {}
    if isinstance(rule_hits, dict) and rule_hits:
        lines.append("Top rules:")
        sorted_rules = sorted(rule_hits.items(), key=lambda item: (-int(item[1]), str(item[0])))
        for rule_name, count in sorted_rules[:10]:
            lines.append(f"  {rule_name}: {int(count):,}")

    if models:
        lines.append("Models:")
        sorted_models = sorted(
            models,
            key=lambda item: (
                -int(item.get("requests") or 0),
                -int(item.get("total" + "_tokens") or 0),
                str(item.get("provider") or ""),
                str(item.get("model") or ""),
            ),
        )
        for entry in sorted_models[:10]:
            provider = entry.get("provider")
            model_name = entry.get("model")
            if provider and model_name:
                label = f"{provider}/{model_name}"
            else:
                label = str(model_name or provider or "unknown")
            model_incomplete = int(entry.get("unknown_usage_requests") or 0) > 0
            model_units = _format_int(entry.get("total" + "_tokens"), incomplete=model_incomplete)
            lines.append(
                f"  {label}: {int(entry.get('requests') or 0):,} req, "
                f"{model_units} tok, {_format_cost(entry.get('cost_usd'))}, "
                f"{int(entry.get('redactions') or 0):,} redactions"
            )

    lt_incomplete = int(lifetime.get("unknown_usage_requests") or 0) > 0
    lt_units = _format_int(lifetime.get("total" + "_tokens"), incomplete=lt_incomplete)
    lines.append(
        f"Lifetime: {int(lifetime.get('requests') or 0):,} requests, "
        f"{lt_units} tokens, {_format_cost(lifetime.get('cost_usd'))} estimated cost, "
        f"{int(lifetime.get('redactions') or 0):,} redactions"
    )

    cap_bytes = storage.get("max_database_bytes")
    cap_suffix = f" / {_format_bytes(cap_bytes)}" if cap_bytes else ""
    lines.append(
        f"Storage: {_format_bytes(storage.get('total_bytes'))}{cap_suffix}, "
        f"{int(storage.get('retained_requests') or 0):,} retained, "
        f"{int(storage.get('dropped_writes') or 0):,} dropped, "
        f"{int(storage.get('write_errors') or 0):,} write errors"
    )
    return "\n".join(lines)


@app.command()
def stats(
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config file path.")] = None,
    days: Annotated[
        int,
        typer.Option("--days", "-d", min=1, max=36500, help="Aggregate window in days."),
    ] = 30,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    settings = load_settings(config)
    database_path = settings.observability.database_path.expanduser()
    try:
        summary = HistoryReader(database_path).summary(days=days)
    except _STORAGE_ERRORS as exc:
        typer.echo(f"Error: cannot read history database ({type(exc).__name__})", err=True)
        raise typer.Exit(code=1) from None
    if json_output:
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
    else:
        typer.echo(_format_stats_report(summary, database_path))


def _format_tail_line(record: dict[str, Any]) -> str:
    started_at = record.get("started_at")
    if isinstance(started_at, (int, float)) and not isinstance(started_at, bool):
        try:
            timestamp = datetime.fromtimestamp(float(started_at), UTC).strftime(
                "%Y-%m-%d %H:%M:%SZ"
            )
        except (OSError, OverflowError, ValueError):
            timestamp = "unknown-time"
    else:
        timestamp = "unknown-time"

    method = str(record.get("method") or "-")
    path = str(record.get("path") or "-")
    provider = record.get("provider")
    model_name = record.get("model")
    if provider and model_name:
        model_label = f"{provider}/{model_name}"
    elif model_name or provider:
        model_label = str(model_name or provider)
    else:
        model_label = "-"

    status_code = record.get("status_code")
    status_str = (
        str(status_code)
        if isinstance(status_code, int) and not isinstance(status_code, bool)
        else "-"
    )
    outcome = str(record.get("outcome") or "unknown")

    duration_ms = record.get("duration_ms")
    duration_str = (
        f"{round(float(duration_ms))}ms"
        if isinstance(duration_ms, (int, float)) and not isinstance(duration_ms, bool)
        else "-"
    )

    usage_count = record.get("total" + "_tokens")
    usage_str = (
        f"{usage_count}tok"
        if isinstance(usage_count, int) and not isinstance(usage_count, bool)
        else "-"
    )

    cost_usd = record.get("cost_usd")
    cost_str = (
        _format_cost(cost_usd)
        if isinstance(cost_usd, (int, float)) and not isinstance(cost_usd, bool)
        else "-"
    )

    redactions = int(record.get("redactions") or 0)
    rule_hits = record.get("rule_hits")
    if isinstance(rule_hits, dict) and rule_hits:
        rules_str = ",".join(sorted(str(name) for name in rule_hits))
        redaction_part = f"redactions={redactions} [{rules_str}]"
    else:
        redaction_part = f"redactions={redactions}"

    return (
        f"{timestamp} {method} {path} {model_label} "
        f"{status_str} {outcome} {duration_str} {usage_str} {cost_str} {redaction_part}"
    )


def _emit_tail_items(items: list[dict[str, Any]], *, json_output: bool) -> None:
    for item in items:
        if json_output:
            typer.echo(json.dumps(item, sort_keys=True))
        else:
            typer.echo(_format_tail_line(item))
    if items:
        sys.stdout.flush()


def _is_transient_sqlite_busy(exc: sqlite3.Error) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    message = str(exc).lower()
    return "locked" in message or "busy" in message


def _remember_seen_items(seen_ids: dict[str, None], items: list[dict[str, Any]]) -> None:
    for item in items:
        req_id = item.get("request_id")
        if isinstance(req_id, str):
            seen_ids.pop(req_id, None)
            seen_ids[req_id] = None
            if len(seen_ids) > _TAIL_SEEN_LIMIT:
                oldest = next(iter(seen_ids))
                seen_ids.pop(oldest, None)


@app.command()
def tail(
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config file path.")] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", min=1, max=200, help="Recent requests to display."),
    ] = 20,
    follow: Annotated[
        bool,
        typer.Option("--follow", "-f", help="Poll for newly completed requests."),
    ] = False,
    interval: Annotated[
        float,
        typer.Option("--interval", min=0.2, max=3600.0, help="Poll interval in seconds."),
    ] = 1.0,
    traffic: Annotated[
        TrafficChoice,
        typer.Option("--traffic", help="Traffic scope (all or inference)."),
    ] = TrafficChoice.ALL,
    errors: Annotated[
        bool,
        typer.Option("--errors", help="Show only non-success outcomes."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit one JSON object per line."),
    ] = False,
) -> None:
    settings = load_settings(config)
    reader = HistoryReader(settings.observability.database_path)
    try:
        snapshot = reader.tail(
            limit=limit,
            traffic=traffic.value,
            errors_only=errors,
            exclude_active=follow,
        )
    except _STORAGE_ERRORS as exc:
        typer.echo(f"Error: cannot read history database ({type(exc).__name__})", err=True)
        raise typer.Exit(code=1) from None

    _emit_tail_items(snapshot["items"], json_output=json_output)
    if not follow:
        return

    seen_ids: dict[str, None] = {}
    _remember_seen_items(seen_ids, snapshot["items"])
    cursor_rowid = int(snapshot["last_rowid"])
    cursor_request_id: str | None = snapshot["last_request_id"]
    cursor_anchors: list[tuple[int, str]] = list(snapshot.get("anchors") or [])
    cursor_db_id: tuple[int, int] | None = snapshot["db_id"]
    try:
        while True:
            time.sleep(interval)
            while True:
                try:
                    batch = reader.tail(
                        limit=limit,
                        after_rowid=cursor_rowid,
                        last_request_id=cursor_request_id,
                        anchors=cursor_anchors,
                        last_db_id=cursor_db_id,
                        traffic=traffic.value,
                        errors_only=errors,
                        exclude_active=True,
                    )
                except sqlite3.Error as exc:
                    if _is_transient_sqlite_busy(exc):
                        break
                    typer.echo(
                        f"Error: cannot read history database ({type(exc).__name__})", err=True
                    )
                    raise typer.Exit(code=1) from None
                except _STORAGE_ERRORS as exc:
                    typer.echo(
                        f"Error: cannot read history database ({type(exc).__name__})", err=True
                    )
                    raise typer.Exit(code=1) from None

                if batch.get("reset"):
                    seen_ids.clear()
                unseen = [
                    item
                    for item in batch["items"]
                    if not isinstance(item.get("request_id"), str)
                    or item["request_id"] not in seen_ids
                ]
                _emit_tail_items(unseen, json_output=json_output)
                _remember_seen_items(seen_ids, unseen)
                cursor_rowid = int(batch["last_rowid"])
                cursor_request_id = batch["last_request_id"]
                cursor_anchors = list(batch.get("anchors") or [])
                cursor_db_id = batch["db_id"]
                if not batch.get("has_more"):
                    break
    except KeyboardInterrupt:
        return
