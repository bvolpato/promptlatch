import gzip
import io
import json
import os
import socket
import sqlite3
import stat
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from promptlatch.cli import app
from promptlatch.history import HistoryReader, HistoryStore
from promptlatch.security import load_private_token
from promptlatch.version import __version__
from tests.fixtures import PROVIDER_FIXTURES


def test_version_command() -> None:
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_version_option() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_init_defaults_to_openai(tmp_path) -> None:
    config = tmp_path / "config.yaml"

    result = CliRunner().invoke(app, ["init", "--config", str(config)])

    assert result.exit_code == 0
    data = config.read_text(encoding="utf-8")
    assert "default_base_url: https://api.openai.com/v1" in data
    assert "api_key: ${OPENAI_API_KEY}" in data
    assert yaml.safe_load(data)["redaction"]["rules"] == []
    assert stat.S_IMODE(config.stat().st_mode) == 0o600


def test_version_does_not_load_default_config(tmp_path) -> None:
    invalid_config = tmp_path / "invalid.yaml"
    invalid_config.write_text("[invalid", encoding="utf-8")
    env = os.environ | {"PROMPTLATCH_CONFIG": str(invalid_config)}

    result = subprocess.run(
        ["promptlatch", "version"],
        capture_output=True,
        check=False,
        env=env,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == __version__


@pytest.mark.parametrize("debug_requests", [False, True])
def test_serve_does_not_log_request_url_secrets(tmp_path, debug_requests: bool) -> None:
    query_token = "FixtureTokenOpaqueQuery0000000000000000"
    server_token = "FixtureTokenServerAuth0000000000000000"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "server": {
                    "host": "127.0.0.1",
                    "port": port,
                    "api_key": server_token,
                    "require_api_key": True,
                },
                "target": {"default_base_url": "https://example.invalid/v1"},
                "redaction": {"engine": "basic"},
                "observability": {
                    "database_path": str(tmp_path / "requests.sqlite3"),
                    "pricing_enabled": False,
                },
            }
        ),
        encoding="utf-8",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PROMPTLATCH_", "PROMPTCLOAK_"))
    }
    command = ["promptlatch", "serve", "--config", str(config)]
    if debug_requests:
        command.append("--debug-requests")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )

    try:
        health_url = f"http://127.0.0.1:{port}/healthz"
        deadline = time.monotonic() + 10
        while True:
            try:
                with urllib.request.urlopen(health_url, timeout=0.25) as response:
                    assert response.status == 200
                break
            except (OSError, urllib.error.URLError):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError("PromptLatch server did not start") from None
                time.sleep(0.05)

        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/models?api_key={query_token}",
            headers={"Authorization": "Bearer FixtureTokenWrongAuth000000000000000"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(request, timeout=2)
        assert exc_info.value.code == 401
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)

    assert query_token not in stdout + stderr


def test_encrypt_rules_is_idempotent(tmp_path) -> None:
    runner = CliRunner()
    config = tmp_path / "config.yaml"
    key_file = tmp_path / "key"
    assert runner.invoke(app, ["init", "--config", str(config)]).exit_code == 0

    first = runner.invoke(
        app,
        ["encrypt-rules", "--config", str(config), "--key-file", str(key_file)],
    )
    encrypted = yaml.safe_load(config.read_text(encoding="utf-8"))["redaction"]["encrypted_rules"]
    second = runner.invoke(
        app,
        ["encrypt-rules", "--config", str(config), "--key-file", str(key_file)],
    )

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert "already encrypted" in second.output
    assert (
        yaml.safe_load(config.read_text(encoding="utf-8"))["redaction"]["encrypted_rules"]
        == encrypted
    )
    assert stat.S_IMODE(config.stat().st_mode) == 0o600


def test_dashboard_token_creation_is_private_and_race_safe(tmp_path) -> None:
    token_file = tmp_path / "state" / "requests.sqlite3.dashboard-token"

    with ThreadPoolExecutor(max_workers=4) as executor:
        tokens = list(executor.map(load_private_token, [token_file] * 8))

    assert len(set(tokens)) == 1
    assert len(tokens[0]) == 43
    assert token_file.read_text(encoding="ascii").strip() == tokens[0]
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600


def test_dashboard_token_rejects_symlink_without_modifying_target(tmp_path) -> None:
    target = tmp_path / "other-file"
    target.write_text("private unrelated content", encoding="utf-8")
    token_file = tmp_path / "token"
    token_file.symlink_to(target)

    with pytest.raises(OSError):
        load_private_token(token_file)

    assert target.read_text(encoding="utf-8") == "private unrelated content"
    assert token_file.is_symlink()


def test_dashboard_token_rejects_public_permissions(tmp_path) -> None:
    token_file = tmp_path / "token"
    token = load_private_token(token_file)
    token_file.chmod(0o644)

    with pytest.raises(ValueError, match="private regular file"):
        load_private_token(token_file)

    assert token_file.read_text(encoding="ascii").strip() == token


@pytest.mark.parametrize("enable_with_flag", [False, True])
def test_serve_dashboard_uses_proxy_port(monkeypatch, tmp_path, enable_with_flag: bool) -> None:
    database = tmp_path / "requests.sqlite3"
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "server": {"api_key": "FixtureProxyKeyMustNotAuthenticateDashboard"},
                "observability": {
                    "database_path": str(database),
                    "dashboard_enabled": not enable_with_flag,
                },
            }
        ),
        encoding="utf-8",
    )
    calls = {}
    application = object()

    def create_app(settings):
        calls["settings"] = settings
        return application

    def run(app, **kwargs):
        calls["app"] = app
        calls.update(kwargs)

    monkeypatch.setattr("promptlatch.cli.create_app", create_app)
    monkeypatch.setattr("promptlatch.cli.uvicorn.run", run)

    arguments = ["serve", "--config", str(config), "--host", "::1", "--port", "8090"]
    if enable_with_flag:
        arguments.append("--dashboard")
    result = CliRunner().invoke(app, arguments)

    assert result.exit_code == 0, result.output
    assert calls["settings"].observability.database_path == database
    assert calls["settings"].observability.dashboard_enabled is True
    assert calls["app"] is application
    assert calls["host"] == "::1"
    assert calls["port"] == 8090
    assert calls["access_log"] is False
    assert "FixtureProxyKeyMustNotAuthenticateDashboard" not in result.output
    assert "http://[::1]:8090/" in result.output
    assert str(database) + ".dashboard-token" in result.output


def test_serve_without_dashboard_does_not_print_token_path(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr("promptlatch.cli.create_app", lambda settings: object())
    monkeypatch.setattr("promptlatch.cli.uvicorn.run", lambda app, **kwargs: None)

    result = CliRunner().invoke(app, ["serve", "--config", str(tmp_path / "missing.yaml")])

    assert result.exit_code == 0
    assert "Dashboard:" not in result.output
    assert "Token file:" not in result.output
    assert not (tmp_path / "promptlatch").exists()


def _write_cli_config(tmp_path, extra: dict | None = None):
    database = tmp_path / "state" / "requests.sqlite3"
    config = tmp_path / "config.yaml"
    payload = {
        "server": {"host": "127.0.0.1", "port": 8099},
        "redaction": {"engine": "basic", "redact_mode": "full"},
        "observability": {"database_path": str(database)},
    }
    if extra:
        for key, value in extra.items():
            if isinstance(value, dict) and isinstance(payload.get(key), dict):
                payload[key].update(value)
            else:
                payload[key] = value
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return config, database


def test_scan_supports_argument_stdin_file_mode_check_and_quiet(tmp_path, monkeypatch) -> None:
    runner = CliRunner()
    config, _ = _write_cli_config(
        tmp_path,
        {"redaction": {"tag_key": "fixture-hmac-tag-secret-key"}},
    )
    secret = PROVIDER_FIXTURES["openai_key"]
    sample = f"OPENAI_API_KEY={secret} and repeat {secret}"

    # Positional argument with --mode tagged
    tagged = runner.invoke(
        app,
        ["scan", sample, "--config", str(config), "--mode", "tagged"],
    )
    assert tagged.exit_code == 0, tagged.output
    assert secret not in tagged.output
    assert "[REDACTED:openai_key#" in tagged.output
    # Same secret gets identical HMAC tag
    parts = tagged.output.strip().split(" and repeat ")
    assert len(parts) == 2
    assert parts[0].endswith(parts[1])

    # Stdin via '-' and implicit piped stdin
    piped = runner.invoke(
        app,
        ["scan", "-", "--config", str(config), "--json"],
        input=sample,
    )
    assert piped.exit_code == 0, piped.output
    parsed = json.loads(piped.output)
    assert secret not in parsed["text"]
    assert parsed["stats"]["redactions"] == 2

    implicit_piped = runner.invoke(
        app,
        ["scan", "--config", str(config)],
        input="clean line without credentials",
    )
    assert implicit_piped.exit_code == 0
    assert implicit_piped.output.strip() == "clean line without credentials"

    # --file scanning + --check + --quiet
    env_file = tmp_path / "sample.env"
    env_file.write_text(sample, encoding="utf-8")

    detected_quiet = runner.invoke(
        app,
        ["scan", "--config", str(config), "--file", str(env_file), "--check", "--quiet"],
    )
    assert detected_quiet.exit_code == 1
    assert detected_quiet.output == ""

    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("no credentials here\n", encoding="utf-8")
    clean_check = runner.invoke(
        app,
        ["scan", "--config", str(config), "-f", str(clean_file), "--check", "-q"],
    )
    assert clean_check.exit_code == 0
    assert clean_check.output == ""

    # PROMPTLATCH_CONFIG honored when --config is omitted
    monkeypatch.setenv("PROMPTLATCH_CONFIG", str(config))
    env_cfg_scan = runner.invoke(app, ["scan", "--mode", "partial", sample])
    assert env_cfg_scan.exit_code == 0
    assert secret not in env_cfg_scan.output


def test_scan_validates_conflicting_missing_and_invalid_inputs(tmp_path, monkeypatch) -> None:
    runner = CliRunner()
    config, _ = _write_cli_config(tmp_path)
    sample_file = tmp_path / "note.txt"
    sample_file.write_text("hello", encoding="utf-8")

    both = runner.invoke(
        app,
        ["scan", "inline", "--file", str(sample_file), "--config", str(config)],
    )
    assert both.exit_code == 2

    quiet_json = runner.invoke(
        app,
        ["scan", "inline", "--quiet", "--json", "--config", str(config)],
    )
    assert quiet_json.exit_code == 2

    bad_utf8 = tmp_path / "binary.bin"
    bad_utf8.write_bytes(b"\xff\xfe\xfd" + PROVIDER_FIXTURES["openai_key"].encode("ascii"))
    invalid_file = runner.invoke(
        app,
        ["scan", "--file", str(bad_utf8), "--config", str(config)],
    )
    assert invalid_file.exit_code == 2
    assert PROVIDER_FIXTURES["openai_key"] not in invalid_file.output

    missing_file = runner.invoke(
        app,
        ["scan", "--file", str(tmp_path / "does-not-exist.txt"), "--config", str(config)],
    )
    assert missing_file.exit_code == 2

    class _InteractiveStdin(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(
        "promptlatch.cli._read_scan_input", __import__("promptlatch.cli").cli._read_scan_input
    )
    real_stdin = _InteractiveStdin("")
    monkeypatch.setattr("promptlatch.cli.sys.stdin", real_stdin)
    with pytest.raises(Exception, match="Provide TEXT"):
        __import__("promptlatch.cli").cli._read_scan_input(None, None)


@respx.mock
def test_doctor_preserves_legacy_keys_checks_live_proxy_and_strict_mode(tmp_path) -> None:
    runner = CliRunner()
    config, database = _write_cli_config(tmp_path, {"server": {"host": "0.0.0.0", "port": 18080}})

    respx.get("http://127.0.0.1:18080/healthz").mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "service": "promptlatch",
                "version": __version__,
                "redaction": True,
                "observability": {"enabled": True, "healthy": True},
                "client_shims": {"native_auth": True, "native_responses": True},
            },
        )
    )

    result = runner.invoke(app, ["doctor", "--config", str(config), "--strict"])
    assert result.exit_code == 0, result.output
    checks = json.loads(result.output)

    # Legacy keys preserved
    assert checks["config"] == str(config)
    assert checks["config_exists"] is True
    assert checks["target"] == "https://api.openai.com/v1"
    assert checks["redaction"] is True
    assert checks["engine"] == "basic"
    assert checks["responses_to_chat"] is False
    assert checks["telemetry"] is False

    # Enhanced diagnostic keys
    assert checks["version"] == __version__
    assert checks["redact_mode"] == "full"
    assert checks["observability_enabled"] is True
    assert checks["proxy"] == {
        "url": "http://127.0.0.1:18080",
        "checked": True,
        "reachable": True,
        "ok": True,
        "running_version": __version__,
        "version_match": True,
        "redaction": True,
        "observability_enabled": True,
        "observability_healthy": True,
        "client_shims": {"native_auth": True, "native_responses": True},
    }
    assert checks["storage"]["database_path"] == str(database)
    assert checks["storage"]["exists"] is False
    assert checks["storage"]["readable"] is True
    assert not database.parent.exists()


@respx.mock
def test_doctor_detects_version_drift_via_openapi_fallback_and_non_loopback_hosts(tmp_path) -> None:
    runner = CliRunner()
    config, _ = _write_cli_config(tmp_path, {"server": {"host": "127.0.0.1", "port": 18081}})

    # Simulate an older running PromptLatch without "version" in /healthz
    respx.get("http://127.0.0.1:18081/healthz").mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "service": "promptlatch",
                "redaction": True,
                "observability": {"enabled": True, "healthy": True},
            },
        )
    )
    respx.get("http://127.0.0.1:18081/openapi.json").mock(
        return_value=httpx.Response(
            200,
            json={"info": {"title": "PromptLatch", "version": "0.2.9"}},
        )
    )

    non_strict = runner.invoke(app, ["doctor", "--config", str(config)])
    assert non_strict.exit_code == 0
    drift_payload = json.loads(non_strict.output)
    assert drift_payload["proxy"]["running_version"] == "0.2.9"
    assert drift_payload["proxy"]["version_match"] is False

    strict_drift = runner.invoke(app, ["doctor", "--config", str(config), "--strict"])
    assert strict_drift.exit_code == 1

    # Observability intentionally disabled on both config and live proxy passes --strict
    disabled_obs_cfg, _ = _write_cli_config(
        tmp_path / "obs_off",
        {
            "server": {"host": "127.0.0.1", "port": 18082},
            "observability": {"enabled": False},
        },
    )
    respx.get("http://127.0.0.1:18082/healthz").mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "service": "promptlatch",
                "version": __version__,
                "redaction": True,
                "observability": {"enabled": False, "healthy": False},
            },
        )
    )
    strict_obs_off = runner.invoke(app, ["doctor", "--config", str(disabled_obs_cfg), "--strict"])
    assert strict_obs_off.exit_code == 0, strict_obs_off.output

    # Non-loopback bind host never triggers outbound HTTP probes
    respx.reset()
    remote_cfg, _ = _write_cli_config(
        tmp_path / "remote",
        {"server": {"host": "192.0.2.25", "port": 18083}},
    )
    remote_doc = runner.invoke(app, ["doctor", "--config", str(remote_cfg)])
    assert remote_doc.exit_code == 0
    remote_payload = json.loads(remote_doc.output)
    assert remote_payload["proxy"]["checked"] is False
    assert remote_payload["proxy"]["url"] is None
    assert not respx.calls

    remote_strict = runner.invoke(app, ["doctor", "--config", str(remote_cfg), "--strict"])
    assert remote_strict.exit_code == 1


@respx.mock
def test_doctor_handles_unreadable_storage_without_crashing(tmp_path) -> None:
    runner = CliRunner()
    config, database = _write_cli_config(tmp_path, {"server": {"host": "127.0.0.1", "port": 18084}})
    store = HistoryStore(database)
    store.start()
    store.close()
    database.parent.chmod(0o777)
    try:
        respx.get("http://127.0.0.1:18084/healthz").mock(
            return_value=httpx.Response(
                200,
                json={
                    "ok": True,
                    "service": "promptlatch",
                    "version": __version__,
                    "redaction": True,
                    "observability": {"enabled": True, "healthy": True},
                },
            )
        )
        result = runner.invoke(app, ["doctor", "--config", str(config)])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["storage"]["exists"] is True
        assert payload["storage"]["readable"] is False
        assert payload["storage"]["error"] == "PermissionError"

        strict_result = runner.invoke(app, ["doctor", "--config", str(config), "--strict"])
        assert strict_result.exit_code == 1
    finally:
        database.parent.chmod(0o700)


def _seed_history(database) -> None:
    now = time.time()
    store = HistoryStore(database)
    store.start()
    try:
        store.submit_start(
            {
                "request_id": "req-models",
                "thread_id": "th-models",
                "started_at": now - 30,
                "method": "GET",
                "path": "/v1/models",
                "provider": "openai",
                "usage_applicable": False,
                "redactions": 0,
                "rule_hits": {},
            }
        )
        store.submit_finish(
            "req-models",
            {
                "completed_at": now - 29.9,
                "outcome": "success",
                "status_code": 200,
                "duration_ms": 100.0,
            },
        )

        store.submit_start(
            {
                "request_id": "req-err",
                "thread_id": "th-1",
                "started_at": now - 20,
                "method": "POST",
                "path": "/v1/responses",
                "provider": "openai",
                "model": "gpt-5.4",
                "stream": False,
                "usage_applicable": True,
                "redactions": 1,
                "rule_hits": {"github_token": 1},
                "request_body": '{"input":"sensitive prompt body 1"}',
                "session_preview": "private session preview",
                "user_preview": "private user preview",
            }
        )
        store.submit_finish(
            "req-err",
            {
                "completed_at": now - 19.5,
                "outcome": "http_error",
                "status_code": 429,
                "duration_ms": 500.0,
                "upstream_error": {"message": "private error text"},
            },
        )

        store.submit_start(
            {
                "request_id": "req-ok",
                "thread_id": "th-1",
                "started_at": now - 10,
                "method": "POST",
                "path": "/v1/responses",
                "provider": "openai",
                "model": "gpt-5.4",
                "stream": True,
                "usage_applicable": True,
                "redactions": 2,
                "rule_hits": {"openai_api_key": 2},
                "request_body": '{"input":"sensitive prompt body 2"}',
                "session_preview": "private session preview 2",
                "user_preview": "private user preview 2",
                "assistant_preview": "private assistant preview 2",
            }
        )
        store.submit_finish(
            "req-ok",
            {
                "completed_at": now - 9.2,
                "outcome": "success",
                "status_code": 200,
                "duration_ms": 800.0,
                "ttft_ms": 120.0,
                "tps": 45.0,
                "input_tokens": 300,
                "cached_input_tokens": 100,
                "output_tokens": 150,
                "reasoning_tokens": 30,
                "total_tokens": 450,
                "cost_usd": 0.0042,
                "cost_source": "bundled",
            },
        )
    finally:
        store.close()


def test_stats_reports_human_and_json_without_creating_missing_db(tmp_path) -> None:
    runner = CliRunner()
    config, database = _write_cli_config(tmp_path)

    empty = runner.invoke(app, ["stats", "--config", str(config), "--days", "7"])
    assert empty.exit_code == 0, empty.output
    assert "Window: last 7 day(s)" in empty.output
    assert "Requests: 0" in empty.output
    assert not database.parent.exists()

    _seed_history(database)

    human = runner.invoke(app, ["stats", "--config", str(config), "--days", "14"])
    assert human.exit_code == 0, human.output
    assert "Window: last 14 day(s)" in human.output
    assert "Requests: 3 (2 ok, 1 errors, 0 cancelled, 0 interrupted, 0 active)" in human.output
    assert "Tokens: 450+ total (input 300, cached 100, output 150, reasoning 30)" in human.output
    assert "$0.0042 (1/2 inference requests priced)" in human.output
    assert "openai_api_key: 2" in human.output
    assert "github_token: 1" in human.output
    assert "openai/gpt-5.4: 2 req" in human.output
    assert "\u2014" not in human.output
    assert "private" not in human.output
    assert "sensitive prompt body" not in human.output

    as_json = runner.invoke(app, ["stats", "--config", str(config), "--days", "14", "--json"])
    assert as_json.exit_code == 0, as_json.output
    parsed = json.loads(as_json.output)
    assert parsed["days"] == 14
    assert parsed["totals"]["requests"] == 3
    assert parsed["totals"]["redactions"] == 3


def test_tail_filters_traffic_and_errors_and_strips_bodies_and_previews(tmp_path) -> None:
    runner = CliRunner()
    config, database = _write_cli_config(tmp_path)

    empty = runner.invoke(app, ["tail", "--config", str(config)])
    assert empty.exit_code == 0
    assert empty.output == ""
    assert not database.parent.exists()

    _seed_history(database)

    # Chronological order (oldest -> newest) and privacy hygiene
    human = runner.invoke(app, ["tail", "--config", str(config), "--limit", "10"])
    assert human.exit_code == 0, human.output
    lines = human.output.strip().splitlines()
    assert len(lines) == 3
    assert "GET /v1/models" in lines[0]
    assert "429 http_error" in lines[1]
    assert "200 success" in lines[2]
    assert "redactions=2 [openai_api_key]" in lines[2]
    assert "private" not in human.output
    assert "sensitive prompt body" not in human.output
    assert "\u2014" not in human.output

    # --traffic inference excludes GET /v1/models
    inference = runner.invoke(
        app,
        ["tail", "--config", str(config), "--traffic", "inference", "--json"],
    )
    assert inference.exit_code == 0, inference.output
    items = [json.loads(line) for line in inference.output.strip().splitlines()]
    assert [item["request_id"] for item in items] == ["req-err", "req-ok"]
    for item in items:
        assert "request_body" not in item
        assert "upstream_error" not in item
        assert "session_preview" not in item
        assert "user_preview" not in item
        assert "assistant_preview" not in item

    # --errors finds older error even with --limit 1 (when newest record is success)
    errors_only = runner.invoke(
        app,
        ["tail", "--config", str(config), "--errors", "--limit", "1", "--json"],
    )
    assert errors_only.exit_code == 0, errors_only.output
    err_items = [json.loads(line) for line in errors_only.output.strip().splitlines()]
    assert [item["request_id"] for item in err_items] == ["req-err"]


def test_tail_follow_emits_newly_completed_requests_once_and_exits_cleanly(
    tmp_path, monkeypatch
) -> None:
    runner = CliRunner()
    config, database = _write_cli_config(tmp_path)
    now = time.time()

    store = HistoryStore(database)
    store.start()
    try:
        # One already-completed request + one in-flight active request before follow starts
        store.submit_start(
            {
                "request_id": "req-initial",
                "thread_id": "th-follow",
                "started_at": now - 5,
                "method": "POST",
                "path": "/v1/responses",
                "provider": "openai",
                "model": "gpt-5.4",
            }
        )
        store.submit_finish(
            "req-initial",
            {"completed_at": now - 4.5, "outcome": "success", "status_code": 200},
        )
        store.submit_start(
            {
                "request_id": "req-inflight",
                "thread_id": "th-follow",
                "started_at": now - 2,
                "method": "POST",
                "path": "/v1/responses",
                "provider": "anthropic",
                "model": "claude-sonnet-4-6",
            }
        )
        store._queue.join()

        step = 0

        def fake_sleep(_seconds: float) -> None:
            nonlocal step
            step += 1
            if step == 1:
                # Start and finish a fast request before the older in-flight request completes
                store.submit_start(
                    {
                        "request_id": "req-fast",
                        "thread_id": "th-follow",
                        "started_at": now - 1,
                        "method": "POST",
                        "path": "/v1/messages",
                        "provider": "anthropic",
                        "model": "claude-haiku-4-5",
                    }
                )
                store.submit_finish(
                    "req-fast",
                    {"completed_at": now - 0.8, "outcome": "success", "status_code": 200},
                )
                store._queue.join()
            elif step == 2:
                # Now finish the older in-flight request; INSERT OR REPLACE gives it a new rowid
                store.submit_finish(
                    "req-inflight",
                    {
                        "completed_at": now,
                        "outcome": "success",
                        "status_code": 200,
                        "total_tokens": 128,
                    },
                )
                store._queue.join()
            else:
                raise KeyboardInterrupt

        monkeypatch.setattr("promptlatch.cli.time.sleep", fake_sleep)

        result = runner.invoke(
            app,
            ["tail", "--config", str(config), "--follow", "--interval", "0.2", "--json"],
        )
        assert result.exit_code == 0, result.output
        emitted = [json.loads(line) for line in result.output.strip().splitlines()]
        assert [item["request_id"] for item in emitted] == [
            "req-initial",
            "req-fast",
            "req-inflight",
        ]
        assert all(item["outcome"] == "success" for item in emitted)
        assert emitted[2]["total_tokens"] == 128
    finally:
        store.close()


def test_scan_rejects_surrogateescape_stdin_directory_and_disabled_redaction_check(
    tmp_path, monkeypatch
) -> None:
    runner = CliRunner()
    config, _ = _write_cli_config(tmp_path)
    secret = PROVIDER_FIXTURES["openai_key"]

    # --file - reads stdin
    stdin_via_flag = runner.invoke(
        app,
        ["scan", "--file", "-", "--config", str(config)],
        input=f"key={secret}",
    )
    assert stdin_via_flag.exit_code == 0, stdin_via_flag.output
    assert secret not in stdin_via_flag.output
    assert "[REDACTED_SECRET]" in stdin_via_flag.output

    # Binary stdin (including surrogateescape-wrapped stream as under LC_ALL=POSIX) fails closed
    binary_payload = b"\xff\xfe" + secret.encode("ascii")
    raw_buf = io.BytesIO(binary_payload)
    surrogate_stdin = io.TextIOWrapper(raw_buf, encoding="ascii", errors="surrogateescape")
    monkeypatch.setattr("promptlatch.cli.sys.stdin", surrogate_stdin)
    with pytest.raises(Exception, match="not valid UTF-8"):
        __import__("promptlatch.cli").cli._read_scan_input("-", None)

    # Fallback text stream without .buffer rejects lone surrogates too
    class _SurrogateStringStream:
        def isatty(self) -> bool:
            return False

        def read(self) -> str:
            return "\udcff" + secret

    monkeypatch.setattr("promptlatch.cli.sys.stdin", _SurrogateStringStream())
    with pytest.raises(Exception, match="not valid UTF-8"):
        __import__("promptlatch.cli").cli._read_scan_input(None, None)

    # Directory path passed to --file fails cleanly with exit code 2
    dir_res = runner.invoke(app, ["scan", "--file", str(tmp_path), "--config", str(config)])
    assert dir_res.exit_code == 2

    # --check fails closed when redaction.enabled is false
    disabled_cfg, _ = _write_cli_config(
        tmp_path / "disabled",
        {"redaction": {"enabled": False}},
    )
    disabled_check = runner.invoke(
        app,
        ["scan", f"OPENAI_API_KEY={secret}", "--config", str(disabled_cfg), "--check", "--quiet"],
    )
    assert disabled_check.exit_code == 2
    assert secret not in disabled_check.output


@respx.mock
def test_doctor_hardens_ipv6_scope_injection_compressed_oversized_and_nested_responses(
    tmp_path,
) -> None:
    runner = CliRunner()

    # IPv6 %scope_id authority injection must never produce an outbound probe
    scoped_cfg, _ = _write_cli_config(
        tmp_path / "scoped",
        {"server": {"host": "::1%]@198.51.100.1:80#", "port": 18090}},
    )
    scoped_res = runner.invoke(app, ["doctor", "--config", str(scoped_cfg)])
    assert scoped_res.exit_code == 0, scoped_res.output
    scoped_json = json.loads(scoped_res.output)
    assert scoped_json["proxy"]["checked"] is False
    assert scoped_json["proxy"]["url"] is None
    assert not respx.calls

    # IPv4-mapped loopback ::ffff:127.0.0.1 is allowed while ::ffff:192.0.2.1 is blocked
    mapped_remote_cfg, _ = _write_cli_config(
        tmp_path / "mapped_remote",
        {"server": {"host": "::ffff:192.0.2.1", "port": 18090}},
    )
    mapped_remote = json.loads(
        runner.invoke(app, ["doctor", "--config", str(mapped_remote_cfg)]).output
    )
    assert mapped_remote["proxy"]["checked"] is False
    assert not respx.calls

    # 1) HTTP 302 redirect not followed and treated as not ok
    # 2) Non-promptlatch service rejected
    # 3) Content-Encoding: gzip rejected without decompressing
    # 4) Oversized >64 KiB body rejected
    # 5) Deeply nested JSON (RecursionError) handled without crashing
    probe_cases = [
        httpx.Response(302, headers={"Location": "http://198.51.100.1/healthz"}, json={"ok": True}),
        httpx.Response(200, json={"ok": True, "service": "other-service", "version": __version__}),
        httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            content=gzip.compress(b'{"ok":true,"service":"promptlatch"}'),
        ),
        httpx.Response(200, content=b'{"pad":"' + (b"a" * 70000) + b'"}'),
        httpx.Response(200, content=(b"[" * 4096) + (b"]" * 4096)),
    ]
    for index, mocked_response in enumerate(probe_cases):
        port = 18100 + index
        cfg, _ = _write_cli_config(
            tmp_path / f"case_{index}",
            {"server": {"host": "127.0.0.1", "port": port}},
        )
        respx.get(f"http://127.0.0.1:{port}/healthz").mock(return_value=mocked_response)
        res = runner.invoke(app, ["doctor", "--config", str(cfg)])
        assert res.exit_code == 0, res.output
        body = json.loads(res.output)
        assert body["proxy"]["reachable"] is True
        assert body["proxy"]["ok"] is False

        strict_res = runner.invoke(app, ["doctor", "--config", str(cfg), "--strict"])
        assert strict_res.exit_code == 1


@respx.mock
@pytest.mark.parametrize(
    "health_payload",
    [
        # Missing redaction field -> redaction is None -> --strict must fail closed
        {
            "ok": True,
            "service": "promptlatch",
            "version": __version__,
            "observability": {"enabled": True, "healthy": True},
        },
        # redaction: False -> --strict fails
        {
            "ok": True,
            "service": "promptlatch",
            "version": __version__,
            "redaction": False,
            "observability": {"enabled": True, "healthy": True},
        },
        # Missing version and /openapi.json unavailable -> version_match is None -> --strict fails
        {
            "ok": True,
            "service": "promptlatch",
            "redaction": True,
            "observability": {"enabled": True, "healthy": True},
        },
        # Live observability unhealthy -> --strict fails
        {
            "ok": True,
            "service": "promptlatch",
            "version": __version__,
            "redaction": True,
            "observability": {"enabled": True, "healthy": False},
        },
    ],
)
def test_doctor_strict_fails_closed_on_missing_or_unhealthy_proxy_fields(
    tmp_path, health_payload
) -> None:
    runner = CliRunner()
    cfg, _ = _write_cli_config(tmp_path, {"server": {"host": "127.0.0.1", "port": 18120}})
    respx.get("http://127.0.0.1:18120/healthz").mock(
        return_value=httpx.Response(200, json=health_payload)
    )
    respx.get("http://127.0.0.1:18120/openapi.json").mock(
        return_value=httpx.Response(404, json={"detail": "not found"})
    )

    strict_res = runner.invoke(app, ["doctor", "--config", str(cfg), "--strict"])
    assert strict_res.exit_code == 1


def test_corrupt_sqlite_json_and_headers_do_not_crash_or_leak_keys(tmp_path) -> None:
    runner = CliRunner()
    config, database = _write_cli_config(tmp_path)
    _seed_history(database)

    stats_db = database.with_name(database.name + ".stats.sqlite3")
    leak_marker = "unexpected_corrupt_marker_xyz"
    with sqlite3.connect(stats_db) as conn:
        conn.execute(
            "UPDATE lifetime SET metrics=?",
            (json.dumps({leak_marker: "bad-non-numeric-type", "requests": "not-a-number"}),),
        )
        conn.execute(
            "INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)",
            ("readable", "injected"),
        )
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE requests SET record='[\"not_a_dict\"]'")

    doc = runner.invoke(app, ["doctor", "--config", str(config)])
    assert doc.exit_code == 0, doc.output
    doc_json = json.loads(doc.output)
    assert doc_json["storage"]["readable"] is False
    assert leak_marker not in doc.output

    stats_res = runner.invoke(app, ["stats", "--config", str(config)])
    assert stats_res.exit_code == 1
    assert leak_marker not in stats_res.output

    tail_res = runner.invoke(app, ["tail", "--config", str(config)])
    assert tail_res.exit_code == 1
    assert "not_a_dict" not in tail_res.output


def test_tail_never_reads_legacy_request_body_and_follow_handles_reprice_burst_reset_and_busy(
    tmp_path, monkeypatch
) -> None:
    runner = CliRunner()
    config, database = _write_cli_config(tmp_path)
    now = time.time()

    store = HistoryStore(database)
    store.start()
    try:
        # Insert legacy record without PREVIEW_FIELDS and with request_body
        store.submit_start(
            {
                "request_id": "req-legacy",
                "thread_id": "th-legacy",
                "started_at": now - 10,
                "method": "POST",
                "path": "/v1/responses",
                "provider": "chatgpt",
                "model": "gpt-5.4",
                "usage_applicable": True,
                "request_body": (
                    '{"input":[{"role":"user","content":"legacy body must stay unread"}]}'
                ),
            }
        )
        store.submit_finish(
            "req-legacy",
            {
                "completed_at": now - 9.5,
                "outcome": "success",
                "status_code": 200,
                "input_tokens": 100,
                "output_tokens": 50,
                "total_tokens": 150,
            },
        )
        store._queue.join()
    finally:
        store.close()

    # One-shot tail ignores legacy request_body and never computes legacy previews
    initial = runner.invoke(app, ["tail", "--config", str(config), "--json"])
    assert initial.exit_code == 0, initial.output
    assert "legacy body must stay unread" not in initial.output
    legacy_row = json.loads(initial.output.strip())
    assert legacy_row["request_id"] == "req-legacy"
    assert "user_preview" not in legacy_row

    # Follow mode: test reprice UPDATE non-duplication, >200 burst has_more,
    # transient OperationalError("database is locked"), and full DB reset.
    store = HistoryStore(database)
    store.start()
    real_tail = HistoryReader.tail
    injected_busy = False

    def flaky_tail(self, *args, **kwargs):
        nonlocal injected_busy
        if kwargs.get("after_rowid") is not None and not injected_busy:
            injected_busy = True
            raise sqlite3.OperationalError("database is locked")
        return real_tail(self, *args, **kwargs)

    monkeypatch.setattr("promptlatch.history.HistoryReader.tail", flaky_tail)

    step = 0

    def fake_sleep(_seconds: float) -> None:
        nonlocal step, store
        step += 1
        if step == 1:
            # Poll 1 hits transient sqlite busy error and retries next tick
            return
        if step == 2:
            # Background reprice UPDATE must not re-emit req-legacy; also insert 205 burst rows
            assert (
                store.submit_reprice(
                    "req-legacy",
                    {
                        "cost_usd": 0.001,
                        "cost_source": "litellm_api_equivalent",
                        "pricing_model": "gpt-5.4",
                        "pricing_rates": {"scope": "text_tokens"},
                    },
                )
                is True
            )
            for idx in range(205):
                rid = f"req-burst-{idx:03d}"
                store.submit_start(
                    {
                        "request_id": rid,
                        "thread_id": "th-burst",
                        "started_at": now + idx * 0.001,
                        "method": "POST",
                        "path": "/v1/responses",
                        "provider": "openai",
                        "model": "gpt-5.4",
                    }
                )
                store.submit_finish(
                    rid,
                    {
                        "completed_at": now + idx * 0.001 + 0.0005,
                        "outcome": "success",
                        "status_code": 200,
                    },
                )
            store._queue.join()
        elif step == 3:
            # Recreate DB file from scratch and finish 2 new requests (max_rowid=4)
            store.close()
            for suffix in ("", ".stats.sqlite3", ".lock"):
                candidate = database.with_name(database.name + suffix) if suffix else database
                if candidate.exists():
                    candidate.unlink()
            store = HistoryStore(database)
            store.start()
            for idx in (1, 2):
                rid = f"req-after-recreate-{idx}"
                store.submit_start(
                    {
                        "request_id": rid,
                        "thread_id": "th-reset",
                        "started_at": now + 10 + idx,
                        "method": "POST",
                        "path": "/v1/responses",
                        "provider": "openai",
                        "model": "gpt-5.4",
                    }
                )
                store.submit_finish(
                    rid,
                    {"completed_at": now + 10.5 + idx, "outcome": "success", "status_code": 200},
                )
            store._queue.join()
        else:
            raise KeyboardInterrupt

    monkeypatch.setattr("promptlatch.cli.time.sleep", fake_sleep)
    try:
        follow_res = runner.invoke(
            app,
            [
                "tail",
                "--config",
                str(config),
                "--follow",
                "--limit",
                "5",
                "--interval",
                "0.2",
                "--json",
            ],
        )
        assert follow_res.exit_code == 0, follow_res.output
        rows = [json.loads(line) for line in follow_res.output.strip().splitlines()]
        ids = [row["request_id"] for row in rows]
        assert ids[0] == "req-legacy"
        assert ids.count("req-legacy") == 1
        assert len([rid for rid in ids if rid.startswith("req-burst-")]) == 205
        assert ids[-2:] == ["req-after-recreate-1", "req-after-recreate-2"]
    finally:
        store.close()


def test_tail_follow_does_not_replay_surviving_history_when_slow_max_rowid_is_pruned(
    tmp_path, monkeypatch
) -> None:
    runner = CliRunner()
    config, database = _write_cli_config(
        tmp_path,
        {
            "observability": {
                "max_database_bytes": 1024 * 1024,
                "max_body_bytes": 32768,
            }
        },
    )
    store = HistoryStore(database, max_database_bytes=1024 * 1024, max_body_bytes=32768)
    store.start()
    try:
        # Start req-slow early, finish 49 fast requests, then finish req-slow last
        # so req-slow takes max_rowid=100 while having the oldest started_at.
        body_6k = '{"input":"' + ("x" * 6000) + '"}'
        store.submit_start(
            {
                "request_id": "req-slow",
                "thread_id": "th-slow",
                "started_at": 100.0,
                "method": "POST",
                "path": "/v1/responses",
                "provider": "openai",
                "model": "gpt-5.4",
                "request_body": body_6k,
            }
        )
        for idx in range(1, 50):
            rid = f"req-fast-{idx:03d}"
            store.submit_start(
                {
                    "request_id": rid,
                    "thread_id": "th-fast",
                    "started_at": 100.0 + idx,
                    "method": "POST",
                    "path": "/v1/responses",
                    "provider": "openai",
                    "model": "gpt-5.4",
                    "request_body": body_6k,
                }
            )
            store.submit_finish(
                rid,
                {"completed_at": 100.5 + idx, "outcome": "success", "status_code": 200},
            )
        store.submit_finish(
            "req-slow",
            {"completed_at": 160.0, "outcome": "success", "status_code": 200},
        )
        store._queue.join()

        step = 0
        body_16k = '{"input":"' + ("y" * 16000) + '"}'

        def fake_sleep(_seconds: float) -> None:
            nonlocal step
            step += 1
            if step == 1:
                # Insert 25 large requests to trigger pruning of req-slow + early req-fast rows
                for idx in range(25):
                    rid = f"req-new-{idx:03d}"
                    store.submit_start(
                        {
                            "request_id": rid,
                            "thread_id": "th-new",
                            "started_at": 250.0 + idx,
                            "method": "POST",
                            "path": "/v1/responses",
                            "provider": "openai",
                            "model": "gpt-5.4",
                            "request_body": body_16k,
                        }
                    )
                    store.submit_finish(
                        rid,
                        {"completed_at": 250.5 + idx, "outcome": "success", "status_code": 200},
                    )
                store._queue.join()
            else:
                raise KeyboardInterrupt

        monkeypatch.setattr("promptlatch.cli.time.sleep", fake_sleep)
        res = runner.invoke(
            app,
            [
                "tail",
                "--config",
                str(config),
                "--follow",
                "--limit",
                "5",
                "--interval",
                "0.2",
                "--json",
            ],
        )
        assert res.exit_code == 0, res.output
        rows = [json.loads(line) for line in res.output.strip().splitlines()]
        ids = [row["request_id"] for row in rows]
        # Initial snapshot (--limit 5) emitted req-fast-045..049;
        # follow must emit ONLY req-new-000..024 and NEVER replay surviving req-fast-032..044!
        assert ids[:5] == [f"req-fast-{idx:03d}" for idx in range(45, 50)]
        assert ids[5:] == [f"req-new-{idx:03d}" for idx in range(25)]
    finally:
        store.close()
