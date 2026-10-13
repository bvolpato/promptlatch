from __future__ import annotations

import ipaddress
import json
import os
import re
import selectors
import shutil
import socket
import subprocess
import sys
import time
import tomllib
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit, urlunsplit

import httpx

_DEFAULT_PROXY_URL = "http://127.0.0.1:8000"
_PROXY_HEALTH_TIMEOUT = 0.8
_CODEX_PROVIDER = "promptlatch-official"
_CODEX_MINIMUM_VERSION = (0, 162, 1)
_CLAUDE_MINIMUM_VERSION = (2, 1, 220)
_CLI_VERSION_TIMEOUT = 3.0
_CODEX_CONFIG_TIMEOUT = 5.0
_CODEX_CONFIG_OUTPUT_LIMIT = 1024 * 1024
_CODEX_CHATGPT_TARGET = "https://chatgpt.com/backend-api/codex"
_CODEX_API_TARGET = "https://api.openai.com/v1"
_CLAUDE_TARGET = "https://api.anthropic.com"
_LOCAL_NO_PROXY = ("localhost", "127.0.0.1", "::1")
_RESERVED_CLAUDE_HEADERS = ("x-target-", "x-redact-")
_ROUTING_CONFIG_KEYS = {"model_provider", "model_providers", "openai_base_url"}
_BYPASS_FLAGS = ("--oss", "--local-provider", "--remote")
_CODEX_OPTIONS_WITH_VALUES = {
    "-a",
    "-c",
    "-i",
    "-m",
    "-p",
    "-s",
    "-C",
    "--ask-for-approval",
    "--add-dir",
    "--config",
    "--disable",
    "--enable",
    "--image",
    "--local-provider",
    "--model",
    "--profile",
    "--remote",
    "--remote-auth-token-env",
    "--sandbox",
    "--cd",
}
_CODEX_SHORT_VALUE_OPTIONS = ("-a", "-c", "-i", "-m", "-p", "-s", "-C")
_TRUE_VALUES = {"1", "true", "yes", "on"}


class LauncherError(Exception):
    """A safe, user-facing launcher error that contains no credentials."""


@dataclass(frozen=True)
class ProxyAddress:
    origin: str
    hostname: str


def codex_main() -> NoReturn:
    _main("codex", sys.argv[1:])


def claude_main() -> NoReturn:
    _main("claude", sys.argv[1:])


def _main(client: str, arguments: list[str]) -> NoReturn:
    program = f"{client}-latch"
    if _requests_latch_help(arguments):
        _print_help(program, client)
        raise SystemExit(0)

    try:
        environment = os.environ.copy()
        proxy = _proxy_address(environment.get("PROMPTLATCH_PROXY_URL", _DEFAULT_PROXY_URL))
        _merge_no_proxy(environment, proxy.hostname)
        executable = _resolve_cli(client, environment)

        if client == "codex":
            _reject_codex_routing_overrides(arguments)
            _reject_codex_unproxied_commands(arguments)
            _require_supported_cli_version(client, executable, environment)
        else:
            _reject_alternate_claude_providers(environment)
            _require_supported_cli_version(client, executable, environment)

        _require_ready_proxy(proxy.origin, client_name=client)
        if client == "codex":
            environment, cli_arguments, provider = _codex_invocation(
                executable, arguments, environment, proxy
            )
            _verify_codex_configuration(executable, arguments, environment, provider)
        else:
            environment = _claude_environment(environment, proxy)
            cli_arguments = arguments

        os.execvpe(executable, [executable, *cli_arguments], environment)
    except LauncherError as exc:
        print(f"{program}: error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


def _print_help(program: str, client: str) -> None:
    lines = [
        f"Usage: {program} [--latch-help] [arguments for {client}]",
        "",
        "Runs the official CLI through the local PromptLatch redaction proxy.",
        "The local proxy must be running with native CLI support enabled.",
        "",
        "Environment:",
        f"  PROMPTLATCH_PROXY_URL  Loopback proxy URL (default: {_DEFAULT_PROXY_URL})",
    ]
    if client == "codex":
        lines.extend(
            [
                "  PROMPTLATCH_CODEX_AUTH  auto, chatgpt, or api-key (default: auto)",
                "  PROMPTLATCH_CODEX_BIN   Codex executable override",
                "",
                "Auto mode uses saved Codex login type, then OPENAI_API_KEY when not logged in.",
                "Run codex-latch --latch-help to see this message without contacting the proxy.",
            ]
        )
    else:
        lines.extend(
            [
                "  PROMPTLATCH_CLAUDE_BIN  Claude executable override",
                "",
                "Native Claude Code login and API key environment variables are preserved.",
                "Run claude-latch --latch-help to see this message without contacting the proxy.",
            ]
        )
    print("\n".join(lines))


def _requests_latch_help(arguments: list[str]) -> bool:
    for argument in arguments:
        if argument == "--":
            return False
        if argument == "--latch-help":
            return True
    return False


def _proxy_address(value: str) -> ProxyAddress:
    if (
        not value
        or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)
        or "?" in value
        or "#" in value
        or "\\" in value
    ):
        raise LauncherError("PROMPTLATCH_PROXY_URL must be a loopback HTTP(S) root URL")

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise LauncherError("PROMPTLATCH_PROXY_URL must be a loopback HTTP(S) root URL") from None

    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.netloc
        or parts.username is not None
        or parts.password is not None
        or "@" in parts.netloc
        or parts.netloc.endswith(":")
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise LauncherError("PROMPTLATCH_PROXY_URL must be a loopback HTTP(S) root URL")

    hostname = parts.hostname
    if not hostname:
        raise LauncherError("PROMPTLATCH_PROXY_URL must be a loopback HTTP(S) root URL")
    hostname_lower = hostname.lower()
    if hostname_lower != "localhost":
        if "%" in hostname:
            raise LauncherError("PROMPTLATCH_PROXY_URL must use a loopback host")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            raise LauncherError(
                "PROMPTLATCH_PROXY_URL must use localhost or a loopback IP"
            ) from None
        if not address.is_loopback:
            raise LauncherError("PROMPTLATCH_PROXY_URL must use localhost or a loopback IP")

    if port is not None and not 1 <= port <= 65535:
        raise LauncherError("PROMPTLATCH_PROXY_URL must use a valid port")

    origin = urlunsplit((parts.scheme.lower(), parts.netloc, "", "", ""))
    return ProxyAddress(origin=origin, hostname=hostname_lower)


def _resolve_cli(client: str, environment: dict[str, str]) -> str:
    override_name = f"PROMPTLATCH_{client.upper()}_BIN"
    requested = environment.get(override_name) or client
    executable = shutil.which(requested, path=environment.get("PATH"))
    if not executable:
        raise LauncherError(
            f"{client} CLI was not found; install it or set {override_name} to its executable"
        )
    return executable


def _require_ready_proxy(proxy_url: str, *, client_name: str = "codex") -> None:
    health_url = f"{proxy_url}/healthz"
    try:
        with httpx.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=_PROXY_HEALTH_TIMEOUT,
        ) as http_client:
            response = http_client.get(health_url)
        health = response.json()
    except (httpx.HTTPError, ValueError):
        raise LauncherError(
            "local PromptLatch is unavailable or not ready; start it and verify /healthz"
        ) from None

    if response.status_code != 200 or not isinstance(health, dict):
        raise LauncherError(
            "local PromptLatch is unavailable or not ready; start it and verify /healthz"
        )
    shims = health.get("client_shims")
    if health.get("ok") is not True or health.get("redaction") is not True:
        raise LauncherError("local PromptLatch is not healthy with redaction enabled")
    if not isinstance(shims, dict):
        raise LauncherError(
            "local PromptLatch lacks native CLI support; update the proxy before using this shim"
        )
    if shims.get("native_auth") is not True:
        raise LauncherError(
            "local PromptLatch cannot forward native CLI auth; set "
            "target.forward_client_authorization: true and leave server.api_key and "
            "target.api_key unset, as shown in "
            "examples/promptlatch-agents.config.yaml"
        )
    if client_name == "codex" and shims.get("native_responses") is not True:
        raise LauncherError(
            "local PromptLatch lacks native Responses API support; update the proxy "
            "before using codex-latch"
        )


def _codex_invocation(
    executable: str,
    arguments: list[str],
    environment: dict[str, str],
    proxy: ProxyAddress,
) -> tuple[dict[str, str], list[str], dict[str, object]]:
    mode = environment.get("PROMPTLATCH_CODEX_AUTH", "auto").strip().lower()
    if mode not in {"auto", "chatgpt", "api-key"}:
        raise LauncherError("PROMPTLATCH_CODEX_AUTH must be auto, chatgpt, or api-key")

    has_api_key = bool(environment.get("OPENAI_API_KEY", "").strip())
    if mode == "auto":
        mode = _saved_codex_auth(executable, environment, has_api_key)
    elif mode == "api-key" and not has_api_key:
        saved = _saved_codex_auth(executable, environment, False)
        if saved != "api-key":
            raise LauncherError(
                "api-key mode requires OPENAI_API_KEY or a saved Codex API-key login"
            )

    if mode == "chatgpt":
        if environment.get("OPENAI_API_KEY", "").strip():
            environment.pop("OPENAI_API_KEY", None)
        target = _CODEX_CHATGPT_TARGET
        local_base_url = proxy.origin + "/backend-api/codex"
        provider_name = "OpenAI"
        requires_auth = True
        extra_fields: dict[str, str | bool] = {}
    else:
        target = _CODEX_API_TARGET
        local_base_url = proxy.origin + "/v1"
        provider_name = "PromptLatch official endpoint"
        if has_api_key:
            extra_fields = {"env_key": "OPENAI_API_KEY"}
            requires_auth = False
        else:
            extra_fields = {}
            requires_auth = True

    environment.pop("OPENAI_BASE_URL", None)
    provider: dict[str, object] = {
        "name": provider_name,
        "base_url": local_base_url,
        "wire_api": "responses",
        "supports_websockets": False,
        "requires_openai_auth": requires_auth,
        "http_headers": {"X-Target-Base-URL": target},
        **extra_fields,
    }
    provider_toml = f"model_providers.{_CODEX_PROVIDER}={_toml_inline_table(provider)}"
    cli_arguments = [
        "--no-daemon",
        "-c",
        f"model_provider={json.dumps(_CODEX_PROVIDER)}",
        "-c",
        provider_toml,
        "-c",
        "features.enable_request_compression=false",
        *arguments,
    ]
    return environment, cli_arguments, provider


def _require_supported_cli_version(
    client: str, executable: str, environment: dict[str, str]
) -> None:
    minimum = _CODEX_MINIMUM_VERSION if client == "codex" else _CLAUDE_MINIMUM_VERSION
    try:
        result = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_CLI_VERSION_TIMEOUT,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        result = None

    match = (
        re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", result.stdout)
        if result is not None and result.returncode == 0
        else None
    )
    version = tuple(map(int, match.groups())) if match else None
    if version is None or version < minimum:
        required = ".".join(map(str, minimum))
        label = "Codex" if client == "codex" else "Claude Code"
        raise LauncherError(
            f"{label} CLI {required} or newer is required; version could not be verified"
        )


def _verify_codex_configuration(
    executable: str,
    arguments: list[str],
    environment: dict[str, str],
    provider: dict[str, object],
) -> None:
    _reject_codex_profile_collisions(arguments, environment)
    cwd = _codex_effective_cwd(arguments)
    reader_arguments = _codex_config_reader_arguments(executable, arguments, provider)
    reader_environment = environment.copy()
    reader_environment.pop("OPENAI_API_KEY", None)
    reader_environment, offline_socket = _codex_offline_environment(reader_environment)
    try:
        try:
            config, requirements = _read_codex_config(reader_arguments, reader_environment, cwd)
            _validate_codex_effective_config(config, requirements, provider)
        except LauncherError:
            raise
        except (OSError, ValueError, TypeError, KeyError):
            raise _codex_config_error() from None
    finally:
        offline_socket.close()


def _codex_offline_environment(
    environment: dict[str, str],
) -> tuple[dict[str, str], socket.socket]:
    sink: socket.socket | None = None
    try:
        sink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sink.bind(("127.0.0.1", 0))
        port = sink.getsockname()[1]
    except OSError:
        if sink is not None:
            sink.close()
        raise _codex_config_error() from None

    offline_environment = environment.copy()
    proxy_url = f"http://127.0.0.1:{port}"
    for name in (
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        offline_environment[name] = proxy_url
    offline_environment["NO_PROXY"] = ""
    offline_environment["no_proxy"] = ""
    return offline_environment, sink


def _codex_config_reader_arguments(
    executable: str, arguments: list[str], provider: dict[str, object]
) -> list[str]:
    provider_override = f"model_providers.{_CODEX_PROVIDER}={_toml_inline_table(provider)}"
    result = [
        executable,
        "--no-daemon",
        "-c",
        f"model_provider={json.dumps(_CODEX_PROVIDER)}",
        "-c",
        provider_override,
        "-c",
        "features.enable_request_compression=false",
    ]
    result.extend(_codex_config_overrides(arguments))
    result.extend(("app-server", "--stdio"))
    return result


def _codex_config_overrides(arguments: list[str]) -> list[str]:
    result: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        if argument in {"-c", "--config"}:
            if index + 1 < len(arguments):
                result.extend((argument, arguments[index + 1]))
                index += 2
                continue
        elif argument.startswith("--config="):
            result.append(argument)
        elif argument.startswith("-c") and len(argument) > 2:
            result.extend(("-c", argument[2:].lstrip("=")))
        index += 1
    return result


def _read_codex_config(
    arguments: list[str], environment: dict[str, str], cwd: Path
) -> tuple[dict[str, object], dict[str, object] | None]:
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            env=environment,
            bufsize=0,
        )
        if process.stdin is None or process.stdout is None:
            raise _codex_config_error()

        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + _CODEX_CONFIG_TIMEOUT
        messages: dict[int, dict[str, object]] = {}
        output = bytearray()
        output_size = 0
        _write_json_rpc(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "promptlatch", "version": "1"},
                    "capabilities": {"experimentalApi": True},
                },
            },
        )

        while len(messages) < 3:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _codex_config_error()
            ready = selector.select(remaining)
            if not ready:
                if process.poll() is not None:
                    raise _codex_config_error()
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                raise _codex_config_error()
            output_size += len(chunk)
            if output_size > _CODEX_CONFIG_OUTPUT_LIMIT:
                raise _codex_config_error()
            output.extend(chunk)

            while b"\n" in output:
                line, _, rest = output.partition(b"\n")
                output = bytearray(rest)
                if not line.strip():
                    continue
                try:
                    message = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise _codex_config_error() from None
                if not isinstance(message, dict):
                    raise _codex_config_error()
                request_id = message.get("id")
                if request_id not in {1, 2, 3}:
                    continue
                if "error" in message or not isinstance(message.get("result"), dict):
                    raise _codex_config_error()
                messages[request_id] = message["result"]
                if request_id == 1:
                    _write_json_rpc(
                        process,
                        {"jsonrpc": "2.0", "method": "initialized", "params": {}},
                    )
                    _write_json_rpc(
                        process,
                        {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "config/read",
                            "params": {"includeLayers": False, "cwd": str(cwd)},
                        },
                    )
                    _write_json_rpc(
                        process,
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "configRequirements/read",
                            "params": {},
                        },
                    )

        config_result = messages[2].get("config")
        if "requirements" not in messages[3]:
            raise _codex_config_error()
        requirements_result = messages[3].get("requirements")
        if not isinstance(config_result, dict):
            raise _codex_config_error()
        if requirements_result is not None and not isinstance(requirements_result, dict):
            raise _codex_config_error()
        return config_result, requirements_result
    except LauncherError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        raise _codex_config_error() from None
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            try:
                if process.stdin is not None:
                    with suppress(OSError):
                        process.stdin.close()
                if process.poll() is None:
                    with suppress(OSError):
                        process.terminate()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        raise _codex_config_error() from None
            finally:
                if process.stdout is not None:
                    process.stdout.close()


def _write_json_rpc(process: subprocess.Popen[bytes], message: dict[str, object]) -> None:
    if process.stdin is None:
        raise _codex_config_error()
    try:
        process.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
        process.stdin.flush()
    except (BrokenPipeError, OSError):
        raise _codex_config_error() from None


def _validate_codex_effective_config(
    config: dict[str, object],
    requirements: dict[str, object] | None,
    expected_provider: dict[str, object],
) -> None:
    if config.get("model_provider") != _CODEX_PROVIDER:
        raise _codex_config_error()
    providers = config.get("model_providers")
    if not isinstance(providers, dict):
        raise _codex_config_error()
    provider = providers.get(_CODEX_PROVIDER)
    if not isinstance(provider, dict):
        raise _codex_config_error()
    _validate_codex_provider(provider, expected_provider)

    features = config.get("features")
    if not isinstance(features, dict) or features.get("enable_request_compression") is not False:
        raise _codex_config_error()
    for key in ("profile", "profiles"):
        if _profile_routes_away(config.get(key)):
            raise _codex_config_error()

    if requirements is None:
        return
    required_provider = requirements.get("modelProvider")
    if required_provider is not None and required_provider != _CODEX_PROVIDER:
        raise _codex_config_error()
    required_providers = requirements.get("modelProviders")
    if required_providers is None:
        required_providers = {}
    if not isinstance(required_providers, dict):
        raise _codex_config_error()
    required_definition = required_providers.get(_CODEX_PROVIDER)
    if required_definition is not None:
        if not isinstance(required_definition, dict):
            raise _codex_config_error()
        _validate_codex_provider(required_definition, expected_provider)


def _validate_codex_provider(provider: dict[str, object], expected: dict[str, object]) -> None:
    for field in (
        "name",
        "base_url",
        "wire_api",
        "supports_websockets",
        "requires_openai_auth",
        "http_headers",
    ):
        if provider.get(field) != expected.get(field):
            raise _codex_config_error()
    if provider.get("env_key") != expected.get("env_key"):
        raise _codex_config_error()
    for field in (
        "env_http_headers",
        "query_params",
        "experimental_bearer_token",
        "auth",
        "gateway_oauth",
        "aws",
        "model_catalog_url",
    ):
        if provider.get(field) not in (None, {}, ""):
            raise _codex_config_error()


def _profile_routes_away(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            key in _ROUTING_CONFIG_KEYS or _profile_routes_away(nested)
            for key, nested in value.items()
        )
    if isinstance(value, list):
        return any(_profile_routes_away(item) for item in value)
    return False


def _reject_codex_profile_collisions(arguments: list[str], environment: dict[str, str]) -> None:
    profile_name = _selected_codex_profile(arguments)
    if profile_name is None:
        return
    if not profile_name or Path(profile_name).name != profile_name:
        raise LauncherError("Codex profile name cannot be safely verified")
    codex_home = Path(environment.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    profile_path = codex_home / f"{profile_name}.config.toml"
    try:
        try:
            profile_stat = profile_path.stat()
        except FileNotFoundError:
            return
        if profile_stat.st_size > _CODEX_CONFIG_OUTPUT_LIMIT:
            raise LauncherError("Codex profile is too large to verify safely")
        profile = tomllib.loads(profile_path.read_text(encoding="utf-8"))
    except LauncherError:
        raise
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise LauncherError("selected Codex profile could not be verified safely") from None
    if _contains_reserved_codex_provider(profile):
        raise LauncherError(
            "selected Codex profile defines the reserved PromptLatch provider; "
            "remove that provider entry before using codex-latch"
        )


def _selected_codex_profile(arguments: list[str]) -> str | None:
    profile: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        if argument in {"-p", "--profile"}:
            if index + 1 < len(arguments):
                profile = arguments[index + 1]
                index += 2
                continue
        elif argument.startswith("--profile="):
            profile = argument.partition("=")[2]
        elif argument.startswith("-p") and len(argument) > 2:
            profile = argument[2:].lstrip("=")
        elif argument in _CODEX_OPTIONS_WITH_VALUES:
            index += 2
            continue
        elif argument.startswith(_CODEX_SHORT_VALUE_OPTIONS) and len(argument) > 2:
            index += 1
            continue
        index += 1
    return profile


def _contains_reserved_codex_provider(value: object) -> bool:
    if isinstance(value, dict):
        providers = value.get("model_providers")
        if isinstance(providers, dict) and _CODEX_PROVIDER in providers:
            return True
        return any(_contains_reserved_codex_provider(nested) for nested in value.values())
    if isinstance(value, list):
        return any(_contains_reserved_codex_provider(item) for item in value)
    return False


def _codex_effective_cwd(arguments: list[str]) -> Path:
    cwd = Path.cwd()
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        value: str | None = None
        if argument in {"-C", "--cd"} and index + 1 < len(arguments):
            value = arguments[index + 1]
            index += 1
        elif argument.startswith("--cd="):
            value = argument.partition("=")[2]
        elif argument.startswith("-C") and len(argument) > 2:
            value = argument[2:].lstrip("=")
        elif argument in _CODEX_OPTIONS_WITH_VALUES:
            index += 1
        elif argument.startswith(_CODEX_SHORT_VALUE_OPTIONS) and len(argument) > 2:
            pass
        if value is not None:
            candidate = Path(value).expanduser()
            cwd = candidate if candidate.is_absolute() else Path.cwd() / candidate
        index += 1
    try:
        return cwd.resolve()
    except OSError:
        raise LauncherError("Codex working directory could not be verified") from None


def _codex_config_error() -> LauncherError:
    return LauncherError(
        "could not verify Codex's effective PromptLatch configuration; check for "
        "conflicting Codex or managed settings"
    )


def _toml_inline_table(value: dict[str, object]) -> str:
    fields: list[str] = []
    for key, item in value.items():
        toml_key = key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else json.dumps(key)
        if isinstance(item, str):
            rendered = json.dumps(item)
        elif isinstance(item, bool):
            rendered = "true" if item else "false"
        elif isinstance(item, dict):
            rendered = _toml_inline_table(item)
        else:
            raise TypeError(f"unsupported TOML inline-table value: {type(item).__name__}")
        fields.append(f"{toml_key} = {rendered}")
    return "{ " + ", ".join(fields) + " }"


def _saved_codex_auth(executable: str, environment: dict[str, str], has_api_key: bool) -> str:
    try:
        result = subprocess.run(
            [executable, "login", "status"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=4.0,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        raise LauncherError(
            "could not determine saved Codex login; run `codex login status` "
            "and choose an auth mode"
        ) from None

    status = result.stdout.casefold()
    if re.search(r"logged\s+in\s+using\s+(?:a\s+|an\s+)?chatgpt", status):
        if result.returncode != 0:
            raise LauncherError(
                "could not determine saved Codex login; run `codex login status` "
                "and choose an auth mode"
            )
        return "chatgpt"
    if re.search(r"logged\s+in\s+using\s+(?:a\s+|an\s+)?api\s+key", status):
        if result.returncode != 0:
            raise LauncherError(
                "could not determine saved Codex login; run `codex login status` "
                "and choose an auth mode"
            )
        return "api-key"
    if re.search(r"not\s+logged\s+in|no\s+saved\s+login", status):
        if has_api_key:
            return "api-key"
        raise LauncherError(
            "Codex has no saved login or OPENAI_API_KEY; run `codex login` "
            "or set PROMPTLATCH_CODEX_AUTH"
        )
    raise LauncherError(
        "could not identify the saved Codex login type; run `codex login status` "
        "or set PROMPTLATCH_CODEX_AUTH"
    )


def _reject_codex_routing_overrides(arguments: list[str]) -> None:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return
        if any(argument == flag or argument.startswith(flag + "=") for flag in _BYPASS_FLAGS):
            raise LauncherError(f"{argument.split('=', 1)[0]} can bypass the PromptLatch proxy")

        config_value: str | None = None
        if argument in {"-c", "--config"}:
            if index + 1 < len(arguments):
                index += 1
                config_value = arguments[index]
        elif argument.startswith("--config="):
            config_value = argument.partition("=")[2]
        elif argument.startswith("-c") and len(argument) > 2:
            config_value = argument[2:].lstrip("=")
        if config_value is not None and _config_routes_away(config_value):
            raise LauncherError("Codex model provider or base URL overrides can bypass PromptLatch")
        index += 1


def _reject_codex_unproxied_commands(arguments: list[str]) -> None:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return
        if argument == "cloud":
            raise LauncherError(
                "Codex Cloud requests bypass the local proxy; "
                "run cloud commands without codex-latch"
            )

        option, separator, _ = argument.partition("=")
        if option in _CODEX_OPTIONS_WITH_VALUES:
            index += 1 if separator else 2
            continue
        if argument.startswith(_CODEX_SHORT_VALUE_OPTIONS) and len(argument) > 2:
            index += 1
            continue
        if argument.startswith("-"):
            index += 1
            continue
        # Codex treats the first positional token as either a command or prompt.
        return


def _config_routes_away(value: str) -> bool:
    try:
        parsed = tomllib.loads(value)
    except tomllib.TOMLDecodeError:
        first_assignment = re.match(r"\s*([A-Za-z0-9_.-]+)\s*=", value)
        if first_assignment is None:
            return False
        key = first_assignment.group(1).split(".", 1)[0]
        return key in _ROUTING_CONFIG_KEYS
    return any(key in parsed for key in _ROUTING_CONFIG_KEYS)


def _reject_alternate_claude_providers(environment: dict[str, str]) -> None:
    switches = (
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
    )
    active = [
        name for name in switches if environment.get(name, "").strip().lower() in _TRUE_VALUES
    ]
    if active:
        raise LauncherError(
            "Claude Code Bedrock, Vertex, or Foundry mode bypasses PromptLatch; unset "
            + ", ".join(active)
        )


def _claude_environment(environment: dict[str, str], proxy: ProxyAddress) -> dict[str, str]:
    existing_headers = environment.get("ANTHROPIC_CUSTOM_HEADERS", "")
    kept_headers = [
        line for line in existing_headers.splitlines() if not _is_reserved_claude_header(line)
    ]
    kept_headers.append(f"X-Target-Base-URL: {_CLAUDE_TARGET}")

    environment["ANTHROPIC_BASE_URL"] = proxy.origin
    environment["ANTHROPIC_CUSTOM_HEADERS"] = "\n".join(kept_headers)
    environment["CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST"] = "1"
    environment["CLAUDE_CODE_GZIP_REQUEST_BODIES"] = "0"
    environment["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    return environment


def _is_reserved_claude_header(line: str) -> bool:
    name, separator, _ = line.partition(":")
    if not separator:
        return False
    normalized = name.strip().lower()
    return normalized in {"x-target", "x-redact"} or any(
        normalized.startswith(prefix) for prefix in _RESERVED_CLAUDE_HEADERS
    )


def _merge_no_proxy(environment: dict[str, str], proxy_hostname: str) -> None:
    local_hosts: list[str] = list(_LOCAL_NO_PROXY)
    if proxy_hostname not in local_hosts:
        local_hosts.append(proxy_hostname)
    for variable in ("NO_PROXY", "no_proxy"):
        entries = [entry.strip() for entry in environment.get(variable, "").split(",")]
        entries = [entry for entry in entries if entry]
        present = {entry.casefold() for entry in entries}
        entries.extend(host for host in local_hosts if host.casefold() not in present)
        environment[variable] = ",".join(entries)
