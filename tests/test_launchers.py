from __future__ import annotations

import socket
import subprocess
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
import respx

from promptlatch import launchers


def _healthy_response(**overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": True,
        "redaction": True,
        "client_shims": {"native_auth": True, "native_responses": True},
    }
    result.update(overrides)
    return result


def _clear_launcher_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    names = (
        "PROMPTLATCH_PROXY_URL",
        "PROMPTLATCH_CODEX_AUTH",
        "PROMPTLATCH_CODEX_BIN",
        "CODEX_HOME",
        "PROMPTLATCH_CLAUDE_BIN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_CUSTOM_HEADERS",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "NO_PROXY",
        "no_proxy",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CODEX_HOME", "/tmp/promptlatch-launchers-test-codex-home")


def _install_exec_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, list[str], dict[str, str]]]:
    calls: list[tuple[str, list[str], dict[str, str]]] = []

    def capture(executable: str, arguments: list[str], environment: dict[str, str]) -> None:
        calls.append((executable, arguments, environment))

    monkeypatch.setattr(launchers.os, "execvpe", capture)
    monkeypatch.setattr(launchers.shutil, "which", lambda _name, path=None: "/opt/bin/cli")
    monkeypatch.setattr(launchers, "_require_ready_proxy", lambda _url, **_kwargs: None)
    monkeypatch.setattr(launchers, "_require_supported_cli_version", lambda *_args: None)
    monkeypatch.setattr(launchers, "_verify_codex_configuration", lambda *_args: None)
    return calls


def _api_key_provider() -> dict[str, object]:
    _, _, provider = launchers._codex_invocation(
        "/opt/bin/codex",
        [],
        {"PROMPTLATCH_CODEX_AUTH": "api-key", "OPENAI_API_KEY": "fixture-key"},
        launchers.ProxyAddress("http://127.0.0.1:8000", "127.0.0.1"),
    )
    return provider


def _codex_effective_config(arguments: list[str]) -> dict[str, Any]:
    overrides = [arguments[index + 1] for index, item in enumerate(arguments[:-1]) if item == "-c"]
    return tomllib.loads("\n".join(overrides))


@pytest.mark.parametrize(
    "value",
    [
        "https://api.openai.com",
        "http://192.168.1.8:8000",
        "http://[::ffff:192.168.1.8]:8000",
        "http://[::ffff:8.8.8.8]:8000",
        "http://evil.localhost:8000",
        "http://localhost.evil:8000",
        "http://user:pass@localhost:8000",
        "http://@localhost:8000",
        "http://localhost:8000?",
        "http://localhost:8000#",
        "http://localhost:8000/v1",
        "ftp://localhost:8000",
        "http://localhost:65536",
        "http://localhost:/",
    ],
)
def test_proxy_url_rejects_non_loopback_or_non_root_urls(value: str) -> None:
    with pytest.raises(launchers.LauncherError):
        launchers._proxy_address(value)


@pytest.mark.parametrize(
    ("value", "origin", "hostname"),
    [
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000", "127.0.0.1"),
        ("https://LOCALHOST:8443/", "https://LOCALHOST:8443", "localhost"),
        ("http://127.0.0.2:8001/", "http://127.0.0.2:8001", "127.0.0.2"),
        ("https://[::1]:8443", "https://[::1]:8443", "::1"),
        (
            "http://[::ffff:127.0.0.1]:8000",
            "http://[::ffff:127.0.0.1]:8000",
            "::ffff:127.0.0.1",
        ),
    ],
)
def test_proxy_url_accepts_loopback_roots(value: str, origin: str, hostname: str) -> None:
    address = launchers._proxy_address(value)
    assert address.origin == origin
    assert address.hostname == hostname


def test_health_check_requires_redaction_and_both_native_capabilities() -> None:
    with respx.mock() as router:
        route = router.get("http://127.0.0.1:8000/healthz").mock(
            return_value=httpx.Response(200, json=_healthy_response())
        )
        launchers._require_ready_proxy("http://127.0.0.1:8000")
    assert route.called

    invalid_responses = [
        httpx.Response(503, json=_healthy_response()),
        httpx.Response(302, headers={"location": "/login"}),
        httpx.Response(200, json=_healthy_response(redaction=False)),
        httpx.Response(200, json=_healthy_response(client_shims={"native_auth": True})),
        httpx.Response(200, json={"ok": True, "redaction": True}),
        httpx.Response(200, text="not json"),
    ]
    for response in invalid_responses:
        with respx.mock() as router:
            router.get("http://127.0.0.1:8000/healthz").mock(return_value=response)
            with pytest.raises(launchers.LauncherError):
                launchers._require_ready_proxy("http://127.0.0.1:8000")


def test_claude_launcher_accepts_chat_compatibility_without_native_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_launcher_environment(monkeypatch)
    require_ready_proxy = launchers._require_ready_proxy
    calls = _install_exec_capture(monkeypatch)
    monkeypatch.setattr(launchers, "_require_ready_proxy", require_ready_proxy)

    with respx.mock() as router:
        router.get("http://127.0.0.1:8000/healthz").mock(
            return_value=httpx.Response(
                200,
                json=_healthy_response(
                    client_shims={"native_auth": True, "native_responses": False}
                ),
            )
        )
        launchers._main("claude", [])

    assert len(calls) == 1


def test_codex_launcher_still_requires_native_responses(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _clear_launcher_environment(monkeypatch)
    require_ready_proxy = launchers._require_ready_proxy
    calls = _install_exec_capture(monkeypatch)
    monkeypatch.setattr(launchers, "_require_ready_proxy", require_ready_proxy)

    with respx.mock() as router:
        router.get("http://127.0.0.1:8000/healthz").mock(
            return_value=httpx.Response(
                200,
                json=_healthy_response(
                    client_shims={"native_auth": True, "native_responses": False}
                ),
            )
        )
        with pytest.raises(SystemExit) as result:
            launchers._main("codex", [])

    assert result.value.code == 1
    assert calls == []
    assert "native Responses API support" in capsys.readouterr().err


def test_codex_api_key_mode_uses_official_responses_endpoint_and_preserves_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_launcher_environment(monkeypatch)
    calls = _install_exec_capture(monkeypatch)
    monkeypatch.setenv("PROMPTLATCH_CODEX_AUTH", "api-key")
    monkeypatch.setenv("OPENAI_API_KEY", "secret-key-do-not-place-in-argv")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://external.example/v1")
    monkeypatch.setenv("NO_PROXY", "example.test")
    monkeypatch.setenv("no_proxy", "other.test")
    arguments = ["exec", "-p", "profile", "ordinary prompt mentioning --remote"]

    launchers._main("codex", arguments)

    assert len(calls) == 1
    executable, argv, environment = calls[0]
    assert executable == "/opt/bin/cli"
    assert argv[-len(arguments) :] == arguments
    assert "secret-key-do-not-place-in-argv" not in argv
    assert environment["OPENAI_API_KEY"] == "secret-key-do-not-place-in-argv"
    assert "OPENAI_BASE_URL" not in environment
    assert set(environment["NO_PROXY"].split(",")) == {
        "example.test",
        "localhost",
        "127.0.0.1",
        "::1",
    }
    assert set(environment["no_proxy"].split(",")) == {
        "other.test",
        "localhost",
        "127.0.0.1",
        "::1",
    }

    config = _codex_effective_config(argv)
    assert config["model_provider"] == "promptlatch-official"
    provider = config["model_providers"]["promptlatch-official"]
    assert provider == {
        "name": "PromptLatch official endpoint",
        "base_url": "http://127.0.0.1:8000/v1",
        "wire_api": "responses",
        "supports_websockets": False,
        "requires_openai_auth": False,
        "http_headers": {"X-Target-Base-URL": "https://api.openai.com/v1"},
        "env_key": "OPENAI_API_KEY",
    }
    assert config["features"]["enable_request_compression"] is False


def test_codex_chatgpt_mode_uses_native_login_without_openai_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_launcher_environment(monkeypatch)
    calls = _install_exec_capture(monkeypatch)
    monkeypatch.setenv("PROMPTLATCH_CODEX_AUTH", "chatgpt")
    monkeypatch.setenv("OPENAI_API_KEY", "environment-key")
    monkeypatch.setattr(
        launchers.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("chatgpt mode must not inspect saved auth"),
    )

    launchers._main("codex", ["exec", "-p", "work"])

    _, argv, environment = calls[0]
    assert "OPENAI_API_KEY" not in environment
    provider = _codex_effective_config(argv)["model_providers"]["promptlatch-official"]
    assert provider["name"] == "OpenAI"
    assert provider["base_url"] == "http://127.0.0.1:8000/backend-api/codex"
    assert provider["http_headers"]["X-Target-Base-URL"] == launchers._CODEX_CHATGPT_TARGET
    assert provider["requires_openai_auth"] is True
    assert "env_key" not in provider


@pytest.mark.parametrize(
    ("status", "key", "expected_mode"),
    [
        ("Logged in using ChatGPT", "present", "chatgpt"),
        ("Not logged in", "present", "api-key"),
    ],
)
def test_codex_auto_mode_selects_saved_login_or_environment_key(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    key: str,
    expected_mode: str,
) -> None:
    _clear_launcher_environment(monkeypatch)
    calls = _install_exec_capture(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "api-key-value")
    monkeypatch.setattr(
        launchers.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["codex", "login", "status"], returncode=0, stdout=status
        ),
    )

    launchers._main("codex", [])

    _, argv, environment = calls[0]
    provider = _codex_effective_config(argv)["model_providers"]["promptlatch-official"]
    if expected_mode == "chatgpt":
        assert provider["http_headers"]["X-Target-Base-URL"] == launchers._CODEX_CHATGPT_TARGET
        assert "OPENAI_API_KEY" not in environment
    else:
        assert provider["env_key"] == "OPENAI_API_KEY"
        assert key == "present"


def test_codex_auto_mode_fails_closed_when_saved_login_is_ambiguous(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_launcher_environment(monkeypatch)
    calls = _install_exec_capture(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "key-that-must-not-be-printed")
    monkeypatch.setattr(
        launchers.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["codex", "login", "status"],
            returncode=0,
            stdout="Saved credential is key-that-must-not-be-printed but type is unknown",
        ),
    )

    with pytest.raises(SystemExit) as result:
        launchers._main("codex", [])
    assert result.value.code == 1
    assert calls == []
    assert "key-that-must-not-be-printed" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "arguments",
    [
        ["-c", 'model_provider="other"'],
        ['--config=model_provider="other"'],
        ['-cmodel_provider="other"'],
        ['-c=model_provider="other"'],
        ["-c", 'model_providers.other.base_url="https://other.test"'],
        ["-c", 'openai_base_url="https://other.test"'],
        ["--oss"],
        ["--local-provider", "ollama"],
        ["--remote"],
        ["--remote=other"],
    ],
)
def test_codex_rejects_routing_and_bypass_overrides(arguments: list[str]) -> None:
    with pytest.raises(launchers.LauncherError):
        launchers._reject_codex_routing_overrides(arguments)


def test_codex_routing_override_check_stops_at_double_dash() -> None:
    launchers._reject_codex_routing_overrides(
        ["exec", "-p", "profile", "--", "-c", 'model_provider="prompt text"', "--remote"]
    )
    launchers._reject_codex_routing_overrides(
        ["exec", "please include -c model_provider=other in the example"]
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["cloud", "exec", "--env", "ID", "prompt"],
        ["--profile", "work", "cloud", "exec"],
        ["-pwork", "cloud", "status"],
        ["--add-dir", "/tmp", "cloud", "exec"],
    ],
)
def test_codex_cloud_subcommands_are_rejected(arguments: list[str]) -> None:
    with pytest.raises(launchers.LauncherError, match="Codex Cloud"):
        launchers._reject_codex_unproxied_commands(arguments)


def test_codex_cloud_words_in_prompts_do_not_trigger_cloud_guard() -> None:
    launchers._reject_codex_unproxied_commands(["exec", "cloud tasks should be described"])
    launchers._reject_codex_unproxied_commands(["Ask about cloud tasks"])
    launchers._reject_codex_unproxied_commands(["--", "cloud", "exec"])


def test_codex_effective_config_accepts_only_expected_provider_and_managed_policy() -> None:
    provider = _api_key_provider()
    config = {
        "model_provider": launchers._CODEX_PROVIDER,
        "model_providers": {launchers._CODEX_PROVIDER: provider},
        "features": {"enable_request_compression": False},
    }

    launchers._validate_codex_effective_config(
        config,
        {
            "modelProvider": launchers._CODEX_PROVIDER,
            "modelProviders": None,
        },
        provider,
    )

    altered = {**provider, "env_http_headers": {"X-Target-Base-URL": "https://evil.test"}}
    unsafe_config = {
        **config,
        "model_providers": {launchers._CODEX_PROVIDER: altered},
    }
    with pytest.raises(launchers.LauncherError):
        launchers._validate_codex_effective_config(unsafe_config, None, provider)

    with pytest.raises(launchers.LauncherError):
        launchers._validate_codex_effective_config(
            config, {"modelProvider": "unmanaged-provider"}, provider
        )


def test_codex_effective_config_rejects_managed_provider_definition_mismatch() -> None:
    provider = _api_key_provider()
    bad_required_provider = {**provider, "http_headers": {"X-Target-Base-URL": "https://evil.test"}}
    config = {
        "model_provider": launchers._CODEX_PROVIDER,
        "model_providers": {launchers._CODEX_PROVIDER: provider},
        "features": {"enable_request_compression": False},
    }
    with pytest.raises(launchers.LauncherError):
        launchers._validate_codex_effective_config(
            config,
            {"modelProviders": {launchers._CODEX_PROVIDER: bad_required_provider}},
            provider,
        )


def test_codex_config_read_uses_offline_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = {
        "OPENAI_API_KEY": "fixture-must-not-be-in-reader-env",
        "HTTP_PROXY": "http://capture.example",
        "http_proxy": "http://capture.example",
        "HTTPS_PROXY": "http://capture.example",
        "https_proxy": "http://capture.example",
        "ALL_PROXY": "http://capture.example",
        "all_proxy": "http://capture.example",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    provider = _api_key_provider()
    config = {
        "model_provider": launchers._CODEX_PROVIDER,
        "model_providers": {launchers._CODEX_PROVIDER: provider},
        "features": {"enable_request_compression": False},
    }
    observed_sockets: list[socket.socket] = []
    original_offline_environment = launchers._codex_offline_environment

    def capture_socket(reader_environment: dict[str, str]):
        safe_environment, sink = original_offline_environment(reader_environment)
        observed_sockets.append(sink)
        return safe_environment, sink

    monkeypatch.setattr(launchers, "_codex_offline_environment", capture_socket)

    def read_config(
        _arguments: list[str], reader_environment: dict[str, str], _cwd: Path
    ) -> tuple[dict[str, object], None]:
        assert "OPENAI_API_KEY" not in reader_environment
        assert reader_environment["NO_PROXY"] == ""
        assert reader_environment["no_proxy"] == ""
        proxy_urls = {
            reader_environment[name]
            for name in (
                "HTTP_PROXY",
                "http_proxy",
                "HTTPS_PROXY",
                "https_proxy",
                "ALL_PROXY",
                "all_proxy",
            )
        }
        assert len(proxy_urls) == 1
        proxy = launchers._proxy_address(next(iter(proxy_urls)))
        assert proxy.hostname == "127.0.0.1"
        port = urlsplit(next(iter(proxy_urls))).port
        assert port is not None
        probe = socket.socket()
        try:
            probe.settimeout(0.2)
            assert probe.connect_ex(("127.0.0.1", port)) != 0
        finally:
            probe.close()
        return config, None

    monkeypatch.setattr(launchers, "_read_codex_config", read_config)
    launchers._verify_codex_configuration("/opt/bin/codex", [], environment, provider)
    assert len(observed_sockets) == 1
    assert observed_sockets[0].fileno() == -1


def test_codex_profile_reserved_provider_collision_is_rejected(tmp_path) -> None:
    (tmp_path / "work.config.toml").write_text(
        '[model_providers.promptlatch-official]\nname = "inherited"\n',
        encoding="utf-8",
    )
    with pytest.raises(launchers.LauncherError, match="reserved PromptLatch provider"):
        launchers._reject_codex_profile_collisions(
            ["exec", "-p=work", "prompt"], {"CODEX_HOME": str(tmp_path)}
        )


def test_codex_profile_with_ordinary_model_settings_remains_usable(tmp_path) -> None:
    (tmp_path / "work.config.toml").write_text(
        'model = "gpt-5-codex"\nmodel_provider = "other"\n', encoding="utf-8"
    )
    launchers._reject_codex_profile_collisions(
        ["exec", "--profile=work", "prompt"], {"CODEX_HOME": str(tmp_path)}
    )


def test_codex_effective_cwd_handles_joined_equals_form(tmp_path) -> None:
    assert launchers._codex_effective_cwd([f"-C={tmp_path}"]) == tmp_path.resolve()


def test_codex_config_guard_has_local_no_proxy_before_app_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_launcher_environment(monkeypatch)
    monkeypatch.setenv("PROMPTLATCH_CODEX_AUTH", "api-key")
    monkeypatch.setenv("OPENAI_API_KEY", "fixture-key")
    calls = _install_exec_capture(monkeypatch)
    observed: list[dict[str, str]] = []

    def verify(
        _executable: str,
        _arguments: list[str],
        environment: dict[str, str],
        _provider: dict[str, object],
    ) -> None:
        observed.append(environment)

    monkeypatch.setattr(launchers, "_verify_codex_configuration", verify)
    launchers._main("codex", [])

    assert observed
    assert "127.0.0.1" in observed[0]["NO_PROXY"].split(",")
    assert calls


def test_claude_version_below_supported_minimum_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        launchers.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["claude", "--version"], returncode=0, stdout="2.1.219 (Claude Code)"
        ),
    )
    with pytest.raises(launchers.LauncherError, match="2.1.220 or newer"):
        launchers._require_supported_cli_version("claude", "/opt/bin/claude", {})


def test_claude_launcher_preserves_native_auth_and_filters_routing_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_launcher_environment(monkeypatch)
    calls = _install_exec_capture(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "native-api-key")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "native-auth-token")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "native-oauth-token")
    monkeypatch.setenv(
        "ANTHROPIC_CUSTOM_HEADERS",
        "X-Request-ID: request-123\n"
        "x-target-base-url: https://attacker.example\n"
        "X-Target-API-Key: sensitive-routing-key\n"
        "X-Redact-Extra-Rules: []\n"
        "X-Client-Feature: example",
    )
    arguments = ["--", "prompt", "preserve exactly"]

    launchers._main("claude", arguments)

    _, argv, environment = calls[0]
    assert argv[-len(arguments) :] == arguments
    assert environment["ANTHROPIC_API_KEY"] == "native-api-key"
    assert environment["ANTHROPIC_AUTH_TOKEN"] == "native-auth-token"
    assert environment["CLAUDE_CODE_OAUTH_TOKEN"] == "native-oauth-token"
    assert environment["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8000"
    assert environment["CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST"] == "1"
    assert environment["CLAUDE_CODE_GZIP_REQUEST_BODIES"] == "0"
    assert environment["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
    assert environment["ANTHROPIC_CUSTOM_HEADERS"] == (
        "X-Request-ID: request-123\n"
        "X-Client-Feature: example\n"
        "X-Target-Base-URL: https://api.anthropic.com"
    )
    assert "sensitive-routing-key" not in argv


@pytest.mark.parametrize(
    "switch",
    ["CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"],
)
def test_claude_launcher_refuses_alternate_provider_modes(
    monkeypatch: pytest.MonkeyPatch, switch: str
) -> None:
    _clear_launcher_environment(monkeypatch)
    monkeypatch.setenv(switch, "true")
    calls = _install_exec_capture(monkeypatch)
    with pytest.raises(SystemExit) as result:
        launchers._main("claude", [])
    assert result.value.code == 1
    assert calls == []


def test_proxy_health_failure_prevents_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_launcher_environment(monkeypatch)
    calls = _install_exec_capture(monkeypatch)

    def fail_health(_url: str, **_kwargs: Any) -> None:
        raise launchers.LauncherError("local PromptLatch is not healthy with redaction enabled")

    monkeypatch.setattr(launchers, "_require_ready_proxy", fail_health)
    with pytest.raises(SystemExit) as result:
        launchers._main("claude", [])
    assert result.value.code == 1
    assert calls == []


def test_invalid_proxy_url_prevents_health_and_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_launcher_environment(monkeypatch)
    monkeypatch.setenv("PROMPTLATCH_PROXY_URL", "https://api.openai.com")
    calls = _install_exec_capture(monkeypatch)

    def unexpected_health(_url: str, **_kwargs: Any) -> None:
        pytest.fail("invalid proxy URL must be rejected before health check")

    monkeypatch.setattr(launchers, "_require_ready_proxy", unexpected_health)
    with pytest.raises(SystemExit) as result:
        launchers._main("claude", [])
    assert result.value.code == 1
    assert calls == []


def test_missing_cli_fails_before_health_check(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_launcher_environment(monkeypatch)
    monkeypatch.setenv("PROMPTLATCH_CLAUDE_BIN", "/missing/claude")
    monkeypatch.setattr(launchers.shutil, "which", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        launchers,
        "_require_ready_proxy",
        lambda _url, **_kwargs: pytest.fail("missing CLI must fail before health check"),
    )
    with pytest.raises(SystemExit) as result:
        launchers._main("claude", [])
    assert result.value.code == 1


def test_invalid_codex_auth_mode_fails_before_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_launcher_environment(monkeypatch)
    calls = _install_exec_capture(monkeypatch)
    monkeypatch.setenv("PROMPTLATCH_CODEX_AUTH", "ambient")
    with pytest.raises(SystemExit) as result:
        launchers._main("codex", [])
    assert result.value.code == 1
    assert calls == []


def test_launcher_help_does_not_check_proxy_or_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_launcher_environment(monkeypatch)
    monkeypatch.setattr(
        launchers,
        "_require_ready_proxy",
        lambda _url, **_kwargs: pytest.fail("help must not contact the proxy"),
    )
    monkeypatch.setattr(
        launchers.shutil,
        "which",
        lambda *_args, **_kwargs: pytest.fail("help must not resolve the CLI"),
    )
    with pytest.raises(SystemExit) as result:
        launchers._main("codex", ["--latch-help"])
    assert result.value.code == 0
    output = capsys.readouterr().out
    assert "PROMPTLATCH_PROXY_URL" in output
    assert "PROMPTLATCH_CODEX_AUTH" in output


def test_no_proxy_keeps_existing_values_and_adds_local_hosts() -> None:
    environment = {"NO_PROXY": "example.test,localhost", "no_proxy": "*.internal"}
    launchers._merge_no_proxy(environment, "127.0.0.2")
    assert environment["NO_PROXY"].split(",") == [
        "example.test",
        "localhost",
        "127.0.0.1",
        "::1",
        "127.0.0.2",
    ]
    assert set(environment["no_proxy"].split(",")) == {
        "*.internal",
        "localhost",
        "127.0.0.1",
        "::1",
        "127.0.0.2",
    }


def test_launcher_does_not_change_working_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_launcher_environment(monkeypatch)
    calls = _install_exec_capture(monkeypatch)
    launchers._main("claude", [])
    assert calls[0][0] == "/opt/bin/cli"
