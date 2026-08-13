import pytest
from pydantic import ValidationError

from promptlatch.config import (
    RedactionConfig,
    RuleConfig,
    ServerConfig,
    Settings,
    TargetConfig,
    load_settings,
)


def test_server_api_key_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PROMPTLATCH_SERVER_API_KEY", "local-token")
    monkeypatch.setenv("PROMPTLATCH_DEBUG_REQUESTS", "true")
    monkeypatch.setenv("PROMPTLATCH_DEBUG_MAX_BODY_CHARS", "1234")
    monkeypatch.setenv("PROMPTLATCH_TARGET_API_KEY", "upstream-token")
    monkeypatch.setenv("PROMPTLATCH_TARGET_API_KEY_HEADER", "x-api-key")
    monkeypatch.setenv("PROMPTLATCH_TARGET_BASE_URL", "https://upstream.example/v1")
    monkeypatch.setenv("PROMPTLATCH_RESPONSES_TO_CHAT", "true")

    settings = load_settings(tmp_path / "missing.yaml")

    assert settings.server.api_key == "local-token"
    assert settings.server.debug_requests is True
    assert settings.server.debug_max_body_chars == 1234
    assert settings.target.api_key == "upstream-token"
    assert settings.target.api_key_header == "x-api-key"
    assert settings.target.default_base_url == "https://upstream.example/v1"
    assert settings.compat.responses_to_chat is True


def test_legacy_server_api_key_env_remains_authenticated(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PROMPTCLOAK_SERVER_API_KEY", "legacy-fixture-token")
    monkeypatch.setenv("PROMPTLATCH_REQUIRE_SERVER_API_KEY", "true")

    with pytest.warns(FutureWarning, match="PROMPTLATCH_SERVER_API_KEY"):
        settings = load_settings(tmp_path / "missing.yaml")

    assert settings.server.api_key == "legacy-fixture-token"


def test_legacy_default_config_path_is_loaded(monkeypatch, tmp_path) -> None:
    import promptlatch.config as config_module

    current_dir = tmp_path / "promptlatch"
    legacy_dir = tmp_path / "promptcloak"
    legacy_dir.mkdir()
    (legacy_dir / "config.yaml").write_text(
        "server:\n  api_key: legacy-fixture-token\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config_module, "DEFAULT_CONFIG_PATH", current_dir / "config.yaml")
    monkeypatch.setattr(config_module, "DEFAULT_KEY_PATH", current_dir / "key")
    monkeypatch.setattr(config_module, "LEGACY_CONFIG_PATH", legacy_dir / "config.yaml")
    monkeypatch.setattr(config_module, "LEGACY_KEY_PATH", legacy_dir / "key")
    monkeypatch.delenv("PROMPTLATCH_CONFIG", raising=False)
    monkeypatch.delenv("PROMPTCLOAK_CONFIG", raising=False)

    with pytest.warns(FutureWarning, match="using legacy path"):
        settings = load_settings()

    assert settings.server.api_key == "legacy-fixture-token"


def test_required_server_api_key_fails_closed() -> None:
    with pytest.raises(ValidationError, match="server API key is required but missing"):
        ServerConfig(require_api_key=True)


@pytest.mark.parametrize(
    "url",
    [
        "https://",
        "ftp://provider.example/v1",
        "https://user:pass@provider.example/v1",
        "https://provider.example/v1?key=value",
        "https://provider.example/v1#fragment",
        "https://provider.example:invalid/v1",
    ],
)
def test_target_base_urls_reject_ambiguous_values(url: str) -> None:
    with pytest.raises(ValidationError):
        TargetConfig(default_base_url=url)


def test_exact_rules_require_safe_tail_length() -> None:
    with pytest.raises(ValidationError):
        RuleConfig(type="exact", value="short")


def test_rule_names_are_bounded_log_labels() -> None:
    with pytest.raises(ValidationError):
        RuleConfig(type="regex", value="fixture", name="not a safe label")


@pytest.mark.parametrize("value", ["[", ".*"])
def test_regex_rules_reject_invalid_or_empty_matches(value: str) -> None:
    with pytest.raises(ValidationError):
        RuleConfig(type="regex", value=value)


def test_encrypted_rules_fail_closed_when_ciphertext_is_missing() -> None:
    with pytest.raises(ValidationError):
        RedactionConfig(encrypted=True)


def test_config_root_must_be_a_mapping(tmp_path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="config root must be a mapping"):
        load_settings(config)


@pytest.mark.parametrize("port", [0, 65536])
def test_server_port_must_be_valid(port: int) -> None:
    with pytest.raises(ValidationError):
        ServerConfig(port=port)


def test_proxy_auth_rejects_forwarding_client_authorization() -> None:
    with pytest.raises(
        ValidationError,
        match="proxy authentication cannot be combined with client authorization forwarding",
    ):
        Settings(
            server=ServerConfig(api_key="local-fixture-token"),
            target=TargetConfig(forward_client_authorization=True),
        )
