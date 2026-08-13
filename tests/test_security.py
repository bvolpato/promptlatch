import stat

import pytest
import yaml

from promptlatch.config import RedactionConfig, Settings, load_settings
from promptlatch.security import encrypt_text, load_key, write_key_file, write_private_text


def test_private_writes_replace_insecure_file_mode(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("old", encoding="utf-8")
    path.chmod(0o644)

    write_private_text(path, "new")

    assert path.read_text(encoding="utf-8") == "new"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_key_file_is_private(tmp_path) -> None:
    key_file = tmp_path / "key"

    write_key_file(key_file)

    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


def test_legacy_config_key_env_remains_available(monkeypatch, tmp_path) -> None:
    key_file = tmp_path / "missing"
    fixture_key = write_key_file(tmp_path / "fixture-key")
    monkeypatch.setenv("PROMPTCLOAK_CONFIG_KEY", fixture_key)

    with pytest.warns(FutureWarning, match="PROMPTLATCH_CONFIG_KEY"):
        key = load_key(key_file)

    assert len(key) == 32


def test_encrypted_rules_load(tmp_path) -> None:
    key_file = tmp_path / "key"
    write_key_file(key_file)
    rules = [{"type": "exact", "value": "abcd1234", "name": "tail"}]
    encrypted = encrypt_text(yaml.safe_dump(rules), load_key(key_file))
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump(
            Settings(
                redaction=RedactionConfig(encrypted=True, encrypted_rules=encrypted)
            ).model_dump(mode="json")
        ),
        encoding="utf-8",
    )

    settings = load_settings(config, key_file)

    assert settings.redaction.rules[0].value == "abcd1234"
    Settings.model_validate(settings.model_dump())
