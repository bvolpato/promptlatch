import os
import stat
import subprocess

import yaml
from typer.testing import CliRunner

from promptlatch.cli import app
from promptlatch.version import __version__


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
