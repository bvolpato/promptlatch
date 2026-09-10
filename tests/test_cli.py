import os
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.request

import pytest
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
