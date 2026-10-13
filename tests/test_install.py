from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"
BASH = shutil.which("bash")
SYSTEM_PATH = "/usr/bin:/bin"


def _run_installer(
    *args: str,
    path: str,
    installer: Path = INSTALLER,
    **env_overrides: str,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(env_overrides)
    env["PATH"] = path
    assert BASH is not None
    return subprocess.run(
        [BASH, str(installer), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_help_does_not_require_uv_or_run_installer() -> None:
    result = _run_installer("--help", path=SYSTEM_PATH)

    assert result.returncode == 0
    assert "Usage: ./install.sh [--help]" in result.stdout
    assert "uv is required" not in result.stderr


def test_missing_uv_has_actionable_error() -> None:
    result = _run_installer(path=SYSTEM_PATH)

    assert result.returncode == 127
    assert "uv is required" in result.stderr
    assert "https://docs.astral.sh/uv/getting-started/installation/" in result.stderr


def test_installs_this_checkout_with_reinstall_and_preserves_uv_exit_status(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout path with spaces"
    checkout.mkdir()
    installer = checkout / "install.sh"
    shutil.copy2(INSTALLER, installer)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    args_file = tmp_path / "uv-args"
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$UV_ARGS_FILE"\nexit "${UV_EXIT_STATUS:-0}"\n',
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)

    result = _run_installer(
        path=f"{fake_bin}:{SYSTEM_PATH}",
        installer=installer,
        UV_ARGS_FILE=str(args_file),
        UV_EXIT_STATUS="23",
    )

    assert result.returncode == 23
    assert args_file.read_text(encoding="utf-8").splitlines() == [
        "tool",
        "install",
        "--reinstall",
        str(checkout.resolve()),
    ]


def test_rejects_unknown_arguments_without_running_uv(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "uv-called"
    fake_uv = fake_bin / "uv"
    fake_uv.write_text('#!/bin/sh\ntouch "$UV_MARKER_FILE"\n', encoding="utf-8")
    fake_uv.chmod(0o755)

    result = _run_installer(
        "--force",
        path=f"{fake_bin}:{SYSTEM_PATH}",
        UV_MARKER_FILE=str(marker),
    )

    assert result.returncode == 2
    assert "Unexpected argument: --force" in result.stderr
    assert not marker.exists()
