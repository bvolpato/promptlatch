"""Run the dashboard's pure JSON presentation tests with Node's built-in runner."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

NODE = shutil.which("node")


def test_dashboard_json_presentation() -> None:
    if NODE is None:
        pytest.skip("Node.js is required for dashboard JSON behavior tests")
    test_file = Path(__file__).with_name("dashboard_json.test.cjs")
    result = subprocess.run(
        [NODE, "--test", str(test_file)],
        cwd=test_file.parents[1],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Node dashboard tests failed:\n{result.stdout}\n{result.stderr}"
