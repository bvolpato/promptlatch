"""Check that the homepage demo and the Python engine redact the same text the same way."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from promptlatch import redact_text
from tests.fixtures import PROVIDER_FIXTURES

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
DEMO = """
require(process.argv[1] + "/site/rules.js");
const demo = require(process.argv[1] + "/site/demo.js");
let data = "";
process.stdin.on("data", (chunk) => (data += chunk));
process.stdin.on("end", () => {
  process.stdout.write(JSON.stringify(JSON.parse(data).map(demo.text)));
});
"""
CASES = [
    "no secrets here, just prose about tokens and passwords",
    "password = load_password()\nmax_tokens: 4096",
    "OPENAI_API_KEY=<your-api-key-here>",
    "DATABASE_URL=postgres://app:FixturePassw0rd@db.internal:5432/prod",
    "redis://:FixturePassw0rd@cache:6379 client_secret=FixtureSecret0000",
    'curl -H "Authorization: Bearer FixtureToken000000000000000000000"',
    "https://files.example.com/a?X-Amz-Expires=300&X-Amz-Sign" + "ature=FixtureSignature0000",
    '{"bot_token": "' + "xo" + 'xb-FixtureToken-000000000000", "channel": "#releases"}',
    "a=" + "gh" + "p_" + "FixtureToken" + "0" * 24 + ", b=" + "AK" + "IA" + "FIXTURETOKEN0000",
]


def test_site_rules_match_builtin_patterns() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_site_rules.py"), "--check"],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_site_demo_matches_python_engine() -> None:
    if NODE is None:
        pytest.skip("Node.js is required for the homepage demo test")
    texts = CASES + [f"key {secret} end" for secret in PROVIDER_FIXTURES.values()]
    result = subprocess.run(
        [NODE, "-e", DEMO, str(ROOT)],
        input=json.dumps(texts),
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    assert dict(zip(texts, json.loads(result.stdout), strict=True)) == {
        text: redact_text(text) for text in texts
    }
