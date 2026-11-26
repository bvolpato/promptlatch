"""Check that the homepage demo and the Python engine redact the same text the same way."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from promptlatch.config import RedactionConfig
from promptlatch.redaction import SecretRedactor
from tests.fixtures import EXPANDED_PROVIDER_FIXTURES, OPENAI_FAKE, PROVIDER_FIXTURES

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
DEMO = """
require(process.argv[1] + "/site/rules.js");
const demo = require(process.argv[1] + "/site/demo.js");
let data = "";
process.stdin.on("data", (chunk) => (data += chunk));
process.stdin.on("end", () => {
  process.stdout.write(JSON.stringify(JSON.parse(data).map((text) => {
    const pieces = demo.redact(text);
    const rules = {};
    for (const { rule } of pieces) if (rule) rules[rule] = (rules[rule] || 0) + 1;
    const original = pieces.map((piece) => (piece.rule ? piece.original : piece.out)).join("");
    return { text: demo.text(text), original, rules };
  })));
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
    f"first {OPENAI_FAKE} then {OPENAI_FAKE} and {OPENAI_FAKE}x end",
    '{"model":"gpt-6-sol","max_output_tokens": 16384000}',
    "environment:\n  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
    "credentials:\n  username: administrator",
    "if token:\n    return_value = 1",
    "if you need the password:\n  FixturePassw0rd",
    "for staging use this password:\n  administrator = FixturePassw0rd",
    "for x in tokens:\n    process_everything(x)",
    "access_key:\nsecret_key: FixtureSecret0000",
    "AWS_ACCESS_KEY=\nAWS_SECRET_KEY = FixtureSecret0000",
    "AccountName=x;AccountKey=" + "Fixture0" * 11 + "==;EndpointSuffix=y",
    "access_key: Optional, accessKey: process.env.S3_ACCESS_KEY",
    'postgres://u:pa"ssFixture0@db/app {"a":"redis://h:6379","b":"x@y"}',
    "-----BEGIN " + "PRIVATE KEY-----\nFixtureBody0000\n-----END " + "PRIVATE KEY-----\nafter",
    "\\Npostgres://app:FixturePassw0rd@db and HTTPS://app:FixturePassw0rd@db",
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
    fixtures = [*PROVIDER_FIXTURES.values(), *EXPANDED_PROVIDER_FIXTURES.values()]
    texts = CASES + [f"key {secret} end" for secret in fixtures]
    result = subprocess.run(
        [NODE, "-e", DEMO, str(ROOT)],
        input=json.dumps(texts),
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    expected = {}
    for text in texts:
        redacted = redactor.redact_text(text)
        expected[text] = {
            "text": redacted.value,
            "original": text,
            "rules": redacted.stats.rule_hits,
        }
    assert dict(zip(texts, json.loads(result.stdout), strict=True)) == expected
