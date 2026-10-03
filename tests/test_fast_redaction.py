from __future__ import annotations

import base64
import json
import random
import re
import threading

import pytest

from promptlatch import redaction
from promptlatch.config import RedactionConfig
from promptlatch.patterns import BUILTIN_PATTERNS
from promptlatch.redaction import (
    _BUILTIN_PREFIXES,
    RedactionStats,
    SecretRedactor,
    _line_gate,
    _literal_prefix,
    _ScanCache,
)
from tests.fixtures import EXPANDED_PROVIDER_FIXTURES, OPENAI_FAKE, PROVIDER_FIXTURES

HEX = "0123456789abcdef"
BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _run(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _jwt() -> str:
    def part(value: dict[str, str]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return ".".join((part({"alg": "HS256"}), part({"sub": "fixture"}), "c2lnbmF0dXJl"))


def _plugin_samples() -> list[str]:
    """One line per detect-secrets plugin family, built so no literal secret is stored."""
    rng = random.Random(11)
    return [
        "aws_access_key_id = " + "AK" + "IA" + _run(rng, "ABCDEFGHIJKLMNOP234567", 16),
        "artifactory: " + "AKC" + _run(rng, BASE64[:62], 12),
        "DefaultEndpointsProtocol=https;AccountKey=" + _run(rng, BASE64, 86) + "==;azure",
        "clone https://deploy:" + _run(rng, HEX, 20) + "@git.internal/repo.git",
        "https://account:" + _run(rng, HEX, 64) + "@account.cloudant.com",
        "discord "
        + "M"
        + _run(rng, BASE64[:62], 23)
        + "."
        + _run(rng, BASE64[:62], 6)
        + "."
        + _run(rng, BASE64[:62], 27),
        "token " + "gh" + "p_" + _run(rng, BASE64[:62], 36),
        "ibm_cloud_api_key = " + _run(rng, BASE64[:62], 44),
        "cos_hmac_secret_access_key = " + _run(rng, HEX, 48),
        "bearer " + _jwt(),
        "mailchimp " + _run(rng, HEX, 32) + "-us12",
        "//registry.npmjs.org/:_authToken=" + "npm" + "_" + _run(rng, BASE64[:62], 36),
        "-----BEGIN RSA "
        + "PRIVATE KEY-----\n"
        + _run(rng, BASE64, 64)
        + "\n-----END RSA "
        + "PRIVATE KEY-----",
        "sendgrid " + "SG" + "." + _run(rng, BASE64[:62], 22) + "." + _run(rng, BASE64[:62], 43),
        "slack " + "xox" + "b-" + "123456789012-" + _run(rng, BASE64[:62], 24),
        "softlayer_api_key = " + _run(rng, HEX, 64),
        "square " + "sq0" + "csp-" + _run(rng, BASE64[:62], 43),
        "stripe " + "sk" + "_live_" + _run(rng, BASE64[:62], 24),
        "twilio " + "AC" + _run(rng, HEX, 32),
        'db_password = "' + _run(rng, BASE64[:62], 18) + '"',
        "paſſword: '" + _run(rng, BASE64[:62], 18) + "'",
    ]


def _generated_texts() -> list[str]:
    """Random lines from fragments that sit close to what the detectors match."""
    rng = random.Random(7)
    fragments = [
        "password", "Password", "api_key", "apiKey", "token", "secret", "client_secret",
        "pwd", "db_pass", "contraseña", "paſſword", "toKen", "private_key", "auth",
        "=", " = ", ": ", ":=", "==", "=>", '"', "'", "(", ")", ";", ",", " ", "\t",
        "AK" + "IA", "AS" + "IA", "xox" + "b-", "sk" + "_live_", "SG" + ".", "npm" + "_",
        "eyJ", "-----BEGIN ", "PRIVATE KEY-----", "://", "@", "user", "example.com",
        "git.internal", "AC", "SK", "ibm_cloud_api_key", "cloudant", "softlayer",
        "sq0" + "atp-", "AccountKey", "azure", "-us12", "the", "review", "def fetch(key):",
        "return cache[key]", "{", "}", "[", "]", "#", "//",
    ]  # fmt: skip
    texts = []
    for _ in range(60):
        lines = []
        for _ in range(rng.randint(1, 14)):
            parts = []
            for _ in range(rng.randint(1, 8)):
                if rng.random() < 0.3:
                    alphabet = rng.choice((HEX, BASE64, BASE64[:26], "0123456789"))
                    parts.append(_run(rng, alphabet, rng.choice((8, 16, 20, 24, 32, 44, 64, 88))))
                else:
                    parts.append(rng.choice(fragments))
            lines.append(rng.choice(("", " ")).join(parts))
        texts.append("\n".join(lines))
    return texts


def _fixture_texts() -> list[str]:
    secrets = {**PROVIDER_FIXTURES, **EXPANDED_PROVIDER_FIXTURES}
    prose = (
        f"plain prose line {index}, then {value} inline"
        for index, value in enumerate(secrets.values())
    )
    compose = "services:\n  api:\n    environment:\n      API_TOKEN: "
    return [
        "\n".join(f"{name}={value}" for name, value in secrets.items()),
        "\n".join(prose),
        compose + OPENAI_FAKE + "\n      MODE: test",
        '{"config": {"client_secret": "' + OPENAI_FAKE + '", "retries": 3}}',
        "No secret here.\nOnly a discussion of token limits and cache keys.\n",
    ]


def _scan(text: str) -> tuple[str, dict[str, int]]:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    result = redactor.redact_text(text)
    return result.value, result.stats.rule_hits


@pytest.fixture
def full_scan(monkeypatch: pytest.MonkeyPatch):
    """Scan every line with every pattern, as before the fast paths existed."""

    def scan(text: str) -> tuple[str, dict[str, int]]:
        with monkeypatch.context() as patch:
            patch.setattr(redaction, "_line_gate", lambda: None)
            patch.setattr(redaction, "_BUILTIN_PREFIXES", dict.fromkeys(_BUILTIN_PREFIXES))
            return _scan(text)

    return scan


def test_fast_paths_find_exactly_what_a_full_scan_finds(full_scan) -> None:
    samples = _plugin_samples()
    texts = [*samples, "\n".join(samples), *_fixture_texts(), *_generated_texts()]
    redactions = 0
    for text in texts:
        fast = _scan(text)
        assert fast == full_scan(text), text
        redactions += sum(fast[1].values())
    # The comparison is only meaningful when the corpus triggers the detectors.
    assert redactions > 100


def test_line_gate_covers_every_installed_detector() -> None:
    # A new detect-secrets plugin turns the gate off until it is reviewed and
    # added to the gated set. This test fails first, so the slowdown is seen.
    assert _line_gate() is not None


def test_line_gate_is_off_for_an_unknown_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    class NewDetector:
        pass

    plugins = (*redaction._detect_secrets_plugins(), NewDetector)
    monkeypatch.setattr(redaction, "_detect_secrets_plugins", lambda: plugins)
    _line_gate.cache_clear()
    try:
        assert _line_gate() is None
    finally:
        _line_gate.cache_clear()


def test_line_gate_skips_lines_that_no_detector_can_match() -> None:
    gate = _line_gate()
    assert gate is not None
    lines = [
        "def fetch(key_id):",
        "    return load(key_id)",
        "The request failed twice before the retry.",
        "aws " + "AK" + "IA" + "ABCDEFGHIJKLMNOP",
        "x = 1",
    ]

    # The first two lines hold a keyword literal, and the fourth an AWS key.
    assert gate.candidates(lines) == [lines[0], lines[1], lines[3]]
    assert gate.candidates(["plain text", "x = 1"]) == []


def test_repeated_strings_are_scanned_once(monkeypatch: pytest.MonkeyPatch) -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    scans: list[str] = []
    original = redactor._scan_string

    def counting(value: str, stats: RedactionStats) -> str:
        scans.append(value)
        return original(value, stats)

    monkeypatch.setattr(redactor, "_scan_string", counting)
    history = [
        {"role": "user", "content": f"Debug OPENAI_API_KEY={OPENAI_FAKE} " + "context " * 60},
        {"role": "assistant", "content": "The retry loop repeats a committed charge."},
    ]
    first = redactor.redact_payload({"messages": history})
    scanned = len(scans)
    follow_up = [*history, {"role": "user", "content": "Propose a fix."}]
    second = redactor.redact_payload({"messages": follow_up})

    # The second request scans only its new text, and reports the same hits.
    assert scans[scanned:] == ["Propose a fix."]
    assert second.value["messages"][:2] == first.value["messages"]
    assert second.stats.rule_hits == first.stats.rule_hits
    assert OPENAI_FAKE not in json.dumps(second.value)


def test_scan_cache_is_bounded_by_entries_and_size() -> None:
    cache = _ScanCache(max_entries=2, max_chars=40)
    cache.put(b"a", None, ())
    cache.put(b"b", "x" * 10, (("rule", 1),))
    assert cache.get(b"a") == (None, ())
    cache.put(b"c", None, ())
    # "b" was used least recently, so it leaves first.
    assert cache.get(b"b") is None
    assert cache.get(b"a") is not None and cache.get(b"c") is not None
    # The entry limit removes "a", and the size limit then removes "c".
    cache.put(b"d", "y" * 39, ())
    assert cache.get(b"a") is None and cache.get(b"c") is None
    assert cache.get(b"d") is not None
    cache.put(b"too large", "z" * 100, ())
    assert cache.get(b"too large") is None


def test_scan_cache_never_keeps_unredacted_input() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    text = f"OPENAI_API_KEY={OPENAI_FAKE}"

    assert OPENAI_FAKE not in redactor.redact_text(text).value
    for key, (redacted, _hits) in redactor._cache._entries.items():
        assert isinstance(key, bytes) and len(key) == 16
        assert OPENAI_FAKE not in (redacted or "")
    cache = redactor._cache
    assert cache.key(text) == cache.key("".join(text)) != cache.key(text + "x")
    # Another process, or another redactor, derives different keys.
    assert cache.key(text) != SecretRedactor(RedactionConfig())._cache.key(text)


@pytest.mark.parametrize(
    ("pattern", "prefix"),
    [
        (r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", "sk-ant-"),
        (r"\bhttps?://hooks\.slack\.com/(?:services|workflows)/x", "http"),
        (r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b", "gh"),
        (r"\bfoo[0-9]+|bar[0-9]+", None),
        (r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b", None),
        (r"\bab*c", None),
        (r"(?i)\btoken[0-9]+", None),
    ],
)
def test_literal_prefix_is_text_that_every_match_starts_with(
    pattern: str, prefix: str | None
) -> None:
    assert _literal_prefix(re.compile(pattern)) == prefix


def test_builtin_prefixes_hold_for_every_fixture_secret() -> None:
    secrets = [*PROVIDER_FIXTURES.values(), *EXPANDED_PROVIDER_FIXTURES.values()]
    checked = 0
    for name, pattern in BUILTIN_PATTERNS:
        prefix = _BUILTIN_PREFIXES[name]
        for secret in secrets:
            for match in pattern.finditer(f"value {secret} end"):
                if prefix is not None:
                    assert match.group(0).startswith(prefix), name
                    checked += 1
    assert checked >= 20


def test_concurrent_scans_match_a_single_scan() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    texts = [f"{index} " + text for index, text in enumerate(_plugin_samples())]
    expected = [_scan(text) for text in texts]
    results: dict[int, tuple[str, dict[str, int]]] = {}

    def work(index: int) -> None:
        result = redactor.redact_text(texts[index])
        results[index] = (result.value, result.stats.rule_hits)

    threads = [threading.Thread(target=work, args=(index,)) for index in range(len(texts))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert [results[index] for index in range(len(texts))] == expected
