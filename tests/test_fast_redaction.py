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
    _config_transformers_cannot_parse,
    _line_gate,
    _literal_prefix,
    _regex_requirements,
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
            patch.setattr(redaction, "_BUILTIN_REQUIREMENTS", {})
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

    # Merely discussing keys cannot satisfy the keyword detector's regexes.
    assert gate.candidates(lines) == [lines[3]]
    assert gate.candidates(["plain text", "x = 1"]) == []


@pytest.mark.parametrize(
    ("source", "examples"),
    [
        (r"BEGIN(?: RSA | EC | )PRIVATE KEY", ["BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY"]),
        (r"a{1,2}c{1,2}b", ["acb", "accb", "aacb", "aaccb"]),
        (r"(?:alpha|beta)tail", ["alphatail", "betatail"]),
        (r"(?:optional)?required", ["required", "optionalrequired"]),
        (r"(?i:KEY)CaseSensitive", ["KeyCaseSensitive", "KEYCaseSensitive"]),
        (r"(?i)[a-z0-9_-]{44}", ["ı" * 44, "ſ" * 44, "K" * 44, "İ" * 44]),
        (r"(?:[a-z]{32}|[0-9]{32})suffix", ["a" * 32 + "suffix", "1" * 32 + "suffix"]),
        (r"(?=prefix)prefix.*end", ["prefix-end", "prefix123end"]),
        (r"[^\n]{40}", ["x " * 20]),
        (r"[\t-z]{40}", ["x " * 20]),
        (r"(?i:up(?-i:Down))tail", ["UPDowntail", "upDowntail"]),
        (r"(?i)apikey", ["apİkey", "apıkey", "apiKey", "APIKEY"]),
        (r"(?i)secret", ["ſecret", "SECRET"]),
        (r"(?i)(?:first|second)key", ["fİrſtKey", "ſecondkey"]),
        (r"(?i:HEAD)(?:Upper|lower)Tail", ["headUpperTail", "HEADlowerTail"]),
        (r"(?i)(?:[0-9]+|prefix)tail", ["123TAIL", "PREFIXtail"]),
        (r"(?i)äßkey", ["ÄßKEY"]),
        (r"(?i)[A-z]{24}", ["İ" * 24, "ſ" * 24, "_" * 24]),
        (r"(?i:[A-Z+/]{24})(?-i:Suffix)", ["ſ" * 24 + "Suffix", "+" * 24 + "Suffix"]),
        (r"(?i)[éa-z]{24}", ["É" * 24, "İ" * 24]),
        (r"(?:prefix|(?:other|fallback))tail", ["prefixtail", "othertail", "fallbacktail"]),
        (r"(?:[0-9]+|(?:other|fallback))tail", ["123tail", "othertail"]),
        (r"[!=]{2,3}", ["!!", "!=", "=!", "==", "==="]),
        (r"a{2}", ["aa"]),
        (r"[ab]{2}", ["ab", "ba"]),
        (r"(?i)[!=]{2,3}", ["!!", "!=", "=!", "=="]),
        (r"[A-Z]{2}", ["AB", "ZZ"]),
        (r"(?i)[ab]{2}", ["AB", "aB"]),
        (r"[^=]{2}", ["ab"]),
        (r"[\wé]{2}", ["éa"]),
        (r"[abc]{2}", ["ab", "cc"]),
        (r"[!=]{0,2}tail", ["tail", "=tail"]),
    ],
)
def test_regex_requirements_never_exclude_native_matches(source: str, examples: list[str]) -> None:
    pattern = re.compile(source)
    requirements = _regex_requirements(pattern)
    for example in examples:
        assert pattern.search(example)
        text = f"before {example} after"
        assert requirements.possible(text, max(map(len, text.split()), default=0))


def test_repeated_operator_requirements_reject_single_delimiters() -> None:
    required = _regex_requirements(re.compile(r"[!=]{2,3}"))
    assert not required.possible("item = value!", 20)
    assert not required.possible('{"max_tokens": 4096}', 20)
    optional = _regex_requirements(re.compile(r"[!=]{1,3}"))
    assert optional.possible("=", 1)


@pytest.mark.parametrize(
    "snippet",
    [
        'api_key: "fixturevalue"',
        'password = "fixturevalue"',
        'api_key => "fixturevalue"',
        'private_key "fixturevalue";',
        'data.put("password", "fixturevalue")',
        '"fixturevalue" != api_key',
        'recaptcha_x_password: "fixturevalue" more_key',
        '_password: "fixturevalue"',
        'recaptcha_first_key words recaptcha_second_key: "fixturevalue"',
        'paſſword = "fixturevalue"',
        'toKen: "fixturevalue"',
        'contraseña: "fixturevalue"',
        '{"max_tokens": 4096, "item_key": "fixture"}',
        'context = "Discuss token limits and cache keys"',
        "password" + "x" * 5000 + ' "fixturevalue"',
    ],
)
def test_long_line_keyword_gate_matches_native_search(snippet: str) -> None:
    gate = _line_gate()
    assert gate is not None
    line = "context. " * 600 + "context = 1; " + snippet
    expected = any(pattern.search(line) for pattern in gate.keyword_patterns)
    assert gate._keyword_match(line, redaction._ascii_ignorecase(line)) == expected


def test_keyword_locator_falls_back_when_denylist_source_is_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from detect_secrets.plugins import keyword

    monkeypatch.setattr(
        keyword, "DENYLIST", tuple(word for word in keyword.DENYLIST if word != "password")
    )
    _line_gate.cache_clear()
    try:
        gate = _line_gate()
        assert gate is not None
        line = "context. " * 600 + 'password = "fixturevalue"'
        assert gate._keyword_match(line, redaction._ascii_ignorecase(line))
    finally:
        _line_gate.cache_clear()


def test_keyword_locator_falls_back_for_an_unknown_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from detect_secrets.plugins import keyword

    pattern = re.compile(r'context.*token = "fixturevalue"')
    monkeypatch.setattr(keyword, "QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP", {pattern: 1})
    _line_gate.cache_clear()
    try:
        gate = _line_gate()
        assert gate is not None
        line = "context. " * 600 + 'token = "fixturevalue"'
        assert gate._keyword_match(line, redaction._ascii_ignorecase(line))
    finally:
        _line_gate.cache_clear()


@pytest.mark.parametrize(
    "suffix",
    [r':"fixture"|context:"fixture"', r'[](|]|context:"fixture"', r'(?# [ )|context:"fixture"'],
)
def test_keyword_locator_falls_back_for_a_top_level_alternative(
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
) -> None:
    from detect_secrets.plugins import keyword

    pattern = re.compile(keyword.DENYLIST_REGEX + suffix)
    monkeypatch.setattr(keyword, "QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP", {pattern: 0})
    _line_gate.cache_clear()
    try:
        gate = _line_gate()
        assert gate is not None
        line = "padding " * 600 + 'context:"fixture" key'
        assert pattern.search(line)
        assert gate._keyword_match(line, redaction._ascii_ignorecase(line))
    finally:
        _line_gate.cache_clear()


@pytest.mark.parametrize(
    "error", [ImportError, AttributeError, RuntimeError, AssertionError, KeyError]
)
def test_regex_requirements_fail_open_when_stdlib_parser_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    error: type[Exception],
) -> None:
    def unavailable(_name: str):
        raise error("stdlib parser unavailable")

    monkeypatch.setattr(redaction, "import_module", unavailable)
    requirements = _regex_requirements(re.compile(r"mandatory[a-z]{44}"))
    assert requirements.possible("unrelated text", 0)
    assert _literal_prefix(re.compile(r"mandatory[a-z]{44}")) is None


def test_regex_requirements_fail_open_for_unsupported_parser_operation() -> None:
    requirements = _regex_requirements(re.compile(r"(?>mandatory)[a-z]{44}"))
    assert requirements.possible("unrelated text", 0)


def test_later_builtin_rules_scan_placeholder_inserted_by_prior_rule() -> None:
    placeholder = "?X-Amz-" + "Signature=fixturevalue https://user:fixturepassword@host"
    text = "-----BEGIN PRIVATE " + "KEY-----\nfixture\n-----END PRIVATE " + "KEY-----"
    redactor = SecretRedactor(RedactionConfig(engine="basic", placeholder=placeholder))
    expected = text
    hits: dict[str, int] = {}
    for name, pattern in BUILTIN_PATTERNS:
        expected, count = redactor._sub_builtin_pattern(name, pattern, expected)
        if count:
            hits[name] = count

    actual = redactor.redact_text(text)
    assert actual.value == expected
    assert actual.stats.rule_hits == hits
    assert hits["private_key"] == hits["signed_url_query_param"] == 1
    assert hits["url_credentials"] > 0


@pytest.mark.parametrize("name", ["assigned_secret", "auth_header"])
def test_assignment_candidate_scanner_matches_original_substitution(name: str) -> None:
    pattern = dict(BUILTIN_PATTERNS)[name]
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    rng = random.Random(83)
    fields = [
        "password", "api-key", "client.secret", "authorization", "proxy-authorization",
        "X-Api-Key", "paſſword", "toKen", "credentıals", "apİ_key", "not_sensitive",
        "x_password_suffix", "session_token", "123token456", "_password", "foo/bar/password",
        "passwd", "pwd", "access_token", "refresh_tokens", "id_token", "auth-token",
        "private-key", "credentials", "webhook-url", "client-secrets", "api_keys",
        "cf-access-token", "x-auth-key", "x-auth-token",
    ]  # fmt: skip
    texts = [
        *(_generated_texts()),
        *(_fixture_texts()),
        '"password=abcdefgh',
        "'password=abcdefgh",
        'nonsense="password"=abcdefgh',
        "password='authorization=abcdefgh'",
        "password=abcdefgh:authorization=ijklmnop",
        '"password"\n\t= "abcdefgh"',
        "authorization: Bearer abcdefghijklmnop",
        "password=abcdefgh password=ijklmnop",
        "password = abcdefgh\npassword = abcdefgh",
        "password=" + "ab:cd=" * 2_000 + "; password=zyxwvuts",
        "İ prefix password=abcdefgh",
        "İ prefix authorization: Bearer abcdefghijklmnop",
        "unrelated fooİ=abcdefgh; credential=ijklmnop",
        "key" * 2_000 + ";=unrelated",
        "password='abcdefgh'password=zyxwvuts",
        'api-key="a"authorization=zyxwvuts',
        "password=authorization=abcdefgh",
    ]
    texts.extend(" " * 4096 + field + "=abcdefghijk" for field in fields)
    for _ in range(1_000):
        left_quote, right_quote, value_quote = (rng.choice(("", "'", '"')) for _ in range(3))
        secret = _run(rng, BASE64 + ":=._-", rng.randint(4, 60))
        texts.append(
            rng.choice(("", "before ", "K", "ı", "ſ", "[", "x/", "x-"))
            + left_quote
            + rng.choice(fields)
            + right_quote
            + rng.choice(("", " ", "\t", "\n", "\u0085", "\u2003"))
            + rng.choice((":", "=", "==", ":=", "=>"))
            + rng.choice(("", " ", "\n", "\t"))
            + value_quote
            + secret
            + rng.choice(("", value_quote, "; after", " password=zyxwvuts"))
        )
    for text in texts:
        expected = pattern.subn(
            lambda match: (
                f"{match.group('prefix')}{redactor.placeholder}{match.group('value_quote')}"
            ),
            text,
        )
        assert redactor._sub_builtin_pattern(name, pattern, text) == expected, text


def test_transformer_preflight_only_rejects_invalid_ini() -> None:
    from detect_secrets.transformers import get_transformed_file

    from promptlatch.redaction import _PromptText

    rng = random.Random(99)
    fragments = [
        "password=abcdefghi", "[section]", "[]odd]", "# comment", "; comment",
        "  continuation", "", "plain prose", "token: abcdefghi", "[DEFAULT]",
        "[header] trailing text", "password=abcdefghi\vcontinued", "\u2003continuation",
    ]  # fmt: skip
    texts = [
        "password=abcdefghi\vcontinued",
        "[]odd]\npassword=abcdefghi",
        "password=abcdefghi\n  continued",
        *("\n".join(rng.choices(fragments, k=rng.randint(1, 8))) for _ in range(300)),
    ]
    rejected = 0
    for text in texts:
        if not _config_transformers_cannot_parse(text, get_transformed_file):
            continue
        rejected += 1
        for eager in (False, True):
            assert get_transformed_file(_PromptText(text), use_eager_transformers=eager) is None
    assert rejected > 50


@pytest.mark.parametrize("separator", ["\r", "\v", "\f", "\u0085", "\u2028", "\u2029"])
def test_ini_eager_transformation_preserves_non_lf_separators(separator: str, full_scan) -> None:
    text = f"password=hello{separator}world"
    fast = _scan(text)
    assert fast == full_scan(text)
    assert "hello" not in fast[0]


def test_config_preflight_is_disabled_for_unknown_transformers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import detect_secrets.transformers as transformers

    class UnknownTransformer:
        def should_parse_file(self, _name: str) -> bool:
            return True

    monkeypatch.setattr(transformers, "get_transformers", lambda: [UnknownTransformer()])
    assert not _config_transformers_cannot_parse("plain prose", transformers.get_transformed_file)


def test_custom_eager_transformer_runs_before_transient_plugin_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import detect_secrets.transformers as transformers
    from detect_secrets.settings import get_settings, transient_settings

    observed: list[list[str]] = []
    clean = 'password="abcdef"'
    secret = 'password="c0mpl3xFixtureValue"'

    def transformed(source, *, use_eager_transformers: bool = False):
        if use_eager_transformers:
            observed.append([plugin["name"] for plugin in get_settings().json()["plugins_used"]])
            return [secret]
        return [clean]

    monkeypatch.setattr(transformers, "get_transformed_file", transformed)
    with transient_settings({"plugins_used": [{"name": "KeywordDetector"}]}):
        result = SecretRedactor(RedactionConfig(engine="detect-secrets")).redact_text(
            f"{clean}\n{secret}"
        )
    assert observed == [["KeywordDetector"]]
    assert "c0mpl3xFixtureValue" not in result.value


def test_modified_native_transformer_bypasses_preflight_and_keeps_settings_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from detect_secrets.settings import get_settings, transient_settings
    from detect_secrets.transformers.config import ConfigFileTransformer, EagerConfigFileTransformer

    observed: list[list[str]] = []
    value = "only-in-fixture-24680"

    def transformed(_self, _source):
        observed.append([plugin["name"] for plugin in get_settings().json()["plugins_used"]])
        return [f'password="{value}"']

    monkeypatch.setattr(ConfigFileTransformer, "parse_file", transformed)
    monkeypatch.setattr(EagerConfigFileTransformer, "parse_file", transformed)
    with transient_settings({"plugins_used": [{"name": "KeywordDetector"}]}):
        result = SecretRedactor(RedactionConfig(engine="detect-secrets")).redact_text(value)

    assert result.value == redaction.MASK
    assert result.stats.rule_hits == {"detect_secrets:Secret Keyword": 1}
    assert observed == [["KeywordDetector"], ["KeywordDetector"]]


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


def test_scan_cache_tracks_mutable_redaction_mode() -> None:
    config = RedactionConfig(engine="basic", redact_mode="partial")
    redactor = SecretRedactor(config)
    text = f"token {OPENAI_FAKE}"

    partial = redactor.redact_text(text)
    assert partial.value != text
    assert partial.value != f"token {redactor.placeholder}"

    config.redact_mode = "full"
    full = redactor.redact_text(text)

    assert full.value == f"token {redactor.placeholder}"
    assert full.stats.rule_hits == partial.stats.rule_hits


def test_scan_cache_tracks_mutable_engine() -> None:
    config = RedactionConfig(engine="basic")
    redactor = SecretRedactor(config)
    # Mailchimp format is covered by detect-secrets but not a built-in rule.
    text = next(sample for sample in _plugin_samples() if sample.startswith("mailchimp "))

    basic = redactor.redact_text(text)
    assert basic.value == text
    assert basic.stats.rule_hits == {}

    config.engine = "detect-secrets"
    detected = redactor.redact_text(text)

    assert text not in detected.value
    assert any(name.startswith("detect_secrets:") for name in detected.stats.rule_hits)


def test_clean_candidate_lines_are_cached_across_distinct_strings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from detect_secrets.core import scan as detect_scan

    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    clean_line = 'password="abcdef"'
    scanned: list[str] = []
    original = detect_scan.scan_line

    def counting(line: str):
        scanned.append(line)
        return original(line)

    monkeypatch.setattr(detect_scan, "scan_line", counting)
    first = redactor.redact_text(f"{clean_line}\ncontext alpha")
    second = redactor.redact_text(f"{clean_line}\ncontext beta")

    assert first.value == f"{clean_line}\ncontext alpha"
    assert second.value == f"{clean_line}\ncontext beta"
    assert scanned.count(clean_line) == 1


def test_positive_candidate_lines_keep_redaction_output_and_hit_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from detect_secrets.core import scan as detect_scan

    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    positive_line = 'password="REDACTED_SECRET"'
    scanned: list[str] = []
    original = detect_scan.scan_line

    def counting(line: str):
        scanned.append(line)
        return original(line)

    monkeypatch.setattr(detect_scan, "scan_line", counting)
    text = f"{positive_line}\n{positive_line}"
    first = redactor.redact_text(text)
    scans_after_first = len(scanned)
    repeated = redactor.redact_text(text)
    variant = redactor.redact_text(f"{text}\ncontext fixture")

    expected = 'password="[[REDACTED_SECRET]]"\npassword="[[REDACTED_SECRET]]"'
    assert first.value == expected
    assert first.stats.redactions == 4
    assert repeated.value == first.value
    assert repeated.stats.rule_hits == first.stats.rule_hits
    assert variant.stats.redactions == 4
    assert len(scanned) > scans_after_first


def test_clean_line_cache_is_disabled_when_line_gate_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from detect_secrets.core import scan as detect_scan

    monkeypatch.setattr(redaction, "_line_gate", lambda: None)
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    clean_line = "def fetch(key_id):"
    scanned: list[str] = []
    original = detect_scan.scan_line

    def counting(line: str):
        scanned.append(line)
        return original(line)

    monkeypatch.setattr(detect_scan, "scan_line", counting)
    redactor.redact_text(f"{clean_line}\ncontext alpha")
    redactor.redact_text(f"{clean_line}\ncontext beta")

    assert scanned.count(clean_line) == 2


def test_eager_only_candidate_is_scanned_after_raw_clean_line_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import detect_secrets.transformers as transformers
    from detect_secrets.core import scan as detect_scan

    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    clean_line = "description = token rotation"
    eager_line = 'password="REDACTED_SECRET"'
    scanned: list[str] = []
    original_scan = detect_scan.scan_line

    def transformed(source, *, use_eager_transformers: bool = False):
        if use_eager_transformers:
            return [eager_line] if "include eager" in source.getvalue() else []
        return [clean_line]

    def counting(line: str):
        scanned.append(line)
        return original_scan(line)

    monkeypatch.setattr(transformers, "get_transformed_file", transformed)
    monkeypatch.setattr(detect_scan, "scan_line", counting)
    redactor.redact_text("seed raw clean cache")
    result = redactor.redact_text('include eager password="REDACTED_SECRET"')

    assert eager_line in scanned
    assert result.value == 'include eager password="[REDACTED_SECRET]"'
    assert result.stats.rule_hits["detect_secrets:Secret Keyword"] > 0


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
        (r"foo[](|]|bar", None),
        (r"foo[](|]|foob", "foo"),
        (r"foo(?# [ )|bar", None),
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
