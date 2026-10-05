from __future__ import annotations

import random
import re

import pytest
from detect_secrets.transformers import config as native
from detect_secrets.transformers import get_transformed_file

from promptlatch import _config_transform
from promptlatch.redaction import _PromptText


@pytest.mark.parametrize("eager", [False, True])
@pytest.mark.parametrize(
    "text",
    [
        "",
        "plain prose",
        "password=firstfixture\nsecond=nextfixture",
        "[section]\nkey = value\nnext=value2",
        "[section]\nkey==value\nnext=value2",
        "[section]\nkey=:=value\nnext=value2",
        "[section]\nkey=:value\nnext=value2",
        "[section]\nkey=\n  first\n\n  second\nnext=last",
        "[section]\nkey=first\n  # comment\n  second\nnext=last",
        "[section]\n# pragma: allowlist nextline secret\npassword=fixturevalue\nother=value",
        "[section]\nkey=first\n; pragma: allowlist nextline secret\nkey2=second",
        "[DEFAULT]\nfirst=one\n[section]\nsecond=two\n[other]\nthird=three",
        "[DEFAULT]\nfirst=one\n[section]\nfirst=override\n[other]\nthird=three",
        "[DEFAULT]\nonly=default",
        "[section]\nkey=first\nkey=second",
        "[section]\nkey=%(other)s\nother=interpolated",
        "[section]\nkey=%(missing)s",
        "[section]\nkey=100%",
        '[section]\nkey=\'quoted\'\nother="quoted"\nembedded=a"b',
        "[section]\nkey=first\rsecond",
        "[section]\nkey=first\vsecond",
        "[section]\nkey=first\u0085second",
        "[section]\nκλειδί=value\nſecret=value2",
        "[section]\nkey=\nother=last\n# trailing comment",
        "[global]\nkey=value\n[section]\nother=next",
    ],
)
def test_literal_transform_matches_native_output(text: str, eager: bool) -> None:
    expected = get_transformed_file(_PromptText(text), use_eager_transformers=eager)
    actual = _config_transform.transform(_PromptText(text), add_header=eager)
    assert actual == expected
    if actual is not None and actual.eager_equivalent:
        eager_output = get_transformed_file(_PromptText(text), use_eager_transformers=True)
        assert eager_output is None or eager_output == actual


def test_first_value_matcher_preserves_separator_backtracking() -> None:
    rng = random.Random(442)
    keys = ["key", "key_suffix", "a.b", "κλειδί", "[brackets]", "key+special"]
    values = ["", "value", ":", "=", ":=value", "==", ":=:", " value", "'quoted'"]
    for _ in range(2_000):
        key = rng.choice(keys)
        value = rng.choice(values)
        line = rng.choice(("", key, "wrong", "key_suffix"))
        line += "".join(rng.choices(" :=", k=rng.randrange(8)))
        line += rng.choice((value, "other", "=" + value, ":" + value, " "))
        line = line.strip()
        expected = bool(re.match(rf"^\s*{re.escape(key)}[ :=]+{re.escape(value)}", line))
        assert _config_transform._first_value_matches(line, key, value) == expected


def test_literal_transform_matches_randomized_native_iteration() -> None:
    rng = random.Random(625)
    fragments = [
        "[section]", "[other]", "[DEFAULT]", "key=value", "next==value", "password=:value",
        "empty=", "  continuation", "", "# comment", "; comment",
        "# pragma: allowlist nextline secret", "  ; pragma: allowlist nextline secret",
        "value=%(key)s", "value=%(missing)s", "description='first\"second'",
    ]  # fmt: skip
    for _ in range(600):
        text = "\n".join(rng.choices(fragments, k=rng.randrange(1, 14)))
        for eager in (False, True):
            assert _config_transform.transform(_PromptText(text), add_header=eager) == (
                get_transformed_file(_PromptText(text), use_eager_transformers=eager)
            )


def test_adapter_is_disabled_when_native_parser_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native.IniFileParser, "_get_value_and_line_offset", lambda *_args: [])
    assert not _config_transform.supported()


def test_adapter_is_disabled_for_unreviewed_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_config_transform, "_SUPPORTED_VERSION", False)
    assert not _config_transform.supported()
