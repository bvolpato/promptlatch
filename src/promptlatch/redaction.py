from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import threading
from bisect import bisect_right
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import import_module
from typing import Any

from detect_secrets.custom_types import NamedIO

from promptlatch.config import RedactionConfig, RuleConfig
from promptlatch.patterns import BUILTIN_PATTERNS, SENSITIVE_FIELD_RE, STRICT_SENSITIVE_FIELD_RE

MASK = "[REDACTED_SECRET]"

# detect-secrets keeps plugin settings in process-wide state.
_DETECT_SECRETS_LOCK = threading.Lock()
_ENTROPY_PLUGINS = frozenset({"Base64HighEntropyString", "HexHighEntropyString"})
# Regex plugins checked to report only matches of their own denylist patterns.
# A plugin outside this set turns the line gate off, so every line is scanned.
_GATED_REGEX_PLUGINS = frozenset(
    {
        "AWSKeyDetector",
        "ArtifactoryDetector",
        "AzureStorageKeyDetector",
        "BasicAuthDetector",
        "CloudantDetector",
        "DiscordBotTokenDetector",
        "GitHubTokenDetector",
        "IbmCloudIamDetector",
        "IbmCosHmacDetector",
        "JwtTokenDetector",
        "MailchimpDetector",
        "NpmDetector",
        "PrivateKeyDetector",
        "SendGridDetector",
        "SlackDetector",
        "SoftlayerDetector",
        "SquareOAuthDetector",
        "StripeDetector",
        "TwilioKeyDetector",
    }
)
# Each keyword the keyword plugin reacts to contains one of these, in any case.
_KEYWORD_LITERALS = ("key", "pass", "token", "pwd", "secret", "contrase")
_ASCII_IGNORECASE_TRANSLATION = str.maketrans({"İ": "i", "ı": "i", "ſ": "s", "K": "k"})
_STRING_ANCHOR_RE = re.compile(r"\\[AZz]")
_ASSIGNMENT_SEPARATOR = re.compile(r"[:=]")
_ASSIGNED_SECRET_PATTERN = dict(BUILTIN_PATTERNS)["assigned_secret"]
_ASCII_ASSIGNMENT_CANDIDATES = {
    _ASSIGNED_SECRET_PATTERN: re.compile(
        r"[^a-z0-9_.-]((?>[a-z0-9_.-]*?"
        r"(?:key|secret|password|passwd|pwd|token|credential|url))[a-z0-9_.-]*+)"
        r"[\"']?\s*[:=]"
    ),
    dict(BUILTIN_PATTERNS)["auth_header"]: re.compile(
        r"[^a-z0-9_.-]((?:authorization|proxy-authorization|x-api-key|api-key|"
        r"x-auth-token|x-auth-key|cf-access-token))[\"']?\s*[:=]"
    ),
}
_ASSIGNMENT_FIELD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-İıſK"
)

# Scan results are kept per string, so repeated text is scanned once.
_CACHE_MAX_ENTRIES = 16_384
_CACHE_MAX_CHARS = 8_000_000


def _ascii_ignorecase(value: str) -> str:
    if value.isascii():
        return value.lower()
    return value.translate(_ASCII_IGNORECASE_TRANSLATION).lower()


@dataclass
class RedactionStats:
    redactions: int = 0
    rule_hits: dict[str, int] = field(default_factory=dict)

    def add(self, name: str, count: int) -> None:
        if count <= 0:
            return
        self.redactions += count
        self.rule_hits[name] = self.rule_hits.get(name, 0) + count

    def merge(self, other: RedactionStats) -> None:
        for name, count in other.rule_hits.items():
            self.add(name, count)


@dataclass
class RedactionResult:
    value: Any
    stats: RedactionStats


class RedactionKeyCollisionError(ValueError):
    """Raised when distinct mapping keys become identical after redaction."""


_RuleHits = tuple[tuple[str, int], ...]


class _ScanCache:
    """Bounded, thread-safe record of scan results by string.

    Keys are digests, so the cache never keeps unredacted input in memory. The
    digest is an HMAC under a random key that exists only in this process, so a
    key cannot be matched against guessed input outside of it.
    """

    def __init__(self, max_entries: int, max_chars: int) -> None:
        self._max_entries = max_entries
        self._max_chars = max_chars
        self._chars = 0
        self._entries: OrderedDict[bytes, tuple[str | None, _RuleHits]] = OrderedDict()
        self._lock = threading.Lock()
        self._secret = os.urandom(32)

    def context_key(self, context: bytes) -> bytes:
        return hmac.digest(self._secret, context, "sha256")

    def key(self, value: str, *, secret: bytes | None = None) -> bytes:
        data = value.encode("utf-8", "surrogatepass")
        return hmac.digest(self._secret if secret is None else secret, data, "sha256")[:16]

    def get(self, key: bytes) -> tuple[str | None, _RuleHits] | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                self._entries.move_to_end(key)
            return entry

    def put(self, key: bytes, redacted: str | None, hits: _RuleHits) -> None:
        size = len(key) + len(redacted or "")
        if size > self._max_chars:
            return
        with self._lock:
            previous = self._entries.pop(key, None)
            if previous is not None:
                self._chars -= len(key) + len(previous[0] or "")
            self._entries[key] = (redacted, hits)
            self._chars += size
            while len(self._entries) > self._max_entries or self._chars > self._max_chars:
                old_key, (old_redacted, _) = self._entries.popitem(last=False)
                self._chars -= len(old_key) + len(old_redacted or "")


@dataclass(frozen=True)
class _LineGate:
    """Selects the lines that a detect-secrets plugin can match.

    Every gated plugin reports only text that one of these patterns matches, or
    a line that holds a keyword. All other lines produce no result, so the
    per-line scan can skip them.
    """

    patterns: tuple[re.Pattern[str], ...]
    keyword_patterns: tuple[re.Pattern[str], ...]
    requirements: tuple[_RegexRequirements, ...]
    keyword_requirements: tuple[_RegexRequirements, ...]
    keyword_locator: re.Pattern[str] | None
    forward_keywords: frozenset[re.Pattern[str]]

    def _keyword_match(self, line: str, folded: str) -> bool:
        if self.keyword_locator is None or len(line) < 4096 or not line.isascii():
            return any(
                requirements.possible(line, len(line), folded) and pattern.search(line)
                for pattern, requirements in zip(
                    self.keyword_patterns, self.keyword_requirements, strict=True
                )
            )
        eligible = [
            pattern
            for pattern, requirements in zip(
                self.keyword_patterns, self.keyword_requirements, strict=True
            )
            if requirements.possible(line, len(line), folded)
        ]
        forward = [pattern for pattern in eligible if pattern in self.forward_keywords]
        if not forward:
            return any(pattern.search(line) for pattern in eligible)
        if any(
            pattern.search(line) for pattern in eligible if pattern not in self.forward_keywords
        ):
            return True
        position = 0
        while candidate := self.keyword_locator.search(folded, position):
            if any(pattern.match(line, candidate.start()) for pattern in forward):
                return True
            # Resume after the start, retaining matches inside the previous prefix.
            position = candidate.start() + 1
        return False

    def candidates(self, lines: list[str]) -> list[str]:
        text = "\n".join(lines)
        folded_text = _ascii_ignorecase(text)
        longest_word = max(map(len, text.split()), default=0)
        marked: set[int] = set()
        starts: list[int] = []
        for pattern, requirements in zip(self.patterns, self.requirements, strict=True):
            if not requirements.possible(text, longest_word, folded_text):
                continue
            for match in pattern.finditer(text):
                if not starts:
                    offset = 0
                    for line in lines:
                        starts.append(offset)
                        offset += len(line) + 1
                first = bisect_right(starts, match.start()) - 1
                last = bisect_right(starts, max(match.start(), match.end() - 1)) - 1
                marked.update(range(first, last + 1))
                if len(marked) == len(lines):
                    return lines
        if any(literal in folded_text for literal in _KEYWORD_LITERALS):
            for index, line in enumerate(lines):
                if index not in marked:
                    if not any(quote in line for quote in "\"'`"):
                        continue
                    folded = _ascii_ignorecase(line)
                    if any(
                        literal in folded for literal in _KEYWORD_LITERALS
                    ) and self._keyword_match(line, folded):
                        marked.add(index)
        return [lines[index] for index in sorted(marked)]


@lru_cache(maxsize=1)
def _detect_secrets_plugins() -> tuple[type, ...]:
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    return tuple(
        plugin_type
        for plugin_type in get_mapping_from_secret_type_to_class().values()
        if plugin_type.__name__ not in _ENTROPY_PLUGINS
    )


@lru_cache(maxsize=1)
def _line_gate() -> _LineGate | None:
    """Build the gate, or return None when a plugin is not known to be gateable."""
    from detect_secrets.plugins.keyword import (
        DENYLIST,
        DENYLIST_REGEX,
        QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP,
        KeywordDetector,
    )

    patterns: list[re.Pattern[str]] = []
    for plugin_type in _detect_secrets_plugins():
        if plugin_type is KeywordDetector:
            if not all(any(literal in word for literal in _KEYWORD_LITERALS) for word in DENYLIST):
                return None
            continue
        if plugin_type.__name__ not in _GATED_REGEX_PLUGINS:
            return None
        denylist = tuple(plugin_type().denylist)
        if not denylist:
            return None
        for regex in denylist:
            # The gate searches all lines as one text. A string anchor would
            # then match at different places than in a single line.
            if _STRING_ANCHOR_RE.search(regex.pattern):
                return None
            patterns.append(re.compile(regex.pattern, regex.flags | re.MULTILINE))
    keyword_patterns = tuple(QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP)
    locator = None
    forward_keywords: frozenset[re.Pattern[str]] = frozenset()
    denylist_source = "(" + "|".join(DENYLIST) + r")\w*"
    if denylist_source == DENYLIST_REGEX:
        prefixes = [_literal_prefix(re.compile(word)) for word in DENYLIST]
        if prefixes and all(prefixes):
            source = "|".join(sorted({re.escape(prefix.lower()) for prefix in prefixes if prefix}))
            locator = re.compile(source)
            forward_keywords = frozenset(
                pattern
                for pattern in keyword_patterns
                if pattern.pattern.startswith(DENYLIST_REGEX)
                and _starts_with_keyword_group(pattern)
                and not pattern.flags & ~(re.IGNORECASE | re.UNICODE)
            )
    return _LineGate(
        tuple(patterns),
        keyword_patterns,
        tuple(_regex_requirements(pattern) for pattern in patterns),
        tuple(_regex_requirements(pattern) for pattern in QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP),
        locator,
        forward_keywords,
    )


@dataclass(frozen=True)
class _RegexRequirements:
    literals: tuple[str, ...] = ()
    runs: tuple[re.Pattern[str], ...] = ()
    minimum_word_length: int = 0
    ignorecase_literals: tuple[str, ...] = ()
    alternatives: tuple[tuple[tuple[str, bool], ...], ...] = ()
    folded_runs: tuple[re.Pattern[str], ...] = ()

    def possible(self, text: str, longest_word: int, folded_text: str | None = None) -> bool:
        if folded_text is None:
            folded_text = (
                _ascii_ignorecase(text)
                if self.ignorecase_literals or self.alternatives or self.folded_runs
                else text
            )
        if not (longest_word >= self.minimum_word_length):
            return False
        for literal in self.literals:
            if literal not in text:
                return False
        for literal in self.ignorecase_literals:
            if literal not in folded_text:
                return False
        for group in self.alternatives:
            for literal, ignorecase in group:
                if literal in (folded_text if ignorecase else text):
                    break
            else:
                return False
        for pattern in self.runs:
            if not pattern.search(text):
                return False
        return not self.folded_runs or all(
            pattern.search(folded_text) for pattern in self.folded_runs
        )


def _regex_requirements(pattern: re.Pattern[str]) -> _RegexRequirements:
    """Find mandatory substrings, retaining native regexes for every actual match.

    The optional stdlib parser optimization fails open if its private API changes.
    Literal runs stop at every structural boundary. Optional repetitions and
    lookarounds contribute nothing; branches keep only requirements common to all.
    """

    def nonspace_character_class(tokens: Any) -> str | None:
        if len(tokens) != 1:
            return None
        operation, argument = tokens[0]
        if str(operation) == "LITERAL":
            return re.escape(chr(argument)) if not chr(argument).isspace() else None
        if str(operation) != "IN":
            return None
        parts: list[str] = []
        class_tokens = argument
        for operation, argument in class_tokens:
            name = str(operation)
            if name == "LITERAL":
                if chr(argument).isspace():
                    return None
                parts.append(re.escape(chr(argument)))
            elif name == "RANGE":
                if argument[1] > 127 or any(
                    chr(codepoint).isspace() for codepoint in range(argument[0], argument[1] + 1)
                ):
                    return None
                parts.append(f"{re.escape(chr(argument[0]))}-{re.escape(chr(argument[1]))}")
            else:
                return None
        return "[" + "".join(parts) + "]" if parts else None

    def folded_ascii_class(tokens: Any) -> str | None:
        if len(tokens) != 1:
            return None
        operation, argument = tokens[0]
        if str(operation) == "LITERAL":
            members = [(operation, argument)]
        elif str(operation) == "IN":
            members = argument
        else:
            return None
        characters: set[str] = set()
        for operation, argument in members:
            if str(operation) == "LITERAL":
                codes = range(argument, argument + 1)
            elif str(operation) == "RANGE":
                codes = range(argument[0], argument[1] + 1)
            else:
                return None
            if codes.stop > 128:
                return None
            characters.update(chr(code).lower() for code in codes)
        if not characters or any(character.isspace() for character in characters):
            return None
        return "[" + "".join(re.escape(character) for character in sorted(characters)) + "]"

    def repeated_pairs(tokens: Any, flags: int) -> tuple[tuple[str, bool], ...] | None:
        if len(tokens) != 1:
            return None
        operation, argument = tokens[0]
        members = [(operation, argument)] if str(operation) == "LITERAL" else argument
        if str(operation) not in {"LITERAL", "IN"}:
            return None
        characters: set[str] = set()
        for operation, argument in members:
            if str(operation) != "LITERAL" or argument > 127:
                return None
            character = chr(argument)
            if flags & re.IGNORECASE and character.lower() != character.upper():
                return None
            characters.add(character)
        if not characters or len(characters) ** 2 > 8:
            return None
        return tuple(sorted((left + right, False) for left in characters for right in characters))

    def required(
        tokens: Any, flags: int
    ) -> tuple[
        set[tuple[str, bool]],
        set[tuple[str, int, int, bool]],
        set[tuple[tuple[str, bool], ...]],
    ]:
        literals: set[tuple[str, bool]] = set()
        runs: set[tuple[str, int, int, bool]] = set()
        alternatives: set[tuple[tuple[str, bool], ...]] = set()
        pending: list[str] = []

        def flush() -> None:
            if pending and (
                len(pending) >= 2 or (not pending[0].isalnum() and not pending[0].isspace())
            ):
                literal = "".join(pending)
                ignorecase = bool(flags & re.IGNORECASE)
                if not ignorecase or literal.isascii():
                    literals.add((literal.lower() if ignorecase else literal, ignorecase))
            pending.clear()

        for operation, argument in tokens:
            name = str(operation)
            if name == "LITERAL":
                pending.append(chr(argument))
                continue
            flush()
            if name == "SUBPATTERN":
                _, added, removed, child = argument
                child_literals, child_runs, child_alternatives = required(
                    child, (flags | added) & ~removed
                )
                literals.update(child_literals)
                runs.update(child_runs)
                alternatives.update(child_alternatives)
            elif name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
                minimum, _, child = argument
                if minimum:
                    child_literals, child_runs, child_alternatives = required(child, flags)
                    literals.update(child_literals)
                    runs.update(child_runs)
                    alternatives.update(child_alternatives)
                    if minimum >= 2 and (pairs := repeated_pairs(child, flags)) is not None:
                        alternatives.add(pairs)
                    folded = folded_ascii_class(child) if flags & re.IGNORECASE else None
                    source = folded or nonspace_character_class(child)
                    if minimum >= 24 and source is not None:
                        run_flags = flags & ~re.IGNORECASE if folded else flags
                        runs.add((f"{source}{{{minimum}}}", run_flags, minimum, folded is not None))
            elif name == "BRANCH":
                branches = [required(branch, flags) for branch in argument[1]]
                if branches:
                    literals.update(set.intersection(*(item[0] for item in branches)))
                    runs.update(set.intersection(*(item[1] for item in branches)))
                    alternatives.update(set.intersection(*(item[2] for item in branches)))
                    choices: list[set[tuple[str, bool]]] = []
                    for child_literals, _, child_alternatives in branches:
                        if child_literals:
                            choices.append(
                                {
                                    max(
                                        child_literals,
                                        key=lambda literal: (len(literal[0]), literal),
                                    )
                                }
                            )
                        elif child_alternatives:
                            choices.append(
                                set(
                                    max(
                                        child_alternatives,
                                        key=lambda group: min(len(item[0]) for item in group),
                                    )
                                )
                            )
                        else:
                            break
                    if len(choices) == len(branches):
                        alternatives.add(tuple(sorted(set.union(*choices))))
            elif name not in {
                "LITERAL",
                "IN",
                "ANY",
                "NOT_LITERAL",
                "AT",
                "ASSERT",
                "ASSERT_NOT",
                "GROUPREF",
            }:
                raise ValueError("unsupported regex parser operation")
        flush()
        return literals, runs, alternatives

    try:
        parsed = import_module("re._parser").parse(pattern.pattern, pattern.flags)
        literals, runs, alternatives = required(parsed, pattern.flags)
        return _RegexRequirements(
            tuple(
                sorted(
                    (literal for literal, folded in literals if not folded), key=len, reverse=True
                )
            ),
            tuple(
                re.compile(source, flags) for source, flags, _, folded in sorted(runs) if not folded
            ),
            max((minimum for _, _, minimum, _ in runs), default=0),
            tuple(
                sorted((literal for literal, folded in literals if folded), key=len, reverse=True)
            ),
            tuple(sorted(alternatives)),
            tuple(re.compile(source, flags) for source, flags, _, folded in sorted(runs) if folded),
        )
    except Exception:
        return _RegexRequirements()


def _starts_with_keyword_group(pattern: re.Pattern[str]) -> bool:
    try:
        parsed = import_module("re._parser").parse(pattern.pattern, pattern.flags)
        operation, argument = parsed[0]
        return str(operation) == "SUBPATTERN" and argument[0] == 1
    except Exception:
        return False


def _literal_prefix(pattern: re.Pattern[str]) -> str | None:
    """Return text that every match of a case-sensitive pattern starts with."""
    if pattern.flags & re.IGNORECASE:
        return None
    literal: list[str] = []
    try:
        parsed = import_module("re._parser").parse(
            pattern.pattern.removeprefix(r"\b"), pattern.flags
        )
        for operation, argument in parsed:
            if str(operation) != "LITERAL":
                break
            char = chr(argument)
            if not char.isascii() or not (char.isalnum() or char in "-_ "):
                break
            literal.append(char)
    except Exception:
        return None
    return "".join(literal) if len(literal) >= 2 else None


_BUILTIN_PREFIXES = {name: _literal_prefix(pattern) for name, pattern in BUILTIN_PATTERNS}
_BUILTIN_REQUIREMENTS = {}
for _name, _pattern in BUILTIN_PATTERNS:
    if _BUILTIN_PREFIXES[_name] is not None or _name in {"assigned_secret", "auth_header"}:
        continue
    _requirements = _regex_requirements(_pattern)
    _BUILTIN_REQUIREMENTS[_name] = _RegexRequirements(
        literals=_requirements.literals,
        ignorecase_literals=_requirements.ignorecase_literals,
        alternatives=_requirements.alternatives,
    )


def _uses_builtin_config_transformers(transform: Any) -> bool:
    from detect_secrets.transformers import get_transformers
    from detect_secrets.transformers.config import ConfigFileTransformer, EagerConfigFileTransformer
    from detect_secrets.transformers.yaml import YAMLTransformer

    if getattr(transform, "__module__", None) != "detect_secrets.transformers":
        return False
    transformers = tuple(get_transformers())
    if tuple(type(transformer) for transformer in transformers) != (
        ConfigFileTransformer,
        EagerConfigFileTransformer,
        YAMLTransformer,
    ):
        return False
    eligible = tuple(
        type(transformer)
        for transformer in transformers
        if transformer.should_parse_file(_PromptText.name)
    )
    return eligible == (ConfigFileTransformer, EagerConfigFileTransformer)


def _invalid_ini(value: str) -> bool:
    for line in value.split("\n"):
        if not line or line[0].isspace() or line[0] in "#;":
            continue
        if ":" in line or "=" in line:
            continue
        if line.startswith("[") and line.rfind("]") > 1:
            continue
        # A column-zero line cannot continue a preceding option. Without a
        # section or delimiter, ConfigParser records an unconditional error.
        return True
    return False


def _config_transformers_cannot_parse(value: str, transform: Any) -> bool:
    """Reject only syntax that both installed INI transformers must reject."""
    return _uses_builtin_config_transformers(transform) and _invalid_ini(value)


class SecretRedactor:
    def __init__(self, config: RedactionConfig, *, _cache_from: SecretRedactor | None = None):
        self.config = config
        self.placeholder = config.placeholder or MASK
        self._custom_patterns = self._compile_custom_patterns(config.rules)
        self._cache = (
            _cache_from._cache
            if _cache_from is not None
            else _ScanCache(_CACHE_MAX_ENTRIES, _CACHE_MAX_CHARS)
        )
        self._clean_lines = (
            _cache_from._clean_lines
            if _cache_from is not None
            else _ScanCache(_CACHE_MAX_ENTRIES, _CACHE_MAX_ENTRIES * 16)
        )
        # Keyed namespaces isolate rules without retaining their values or patterns in the cache.
        self._cache_namespace = self._cache.key(
            json.dumps(
                [
                    self.placeholder,
                    [
                        (name, pattern.pattern, pattern.flags)
                        for name, pattern in self._custom_patterns
                    ],
                ]
            )
        )
        self._context_keys: dict[tuple[str, str], bytes] = {}

    def redact_payload(self, payload: Any) -> RedactionResult:
        stats = RedactionStats()
        if not self.config.enabled:
            return RedactionResult(payload, stats)
        return RedactionResult(self._walk(payload, stats), stats)

    def redact_text(self, text: str) -> RedactionResult:
        stats = RedactionStats()
        if not self.config.enabled:
            return RedactionResult(text, stats)
        return RedactionResult(self._redact_string(text, stats), stats)

    def _compile_custom_patterns(
        self, rules: list[RuleConfig]
    ) -> list[tuple[str, re.Pattern[str]]]:
        patterns: list[tuple[str, re.Pattern[str]]] = []
        for index, rule in enumerate(rules):
            name = rule.name or f"{rule.type}_{index}"
            if rule.type == "regex":
                patterns.append((name, re.compile(rule.value)))
                continue
            if len(rule.value) <= 16:
                tail = re.escape(rule.value)
                patterns.append(
                    (
                        name,
                        re.compile(
                            rf"(?<![A-Za-z0-9_./+-])[A-Za-z0-9_./+-]{{8,}}{tail}"
                            rf"(?![A-Za-z0-9_./+=-])"
                        ),
                    )
                )
            else:
                patterns.append((name, re.compile(re.escape(rule.value))))
        return patterns

    def _walk(self, value: Any, stats: RedactionStats) -> Any:
        if isinstance(value, str):
            return self._redact_string(value, stats)
        model_fields = self._model_fields(value)
        if model_fields is not None:
            return self._redact_model(value, model_fields, stats)
        if isinstance(value, list):
            return [self._walk(item, stats) for item in value]
        if isinstance(value, tuple):
            return tuple(self._walk(item, stats) for item in value)
        if isinstance(value, Mapping):
            redacted: dict[Any, Any] = {}
            for key, item in value.items():
                redacted_key = self._redact_string(key, stats) if isinstance(key, str) else key
                if redacted_key in redacted:
                    raise RedactionKeyCollisionError("mapping keys collide after redaction")
                redacted[redacted_key] = self._redact_field_value(key, item, stats)
            return redacted
        return value

    def _model_fields(self, value: Any) -> Mapping[str, Any] | None:
        model_fields = getattr(type(value), "model_fields", None)
        model_copy = getattr(value, "model_copy", None)
        if isinstance(model_fields, Mapping) and callable(model_copy):
            return model_fields
        return None

    def _redact_model(
        self,
        value: Any,
        model_fields: Mapping[str, Any],
        stats: RedactionStats,
        *,
        sensitive: bool = False,
        strict: bool = False,
    ) -> Any:
        updates: dict[str, Any] = {}
        for name in model_fields:
            try:
                item = getattr(value, name)
            except AttributeError:
                continue
            before = stats.redactions
            redacted = (
                self._redact_sensitive_field(item, stats, strict=strict)
                if sensitive
                else self._redact_field_value(name, item, stats)
            )
            if stats.redactions > before:
                updates[name] = redacted

        model_extra = getattr(value, "model_extra", None)
        if isinstance(model_extra, Mapping):
            for name in model_extra:
                if isinstance(name, str) and self._redact_string(name, RedactionStats()) != name:
                    raise ValueError("model extra key cannot be safely redacted")
            for name, item in model_extra.items():
                before = stats.redactions
                redacted = (
                    self._redact_sensitive_field(item, stats, strict=strict)
                    if sensitive
                    else self._redact_field_value(name, item, stats)
                )
                if stats.redactions > before:
                    updates[name] = redacted

        return value.model_copy(update=updates)

    def _redact_field_value(self, key: Any, value: Any, stats: RedactionStats) -> Any:
        if self._is_sensitive_field(key):
            return self._redact_sensitive_field(value, stats, strict=self._is_strict_field(key))
        return self._walk(value, stats)

    def _is_sensitive_field(self, key: Any) -> bool:
        if not isinstance(key, str):
            return False
        return SENSITIVE_FIELD_RE.search(self._normalized_field(key)) is not None

    def _is_strict_field(self, key: Any) -> bool:
        return (
            isinstance(key, str)
            and STRICT_SENSITIVE_FIELD_RE.search(self._normalized_field(key)) is not None
        )

    def _normalized_field(self, key: str) -> str:
        normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
        return re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", normalized)

    def _redact_sensitive_field(
        self, value: Any, stats: RedactionStats, *, strict: bool = False
    ) -> Any:
        if isinstance(value, str):
            if not value.strip() or (not strict and len(value.strip()) < 8):
                return value
            stats.add("sensitive_field", 1)
            return self.placeholder
        model_fields = self._model_fields(value)
        if model_fields is not None:
            return self._redact_model(
                value,
                model_fields,
                stats,
                sensitive=True,
                strict=strict,
            )
        if isinstance(value, list):
            return [self._redact_sensitive_field(item, stats, strict=strict) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redact_sensitive_field(item, stats, strict=strict) for item in value)
        if isinstance(value, Mapping):
            redacted: dict[Any, Any] = {}
            for key, item in value.items():
                redacted_key = self._redact_string(key, stats) if isinstance(key, str) else key
                if redacted_key in redacted:
                    raise RedactionKeyCollisionError("mapping keys collide after redaction")
                redacted[redacted_key] = self._redact_sensitive_field(item, stats, strict=strict)
            return redacted
        if strict and value is not None and not isinstance(value, bool):
            stats.add("sensitive_field", 1)
            return self.placeholder
        return value

    def _redact_string(self, value: str, stats: RedactionStats) -> str:
        context = (self.config.engine, self.config.redact_mode)
        secret = self._context_keys.get(context)
        if secret is None:
            secret = self._cache.context_key(
                self._cache_namespace + ":".join(context).encode("ascii")
            )
            self._context_keys[context] = secret
        key = self._cache.key(value, secret=secret)
        cached = self._cache.get(key)
        if cached is not None:
            redacted, hits = cached
            for name, count in hits:
                stats.add(name, count)
            return value if redacted is None else redacted
        found = RedactionStats()
        redacted = self._scan_string(value, found)
        self._cache.put(
            key,
            None if redacted == value else redacted,
            tuple(found.rule_hits.items()),
        )
        stats.merge(found)
        return redacted

    def _scan_string(self, value: str, stats: RedactionStats) -> str:
        if self.config.engine == "detect-secrets":
            value = self._run_detect_secrets(value, stats)
        for name, pattern in self._custom_patterns:
            value, count = pattern.subn(self._replacement, value)
            stats.add(name, count)
        folded_value: str | None = None
        for name, pattern in BUILTIN_PATTERNS:
            prefix = _BUILTIN_PREFIXES[name]
            if prefix is not None and prefix not in value:
                continue
            requirements = _BUILTIN_REQUIREMENTS.get(name)
            if requirements is not None:
                if folded_value is None:
                    folded_value = _ascii_ignorecase(value)
                if not requirements.possible(value, len(value), folded_value):
                    continue
            value, count = self._sub_builtin_pattern(name, pattern, value)
            stats.add(name, count)
            if count:
                folded_value = None
        return value

    def _run_detect_secrets(self, value: str, stats: RedactionStats) -> str:
        if not value.strip():
            return value
        from detect_secrets.core.scan import scan_line
        from detect_secrets.settings import transient_settings
        from detect_secrets.transformers import get_transformed_file

        from promptlatch._config_transform import _ConfigLines, supported, transform

        source = _PromptText(value)
        known_transformers = _uses_builtin_config_transformers(get_transformed_file) and supported()
        use_literal_transform = known_transformers
        cannot_transform = known_transformers and _invalid_ini(value)
        transformed = None
        if not cannot_transform:
            transformed = (
                transform(source) if use_literal_transform else get_transformed_file(source)
            )
        lines = transformed or value.splitlines()
        # PrivateKeyDetector can also inspect this relative filename. Keep its
        # original calls when an on-disk file could affect the result.
        gate = None if os.path.exists("adhoc-string-scan") else _line_gate()

        def candidates(lines: list[str]) -> list[str]:
            if gate is None:
                return lines
            return [
                line
                for line in gate.candidates(lines)
                if self._clean_lines.get(self._clean_lines.key(line)) is None
            ]

        lines = candidates(lines)
        eager_candidates: list[str] | None = (
            []
            if cannot_transform
            or (
                use_literal_transform
                and isinstance(transformed, _ConfigLines)
                and transformed.eager_equivalent
            )
            else None
        )

        def eager() -> list[str]:
            source.seek(0)
            transformed = (
                transform(source, add_header=True)
                if use_literal_transform
                else get_transformed_file(source, use_eager_transformers=True)
            )
            return candidates(transformed or [])

        if not known_transformers:
            # Custom transformers may depend on global settings. Keep their
            # original phase before entering transient plugin settings.
            eager_candidates = eager()
        if not lines:
            if eager_candidates is None:
                eager_candidates = eager()
            if not eager_candidates:
                return value
        plugin_config = [
            {"name": plugin_type.__name__} for plugin_type in _detect_secrets_plugins()
        ]
        with _DETECT_SECRETS_LOCK, transient_settings({"plugins_used": plugin_config}):

            def scan(lines: list[str]) -> list[Any]:
                found: list[Any] = []
                for line in lines:
                    key = self._clean_lines.key(line) if gate is not None else None
                    if key is not None and self._clean_lines.get(key) is not None:
                        continue
                    secrets = list(scan_line(line))
                    if key is not None and not secrets:
                        self._clean_lines.put(key, None, ())
                    found.extend(secrets)
                return found

            found_secrets = scan(lines)
            if not found_secrets:
                if eager_candidates is None:
                    eager_candidates = eager()
                found_secrets = scan(eager_candidates)

        for found_secret in found_secrets:
            secret_value = getattr(found_secret, "secret_value", None)
            if not secret_value:
                continue
            value, count = self._replace_detected_secret(secret_value, value)
            stats.add(f"detect_secrets:{found_secret.type}", count)
        return value

    def _replace_detected_secret(self, secret_value: str, value: str) -> tuple[str, int]:
        if "," not in secret_value:
            return re.subn(re.escape(secret_value), self._replacement, value)

        total = 0
        for segment in secret_value.split(","):
            candidate = segment.strip().strip("\"'")
            if not candidate:
                continue
            value, count = re.subn(re.escape(candidate), self._replacement, value)
            total += count

        if total:
            return value, total
        return re.subn(re.escape(secret_value), self._replacement, value)

    def _sub_builtin_pattern(
        self, name: str, pattern: re.Pattern[str], value: str
    ) -> tuple[str, int]:
        if name in {"assigned_secret", "auth_header"}:
            return self._sub_assignment_pattern(pattern, value)
        if name == "signed_url_query_param":
            return pattern.subn(lambda match: f"{match.group(1)}{self.placeholder}", value)
        if name == "url_credentials":
            return pattern.subn(
                lambda match: f"{match.group(1)}{self.placeholder}{match.group(3)}", value
            )
        return pattern.subn(self._replacement, value)

    def _sub_assignment_pattern(self, pattern: re.Pattern[str], value: str) -> tuple[str, int]:
        """Locate assignments cheaply; keep the original regex as matching authority."""
        chunks: list[str] = []
        consumed = 0
        count = 0
        position = 0
        ascii_pattern = _ASCII_ASSIGNMENT_CANDIDATES.get(pattern) if value.isascii() else None
        check_field = (
            ascii_pattern is not None and pattern is _ASSIGNED_SECRET_PATTERN and len(value) >= 4096
        )
        # Consume a field boundary to scan each word once. Atomic keyword
        # selection and a possessive tail avoid rescanning rejected long fields.
        # The sentinel includes an assignment starting at offset zero.
        candidate_pattern = ascii_pattern or _ASSIGNMENT_SEPARATOR
        searchable = " " + value.lower() if ascii_pattern is not None else value
        while candidate := candidate_pattern.search(searchable, position):
            if ascii_pattern is not None:
                # Reuse the delimiter as a possible following field's boundary.
                position = candidate.end() - 1
                start = candidate.start(1) - 1
                if check_field:
                    field = candidate.group(1)
                    if not (
                        "secret" in field
                        or "passw" in field
                        or "pwd" in field
                        or "token" in field
                        or "credential" in field
                        or "api" in field
                        or "private" in field
                        or "webhook" in field
                    ):
                        continue
            else:
                position = candidate.end()
                start = candidate.start()
                while start and value[start - 1].isspace():
                    start -= 1
                if start and value[start - 1] in "\"'":
                    start -= 1
                field_end = start
                while start and value[start - 1] in _ASSIGNMENT_FIELD_CHARS:
                    start -= 1
                if start == field_end:
                    continue
            starts = (start - 1, start) if start and value[start - 1] in "\"'" else (start,)
            for candidate in starts:
                if candidate < consumed:
                    continue
                match = pattern.match(value, candidate)
                if match is None:
                    continue
                chunks.append(value[consumed : match.start()])
                chunks.append(
                    f"{match.group('prefix')}{self.placeholder}{match.group('value_quote')}"
                )
                consumed = match.end()
                position = consumed
                count += 1
                break
        if not count:
            return value, 0
        chunks.append(value[consumed:])
        return "".join(chunks), count

    def _replacement(self, match: re.Match[str]) -> str:
        secret = match.group(0)
        if self.config.redact_mode == "full" or len(secret) <= 12:
            return self.placeholder
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]
        return f"{secret[:4]}...{secret[-4:]}:{digest}"


class _PromptText(io.StringIO, NamedIO):
    name = "promptlatch-input"
