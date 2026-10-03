from __future__ import annotations

import hashlib
import io
import re
import threading
from bisect import bisect_right
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
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
_STRING_ANCHOR_RE = re.compile(r"\\[AZ]")

# Scan results are kept per string, so repeated text is scanned once.
_CACHE_MAX_ENTRIES = 16_384
_CACHE_MAX_CHARS = 8_000_000


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

    Keys are digests, so the cache never keeps unredacted input in memory.
    """

    def __init__(self, max_entries: int, max_chars: int) -> None:
        self._max_entries = max_entries
        self._max_chars = max_chars
        self._chars = 0
        self._entries: OrderedDict[bytes, tuple[str | None, _RuleHits]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def key(value: str) -> bytes:
        data = value.encode("utf-8", "surrogatepass")
        return hashlib.blake2b(data, digest_size=16).digest()

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

    def candidates(self, lines: list[str]) -> list[str]:
        text = "\n".join(lines)
        marked: set[int] = set()
        starts: list[int] = []
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                if not starts:
                    offset = 0
                    for line in lines:
                        starts.append(offset)
                        offset += len(line) + 1
                first = bisect_right(starts, match.start()) - 1
                last = bisect_right(starts, max(match.start(), match.end() - 1)) - 1
                marked.update(range(first, last + 1))
        folded_text = text.casefold()
        if any(literal in folded_text for literal in _KEYWORD_LITERALS):
            for index, line in enumerate(lines):
                if index not in marked:
                    folded = line.casefold()
                    if any(literal in folded for literal in _KEYWORD_LITERALS):
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
    from detect_secrets.plugins.keyword import DENYLIST, KeywordDetector

    patterns: list[re.Pattern[str]] = []
    for plugin_type in _detect_secrets_plugins():
        if issubclass(plugin_type, KeywordDetector):
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
    return _LineGate(tuple(patterns))


def _has_top_level_alternation(source: str) -> bool:
    depth = 0
    in_class = False
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            return True
        index += 1
    return False


def _literal_prefix(pattern: re.Pattern[str]) -> str | None:
    """Return text that every match of a case-sensitive pattern starts with."""
    source = pattern.pattern.removeprefix(r"\b")
    if pattern.flags & re.IGNORECASE or _has_top_level_alternation(source):
        return None
    literal: list[str] = []
    for char in source:
        if char.isascii() and (char.isalnum() or char in "-_ "):
            literal.append(char)
            continue
        if char in "?*{" and literal:
            # The quantifier makes the last character optional.
            literal.pop()
        break
    return "".join(literal) if len(literal) >= 2 else None


_BUILTIN_PREFIXES = {name: _literal_prefix(pattern) for name, pattern in BUILTIN_PATTERNS}


class SecretRedactor:
    def __init__(self, config: RedactionConfig):
        self.config = config
        self.placeholder = config.placeholder or MASK
        self._custom_patterns = self._compile_custom_patterns(config.rules)
        self._cache = _ScanCache(_CACHE_MAX_ENTRIES, _CACHE_MAX_CHARS)

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
        key = self._cache.key(value)
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
        for name, pattern in BUILTIN_PATTERNS:
            prefix = _BUILTIN_PREFIXES[name]
            if prefix is not None and prefix not in value:
                continue
            value, count = self._sub_builtin_pattern(name, pattern, value)
            stats.add(name, count)
        return value

    def _run_detect_secrets(self, value: str, stats: RedactionStats) -> str:
        if not value.strip():
            return value
        from detect_secrets.core.scan import scan_line
        from detect_secrets.settings import transient_settings
        from detect_secrets.transformers import get_transformed_file

        source = _PromptText(value)
        lines = get_transformed_file(source) or value.splitlines()
        source.seek(0)
        eager_lines = get_transformed_file(source, use_eager_transformers=True) or []
        gate = _line_gate()
        if gate is not None:
            lines = gate.candidates(lines)
            eager_lines = gate.candidates(eager_lines)
            if not lines and not eager_lines:
                return value
        plugin_config = [
            {"name": plugin_type.__name__} for plugin_type in _detect_secrets_plugins()
        ]
        with _DETECT_SECRETS_LOCK, transient_settings({"plugins_used": plugin_config}):
            found_secrets = [secret for line in lines for secret in scan_line(line)]
            if not found_secrets:
                found_secrets = [secret for line in eager_lines for secret in scan_line(line)]

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
        if name == "assigned_secret":
            return pattern.subn(
                lambda match: (
                    f"{match.group('prefix')}{self.placeholder}{match.group('value_quote')}"
                ),
                value,
            )
        if name == "auth_header":
            return pattern.subn(
                lambda match: (
                    f"{match.group('prefix')}{self.placeholder}{match.group('value_quote')}"
                ),
                value,
            )
        if name == "signed_url_query_param":
            return pattern.subn(lambda match: f"{match.group(1)}{self.placeholder}", value)
        if name == "url_credentials":
            return pattern.subn(
                lambda match: f"{match.group(1)}{self.placeholder}{match.group(3)}", value
            )
        return pattern.subn(self._replacement, value)

    def _replacement(self, match: re.Match[str]) -> str:
        secret = match.group(0)
        if self.config.redact_mode == "full" or len(secret) <= 12:
            return self.placeholder
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]
        return f"{secret[:4]}...{secret[-4:]}:{digest}"


class _PromptText(io.StringIO, NamedIO):
    name = "promptlatch-input"
