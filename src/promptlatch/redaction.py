from __future__ import annotations

import base64
import binascii
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
from typing import Any, Literal

from detect_secrets.custom_types import NamedIO

from promptlatch.config import _ENV_REF_RE, RedactionConfig, RuleConfig
from promptlatch.patterns import BUILTIN_PATTERNS, SENSITIVE_FIELD_RE, STRICT_SENSITIVE_FIELD_RE

MASK = "[REDACTED_SECRET]"
_TAGGED_PLACEHOLDER_RE = re.compile(r"\[REDACTED:([A-Za-z0-9_.-]{1,64})#([0-9a-f]{8})\]")
_TAGGED_OR_MASK_RE = re.compile(
    r"\[REDACTED_SECRET\]|\[REDACTED:([A-Za-z0-9_.-]{1,64})#([0-9a-f]{8})\]"
)
_SIGNED_URL_TAGGED_RE = re.compile(
    r"(?i)([?&](?:x-amz-signature|x-amz-credential|x-amz-security-token|"
    r"x-goog-signature|x-goog-credential|googleaccessid|signature|sig)=)"
    r"((?:\[REDACTED:[A-Za-z0-9_.-]{1,64}#[0-9a-f]{8}\]|[^&#\s])+)"
)
_MAX_DYNAMIC_TAG_LABELS = 4096
_TAG_KEY_PBKDF2_ITERATIONS = 600_000
_TAG_VALUE_PBKDF2_ITERATIONS = 100_000
_MAX_TAG_DERIVATIONS_PER_CALL = 64


class _TagCallState:
    __slots__ = ("capped_count", "derivations", "memo")

    def __init__(self) -> None:
        self.memo: dict[str, str] = {}
        self.derivations = 0
        self.capped_count = 0


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
        r"[^a-z0-9_.-]((?:authorization|proxy-authorization|x-api-key|x-goog-api-key|api-key|"
        r"x-auth-token|x-auth-key|cf-access-token))[\"']?\s*[:=]"
    ),
}
_ASSIGNMENT_FIELD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-İıſK"
)
_CODE_REFERENCE_PREFIX = re.compile(
    r"[A-Za-z_]\w*(?:[ \t]*\.[ \t]*[A-Za-z_]\w*|[ \t]*\([ \t]*\))*[ \t]*[\[(]?",
    re.ASCII,
)
_CREDENTIAL_PLACEHOLDER = re.compile(
    r"(?i)<your[-_](?:api[-_]key|client[-_]secret|password|token|secret)(?:[-_]here)?>"
)

# Scan results are kept per string, so repeated text is scanned once.
_CACHE_MAX_ENTRIES = 16_384
_CACHE_MAX_CHARS = 8_000_000
_OPAQUE_RESPONSE_ENCODING = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_PayloadContext = Literal[
    "responses-request",
    "responses-input-item",
    "responses-opaque-item",
    "responses-message",
    "responses-agent-message",
    "responses-agent-message-content",
    "responses-tool-output",
    "responses-tool-output-content",
    "responses-image-part",
    "responses-encrypted-content-part",
    "gemini-request",
    "gemini-inner-request",
    "gemini-content",
    "gemini-part",
    "gemini-function-response",
    "gemini-inline-image-blob",
]
_RedactionProtocol = Literal["openai-responses", "gemini-generate-content"]
_IMAGE_MIME_SIGNATURES = {
    "data:image/png;base64": (b"\x89PNG\r\n\x1a\n",),
    "data:image/jpeg;base64": (b"\xff\xd8\xff",),
    "data:image/gif;base64": (b"GIF87a", b"GIF89a"),
    "data:image/webp;base64": (b"RIFF",),
}
_GEMINI_IMAGE_SIGNATURES = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/gif": (b"GIF87a", b"GIF89a"),
    "image/webp": (b"RIFF",),
}


def _mapping_or_attr_field(value: Any, key: str) -> tuple[bool, Any]:
    if isinstance(value, Mapping):
        return (key in value, value.get(key))
    model_fields = getattr(type(value), "model_fields", None)
    model_copy = getattr(value, "model_copy", None)
    if isinstance(model_fields, Mapping) and callable(model_copy):
        model_extra = getattr(value, "model_extra", None)
        if isinstance(model_extra, Mapping) and key in model_extra:
            return (True, model_extra[key])
        if key in model_fields and hasattr(value, key):
            attr_val = getattr(value, key)
            fields_set = getattr(value, "model_fields_set", None)
            if attr_val is not None or (
                isinstance(fields_set, (set, frozenset)) and key in fields_set
            ):
                return (True, attr_val)
    return (False, None)


def _is_gemini_inline_image_blob(value: Any) -> bool:
    has_camel, mime_camel = _mapping_or_attr_field(value, "mimeType")
    has_snake, mime_snake = _mapping_or_attr_field(value, "mime_type")
    if not has_camel and not has_snake:
        return False
    if has_camel and has_snake and mime_camel != mime_snake:
        return False
    mime = mime_camel if has_camel else mime_snake
    if not isinstance(mime, str):
        return False
    signatures = _GEMINI_IMAGE_SIGNATURES.get(mime)
    has_data, encoded = _mapping_or_attr_field(value, "data")
    if (
        signatures is None
        or not has_data
        or not isinstance(encoded, str)
        or not encoded
        or len(encoded) % 4
    ):
        return False
    try:
        image = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return False
    if not image.startswith(signatures) or base64.b64encode(image).decode("ascii") != encoded:
        return False
    if mime == "image/webp":
        return len(image) >= 12 and image[8:12] == b"WEBP"
    return True


def _is_opaque_response_content(value: Any) -> bool:
    """Recognize a canonical Fernet envelope, without decrypting provider state."""
    if (
        not isinstance(value, str)
        or len(value) < 100
        or len(value) % 4
        or not value.startswith("g")
        or _OPAQUE_RESPONSE_ENCODING.fullmatch(value) is None
    ):
        return False
    try:
        envelope = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return False
    return (
        envelope[0] == 0x80
        and len(envelope) >= 73
        and (len(envelope) - 57) % 16 == 0
        and base64.urlsafe_b64encode(envelope).decode("ascii") == value
    )


def _is_response_image_data(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("data:image/"):
        return False
    header, separator, encoded = value.partition(",")
    signatures = _IMAGE_MIME_SIGNATURES.get(header)
    if not separator or signatures is None or not encoded or len(encoded) % 4:
        return False
    try:
        image = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return False
    if not image.startswith(signatures) or base64.b64encode(image).decode("ascii") != encoded:
        return False
    if header == "data:image/webp;base64":
        return len(image) >= 12 and image[8:12] == b"WEBP"
    return True


def _response_object_context(value: Any, context: _PayloadContext | None) -> _PayloadContext | None:
    if context == "gemini-inline-image-blob":
        return context if _is_gemini_inline_image_blob(value) else None
    if context in (
        "gemini-request",
        "gemini-inner-request",
        "gemini-content",
        "gemini-part",
        "gemini-function-response",
    ):
        return context
    item_type = value.get("type") if isinstance(value, Mapping) else getattr(value, "type", None)
    if context == "responses-image-part":
        return context if item_type == "input_image" else None
    if context in ("responses-agent-message-content", "responses-tool-output-content"):
        if item_type == "encrypted_content":
            return "responses-encrypted-content-part"
        if context == "responses-tool-output-content" and item_type == "input_image":
            return "responses-image-part"
        return None
    if context != "responses-input-item":
        return context
    if item_type in ("reasoning", "compaction"):
        return "responses-opaque-item"
    if item_type in ("function_call_output", "custom_tool_call_output"):
        return "responses-tool-output"
    if item_type == "agent_message":
        return "responses-agent-message"
    role = value.get("role") if isinstance(value, Mapping) else getattr(value, "role", None)
    if item_type in (None, "message") and role in ("user", "assistant", "system", "developer"):
        return "responses-message"
    return None


def _ascii_ignorecase(value: str) -> str:
    if value.isascii():
        return value.lower()
    return value.translate(_ASCII_IGNORECASE_TRANSLATION).lower()


def _is_code_reference(value: str, start: int, end: int) -> bool:
    """Recognize unquoted assignment prefixes, never literals inside a call."""
    position = start
    while position and value[position - 1] in " \t":
        position -= 1
    if not position or value[position - 1] != "=":
        return False
    if position > 1 and value[position - 2] in "=!<>:":
        return False
    if "(" not in value[start:end] and value[end : end + 1] not in {"(", "["}:
        return False
    reference = _CODE_REFERENCE_PREFIX.match(value, start)
    return reference is not None and reference.end() >= end


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
def _plugin_denylist_patterns() -> tuple[re.Pattern[str], ...]:
    return tuple(
        regex
        for plugin_type in _detect_secrets_plugins()
        for regex in getattr(plugin_type(), "denylist", ())
    )


@lru_cache(maxsize=4096)
def _unsafe_tag_label(label: str) -> bool:
    return any(pattern.search(label) for _, pattern in BUILTIN_PATTERNS) or any(
        regex.search(label) for regex in _plugin_denylist_patterns()
    )


def _normalize_tag_label(rule_name: str) -> str:
    if rule_name.startswith("detect_secrets:"):
        raw = rule_name.partition(":")[2]
        label = re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_").lower()
        return label[:64] or "detector"
    label = re.sub(r"[^A-Za-z0-9_.-]+", "_", rule_name).strip("_")[:64] or "secret"
    if _unsafe_tag_label(label):
        return "custom_rule"
    return label


class _DynamicTagLabels:
    """Bounded thread-safe registry of custom rule tag labels shared across child redactors."""

    def __init__(self, max_entries: int) -> None:
        self._max_entries = max_entries
        self._entries: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()
        self.version = 0

    def add(self, label: str) -> None:
        with self._lock:
            if label in self._entries:
                self._entries.move_to_end(label)
                return
            self._entries[label] = None
            self.version += 1
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def contains(self, label: str) -> bool:
        with self._lock:
            return label in self._entries


@lru_cache(maxsize=1)
def _detect_secrets_tag_labels() -> frozenset[str]:
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    return frozenset(
        _normalize_tag_label(f"detect_secrets:{secret_type}")
        for secret_type, plugin_type in get_mapping_from_secret_type_to_class().items()
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
        self._tag_local = threading.local()
        self._default_tag_secret = (
            _cache_from._default_tag_secret if _cache_from is not None else os.urandom(32)
        )
        self._default_tag_id = (
            _cache_from._default_tag_id if _cache_from is not None else os.urandom(4).hex()
        )
        self._derived_tag_pair: tuple[str, bytes, str] | None = (
            _cache_from._derived_tag_pair if _cache_from is not None else None
        )
        # Validate any configured or environment-expanded tag_key eagerly; only run
        # PBKDF2 eagerly when tagged mode is active.
        self._resolve_tag_key()
        if self.config.redact_mode == "tagged":
            self._active_tag_pair()
        self._static_tag_labels = (
            frozenset(
                {
                    "sensitive_field",
                    "custom_rule",
                    *(_normalize_tag_label(name) for name, _ in BUILTIN_PATTERNS),
                }
            )
            | _detect_secrets_tag_labels()
        )
        self._dynamic_tag_labels = (
            _cache_from._dynamic_tag_labels
            if _cache_from is not None
            else _DynamicTagLabels(_MAX_DYNAMIC_TAG_LABELS)
        )
        for name, _ in self._custom_patterns:
            label = self._safe_tag_label(name)
            if label not in self._static_tag_labels:
                self._dynamic_tag_labels.add(label)
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
                    self._default_tag_id,
                    [
                        (name, pattern.pattern, pattern.flags)
                        for name, pattern in self._custom_patterns
                    ],
                ]
            )
        )
        self._context_keys: dict[tuple[str, str, str], bytes] = {}

    def _resolve_tag_key(self) -> str | None:
        tag_key = self.config.tag_key
        if tag_key is None:
            return None
        env_match = _ENV_REF_RE.fullmatch(tag_key)
        if env_match is not None and tag_key not in {
            os.environ.get("PROMPTLATCH_REDACTION_TAG_KEY"),
            os.environ.get("PROMPTCLOAK_REDACTION_TAG_KEY"),
        }:
            env_name = env_match.group(1)
            resolved = os.getenv(env_name)
            if not resolved:
                raise ValueError(f"redaction tag_key environment variable {env_name} is not set")
            tag_key = resolved
        if len(tag_key) < 16:
            raise ValueError("redaction tag_key must be at least 16 characters")
        return tag_key

    def _active_tag_pair(self) -> tuple[bytes, str]:
        resolved_key = self._resolve_tag_key()
        if resolved_key is None:
            return self._default_tag_secret, self._default_tag_id
        cached = self._derived_tag_pair
        if cached is not None and cached[0] == resolved_key:
            return cached[1], cached[2]
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            resolved_key.encode("utf-8"),
            b"promptlatch-redaction-tag-v1",
            _TAG_KEY_PBKDF2_ITERATIONS,
            dklen=36,
        )
        secret, tag_id = derived[:32], derived[32:36].hex()
        self._derived_tag_pair = (resolved_key, secret, tag_id)
        return secret, tag_id

    def _tag_context_id(self) -> str:
        if self.config.redact_mode != "tagged":
            return ""
        _, tag_id = self._active_tag_pair()
        return f"{tag_id}:{self._dynamic_tag_labels.version}"

    def _safe_tag_label(self, rule_name: str) -> str:
        label = _normalize_tag_label(rule_name)
        if label not in self._static_tag_labels and any(
            pattern.search(label) for _, pattern in self._custom_patterns
        ):
            return "custom_rule"
        return label

    def _is_valid_tag_label(self, label: str) -> bool:
        return label in self._static_tag_labels or self._dynamic_tag_labels.contains(label)

    def _is_tagged_placeholder(self, candidate: str) -> bool:
        if candidate == MASK:
            return True
        match = _TAGGED_PLACEHOLDER_RE.fullmatch(candidate)
        return match is not None and self._is_valid_tag_label(match.group(1))

    def _protected_tag_spans(self, value: str) -> list[tuple[int, int]]:
        if "[REDACTED" not in value:
            return []
        return [
            (match.start(), match.end())
            for match in _TAGGED_OR_MASK_RE.finditer(value)
            if match.group(1) is None or self._is_valid_tag_label(match.group(1))
        ]

    def _format_tagged(self, secret: str, rule_name: str) -> str:
        label = self._safe_tag_label(rule_name)
        state: _TagCallState | None = getattr(self._tag_local, "state", None)
        tag = state.memo.get(secret) if state is not None else None
        if tag is None:
            if state is not None and state.derivations >= _MAX_TAG_DERIVATIONS_PER_CALL:
                state.capped_count += 1
                return MASK
            tag_secret, _ = self._active_tag_pair()
            tag = hashlib.pbkdf2_hmac(
                "sha256",
                secret.encode("utf-8", "surrogatepass"),
                b"tag-val\x00" + tag_secret,
                _TAG_VALUE_PBKDF2_ITERATIONS,
                dklen=4,
            ).hex()
            if state is not None:
                state.derivations += 1
                state.memo[secret] = tag
        return f"[REDACTED:{label}#{tag}]"

    def _sub_tagged_safe(
        self,
        pattern: re.Pattern[str],
        value: str,
        rule_name: str,
        *,
        keyword: bool = False,
    ) -> tuple[str, int]:
        protected = self._protected_tag_spans(value)
        if not protected and not keyword:
            count = 0

            def replace_fast(match: re.Match[str]) -> str:
                nonlocal count
                count += 1
                return self._format_tagged(match.group(0), rule_name)

            return pattern.sub(replace_fast, value), count

        spans_to_replace: list[tuple[int, int]] = []
        for match in pattern.finditer(value):
            start, end = match.start(), match.end()
            if keyword and _is_code_reference(value, start, end):
                continue
            if any(ps <= start and end <= pe for ps, pe in protected):
                continue
            merged_start, merged_end = start, end
            for ps, pe in protected:
                if merged_start < pe and merged_end > ps:
                    merged_start = min(merged_start, ps)
                    merged_end = max(merged_end, pe)
            if spans_to_replace and merged_start < spans_to_replace[-1][1]:
                prev_start, prev_end = spans_to_replace[-1]
                spans_to_replace[-1] = (min(prev_start, merged_start), max(prev_end, merged_end))
            else:
                spans_to_replace.append((merged_start, merged_end))

        if not spans_to_replace:
            return value, 0

        chunks: list[str] = []
        cursor = 0
        for start, end in spans_to_replace:
            chunks.append(value[cursor:start])
            chunks.append(self._format_tagged(value[start:end], rule_name))
            cursor = end
        chunks.append(value[cursor:])
        return "".join(chunks), len(spans_to_replace)

    def _sub_pattern_with_rule(
        self, pattern: re.Pattern[str], value: str, rule_name: str
    ) -> tuple[str, int]:
        if self.config.redact_mode != "tagged":
            return pattern.subn(self._replacement, value)
        return self._sub_tagged_safe(pattern, value, rule_name)

    def redact_payload(
        self, payload: Any, *, protocol: _RedactionProtocol | None = None
    ) -> RedactionResult:
        if protocol not in (None, "openai-responses", "gemini-generate-content"):
            raise ValueError("unsupported redaction protocol")
        stats = RedactionStats()
        if not self.config.enabled:
            return RedactionResult(payload, stats)
        context: _PayloadContext | None = None
        if protocol == "openai-responses":
            context = "responses-request"
        elif protocol == "gemini-generate-content":
            context = "gemini-request"
        if (
            self.config.redact_mode != "tagged"
            or getattr(self._tag_local, "state", None) is not None
        ):
            return RedactionResult(self._walk(payload, stats, context=context), stats)
        state = _TagCallState()
        self._tag_local.state = state
        try:
            return RedactionResult(self._walk(payload, stats, context=context), stats)
        finally:
            state.memo.clear()
            self._tag_local.state = None

    def redact_text(self, text: str) -> RedactionResult:
        stats = RedactionStats()
        if not self.config.enabled:
            return RedactionResult(text, stats)
        if (
            self.config.redact_mode != "tagged"
            or getattr(self._tag_local, "state", None) is not None
        ):
            return RedactionResult(self._redact_string(text, stats), stats)
        state = _TagCallState()
        self._tag_local.state = state
        try:
            return RedactionResult(self._redact_string(text, stats), stats)
        finally:
            state.memo.clear()
            self._tag_local.state = None

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

    def _walk(
        self, value: Any, stats: RedactionStats, *, context: _PayloadContext | None = None
    ) -> Any:
        if isinstance(value, str):
            return self._redact_string(value, stats)
        if context is not None:
            context = _response_object_context(value, context)
        model_fields = self._model_fields(value)
        if model_fields is not None:
            return self._redact_model(value, model_fields, stats, context=context)
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
                redacted[redacted_key] = self._redact_field_value(key, item, stats, context=context)
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
        context: _PayloadContext | None = None,
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
                else self._redact_field_value(name, item, stats, context=context)
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
                    else self._redact_field_value(name, item, stats, context=context)
                )
                if stats.redactions > before:
                    updates[name] = redacted

        return value.model_copy(update=updates)

    def _redact_field_value(
        self,
        key: Any,
        value: Any,
        stats: RedactionStats,
        *,
        context: _PayloadContext | None = None,
    ) -> Any:
        if (
            context in ("responses-opaque-item", "responses-encrypted-content-part")
            and key == "encrypted_content"
            and _is_opaque_response_content(value)
        ):
            return value
        if (
            context == "responses-image-part"
            and key == "image_url"
            and _is_response_image_data(value)
        ):
            return value
        if context == "gemini-inline-image-blob" and key == "data" and isinstance(value, str):
            return value
        if self._is_sensitive_field(key):
            return self._redact_sensitive_field(value, stats, strict=self._is_strict_field(key))
        child_context: _PayloadContext | None = None
        allow_sequence = False
        allow_mapping = False
        if context == "responses-request" and key == "input":
            child_context = "responses-input-item"
            allow_sequence = True
        elif context == "responses-agent-message" and key == "content":
            child_context = "responses-agent-message-content"
            allow_sequence = True
        elif (context == "responses-message" and key == "content") or (
            context == "responses-tool-output" and key == "output"
        ):
            child_context = (
                "responses-image-part"
                if context == "responses-message"
                else "responses-tool-output-content"
            )
            allow_sequence = True
        elif context == "gemini-request" and key in (
            "request",
            "generateContentRequest",
            "generate_content_request",
        ):
            child_context = "gemini-inner-request"
            allow_mapping = True
        elif context in ("gemini-request", "gemini-inner-request") and key in (
            "contents",
            "systemInstruction",
            "system_instruction",
        ):
            child_context = "gemini-content"
            allow_sequence = True
            allow_mapping = True
        elif context in ("gemini-content", "gemini-function-response") and key == "parts":
            child_context = "gemini-part"
            allow_sequence = True
        elif context in ("gemini-content", "gemini-part") and key in (
            "functionResponse",
            "function_response",
        ):
            child_context = "gemini-function-response"
            allow_mapping = True
        elif (
            context in ("gemini-content", "gemini-part")
            and key in ("inlineData", "inline_data")
            and _is_gemini_inline_image_blob(value)
        ):
            child_context = "gemini-inline-image-blob"
            allow_mapping = True
        if child_context is not None:
            if allow_sequence and isinstance(value, (list, tuple)):
                items = [self._walk(item, stats, context=child_context) for item in value]
                return tuple(items) if isinstance(value, tuple) else items
            if allow_mapping and (
                isinstance(value, Mapping) or self._model_fields(value) is not None
            ):
                return self._walk(value, stats, context=child_context)
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
            stripped = value.strip()
            if not stripped or (not strict and len(stripped) < 8):
                return value
            if self.config.redact_mode == "tagged":
                if self._is_tagged_placeholder(stripped):
                    return value
                stats.add("sensitive_field", 1)
                return self._format_tagged(value, "sensitive_field")
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
            if self.config.redact_mode == "tagged":
                return self._format_tagged(str(value), "sensitive_field")
            return self.placeholder
        return value

    def _redact_string(self, value: str, stats: RedactionStats) -> str:
        context = (self.config.engine, self.config.redact_mode, self._tag_context_id())
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
        state: _TagCallState | None = getattr(self._tag_local, "state", None)
        capped_before = state.capped_count if state is not None else 0
        found = RedactionStats()
        redacted = self._scan_string(value, found)
        capped_after = state.capped_count if state is not None else 0
        if capped_after == capped_before:
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
            value, count = self._sub_pattern_with_rule(pattern, value, name)
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

        protected = self._protected_tag_spans(value) if self.config.redact_mode == "tagged" else []
        nonce = ""
        sentinel_map: dict[str, str] = {}
        scan_text = value
        if protected:
            nonce = os.urandom(4).hex()
            while nonce in value:
                nonce = os.urandom(4).hex()
            masked_parts: list[str] = []
            cursor = 0
            for index, (ps, pe) in enumerate(protected):
                sentinel = f"^PL{nonce}_{index}^"
                sentinel_map[sentinel] = value[ps:pe]
                masked_parts.append(value[cursor:ps])
                masked_parts.append(sentinel)
                cursor = pe
            masked_parts.append(value[cursor:])
            scan_text = "".join(masked_parts)

        source = _PromptText(scan_text)
        known_transformers = _uses_builtin_config_transformers(get_transformed_file) and supported()
        use_literal_transform = known_transformers
        cannot_transform = known_transformers and _invalid_ini(scan_text)
        transformed = None
        if not cannot_transform:
            transformed = (
                transform(source) if use_literal_transform else get_transformed_file(source)
            )
        lines = transformed or scan_text.splitlines()
        # PrivateKeyDetector can also inspect this relative filename. Keep its
        # original calls when an on-disk file could affect the result.
        gate = None if os.path.exists("adhoc-string-scan") else _line_gate()

        def candidates(lines: list[str]) -> list[str]:
            if gate is None:
                return lines
            return [
                line
                for line in gate.candidates(lines)
                if (nonce and nonce in line)
                or self._clean_lines.get(self._clean_lines.key(line)) is None
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
                    has_sentinel = bool(nonce and nonce in line)
                    key = (
                        self._clean_lines.key(line)
                        if gate is not None and not has_sentinel
                        else None
                    )
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
            if sentinel_map and nonce in secret_value:
                for sentinel, original_tag in sentinel_map.items():
                    if sentinel in secret_value:
                        secret_value = secret_value.replace(sentinel, original_tag)
            if found_secret.type == "GitHub Token" and len(secret_value) < 30:
                continue
            if found_secret.type == "Artifactory Credentials":
                secret_value = secret_value.lstrip(" \t\r\n=:\"'").rstrip(" \t\r\n\"'")
            elif found_secret.type == "Azure Storage Account access key":
                secret_value = secret_value.strip("\"'")
            if not secret_value:
                continue
            rule_name = f"detect_secrets:{found_secret.type}"
            value, count = self._replace_detected_secret(
                secret_value,
                value,
                rule_name=rule_name,
                keyword=found_secret.type == "Secret Keyword",
            )
            stats.add(rule_name, count)
        return value

    def _replace_detected_secret(
        self,
        secret_value: str,
        value: str,
        *,
        rule_name: str = "detect_secrets:detector",
        keyword: bool = False,
    ) -> tuple[str, int]:
        if self.config.redact_mode == "tagged":
            if self._is_tagged_placeholder(secret_value):
                return value, 0
            if "," not in secret_value:
                return self._sub_tagged_safe(
                    re.compile(re.escape(secret_value)),
                    value,
                    rule_name,
                    keyword=keyword,
                )
            total = 0
            saw_tagged_segment = False
            for segment in secret_value.split(","):
                candidate = segment.strip().strip("\"'")
                if not candidate:
                    continue
                if self._is_tagged_placeholder(candidate):
                    saw_tagged_segment = True
                    continue
                value, replaced = self._sub_tagged_safe(
                    re.compile(re.escape(candidate)),
                    value,
                    rule_name,
                    keyword=keyword,
                )
                total += replaced
            if total or saw_tagged_segment:
                return value, total
            return self._sub_tagged_safe(
                re.compile(re.escape(secret_value)),
                value,
                rule_name,
                keyword=keyword,
            )

        if not keyword and "," not in secret_value:
            return re.subn(re.escape(secret_value), self._replacement, value)

        total = 0

        def replace(match: re.Match[str]) -> str:
            nonlocal total
            start, end = match.start(), match.end()
            if keyword and _is_code_reference(match.string, start, end):
                return match.group(0)
            total += 1
            return self._replacement(match)

        if "," not in secret_value:
            value = re.sub(re.escape(secret_value), replace, value)
            return value, total

        for segment in secret_value.split(","):
            candidate = segment.strip().strip("\"'")
            if not candidate:
                continue
            value = re.sub(re.escape(candidate), replace, value)

        if total:
            return value, total
        value = re.sub(re.escape(secret_value), replace, value)
        return value, total

    def _sub_builtin_pattern(
        self, name: str, pattern: re.Pattern[str], value: str
    ) -> tuple[str, int]:
        if name in {"assigned_secret", "auth_header"}:
            return self._sub_assignment_pattern(pattern, value, rule_name=name)
        if name == "signed_url_query_param":
            if self.config.redact_mode == "tagged":
                count = 0

                def replace_signed(match: re.Match[str]) -> str:
                    nonlocal count
                    if self._is_tagged_placeholder(match.group(2)):
                        return match.group(0)
                    count += 1
                    return f"{match.group(1)}{self._format_tagged(match.group(2), name)}"

                return _SIGNED_URL_TAGGED_RE.sub(replace_signed, value), count
            return pattern.subn(lambda match: f"{match.group(1)}{self.placeholder}", value)
        if name == "url_credentials":
            if self.config.redact_mode == "tagged":
                count = 0

                def replace_url(match: re.Match[str]) -> str:
                    nonlocal count
                    if self._is_tagged_placeholder(match.group(2)):
                        return match.group(0)
                    count += 1
                    return (
                        f"{match.group(1)}{self._format_tagged(match.group(2), name)}"
                        f"{match.group(3)}"
                    )

                return pattern.sub(replace_url, value), count
            return pattern.subn(
                lambda match: f"{match.group(1)}{self.placeholder}{match.group(3)}", value
            )
        return self._sub_pattern_with_rule(pattern, value, name)

    def _sub_assignment_pattern(
        self, pattern: re.Pattern[str], value: str, *, rule_name: str = "assigned_secret"
    ) -> tuple[str, int]:
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
                if _is_code_reference(value, match.start("secret"), match.end("secret")):
                    continue
                if _CREDENTIAL_PLACEHOLDER.fullmatch(match.group("secret")):
                    continue
                if self.config.redact_mode == "tagged" and self._is_tagged_placeholder(
                    match.group("secret")
                ):
                    continue
                replacement = (
                    self._format_tagged(match.group("secret"), rule_name)
                    if self.config.redact_mode == "tagged"
                    else self.placeholder
                )
                chunks.append(value[consumed : match.start()])
                chunks.append(f"{match.group('prefix')}{replacement}{match.group('value_quote')}")
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
