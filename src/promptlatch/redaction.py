from __future__ import annotations

import hashlib
import io
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from detect_secrets.custom_types import NamedIO

from promptlatch.config import RedactionConfig, RuleConfig
from promptlatch.patterns import BUILTIN_PATTERNS, SENSITIVE_FIELD_RE, STRICT_SENSITIVE_FIELD_RE

MASK = "[REDACTED_SECRET]"


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


class SecretRedactor:
    def __init__(self, config: RedactionConfig):
        self.config = config
        self.placeholder = config.placeholder or MASK
        self._custom_patterns = self._compile_custom_patterns(config.rules)

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
                redacted[redacted_key] = (
                    self._redact_sensitive_field(item, stats, strict=self._is_strict_field(key))
                    if self._is_sensitive_field(key)
                    else self._walk(item, stats)
                )
            return redacted
        return value

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
        original = value
        if self.config.engine == "detect-secrets":
            value = self._run_detect_secrets(value, stats)
        for name, pattern in self._custom_patterns:
            value, count = pattern.subn(self._replacement, value)
            stats.add(name, count)
        for name, pattern in BUILTIN_PATTERNS:
            value, count = self._sub_builtin_pattern(name, pattern, value)
            stats.add(name, count)
        if value != original and self.config.redact_mode == "partial":
            return value
        return value

    def _run_detect_secrets(self, value: str, stats: RedactionStats) -> str:
        if not value.strip():
            return value
        from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
        from detect_secrets.core.scan import scan_line
        from detect_secrets.settings import transient_settings
        from detect_secrets.transformers import get_transformed_file

        plugin_config = [
            {"name": plugin_type.__name__}
            for plugin_type in get_mapping_from_secret_type_to_class().values()
            if plugin_type.__name__ not in {"Base64HighEntropyString", "HexHighEntropyString"}
        ]
        source = _PromptText(value)
        lines = get_transformed_file(source) or value.splitlines()
        source.seek(0)
        eager_lines = get_transformed_file(source, use_eager_transformers=True) or []
        with transient_settings({"plugins_used": plugin_config}):
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
                    f"{match.group(1)}{match.group(2)}{match.group(3)}"
                    f"{self.placeholder}{match.group(5)}"
                ),
                value,
            )
        if name == "auth_header":
            return pattern.subn(lambda match: f"{match.group(1)}{self.placeholder}", value)
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
