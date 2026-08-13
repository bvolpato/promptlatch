from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import copy
from dataclasses import dataclass, field
from typing import Any

from promptlatch.config import RedactionConfig
from promptlatch.redaction import RedactionResult, RedactionStats, SecretRedactor


def _merge_stats(target: RedactionStats, source: RedactionStats) -> None:
    target.redactions += source.redactions
    for name, count in source.rule_hits.items():
        target.rule_hits[name] = target.rule_hits.get(name, 0) + count


def _with_content(message: Any, content: Any) -> Any:
    model_copy = getattr(message, "model_copy", None)
    if callable(model_copy):
        return model_copy(update={"content": content})

    pydantic_copy = getattr(message, "copy", None)
    if callable(pydantic_copy):
        return pydantic_copy(update={"content": content})

    cloned = copy(message)
    try:
        cloned.content = content
    except (AttributeError, TypeError) as exc:
        raise TypeError(
            "message object has content but cannot be copied with redacted content"
        ) from exc
    return cloned


def _is_message_array(value: Any) -> bool:
    return isinstance(value, Iterable) and not isinstance(value, str | bytes | Mapping)


@dataclass
class PromptLatch:
    config: RedactionConfig = field(default_factory=RedactionConfig)

    def __post_init__(self) -> None:
        self._redactor = SecretRedactor(self.config)

    def scan_text(self, text: str) -> RedactionResult:
        return self._redactor.redact_text(text)

    def text(self, text: str) -> str:
        return self.scan_text(text).value

    def scan_payload(self, payload: Any) -> RedactionResult:
        return self._redactor.redact_payload(payload)

    def payload(self, payload: Any) -> Any:
        return self.scan_payload(payload).value

    def scan_messages(self, messages: Iterable[Any]) -> RedactionResult:
        stats = RedactionStats()
        redacted = []
        for message in messages:
            result = self._redact_message(message)
            _merge_stats(stats, result.stats)
            redacted.append(result.value)
        return RedactionResult(redacted, stats)

    def messages(self, messages: Iterable[Any]) -> list[Any]:
        return self.scan_messages(messages).value

    def scan_params(
        self, params: Mapping[str, Any] | None = None, **kwargs: Any
    ) -> RedactionResult:
        data = dict(params or {})
        data.update(kwargs)

        stats = RedactionStats()
        redacted: dict[str, Any] = {}
        for key, value in data.items():
            result = (
                self.scan_messages(value)
                if key == "messages" and _is_message_array(value)
                else self.scan_payload(value)
            )
            _merge_stats(stats, result.stats)
            redacted[key] = result.value
        return RedactionResult(redacted, stats)

    def params(self, params: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.scan_params(params, **kwargs).value

    def _redact_message(self, message: Any) -> RedactionResult:
        if not hasattr(message, "content") or isinstance(message, Mapping):
            return self.scan_payload(message)

        field_names = getattr(type(message), "model_fields", None)
        model_copy = getattr(message, "model_copy", None)
        if isinstance(field_names, Mapping) and callable(model_copy):
            stats = RedactionStats()
            updates: dict[str, Any] = {}
            for name in field_names:
                result = self.scan_payload(getattr(message, name))
                _merge_stats(stats, result.stats)
                if result.stats.redactions:
                    updates[name] = result.value
            return RedactionResult(model_copy(update=updates), stats)

        content_result = self.scan_payload(message.content)
        return RedactionResult(_with_content(message, content_result.value), content_result.stats)


PromptCloak = PromptLatch


_default = PromptLatch()


def scan_text(text: str) -> RedactionResult:
    return _default.scan_text(text)


def redact_text(text: str) -> str:
    return _default.text(text)


def scan_payload(payload: Any) -> RedactionResult:
    return _default.scan_payload(payload)


def redact_payload(payload: Any) -> Any:
    return _default.payload(payload)


def scan_messages(messages: Iterable[Any]) -> RedactionResult:
    return _default.scan_messages(messages)


def redact_messages(messages: Iterable[Any]) -> list[Any]:
    return _default.messages(messages)


def scan_params(params: Mapping[str, Any] | None = None, **kwargs: Any) -> RedactionResult:
    return _default.scan_params(params, **kwargs)


def redact_params(params: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    return _default.params(params, **kwargs)
