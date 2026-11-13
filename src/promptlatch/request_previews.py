"""Small, bounded text previews extracted from already-redacted request history."""

from __future__ import annotations

from typing import Any

PREVIEW_FIELDS = ("session_preview", "user_preview", "assistant_preview")
MAX_PREVIEW_CHARS = 200
MAX_LEGACY_BODY_BYTES = 1024 * 1024


def _bound_text(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if len(value) > MAX_PREVIEW_CHARS:
        value = value[: MAX_PREVIEW_CHARS - 1].rstrip() + "…"
    return value


def bound_preview_text(value: str) -> str | None:
    """Apply the storage cap to a preview supplied by any history producer."""
    return _bound_text(value)


def _content_text(content: Any, *, responses: bool = False) -> str | None:
    if isinstance(content, str):
        return _bound_text(content)
    if not isinstance(content, list):
        return None
    accepted = {"text", "input_text", "output_text"} if responses else {"text"}
    parts: list[str] = []
    size = 0
    for part in content:
        if not isinstance(part, dict) or part.get("type") not in accepted:
            continue
        text = part.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        separator = "\n" if parts else ""
        remaining = MAX_PREVIEW_CHARS + 1 - size - len(separator)
        if remaining <= 0:
            break
        fragment = text.strip()[:remaining]
        parts.append(separator + fragment)
        size += len(separator) + len(fragment)
        if len(text.strip()) > len(fragment):
            break
    return _bound_text("".join(parts)) if parts else None


def _gemini_parts_text(content: Any) -> str | None:
    if isinstance(content, str):
        return _bound_text(content)
    if not isinstance(content, list):
        return None
    parts: list[str] = []
    size = 0
    for part in content:
        if isinstance(part, str):
            text: Any = part
        elif isinstance(part, dict):
            if part.get("thought") is True:
                continue
            text = part.get("text")
        else:
            continue
        if not isinstance(text, str) or not text.strip():
            continue
        separator = "\n" if parts else ""
        remaining = MAX_PREVIEW_CHARS + 1 - size - len(separator)
        if remaining <= 0:
            break
        fragment = text.strip()[:remaining]
        parts.append(separator + fragment)
        size += len(separator) + len(fragment)
        if len(text.strip()) > len(fragment):
            break
    return _bound_text("".join(parts)) if parts else None


def _gemini_contents(payload: dict[str, Any]) -> Any:
    if "contents" in payload:
        return payload.get("contents")
    for key in ("request", "generateContentRequest", "generate_content_request"):
        nested = payload.get(key)
        if isinstance(nested, dict) and "contents" in nested:
            return nested.get("contents")
    return None


def extract_request_previews(payload: Any) -> dict[str, str | None]:
    """Extract user and prior-assistant text. Caller must pass fully redacted data."""
    result: dict[str, str | None] = {field: None for field in PREVIEW_FIELDS}
    if not isinstance(payload, dict):
        return result

    if "messages" in payload:
        messages = payload.get("messages")
        responses = False
    elif "input" in payload:
        messages = payload.get("input")
        responses = True
        if isinstance(messages, str):
            text = _bound_text(messages)
            result["session_preview"] = result["user_preview"] = text
            return result
    else:
        contents = _gemini_contents(payload)
        if isinstance(contents, str):
            text = _bound_text(contents)
            result["session_preview"] = result["user_preview"] = text
            return result
        if isinstance(contents, dict):
            contents = [contents]
        if not isinstance(contents, list):
            return result
        for item in contents:
            if isinstance(item, str):
                text = _bound_text(item)
                if text is not None:
                    if result["session_preview"] is None:
                        result["session_preview"] = text
                    result["user_preview"] = text
                continue
            if not isinstance(item, dict):
                continue
            raw_role = item.get("role")
            if raw_role == "model":
                role = "assistant"
            elif raw_role in (None, "user"):
                role = "user"
            else:
                continue
            parts = item.get("parts")
            if parts is None and "text" in item:
                parts = [item]
            text = _gemini_parts_text(parts)
            if text is None:
                continue
            if role == "user":
                if result["session_preview"] is None:
                    result["session_preview"] = text
                result["user_preview"] = text
            else:
                result["assistant_preview"] = text
        return result
    if not isinstance(messages, list):
        return result

    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role not in {"user", "assistant"}:
            continue
        text = _content_text(message.get("content"), responses=responses)
        if text is None:
            continue
        if role == "user":
            if result["session_preview"] is None:
                result["session_preview"] = text
            result["user_preview"] = text
        elif role == "assistant":
            result["assistant_preview"] = text

    return result


def legacy_request_previews(record: dict[str, Any], body: str | None) -> dict[str, str | None]:
    """Derive previews for pre-preview rows from a bounded, complete retained body."""
    result: dict[str, str | None] = {field: None for field in PREVIEW_FIELDS}
    if any(field in record for field in PREVIEW_FIELDS):
        return result
    if (
        not isinstance(body, str)
        or record.get("body_truncated")
        or len(body) > MAX_LEGACY_BODY_BYTES
    ):
        return result
    if len(body.encode("utf-8", errors="ignore")) > MAX_LEGACY_BODY_BYTES:
        return result
    try:
        import json

        payload = json.loads(body)
    except (ValueError, RecursionError):
        return result
    return extract_request_previews(payload)
