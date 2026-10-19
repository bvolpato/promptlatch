"""Limits for redacted, per-request upstream error details."""

from __future__ import annotations

from typing import Any

PROVIDER_ERROR_FIELDS = ("event", "type", "code", "message", "param")
ERROR_FIELD_BYTES = {
    "event": 128,
    "type": 256,
    "code": 256,
    "message": 2048,
    "param": 256,
    "transport_phase": 64,
    "transport_phase_ms": 32,
    "transport_cause": 64,
    "transport_errno": 16,
    "connection_origin": 8,
    "tls_reason": 64,
    "request_body_bytes": 32,
    "response_bytes_observed": 32,
    "upstream_status": 3,
    "upstream_request_id": 128,
    "upstream_cf_ray": 64,
}
MAX_ERROR_SOURCE_BYTES = 16 * 1024
OVERSIZED_ERROR_FIELD = "[Upstream error detail omitted: size limit]"


def bound_error_details(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    result = {}
    for key, limit in ERROR_FIELD_BYTES.items():
        text = value.get(key)
        if not isinstance(text, str) or not text:
            continue
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) > limit:
            text = encoded[: limit - 3].decode("utf-8", errors="ignore") + "…"
        else:
            text = encoded.decode("utf-8")
        result[key] = text
    return result or None
