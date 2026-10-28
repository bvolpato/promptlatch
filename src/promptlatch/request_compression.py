"""Endpoint-specific compression of redacted JSON uploads."""

from __future__ import annotations

import gzip
import logging
import sys
import time
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

import httpx

from promptlatch.config import RequestCompressionConfig

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

logger = logging.getLogger("promptlatch")
CompressionCodec = Literal["gzip", "zstd"]
_OPENAI_RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses"
_BUILTIN_ENDPOINTS = {
    _OPENAI_RESPONSES_ENDPOINT,
    "https://chatgpt.com/backend-api/codex/responses",
}


def request_compression_codec(
    method: str,
    target_url: str,
    headers: Mapping[str, str],
    size: int,
    config: RequestCompressionConfig,
) -> CompressionCodec | None:
    media_type = headers.get("content-type", "").partition(";")[0].strip().lower()
    if (
        not config.enabled
        or method != "POST"
        or not size
        or size < config.min_bytes
        or headers.get("content-encoding", "identity").strip().lower() != "identity"
        or not (media_type == "application/json" or media_type.endswith("+json"))
    ):
        return None
    endpoint = str(httpx.URL(target_url))
    configured = config.endpoints.get(endpoint)
    if configured is not None:
        return configured if configured != "identity" else None
    return "zstd" if endpoint in _BUILTIN_ENDPOINTS else None


@dataclass(frozen=True, slots=True)
class CompressedRequestBody:
    body: bytes
    encoding: Literal["identity", "gzip", "zstd"]
    compression_ms: float


def compress_request_body(
    body: bytes, encoding: CompressionCodec, target_url: str
) -> CompressedRequestBody:
    started = time.perf_counter()
    try:
        compressed = (
            gzip.compress(body, compresslevel=1, mtime=0)
            if encoding == "gzip"
            else zstd.compress(body, level=1)
        )
    except (zlib.error, zstd.ZstdError) as exc:
        logger.warning("request compression failed (%s)", type(exc).__name__)
        compressed = body
    elapsed_ms = (time.perf_counter() - started) * 1000
    # The public Responses API rejects zstd expansion ratios above 100:1.
    exceeds_ratio = (
        encoding == "zstd"
        and str(httpx.URL(target_url)) == _OPENAI_RESPONSES_ENDPOINT
        and len(body) > len(compressed) * 100
    )
    if len(compressed) >= len(body) or exceeds_ratio:
        return CompressedRequestBody(body, "identity", elapsed_ms)
    return CompressedRequestBody(compressed, encoding, elapsed_ms)
