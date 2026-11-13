"""Bounded decompression of client uploads and endpoint-specific upstream compression."""

from __future__ import annotations

import gzip
import logging
import sys
import time
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

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
_INPUT_CHUNK_BYTES = 64 * 1024
_DECODE_CHUNK_BYTES = 64 * 1024
_ZSTD_MAX_WINDOW_LOG = 25


class UnsupportedRequestEncodingError(ValueError):
    """Raised when a client Content-Encoding cannot be safely decoded."""


class InvalidCompressedRequestError(ValueError):
    """Raised when a compressed client request body is corrupt or incomplete."""


class DecompressedRequestTooLargeError(ValueError):
    """Raised when a decompressed client request body exceeds the configured cap."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"decompressed request body exceeds {limit} bytes")
        self.limit = limit


def content_encoding_tokens(headers: Mapping[str, str]) -> list[str] | None:
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        raw_values: Any = getlist("content-encoding")
    else:
        raw_values = [value for key, value in headers.items() if key.lower() == "content-encoding"]
    if not raw_values:
        return []
    tokens: list[str] = []
    for raw in raw_values:
        parts = [part.strip().lower() for part in str(raw).split(",")]
        if not parts or any(not part for part in parts):
            return None
        tokens.extend(parts)
    return tokens


def has_non_identity_content_encoding(headers: Mapping[str, str]) -> bool:
    tokens = content_encoding_tokens(headers)
    if tokens is None:
        return True
    return bool(tokens) and tokens != ["identity"]


def parse_request_content_encoding(
    headers: Mapping[str, str],
) -> Literal["identity", "gzip", "zstd"]:
    tokens = content_encoding_tokens(headers)
    if tokens is None or len(tokens) > 1:
        raise UnsupportedRequestEncodingError("unsupported Content-Encoding")
    if not tokens or tokens[0] == "identity":
        return "identity"
    token = tokens[0]
    if token in {"gzip", "x-gzip"}:
        return "gzip"
    if token == "zstd":
        return "zstd"
    raise UnsupportedRequestEncodingError("unsupported Content-Encoding")


def _new_zstd_decoder() -> Any:
    return zstd.ZstdDecompressor(
        options={zstd.DecompressionParameter.window_log_max: _ZSTD_MAX_WINDOW_LOG}
    )


def decompress_request_body(body: bytes, encoding: CompressionCodec, max_bytes: int = 0) -> bytes:
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    if not body:
        raise InvalidCompressedRequestError("empty compressed request body")
    if encoding == "gzip":
        return _decompress_gzip_body(body, max_bytes)
    if encoding == "zstd":
        return _decompress_zstd_body(body, max_bytes)
    raise UnsupportedRequestEncodingError("unsupported Content-Encoding")


def _decompress_gzip_body(body: bytes, max_bytes: int) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    chunks: list[bytes] = []
    total = 0
    offset = 0
    length = len(body)
    try:
        while offset < length:
            piece = body[offset : offset + _INPUT_CHUNK_BYTES]
            offset += len(piece)
            while piece:
                step = (
                    min(_DECODE_CHUNK_BYTES, max_bytes - total + 1)
                    if max_bytes > 0
                    else _DECODE_CHUNK_BYTES
                )
                part = decoder.decompress(piece, step)
                if part:
                    total += len(part)
                    if max_bytes > 0 and total > max_bytes:
                        raise DecompressedRequestTooLargeError(max_bytes)
                    chunks.append(part)
                if decoder.eof:
                    if decoder.unused_data:
                        piece = decoder.unused_data
                        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    else:
                        piece = b""
                        if offset < length:
                            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                else:
                    piece = decoder.unconsumed_tail
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise InvalidCompressedRequestError("incomplete gzip request body")
    except zlib.error as exc:
        raise InvalidCompressedRequestError("corrupt gzip request body") from exc
    return b"".join(chunks)


def _decompress_zstd_body(body: bytes, max_bytes: int) -> bytes:
    decoder = _new_zstd_decoder()
    chunks: list[bytes] = []
    total = 0
    offset = 0
    length = len(body)
    try:
        while offset < length:
            piece = body[offset : offset + _INPUT_CHUNK_BYTES]
            offset += len(piece)
            while piece or (not decoder.needs_input and not decoder.eof):
                step = (
                    min(_DECODE_CHUNK_BYTES, max_bytes - total + 1)
                    if max_bytes > 0
                    else _DECODE_CHUNK_BYTES
                )
                part = decoder.decompress(piece, max_length=step)
                if part:
                    total += len(part)
                    if max_bytes > 0 and total > max_bytes:
                        raise DecompressedRequestTooLargeError(max_bytes)
                    chunks.append(part)
                if decoder.eof:
                    if decoder.unused_data:
                        piece = decoder.unused_data
                        decoder = _new_zstd_decoder()
                    else:
                        piece = b""
                        if offset < length:
                            decoder = _new_zstd_decoder()
                else:
                    piece = b""
        if not decoder.eof or decoder.unused_data:
            raise InvalidCompressedRequestError("incomplete zstd request body")
    except zstd.ZstdError as exc:
        raise InvalidCompressedRequestError("corrupt zstd request body") from exc
    return b"".join(chunks)


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
        or has_non_identity_content_encoding(headers)
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
