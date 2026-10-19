"""Bounded response observers. Response content is never part of a snapshot."""

from __future__ import annotations

import json
import math
import re
import sys
import time
import zlib
from collections.abc import Callable, Iterator, Mapping
from typing import TYPE_CHECKING, Any, Protocol

import brotli
from pydantic_core import from_json

from promptlatch.upstream_errors import (
    MAX_ERROR_SOURCE_BYTES,
    OVERSIZED_ERROR_FIELD,
    PROVIDER_ERROR_FIELDS,
)

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

if TYPE_CHECKING:
    from zlib import _Decompress

_MAX_EVENT_BYTES = 1024 * 1024
_MAX_BODY_BYTES = 8 * 1024 * 1024
_MAX_STREAM_BYTES = 128 * 1024 * 1024
_DECODE_CHUNK_BYTES = 64 * 1024
_MAX_TOKENS = (1 << 63) - 1
_LINE_END = re.compile(rb"[\r\n]")
_SINGLE_DATA_EVENT = re.compile(rb"data: ?([^\r\n]*)(?:\n\n|\r\n\r\n|\r\r)")
_CHAT_EVENT_KEYS = frozenset(
    {"choices", "id", "model", "service_tier", "usage", "object", "created", "system_fingerprint"}
)
_TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
)
_SSE_PREFIXES = (b"data:", b"event:", b":", b"id:", b"retry:")
_RESPONSE_DELTAS = {
    "response.output_text.delta",
    "response.refusal.delta",
    "response.reasoning_text.delta",
    "response.reasoning_summary_text.delta",
    "response.function_call_arguments.delta",
    "response.custom_tool_call_input.delta",
}
_HOSTED_OUTPUT = {
    "web_search_call",
    "file_search_call",
    "code_interpreter_call",
    "computer_call",
    "image_generation_call",
    "mcp_call",
    "mcp_list_tools",
    "server_tool_use",
    "web_search_tool_result",
    "code_execution_tool_result",
}
_TRANSPORT_REASONS = {
    "ConnectTimeout": "Timed out connecting to upstream.",
    "ReadTimeout": "Timed out reading the upstream response.",
    "WriteTimeout": "Timed out sending the upstream request.",
    "PoolTimeout": "Timed out waiting for an upstream connection.",
    "ConnectError": "Could not establish an upstream connection.",
    "ReadError": "Upstream connection failed while reading the response.",
    "WriteError": "Upstream connection failed while sending the request.",
    "CloseError": "Upstream connection failed while closing.",
    "RemoteProtocolError": "Upstream returned an invalid or incomplete HTTP response.",
    "LocalProtocolError": "The upstream request violated the HTTP protocol.",
    "ProxyError": "Could not establish a connection through the upstream proxy.",
    "UnsupportedProtocol": "The upstream URL protocol is unsupported.",
    "DecodingError": "The upstream response could not be decoded.",
    "TooManyRedirects": "The upstream response exceeded the redirect limit.",
    "TimeoutException": "The upstream request timed out.",
    "NetworkError": "The upstream network connection failed.",
    "ProtocolError": "The upstream connection failed HTTP protocol validation.",
    "TransportError": "Upstream transport failed.",
    "RequestError": "Upstream request failed.",
}
_ANTHROPIC_STREAM_EVENTS = {
    "message_start",
    "message_delta",
    "message_stop",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
}


class _BrotliDecoder(Protocol):
    def process(self, data: bytes, *, output_buffer_limit: int) -> bytes: ...
    def can_accept_more_data(self) -> bool: ...
    def is_finished(self) -> bool: ...


class ResponseMetrics:
    """Observe copied bytes without modifying them or retaining response bodies.

    Token counts come only from upstream usage. Streaming TPS approximates the
    rate after the first token; chunk boundaries cannot reveal exact token times.
    """

    def __init__(self, started: float, *, clock: Callable[[], float] = time.perf_counter) -> None:
        self._started = started
        self._clock = clock
        self._model: str | None = None
        self._response_id: str | None = None
        self._service_tier: str | None = None
        self._unsupported_costs = False
        self._usage: dict[str, int | None] = dict.fromkeys(_TOKEN_FIELDS)
        self._usage_source: str | None = None
        self._anthropic_input: int | None = None
        self._cost: float | None = None
        self._first_output: float | None = None
        self._last_output: float | None = None
        self._arrival_time: float | None = None
        self._saw_output = False
        self._output_events = 0
        self._terminal = False
        self._outcome: str | None = None
        self._incomplete = False
        self._finished = False
        self._encoding = ""
        self._decoder: _Decompress | None = None
        self._brotli_decoder: _BrotliDecoder | None = None
        self._zstd_decoder: zstd.ZstdDecompressor | None = None
        self._compressed_seen = False
        self._compression_probe = b""
        self._skip = False
        self._observed_bytes = 0
        self._line = bytearray()
        self._first_line = True
        self._skip_line = False
        self._after_cr = False
        self._event_data = bytearray()
        self._event_name = ""
        self._skip_event = False
        self._protocol: str | None = None
        self._llm_stream = False
        self._probe = bytearray()
        self._body = bytearray()
        self._unavailable_reason: str | None = None
        self._http_error = False
        self._error_details: dict[str, str] = {}
        self._transport_error_details: dict[str, str] = {}

    def response_headers(self, headers: Mapping[str, str], status_code: int) -> None:
        self._http_error = status_code >= 400
        fields = {key.lower(): value for key, value in headers.items()}
        self._encoding = fields.get("content-encoding", "").strip().lower()
        if "text/event-stream" in fields.get("content-type", "").lower():
            self._protocol = "sse"
        cost = fields.get("x-litellm-response-cost")
        if cost is not None:
            try:
                parsed = float(cost)
            except (TypeError, ValueError, OverflowError):
                pass
            else:
                if math.isfinite(parsed) and parsed >= 0:
                    self._cost = parsed

    def feed(self, chunk: bytes, *, decoded: bool = False) -> None:
        self._protocol = "sse"
        self.feed_response(chunk, decoded=decoded)

    def feed_response(self, chunk: bytes, *, decoded: bool = False) -> None:
        """Observe arrivals even when an upstream labels SSE as JSON or omits its type."""
        if self._finished or self._skip or not chunk:
            return
        arrival = self._clock()
        self._arrival_time = arrival if math.isfinite(arrival) else None
        self._saw_output = False
        for part in self._decode(chunk, decoded=decoded):
            self._observed_bytes += len(part)
            if self._observed_bytes > _MAX_STREAM_BYTES:
                self._stop_observing("observation_limit")
                break
            if self._protocol is None:
                self._probe.extend(part)
                prefix = bytes(self._probe).removeprefix(b"\xef\xbb\xbf").lstrip()
                if prefix.startswith(_SSE_PREFIXES):
                    self._protocol = "sse"
                elif prefix.startswith((b"{", b"[")) or len(self._probe) >= 32:
                    self._protocol = "json"
                else:
                    continue
                part = bytes(self._probe)
                self._probe.clear()
            if self._protocol == "sse":
                self._feed_lines(part)
            elif len(self._body) + len(part) > _MAX_BODY_BYTES:
                self._stop_observing("observation_limit")
                break
            else:
                self._body.extend(part)
        if self._saw_output:
            self._record_output()

    def finish_stream(self, *, complete: bool = True) -> None:
        if self._finished:
            return
        compression_incomplete = (
            not self._skip and self._compressed_seen and not self._compression_complete()
        )
        if compression_incomplete:
            self._incomplete = True
            if self._outcome != "stream_error":
                self._outcome = "incomplete"
        if not self._skip:
            self._saw_output = False
            if self._line:
                self._consume_line(bytes(self._line))
            self._dispatch_event()
            if self._saw_output:
                self._record_output()
        if not self._terminal and self._outcome != "stream_error":
            self._outcome = "incomplete"
            self._incomplete = True
            if (
                complete
                and self._llm_stream
                and not self._skip
                and not compression_incomplete
                and not self._unavailable_reason
                and not self._error_details
                and not self._transport_error_details
            ):
                self._error_details = {
                    "event": "stream",
                    "type": "stream_error",
                    "code": "stream_incomplete",
                    "message": "Upstream stream ended before a completion event.",
                }
        self._finished = True
        self._clear_buffers()

    def finish_response(self, *, complete: bool = True) -> None:
        if self._finished:
            return
        if self._protocol == "sse":
            self.finish_stream(complete=complete)
            return
        if not self._skip and self._compressed_seen and not self._compression_complete():
            self._incomplete = True
            self._unavailable_reason = "malformed_response"
        if not self._skip:
            self._body.extend(self._probe)
            self._probe.clear()
            if self._body:
                payload = self._parse(bytes(self._body))
                if payload is not None:
                    self._protocol = "json"
                    self._observe_payload(payload, streaming=False)
        self._finished = True
        self._clear_buffers()

    def observe_body(self, body: bytes, *, decoded: bool = False) -> None:
        self.feed_response(body, decoded=decoded)
        self.finish_response()

    def take_error_details(self) -> dict[str, str]:
        """Consume bounded raw error fields; callers must redact before retaining them."""
        details = self._error_details or self._transport_error_details
        self._error_details = {}
        self._transport_error_details = {}
        return details

    def transport_error(self, error_type: str) -> None:
        """Retain an allowlisted class and static reason, never exception text."""
        if self._transport_error_details:
            return
        if error_type not in _TRANSPORT_REASONS:
            error_type = "RequestError"
        self._transport_error_details = {
            "event": "transport",
            "type": error_type,
            "code": "upstream_transport_error",
            "message": _TRANSPORT_REASONS[error_type],
        }

    def snapshot(self) -> dict[str, Any]:
        ttft = generation = tps = None
        if self._first_output is not None:
            ttft = max(0.0, self._first_output - self._started) * 1000
            if self._last_output is not None and self._output_events > 1:
                elapsed = self._last_output - self._first_output
                if elapsed > 0:
                    generation = elapsed * 1000
                    output = self._usage["output_tokens"]
                    if output is not None and output > 1:
                        tps = (output - 1) / elapsed
        return {
            "model": self._model,
            "response_id": self._response_id,
            "service_tier": self._service_tier,
            "unsupported_costs": self._unsupported_costs,
            "outcome_override": self._outcome,
            **self._usage,
            "usage_source": self._usage_source,
            "ttft_ms": ttft,
            "generation_ms": generation,
            "tps": tps,
            "cost_usd": self._cost,
            "cost_source": "litellm_header" if self._cost is not None else None,
            "metrics_incomplete": self._incomplete
            or self._usage["input_tokens"] is None
            or self._usage["output_tokens"] is None,
            "response_format": self._protocol or "unknown",
            "metrics_unavailable_reason": self._unavailable_reason
            or (
                "usage_missing"
                if self._usage["input_tokens"] is None or self._usage["output_tokens"] is None
                else None
            ),
        }

    def _decode(self, chunk: bytes, *, decoded: bool) -> Iterator[bytes]:
        if decoded or self._encoding in {"", "identity"}:
            yield chunk
            return
        if self._encoding == "br":
            yield from self._decode_brotli(chunk)
            return
        if self._encoding == "zstd":
            yield from self._decode_zstd(chunk)
            return
        if self._encoding not in {"gzip", "deflate"}:
            self._stop_observing("unsupported_encoding")
            return
        self._compressed_seen = True
        if self._decoder is None:
            if self._encoding == "gzip":
                self._decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            else:
                chunk = self._compression_probe + chunk
                self._compression_probe = b""
                if len(chunk) < 2:
                    self._compression_probe = chunk
                    return
                wrapped = chunk[0] & 15 == 8 and int.from_bytes(chunk[:2]) % 31 == 0
                self._decoder = zlib.decompressobj(zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
        decoder = self._decoder
        try:
            while chunk:
                part = decoder.decompress(chunk, _DECODE_CHUNK_BYTES)
                if part:
                    yield part
                if self._skip:
                    return
                if decoder.unused_data:
                    # gzip permits concatenated members.
                    if self._encoding != "gzip":
                        self._stop_observing("malformed_response")
                        return
                    chunk = decoder.unused_data
                    decoder = self._decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                else:
                    chunk = decoder.unconsumed_tail
        except zlib.error:
            self._stop_observing("malformed_response")

    def _decode_brotli(self, chunk: bytes) -> Iterator[bytes]:
        self._compressed_seen = True
        decoder: _BrotliDecoder = self._brotli_decoder or brotli.Decompressor()
        self._brotli_decoder = decoder
        try:
            while chunk or not decoder.can_accept_more_data():
                part = decoder.process(chunk, output_buffer_limit=_DECODE_CHUNK_BYTES)
                chunk = b""
                if part:
                    yield part
                if self._skip:
                    return
        except brotli.error:
            self._stop_observing("malformed_response")

    def _decode_zstd(self, chunk: bytes) -> Iterator[bytes]:
        self._compressed_seen = True
        decoder = self._zstd_decoder
        try:
            while chunk or (decoder is not None and not decoder.needs_input and not decoder.eof):
                if decoder is None or decoder.eof:
                    decoder = self._zstd_decoder = zstd.ZstdDecompressor(
                        options={zstd.DecompressionParameter.window_log_max: 23}
                    )
                part = decoder.decompress(chunk, max_length=_DECODE_CHUNK_BYTES)
                if part:
                    yield part
                if self._skip:
                    return
                chunk = decoder.unused_data if decoder.eof else b""
        except zstd.ZstdError:
            self._stop_observing("malformed_response")

    def _compression_complete(self) -> bool:
        if self._encoding == "br":
            return self._brotli_decoder is not None and self._brotli_decoder.is_finished()
        if self._encoding == "zstd":
            return self._zstd_decoder is not None and self._zstd_decoder.eof
        return self._decoder is not None and self._decoder.eof

    def _feed_lines(self, chunk: bytes) -> None:
        start = 0
        if self._after_cr:
            if chunk.startswith(b"\n"):
                start = 1
            if chunk:
                self._after_cr = False
        while start < len(chunk):
            if not (
                self._line
                or self._event_data
                or self._event_name
                or self._skip_line
                or self._skip_event
            ):
                event = _SINGLE_DATA_EVENT.match(chunk, start)
                if event is not None and event.end(1) - start <= _MAX_EVENT_BYTES:
                    self._first_line = False
                    self._after_cr = chunk[event.end() - 1] == 13
                    self._observe_event_data(event[1])
                    start = event.end()
                    continue
            match = _LINE_END.search(chunk, start)
            if match is None:
                break
            end = match.start()
            if self._after_cr and chunk[end] == 10 and end == start:
                self._after_cr = False
                start = end + 1
                continue
            self._append_line(chunk, start, end)
            if not self._skip_line:
                self._consume_line(bytes(self._line))
            self._line.clear()
            self._skip_line = False
            self._after_cr = chunk[end] == 13
            start = end + 1
        if start < len(chunk):
            self._after_cr = False
            self._append_line(chunk, start, len(chunk))

    def _append_line(self, chunk: bytes, start: int, end: int) -> None:
        if self._skip_line:
            return
        if len(self._line) + end - start > _MAX_EVENT_BYTES:
            self._line.clear()
            self._event_data.clear()
            self._skip_line = self._skip_event = self._incomplete = True
            self._unavailable_reason = "observation_limit"
            return
        self._line.extend(memoryview(chunk)[start:end])

    def _consume_line(self, line: bytes) -> None:
        if self._first_line:
            line = line.removeprefix(b"\xef\xbb\xbf")
            self._first_line = False
        if not line:
            self._dispatch_event()
            return
        if self._skip_event or line.startswith(b":"):
            return
        field, _, value = line.partition(b":")
        if value.startswith(b" "):
            value = value[1:]
        if field == b"event":
            self._event_name = value[:128].decode("ascii", errors="replace")
        elif field == b"data":
            if len(self._event_data) + len(value) + 1 > _MAX_EVENT_BYTES:
                self._event_data.clear()
                self._skip_event = self._incomplete = True
                self._unavailable_reason = "observation_limit"
            else:
                self._event_data.extend(value)
                self._event_data.append(10)

    def _dispatch_event(self) -> None:
        if self._event_name == "error":
            self._outcome = "stream_error"
            self._error_details.setdefault("event", "error")
        if self._event_data and not self._skip_event:
            data = bytes(self._event_data[:-1])
            self._observe_event_data(data)
        self._event_data.clear()
        self._event_name = ""
        self._skip_event = False

    def _observe_event_data(self, data: bytes) -> None:
        if data.strip() == b"[DONE]":
            self._terminal = True
        else:
            payload = self._parse(data)
            if payload is not None:
                self._observe_payload(payload, streaming=True)

    def _parse(self, data: bytes) -> dict[str, Any] | None:
        try:
            try:
                payload = from_json(data, cache_strings=False)
            except ValueError:
                payload = json.loads(data)
        except (ValueError, UnicodeError, RecursionError):
            self._incomplete = True
            self._unavailable_reason = "malformed_response"
            return None
        if not isinstance(payload, dict):
            self._incomplete = True
            self._unavailable_reason = "malformed_response"
            return None
        return payload

    def _observe_payload(self, payload: dict[str, Any], *, streaming: bool) -> None:
        if streaming and not self._llm_stream:
            event_type = payload.get("type")
            self._llm_stream = isinstance(payload.get("choices"), list) or (
                isinstance(event_type, str)
                and (event_type.startswith("response.") or event_type in _ANTHROPIC_STREAM_EVENTS)
            )
        if streaming and payload.keys() <= _CHAT_EVENT_KEYS:
            if "model" in payload or "id" in payload or "service_tier" in payload:
                self._metadata(payload)
            if "usage" in payload:
                usage = payload["usage"]
                if isinstance(usage, dict):
                    self._merge_usage(usage, anthropic=False)
            if self._observe_choices(payload.get("choices")):
                self._saw_output = True
            return
        event_type = payload.get("type")
        if not isinstance(event_type, str):
            event_type = ""
        response = payload.get("response")
        message = payload.get("message")
        envelope = response if isinstance(response, dict) else payload
        anthropic = event_type in {"message", "message_start", "message_delta", "message_stop"}
        if event_type == "message_start" and isinstance(message, dict):
            envelope = message
        self._metadata(envelope)
        self._inspect_output_costs(envelope)
        if envelope is not payload:
            self._inspect_output_costs(payload)
        if event_type.startswith(("response.audio.", "response.output_audio.")):
            self._unsupported_costs = True
        if isinstance(envelope.get("usage"), dict):
            self._merge_usage(envelope["usage"], anthropic=anthropic)
        if envelope is not payload and isinstance(payload.get("usage"), dict):
            self._merge_usage(payload["usage"], anthropic=anthropic)
        error = envelope.get("error")
        if error is None:
            error = payload.get("error")
        failed = event_type in {"error", "response.failed", "response.error"}
        if error is not None:
            self._outcome = "stream_error"
        status = envelope.get("status")
        if not isinstance(status, str):
            status = ""
        if failed or status == "failed":
            self._outcome = "stream_error"
        elif (
            event_type == "response.incomplete" or status in {"incomplete", "cancelled"}
        ) and self._outcome != "stream_error":
            self._outcome = "incomplete"
        if (
            error is not None
            or failed
            or status == "failed"
            or self._http_error
            or self._event_name == "error"
        ):
            self._capture_error(payload, error, event_type)
        if event_type in {
            "response.completed",
            "response.failed",
            "response.incomplete",
            "message_stop",
        }:
            self._terminal = True
        meaningful = self._observe_choices(payload.get("choices"))
        if isinstance(event_type, str) and event_type in _RESPONSE_DELTAS:
            meaningful |= _has_text(payload.get("delta"))
        if event_type == "content_block_delta":
            delta = payload.get("delta")
            if isinstance(delta, dict):
                meaningful |= any(
                    _has_text(delta.get(key)) for key in ("text", "thinking", "partial_json")
                )
        if event_type == "content_block_start":
            block = payload.get("content_block")
            if isinstance(block, dict):
                meaningful |= _has_text(block.get("text")) or _has_text(block.get("thinking"))
        if event_type == "message_delta":
            delta = payload.get("delta")
            stop = delta.get("stop_reason") if isinstance(delta, dict) else None
            if (
                isinstance(stop, str)
                and stop in {"max_tokens", "model_context_window_exceeded"}
                and self._outcome != "stream_error"
            ):
                self._outcome = "incomplete"
        if streaming and meaningful:
            self._saw_output = True

    def _capture_error(self, payload: dict[str, Any], error: Any, event_type: str) -> None:
        if isinstance(error, dict):
            details = error
        elif isinstance(error, str):
            details = {"message": error}
        else:
            details = payload
            if isinstance(payload.get("detail"), str):
                details = {**payload, "message": payload["detail"]}
        for key in PROVIDER_ERROR_FIELDS:
            if key in self._error_details:
                continue
            value = (
                event_type or ("error" if self._event_name == "error" else "")
                if key == "event" and self._protocol == "sse"
                else details.get(key)
            )
            if key == "code" and type(value) is int and 0 <= value <= 999_999_999:
                value = str(value)
            if not isinstance(value, str) or not value:
                continue
            self._error_details[key] = _bounded_error_source(value)

    def _observe_choices(self, choices: Any) -> bool:
        meaningful = False
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                if "text" in choice:
                    meaningful |= _has_text(choice["text"])
                finish = choice.get("finish_reason")
                if finish and isinstance(finish, str):
                    self._terminal = True
                    if finish in {"length", "content_filter"} and self._outcome != "stream_error":
                        self._outcome = "incomplete"
                delta = choice.get("delta")
                if isinstance(delta, dict):
                    if delta.get("audio"):
                        self._unsupported_costs = True
                    content = delta.get("content")
                    if isinstance(content, str) and content:
                        meaningful = True
                    else:
                        meaningful |= self._chat_output(delta)
                if "message" in choice:
                    message = choice["message"]
                    if isinstance(message, dict) and message.get("audio"):
                        self._unsupported_costs = True
        return meaningful

    def _record_output(self) -> None:
        if self._arrival_time is not None:
            if self._first_output is None:
                self._first_output = self._arrival_time
            self._last_output = self._arrival_time
            self._output_events += 1

    def _metadata(self, envelope: dict[str, Any]) -> None:
        model = envelope.get("model")
        response_id = envelope.get("id")
        tier = envelope.get("service_tier")
        if isinstance(model, str) and 0 < len(model) <= 512:
            self._model = model
        if isinstance(response_id, str) and 0 < len(response_id) <= 512:
            self._response_id = response_id
        if isinstance(tier, str) and 0 < len(tier) <= 64:
            self._service_tier = tier

    def _inspect_output_costs(self, envelope: dict[str, Any]) -> None:
        for key in ("output", "content"):
            blocks = envelope.get(key)
            if isinstance(blocks, list):
                for block in blocks:
                    self._inspect_output_block(block)
        self._inspect_output_block(envelope.get("item"))
        self._inspect_output_block(envelope.get("content_block"))

    def _inspect_output_block(self, block: Any) -> None:
        if not isinstance(block, dict):
            return
        kind = block.get("type")
        if isinstance(kind, str) and (kind in _HOSTED_OUTPUT or "audio" in kind):
            self._unsupported_costs = True
        content = block.get("content")
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    kind = part.get("type")
                    if isinstance(kind, str) and "audio" in kind:
                        self._unsupported_costs = True

    def _merge_usage(self, usage: dict[str, Any], *, anthropic: bool) -> None:
        for key in (
            "input_tokens_details",
            "prompt_tokens_details",
            "output_tokens_details",
            "completion_tokens_details",
            "server_tool_use",
        ):
            details = usage.get(key)
            if isinstance(details, dict):
                for name, value in details.items():
                    if ("audio" in name or name.endswith("_requests")) and value != 0:
                        self._unsupported_costs = True
        fields = {
            "input_tokens": "input_tokens" if "input_tokens" in usage else "prompt_tokens",
            "output_tokens": "output_tokens" if "output_tokens" in usage else "completion_tokens",
            "total_tokens": "total_tokens",
            "cached_input_tokens": "cache_read_input_tokens",
            "cache_write_tokens": "cache_creation_input_tokens",
        }
        for target, source in fields.items():
            if source not in usage:
                continue
            value = _token_count(usage[source])
            if value is None:
                self._incomplete = True
                continue
            self._usage_source = "upstream"
            if target == "input_tokens" and anthropic:
                self._anthropic_input = value
            else:
                self._usage[target] = value
        details = usage.get("input_tokens_details", usage.get("prompt_tokens_details"))
        if isinstance(details, dict) and "cached_tokens" in details:
            value = _token_count(details["cached_tokens"])
            if value is None:
                self._incomplete = True
            else:
                self._usage["cached_input_tokens"] = value
                self._usage_source = "upstream"
        for key, target, source in (
            ("input_tokens_details", "cache_write_tokens", "cache_write_tokens"),
            ("output_tokens_details", "reasoning_tokens", "reasoning_tokens"),
            ("completion_tokens_details", "reasoning_tokens", "reasoning_tokens"),
        ):
            details = usage.get(key)
            if isinstance(details, dict) and source in details:
                value = _token_count(details[source])
                if value is None:
                    self._incomplete = True
                else:
                    self._usage[target] = value
                    self._usage_source = "upstream"
        if self._anthropic_input is not None:
            self._usage["input_tokens"] = _token_count(
                self._anthropic_input
                + (self._usage["cached_input_tokens"] or 0)
                + (self._usage["cache_write_tokens"] or 0)
            )
        if "total_tokens" not in usage:
            input_tokens, output_tokens = self._usage["input_tokens"], self._usage["output_tokens"]
            if input_tokens is not None and output_tokens is not None:
                self._usage["total_tokens"] = _token_count(input_tokens + output_tokens)

    @staticmethod
    def _chat_output(delta: dict[str, Any]) -> bool:
        content = delta.get("content")
        if isinstance(content, str) and content:
            return True
        for key in ("refusal", "reasoning", "reasoning_content"):
            if _has_text(delta.get(key)):
                return True
        function = delta.get("function_call")
        if isinstance(function, dict) and _has_text(function.get("arguments")):
            return True
        calls = delta.get("tool_calls")
        if isinstance(calls, list):
            for call in calls:
                if isinstance(call, dict):
                    function = call.get("function")
                    if isinstance(function, dict) and _has_text(function.get("arguments")):
                        return True
        return False

    def _clear_buffers(self) -> None:
        self._line.clear()
        self._event_data.clear()
        self._event_name = ""
        self._compression_probe = b""
        self._decoder = None
        self._brotli_decoder = None
        self._zstd_decoder = None
        self._probe.clear()
        self._body.clear()

    def _stop_observing(self, reason: str) -> None:
        self._skip = self._incomplete = True
        self._unavailable_reason = reason
        self._clear_buffers()


def _has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _bounded_error_source(value: str) -> str:
    # Never cut raw secrets: oversized fields are omitted before redaction.
    if (
        len(value) > MAX_ERROR_SOURCE_BYTES
        or len(value.encode("utf-8", errors="replace")) > MAX_ERROR_SOURCE_BYTES
    ):
        return OVERSIZED_ERROR_FIELD
    return value


def _token_count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= _MAX_TOKENS else None
