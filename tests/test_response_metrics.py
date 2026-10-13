import gzip
import json
import zlib
from typing import Any

import brotli
import pytest

from promptlatch.response_metrics import ResponseMetrics, zstd


class Clock:
    def __init__(self) -> None:
        self.now = 10.0

    def __call__(self) -> float:
        return self.now


def event(payload: dict[str, Any], *, newline: bytes = b"\n") -> bytes:
    return b"data: " + json.dumps(payload, ensure_ascii=False).encode() + newline * 2


def chat_delta(delta: dict[str, Any]) -> bytes:
    return event({"id": "chat_fixture", "model": "fixture-model", "choices": [{"delta": delta}]})


def test_chat_stream_timing_excludes_metadata_and_merges_cumulative_usage() -> None:
    clock = Clock()
    metrics = ResponseMetrics(clock.now, clock=clock)
    metrics.response_headers({"X-LiteLLM-Response-Cost": "0.000012"}, 200)
    clock.now = 11
    metrics.feed(chat_delta({"role": "assistant", "content": ""}))
    metrics.feed(b": ping\n\n")
    assert metrics.snapshot()["ttft_ms"] is None
    clock.now = 12
    metrics.feed(chat_delta({"content": "secret response content"}))
    clock.now = 14
    metrics.feed(chat_delta({"content": "final content"}))
    clock.now = 18
    metrics.feed(event({"usage": {"prompt_tokens": 10, "completion_tokens": 3}}))
    metrics.feed(
        event({"usage": {"completion_tokens": 5, "prompt_tokens_details": {"cached_tokens": 4}}})
    )
    metrics.feed(event({"choices": [{"finish_reason": "stop", "delta": {}}]}))
    metrics.finish_stream()
    assert metrics.snapshot() == {
        "model": "fixture-model",
        "response_id": "chat_fixture",
        "service_tier": None,
        "unsupported_costs": False,
        "outcome_override": None,
        "input_tokens": 10,
        "output_tokens": 5,
        "total_tokens": 15,
        "cached_input_tokens": 4,
        "cache_write_tokens": None,
        "reasoning_tokens": None,
        "usage_source": "upstream",
        "ttft_ms": 2000,
        "generation_ms": 2000,
        "tps": 2,
        "cost_usd": 0.000012,
        "cost_source": "litellm_header",
        "metrics_incomplete": False,
        "response_format": "sse",
        "metrics_unavailable_reason": None,
    }


@pytest.mark.parametrize(
    "delta",
    [
        {"refusal": "No"},
        {"reasoning_content": "Consider"},
        {"reasoning": "Consider"},
        {"tool_calls": [{"function": {"arguments": "{"}}]},
        {"function_call": {"arguments": "{"}},
    ],
)
def test_chat_nontext_output_starts_timing(delta: dict[str, Any]) -> None:
    metrics = ResponseMetrics(1, clock=lambda: 2)
    metrics.feed(chat_delta(delta))
    assert metrics.snapshot()["ttft_ms"] == 1000


def test_legacy_completions_text_drives_stream_timing_only() -> None:
    clock = Clock()
    metrics = ResponseMetrics(clock.now, clock=clock)
    metrics.feed(event({"choices": [{"text": ""}]}))
    assert metrics.snapshot()["ttft_ms"] is None
    clock.now = 11
    metrics.feed(event({"choices": [{"text": "hello"}]}))
    clock.now = 13
    metrics.feed(event({"choices": [{"text": " world"}]}))
    clock.now = 17
    complete = {
        "choices": [{"text": "", "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 5},
    }
    metrics.feed(event(complete))
    metrics.finish_stream()
    result = metrics.snapshot()
    assert result["ttft_ms"] == 1000
    assert result["generation_ms"] == 2000
    assert result["tps"] == 2
    assert result["outcome_override"] is None

    nonstream = ResponseMetrics(10, clock=clock)
    complete["choices"][0]["text"] = "hello world"
    nonstream.observe_body(json.dumps(complete).encode())
    assert nonstream.snapshot()["ttft_ms"] is None
    assert nonstream.snapshot()["generation_ms"] is None
    assert nonstream.snapshot()["tps"] is None


def test_responses_usage_and_tool_arguments() -> None:
    clock = Clock()
    metrics = ResponseMetrics(clock.now, clock=clock)
    metrics.feed(event({"type": "response.created", "response": {"id": "resp_fixture"}}))
    clock.now = 11
    metrics.feed(event({"type": "response.function_call_arguments.delta", "delta": "{"}))
    clock.now = 13
    metrics.feed(event({"type": "response.function_call_arguments.delta", "delta": "}"}))
    clock.now = 30
    metrics.feed(
        event(
            {
                "type": "response.completed",
                "response": {
                    "model": "fixture",
                    "status": "completed",
                    "usage": {
                        "input_tokens": 8,
                        "output_tokens": 7,
                        "input_tokens_details": {"cached_tokens": 3},
                    },
                },
            }
        )
    )
    metrics.finish_stream()
    result = metrics.snapshot()
    assert result["input_tokens"] == 8
    assert result["output_tokens"] == 7
    assert result["total_tokens"] == 15
    assert result["cached_input_tokens"] == 3
    assert result["ttft_ms"] == 1000
    assert result["generation_ms"] == 2000
    assert result["tps"] == 3
    assert result["outcome_override"] is None


def test_responses_custom_tool_input_drives_first_token_timing() -> None:
    clock = Clock()
    metrics = ResponseMetrics(clock.now, clock=clock)
    clock.now = 12
    metrics.feed(event({"type": "response.custom_tool_call_input.delta", "delta": "*** Begin"}))
    clock.now = 14
    metrics.feed(event({"type": "response.custom_tool_call_input.delta", "delta": " Patch"}))
    metrics.feed(
        event(
            {
                "type": "response.completed",
                "response": {"usage": {"input_tokens": 3, "output_tokens": 7}},
            }
        )
    )
    metrics.finish_stream()
    assert metrics.snapshot()["ttft_ms"] == 2000
    assert metrics.snapshot()["generation_ms"] == 2000
    assert metrics.snapshot()["tps"] == 3


@pytest.mark.parametrize("content_type", ["", "application/json", "application/octet-stream"])
@pytest.mark.parametrize("encoding", ["identity", "gzip"])
def test_response_protocol_detection_uses_bytes_and_preserves_arrival_times(
    content_type: str, encoding: str
) -> None:
    clock = Clock()
    metrics = ResponseMetrics(clock.now, clock=clock)
    metrics.response_headers({"content-type": content_type, "content-encoding": encoding}, 200)
    compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS) if encoding == "gzip" else None

    def feed(payload: dict[str, Any]) -> None:
        wire = event(payload)
        if compressor is not None:
            wire = compressor.compress(wire) + compressor.flush(zlib.Z_SYNC_FLUSH)
        metrics.feed_response(wire)

    clock.now = 11
    feed({"type": "response.created", "response": {"id": "resp_fixture"}})
    clock.now = 12
    feed({"type": "response.output_text.delta", "delta": "PRIVATE RESPONSE SENTINEL"})
    clock.now = 14
    feed({"type": "response.function_call_arguments.delta", "delta": "{}"})
    clock.now = 20
    feed(
        {
            "type": "response.completed",
            "response": {
                "model": "fixture-model",
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 7,
                    "input_tokens_details": {"cached_tokens": 30, "cache_write_tokens": 5},
                    "output_tokens_details": {"reasoning_tokens": 2},
                },
            },
        }
    )
    if compressor is not None:
        metrics.feed_response(compressor.flush())
    metrics.finish_response()
    result = metrics.snapshot()
    assert result["response_format"] == "sse"
    assert result["ttft_ms"] == 2000
    assert result["generation_ms"] == 2000
    assert result["tps"] == 3
    assert result["input_tokens"] == 100
    assert result["output_tokens"] == 7
    assert result["total_tokens"] == 107
    assert result["cached_input_tokens"] == 30
    assert result["cache_write_tokens"] == 5
    assert result["reasoning_tokens"] == 2
    assert result["metrics_incomplete"] is False
    assert result["metrics_unavailable_reason"] is None
    assert "PRIVATE RESPONSE SENTINEL" not in json.dumps(result)


def test_protocol_probe_handles_bytewise_bom_comments_and_nonstream_json() -> None:
    metrics = ResponseMetrics(1, clock=lambda: 2)
    wire = (
        b"\xef\xbb\xbf: keepalive\r\n\r\n"
        + event({"type": "response.output_text.delta", "delta": "hello"})
        + event(
            {
                "type": "response.completed",
                "response": {"usage": {"input_tokens": 3, "output_tokens": 1}},
            }
        )
    )
    for byte in wire:
        metrics.feed_response(bytes([byte]))
    metrics.finish_response()
    assert metrics.snapshot()["response_format"] == "sse"
    assert metrics.snapshot()["input_tokens"] == 3
    assert metrics.snapshot()["ttft_ms"] == 1000
    nonstream = ResponseMetrics(1, clock=lambda: 2)
    for byte in b'{"usage":{"input_tokens":3,"output_tokens":1}}':
        nonstream.feed_response(bytes([byte]))
    nonstream.finish_response()
    assert nonstream.snapshot()["response_format"] == "json"
    assert nonstream.snapshot()["input_tokens"] == 3
    assert nonstream.snapshot()["ttft_ms"] is None


@pytest.mark.parametrize(
    "encoding,body,reason",
    [
        ("fixture-encoding", b"opaque-compressed-data", "unsupported_encoding"),
        ("identity", b"not a JSON or SSE response", "malformed_response"),
        ("identity", b'{"output":[]}', "usage_missing"),
    ],
)
def test_missing_metrics_have_bounded_content_free_reason(encoding, body, reason) -> None:
    metrics = ResponseMetrics(1)
    metrics.response_headers({"content-encoding": encoding}, 200)
    metrics.observe_body(body)
    result = metrics.snapshot()
    assert result["metrics_unavailable_reason"] == reason
    assert result["input_tokens"] is None
    assert result["output_tokens"] is None
    assert result["metrics_incomplete"] is True
    assert body.decode() not in json.dumps(result)


def test_anthropic_cached_input_and_partial_cumulative_usage() -> None:
    clock = Clock()
    metrics = ResponseMetrics(clock.now, clock=clock)
    start = {
        "type": "message_start",
        "message": {
            "id": "msg_fixture",
            "model": "fixture",
            "usage": {
                "input_tokens": 5,
                "cache_read_input_tokens": 10,
                "cache_creation_input_tokens": 2,
                "output_tokens": 1,
            },
        },
    }
    metrics.feed(event(start))
    clock.now = 11
    metrics.feed(
        event(
            {
                "type": "content_block_delta",
                "delta": {"type": "thinking_delta", "thinking": "thinking"},
            }
        )
    )
    clock.now = 12
    metrics.feed(
        event(
            {
                "type": "content_block_delta",
                "delta": {"type": "input_json_delta", "partial_json": "{}"},
            }
        )
    )
    metrics.feed(event({"type": "message_delta", "usage": {"output_tokens": 7}}))
    metrics.feed(event({"type": "message_delta", "usage": {"output_tokens": 7}}))
    metrics.feed(event({"type": "message_stop"}))
    metrics.finish_stream()
    result = metrics.snapshot()
    assert result["input_tokens"] == 17
    assert result["output_tokens"] == 7
    assert result["cached_input_tokens"] == 10
    assert result["cache_write_tokens"] == 2
    assert result["total_tokens"] == 24
    assert result["tps"] == 6
    assert result["outcome_override"] is None


@pytest.mark.parametrize("newline", [b"\n", b"\r", b"\r\n"])
@pytest.mark.parametrize("chunk_size", [1, 7, 4096])
def test_sse_boundaries_utf8_and_multiline_data(newline: bytes, chunk_size: int) -> None:
    metrics = ResponseMetrics(1, clock=lambda: 2)
    stream = (
        b": comment"
        + newline
        + b"event: message"
        + newline
        + b'data: {"choices": [{"delta": {"content": "'
        + "日本語".encode()
        + b'"}}],'
        + newline
        + b'data: "usage": {"prompt_tokens": 2, "completion_tokens": 1}}'
        + newline * 2
        + b"data: [DONE]"
        + newline * 2
    )
    for start in range(0, len(stream), chunk_size):
        metrics.feed(stream[start : start + chunk_size])
    metrics.finish_stream()
    assert metrics.snapshot()["total_tokens"] == 3
    assert metrics.snapshot()["ttft_ms"] == 1000
    assert metrics.snapshot()["outcome_override"] is None


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "raw-deflate", "br", "zstd"])
def test_compressed_stream_does_not_change_input(encoding: str) -> None:
    stream = (
        chat_delta({"content": "hello"})
        + event({"usage": {"prompt_tokens": 2, "completion_tokens": 1}})
        + b"data: [DONE]\n\n"
    )
    if encoding == "gzip":
        compressed = gzip.compress(stream)
    elif encoding == "deflate":
        compressed = zlib.compress(stream)
    elif encoding == "br":
        compressed = brotli.compress(stream)
    elif encoding == "zstd":
        compressed = zstd.compress(stream)
    else:
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        compressed = compressor.compress(stream) + compressor.flush()
    metrics = ResponseMetrics(1, clock=lambda: 2)
    metrics.response_headers({"content-encoding": encoding.replace("raw-", "")}, 200)
    forwarded = []
    for offset in range(0, len(compressed), 1):
        chunk = compressed[offset : offset + 1]
        metrics.feed(chunk)
        forwarded.append(chunk)
    metrics.finish_stream()
    assert b"".join(forwarded) == compressed
    assert metrics.snapshot()["total_tokens"] == 3
    assert metrics.snapshot()["metrics_incomplete"] is False


def test_decoded_bridge_bytes_bypass_original_compression_header() -> None:
    metrics = ResponseMetrics(1, clock=lambda: 2)
    metrics.response_headers({"content-encoding": "gzip"}, 200)
    metrics.feed(event({"type": "response.output_text.delta", "delta": "hello"}), decoded=True)
    metrics.feed(
        event(
            {
                "type": "response.completed",
                "response": {"usage": {"input_tokens": 2, "output_tokens": 1}},
            }
        ),
        decoded=True,
    )
    metrics.finish_stream()
    assert metrics.snapshot()["metrics_incomplete"] is False
    assert metrics.snapshot()["ttft_ms"] == 1000


@pytest.mark.parametrize("bad", [-1, True, False, 1.5, "4", None, 1 << 64])
def test_invalid_token_counts_remain_unknown(bad: Any) -> None:
    metrics = ResponseMetrics(1)
    metrics.observe_body(
        json.dumps({"usage": {"prompt_tokens": bad, "completion_tokens": 3}}).encode()
    )
    result = metrics.snapshot()
    assert result["input_tokens"] is None
    assert result["total_tokens"] is None
    assert result["output_tokens"] == 3
    assert result["metrics_incomplete"] is True


@pytest.mark.parametrize("cost", ["-1", "nan", "inf", "1e999", "", "wrong"])
def test_invalid_cost_is_not_reported(cost: str) -> None:
    metrics = ResponseMetrics(1)
    metrics.response_headers({"x-litellm-response-cost": cost}, 200)
    assert metrics.snapshot()["cost_usd"] is None
    assert metrics.snapshot()["cost_source"] is None


@pytest.mark.parametrize("encoding", ["identity", "gzip", "deflate", "br", "zstd"])
def test_nonstream_usage_never_infers_token_timing(encoding: str) -> None:
    body = json.dumps(
        {
            "id": "resp_fixture",
            "model": "fixture",
            "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5},
        }
    ).encode()
    wire = (
        gzip.compress(body)
        if encoding == "gzip"
        else zlib.compress(body)
        if encoding == "deflate"
        else brotli.compress(body)
        if encoding == "br"
        else zstd.compress(body)
        if encoding == "zstd"
        else body
    )
    metrics = ResponseMetrics(1)
    metrics.response_headers({"content-encoding": encoding}, 200)
    metrics.observe_body(wire)
    assert metrics.snapshot()["total_tokens"] == 5
    assert metrics.snapshot()["ttft_ms"] is None
    assert metrics.snapshot()["generation_ms"] is None
    assert metrics.snapshot()["tps"] is None


@pytest.mark.parametrize(
    "stream",
    [
        b"",
        b": ping\n\n",
        b"data: not json\n\n",
        event({"type": [], "status": {}, "usage": []}),
        event({"unknown": True}),
    ],
)
def test_unknown_malformed_and_unterminated_streams_are_incomplete(stream: bytes) -> None:
    metrics = ResponseMetrics(1)
    metrics.feed(stream)
    metrics.finish_stream()
    assert metrics.snapshot()["outcome_override"] == "incomplete"
    assert metrics.snapshot()["metrics_incomplete"] is True


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"error": {"message": "private error"}}, "stream_error"),
        ({"type": "response.failed", "response": {"error": {"code": "failure"}}}, "stream_error"),
        ({"type": "response.incomplete"}, "incomplete"),
        ({"choices": [{"finish_reason": "length"}]}, "incomplete"),
        ({"type": "message_delta", "delta": {"stop_reason": "max_tokens"}}, "incomplete"),
    ],
)
def test_terminal_failures_override_http_success(payload: dict[str, Any], expected: str) -> None:
    metrics = ResponseMetrics(1)
    metrics.response_headers({}, 200)
    metrics.feed(event(payload))
    metrics.feed(b"data: [DONE]\n\n")
    metrics.finish_stream()
    assert metrics.snapshot()["outcome_override"] == expected
    assert "private error" not in json.dumps(metrics.snapshot())


@pytest.mark.parametrize("same_time", [False, True])
def test_tps_is_unknown_for_one_event_or_zero_interval(same_time: bool) -> None:
    metrics = ResponseMetrics(1, clock=lambda: 2)
    metrics.feed(chat_delta({"content": "first"}))
    if same_time:
        metrics.feed(chat_delta({"content": "second"}))
    metrics.feed(event({"usage": {"prompt_tokens": 2, "completion_tokens": 20}}))
    metrics.feed(b"data: [DONE]\n\n")
    metrics.finish_stream()
    assert metrics.snapshot()["tps"] is None
    assert metrics.snapshot()["generation_ms"] is None


@pytest.mark.parametrize("encoding", ["identity", "gzip", "gzip-members"])
def test_output_events_in_one_received_chunk_share_arrival_time(encoding: str) -> None:
    ticks = iter([2.0, 2.001, 2.002])
    metrics = ResponseMetrics(1, clock=lambda: next(ticks))
    first = chat_delta({"content": "first"})
    last = (
        chat_delta({"content": "second"})
        + event({"usage": {"prompt_tokens": 2, "completion_tokens": 20}})
        + b"data: [DONE]\n\n"
    )
    metrics.response_headers({"content-encoding": encoding.removesuffix("-members")}, 200)
    wire = (
        gzip.compress(first) + gzip.compress(last)
        if encoding == "gzip-members"
        else gzip.compress(first + last)
        if encoding == "gzip"
        else first + last
    )
    metrics.feed(wire)
    metrics.finish_stream()
    result = metrics.snapshot()
    assert result["ttft_ms"] == 1000
    assert result["generation_ms"] is None
    assert result["tps"] is None
    assert result["output_tokens"] == 20


def test_final_buffered_output_uses_last_chunk_arrival_not_finish_time() -> None:
    clock = Clock()
    metrics = ResponseMetrics(clock.now, clock=clock)
    clock.now = 12
    metrics.feed(chat_delta({"content": "first"}).rstrip(b"\n"))
    clock.now = 100
    metrics.finish_stream()
    assert metrics.snapshot()["ttft_ms"] == 2000


def test_chat_delta_does_not_bypass_error_usage_metadata_or_hosted_output() -> None:
    metrics = ResponseMetrics(1, clock=lambda: 2)
    metrics.feed(
        event(
            {
                "choices": [{"delta": {"content": "hello"}}],
                "error": {"code": "upstream_failure"},
                "usage": {"prompt_tokens": 3, "completion_tokens": 4},
                "model": "fixture",
                "id": "resp_fixture",
                "service_tier": "flex",
                "output": [{"type": "web_search_call"}],
            }
        )
    )
    metrics.feed(b"data: [DONE]\n\n")
    metrics.finish_stream()
    result = metrics.snapshot()
    assert result["outcome_override"] == "stream_error"
    assert result["total_tokens"] == 7
    assert result["model"] == "fixture"
    assert result["response_id"] == "resp_fixture"
    assert result["service_tier"] == "flex"
    assert result["unsupported_costs"] is True
    assert result["ttft_ms"] == 1000


def test_oversized_event_is_dropped_and_following_usage_still_parses() -> None:
    metrics = ResponseMetrics(1)
    metrics.feed(b'data: {"content": "' + b"x" * (1024 * 1024 + 1))
    metrics.feed(b'"}\n\n')
    metrics.feed(event({"usage": {"prompt_tokens": 2, "completion_tokens": 3}}))
    metrics.feed(b"data: [DONE]\n\n")
    metrics.finish_stream()
    assert metrics.snapshot()["total_tokens"] == 5
    assert metrics.snapshot()["metrics_incomplete"] is True


@pytest.mark.parametrize("encoding", ["gzip", "br", "zstd"])
def test_oversized_compressed_body_is_bounded(encoding: str) -> None:
    metrics = ResponseMetrics(1)
    metrics.response_headers({"content-encoding": encoding}, 200)
    body = b" " * (8 * 1024 * 1024 + 1)
    wire = (
        gzip.compress(body)
        if encoding == "gzip"
        else brotli.compress(body)
        if encoding == "br"
        else zstd.compress(body)
    )
    metrics.observe_body(wire)
    assert metrics.snapshot()["metrics_incomplete"] is True
    assert metrics.snapshot()["usage_source"] is None
    assert metrics.snapshot()["metrics_unavailable_reason"] == "observation_limit"


def test_concatenated_zstd_frames_and_truncation_keep_metrics_conservative() -> None:
    wire = zstd.compress(chat_delta({"content": "hello"})) + zstd.compress(
        event({"usage": {"prompt_tokens": 2, "completion_tokens": 1}}) + b"data: [DONE]\n\n"
    )
    metrics = ResponseMetrics(1, clock=lambda: 2)
    metrics.response_headers({"content-encoding": "zstd"}, 200)
    metrics.feed(wire)
    metrics.finish_stream()
    assert metrics.snapshot()["total_tokens"] == 3
    assert metrics.snapshot()["metrics_incomplete"] is False
    incomplete = ResponseMetrics(1)
    incomplete.response_headers({"content-encoding": "zstd"}, 200)
    incomplete.feed(wire[:-1])
    incomplete.finish_stream()
    assert incomplete.snapshot()["metrics_incomplete"] is True


@pytest.mark.parametrize(
    "encoding,chunk",
    [
        ("br", b"uninspected"),
        ("gzip", b"not gzip"),
        ("gzip", gzip.compress(b"data: [DONE]\n\n")[:-8]),
    ],
)
def test_unsupported_invalid_and_truncated_compression_does_not_raise(
    encoding: str, chunk: bytes
) -> None:
    metrics = ResponseMetrics(1)
    metrics.response_headers({"content-encoding": encoding}, 200)
    metrics.feed(chunk)
    metrics.finish_stream()
    assert metrics.snapshot()["metrics_incomplete"] is True


def test_actual_service_tier_is_preserved_from_completed_response() -> None:
    metrics = ResponseMetrics(1)
    metrics.feed(event({"type": "response.completed", "response": {"service_tier": "flex"}}))
    metrics.finish_stream()
    assert metrics.snapshot()["service_tier"] == "flex"


def test_sse_byte_order_mark_and_unterminated_final_event() -> None:
    metrics = ResponseMetrics(1, clock=lambda: 2)
    stream = b"\xef\xbb\xbf" + chat_delta({"content": "hello"}) + b"data: [DONE]"
    for byte in stream:
        metrics.feed(bytes([byte]))
    metrics.finish_stream()
    assert metrics.snapshot()["outcome_override"] is None
    assert metrics.snapshot()["ttft_ms"] == 1000


def test_gzip_concatenated_members_are_observed() -> None:
    metrics = ResponseMetrics(1, clock=lambda: 2)
    metrics.response_headers({"content-encoding": "gzip"}, 200)
    metrics.feed(gzip.compress(chat_delta({"content": "hello"})))
    metrics.feed(
        gzip.compress(event({"usage": {"prompt_tokens": 2, "completion_tokens": 3}}))
        + gzip.compress(b"data: [DONE]\n\n")
    )
    metrics.finish_stream()
    assert metrics.snapshot()["total_tokens"] == 5
    assert metrics.snapshot()["metrics_incomplete"] is False


def test_many_data_lines_share_the_event_size_bound() -> None:
    metrics = ResponseMetrics(1)
    metrics.feed((b"data: " + b"x" * 1000 + b"\n") * 1100 + b"\n")
    metrics.feed(event({"usage": {"prompt_tokens": 2, "completion_tokens": 3}}))
    metrics.feed(b"data: [DONE]\n\n")
    metrics.finish_stream()
    assert metrics.snapshot()["total_tokens"] == 5
    assert metrics.snapshot()["metrics_incomplete"] is True


@pytest.mark.parametrize(
    "payload",
    [
        {"usage": {"completion_tokens_details": {"audio_tokens": 20}}},
        {"usage": {"input_tokens_details": {"audio_tokens": 3}}},
        {"usage": {"server_tool_use": {"web_search_requests": 1}}},
        {"output": [{"type": "web_search_call", "action": {"query": "private"}}]},
        {"type": "response.output_item.added", "item": {"type": "image_generation_call"}},
        {"type": "content_block_start", "content_block": {"type": "server_tool_use"}},
        {"type": "response.output_audio.delta", "delta": "private"},
        {"choices": [{"delta": {"audio": {"data": "private"}}}]},
        {"choices": [{"message": {"audio": {"data": "private"}}}]},
        {"output": [{"type": "message", "content": [{"type": "output_audio"}]}]},
    ],
)
def test_observed_audio_and_hosted_tools_disable_plain_token_costs(payload: dict[str, Any]) -> None:
    metrics = ResponseMetrics(1)
    metrics.feed(event(payload))
    assert metrics.snapshot()["unsupported_costs"] is True
    assert "private" not in json.dumps(metrics.snapshot())
