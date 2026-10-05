from __future__ import annotations

import asyncio
import json
import sys

import pytest

from promptlatch.compat import chat_stream_to_responses


async def _collect(chunks: list[bytes]) -> bytes:
    async def source():
        for chunk in chunks:
            yield chunk

    return b"".join([part async for part in chat_stream_to_responses(source())])


def _events(output: bytes) -> list[dict]:
    return [
        json.loads(line.removeprefix("data: "))
        for line in output.decode().splitlines()
        if line.startswith("data: ")
    ]


def _summary(events: list[dict]) -> list[tuple[object, ...]]:
    return [
        (
            event["type"],
            event.get("delta"),
            event.get("code"),
            event.get("response", {}).get("status"),
        )
        for event in events
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", [b"\n", b"\r", b"\r\n"])
async def test_sse_framing_is_stable_across_byte_splits_and_line_endings(ending: bytes) -> None:
    first_event = (
        ending.join(
            [
                b": heartbeat",
                b"id: fixture",
                b"retry: 3000",
                b"event: message",
                b'data: {"choices":[',
                b'data: {"delta":{"content":"caf\xc3\xa9"}}]}',
            ]
        )
        + ending * 2
    )
    finish_event = b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}' + ending * 2
    done_event = b"data: [DONE]" + ending * 2
    raw = first_event + finish_event + done_event

    coalesced = _events(await _collect([raw]))
    bytewise = _events(await _collect([raw[index : index + 1] for index in range(len(raw))]))

    assert _summary(bytewise) == _summary(coalesced)
    deltas = [event["delta"] for event in bytewise if event["type"] == "response.output_text.delta"]
    assert deltas == ["café"]
    assert bytewise[-1]["type"] == "response.completed"
    assert [event["sequence_number"] for event in bytewise] == list(range(len(bytewise)))


@pytest.mark.asyncio
async def test_invalid_utf8_is_replaced_and_unterminated_done_finishes() -> None:
    raw = (
        b'data: {"choices":[{"delta":{"content":"before\xffafter"}}]}\r\n\r\n'
        b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\r\n\r\n'
        b"data: [DONE]"
    )

    events = _events(await _collect([raw[index : index + 1] for index in range(len(raw))]))

    deltas = [event["delta"] for event in events if event["type"] == "response.output_text.delta"]
    assert deltas == ["before\ufffdafter"]
    assert events[-1]["type"] == "response.completed"


@pytest.mark.asyncio
async def test_upstream_error_closes_source_iterator() -> None:
    closed = asyncio.Event()

    async def source():
        try:
            yield b'event: error\ndata: {"code":"rate_limit_exceeded","message":"try later"}\n\n'
            await asyncio.Event().wait()
        finally:
            closed.set()

    output = b"".join([part async for part in chat_stream_to_responses(source())])
    events = _events(output)

    assert any(event.get("code") == "rate_limit_exceeded" for event in events)
    assert events[-1]["type"] == "response.failed"
    assert closed.is_set()


@pytest.mark.asyncio
async def test_consumer_cancellation_closes_source_iterator() -> None:
    closed = asyncio.Event()

    async def source():
        try:
            yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
            await asyncio.Event().wait()
        finally:
            closed.set()

    converted = chat_stream_to_responses(source())
    assert json.loads((await anext(converted)).decode().removeprefix("data: "))["type"] == (
        "response.created"
    )
    await anext(converted)
    await converted.aclose()

    assert closed.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["quote\\slash", "quote\\slash\ud800"])
async def test_json_parser_preserves_large_tool_indices_and_surrogate_strings(value: str) -> None:
    payload = {
        "choices": [
            {
                "delta": {
                    "content": value,
                    "tool_calls": [
                        {
                            "index": 900719925474099312312312313,
                            "function": {"name": "inspect", "arguments": value},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ]
    }
    events = _events(
        await _collect([f"data: {json.dumps(payload)}\n\n".encode(), b"data: [DONE]\n\n"])
    )

    deltas = [event["delta"] for event in events if "delta" in event]
    assert deltas == [value, value]
    assert events[-1]["type"] == "response.completed"


@pytest.mark.asyncio
async def test_json_parser_falls_back_for_deep_ignored_fields() -> None:
    raw = (
        b'data: {"ignored":'
        + b"[" * 250
        + b"0"
        + b"]" * 250
        + b',"choices":[{"delta":{"content":"kept"},"finish_reason":"stop"}]}\n\n'
        + b"data: [DONE]\n\n"
    )
    events = _events(await _collect([raw]))

    assert next(event["delta"] for event in events if "delta" in event) == "kept"
    assert events[-1]["type"] == "response.completed"


@pytest.mark.asyncio
async def test_json_parser_retains_stdlib_usage_number_precision() -> None:
    usage_data = (
        '{"usage":{"prompt_tokens":1.23456789012345678901234567890,'
        '"completion_tokens":2},"choices":[{"delta":{},"finish_reason":"stop"}]}'
    )
    expected = json.loads(usage_data)["usage"]["prompt_tokens"]
    events = _events(await _collect([f"data: {usage_data}\n\ndata: [DONE]\n\n".encode()]))

    assert events[-1]["type"] == "response.completed"
    assert events[-1]["response"]["usage"]["input_tokens"] == expected


@pytest.mark.asyncio
async def test_json_parser_preserves_configured_integer_digit_limit() -> None:
    raw = (
        b'data: {"choices":[{"delta":{"tool_calls":[{"index":'
        + b"7" * 641
        + b',"function":{"name":"inspect","arguments":"{}"}}]}}]}\n\n'
    )
    previous_limit = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        with pytest.raises(ValueError, match=r"Exceeds the limit \(640 digits\)"):
            await _collect([raw])
    finally:
        sys.set_int_max_str_digits(previous_limit)
