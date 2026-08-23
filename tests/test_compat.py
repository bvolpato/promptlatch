from __future__ import annotations

import json

import pytest

from promptlatch.compat import (
    ResponsesInputError,
    chat_response_to_responses,
    chat_stream_to_responses,
    responses_to_chat_payload,
)


async def _collect(parts: list[bytes]) -> str:
    async def chunks():
        for part in parts:
            yield part

    return b"".join([chunk async for chunk in chat_stream_to_responses(chunks())]).decode()


def _events(stream: str) -> list[dict]:
    return [
        json.loads(line.removeprefix("data: "))
        for line in stream.splitlines()
        if line.startswith("data: ")
    ]


@pytest.mark.asyncio
async def test_chat_stream_preserves_utf8_split_across_chunks() -> None:
    raw = (
        "data: "
        + json.dumps(
            {"choices": [{"delta": {"content": "😀"}}]},
            ensure_ascii=False,
        )
        + '\n\ndata: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
        + "data: [DONE]\n\n"
    ).encode()
    split = raw.index("😀".encode()) + 2

    output = await _collect([raw[:split], raw[split:]])

    deltas = [event["delta"] for event in _events(output) if event["type"].endswith(".delta")]
    assert deltas == ["😀"]


@pytest.mark.asyncio
async def test_chat_stream_accepts_crlf_events_split_between_chunks() -> None:
    raw = (
        b'data: {"choices":[{"delta":{"content":"hello"}}]}\r\n\r\n'
        b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\r\n\r\n'
        b"data: [DONE]\r\n\r\n"
    )
    split = raw.index(b"\r\n") + 1

    output = await _collect([raw[:split], raw[split:]])

    deltas = [event["delta"] for event in _events(output) if event["type"].endswith(".delta")]
    assert deltas == ["hello"]
    assert any(event["type"] == "response.completed" for event in _events(output))


@pytest.mark.asyncio
async def test_chat_stream_marks_token_limit_as_incomplete() -> None:
    output = await _collect(
        [
            b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
            b'data: {"choices":[{"delta":{},"finish_reason":"length"}]}\n\n'
            b"data: [DONE]\n\n"
        ]
    )

    events = _events(output)
    terminal = events[-1]
    assert terminal["type"] == "response.incomplete"
    assert terminal["response"]["status"] == "incomplete"
    assert terminal["response"]["incomplete_details"] == {"reason": "max_output_tokens"}
    assert not any(event["type"] == "response.completed" for event in events)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_event",
    [
        b'data: {"error":{"code":"rate_limit_exceeded","message":"try later"}}\n\n',
        b'event: error\ndata: {"code":"rate_limit_exceeded","message":"try later"}\n\n',
    ],
)
async def test_chat_stream_marks_upstream_error_as_failed(raw_event: bytes) -> None:
    output = await _collect([raw_event])

    events = _events(output)
    assert any(
        event["type"] == "error"
        and event["code"] == "rate_limit_exceeded"
        and event["message"] == "try later"
        for event in events
    )
    assert events[-1]["type"] == "response.failed"
    assert not any(event["type"] == "response.completed" for event in events)


@pytest.mark.asyncio
async def test_chat_stream_marks_missing_done_event_as_failed() -> None:
    output = await _collect(
        [
            b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
            b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
        ]
    )

    events = _events(output)
    assert events[-1]["type"] == "response.failed"
    assert events[-1]["response"]["error"]["code"] == "upstream_stream_truncated"
    assert not any(event["type"] == "response.completed" for event in events)


@pytest.mark.asyncio
async def test_chat_stream_marks_interrupted_iterator_as_failed() -> None:
    async def interrupted_chunks():
        yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
        raise ConnectionError("fixture disconnect")

    output = b"".join(
        [chunk async for chunk in chat_stream_to_responses(interrupted_chunks())]
    ).decode()

    events = _events(output)
    assert events[-1]["type"] == "response.failed"
    assert events[-1]["response"]["error"]["code"] == "upstream_stream_interrupted"
    assert not any(event["type"] == "response.completed" for event in events)


def test_chat_response_marks_token_limit_as_incomplete() -> None:
    response = chat_response_to_responses(
        {
            "id": "chatcmpl_fixture",
            "choices": [
                {
                    "message": {"role": "assistant", "content": "partial"},
                    "finish_reason": "length",
                }
            ],
        }
    )

    assert response["status"] == "incomplete"
    assert response["incomplete_details"] == {"reason": "max_output_tokens"}
    assert response["end_turn"] is False


def test_responses_vision_input_uses_chat_image_url_shape() -> None:
    chat = responses_to_chat_payload(
        {
            "model": "fixture-model",
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "inspect"},
                        {
                            "type": "input_image",
                            "image_url": "https://example.test/image.png",
                            "detail": "high",
                        },
                    ],
                }
            ],
        }
    )

    assert chat["messages"][0]["content"][1] == {
        "type": "image_url",
        "image_url": {"url": "https://example.test/image.png", "detail": "high"},
    }


@pytest.mark.parametrize(
    "input_item",
    [
        "not-a-mapping",
        {"type": "unknown_fixture", "content": "must not disappear"},
        {"type": "message", "role": "user"},
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_file", "file_id": "file_fixture"}],
        },
    ],
)
def test_responses_input_rejects_unknown_or_malformed_items(input_item: object) -> None:
    with pytest.raises(ResponsesInputError):
        responses_to_chat_payload({"model": "fixture-model", "input": [input_item]})


def test_responses_function_tool_uses_exact_chat_function_shape() -> None:
    chat = responses_to_chat_payload(
        {
            "model": "fixture-model",
            "input": "inspect",
            "tools": [
                {
                    "type": "function",
                    "name": "inspect_config",
                    "description": "Inspect configuration",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                    "strict": True,
                }
            ],
        }
    )

    assert chat["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "inspect_config",
                "description": "Inspect configuration",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
                "strict": True,
            },
        }
    ]


@pytest.mark.parametrize(
    "tools",
    [
        None,
        {},
        ["not-a-tool"],
        [{"type": "web_search"}],
        [
            {
                "type": "function",
                "function": {"name": "chat-shaped", "parameters": {"type": "object"}},
            }
        ],
        [{"type": "function", "name": "missing_parameters"}],
        [{"type": "function", "name": "invalid_parameters", "parameters": []}],
    ],
)
def test_responses_input_rejects_malformed_or_unsupported_tools(tools: object) -> None:
    with pytest.raises(ResponsesInputError):
        responses_to_chat_payload({"model": "fixture-model", "input": "inspect", "tools": tools})


def test_responses_text_tool_output_list_maps_to_chat_text() -> None:
    chat = responses_to_chat_payload(
        {
            "model": "fixture-model",
            "input": [
                {
                    "type": "function_call_output",
                    "call_id": "call_fixture",
                    "output": [
                        {"type": "input_text", "text": "first"},
                        {"type": "input_text", "text": "second"},
                    ],
                }
            ],
        }
    )

    assert chat["messages"] == [
        {"role": "tool", "tool_call_id": "call_fixture", "content": "first\nsecond"}
    ]


@pytest.mark.parametrize(
    "output",
    [
        [],
        0,
        {"type": "input_text", "text": "not-a-list"},
        [{"type": "input_image", "image_url": "https://example.test/image.png"}],
        [
            {"type": "input_text", "text": "partial"},
            {"type": "input_file", "file_id": "file_fixture"},
        ],
        [{"type": "input_text", "text": 0}],
    ],
)
def test_responses_input_rejects_unrepresentable_tool_output(output: object) -> None:
    with pytest.raises(ResponsesInputError):
        responses_to_chat_payload(
            {
                "model": "fixture-model",
                "input": [
                    {
                        "type": "function_call_output",
                        "call_id": "call_fixture",
                        "output": output,
                    }
                ],
            }
        )


@pytest.mark.parametrize("instructions", [False, 0, [], {}])
def test_responses_input_rejects_non_text_falsy_instructions(instructions: object) -> None:
    with pytest.raises(ResponsesInputError):
        responses_to_chat_payload(
            {"model": "fixture-model", "instructions": instructions, "input": "hello"}
        )


@pytest.mark.parametrize("role", [None, False, 0, "", "tool"])
def test_responses_input_rejects_missing_falsy_or_unsupported_role(role: object) -> None:
    with pytest.raises(ResponsesInputError):
        responses_to_chat_payload(
            {
                "model": "fixture-model",
                "input": [{"type": "message", "role": role, "content": "hello"}],
            }
        )
