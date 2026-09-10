from __future__ import annotations

import asyncio
import json

import pytest
from openai.types.chat import ChatCompletionMessageParam
from openai.types.responses import Response, ResponseOutputMessage, ResponseStreamEvent
from openai.types.responses.response_input_param import ResponseInputParam
from pydantic import TypeAdapter

from promptlatch.compat import (
    ResponsesInputError,
    chat_response_to_responses,
    chat_stream_to_responses,
    responses_to_chat_payload,
)

_STREAM_EVENT_ADAPTER = TypeAdapter(ResponseStreamEvent)
_CHAT_MESSAGE_ADAPTER = TypeAdapter(ChatCompletionMessageParam)
_RESPONSE_INPUT_ADAPTER = TypeAdapter(ResponseInputParam)


async def _collect(parts: list[bytes], request_payload: dict | None = None) -> str:
    async def chunks():
        for part in parts:
            yield part

    request = request_payload or {"model": "fixture-model"}
    return b"".join([chunk async for chunk in chat_stream_to_responses(chunks(), request)]).decode()


def _events(stream: str) -> list[dict]:
    events = [
        json.loads(line.removeprefix("data: "))
        for line in stream.splitlines()
        if line.startswith("data: ")
    ]
    for event in events:
        _STREAM_EVENT_ADAPTER.validate_python(event)
    return events


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

    delta = next(
        event for event in _events(output) if event["type"] == "response.output_text.delta"
    )
    assert delta["delta"] == "😀"
    assert delta["item_id"].startswith("msg_")
    assert delta["output_index"] == 0
    assert delta["content_index"] == 0
    event_types = [event["type"] for event in _events(output)]
    assert event_types == [
        "response.created",
        "response.output_item.added",
        "response.content_part.added",
        "response.output_text.delta",
        "response.output_text.done",
        "response.content_part.done",
        "response.output_item.done",
        "response.completed",
    ]


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
    assert events[-2]["code"] == "upstream_stream_truncated"
    assert events[-1]["response"]["error"]["code"] == "server_error"
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
    assert events[-2]["code"] == "upstream_stream_interrupted"
    assert events[-1]["response"]["error"]["code"] == "server_error"
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
        },
        {"model": "fixture-model"},
    )

    assert response["status"] == "incomplete"
    assert response["model"] == "fixture-model"
    assert isinstance(response["created_at"], float)
    assert response["incomplete_details"] == {"reason": "max_output_tokens"}
    assert response["output"][0]["status"] == "incomplete"
    assert response["output"][0]["content"][0]["annotations"] == []
    Response.model_validate(response)


def test_chat_response_maps_legacy_function_call() -> None:
    response = chat_response_to_responses(
        {
            "id": "chatcmpl_fixture",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "function_call": {
                            "name": "inspect_config",
                            "arguments": '{"path":"settings.yaml"}',
                        },
                    },
                    "finish_reason": "function_call",
                }
            ],
        }
    )

    item = response["output"][0]
    assert item["type"] == "function_call"
    assert item["call_id"].startswith("call_")
    assert item["name"] == "inspect_config"
    assert item["arguments"] == '{"path":"settings.yaml"}'
    Response.model_validate(response)


def test_chat_response_rejects_malformed_legacy_function_call() -> None:
    response = chat_response_to_responses(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "function_call": {"name": False, "arguments": {}},
                    },
                    "finish_reason": "function_call",
                }
            ]
        }
    )

    assert response["status"] == "failed"
    assert response["error"]["code"] == "server_error"
    Response.model_validate(response)


def test_chat_response_restores_namespaced_function_call() -> None:
    request = {
        "model": "fixture-model",
        "input": "inspect",
        "tools": [
            {
                "type": "namespace",
                "name": "files",
                "description": "File tools",
                "tools": [
                    {
                        "type": "function",
                        "name": "read",
                        "parameters": {"type": "object", "properties": {}},
                    }
                ],
            }
        ],
    }
    response = chat_response_to_responses(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_fixture",
                                "type": "function",
                                "function": {"name": "files__read", "arguments": "{}"},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        },
        request,
    )

    item = response["output"][0]
    assert item["name"] == "read"
    assert item["namespace"] == "files"
    Response.model_validate(response)


def test_chat_response_emits_refusal_content() -> None:
    response = chat_response_to_responses(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "refusal": "I cannot help with that.",
                    },
                    "finish_reason": "stop",
                }
            ]
        },
        {"model": "fixture-model"},
    )

    assert response["output"][0]["content"] == [
        {"type": "refusal", "refusal": "I cannot help with that."}
    ]
    parsed = Response.model_validate(response)
    assert isinstance(parsed.output[0], ResponseOutputMessage)
    assert parsed.output[0].content[0].type == "refusal"


@pytest.mark.asyncio
async def test_chat_stream_emits_responses_function_call_events() -> None:
    output = await _collect(
        [
            (
                "data: "
                + json.dumps(
                    {
                        "choices": [
                            {
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "call_fixture",
                                            "type": "function",
                                            "function": {
                                                "name": "inspect_config",
                                                "arguments": '{"path":',
                                            },
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                )
                + "\n\n"
            ).encode(),
            (
                "data: "
                + json.dumps(
                    {
                        "choices": [
                            {
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "function": {"arguments": '"settings.yaml"}'},
                                        }
                                    ]
                                },
                                "finish_reason": "tool_calls",
                            }
                        ]
                    }
                )
                + "\n\n"
            ).encode(),
            b"data: [DONE]\n\n",
        ]
    )

    events = _events(output)
    assert [event["sequence_number"] for event in events] == list(range(len(events)))
    added = next(event for event in events if event["type"] == "response.output_item.added")
    item_id = added["item"]["id"]
    assert added["output_index"] == 0
    assert added["item"] == {
        "type": "function_call",
        "id": item_id,
        "call_id": "call_fixture",
        "name": "inspect_config",
        "arguments": "",
        "status": "in_progress",
    }
    argument_events = [
        event for event in events if event["type"] == "response.function_call_arguments.delta"
    ]
    assert [event["delta"] for event in argument_events] == [
        '{"path":',
        '"settings.yaml"}',
    ]
    assert all(event["item_id"] == item_id for event in argument_events)
    arguments_done = next(
        event for event in events if event["type"] == "response.function_call_arguments.done"
    )
    assert arguments_done["arguments"] == '{"path":"settings.yaml"}'
    assert arguments_done["item_id"] == item_id
    assert arguments_done["name"] == "inspect_config"
    item_done = next(event for event in events if event["type"] == "response.output_item.done")
    assert item_done["item"]["arguments"] == '{"path":"settings.yaml"}'
    assert events[-1]["response"]["output"] == [item_done["item"]]


@pytest.mark.asyncio
async def test_chat_stream_accepts_null_tool_call_continuations() -> None:
    output = await _collect(
        [
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_fixture",'
            b'"function":{"name":"inspect_config","arguments":"{\\"path\\":"}}]}}]}\n\n'
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,'
            b'"function":{"name":null,"arguments":null}}]}}]}\n\n'
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,'
            b'"function":{"arguments":"\\"settings.yaml\\"}"}}]},'
            b'"finish_reason":"tool_calls"}]}\n\n'
            b"data: [DONE]\n\n",
        ]
    )

    events = _events(output)
    assert events[-1]["type"] == "response.completed"
    assert events[-1]["response"]["output"][0]["arguments"] == '{"path":"settings.yaml"}'


@pytest.mark.asyncio
async def test_chat_stream_restores_namespaced_function_call() -> None:
    request = {
        "model": "fixture-model",
        "input": "inspect",
        "tools": [
            {
                "type": "namespace",
                "name": "files",
                "description": "File tools",
                "tools": [
                    {
                        "type": "function",
                        "name": "read",
                        "parameters": {"type": "object", "properties": {}},
                    }
                ],
            }
        ],
    }
    output = await _collect(
        [
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_fixture",'
            b'"function":{"name":"files__read","arguments":"{}"}}]},'
            b'"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n\n'
        ],
        request,
    )

    events = _events(output)
    added = next(event for event in events if event["type"] == "response.output_item.added")
    completed_item = events[-1]["response"]["output"][0]
    assert added["item"]["name"] == "read"
    assert added["item"]["namespace"] == "files"
    assert completed_item["name"] == "read"
    assert completed_item["namespace"] == "files"


@pytest.mark.asyncio
async def test_chat_stream_emits_refusal_events_and_content() -> None:
    output = await _collect(
        [
            b'data: {"choices":[{"delta":{"refusal":"I cannot "}}]}\n\n'
            b'data: {"choices":[{"delta":{"refusal":"help with that."},'
            b'"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
        ]
    )

    events = _events(output)
    assert [event["type"] for event in events] == [
        "response.created",
        "response.output_item.added",
        "response.content_part.added",
        "response.refusal.delta",
        "response.refusal.delta",
        "response.refusal.done",
        "response.content_part.done",
        "response.output_item.done",
        "response.completed",
    ]
    assert [event["delta"] for event in events if event["type"] == "response.refusal.delta"] == [
        "I cannot ",
        "help with that.",
    ]
    assert events[-1]["response"]["output"][0]["content"] == [
        {"type": "refusal", "refusal": "I cannot help with that."}
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "function",
    [
        {"name": False},
        {"name": 0},
        {"arguments": False},
        {"arguments": []},
    ],
)
async def test_chat_stream_rejects_non_text_tool_call_deltas(function: object) -> None:
    payload = {
        "choices": [
            {"delta": {"tool_calls": [{"index": 0, "id": "call_fixture", "function": function}]}}
        ]
    }

    events = _events(await _collect([(f"data: {json.dumps(payload)}\n\n").encode()]))

    assert events[-1]["type"] == "response.failed"
    assert events[-2]["code"] == "upstream_stream_invalid"


@pytest.mark.asyncio
async def test_chat_stream_maps_legacy_function_call() -> None:
    output = await _collect(
        [
            b'data: {"choices":[{"delta":{"function_call":{"name":"inspect_config",'
            b'"arguments":"{\\"path\\":"}}}]}\n\n'
            b'data: {"choices":[{"delta":{"function_call":{"arguments":"\\"settings.yaml\\"}"}},'
            b'"finish_reason":"function_call"}]}\n\n'
            b"data: [DONE]\n\n"
        ]
    )

    events = _events(output)
    completed = events[-1]["response"]
    assert completed["output"][0]["name"] == "inspect_config"
    assert completed["output"][0]["arguments"] == '{"path":"settings.yaml"}'


@pytest.mark.asyncio
async def test_chat_stream_preserves_tool_first_output_order() -> None:
    output = await _collect(
        [
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_fixture",'
            b'"function":{"name":"inspect_config","arguments":"{}"}}]}}]}\n\n'
            b'data: {"choices":[{"delta":{"content":"done"},"finish_reason":"tool_calls"}]}\n\n'
            b"data: [DONE]\n\n"
        ]
    )

    completed = _events(output)[-1]["response"]
    assert [item["type"] for item in completed["output"]] == ["function_call", "message"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"choices": {}},
        {"choices": [False]},
        {"choices": [{"delta": []}]},
        {"choices": [{"delta": {"tool_calls": {}}}]},
    ],
)
async def test_chat_stream_fails_closed_on_malformed_nested_payload(payload: dict) -> None:
    output = await _collect([(f"data: {json.dumps(payload)}\n\n").encode()])

    events = _events(output)
    assert events[-1]["type"] == "response.failed"
    assert events[-2]["code"] == "upstream_stream_invalid"
    assert events[-1]["response"]["error"]["code"] == "server_error"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_call", [False, None, 0, "invalid", [], {}])
async def test_chat_stream_fails_closed_on_malformed_tool_call_entry(tool_call: object) -> None:
    payload = {"choices": [{"delta": {"tool_calls": [tool_call]}}]}

    events = _events(await _collect([(f"data: {json.dumps(payload)}\n\n").encode()]))

    assert events[-1]["type"] == "response.failed"
    assert events[-2]["code"] == "upstream_stream_invalid"


@pytest.mark.asyncio
async def test_chat_stream_ignores_events_after_done() -> None:
    output = await _collect(
        [
            b'data: {"choices":[{"delta":{"content":"done"},"finish_reason":"stop"}]}\n\n'
            b"data: [DONE]\n\n"
            b'data: {"choices":[{"delta":{"content":"late"}}]}\n\n'
        ]
    )

    events = _events(output)
    assert events[-1]["type"] == "response.completed"
    assert "late" not in output


@pytest.mark.asyncio
async def test_chat_stream_closes_upstream_iterator_after_done() -> None:
    closed = False

    async def chunks():
        nonlocal closed
        try:
            yield (
                b'data: {"choices":[{"delta":{"content":"done"},'
                b'"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
            )
            await asyncio.Event().wait()
        finally:
            closed = True

    async def collect() -> bytes:
        return b"".join([part async for part in chat_stream_to_responses(chunks())])

    output = await asyncio.wait_for(collect(), timeout=0.2)

    assert output
    assert closed


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


def test_responses_groups_parallel_function_call_history_with_assistant_text() -> None:
    response_input = [
        {
            "type": "message",
            "id": "msg_fixture",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "Inspecting both.", "annotations": []}],
        },
        {
            "type": "function_call",
            "call_id": "call_first",
            "name": "inspect_config",
            "arguments": '{"path":"first.yaml"}',
        },
        {
            "type": "function_call",
            "call_id": "call_second",
            "name": "inspect_config",
            "arguments": '{"path":"second.yaml"}',
        },
        {"type": "function_call_output", "call_id": "call_first", "output": "first"},
        {"type": "function_call_output", "call_id": "call_second", "output": "second"},
    ]
    _RESPONSE_INPUT_ADAPTER.validate_python(response_input)

    chat = responses_to_chat_payload({"model": "fixture-model", "input": response_input})

    assert chat["messages"] == [
        {
            "role": "assistant",
            "content": "Inspecting both.",
            "tool_calls": [
                {
                    "id": "call_first",
                    "type": "function",
                    "function": {
                        "name": "inspect_config",
                        "arguments": '{"path":"first.yaml"}',
                    },
                },
                {
                    "id": "call_second",
                    "type": "function",
                    "function": {
                        "name": "inspect_config",
                        "arguments": '{"path":"second.yaml"}',
                    },
                },
            ],
        },
        {"role": "tool", "tool_call_id": "call_first", "content": "first"},
        {"role": "tool", "tool_call_id": "call_second", "content": "second"},
    ]


def test_responses_groups_tool_first_calls_with_assistant_text_and_refusal() -> None:
    response_input = [
        {
            "type": "function_call",
            "call_id": "call_first",
            "name": "inspect_config",
            "arguments": '{"path":"first.yaml"}',
        },
        {
            "type": "function_call",
            "call_id": "call_second",
            "name": "inspect_config",
            "arguments": '{"path":"second.yaml"}',
        },
        {
            "type": "message",
            "id": "msg_fixture",
            "status": "completed",
            "role": "assistant",
            "content": [
                {"type": "output_text", "text": "Inspecting both.", "annotations": []},
                {"type": "refusal", "refusal": "One path is unavailable."},
            ],
        },
        {"type": "function_call_output", "call_id": "call_first", "output": "first"},
        {"type": "function_call_output", "call_id": "call_second", "output": "second"},
    ]
    _RESPONSE_INPUT_ADAPTER.validate_python(response_input)

    chat = responses_to_chat_payload({"model": "fixture-model", "input": response_input})

    assert chat["messages"][0] == {
        "role": "assistant",
        "content": "Inspecting both.",
        "refusal": "One path is unavailable.",
        "tool_calls": [
            {
                "id": "call_first",
                "type": "function",
                "function": {
                    "name": "inspect_config",
                    "arguments": '{"path":"first.yaml"}',
                },
            },
            {
                "id": "call_second",
                "type": "function",
                "function": {
                    "name": "inspect_config",
                    "arguments": '{"path":"second.yaml"}',
                },
            },
        ],
    }
    assert [message["role"] for message in chat["messages"]] == ["assistant", "tool", "tool"]
    _CHAT_MESSAGE_ADAPTER.validate_python(chat["messages"][0])


def test_responses_roundtrips_refusal_output_item_to_chat_history() -> None:
    response_input = [
        {
            "type": "message",
            "id": "msg_fixture",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "refusal", "refusal": "I cannot help with that."}],
        }
    ]
    _RESPONSE_INPUT_ADAPTER.validate_python(response_input)

    chat = responses_to_chat_payload({"model": "fixture-model", "input": response_input})

    assert chat["messages"] == [
        {"role": "assistant", "content": None, "refusal": "I cannot help with that."}
    ]
    _CHAT_MESSAGE_ADAPTER.validate_python(chat["messages"][0])


def test_responses_named_tool_choice_uses_chat_function_shape() -> None:
    chat = responses_to_chat_payload(
        {
            "model": "fixture-model",
            "input": "inspect",
            "tool_choice": {"type": "function", "name": "inspect_config"},
        }
    )

    assert chat["tool_choice"] == {
        "type": "function",
        "function": {"name": "inspect_config"},
    }


def test_responses_namespace_tool_and_choice_use_flattened_chat_name() -> None:
    chat = responses_to_chat_payload(
        {
            "model": "fixture-model",
            "input": "inspect",
            "tools": [
                {
                    "type": "namespace",
                    "name": "files",
                    "tools": [
                        {
                            "type": "function",
                            "name": "read",
                            "parameters": {"type": "object", "properties": {}},
                        }
                    ],
                }
            ],
            "tool_choice": {"type": "function", "name": "read", "namespace": "files"},
        }
    )

    assert chat["tools"][0]["function"]["name"] == "files__read"
    assert chat["tool_choice"]["function"]["name"] == "files__read"


def test_responses_rejects_colliding_flattened_tool_names() -> None:
    with pytest.raises(ResponsesInputError, match="collision"):
        responses_to_chat_payload(
            {
                "model": "fixture-model",
                "input": "inspect",
                "tools": [
                    {
                        "type": "function",
                        "name": "files__read",
                        "parameters": {"type": "object", "properties": {}},
                    },
                    {
                        "type": "namespace",
                        "name": "files",
                        "tools": [
                            {
                                "type": "function",
                                "name": "read",
                                "parameters": {"type": "object", "properties": {}},
                            }
                        ],
                    },
                ],
            }
        )


@pytest.mark.parametrize(
    "tool_choice",
    [None, False, "unsupported", {}, {"type": "function"}, {"type": "custom", "name": "x"}],
)
def test_responses_input_rejects_unsupported_tool_choice(tool_choice: object) -> None:
    with pytest.raises(ResponsesInputError):
        responses_to_chat_payload(
            {"model": "fixture-model", "input": "inspect", "tool_choice": tool_choice}
        )


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
