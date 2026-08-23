from __future__ import annotations

import codecs
import json
from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4


class ResponsesInputError(ValueError):
    """Raised when Responses input cannot be represented as chat messages."""


def responses_to_chat_payload(payload: dict[str, Any]) -> dict[str, Any]:
    chat: dict[str, Any] = {
        "model": payload.get("model"),
        "messages": _responses_messages_to_chat(payload),
        "stream": bool(payload.get("stream", False)),
    }
    if "tools" in payload:
        tools = payload["tools"]
        if not isinstance(tools, list):
            raise ResponsesInputError("Responses tools must be a list")
        if tools:
            chat["tools"] = _responses_tools_to_chat(tools)
    if payload.get("tool_choice") in {"auto", "none", "required"}:
        chat["tool_choice"] = payload["tool_choice"]
    if "parallel_tool_calls" in payload:
        chat["parallel_tool_calls"] = payload["parallel_tool_calls"]
    for source, target in {
        "temperature": "temperature",
        "top_p": "top_p",
        "max_output_tokens": "max_tokens",
    }.items():
        if source in payload:
            chat[target] = payload[source]
    response_format = _response_format(payload.get("text"))
    if response_format:
        chat["response_format"] = response_format
    if chat["stream"]:
        chat["stream_options"] = {"include_usage": True}
    return {key: value for key, value in chat.items() if value is not None}


def chat_response_to_responses(payload: dict[str, Any]) -> dict[str, Any]:
    response_id = _response_id(payload)
    output = _chat_message_to_response_items(_chat_message(payload), response_id)
    finish_reason = _chat_finish_reason(payload)
    response: dict[str, Any] = {
        "id": response_id,
        "object": "response",
        "output": output,
        "usage": _responses_usage(payload.get("usage")),
    }
    if finish_reason in {"stop", "tool_calls", "function_call"}:
        response.update(status="completed", end_turn=True)
    elif finish_reason in {"length", "content_filter"}:
        reason = "max_output_tokens" if finish_reason == "length" else "content_filter"
        response.update(
            status="incomplete",
            incomplete_details={"reason": reason},
            end_turn=False,
        )
    else:
        response.update(
            status="failed",
            error={
                "code": "upstream_response_invalid",
                "message": "Upstream Chat Completions response has no valid finish reason.",
            },
            end_turn=False,
        )
    return response


async def chat_stream_to_responses(chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    state = _ChatStreamState()
    yield _sse(
        {
            "type": "response.created",
            "response": {"id": state.response_id, "status": "in_progress"},
        }
    )
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    buffer = ""
    event_lines: list[str] = []
    iterator = aiter(chunks)
    while True:
        try:
            chunk = await anext(iterator)
        except StopAsyncIteration:
            break
        except Exception:
            for event in state.failure_events(
                "upstream_stream_interrupted", "Upstream stream failed before completion."
            ):
                yield event
            return
        buffer += decoder.decode(chunk)
        while (line := _pop_sse_line(buffer)) is not None:
            value, buffer = line
            if value:
                event_lines.append(value)
                continue
            async for event in _chat_sse_event_to_responses("\n".join(event_lines), state):
                yield event
            event_lines.clear()
    buffer += decoder.decode(b"", final=True)
    while (line := _pop_sse_line(buffer, final=True)) is not None:
        value, buffer = line
        if value:
            event_lines.append(value)
        elif event_lines:
            async for event in _chat_sse_event_to_responses("\n".join(event_lines), state):
                yield event
            event_lines.clear()
    if buffer:
        event_lines.append(buffer)
    if event_lines:
        async for event in _chat_sse_event_to_responses("\n".join(event_lines), state):
            yield event
    for event in state.failure_events(
        "upstream_stream_truncated", "Upstream stream ended before the [DONE] event."
    ):
        yield event


def _pop_sse_line(buffer: str, *, final: bool = False) -> tuple[str, str] | None:
    for index, character in enumerate(buffer):
        if character == "\n":
            return buffer[:index], buffer[index + 1 :]
        if character != "\r":
            continue
        if index + 1 == len(buffer) and not final:
            return None
        end = index + 2 if buffer[index + 1 : index + 2] == "\n" else index + 1
        return buffer[:index], buffer[end:]
    return None


class _ChatStreamState:
    def __init__(self) -> None:
        self.response_id = f"resp_{uuid4().hex}"
        self.message_id = f"msg_{uuid4().hex}"
        self.text = ""
        self.message_started = False
        self.tool_calls: dict[int, dict[str, Any]] = {}
        self.usage: dict[str, Any] | None = None
        self.finish_reason: str | None = None
        self.finished = False

    def text_delta_events(self, delta: str) -> list[bytes]:
        events = []
        if not self.message_started:
            self.message_started = True
            events.append(
                _sse(
                    {
                        "type": "response.output_item.added",
                        "item": self.message_item(""),
                    }
                )
            )
        self.text += delta
        events.append(_sse({"type": "response.output_text.delta", "delta": delta}))
        return events

    def merge_tool_call_delta(self, delta: dict[str, Any]) -> None:
        index = int(delta.get("index", len(self.tool_calls)))
        tool_call = self.tool_calls.setdefault(
            index,
            {"id": delta.get("id") or f"call_{uuid4().hex}", "name": "", "arguments": ""},
        )
        if delta.get("id"):
            tool_call["id"] = delta["id"]
        function = delta.get("function") or {}
        if function.get("name"):
            tool_call["name"] += function["name"]
        if function.get("arguments"):
            tool_call["arguments"] += function["arguments"]

    def message_item(self, text: str) -> dict[str, Any]:
        return {
            "type": "message",
            "role": "assistant",
            "id": self.message_id,
            "content": [{"type": "output_text", "text": text}],
        }

    def tool_item(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "function_call",
            "call_id": tool_call["id"],
            "name": tool_call["name"],
            "arguments": tool_call["arguments"],
        }

    def finish_events(self) -> list[bytes]:
        if self.finished:
            return []
        if self.finish_reason not in {
            "stop",
            "tool_calls",
            "function_call",
            "length",
            "content_filter",
        }:
            return self.failure_events(
                "upstream_stream_invalid",
                "Upstream stream ended without a valid finish reason.",
            )
        self.finished = True
        events, output = self._output_events()
        incomplete = self.finish_reason in {"length", "content_filter"}
        status = "incomplete" if incomplete else "completed"
        response: dict[str, Any] = {
            "id": self.response_id,
            "status": status,
            "output": output,
            "usage": _responses_usage(self.usage),
            "end_turn": not incomplete,
        }
        if incomplete:
            reason = "max_output_tokens" if self.finish_reason == "length" else "content_filter"
            response["incomplete_details"] = {"reason": reason}
        events.append(_sse({"type": f"response.{status}", "response": response}))
        return events

    def failure_events(self, code: str, message: str) -> list[bytes]:
        if self.finished:
            return []
        self.finished = True
        events, output = self._output_events()
        error = {"code": code, "message": message}
        events.append(_sse({"type": "error", **error, "param": None}))
        events.append(
            _sse(
                {
                    "type": "response.failed",
                    "response": {
                        "id": self.response_id,
                        "status": "failed",
                        "output": output,
                        "usage": _responses_usage(self.usage),
                        "error": error,
                        "end_turn": False,
                    },
                }
            )
        )
        return events

    def _output_events(self) -> tuple[list[bytes], list[dict[str, Any]]]:
        events: list[bytes] = []
        output: list[dict[str, Any]] = []
        if self.message_started:
            item = self.message_item(self.text)
            output.append(item)
            events.append(_sse({"type": "response.output_item.done", "item": item}))
        for tool_call in self.tool_calls.values():
            item = self.tool_item(tool_call)
            output.append(item)
            events.append(_sse({"type": "response.output_item.done", "item": item}))
        return events, output


async def _chat_sse_event_to_responses(raw: str, state: _ChatStreamState) -> AsyncIterator[bytes]:
    event_name = next(
        (
            line.removeprefix("event:").lstrip()
            for line in raw.splitlines()
            if line.startswith("event:")
        ),
        None,
    )
    data = "\n".join(
        line.removeprefix("data:").lstrip() for line in raw.splitlines() if line.startswith("data:")
    )
    if not data:
        return
    if data == "[DONE]":
        for event in state.finish_events():
            yield event
        return
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        for event in state.failure_events(
            "upstream_stream_invalid", "Upstream stream contained invalid JSON."
        ):
            yield event
        return
    if not isinstance(payload, dict):
        for event in state.failure_events(
            "upstream_stream_invalid", "Upstream stream event must contain a JSON object."
        ):
            yield event
        return
    upstream_error = payload.get("error")
    if event_name == "error" or isinstance(upstream_error, dict):
        error = upstream_error if isinstance(upstream_error, dict) else payload
        raw_code = error.get("code")
        raw_message = error.get("message")
        code = raw_code if isinstance(raw_code, str) else "upstream_error"
        message = raw_message if isinstance(raw_message, str) else "Upstream error."
        for event in state.failure_events(code, message):
            yield event
        return
    if payload.get("usage"):
        state.usage = payload["usage"]
    for choice in payload.get("choices") or []:
        finish_reason = choice.get("finish_reason")
        if finish_reason is not None:
            state.finish_reason = finish_reason if isinstance(finish_reason, str) else ""
        delta = choice.get("delta") or {}
        if delta.get("content"):
            for event in state.text_delta_events(delta["content"]):
                yield event
        for tool_delta in delta.get("tool_calls") or []:
            state.merge_tool_call_delta(tool_delta)


def _responses_messages_to_chat(payload: dict[str, Any]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    instructions = payload.get("instructions")
    if instructions is not None and not isinstance(instructions, str):
        raise ResponsesInputError("Responses instructions must be text")
    if instructions:
        messages.append({"role": "system", "content": instructions})
    input_value = payload.get("input")
    if isinstance(input_value, str):
        messages.append({"role": "user", "content": input_value})
    elif isinstance(input_value, list):
        if not input_value:
            raise ResponsesInputError("Responses input list cannot be empty")
        for item in input_value:
            messages.extend(_response_item_to_chat_messages(item))
    else:
        raise ResponsesInputError("Responses input must be text or a list")
    return messages


def _response_item_to_chat_messages(item: Any) -> list[dict[str, Any]]:
    if not isinstance(item, dict):
        raise ResponsesInputError("Responses input item must be an object")
    kind = item.get("type", "message")
    if not isinstance(kind, str):
        raise ResponsesInputError("Responses input item type must be text")
    if kind == "message":
        role = item.get("role")
        if not isinstance(role, str) or not role:
            raise ResponsesInputError("Responses message role is required")
        if role not in {"user", "assistant", "system", "developer"}:
            raise ResponsesInputError("unsupported Responses message role")
        if "content" not in item:
            raise ResponsesInputError("Responses message content is required")
        return [{"role": role, "content": _content_to_chat(item["content"])}]
    if kind in {"function_call", "custom_tool_call"}:
        call_id = item.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            raise ResponsesInputError("Responses tool call requires call_id")
        name = _tool_name(item)
        arguments = item.get("arguments") if kind == "function_call" else item.get("input")
        if not isinstance(arguments, str):
            raise ResponsesInputError("Responses tool call arguments must be text")
        return [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {"name": name, "arguments": arguments},
                    }
                ],
            }
        ]
    if kind in {"function_call_output", "custom_tool_call_output"}:
        call_id = item.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            raise ResponsesInputError("Responses tool output requires call_id")
        if "output" not in item or item["output"] is None:
            raise ResponsesInputError("Responses tool output is required")
        return [
            {
                "role": "tool",
                "tool_call_id": call_id,
                "content": _output_to_text(item["output"]),
            }
        ]
    raise ResponsesInputError("unsupported Responses input item type")


def _content_to_chat(content: Any) -> str | list[dict[str, Any]]:
    if isinstance(content, str):
        return content
    if not isinstance(content, list) or not content:
        raise ResponsesInputError("Responses message content must be text or a non-empty list")
    parts: list[dict[str, Any]] = []
    texts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            raise ResponsesInputError("Responses content item must be an object")
        kind = item.get("type")
        text = item.get("text")
        if kind in {"input_text", "output_text", "text"}:
            if not isinstance(text, str):
                raise ResponsesInputError("Responses text content requires text")
            texts.append(text)
            parts.append({"type": "text", "text": text})
            continue
        if kind not in {"input_image", "image_url"}:
            raise ResponsesInputError("unsupported Responses content item type")
        image_url = item.get("image_url") or item.get("url")
        if isinstance(image_url, str) and image_url:
            image: dict[str, Any] = {"url": image_url}
        elif (
            isinstance(image_url, dict)
            and isinstance(image_url.get("url"), str)
            and image_url["url"]
        ):
            image = dict(image_url)
        else:
            raise ResponsesInputError("Responses image content requires image_url")
        detail = item.get("detail")
        if detail is not None and not isinstance(detail, str):
            raise ResponsesInputError("Responses image detail must be text")
        if detail and "detail" not in image:
            image["detail"] = detail
        parts.append({"type": "image_url", "image_url": image})
    if len(parts) == len(texts):
        return "\n".join(texts)
    return parts or "\n".join(texts)


def _output_to_text(output: Any) -> str:
    if isinstance(output, str):
        return output
    if not isinstance(output, list) or not output:
        raise ResponsesInputError("Responses tool output must be text or a non-empty text list")
    texts: list[str] = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "input_text":
            raise ResponsesInputError("unsupported Responses tool output content type")
        text = item.get("text")
        if not isinstance(text, str):
            raise ResponsesInputError("Responses tool output text must be text")
        texts.append(text)
    return "\n".join(texts)


def _responses_tools_to_chat(tools: list[Any]) -> list[dict[str, Any]]:
    chat_tools: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            raise ResponsesInputError("Responses tool must be an object")
        kind = tool.get("type")
        if kind == "function":
            chat_tools.append(_function_tool_to_chat(tool))
        elif kind == "namespace":
            namespace = tool.get("name")
            if not isinstance(namespace, str) or not namespace:
                raise ResponsesInputError("Responses tool namespace requires name")
            nested_tools = tool.get("tools")
            if not isinstance(nested_tools, list) or not nested_tools:
                raise ResponsesInputError("Responses tool namespace requires tools")
            for nested in nested_tools:
                if not isinstance(nested, dict) or nested.get("type") != "function":
                    raise ResponsesInputError("Responses namespace supports only function tools")
                chat_tools.append(_function_tool_to_chat(nested, namespace))
        else:
            raise ResponsesInputError("unsupported Responses tool type")
    return chat_tools


def _function_tool_to_chat(tool: dict[str, Any], namespace: str | None = None) -> dict[str, Any]:
    name = tool.get("name")
    if not isinstance(name, str) or not name:
        raise ResponsesInputError("Responses function tool requires name")
    description = tool.get("description")
    if description is not None and not isinstance(description, str):
        raise ResponsesInputError("Responses function tool description must be text")
    parameters = tool.get("parameters")
    if not isinstance(parameters, dict):
        raise ResponsesInputError("Responses function tool parameters must be an object")
    strict = tool.get("strict")
    if strict is not None and not isinstance(strict, bool):
        raise ResponsesInputError("Responses function tool strict must be boolean")
    function = {
        "name": f"{namespace}__{name}" if namespace else name,
        "description": description or "",
        "parameters": parameters,
    }
    if "strict" in tool:
        function["strict"] = tool["strict"]
    return {"type": "function", "function": function}


def _response_format(text_config: Any) -> dict[str, Any] | None:
    if not isinstance(text_config, dict):
        return None
    fmt = text_config.get("format")
    if not isinstance(fmt, dict):
        return None
    if fmt.get("type") != "json_schema":
        return None
    return {
        "type": "json_schema",
        "json_schema": {
            "name": fmt.get("name") or "response",
            "schema": fmt.get("schema") or {},
            "strict": bool(fmt.get("strict", False)),
        },
    }


def _chat_message(payload: dict[str, Any]) -> dict[str, Any]:
    choices = payload.get("choices") or []
    if choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            return message
    return {}


def _chat_finish_reason(payload: dict[str, Any]) -> str | None:
    choices = payload.get("choices") or []
    if choices and isinstance(choices[0], dict):
        finish_reason = choices[0].get("finish_reason")
        if isinstance(finish_reason, str):
            return finish_reason
    return None


def _chat_message_to_response_items(
    message: dict[str, Any], response_id: str
) -> list[dict[str, Any]]:
    items = []
    content = message.get("content")
    if content:
        items.append(
            {
                "type": "message",
                "role": "assistant",
                "id": f"msg_{response_id}",
                "content": [{"type": "output_text", "text": content}],
            }
        )
    for tool_call in message.get("tool_calls") or []:
        function = tool_call.get("function") or {}
        items.append(
            {
                "type": "function_call",
                "call_id": tool_call.get("id") or f"call_{uuid4().hex}",
                "name": function.get("name") or "tool",
                "arguments": function.get("arguments") or "{}",
            }
        )
    return items


def _response_id(payload: dict[str, Any]) -> str:
    upstream_id = payload.get("id")
    if upstream_id:
        return f"resp_{upstream_id}"
    return f"resp_{uuid4().hex}"


def _responses_usage(usage: Any) -> dict[str, Any] | None:
    if not isinstance(usage, dict):
        return None
    input_tokens = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
    output_tokens = usage.get("completion_tokens") or usage.get("output_tokens") or 0
    total_tokens = usage.get("total_tokens") or input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "input_tokens_details": {"cached_tokens": 0},
        "output_tokens": output_tokens,
        "output_tokens_details": {"reasoning_tokens": 0},
        "total_tokens": total_tokens,
    }


def _tool_name(item: dict[str, Any]) -> str:
    name = item.get("name")
    if not isinstance(name, str) or not name:
        raise ResponsesInputError("Responses tool call requires name")
    namespace = item.get("namespace")
    if namespace is not None and not isinstance(namespace, str):
        raise ResponsesInputError("Responses tool namespace must be text")
    return f"{namespace}__{name}" if namespace else name


def _sse(payload: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n".encode()
