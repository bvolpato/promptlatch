from __future__ import annotations

import codecs
import json
from collections.abc import AsyncIterator
from contextlib import suppress
from time import time
from typing import Any
from uuid import uuid4


class ResponsesInputError(ValueError):
    """Raised when Responses input cannot be represented as chat messages."""


class _ChatOutputError(ValueError):
    pass


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
    if "tool_choice" in payload:
        chat["tool_choice"] = _tool_choice_to_chat(payload["tool_choice"])
    if "parallel_tool_calls" in payload:
        parallel_tool_calls = payload["parallel_tool_calls"]
        if not isinstance(parallel_tool_calls, bool):
            raise ResponsesInputError("Responses parallel_tool_calls must be boolean")
        chat["parallel_tool_calls"] = parallel_tool_calls
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


def chat_response_to_responses(
    payload: dict[str, Any], request_payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    response_id = _response_id(payload)
    finish_reason = _chat_finish_reason(payload)
    item_status = "incomplete" if finish_reason in {"length", "content_filter"} else "completed"
    try:
        tool_names = _request_tool_name_map(request_payload)
        output = _chat_message_to_response_items(
            _chat_message(payload), response_id, status=item_status, tool_names=tool_names
        )
    except (_ChatOutputError, ResponsesInputError):
        output = []
        output_invalid = True
    else:
        output_invalid = False
    has_tool_call = any(item.get("type") == "function_call" for item in output)
    if output_invalid or (finish_reason in {"tool_calls", "function_call"} and not has_tool_call):
        status = "failed"
        error = _response_error("Upstream Chat Completions response contains an invalid tool call.")
        incomplete_details = None
    elif finish_reason in {"stop", "tool_calls", "function_call"}:
        status = "completed"
        error = None
        incomplete_details = None
    elif finish_reason in {"length", "content_filter"}:
        reason = "max_output_tokens" if finish_reason == "length" else "content_filter"
        status = "incomplete"
        error = None
        incomplete_details = {"reason": reason}
    else:
        status = "failed"
        error = _response_error("Upstream Chat Completions response has no valid finish reason.")
        incomplete_details = None
    return _response_envelope(
        response_id,
        request_payload=request_payload,
        upstream_payload=payload,
        output=output,
        status=status,
        usage=_responses_usage(payload.get("usage")),
        error=error,
        incomplete_details=incomplete_details,
    )


async def chat_stream_to_responses(
    chunks: AsyncIterator[bytes], request_payload: dict[str, Any] | None = None
) -> AsyncIterator[bytes]:
    state = _ChatStreamState(request_payload)
    yield state.event(
        {
            "type": "response.created",
            "response": state.response([], "in_progress"),
        }
    )
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    buffer = ""
    event_lines: list[str] = []
    iterator = aiter(chunks)
    try:
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
                if state.finished:
                    return
        buffer += decoder.decode(b"", final=True)
        while (line := _pop_sse_line(buffer, final=True)) is not None:
            value, buffer = line
            if value:
                event_lines.append(value)
            elif event_lines:
                async for event in _chat_sse_event_to_responses("\n".join(event_lines), state):
                    yield event
                event_lines.clear()
                if state.finished:
                    return
        if buffer:
            event_lines.append(buffer)
        if event_lines:
            async for event in _chat_sse_event_to_responses("\n".join(event_lines), state):
                yield event
            if state.finished:
                return
        for event in state.failure_events(
            "upstream_stream_truncated", "Upstream stream ended before the [DONE] event."
        ):
            yield event
    finally:
        close = getattr(iterator, "aclose", None)
        if close is not None:
            with suppress(Exception):
                await close()


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
    def __init__(self, request_payload: dict[str, Any] | None = None) -> None:
        self.response_id = f"resp_{uuid4().hex}"
        self.request_payload = request_payload
        self.tool_names = _request_tool_name_map(request_payload)
        self.created_at = time()
        self.message_id = f"msg_{uuid4().hex}"
        self.text = ""
        self.refusal = ""
        self.message_started = False
        self.message_output_index: int | None = None
        self.content_order: list[str] = []
        self.content_indices: dict[str, int] = {}
        self.tool_calls: dict[int, dict[str, Any]] = {}
        self.next_output_index = 0
        self.sequence_number = 0
        self.usage: dict[str, Any] | None = None
        self.finish_reason: str | None = None
        self.finished = False

    def text_delta_events(self, delta: str) -> list[bytes]:
        return self._content_delta_events("output_text", delta)

    def refusal_delta_events(self, delta: str) -> list[bytes]:
        return self._content_delta_events("refusal", delta)

    def _content_delta_events(self, kind: str, delta: str) -> list[bytes]:
        events: list[bytes] = []
        if not self.message_started:
            self.message_started = True
            self.message_output_index = self._allocate_output_index()
            events.append(
                self.event(
                    {
                        "type": "response.output_item.added",
                        "output_index": self.message_output_index,
                        "item": self.message_item(status="in_progress", include_content=False),
                    }
                )
            )
        if kind not in self.content_indices:
            content_index = len(self.content_order)
            self.content_order.append(kind)
            self.content_indices[kind] = content_index
            events.append(
                self.event(
                    {
                        "type": "response.content_part.added",
                        "item_id": self.message_id,
                        "output_index": self.message_output_index,
                        "content_index": content_index,
                        "part": self.content_part(kind, ""),
                    }
                )
            )
        else:
            content_index = self.content_indices[kind]
        if kind == "output_text":
            self.text += delta
            event_type = "response.output_text.delta"
        else:
            self.refusal += delta
            event_type = "response.refusal.delta"
        events.append(
            self.event(
                {
                    "type": event_type,
                    "item_id": self.message_id,
                    "output_index": self.message_output_index,
                    "content_index": content_index,
                    "delta": delta,
                    **({"logprobs": []} if kind == "output_text" else {}),
                }
            )
        )
        return events

    def tool_call_delta_events(self, delta: Any) -> list[bytes]:
        if not isinstance(delta, dict) or not delta:
            raise ValueError("invalid tool call")
        raw_index = delta.get("index", len(self.tool_calls))
        if not isinstance(raw_index, int) or isinstance(raw_index, bool) or raw_index < 0:
            raise ValueError("invalid tool call index")
        index = raw_index
        call_id = delta.get("id")
        if call_id is not None and (not isinstance(call_id, str) or not call_id):
            raise ValueError("invalid tool call id")
        function = delta.get("function")
        if function is None:
            function = {}
        elif not isinstance(function, dict):
            raise ValueError("invalid tool call function")
        name_delta = function.get("name")
        arguments_delta = function.get("arguments")
        if name_delta is None:
            name_delta = ""
        if arguments_delta is None:
            arguments_delta = ""
        if not isinstance(name_delta, str) or not isinstance(arguments_delta, str):
            raise ValueError("invalid tool call delta")

        if index not in self.tool_calls:
            self.tool_calls[index] = {
                "id": f"fc_{uuid4().hex}",
                "call_id": call_id or f"call_{uuid4().hex}",
                "name": "",
                "arguments": "",
                "emitted_arguments": 0,
                "output_index": self._allocate_output_index(),
                "added": False,
            }
        tool_call = self.tool_calls[index]
        if call_id:
            tool_call["call_id"] = call_id
        tool_call["name"] += name_delta
        tool_call["arguments"] += arguments_delta

        events: list[bytes] = []
        name_is_known = not self.tool_names or tool_call["name"] in self.tool_names
        if tool_call["name"] and not tool_call["added"] and name_is_known:
            events.extend(self._tool_added_events(tool_call))
        elif tool_call["added"]:
            events.extend(self._tool_argument_delta_events(tool_call))
        return events

    def _tool_added_events(self, tool_call: dict[str, Any]) -> list[bytes]:
        tool_call["added"] = True
        events = [
            self.event(
                {
                    "type": "response.output_item.added",
                    "output_index": tool_call["output_index"],
                    "item": self.tool_item(tool_call, arguments="", status="in_progress"),
                }
            )
        ]
        events.extend(self._tool_argument_delta_events(tool_call))
        return events

    def _tool_argument_delta_events(self, tool_call: dict[str, Any]) -> list[bytes]:
        events: list[bytes] = []
        emitted_arguments = tool_call["emitted_arguments"]
        if len(tool_call["arguments"]) > emitted_arguments:
            argument_delta = tool_call["arguments"][emitted_arguments:]
            tool_call["emitted_arguments"] = len(tool_call["arguments"])
            events.append(
                self.event(
                    {
                        "type": "response.function_call_arguments.delta",
                        "item_id": tool_call["id"],
                        "output_index": tool_call["output_index"],
                        "delta": argument_delta,
                    }
                )
            )
        return events

    def _allocate_output_index(self) -> int:
        index = self.next_output_index
        self.next_output_index += 1
        return index

    def event(self, payload: dict[str, Any]) -> bytes:
        payload["sequence_number"] = self.sequence_number
        self.sequence_number += 1
        return _sse(payload)

    def text_part(self, text: str) -> dict[str, Any]:
        return {"type": "output_text", "text": text, "annotations": []}

    def refusal_part(self, refusal: str) -> dict[str, Any]:
        return {"type": "refusal", "refusal": refusal}

    def content_part(self, kind: str, value: str) -> dict[str, Any]:
        if kind == "output_text":
            return self.text_part(value)
        return self.refusal_part(value)

    def message_item(self, *, status: str, include_content: bool = True) -> dict[str, Any]:
        content = []
        if include_content:
            for kind in self.content_order:
                value = self.text if kind == "output_text" else self.refusal
                content.append(self.content_part(kind, value))
        return {
            "type": "message",
            "role": "assistant",
            "id": self.message_id,
            "status": status,
            "content": content,
        }

    def tool_item(
        self,
        tool_call: dict[str, Any],
        *,
        status: str,
        arguments: str | None = None,
    ) -> dict[str, Any]:
        identity = _response_tool_identity(tool_call["name"], self.tool_names)
        item = {
            "type": "function_call",
            "id": tool_call["id"],
            "call_id": tool_call["call_id"],
            "arguments": tool_call["arguments"] if arguments is None else arguments,
            "status": status,
        }
        item.update(identity)
        return item

    def response(
        self,
        output: list[dict[str, Any]],
        status: str,
        *,
        error: dict[str, str] | None = None,
        incomplete_details: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return _response_envelope(
            self.response_id,
            request_payload=self.request_payload,
            output=output,
            status=status,
            usage=_responses_usage(self.usage),
            error=error,
            incomplete_details=incomplete_details,
            created_at=self.created_at,
        )

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
        if any(not tool_call["name"] for tool_call in self.tool_calls.values()):
            return self.failure_events(
                "upstream_stream_invalid", "Upstream tool call has no function name."
            )
        self.finished = True
        incomplete = self.finish_reason in {"length", "content_filter"}
        status = "incomplete" if incomplete else "completed"
        events, output = self._output_events(status)
        incomplete_details = None
        if incomplete:
            reason = "max_output_tokens" if self.finish_reason == "length" else "content_filter"
            incomplete_details = {"reason": reason}
        response = self.response(output, status, incomplete_details=incomplete_details)
        events.append(self.event({"type": f"response.{status}", "response": response}))
        return events

    def failure_events(self, code: str, message: str) -> list[bytes]:
        if self.finished:
            return []
        self.finished = True
        events, output = self._output_events("incomplete")
        events.append(
            self.event({"type": "error", "code": code, "message": message, "param": None})
        )
        events.append(
            self.event(
                {
                    "type": "response.failed",
                    "response": self.response(output, "failed", error=_response_error(message)),
                }
            )
        )
        return events

    def _output_events(self, status: str) -> tuple[list[bytes], list[dict[str, Any]]]:
        events: list[bytes] = []
        output: list[dict[str, Any]] = []
        items: list[tuple[int, dict[str, Any], dict[str, Any] | None]] = []
        if self.message_started:
            assert self.message_output_index is not None
            item = self.message_item(status=status)
            items.append((self.message_output_index, item, None))
        for tool_call in self.tool_calls.values():
            if not tool_call["added"] and tool_call["name"]:
                events.extend(self._tool_added_events(tool_call))
            if not tool_call["added"]:
                continue
            item = self.tool_item(tool_call, status=status)
            items.append((tool_call["output_index"], item, tool_call))
        for output_index, item, tool_call in sorted(items, key=lambda entry: entry[0]):
            output.append(item)
            if tool_call:
                identity = _response_tool_identity(tool_call["name"], self.tool_names)
                events.append(
                    self.event(
                        {
                            "type": "response.function_call_arguments.done",
                            "item_id": tool_call["id"],
                            "output_index": output_index,
                            "arguments": tool_call["arguments"],
                            "name": identity["name"],
                        }
                    )
                )
            else:
                for kind in self.content_order:
                    content_index = self.content_indices[kind]
                    value = self.text if kind == "output_text" else self.refusal
                    if kind == "output_text":
                        done_event = {
                            "type": "response.output_text.done",
                            "item_id": self.message_id,
                            "output_index": output_index,
                            "content_index": content_index,
                            "text": value,
                            "logprobs": [],
                        }
                    else:
                        done_event = {
                            "type": "response.refusal.done",
                            "item_id": self.message_id,
                            "output_index": output_index,
                            "content_index": content_index,
                            "refusal": value,
                        }
                    events.append(self.event(done_event))
                    events.append(
                        self.event(
                            {
                                "type": "response.content_part.done",
                                "item_id": self.message_id,
                                "output_index": output_index,
                                "content_index": content_index,
                                "part": self.content_part(kind, value),
                            }
                        )
                    )
            events.append(
                self.event(
                    {
                        "type": "response.output_item.done",
                        "output_index": output_index,
                        "item": item,
                    }
                )
            )
        return events, output


async def _chat_sse_event_to_responses(raw: str, state: _ChatStreamState) -> AsyncIterator[bytes]:
    if state.finished:
        return
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
    choices = payload.get("choices")
    if choices is None:
        choices = []
    if not isinstance(choices, list):
        for event in state.failure_events(
            "upstream_stream_invalid", "Upstream stream choices must be a list."
        ):
            yield event
        return
    for choice in choices:
        if not isinstance(choice, dict):
            for event in state.failure_events(
                "upstream_stream_invalid", "Upstream stream contains an invalid choice."
            ):
                yield event
            return
        finish_reason = choice.get("finish_reason")
        if finish_reason is not None:
            state.finish_reason = finish_reason if isinstance(finish_reason, str) else ""
        delta = choice.get("delta")
        if delta is None:
            delta = {}
        if not isinstance(delta, dict):
            for event in state.failure_events(
                "upstream_stream_invalid", "Upstream stream contains an invalid delta."
            ):
                yield event
            return
        content = delta.get("content")
        if content is not None and not isinstance(content, str):
            for event in state.failure_events(
                "upstream_stream_invalid", "Upstream stream contains invalid text."
            ):
                yield event
            return
        if content:
            for event in state.text_delta_events(content):
                yield event
        refusal = delta.get("refusal")
        if refusal is not None and not isinstance(refusal, str):
            for event in state.failure_events(
                "upstream_stream_invalid", "Upstream stream contains invalid refusal text."
            ):
                yield event
            return
        if refusal:
            for event in state.refusal_delta_events(refusal):
                yield event
        tool_deltas = delta.get("tool_calls")
        if tool_deltas is None:
            tool_deltas = []
        if not isinstance(tool_deltas, list):
            for event in state.failure_events(
                "upstream_stream_invalid", "Upstream stream tool calls must be a list."
            ):
                yield event
            return
        for tool_delta in tool_deltas:
            try:
                events = state.tool_call_delta_events(tool_delta)
            except (TypeError, ValueError):
                for event in state.failure_events(
                    "upstream_stream_invalid", "Upstream stream contains an invalid tool call."
                ):
                    yield event
                return
            for event in events:
                yield event
        legacy_function_call = delta.get("function_call")
        if not tool_deltas and legacy_function_call is not None:
            try:
                events = state.tool_call_delta_events(
                    {"index": 0, "function": legacy_function_call}
                )
            except (TypeError, ValueError):
                for event in state.failure_events(
                    "upstream_stream_invalid", "Upstream stream contains an invalid tool call."
                ):
                    yield event
                return
            for event in events:
                yield event


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
            for message in _response_item_to_chat_messages(item):
                if (
                    message.get("role") == "assistant"
                    and messages
                    and messages[-1].get("role") == "assistant"
                    and ("tool_calls" in message or "tool_calls" in messages[-1])
                ):
                    _merge_assistant_turn(messages[-1], message)
                else:
                    messages.append(message)
    else:
        raise ResponsesInputError("Responses input must be text or a list")
    return messages


def _merge_assistant_turn(target: dict[str, Any], source: dict[str, Any]) -> None:
    for field in ("content", "refusal"):
        source_value = source.get(field)
        if source_value is None:
            continue
        target_value = target.get(field)
        if target_value is None:
            target[field] = source_value
        elif isinstance(target_value, str) and isinstance(source_value, str):
            target[field] = f"{target_value}\n{source_value}"
        else:
            raise ResponsesInputError("Responses assistant turn content cannot be combined")
    source_tool_calls = source.get("tool_calls")
    if source_tool_calls:
        target.setdefault("tool_calls", []).extend(source_tool_calls)


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
        if role == "assistant":
            content, refusal = _assistant_content_to_chat(item["content"])
            message = {"role": role, "content": content}
            if refusal is not None:
                message["refusal"] = refusal
            return [message]
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


def _assistant_content_to_chat(content: Any) -> tuple[Any, str | None]:
    if not isinstance(content, list):
        return _content_to_chat(content), None
    if not content:
        raise ResponsesInputError("Responses message content must be text or a non-empty list")
    refusal_parts: list[str] = []
    other_parts: list[Any] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "refusal":
            refusal = item.get("refusal")
            if not isinstance(refusal, str):
                raise ResponsesInputError("Responses refusal content requires refusal text")
            refusal_parts.append(refusal)
        else:
            other_parts.append(item)
    chat_content = _content_to_chat(other_parts) if other_parts else None
    refusal = "\n".join(refusal_parts) if refusal_parts else None
    return chat_content, refusal


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
    return [chat_tool for chat_tool, _, _ in _flattened_function_tools(tools)]


def _flattened_function_tools(
    tools: list[Any],
) -> list[tuple[dict[str, Any], str, str | None]]:
    entries: list[tuple[dict[str, Any], str, str | None]] = []
    seen_names: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            raise ResponsesInputError("Responses tool must be an object")
        kind = tool.get("type")
        if kind == "function":
            function_tools = [(tool, None)]
        elif kind == "namespace":
            namespace = tool.get("name")
            if not isinstance(namespace, str) or not namespace:
                raise ResponsesInputError("Responses tool namespace requires name")
            nested_tools = tool.get("tools")
            if not isinstance(nested_tools, list) or not nested_tools:
                raise ResponsesInputError("Responses tool namespace requires tools")
            function_tools = []
            for nested in nested_tools:
                if not isinstance(nested, dict) or nested.get("type") != "function":
                    raise ResponsesInputError("Responses namespace supports only function tools")
                function_tools.append((nested, namespace))
        else:
            raise ResponsesInputError("unsupported Responses tool type")
        for function_tool, namespace in function_tools:
            chat_tool = _function_tool_to_chat(function_tool, namespace)
            flattened_name = chat_tool["function"]["name"]
            if flattened_name in seen_names:
                raise ResponsesInputError(
                    "Responses tool name collision after namespace flattening"
                )
            seen_names.add(flattened_name)
            entries.append((chat_tool, function_tool["name"], namespace))
    return entries


def _request_tool_name_map(
    request_payload: dict[str, Any] | None,
) -> dict[str, tuple[str, str | None]]:
    if not request_payload or "tools" not in request_payload:
        return {}
    tools = request_payload["tools"]
    if not isinstance(tools, list):
        raise ResponsesInputError("Responses tools must be a list")
    return {
        chat_tool["function"]["name"]: (name, namespace)
        for chat_tool, name, namespace in _flattened_function_tools(tools)
    }


def _tool_choice_to_chat(tool_choice: Any) -> str | dict[str, Any]:
    if isinstance(tool_choice, str):
        if tool_choice not in {"auto", "none", "required"}:
            raise ResponsesInputError("unsupported Responses tool choice")
        return tool_choice
    if not isinstance(tool_choice, dict) or tool_choice.get("type") != "function":
        raise ResponsesInputError("unsupported Responses tool choice")
    return {"type": "function", "function": {"name": _tool_name(tool_choice)}}


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
    message: dict[str, Any],
    response_id: str,
    *,
    status: str,
    tool_names: dict[str, tuple[str, str | None]],
) -> list[dict[str, Any]]:
    items = []
    content = message.get("content")
    if content is not None and not isinstance(content, str):
        raise _ChatOutputError("invalid assistant content")
    message_content: list[dict[str, Any]] = []
    if content:
        message_content.append({"type": "output_text", "text": content, "annotations": []})
    refusal = message.get("refusal")
    if refusal is not None:
        if not isinstance(refusal, str):
            raise _ChatOutputError("invalid assistant refusal")
        message_content.append({"type": "refusal", "refusal": refusal})
    if message_content:
        items.append(
            {
                "type": "message",
                "role": "assistant",
                "id": f"msg_{response_id}",
                "status": status,
                "content": message_content,
            }
        )
    tool_calls = message.get("tool_calls") or []
    if not isinstance(tool_calls, list):
        raise _ChatOutputError("invalid tool calls")
    for tool_call in tool_calls:
        if not isinstance(tool_call, dict):
            raise _ChatOutputError("invalid tool call")
        call_id = tool_call.get("id")
        if call_id is not None and (not isinstance(call_id, str) or not call_id):
            raise _ChatOutputError("invalid tool call id")
        function = tool_call.get("function")
        if not isinstance(function, dict):
            raise _ChatOutputError("invalid tool call function")
        name = function.get("name")
        arguments = function.get("arguments")
        if not isinstance(name, str) or not name or not isinstance(arguments, str):
            raise _ChatOutputError("invalid tool call function")
        item = {
            "type": "function_call",
            "id": f"fc_{uuid4().hex}",
            "call_id": call_id or f"call_{uuid4().hex}",
            "arguments": arguments,
            "status": status,
        }
        item.update(_response_tool_identity(name, tool_names))
        items.append(item)
    if not tool_calls and isinstance(message.get("function_call"), dict):
        function = message["function_call"]
        name = function.get("name")
        arguments = function.get("arguments")
        if not isinstance(name, str) or not name or not isinstance(arguments, str):
            raise _ChatOutputError("invalid legacy function call")
        item = {
            "type": "function_call",
            "id": f"fc_{uuid4().hex}",
            "call_id": f"call_{uuid4().hex}",
            "arguments": arguments,
            "status": status,
        }
        item.update(_response_tool_identity(name, tool_names))
        items.append(item)
    return items


def _response_id(payload: dict[str, Any]) -> str:
    upstream_id = payload.get("id")
    if upstream_id:
        return f"resp_{upstream_id}"
    return f"resp_{uuid4().hex}"


def _response_error(message: str) -> dict[str, str]:
    return {"code": "server_error", "message": message}


def _response_envelope(
    response_id: str,
    *,
    request_payload: dict[str, Any] | None,
    output: list[dict[str, Any]],
    status: str,
    usage: dict[str, Any] | None,
    upstream_payload: dict[str, Any] | None = None,
    error: dict[str, str] | None = None,
    incomplete_details: dict[str, str] | None = None,
    created_at: float | None = None,
) -> dict[str, Any]:
    request = request_payload or {}
    upstream = upstream_payload or {}
    model = upstream.get("model") or request.get("model") or "unknown"
    upstream_created = upstream.get("created")
    if (
        created_at is None
        and isinstance(upstream_created, int)
        and not isinstance(upstream_created, bool)
    ):
        created_at = float(upstream_created)
    tools = request.get("tools")
    if not isinstance(tools, list):
        tools = []
    tool_choice = request.get("tool_choice", "auto")
    if not isinstance(tool_choice, (str, dict)):
        tool_choice = "auto"
    parallel_tool_calls = request.get("parallel_tool_calls", True)
    if not isinstance(parallel_tool_calls, bool):
        parallel_tool_calls = True
    return {
        "id": response_id,
        "created_at": created_at if created_at is not None else time(),
        "model": str(model),
        "object": "response",
        "output": output,
        "parallel_tool_calls": parallel_tool_calls,
        "tool_choice": tool_choice,
        "tools": tools,
        "status": status,
        "error": error,
        "incomplete_details": incomplete_details,
        "usage": usage,
    }


def _responses_usage(usage: Any) -> dict[str, Any] | None:
    if not isinstance(usage, dict):
        return None
    input_tokens = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
    output_tokens = usage.get("completion_tokens") or usage.get("output_tokens") or 0
    total_tokens = usage.get("total_tokens") or input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
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


def _response_tool_identity(
    flattened_name: str, tool_names: dict[str, tuple[str, str | None]]
) -> dict[str, str]:
    name, namespace = tool_names.get(flattened_name, (flattened_name, None))
    identity = {"name": name}
    if namespace is not None:
        identity["namespace"] = namespace
    return identity


def _sse(payload: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n".encode()
