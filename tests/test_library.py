from __future__ import annotations

import importlib
import json
from dataclasses import dataclass, replace
from typing import Any

import pytest
from openai.types.chat import ChatCompletionMessage
from openai.types.chat.chat_completion_message_function_tool_call import (
    ChatCompletionMessageFunctionToolCall,
    Function,
)
from pydantic import BaseModel, Field

from promptlatch import PromptLatch, redact_messages, redact_params, scan_params
from promptlatch.config import RedactionConfig, RuleConfig, Settings
from tests.fixtures import GEMINI_FAKE, OPENAI_FAKE


@dataclass(frozen=True)
class FixtureMessage:
    content: Any
    role: str = "human"

    def model_copy(self, update: dict[str, Any]) -> FixtureMessage:
        return replace(self, **update)


class FixturePydanticMessage(BaseModel):
    content: str
    additional_kwargs: dict[str, Any] = Field(default_factory=dict)


def test_redact_messages_filters_openai_dict_messages_without_mutating_original() -> None:
    messages = [{"role": "user", "content": f"OPENAI_API_KEY={OPENAI_FAKE}"}]

    redacted = redact_messages(messages)

    assert OPENAI_FAKE in messages[0]["content"]
    assert OPENAI_FAKE not in redacted[0]["content"]
    assert redacted[0]["content"] == "OPENAI_API_KEY=[REDACTED_SECRET]"


def test_redact_params_filters_litellm_style_kwargs() -> None:
    safe_kwargs = redact_params(
        model="openrouter/openai/gpt-5.5",
        messages=[{"role": "user", "content": f"GEMINI_API_KEY={GEMINI_FAKE}"}],
        temperature=0,
    )

    assert safe_kwargs["model"] == "openrouter/openai/gpt-5.5"
    assert safe_kwargs["temperature"] == 0
    assert GEMINI_FAKE not in safe_kwargs["messages"][0]["content"]
    assert safe_kwargs["messages"][0]["content"] == "GEMINI_API_KEY=[REDACTED_SECRET]"


def test_redact_messages_filters_langchain_tuple_messages() -> None:
    messages = [("human", f"token={OPENAI_FAKE}")]

    redacted = redact_messages(messages)

    assert redacted == [("human", "token=[REDACTED_SECRET]")]


def test_redact_messages_filters_langchain_message_objects() -> None:
    messages = [FixtureMessage(content=f"secret={GEMINI_FAKE}")]

    redacted = redact_messages(messages)

    assert isinstance(redacted[0], FixtureMessage)
    assert messages[0].content.endswith(GEMINI_FAKE)
    assert redacted[0].content == "secret=[REDACTED_SECRET]"


def test_redact_messages_scans_all_pydantic_message_fields() -> None:
    messages = [
        FixturePydanticMessage(
            content="hello",
            additional_kwargs={"tool_token": OPENAI_FAKE},
        )
    ]

    redacted = redact_messages(messages)

    assert messages[0].additional_kwargs["tool_token"] == OPENAI_FAKE
    assert redacted[0].additional_kwargs["tool_token"] == "[REDACTED_SECRET]"


def test_redact_messages_scans_nested_openai_sdk_tool_arguments() -> None:
    bearer = "FixtureToken000000000000000000000"
    message = ChatCompletionMessage.model_validate(
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "call_fixture",
                    "type": "function",
                    "function": {
                        "name": "call_api",
                        "arguments": json.dumps({"Authorization": f"Bearer {bearer}"}),
                    },
                }
            ],
        }
    )
    original = message.model_dump(mode="json")

    redacted_message = redact_messages([message])[0]
    network_payload = redacted_message.model_dump(mode="json")

    assert isinstance(redacted_message, ChatCompletionMessage)
    assert message.tool_calls is not None
    assert redacted_message.tool_calls is not None
    original_tool_call = message.tool_calls[0]
    redacted_tool_call = redacted_message.tool_calls[0]
    assert isinstance(original_tool_call, ChatCompletionMessageFunctionToolCall)
    assert isinstance(redacted_tool_call, ChatCompletionMessageFunctionToolCall)
    assert type(redacted_tool_call) is type(original_tool_call)
    assert type(redacted_tool_call.function) is type(original_tool_call.function)
    assert network_payload["tool_calls"][0]["function"]["arguments"] == (
        '{"Authorization": "Bearer [REDACTED_SECRET]"}'
    )
    assert message.model_dump(mode="json") == original


def test_redact_messages_preserves_lax_openai_sdk_models_with_missing_fields() -> None:
    bearer = "FixtureToken000000000000000000000"
    function = Function.model_construct(arguments=json.dumps({"Authorization": f"Bearer {bearer}"}))
    tool_call = ChatCompletionMessageFunctionToolCall.model_construct(function=function)
    message = ChatCompletionMessage.model_construct(role="assistant", tool_calls=[tool_call])
    for model, fields in ((function, ("name",)), (tool_call, ("id", "type"))):
        for field in fields:
            delattr(model, field)

    redacted_message = redact_messages([message])[0]
    network_payload = redacted_message.model_dump(mode="json", warnings=False)

    assert isinstance(redacted_message, ChatCompletionMessage)
    assert redacted_message.tool_calls is not None
    assert isinstance(redacted_message.tool_calls[0], ChatCompletionMessageFunctionToolCall)
    assert isinstance(redacted_message.tool_calls[0].function, Function)
    assert network_payload["tool_calls"][0]["function"]["arguments"] == (
        '{"Authorization": "Bearer [REDACTED_SECRET]"}'
    )
    assert message.tool_calls is not None
    assert function.arguments.endswith(f'Bearer {bearer}"}}')


def test_redact_messages_scans_openai_sdk_extra_fields_with_field_context() -> None:
    message = ChatCompletionMessage.model_validate(
        {
            "role": "assistant",
            "authorization": "short",
        }
    )

    redacted_message = redact_messages([message])[0]

    assert isinstance(redacted_message, ChatCompletionMessage)
    assert redacted_message.model_dump(mode="json")["authorization"] == "[REDACTED_SECRET]"
    assert message.model_dump(mode="json")["authorization"] == "short"


def test_redact_messages_rejects_secret_shaped_openai_sdk_extra_key() -> None:
    message = ChatCompletionMessage.model_validate(
        {
            "role": "assistant",
            OPENAI_FAKE: "value",
        }
    )

    with pytest.raises(ValueError) as exc_info:
        redact_messages([message])

    assert str(exc_info.value) == "model extra key cannot be safely redacted"
    assert OPENAI_FAKE not in str(exc_info.value)


def test_scan_params_returns_redaction_stats() -> None:
    result = scan_params(messages=[{"role": "user", "content": f"key {OPENAI_FAKE}"}])

    assert result.stats.redactions >= 1
    assert OPENAI_FAKE not in result.value["messages"][0]["content"]


def test_promptlatch_instance_uses_custom_rules() -> None:
    latch = PromptLatch(
        RedactionConfig(
            engine="basic",
            rules=[RuleConfig(type="exact", value="abcd1234", name="tail")],
        )
    )

    result = latch.scan_text("token=pl_live_000000000000abcd1234")

    assert "pl_live_000000000000abcd1234" not in result.value
    assert "[REDACTED_SECRET]" in result.value
    assert result.stats.rule_hits["tail"] == 1


def test_legacy_import_redacts_with_deprecation_warning() -> None:
    with pytest.warns(FutureWarning, match="use promptlatch"):
        from promptcloak import PromptCloak
        from promptcloak.config import Settings as LegacySettings

    assert LegacySettings is Settings
    assert PromptCloak().text(f"OPENAI_API_KEY={OPENAI_FAKE}") == (
        "OPENAI_API_KEY=[REDACTED_SECRET]"
    )


@pytest.mark.parametrize("module", ["audit", "compat", "patterns"])
def test_legacy_submodules_remain_importable(module: str) -> None:
    assert importlib.import_module(f"promptcloak.{module}")
