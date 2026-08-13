from __future__ import annotations

import importlib
from dataclasses import dataclass, replace
from typing import Any

import pytest
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
