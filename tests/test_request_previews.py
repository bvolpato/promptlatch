from promptlatch.request_previews import extract_request_previews


def test_openai_messages_keep_only_user_and_prior_assistant_text():
    payload = {
        "messages": [
            {"role": "system", "content": "ignore system"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "first question"},
                    {"type": "image_url", "image_url": {"url": "private-image"}},
                ],
            },
            {
                "role": "assistant",
                "content": "prior answer",
                "tool_calls": [{"function": {"arguments": "ignore arguments"}}],
            },
            {"role": "tool", "content": "ignore tool result"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "latest question"},
                    {"type": "input_audio", "data": "private-audio"},
                ],
            },
        ]
    }
    previews = extract_request_previews(payload)
    assert previews == {
        "session_preview": "first question",
        "user_preview": "latest question",
        "assistant_preview": "prior answer",
    }


def test_responses_input_string_and_anthropic_text_blocks_are_bounded():
    string_input = extract_request_previews({"input": "x" * 1000})
    assert string_input["session_preview"] == string_input["user_preview"]
    assert isinstance(string_input["user_preview"], str)
    assert len(string_input["user_preview"]) == 200
    assert string_input["assistant_preview"] is None

    anthropic = extract_request_previews(
        {
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hello"}]},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "name": "hidden", "input": {"secret": "x"}},
                        {"type": "text", "text": "answer"},
                    ],
                },
                {
                    "role": "user",
                    "content": [{"type": "tool_result", "content": "ignore result"}],
                },
            ]
        }
    )
    assert anthropic == {
        "session_preview": "hello",
        "user_preview": "hello",
        "assistant_preview": "answer",
    }


def test_responses_history_ignores_nonmessage_items():
    previews = extract_request_previews(
        {
            "input": [
                {"role": "system", "content": "ignore system"},
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "question"}],
                },
                {"type": "function_call", "arguments": "ignore tool args"},
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "answer"}],
                },
                {"type": "message", "role": "user", "content": "follow up"},
            ]
        }
    )
    assert previews == {
        "session_preview": "question",
        "user_preview": "follow up",
        "assistant_preview": "answer",
    }
