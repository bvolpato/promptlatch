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


def test_gemini_contents_and_code_assist_wrapper_extract_previews_without_thoughts():
    direct = extract_request_previews(
        {
            "systemInstruction": {"parts": [{"text": "ignore system"}]},
            "contents": [
                {"role": "user", "parts": [{"text": "first gemini question"}]},
                {
                    "role": "model",
                    "parts": [
                        {"thought": True, "text": "internal chain of thought"},
                        {"functionCall": {"name": "lookup", "args": {"q": "secret"}}},
                        {"text": "visible gemini answer"},
                    ],
                },
                {
                    "role": "user",
                    "parts": [{"functionResponse": {"name": "lookup", "response": {"ok": True}}}],
                },
                {
                    "role": "user",
                    "parts": [
                        {"inlineData": {"mimeType": "image/png", "data": "iVBORw0KGgo="}},
                        {"text": "second gemini question"},
                    ],
                },
            ],
        }
    )
    assert direct == {
        "session_preview": "first gemini question",
        "user_preview": "second gemini question",
        "assistant_preview": "visible gemini answer",
    }

    wrapped = extract_request_previews(
        {
            "model": "gemini-2.5-pro",
            "request": {
                "contents": [
                    {"parts": [{"text": "implicit user role"}]},
                    {"role": "model", "parts": [{"thought": True, "text": "only thought"}]},
                ]
            },
        }
    )
    assert wrapped == {
        "session_preview": "implicit user role",
        "user_preview": "implicit user role",
        "assistant_preview": None,
    }
