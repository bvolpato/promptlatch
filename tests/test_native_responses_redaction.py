import base64
import json

import httpx
import pytest
import respx
from cryptography.fernet import Fernet

from promptlatch.config import (
    ObservabilityConfig,
    RedactionConfig,
    RuleConfig,
    Settings,
    TargetConfig,
)
from promptlatch.history import HistoryReader
from promptlatch.proxy import create_app
from promptlatch.redaction import SecretRedactor
from tests.fixtures import OPENAI_FAKE


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    ("path", "item_type"),
    [
        ("/backend-api/codex/responses", "reasoning"),
        ("/v1/responses", "reasoning"),
        ("/backend-api/codex/responses/compact", "compaction"),
        ("/v1/responses/compact", "compaction"),
    ],
)
async def test_native_responses_preserve_valid_ciphertext_and_redact_text(
    tmp_path, path, item_type
):
    cipher = Fernet(Fernet.generate_key())
    plaintext = b"Synthetic prior reasoning for a proxy regression."
    encrypted = cipher.encrypt(plaintext).decode()
    fragment = encrypted[40:72]
    database = tmp_path / "history.sqlite3"
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic", rules=[RuleConfig(type="exact", value=fragment)]),
        observability=ObservabilityConfig(database_path=database, pricing_enabled=False),
    )
    route = respx.post("https://upstream.example" + path).mock(
        return_value=httpx.Response(200, json={"output": [], "usage": {}})
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.post(
            path,
            json={
                "model": "test",
                "input": [
                    {
                        "type": item_type,
                        "encrypted_content": encrypted,
                        "summary": [{"type": "summary_text", "text": OPENAI_FAKE}],
                    },
                    {"role": "user", "content": OPENAI_FAKE},
                ],
            },
        )
    assert response.status_code == 200
    forwarded = json.loads(route.calls.last.request.content)
    assert forwarded["input"][0]["encrypted_content"] == encrypted
    assert cipher.decrypt(forwarded["input"][0]["encrypted_content"].encode()) == plaintext
    assert forwarded["input"][0]["summary"][0]["text"] == "[REDACTED_SECRET]"
    assert forwarded["input"][1]["content"] == "[REDACTED_SECRET]"

    reader = HistoryReader(database)
    item = reader.requests()["items"][0]
    stored = reader.request(item["request_id"])
    assert stored is not None
    assert OPENAI_FAKE not in stored["request_body"]
    assert fragment not in stored["request_body"]
    assert stored["redactions"] == 2


@pytest.mark.asyncio
@respx.mock
async def test_other_endpoints_do_not_exempt_named_encrypted_fields():
    cipher = Fernet(Fernet.generate_key())
    encrypted = cipher.encrypt(b"Synthetic generic payload.").decode()
    fragment = encrypted[40:72]
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic", rules=[RuleConfig(type="exact", value=fragment)]),
        observability=ObservabilityConfig(enabled=False),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://proxy"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"input": [{"type": "reasoning", "encrypted_content": encrypted}]},
        )
    assert response.status_code == 200
    forwarded = json.loads(route.calls.last.request.content)
    assert fragment not in forwarded["input"][0]["encrypted_content"]
    assert "[REDACTED_SECRET]" in forwarded["input"][0]["encrypted_content"]


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "item_type", ["agent_message", "function_call_output", "custom_tool_call_output"]
)
async def test_native_codex_preserves_encrypted_content_parts(tmp_path, item_type):
    cipher = Fernet(Fernet.generate_key())
    plaintext = b"Synthetic encrypted agent or tool message."
    encrypted = cipher.encrypt(plaintext).decode()
    fragment = encrypted[40:72]
    content = [
        {"type": "input_text", "text": OPENAI_FAKE},
        {"type": "encrypted_content", "encrypted_content": encrypted},
    ]
    if item_type == "agent_message":
        item = {"type": item_type, "author": "agent", "recipient": "parent", "content": content}
        content_key = "content"
    else:
        item = {"type": item_type, "call_id": "call_fixture", "output": content}
        content_key = "output"
    database = tmp_path / "history.sqlite3"
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic", rules=[RuleConfig(type="exact", value=fragment)]),
        observability=ObservabilityConfig(database_path=database, pricing_enabled=False),
    )
    completed = (
        b"event: response.completed\n"
        b'data: {"type":"response.completed","response":{"status":"completed",'
        b'"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12}}}\n\n'
    )
    path = "/backend-api/codex/responses"
    route = respx.post("https://upstream.example" + path).mock(
        return_value=httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=completed
        )
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.post(
            path,
            json={
                "model": "test",
                "stream": True,
                "input": [item, {"role": "user", "content": OPENAI_FAKE}],
            },
        )

    assert response.status_code == 200
    assert response.content == completed
    forwarded = json.loads(route.calls.last.request.content)
    retained = forwarded["input"][0][content_key]
    assert retained[1]["encrypted_content"] == encrypted
    assert cipher.decrypt(retained[1]["encrypted_content"].encode()) == plaintext
    assert retained[0]["text"] == "[REDACTED_SECRET]"
    assert forwarded["input"][1]["content"] == "[REDACTED_SECRET]"

    reader = HistoryReader(database)
    stored = reader.request(reader.requests()["items"][0]["request_id"])
    assert stored is not None
    assert OPENAI_FAKE not in stored["request_body"]
    assert fragment not in stored["request_body"]
    assert stored["outcome"] == "success"
    assert stored["input_tokens"] == 10
    assert stored["output_tokens"] == 2
    assert stored["redactions"] == 2


@pytest.mark.asyncio
@respx.mock
async def test_native_tool_image_data_remains_usable_while_text_is_redacted():
    encoded = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lE"
        "QVR42mP8/x8AAwMCAO+kV5cAAAAASUVORK5CYII="
    )
    data_url = "data:image/png;base64," + encoded
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example", block_private_targets=False
        ),
        redaction=RedactionConfig(
            engine="basic", rules=[RuleConfig(type="exact", value=encoded[8:40])]
        ),
        observability=ObservabilityConfig(enabled=False),
    )
    route = respx.post("https://upstream.example/backend-api/codex/responses").mock(
        return_value=httpx.Response(200, json={"output": []})
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://proxy"
    ) as client:
        response = await client.post(
            "/backend-api/codex/responses",
            json={
                "input": [
                    {
                        "type": "custom_tool_call_output",
                        "call_id": "call_synthetic",
                        "output": [
                            {"type": "input_text", "text": OPENAI_FAKE},
                            {"type": "input_image", "image_url": data_url},
                        ],
                    }
                ]
            },
        )
    assert response.status_code == 200
    output = json.loads(route.calls.last.request.content)["input"][0]["output"]
    assert output[0]["text"] == "[REDACTED_SECRET]"
    assert output[1]["image_url"] == data_url


@pytest.mark.asyncio
@respx.mock
async def test_native_image_request_larger_than_old_limit_is_redacted_and_forwarded(tmp_path):
    image = b"\x89PNG\r\n\x1a\n" + bytes(97 * 1024**2)
    data_url = "data:image/png;base64," + base64.b64encode(image).decode("ascii")
    del image
    database = tmp_path / "history.sqlite3"
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example", block_private_targets=False
        ),
        observability=ObservabilityConfig(database_path=database, pricing_enabled=False),
    )
    route = respx.post("https://upstream.example/backend-api/codex/responses").mock(
        return_value=httpx.Response(200, json={"output": []})
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.post(
            "/backend-api/codex/responses",
            json={
                "input": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": OPENAI_FAKE},
                            {"type": "input_image", "image_url": data_url},
                        ],
                    }
                ]
            },
        )
    assert response.status_code == 200
    assert len(route.calls.last.request.content) > 128 * 1024**2
    content = json.loads(route.calls.last.request.content)["input"][0]["content"]
    assert content[0]["text"] == "[REDACTED_SECRET]"
    assert content[1]["image_url"] == data_url

    reader = HistoryReader(database)
    stored = reader.request(reader.requests()["items"][0]["request_id"])
    assert stored is not None
    assert stored["redactions"] == 1
    assert OPENAI_FAKE not in stored["request_body"]
    assert len(stored["request_body"].encode()) <= settings.observability.max_body_bytes
    assert stored["body_truncated"]


def test_gemini_protocol_preserves_canonical_inline_images_only() -> None:
    png_b64 = base64.b64encode(b"\x89PNG\r\n\x1a\n\x00" + OPENAI_FAKE.encode("ascii")).decode(
        "ascii"
    )
    webp_b64 = base64.b64encode(b"RIFF\x10\x00\x00\x00WEBP" + OPENAI_FAKE.encode("ascii")).decode(
        "ascii"
    )
    fake_png_b64 = base64.b64encode(b"NOTPNG000" + OPENAI_FAKE.encode("ascii")).decode("ascii")
    fragment = base64.b64encode(OPENAI_FAKE.encode("ascii")).decode("ascii")[:24]
    assert fragment in png_b64 and fragment in webp_b64 and fragment in fake_png_b64
    redactor = SecretRedactor(
        RedactionConfig(engine="basic", rules=[RuleConfig(type="exact", value=fragment)])
    )

    payload = {
        "systemInstruction": {
            "parts": [
                {"text": "sys " + OPENAI_FAKE},
                {"inlineData": {"mimeType": "image/png", "data": png_b64}},
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": "prompt " + OPENAI_FAKE},
                    {
                        "inlineData": {
                            "mimeType": "image/webp",
                            "data": webp_b64,
                            "displayName": "shot " + OPENAI_FAKE,
                            "api_key": "sensitive-sibling",
                        }
                    },
                    {"inlineData": {"mimeType": "text/plain", "data": OPENAI_FAKE}},
                    {"inlineData": {"mimeType": "image/png", "data": fake_png_b64}},
                    {
                        "inlineData": {
                            "mimeType": "image/png",
                            "mime_type": "image/jpeg",
                            "data": png_b64,
                        }
                    },
                ],
            },
            {
                "role": "user",
                "parts": [
                    {
                        "functionResponse": {
                            "name": "tool",
                            "response": {
                                "inlineData": {"mimeType": "image/png", "data": OPENAI_FAKE}
                            },
                            "parts": [{"inline_data": {"mime_type": "image/png", "data": png_b64}}],
                        }
                    }
                ],
            },
        ],
    }

    result = redactor.redact_payload(payload, protocol="gemini-generate-content").value
    assert result["systemInstruction"]["parts"][0]["text"] == "sys [REDACTED_SECRET]"
    assert result["systemInstruction"]["parts"][1]["inlineData"]["data"] == png_b64
    user_parts = result["contents"][0]["parts"]
    assert user_parts[0]["text"] == "prompt [REDACTED_SECRET]"
    assert user_parts[1]["inlineData"]["data"] == webp_b64
    assert user_parts[1]["inlineData"]["displayName"] == "shot [REDACTED_SECRET]"
    assert user_parts[1]["inlineData"]["api_key"] == "[REDACTED_SECRET]"
    assert user_parts[2]["inlineData"]["data"] == "[REDACTED_SECRET]"
    assert fragment not in user_parts[3]["inlineData"]["data"]
    assert fragment not in user_parts[4]["inlineData"]["data"]
    fn_resp = result["contents"][1]["parts"][0]["functionResponse"]
    assert fn_resp["response"]["inlineData"]["data"] == "[REDACTED_SECRET]"
    assert fn_resp["parts"][0]["inline_data"]["data"] == png_b64

    wrapped = {
        "model": "gemini-2.5-pro",
        "request": {
            "contents": [{"parts": [{"inlineData": {"mimeType": "image/png", "data": png_b64}}]}]
        },
    }
    assert (
        redactor.redact_payload(wrapped, protocol="gemini-generate-content").value["request"][
            "contents"
        ][0]["parts"][0]["inlineData"]["data"]
        == png_b64
    )

    from pydantic import BaseModel

    class DualOptionalBlob(BaseModel):
        mimeType: str | None = None
        mime_type: str | None = None
        data: str

    class PartModel(BaseModel):
        inline_data: DualOptionalBlob

    class ContentModel(BaseModel):
        parts: list[PartModel]

    class RequestModel(BaseModel):
        contents: list[ContentModel]

    model_payload = RequestModel(
        contents=[
            ContentModel(
                parts=[PartModel(inline_data=DualOptionalBlob(mime_type="image/png", data=png_b64))]
            )
        ]
    )
    redacted_model = redactor.redact_payload(
        model_payload, protocol="gemini-generate-content"
    ).value
    assert redacted_model.contents[0].parts[0].inline_data.data == png_b64
