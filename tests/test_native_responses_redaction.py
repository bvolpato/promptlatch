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
