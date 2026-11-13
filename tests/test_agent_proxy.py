import json
from pathlib import Path

import httpx
import pytest
import respx
import yaml

from promptlatch.config import ObservabilityConfig, Settings
from promptlatch.proxy import create_app
from tests.fixtures import OPENAI_FAKE


def agent_settings() -> Settings:
    example = Path(__file__).resolve().parents[1] / "examples/promptlatch-agents.config.yaml"
    settings = Settings.model_validate(yaml.safe_load(example.read_text()))
    settings.observability = ObservabilityConfig(enabled=False)
    return settings


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "native_auth", "native_responses"),
    [
        ({}, True, True),
        ({"target": {"forward_client_authorization": False}}, False, True),
        ({"target": {"api_key": "fixture-configured-key"}}, False, True),
        ({"compat": {"responses_to_chat": True}}, True, False),
    ],
)
async def test_health_reports_native_client_requirements(change, native_auth, native_responses):
    data = agent_settings().model_dump()
    for section, values in change.items():
        data[section].update(values)
    app = create_app(Settings.model_validate(data))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy"
    ) as client:
        response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["client_shims"] == {
        "native_auth": native_auth,
        "native_responses": native_responses,
    }
    assert "fixture-configured-key" not in response.text


@pytest.mark.asyncio
@respx.mock
async def test_official_clients_share_proxy_and_keep_native_auth():
    settings = agent_settings()
    settings.target.block_private_targets = False  # Mock upstreams need no DNS lookup.
    app = create_app(settings)
    targets = [
        (
            "https://chatgpt.com/backend-api/codex",
            "/backend-api/codex/responses",
            "https://chatgpt.com/backend-api/codex/responses",
            {"authorization": "Bearer fixture-codex-login", "chatgpt-account-id": "fixture"},
            {"input": [{"role": "user", "content": OPENAI_FAKE}]},
        ),
        (
            "https://api.openai.com/v1",
            "/v1/responses/compact",
            "https://api.openai.com/v1/responses/compact",
            {"authorization": "Bearer fixture-openai-key"},
            {"input": [{"role": "user", "content": OPENAI_FAKE}]},
        ),
        (
            "https://api.anthropic.com",
            "/v1/messages",
            "https://api.anthropic.com/v1/messages",
            {
                "authorization": "Bearer fixture-claude-login",
                "anthropic-beta": "oauth-2025-04-20",
                "anthropic-version": "2023-06-01",
            },
            {"messages": [{"role": "user", "content": OPENAI_FAKE}]},
        ),
        (
            "https://api.anthropic.com",
            "/v1/messages/count_tokens",
            "https://api.anthropic.com/v1/messages/count_tokens",
            {"x-api-key": "fixture-anthropic-key", "anthropic-version": "2023-06-01"},
            {"messages": [{"role": "user", "content": OPENAI_FAKE}]},
        ),
        (
            "https://generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.5-pro:streamGenerateContent",
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:streamGenerateContent",
            {"x-goog-api-key": "fixture-gemini-key"},
            {"contents": [{"role": "user", "parts": [{"text": OPENAI_FAKE}]}]},
        ),
        (
            "https://cloudcode-pa.googleapis.com",
            "/v1internal:streamGenerateContent",
            "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent",
            {"authorization": "Bearer fixture-gemini-oauth"},
            {"request": {"contents": [{"role": "user", "parts": [{"text": OPENAI_FAKE}]}]}},
        ),
    ]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy"
    ) as client:
        health = (await client.get("/healthz")).json()
        assert health["redaction"] and health["client_shims"]["native_auth"]
        for base, path, upstream_url, auth_headers, payload in targets:
            stream = b'event: fixture\ndata: {"message":"unchanged"}\n\n'
            route = respx.post(upstream_url).respond(
                200, content=stream, headers={"content-type": "text/event-stream"}
            )
            response = await client.post(
                path,
                headers={"X-Target-Base-URL": base, **auth_headers},
                json={"model": "fixture-model", **payload},
            )
            assert response.status_code == 200
            assert response.content == stream
            forwarded = route.calls.last.request
            assert OPENAI_FAKE.encode() not in forwarded.content
            assert b"[REDACTED_SECRET]" in forwarded.content
            assert json.loads(forwarded.content)["model"] == "fixture-model"
            for header, value in auth_headers.items():
                assert forwarded.headers[header] == value
            assert "x-target-base-url" not in forwarded.headers

        rejected = await client.post(
            "/responses",
            headers={"X-Target-Base-URL": "https://unapproved.example"},
            json={"input": "fixture"},
        )
        assert rejected.status_code == 403


@pytest.mark.asyncio
@respx.mock
async def test_x_goog_api_key_target_header_and_client_stripping():
    settings = Settings.model_validate(
        {
            "target": {
                "default_base_url": "https://generativelanguage.googleapis.com",
                "api_key": "configured-gemini-key",
                "api_key_header": "x-goog-api-key",
                "forward_client_authorization": False,
                "block_private_targets": False,
            },
            "observability": {"enabled": False},
        }
    )
    app = create_app(settings)
    route = respx.post(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    ).respond(200, json={"candidates": []})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy"
    ) as client:
        response = await client.post(
            "/v1beta/models/gemini-2.5-flash:generateContent",
            headers={"x-goog-api-key": "untrusted-client-key"},
            json={"contents": [{"parts": [{"text": "x-goog-api-key: " + OPENAI_FAKE}]}]},
        )
    assert response.status_code == 200
    forwarded = route.calls.last.request
    assert forwarded.headers["x-goog-api-key"] == "configured-gemini-key"
    assert OPENAI_FAKE.encode() not in forwarded.content
    assert b"[REDACTED_SECRET]" in forwarded.content


@pytest.mark.asyncio
@respx.mock
async def test_gemini_query_key_forwarded_when_native_auth_enabled_and_stripped_otherwise():
    fake_gemini_key = "AI" + "zaSyDa1234567890abcdef1234567890abcde"
    # 1. Native auth forwarding preserves ?key= without counting as a prompt redaction hit
    native_settings = Settings.model_validate(
        {
            "target": {
                "default_base_url": "https://generativelanguage.googleapis.com",
                "forward_client_authorization": True,
                "block_private_targets": False,
            },
            "observability": {"enabled": False},
        }
    )
    route_native = respx.post(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent"
    ).respond(200, json={"candidates": []})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(native_settings)), base_url="http://proxy"
    ) as client:
        resp = await client.post(
            "/v1beta/models/gemini-2.5-pro:generateContent",
            params=[("key", fake_gemini_key), ("alt", "sse")],
            json={"contents": [{"parts": [{"text": "hello"}]}]},
        )
    assert resp.status_code == 200
    assert route_native.calls.last.request.url.params["key"] == fake_gemini_key
    assert route_native.calls.last.request.url.params["alt"] == "sse"

    # 2. Target API key configured -> strips client ?key= and ?api_key= completely
    managed_settings = Settings.model_validate(
        {
            "target": {
                "default_base_url": "https://generativelanguage.googleapis.com",
                "api_key": "configured-gemini-key",
                "api_key_header": "x-goog-api-key",
                "forward_client_authorization": True,
                "block_private_targets": False,
            },
            "observability": {"enabled": False},
        }
    )
    route_managed = respx.post(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent"
    ).respond(200, json={"candidates": []})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(managed_settings)), base_url="http://proxy"
    ) as client:
        resp2 = await client.post(
            "/v1beta/models/gemini-2.5-pro:generateContent",
            params=[("key", "OpaqueGatewayKey123"), ("api_key", fake_gemini_key), ("alt", "sse")],
            json={"contents": [{"parts": [{"text": "hello"}]}]},
        )
    assert resp2.status_code == 200
    fwd = route_managed.calls.last.request
    assert "key" not in fwd.url.params
    assert "api_key" not in fwd.url.params
    assert fwd.url.params["alt"] == "sse"
    assert fwd.headers["x-goog-api-key"] == "configured-gemini-key"
