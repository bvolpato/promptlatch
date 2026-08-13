import gzip
import json
import logging

import httpx
import pytest
import respx

from promptlatch.config import CompatConfig, RedactionConfig, ServerConfig, Settings, TargetConfig
from promptlatch.proxy import create_app
from tests.fixtures import OPENAI_FAKE, PROVIDER_FIXTURES


@pytest.mark.asyncio
@respx.mock
async def test_proxy_redacts_and_forwards_json() -> None:
    settings = Settings(
        server=ServerConfig(api_key="local-token"),
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            api_key="upstream-token",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer local-token"},
            json={
                "model": "test",
                "messages": [{"role": "user", "content": f"key {OPENAI_FAKE}"}],
            },
        )

    assert response.status_code == 200
    assert route.called
    forwarded = route.calls.last.request
    assert forwarded.headers["authorization"] == "Bearer upstream-token"
    assert OPENAI_FAKE not in forwarded.content.decode()


@pytest.mark.asyncio
@respx.mock
async def test_proxy_does_not_request_encoding_absent_from_client() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        )
    )
    route = respx.get("https://upstream.example/v1/models").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        request = client.build_request("GET", "/v1/models")
        del request.headers["accept-encoding"]
        response = await client.send(request)

    assert response.status_code == 200
    assert route.calls.last.request.headers["accept-encoding"] == "identity"


@pytest.mark.asyncio
@respx.mock
async def test_proxy_redacts_query_parameters_and_preserves_duplicates() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        )
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/chat/completions",
            params=[("api_key", OPENAI_FAKE), ("tag", "one"), ("tag", "two")],
            json={"messages": []},
        )

    assert response.status_code == 200
    forwarded = route.calls.last.request
    assert OPENAI_FAKE not in str(forwarded.url)
    assert forwarded.url.params["api_key"] == "[REDACTED_SECRET]"
    assert forwarded.url.params.get_list("tag") == ["one", "two"]


@pytest.mark.asyncio
@respx.mock
async def test_proxy_redacts_secret_shaped_query_parameter_names() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        )
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            params=[(OPENAI_FAKE, "value")],
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert OPENAI_FAKE not in str(route.calls.last.request.url)
    assert route.calls.last.request.url.params["[REDACTED_SECRET]"] == "value"


@pytest.mark.asyncio
@respx.mock
async def test_proxy_redacts_multipart_body_without_corrupting_binary_bytes() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        )
    )
    route = respx.post("https://upstream.example/v1/files").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))
    binary_marker = b"\xff\x00\xfe"

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/files",
            files={
                "file": (
                    "fixture.bin",
                    binary_marker + OPENAI_FAKE.encode(),
                    "application/octet-stream",
                )
            },
        )

    assert response.status_code == 200
    forwarded = route.calls.last.request.content
    assert OPENAI_FAKE.encode() not in forwarded
    assert b"[REDACTED_SECRET]" in forwarded
    assert binary_marker in forwarded


@pytest.mark.asyncio
@respx.mock
async def test_proxy_redacts_text_without_corrupting_non_utf8_bytes() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        )
    )
    route = respx.post("https://upstream.example/v1/raw").mock(
        return_value=httpx.Response(200, text="ok")
    )
    transport = httpx.ASGITransport(app=create_app(settings))
    body = b"\xffOPENAI_API_KEY=" + OPENAI_FAKE.encode()

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/raw",
            headers={"Content-Type": "text/plain"},
            content=body,
        )

    assert response.status_code == 200
    assert route.calls.last.request.content == b"\xffOPENAI_API_KEY=[REDACTED_SECRET]"


@pytest.mark.asyncio
async def test_proxy_rejects_encoded_request_bodies() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            content=gzip.compress(json.dumps({"input": OPENAI_FAKE}).encode()),
        )

    assert response.status_code == 415
    assert response.json()["detail"] == "encoded request bodies are not supported"


@pytest.mark.asyncio
@respx.mock
async def test_proxy_preserves_encoded_body_when_redaction_is_disabled() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(enabled=False),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))
    body = gzip.compress(json.dumps({"input": OPENAI_FAKE}).encode())

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            content=body,
        )

    assert response.status_code == 200
    assert route.calls.last.request.content == body
    assert route.calls.last.request.headers["content-encoding"] == "gzip"


@pytest.mark.asyncio
@respx.mock
async def test_x_target_base_url_overrides_target() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://default.example/v1",
            allowed_base_urls=["https://alt.example/v1"],
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://alt.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"id": "resp_1"})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Target-Base-URL": "https://alt.example/v1"},
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_proxy_deduplicates_version_prefix_for_nested_api_base() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://openrouter.example/api/v1",
            block_private_targets=False,
        )
    )
    route = respx.post("https://openrouter.example/api/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/v1/chat/completions", json={"messages": []})

    assert response.status_code == 200
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_per_request_redaction_rules() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"X-Redact-Extra-Rules": '[{"type":"exact","value":"abcd1234","name":"tail"}]'},
            json={"messages": [{"role": "user", "content": "token pl_live_000000abcd1234"}]},
        )

    assert response.status_code == 200
    assert "pl_live_000000abcd1234" not in route.calls.last.request.content.decode()


@pytest.mark.asyncio
async def test_per_request_regex_rules_are_rejected_by_default() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Redact-Extra-Rules": '[{"type":"regex","value":"(a+)+$"}]'},
            json={"input": "hello"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid X-Redact-Extra-Rules header"


@pytest.mark.asyncio
@respx.mock
async def test_per_request_regex_rules_can_be_enabled_explicitly() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic", allow_extra_regex_rules=True),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Redact-Extra-Rules": '[{"type":"regex","value":"fixture-[0-9]+"}]'},
            json={"input": "fixture-123456"},
        )

    assert response.status_code == 200
    assert "fixture-123456" not in route.calls.last.request.content.decode()


@pytest.mark.asyncio
async def test_per_request_rule_count_is_limited() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(max_extra_rules=1),
    )
    transport = httpx.ASGITransport(app=create_app(settings))
    rules = [
        {"type": "exact", "value": "abcd1234"},
        {"type": "exact", "value": "efgh5678"},
    ]

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Redact-Extra-Rules": json.dumps(rules)},
            json={"input": "hello"},
        )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_request_body_size_is_limited_while_streaming() -> None:
    settings = Settings(
        server=ServerConfig(max_request_body_bytes=1024),
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async def body_chunks():
        yield b"a" * 700
        yield b"b" * 700

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"Content-Type": "text/plain"},
            content=body_chunks(),
        )

    assert response.status_code == 413
    assert response.json()["detail"] == "request body too large"


@pytest.mark.asyncio
async def test_proxy_auth_rejects_wrong_key() -> None:
    app = create_app(Settings(server=ServerConfig(api_key="local-token")))
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer wrong"},
            json={"messages": []},
        )

    assert response.status_code == 401


@pytest.mark.asyncio
@respx.mock
async def test_client_auth_headers_not_forwarded_without_target_opt_in() -> None:
    settings = Settings(
        server=ServerConfig(api_key="local-token"),
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer local-token", "X-API-Key": "client-key"},
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert "authorization" not in route.calls.last.request.headers
    assert "x-api-key" not in route.calls.last.request.headers


@pytest.mark.asyncio
@respx.mock
async def test_client_authorization_forwarded_only_when_opted_in() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
            forward_client_authorization=True,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer client-token"},
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert route.calls.last.request.headers["authorization"] == "Bearer client-token"


@pytest.mark.asyncio
@respx.mock
async def test_proxy_auth_is_never_forwarded_if_validation_is_bypassed() -> None:
    settings = Settings(
        server=ServerConfig(api_key="local-fixture-token"),
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    app = create_app(settings)
    app.state.settings.target.forward_client_authorization = True
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer local-fixture-token"},
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert "authorization" not in route.calls.last.request.headers


@pytest.mark.asyncio
@respx.mock
async def test_proxy_auth_allows_dedicated_target_authorization() -> None:
    settings = Settings(
        server=ServerConfig(api_key="local-fixture-token"),
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={
                "Authorization": "Bearer local-fixture-token",
                "X-Target-Authorization": "Bearer upstream-fixture-token",
            },
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert route.calls.last.request.headers["authorization"] == "Bearer upstream-fixture-token"
    assert "x-target-authorization" not in route.calls.last.request.headers


@pytest.mark.asyncio
@respx.mock
async def test_sensitive_headers_do_not_cross_proxy_boundary() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(
            200,
            json={"ok": True},
            headers={
                "Cookie": "provider-fixture-cookie",
                "Set-Cookie": "provider_session=fixture; Secure",
                "Anthropic-Version": "2023-06-01",
                "X-Provider-Trace-ID": "fixture-trace",
            },
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={
                "Cookie": "client_session=fixture",
                "Set-Cookie": "client_session=fixture",
                "X-Custom-Secret": OPENAI_FAKE,
                "Anthropic-Version": "2023-06-01",
                "X-Provider-Trace-ID": "fixture-trace",
            },
            json={"input": "hello"},
        )

    assert response.status_code == 200
    forwarded_headers = route.calls.last.request.headers
    assert "cookie" not in forwarded_headers
    assert "set-cookie" not in forwarded_headers
    assert "x-custom-secret" not in forwarded_headers
    assert forwarded_headers["anthropic-version"] == "2023-06-01"
    assert forwarded_headers["x-provider-trace-id"] == "fixture-trace"
    assert "cookie" not in response.headers
    assert "set-cookie" not in response.headers
    assert response.headers["anthropic-version"] == "2023-06-01"
    assert response.headers["x-provider-trace-id"] == "fixture-trace"


@pytest.mark.asyncio
@respx.mock
async def test_target_api_key_header_sets_upstream_authorization() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Target-API-Key": "upstream-token"},
            json={"input": "hello"},
        )

    assert response.status_code == 200
    forwarded = route.calls.last.request
    assert forwarded.headers["authorization"] == "Bearer upstream-token"
    assert "x-target-api-key" not in forwarded.headers


@pytest.mark.asyncio
@respx.mock
async def test_target_api_key_header_can_set_upstream_x_api_key() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            api_key_header="x-api-key",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/messages").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/messages",
            headers={"X-Target-API-Key": "upstream-token"},
            json={"messages": [{"role": "user", "content": "hello"}]},
        )

    assert response.status_code == 200
    forwarded = route.calls.last.request
    assert forwarded.headers["x-api-key"] == "upstream-token"
    assert "authorization" not in forwarded.headers


@pytest.mark.asyncio
@respx.mock
async def test_target_api_key_header_can_be_overridden_per_request() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/messages").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/messages",
            headers={
                "X-Target-API-Key": "upstream-token",
                "X-Target-API-Key-Header": "x-api-key",
            },
            json={"messages": [{"role": "user", "content": "hello"}]},
        )

    assert response.status_code == 200
    assert route.calls.last.request.headers["x-api-key"] == "upstream-token"


@pytest.mark.asyncio
async def test_invalid_target_api_key_header_is_rejected() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/messages",
            headers={
                "X-Target-API-Key": "upstream-token",
                "X-Target-API-Key-Header": "invalid-header",
            },
            json={"messages": []},
        )

    assert response.status_code == 400


@pytest.mark.asyncio
@respx.mock
async def test_target_api_key_header_overrides_configured_target_key() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            api_key="configured-token",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Target-API-Key": "header-token"},
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert route.calls.last.request.headers["authorization"] == "Bearer header-token"


@pytest.mark.asyncio
@respx.mock
async def test_configured_target_key_is_not_forwarded_to_dynamic_target() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://provider.example/v1",
            api_key="configured-token",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://other.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Target-Base-URL": "https://other.example/v1"},
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert "authorization" not in route.calls.last.request.headers
    assert "x-api-key" not in route.calls.last.request.headers


@pytest.mark.asyncio
@respx.mock
async def test_provider_response_is_forwarded_without_scanning_or_corruption() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    secret = "sk-" + "FixtureToken000000000000000000000"
    respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(
            200,
            content=gzip.compress(json.dumps({"content": secret}).encode()),
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
                "etag": '"compressed-fixture"',
            },
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/v1/responses", json={"input": "hello"})

    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"
    assert response.headers["etag"] == '"compressed-fixture"'
    assert response.json() == {"content": secret}


@pytest.mark.asyncio
@respx.mock
async def test_compressed_stream_is_forwarded_without_corruption() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    stream = b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
    respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            content=gzip.compress(stream),
            headers={"content-type": "text/event-stream", "content-encoding": "gzip"},
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/v1/chat/completions", json={"messages": []})

    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"
    assert "hello" in response.text


@pytest.mark.asyncio
@respx.mock
async def test_debug_requests_log_raw_and_redacted_bodies(caplog: pytest.LogCaptureFixture) -> None:
    settings = Settings(
        server=ServerConfig(debug_requests=True),
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    with caplog.at_level(logging.WARNING, logger="promptlatch"):
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={
                    "Proxy-Authorization": f"Bearer {OPENAI_FAKE}",
                    "X-Custom-Secret": OPENAI_FAKE,
                    "X-Request-ID": "fixture-request",
                    "X-Target-API-Key": "upstream-token",
                },
                json={"messages": [{"role": "user", "content": f"key {OPENAI_FAKE}"}]},
            )

    assert response.status_code == 200
    assert route.called
    events = [
        json.loads(record.message)
        for record in caplog.records
        if '"event": "debug_request"' in record.message
    ]
    assert len(events) == 1
    event = events[0]
    assert event["redactions"] >= 1
    assert OPENAI_FAKE in event["raw_body"]
    assert OPENAI_FAKE not in event["redacted_body"]
    assert "[REDACTED_SECRET]" in event["redacted_body"]
    assert event["headers"]["proxy-authorization"] == "[REDACTED_HEADER]"
    assert event["headers"]["x-custom-secret"] == "[REDACTED_HEADER]"
    assert event["headers"]["x-request-id"] == "fixture-request"
    assert event["headers"]["x-target-api-key"] == "[REDACTED_HEADER]"


@pytest.mark.asyncio
@respx.mock
async def test_responses_to_chat_bridge_rewrites_request_and_response() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            api_key="upstream-token",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
        compat=CompatConfig(responses_to_chat=True),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "chatcmpl_fixture",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            json={
                "model": "gpt-5.5",
                "instructions": "be terse",
                "stream": False,
                "input": [{"type": "message", "role": "user", "content": "hello"}],
            },
        )

    assert response.status_code == 200
    forwarded = json.loads(route.calls.last.request.content)
    assert forwarded["messages"] == [
        {"role": "system", "content": "be terse"},
        {"role": "user", "content": "hello"},
    ]
    assert response.json()["output"][0]["content"][0]["text"] == "ok"
    assert response.json()["usage"]["total_tokens"] == 5


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "input_item",
    [
        "not-a-mapping",
        {"type": "unknown_fixture", "content": "must not disappear"},
        {"type": "message", "role": "user"},
    ],
)
@respx.mock
async def test_responses_to_chat_bridge_rejects_invalid_input_items(input_item: object) -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
        compat=CompatConfig(responses_to_chat=True),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            json={"model": "fixture-model", "input": [input_item]},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid Responses input item"
    assert not route.called


@pytest.mark.asyncio
@respx.mock
async def test_debug_requests_trace_rejected_responses_bridge_payload(
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = Settings(
        server=ServerConfig(debug_requests=True),
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
        compat=CompatConfig(responses_to_chat=True),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    with caplog.at_level(logging.WARNING, logger="promptlatch"):
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/v1/responses",
                json={
                    "model": "fixture-model",
                    "input": [
                        {
                            "type": "unsupported_fixture",
                            "content": f"OPENAI_API_KEY={OPENAI_FAKE}",
                        }
                    ],
                },
            )

    assert response.status_code == 400
    assert not route.called
    events = [
        json.loads(record.message)
        for record in caplog.records
        if '"event": "debug_request"' in record.message
    ]
    assert len(events) == 1
    assert OPENAI_FAKE in events[0]["raw_body"]
    assert OPENAI_FAKE not in events[0]["redacted_body"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {
            "model": "fixture-model",
            "input": "hello",
            "tools": [{"type": "web_search"}],
        },
        {
            "model": "fixture-model",
            "input": "hello",
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "chat-shaped", "parameters": {"type": "object"}},
                }
            ],
        },
        {
            "model": "fixture-model",
            "input": "hello",
            "tools": [{"type": "function", "name": "missing_parameters"}],
        },
        {
            "model": "fixture-model",
            "input": [
                {
                    "type": "function_call_output",
                    "call_id": "call_fixture",
                    "output": [
                        {
                            "type": "input_image",
                            "image_url": "https://example.test/image.png",
                        }
                    ],
                }
            ],
        },
        {"model": "fixture-model", "instructions": 0, "input": "hello"},
        {
            "model": "fixture-model",
            "input": [{"type": "message", "role": 0, "content": "hello"}],
        },
    ],
)
@respx.mock
async def test_responses_to_chat_bridge_rejects_invalid_payload_without_upstream(
    payload: dict[str, object],
) -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
        compat=CompatConfig(responses_to_chat=True),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/v1/responses", json=payload)

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid Responses input item"
    assert not route.called


@pytest.mark.asyncio
@respx.mock
async def test_proxy_rejects_redacted_mapping_key_collisions() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            json={
                OPENAI_FAKE: "first",
                PROVIDER_FIXTURES["deepseek_api_key"]: "second",
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "request contains colliding keys after redaction"
    assert not route.called


@pytest.mark.asyncio
@respx.mock
async def test_responses_to_chat_bridge_streams_responses_events() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
        compat=CompatConfig(responses_to_chat=True),
    )
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            content=(
                b'data: {"id":"chatcmpl_fixture","choices":[{"delta":{"content":"he"}}]}\n\n'
                b'data: {"id":"chatcmpl_fixture","choices":[{"delta":{"content":"llo"}}],'
                b'"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}\n\n'
                b"data: [DONE]\n\n"
            ),
            headers={"content-type": "text/event-stream"},
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            json={"model": "gpt-5.5", "stream": True, "input": "hello"},
        )

    assert response.status_code == 200
    assert route.called
    forwarded = json.loads(route.calls.last.request.content)
    assert forwarded["stream"] is True
    assert forwarded["stream_options"] == {"include_usage": True}
    body = response.text
    assert "response.output_item.added" in body
    assert "response.output_text.delta" in body
    assert "response.output_item.done" in body
    assert "response.completed" in body
    assert "hello" in body


@pytest.mark.asyncio
@respx.mock
async def test_responses_to_chat_bridge_maps_chat_tool_calls() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(engine="basic"),
        compat=CompatConfig(responses_to_chat=True),
    )
    respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "chatcmpl_tool",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "call_fixture",
                                    "type": "function",
                                    "function": {
                                        "name": "exec_command",
                                        "arguments": '{"cmd":"pwd"}',
                                    },
                                }
                            ],
                        }
                    }
                ],
            },
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            json={
                "model": "gpt-5.5",
                "input": "run pwd",
                "tools": [
                    {
                        "type": "function",
                        "name": "exec_command",
                        "description": "run command",
                        "parameters": {"type": "object", "properties": {}},
                    }
                ],
            },
        )

    item = response.json()["output"][0]
    assert item == {
        "type": "function_call",
        "call_id": "call_fixture",
        "name": "exec_command",
        "arguments": '{"cmd":"pwd"}',
    }


@pytest.mark.asyncio
async def test_malformed_dynamic_target_returns_client_error() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Target-Base-URL": "https://[]"},
            json={"input": "hello"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid target URL"


@pytest.mark.asyncio
async def test_unresolvable_idna_target_returns_client_error() -> None:
    settings = Settings(target=TargetConfig(default_base_url="https://upstream.example/v1"))
    transport = httpx.ASGITransport(app=create_app(settings))
    long_label = "a" * 64

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"X-Target-Base-URL": f"https://{long_label}.example/v1"},
            json={"input": "hello"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "target host could not be resolved"


@pytest.mark.asyncio
@respx.mock
async def test_disabled_redaction_preserves_json_body_bytes() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        ),
        redaction=RedactionConfig(enabled=False),
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    transport = httpx.ASGITransport(app=create_app(settings))
    body = b'{ "input" : "preserve whitespace" }\n'

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"Content-Type": "application/json"},
            content=body,
        )

    assert response.status_code == 200
    assert route.calls.last.request.content == body


@pytest.mark.asyncio
@respx.mock
async def test_connection_named_hop_headers_are_not_forwarded() -> None:
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1",
            block_private_targets=False,
        )
    )
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(
            200,
            json={"ok": True},
            headers={"Connection": "X-Upstream-Hop", "X-Upstream-Hop": "remove-me"},
        )
    )
    transport = httpx.ASGITransport(app=create_app(settings))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/responses",
            headers={"Connection": "X-Client-Hop", "X-Client-Hop": "remove-me"},
            json={"input": "hello"},
        )

    assert response.status_code == 200
    assert "x-client-hop" not in route.calls.last.request.headers
    assert "x-upstream-hop" not in response.headers
