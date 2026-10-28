import asyncio
import gzip
import hashlib
import json
import random
import threading

import httpx
import pytest
import respx

from promptlatch.config import (
    CompatConfig,
    ObservabilityConfig,
    RedactionConfig,
    RequestCompressionConfig,
    Settings,
    TargetConfig,
)
from promptlatch.proxy import create_app
from promptlatch.request_compression import (
    compress_request_body,
    request_compression_codec,
    zstd,
)
from tests.fixtures import OPENAI_FAKE


def large_input() -> str:
    return (
        "\n".join(
            f"Synthetic context {index}: {hashlib.sha256(str(index).encode()).hexdigest()}"
            for index in range(400)
        )
        + f"\nCredential fixture: {OPENAI_FAKE}"
    )


def settings_for(target: str, **compression) -> Settings:
    return Settings(
        target=TargetConfig(
            default_base_url=target,
            block_private_targets=False,
            request_compression=RequestCompressionConfig(**compression),
        ),
        redaction=RedactionConfig(engine="basic"),
        observability=ObservabilityConfig(enabled=False),
    )


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("https://api.openai.com/v1/responses", "zstd"),
        ("https://API.OPENAI.COM:443/v1/responses", "zstd"),
        ("https://chatgpt.com/backend-api/codex/responses", "zstd"),
        ("https://api.openai.com/v1/chat/completions", None),
        ("https://api.openai.com/v1/responses/compact", None),
        ("https://api.openai.com/v1/responses/", None),
        ("https://api.openai.com.evil.example/v1/responses", None),
        ("https://api.openai.com:8443/v1/responses", None),
        ("http://api.openai.com/v1/responses", None),
        ("https://upstream.example/v1/responses", None),
    ],
)
def test_compression_defaults_only_match_exact_supported_endpoints(endpoint, expected):
    assert (
        request_compression_codec(
            "POST",
            endpoint,
            {"content-type": "application/json"},
            16384,
            RequestCompressionConfig(),
        )
        == expected
    )


@pytest.mark.parametrize(
    ("method", "headers", "size", "enabled", "expected"),
    [
        ("POST", {"content-type": "application/json"}, 16383, True, None),
        ("POST", {"content-type": "application/json"}, 16384, True, "zstd"),
        ("POST", {"content-type": "application/json"}, 32768, False, None),
        ("GET", {"content-type": "application/json"}, 32768, True, None),
        ("POST", {"content-type": "text/plain"}, 32768, True, None),
        ("POST", {"content-type": "application/problem+json; charset=utf-8"}, 32768, True, "zstd"),
        (
            "POST",
            {"content-type": "application/json", "content-encoding": "gzip"},
            32768,
            True,
            None,
        ),
    ],
)
def test_only_large_unencoded_json_posts_are_compressed(method, headers, size, enabled, expected):
    assert (
        request_compression_codec(
            method,
            "https://api.openai.com/v1/responses",
            headers,
            size,
            RequestCompressionConfig(enabled=enabled),
        )
        == expected
    )


@pytest.mark.parametrize("codec", ["identity", "gzip", "zstd"])
def test_endpoint_overrides_enable_or_disable_a_specific_codec(codec):
    endpoint = "https://upstream.example/v1/responses"
    assert request_compression_codec(
        "POST",
        endpoint,
        {"content-type": "application/json"},
        16384,
        RequestCompressionConfig(endpoints={endpoint: codec}),
    ) == (None if codec == "identity" else codec)


def test_builtin_endpoint_can_be_disabled():
    endpoint = "https://api.openai.com/v1/responses"
    assert (
        request_compression_codec(
            "POST",
            endpoint,
            {"content-type": "application/json"},
            16384,
            RequestCompressionConfig(endpoints={endpoint: "identity"}),
        )
        is None
    )


@pytest.mark.parametrize("codec", ["gzip", "zstd"])
def test_compressing_body_round_trips_and_reduces_upload(codec):
    body = json.dumps({"input": large_input()}).encode()
    result = compress_request_body(body, codec, "https://upstream.example/v1/responses")
    decode = gzip.decompress if codec == "gzip" else zstd.decompress
    assert result.encoding == codec
    assert decode(result.body) == body
    assert len(result.body) < len(body)
    assert result.compression_ms >= 0


@pytest.mark.parametrize("codec", ["gzip", "zstd"])
def test_compression_that_enlarges_body_is_skipped(codec):
    body = random.Random(0).randbytes(4096)
    result = compress_request_body(body, codec, "https://upstream.example/v1/responses")
    assert result.encoding == "identity"
    assert result.body is body


def test_public_responses_expansion_ratio_limit_does_not_create_a_413():
    body = json.dumps({"input": "a" * 65536}).encode()
    compressed = zstd.compress(body, level=1)
    assert len(body) > 100 * len(compressed)
    result = compress_request_body(body, "zstd", "https://api.openai.com/v1/responses")
    assert result.encoding == "identity"
    assert result.body is body


def test_optional_compressor_failure_falls_back_without_logging_payload(monkeypatch, caplog):
    def fail(*_args, **_kwargs):
        raise zstd.ZstdError("PRIVATE_COMPRESSION_FAILURE")

    monkeypatch.setattr(zstd, "compress", fail)
    body = large_input().encode()
    result = compress_request_body(body, "zstd", "https://api.openai.com/v1/responses")
    assert result.encoding == "identity"
    assert result.body is body
    assert "request compression failed" in caplog.text
    assert "PRIVATE_COMPRESSION_FAILURE" not in caplog.text
    assert OPENAI_FAKE not in caplog.text


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    ("target", "overrides", "expected"),
    [
        ("https://api.openai.com/v1", {}, "zstd"),
        ("https://chatgpt.com/backend-api/codex", {}, "zstd"),
        ("https://upstream.example/v1", {}, "identity"),
        (
            "https://upstream.example/v1",
            {"https://upstream.example/v1/responses": "gzip"},
            "gzip",
        ),
        (
            "https://api.openai.com/v1",
            {"https://api.openai.com/v1/responses": "identity"},
            "identity",
        ),
    ],
)
async def test_proxy_compresses_after_redaction_and_keeps_response_stream(
    target, overrides, expected
):
    wire = b'data: {"type":"response.completed","response":{"status":"completed"}}\n\n'
    response_body = gzip.compress(wire)
    route = respx.post(target + "/responses").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/event-stream", "content-encoding": "gzip"},
            content=response_body,
        )
    )
    app = create_app(settings_for(target, endpoints=overrides))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy"
    ) as client:
        response = await client.post(
            "/responses",
            json={"model": "fixture", "input": large_input(), "stream": True},
            headers={"Accept-Encoding": "gzip", "Content-MD5": "stale-body-digest"},
        )
    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"
    assert response.content == wire
    request = route.calls.last.request
    assert len(route.calls) == 1
    assert request.headers["accept-encoding"] == "gzip"
    assert request.headers["content-length"] == str(len(request.content))
    assert request.headers.get("content-encoding", "identity") == expected
    if expected != "identity":
        assert "content-md5" not in request.headers
    decoded = (
        gzip.decompress(request.content)
        if expected == "gzip"
        else zstd.decompress(request.content)
        if expected == "zstd"
        else request.content
    )
    assert OPENAI_FAKE.encode() not in decoded
    assert "[REDACTED_SECRET]" in json.loads(decoded)["input"]


@pytest.mark.asyncio
@respx.mock
async def test_bridge_compresses_the_final_chat_payload_for_its_actual_endpoint():
    target = "https://upstream.example/v1"
    settings = settings_for(target, endpoints={target + "/chat/completions": "gzip"})
    settings.compat = CompatConfig(responses_to_chat=True)
    route = respx.post(target + "/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "fixture",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            },
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://proxy"
    ) as client:
        response = await client.post(
            "/v1/responses", json={"model": "fixture", "input": large_input()}
        )
    assert response.status_code == 200
    assert response.json()["object"] == "response"
    request = route.calls.last.request
    assert request.headers["content-encoding"] == "gzip"
    payload = json.loads(gzip.decompress(request.content))
    assert "input" not in payload
    assert OPENAI_FAKE not in json.dumps(payload)
    assert "[REDACTED_SECRET]" in payload["messages"][0]["content"]


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("failure", ["unsupported", "reset"])
async def test_compressed_post_is_not_replayed_after_provider_failure(failure):
    route = respx.post("https://api.openai.com/v1/responses")
    if failure == "unsupported":
        route.mock(return_value=httpx.Response(415, json={"error": "unsupported compression"}))
    else:
        route.mock(side_effect=httpx.ReadError("PRIVATE_TRANSPORT_FAILURE"))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(settings_for("https://api.openai.com/v1"))),
        base_url="http://proxy",
    ) as client:
        response = await client.post("/responses", json={"input": large_input()})
    assert response.status_code == (415 if failure == "unsupported" else 502)
    assert len(route.calls) == 1
    assert route.calls.last.request.headers["content-encoding"] == "zstd"
    assert "PRIVATE_TRANSPORT_FAILURE" not in response.text


@pytest.mark.asyncio
@respx.mock
async def test_slow_compression_does_not_block_health_requests(monkeypatch):
    import promptlatch.proxy as proxy

    started = threading.Event()
    finish = threading.Event()
    original = proxy.compress_request_body

    def slow_compress(*args):
        started.set()
        assert finish.wait(timeout=5)
        return original(*args)

    monkeypatch.setattr(proxy, "compress_request_body", slow_compress)
    respx.post("https://api.openai.com/v1/responses").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(settings_for("https://api.openai.com/v1"))),
        base_url="http://proxy",
    ) as client:
        upload = asyncio.create_task(client.post("/responses", json={"input": large_input()}))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            response = await asyncio.wait_for(client.get("/healthz"), timeout=1)
            assert response.status_code == 200
            assert not upload.done()
        finally:
            finish.set()
        assert (await upload).status_code == 200
