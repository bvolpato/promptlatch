from __future__ import annotations

import asyncio
import gzip
import json
import os
import sqlite3
import time
import zlib
from pathlib import Path

import brotli
import httpx
import pytest
import respx

from promptlatch.config import ObservabilityConfig, RedactionConfig, Settings, TargetConfig
from promptlatch.history import HistoryReader, HistoryStore
from promptlatch.observability import Observability
from promptlatch.pricing import CATALOG_URL, PricingCatalog
from promptlatch.proxy import create_app
from promptlatch.response_metrics import ResponseMetrics, zstd
from tests.fixtures import OPENAI_FAKE


def settings_for(path: Path, **overrides) -> Settings:
    return Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic"),
        observability=ObservabilityConfig(database_path=path, pricing_enabled=False, **overrides),
    )


def records(path: Path) -> list[dict]:
    reader = HistoryReader(path)
    result = []
    for item in reader.requests()["items"]:
        record = reader.request(item["request_id"])
        assert record is not None
        result.append(record)
    return result


@pytest.mark.asyncio
@respx.mock
async def test_proxy_persists_safe_request_usage_and_thread_without_changing_wire(tmp_path):
    path = tmp_path / "history.sqlite3"
    settings = settings_for(path)
    opaque = 'OpaqueCredentialWith"Quote'
    settings.target.api_key = opaque
    app = create_app(settings)
    response_payload = {
        "id": "resp_fixture",
        "model": "fixture-model",
        "choices": [{"message": {"content": "PRIVATE RESPONSE SENTINEL"}}],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": 4,
            "total_tokens": 16,
            "prompt_tokens_details": {"cached_tokens": 2},
        },
    }
    route = respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200, json=response_payload, headers={"x-litellm-response-cost": "0.002"}
        )
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        for content in ("first", "second"):
            response = await client.post(
                "/v1/chat/completions?token=QuerySecretNotStored",
                headers={
                    "X-PromptLatch-Thread-ID": "PRIVATE THREAD SENTINEL",
                    "Authorization": "Bearer HeaderSecret",
                },
                json={
                    "model": "fixture-model",
                    "messages": [
                        {
                            "role": "user",
                            "content": (
                                f"first question {content}: {OPENAI_FAKE}; "
                                f"configured credential: {opaque}; header credential: HeaderSecret"
                            ),
                        },
                        {"role": "assistant", "content": "prior assistant answer"},
                        {
                            "role": "assistant",
                            "tool_calls": [{"function": {"arguments": "tool args"}}],
                        },
                        {"role": "tool", "content": "tool result"},
                        {"role": "user", "content": "latest user question"},
                        {"role": "assistant", "content": "latest assistant answer"},
                    ],
                },
            )
            assert response.json() == response_payload
            assert "x-promptlatch-thread-id" not in route.calls.last.request.headers
    saved = records(path)
    saved.sort(key=lambda item: item["started_at"])
    assert len(saved) == 2
    assert saved[0]["thread_id"] == saved[1]["thread_id"]
    assert saved[0]["thread_source"] == "explicit"
    assert saved[0]["input_tokens"] == 12
    assert saved[0]["output_tokens"] == 4
    assert saved[0]["cached_input_tokens"] == 2
    assert saved[0]["cost_usd"] == 0.002
    assert saved[0]["ttft_ms"] is None
    assert saved[0]["redactions"] > 0
    assert "[REDACTED_SECRET]" in saved[0]["request_body"]
    assert saved[0]["session_preview"].startswith("first question first:")
    assert "[REDACTED_SECRET]" in saved[0]["session_preview"]
    assert saved[0]["user_preview"] == "latest user question"
    assert saved[0]["assistant_preview"] == "latest assistant answer"
    stored = json.dumps(saved)
    for secret in (
        OPENAI_FAKE,
        opaque,
        "PRIVATE THREAD SENTINEL",
        "PRIVATE RESPONSE SENTINEL",
        "HeaderSecret",
        "QuerySecretNotStored",
    ):
        assert secret not in stored
        for database in tmp_path.glob("*.sqlite3"):
            assert secret.encode() not in database.read_bytes()
    previews = json.dumps(
        [
            {
                field: item[field]
                for field in ("session_preview", "user_preview", "assistant_preview")
            }
            for item in saved
        ]
    )
    assert "tool args" not in previews
    assert "tool result" not in previews
    stats_path = path.with_name(path.name + ".stats.sqlite3")
    for content in ("first question", "latest user question", "latest assistant answer"):
        assert content.encode() not in stats_path.read_bytes()
    summary = HistoryReader(path).summary()
    assert summary["totals"]["requests"] == 2
    assert summary["totals"]["total_tokens"] == 32
    assert summary["totals"]["cost_usd"] == 0.004


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "mode,reason",
    [
        ("disabled", "redaction_disabled"),
        ("partial", "partial_redaction"),
        ("metadata", "disabled"),
    ],
)
async def test_unsafe_or_disabled_capture_omits_body(tmp_path, mode, reason):
    path = tmp_path / "history.sqlite3"
    settings = settings_for(path, store_request_bodies=mode != "metadata")
    if mode == "disabled":
        settings.redaction.enabled = False
    elif mode == "partial":
        settings.redaction.redact_mode = "partial"
    respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"id": "resp_fixture"})
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        assert (await client.post("/v1/responses", json={"input": OPENAI_FAKE})).status_code == 200
    saved = records(path)[0]
    assert saved["request_body"] is None
    assert saved["body_omitted_reason"] == reason
    assert saved["session_preview"] is None
    assert saved["user_preview"] is None
    assert saved["assistant_preview"] is None
    assert saved["total_tokens"] is None
    assert saved["cost_usd"] is None


@pytest.mark.asyncio
@respx.mock
async def test_capture_masks_duplicate_credentials_and_request_specific_regex_in_model(tmp_path):
    path = tmp_path / "history.sqlite3"
    settings = settings_for(path)
    settings.redaction.allow_extra_regex_rules = True
    app = create_app(settings)
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(200, json={"model": "opaque-secret-credential"})
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.post(
            "/v1/responses",
            headers=[
                ("authorization", "Bearer FirstOpaqueCredential"),
                ("authorization", "Bearer SecondOpaqueCredential"),
                (
                    "x-redact-extra-rules",
                    json.dumps([{"type": "regex", "value": "opaque-[a-z]+-credential"}]),
                ),
            ],
            json={
                "model": "fixture-model",
                "input": "FirstOpaqueCredential SecondOpaqueCredential opaque-secret-credential",
            },
        )
        assert response.status_code == 200
        assert route.called
    stored = json.dumps(records(path))
    assert "FirstOpaqueCredential" not in stored
    assert "SecondOpaqueCredential" not in stored
    assert "opaque-secret-credential" not in stored


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("compressed", [False, True])
async def test_stream_metrics_preserve_response_bytes_and_usage(tmp_path, compressed):
    path = tmp_path / "history.sqlite3"
    events = [
        {"choices": [{"delta": {"role": "assistant"}}]},
        {"choices": [{"delta": {"content": "hello"}}]},
        {"choices": [{"delta": {"content": " world"}}]},
        {"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 2, "total_tokens": 9}},
    ]
    wire = (
        b"".join(f"data: {json.dumps(event)}\n\n".encode() for event in events)
        + b"data: [DONE]\n\n"
    )
    headers = {"content-type": "text/event-stream"}
    if compressed:
        headers["content-encoding"] = "gzip"
    respx.post("https://upstream.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200, content=gzip.compress(wire) if compressed else wire, headers=headers
        )
    )
    app = create_app(settings_for(path, dashboard_enabled=True))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.post("/v1/chat/completions", json={"stream": True, "messages": []})
        assert response.content == wire
        assert response.headers.get("content-encoding") == ("gzip" if compressed else None)
        assert response.headers["content-security-policy"].startswith("sandbox;")
    saved = records(path)[0]
    assert saved["outcome"] == "success"
    assert saved["total_tokens"] == 9
    assert saved["ttft_ms"] >= 0
    assert saved["tps"] is None  # One received chunk does not establish token cadence.


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("content_type", [None, "application/json", "text/event-stream"])
@pytest.mark.parametrize("encoding", ["identity", "gzip", "br", "zstd"])
async def test_codex_stream_with_unreliable_content_type_retains_metrics_and_wire(
    tmp_path, monkeypatch, content_type, encoding
):
    path = tmp_path / "history.sqlite3"
    settings = settings_for(path)
    settings.target.default_base_url = "https://chatgpt.com/backend-api/codex"
    clock = [10.0]
    monkeypatch.setattr(
        "promptlatch.observability.ResponseMetrics",
        lambda started: ResponseMetrics(10, clock=lambda: clock[0]),
    )
    payloads = [
        {"type": "response.created", "response": {"id": "resp_fixture"}},
        {"type": "response.output_text.delta", "delta": "PRIVATE RESPONSE SENTINEL"},
        {"type": "response.function_call_arguments.delta", "delta": "{}"},
        {
            "type": "response.completed",
            "response": {
                "model": "fixture-model",
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 7,
                    "input_tokens_details": {"cached_tokens": 30, "cache_write_tokens": 5},
                    "output_tokens_details": {"reasoning_tokens": 2},
                },
            },
        },
    ]
    chunks = [f"data: {json.dumps(payload)}\n\n".encode() for payload in payloads]
    wire = b"".join(chunks)
    if encoding == "gzip":
        compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
        chunks = [
            compressor.compress(chunk) + compressor.flush(zlib.Z_SYNC_FLUSH) for chunk in chunks
        ] + [compressor.flush()]
    elif encoding == "br":
        brotli_compressor = brotli.Compressor()
        chunks = [
            brotli_compressor.process(chunk) + brotli_compressor.flush() for chunk in chunks
        ] + [brotli_compressor.finish()]
    elif encoding == "zstd":
        zstd_compressor = zstd.ZstdCompressor()
        chunks = [
            zstd_compressor.compress(chunk) + zstd_compressor.flush(zstd.ZstdCompressor.FLUSH_BLOCK)
            for chunk in chunks
        ] + [zstd_compressor.flush()]
    forwarded_wire = b"".join(chunks)

    class TimedStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            for arrival, chunk in zip((11, 12, 14, 20, 21), chunks, strict=False):
                clock[0] = arrival
                yield chunk

        async def aclose(self):
            self.closed = True

    stream = TimedStream()
    headers = {"content-type": content_type} if content_type else {}
    if encoding != "identity":
        headers["content-encoding"] = encoding
    respx.post("https://chatgpt.com/backend-api/codex/responses").mock(
        return_value=httpx.Response(200, stream=stream, headers=headers)
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.post(
            "/backend-api/codex/responses?private-query=NOT STORED",
            json={"model": "fixture-model", "input": "hello", "stream": True},
        )
        assert response.status_code == 200
        if encoding == "zstd":
            assert response.content == forwarded_wire  # HTTPX has no optional Zstd decoder here.
        else:
            assert response.content == wire
    saved = records(path)[0]
    assert stream.closed
    assert saved["input_tokens"] == 100
    assert saved["output_tokens"] == 7
    assert saved["ttft_ms"] == 2000
    assert saved["path"] == "/backend-api/codex/responses"
    assert saved["provider"] == "chatgpt"
    assert saved["stream"] is True
    assert saved["usage_applicable"] is True
    assert saved["response_format"] == "sse"
    assert saved["outcome"] == "success"
    assert saved["cached_input_tokens"] == 30
    assert saved["cache_write_tokens"] == 5
    assert saved["reasoning_tokens"] == 2
    assert saved["generation_ms"] == 2000
    assert saved["tps"] == 3
    assert saved["metrics_incomplete"] is False
    assert saved["metrics_unavailable_reason"] is None
    assert saved["cost_usd"] is None
    assert saved["cost_unavailable_reason"] == "pricing_disabled"
    encoded = json.dumps(saved)
    assert "PRIVATE RESPONSE SENTINEL" not in encoded
    assert "private-query" not in encoded
    assert "NOT STORED" not in encoded
    for database in tmp_path.glob("*.sqlite3"):
        assert b"PRIVATE RESPONSE SENTINEL" not in database.read_bytes()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("upstream_cost", [None, "0.125"])
async def test_chatgpt_api_equivalent_cost_is_persisted_without_replacing_reported_cost(
    tmp_path, upstream_cost
):
    path = tmp_path / "history.sqlite3"
    settings = settings_for(path)
    settings.observability.pricing_enabled = True
    settings.target.default_base_url = "https://chatgpt.com/backend-api/codex"
    usage = {
        "input_tokens": 100,
        "output_tokens": 20,
        "input_tokens_details": {"cached_tokens": 40, "cache_write_tokens": 10},
    }
    payload = {"model": "gpt-6.1-sol", "usage": usage}
    headers = {"x-litellm-response-cost": upstream_cost} if upstream_cost else {}
    respx.get(CATALOG_URL).mock(return_value=httpx.Response(503))
    respx.post("https://chatgpt.com/backend-api/codex/responses").mock(
        return_value=httpx.Response(200, json=payload, headers=headers)
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.post(
            "/backend-api/codex/responses", json={"model": "gpt-6.1-sol", "input": "hello"}
        )
        assert response.json() == payload
    saved = records(path)[0]
    assert saved["provider"] == "chatgpt"
    assert saved.get("cost_unavailable_reason") is None
    if upstream_cost:
        assert saved["cost_usd"] == 0.125
        assert saved["cost_source"] == "litellm_header"
    else:
        pricing = PricingCatalog(tmp_path / "missing.json")
        pricing.load()
        expected = pricing.estimate(
            "gpt-6.1-sol",
            "chatgpt",
            {
                "input_tokens": 100,
                "output_tokens": 20,
                "cached_input_tokens": 40,
                "cache_write_tokens": 10,
            },
        )
        assert saved["cost_usd"] == expected["cost_usd"]
        assert saved["cost_source"] == "litellm_api_equivalent"
        assert saved["pricing_rates"]["source"] == "litellm_package"
    totals = HistoryReader(path).summary()["totals"]
    assert totals["cost_usd"] == saved["cost_usd"]
    assert totals["cost_usd_known_requests"] == 1
    assert totals["unknown_cost_requests"] == 0


@pytest.mark.asyncio
async def test_retained_subscription_repricing_pages_and_keeps_stats_consistent(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    now = time.time()
    metadata = {
        "thread_id": "fixture-thread",
        "started_at": now,
        "method": "POST",
        "path": "/backend-api/codex/responses",
        "provider": "chatgpt",
        "model": "gpt-6.1-sol",
        "usage_applicable": True,
    }
    completion = {
        "completed_at": now,
        "outcome": "success",
        "status_code": 200,
        "input_tokens": 100,
        "output_tokens": 20,
        "total_tokens": 120,
        "cached_input_tokens": 40,
        "cache_write_tokens": 10,
        "metrics_incomplete": False,
        "cost_usd": None,
        "cost_unavailable_reason": "subscription",
    }
    for index in range(101):
        request_id = f"retained-{index:03}"
        assert store.submit_start(metadata | {"request_id": request_id})
        assert store.submit_finish(request_id, completion)
    assert store.submit_start(metadata | {"request_id": "missing-usage"})
    assert store.submit_finish("missing-usage", completion | {"input_tokens": None})
    store.close()
    settings = settings_for(path)
    settings.observability.pricing_enabled = True
    observer = Observability(settings)
    observer.start()
    try:
        await observer.reprice_subscriptions()
        await observer.reprice_subscriptions()  # Repeated/queued candidates must be idempotent.
    finally:
        observer.close()
    quote = observer.pricing.estimate("gpt-6.1-sol", "chatgpt", completion)
    assert quote["cost_usd"] is not None
    reader = HistoryReader(path)
    for index in range(101):
        record = reader.request(f"retained-{index:03}")
        assert record is not None
        assert record["cost_usd"] == quote["cost_usd"]
        assert record["cost_source"] == "litellm_api_equivalent"
        assert record["pricing_rates"]["scope"] == "text_tokens"
    missing = reader.request("missing-usage")
    assert missing is not None and missing["cost_usd"] is None
    summary = reader.summary()
    for totals in (
        summary["totals"],
        summary["lifetime_totals"],
        summary["daily"][0],
        summary["models"][0],
    ):
        assert totals["requests"] == 102
        assert totals["cost_usd"] == pytest.approx(101 * quote["cost_usd"])
        assert totals["cost_usd_known_requests"] == 101
        assert totals["unknown_cost_requests"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type", [sqlite3.OperationalError, sqlite3.DatabaseError, PermissionError, ValueError]
)
async def test_repricing_read_errors_preserve_regular_catalog_refresh(
    tmp_path, monkeypatch, caplog, error_type
):
    settings = settings_for(tmp_path / "history.sqlite3")
    settings.observability.pricing_enabled = True
    observer = Observability(settings)
    reads = []
    refreshes = []
    sleeps = []

    def unavailable_history(*args, **kwargs):
        reads.append(True)
        raise error_type("PRIVATE DATABASE ERROR DETAILS")

    async def refresh():
        refreshes.append(True)
        return True

    async def scheduled_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(observer.reader, "subscription_pricing_candidates", unavailable_history)
    monkeypatch.setattr(observer.pricing, "refresh", refresh)
    monkeypatch.setattr("promptlatch.observability.asyncio.sleep", scheduled_sleep)
    with pytest.raises(asyncio.CancelledError):
        await observer.refresh_prices()
    assert len(refreshes) == 2
    assert len(reads) == 3  # Initial pass, then one attempt per successful refresh.
    assert sleeps == [settings.observability.pricing_refresh_hours * 3600] * 2
    assert "PRIVATE DATABASE ERROR DETAILS" not in caplog.text
    assert f"Subscription repricing deferred ({error_type.__name__})" in caplog.text


@pytest.mark.asyncio
@respx.mock
async def test_nonstream_response_alias_usage_and_get_bookkeeping(tmp_path):
    path = tmp_path / "history.sqlite3"
    settings = settings_for(path)
    settings.target.default_base_url = "https://api.openai.com/v1"
    respx.post("https://api.openai.com/v1/responses").mock(
        return_value=httpx.Response(
            200, json={"model": "fixture-model", "usage": {"input_tokens": 3, "output_tokens": 1}}
        )
    )
    respx.get("https://api.openai.com/v1/models").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        assert (await client.post("/responses", json={"input": "hi"})).status_code == 200
        assert (await client.get("/models")).status_code == 200
    saved = records(path)
    response = next(record for record in saved if record["method"] == "POST")
    assert response["path"] == "/responses"
    assert response["provider"] == "openai"
    assert response["response_format"] == "json"
    assert response["stream"] is False
    assert response["input_tokens"] == 3
    assert response["output_tokens"] == 1
    assert response["ttft_ms"] is None
    assert response["usage_applicable"] is True
    models = next(record for record in saved if record["method"] == "GET")
    assert models["usage_applicable"] is False
    totals = HistoryReader(path).summary()["totals"]
    assert totals["unknown_usage_requests"] == 0


@pytest.mark.asyncio
@respx.mock
async def test_previous_response_groups_across_restart(tmp_path):
    path = tmp_path / "history.sqlite3"
    respx.post("https://upstream.example/v1/responses").mock(
        side_effect=[
            httpx.Response(200, json={"id": "resp_first"}),
            httpx.Response(200, json={"id": "resp_second"}),
        ]
    )
    for payload in ({"input": "first"}, {"input": "second", "previous_response_id": "resp_first"}):
        app = create_app(settings_for(path))
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://proxy"
            ) as client,
        ):
            await client.post("/v1/responses", json=payload)
    saved = records(path)
    assert len({item["thread_id"] for item in saved}) == 1
    assert {item["thread_source"] for item in saved} == {"request", "previous_response"}
    first = next(item for item in saved if item["thread_source"] == "request")
    second = next(item for item in saved if item["thread_source"] == "previous_response")
    assert second["parent_response_id_hash"] == first["response_id_hash"]
    assert "turn_id" not in second


@pytest.mark.asyncio
@respx.mock
async def test_transport_and_rejected_requests_finalize_without_raw_body(tmp_path):
    path = tmp_path / "history.sqlite3"
    respx.post("https://upstream.example/v1/responses").mock(
        side_effect=httpx.ConnectError("failed")
    )
    app = create_app(settings_for(path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        assert (await client.post("/v1/responses", json={"input": "hi"})).status_code == 502
        assert (
            await client.post(
                "/v1/responses",
                content="invalid JSON secret",
                headers={"content-type": "application/json"},
            )
        ).status_code == 400
    saved = records(path)
    assert sorted(item["status_code"] for item in saved) == [400, 502]
    assert all(item["outcome"] == "http_error" for item in saved)
    assert "invalid JSON secret" not in json.dumps(saved)


@pytest.mark.asyncio
@respx.mock
async def test_dashboard_shares_server_without_intercepting_proxy_or_counting_panel_traffic(
    tmp_path,
):
    path = tmp_path / "history.sqlite3"
    settings = settings_for(path, dashboard_enabled=True)
    settings.server.api_key = "proxy-fixture-key"
    app = create_app(settings)
    token = path.with_name(path.name + ".dashboard-token").read_text().strip()
    route = respx.post("https://upstream.example/v1/responses").mock(
        return_value=httpx.Response(
            200,
            json={"id": "resp_fixture", "output": []},
            headers={
                "Set-Cookie": "promptlatch_dashboard_session=provider-fixture; Path=/_promptlatch/"
            },
        )
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        root = await client.get("/")
        assert root.status_code == 200
        assert '<base href="/_promptlatch/">' in root.text
        assert (await client.get("/_promptlatch/assets/app.js")).status_code == 200
        for auth in (None, "Bearer proxy-fixture-key"):
            response = await client.get(
                "/_promptlatch/api/summary",
                headers={"authorization": auth} if auth else {},
            )
            assert response.status_code == 401
        auth = {"authorization": f"Bearer {token}"}
        for method in ("GET", "POST", "DELETE"):
            redirect = await client.request(method, "/_promptlatch", headers=auth)
            assert redirect.status_code == 307
            assert redirect.headers["location"] == "/_promptlatch/"
        assert (await client.get("/_promptlatch/api/summary", headers=auth)).status_code == 200
        assert (
            await client.get(
                "/_promptlatch/api/summary", headers={**auth, "origin": "https://evil.example"}
            )
        ).status_code == 403
        login = await client.post("/_promptlatch/api/session", headers=auth)
        assert login.status_code == 200
        session_cookie = client.cookies.get("promptlatch_dashboard_session")
        assert session_cookie
        assert (await client.get("/_promptlatch/api/summary")).status_code == 200
        response = await client.post(
            "/v1/responses",
            headers={
                "authorization": "Bearer proxy-fixture-key",
                "cookie": f"promptlatch_dashboard_session={session_cookie}",
            },
            json={"input": "hello"},
        )
        assert response.status_code == 200
        assert response.json() == {"id": "resp_fixture", "output": []}
        assert route.call_count == 1
        assert "cookie" not in route.calls.last.request.headers
        assert "set-cookie" not in response.headers
        assert client.cookies.get("promptlatch_dashboard_session") == session_cookie
        assert (await client.get("/_promptlatch/api/summary")).status_code == 200
        assert (await client.delete("/_promptlatch/api/session")).status_code == 200
        assert (await client.get("/_promptlatch/api/summary")).status_code == 401
    assert HistoryReader(path).summary()["totals"]["requests"] == 1


@pytest.mark.asyncio
@respx.mock
async def test_disabled_dashboard_preserves_root_forwarding(tmp_path):
    app = create_app(settings_for(tmp_path / "history.sqlite3"))
    respx.get("https://upstream.example/v1/").mock(
        return_value=httpx.Response(200, text="upstream root")
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.get("/")
        assert response.status_code == 200
        assert response.text == "upstream root"
        for path in ("/_promptlatch", "/_promptlatch/", "/_promptlatch/api/summary"):
            response = await client.get(path, headers={"authorization": "Bearer stale-panel-token"})
            assert response.status_code == 404
    assert HistoryReader(tmp_path / "history.sqlite3").summary()["totals"]["requests"] == 1


@pytest.mark.asyncio
@respx.mock
async def test_dashboard_sandboxes_untrusted_upstream_documents(tmp_path):
    app = create_app(settings_for(tmp_path / "history.sqlite3", dashboard_enabled=True))
    html = '<script>sessionStorage.getItem("promptlatch.dashboard.token")</script>'
    respx.get("https://upstream.example/v1/document").mock(
        return_value=httpx.Response(
            200,
            text=html,
            headers={
                "content-type": "text/html",
                "content-security-policy": "script-src 'unsafe-inline'",
                "x-content-type-options": "invalid",
            },
        )
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.get("/v1/document")
    assert response.text == html
    assert response.headers["content-security-policy"] == (
        "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'"
    )
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_failed_pricing_task_still_flushes_and_releases_history(
    tmp_path, monkeypatch, caplog
):
    path = tmp_path / "history.sqlite3"
    failed = asyncio.Event()

    async def fail_refresh(self):
        failed.set()
        raise RuntimeError("private exception details")

    monkeypatch.setattr(Observability, "refresh_prices", fail_refresh)
    app = create_app(settings_for(path))
    async with app.router.lifespan_context(app):
        monitoring = app.state.observability
        await failed.wait()
    assert app.state.observability is None
    assert not monitoring.store.status["running"]
    assert "private exception details" not in caplog.text
    assert "Pricing refresh failed (RuntimeError)" in caplog.text
    restarted = Observability(settings_for(path))
    restarted.start()
    restarted.close()


@pytest.mark.parametrize("kind", ["fifo", "hardlink"])
def test_grouping_key_rejects_unsafe_files_without_retaining_writer_lock(tmp_path, kind):
    path = tmp_path / "history.sqlite3"
    key_path = path.with_name(path.name + ".grouping-key")
    if kind == "fifo":
        os.mkfifo(key_path, 0o600)
    else:
        source = tmp_path / "other-key"
        source.write_bytes(b"x" * 32)
        source.chmod(0o600)
        os.link(source, key_path)
    monitoring = Observability(settings_for(path))
    with pytest.raises(ValueError, match="private regular file"):
        monitoring.start()
    assert not monitoring.store.status["running"]
    key_path.unlink()
    monitoring.start()
    monitoring.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "endpoint,tool_messages",
    [
        (
            "chat/completions",
            [
                {"role": "assistant", "tool_calls": []},
                {"role": "tool", "content": "ok"},
            ],
        ),
        (
            "messages",
            [
                {
                    "role": "assistant",
                    "content": [{"type": "tool_use", "name": "lookup", "input": {}}],
                },
                {"role": "user", "content": [{"type": "tool_result", "content": "ok"}]},
            ],
        ),
    ],
)
async def test_iteration_metadata_and_previews_ignore_tool_cycles(
    tmp_path, endpoint, tool_messages
):
    path = tmp_path / "history.sqlite3"
    app = create_app(settings_for(path, max_body_bytes=12))
    respx.post(f"https://upstream.example/v1/{endpoint}").mock(
        return_value=httpx.Response(200, json={"choices": []})
    )
    original = [{"role": "user", "content": "private user message " + OPENAI_FAKE}]
    tools = [*original, *tool_messages]
    follow_up = (
        [
            {"type": "tool_result", "content": "ok"},
            {"type": "text", "text": "private follow-up message"},
        ]
        if endpoint == "messages"
        else "private follow-up message"
    )
    following = [*tools, {"role": "user", "content": follow_up}]
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        for messages in (original, tools, following):
            response = await client.post(
                f"/v1/{endpoint}",
                json={"messages": messages},
                headers={"X-PromptLatch-Thread-ID": "fixture-session"},
            )
            assert response.status_code == 200
        await client.post(
            f"/v1/{endpoint}",
            json={"messages": original},
            headers={"X-PromptLatch-Thread-ID": "different-session"},
        )
    saved = sorted(records(path), key=lambda item: item["started_at"])
    assert [item["user_turn"] for item in saved] == [1, 1, 2, 1]
    assert [item["message_count"] for item in saved] == [1, 3, 4, 1]
    assert saved[0]["turn_id"] == saved[1]["turn_id"]
    assert len({item["turn_id"] for item in saved}) == 3
    metadata = HistoryReader(path).requests()
    assert all("request_body" not in item for item in metadata["items"])
    assert metadata["items"][-1]["session_preview"].startswith("private user message")
    assert metadata["items"][-1]["assistant_preview"] is None
    assert all("tool result" not in json.dumps(item) for item in metadata["items"])
    assert all("lookup" not in json.dumps(item) for item in metadata["items"])
    assert OPENAI_FAKE not in json.dumps(metadata)
    assert saved[2]["user_preview"] == "private follow-up message"
    assert saved[0]["body_truncated"] is True
    assert len(saved[0]["user_preview"]) <= 200
    assert all(item["body_truncated"] for item in saved)
