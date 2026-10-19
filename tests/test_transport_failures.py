from __future__ import annotations

import json
import ssl

import httpx
import pytest

from promptlatch.config import ObservabilityConfig, RedactionConfig, Settings, TargetConfig
from promptlatch.history import HistoryReader
from promptlatch.proxy import create_app


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["send", "body", "stream"])
async def test_raw_tls_failures_are_safe_and_diagnosed(tmp_path, stage: str) -> None:
    database = tmp_path / "history.sqlite3"
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic"),
        observability=ObservabilityConfig(database_path=database, pricing_enabled=False),
    )
    failure = ssl.SSLError("PRIVATE_TLS_ERROR_SENTINEL")
    failure.reason = "SSLV3_ALERT_BAD_RECORD_MAC"
    prefix = b'data: {"type":"response.created"}\n\n' if stage == "stream" else b'{"output":'

    class FailingBody(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield prefix
            raise failure

        async def aclose(self) -> None:
            self.closed = True

    body = FailingBody()

    async def respond(_request: httpx.Request) -> httpx.Response:
        if stage == "send":
            raise failure
        content_type = "text/event-stream" if stage == "stream" else "application/json"
        return httpx.Response(200, headers={"content-type": content_type}, stream=body)

    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://proxy",
        ) as client,
    ):
        app.state.client = upstream
        response = await client.post(
            "/v1/responses",
            json={"model": "fixture-model", "input": "hello", "stream": stage == "stream"},
        )

    if stage == "stream":
        assert response.status_code == 200
        assert response.content == prefix
    else:
        assert response.status_code == 502
        assert response.json()["detail"] == (
            "upstream request failed" if stage == "send" else "upstream response failed"
        )
        assert "PRIVATE_TLS_ERROR_SENTINEL" not in response.text

    if stage != "send":
        assert body.closed

    listing = HistoryReader(database).requests()["items"]
    assert len(listing) == 1
    saved = HistoryReader(database).request(listing[0]["request_id"])
    assert saved is not None
    assert saved["outcome"] == ("transport_error" if stage == "stream" else "http_error")
    error = saved["upstream_error"]
    assert error["event"] == "transport"
    assert error["type"] == "SSLError"
    assert error["code"] == "upstream_transport_error"
    assert error["message"] == "Upstream TLS communication failed."
    assert error["transport_cause"] == "SSLError"
    assert error["tls_reason"] == "SSLV3_ALERT_BAD_RECORD_MAC"
    assert "PRIVATE_TLS_ERROR_SENTINEL" not in json.dumps(saved)
    assert error["transport_phase"] == (
        "send_request" if stage == "send" else "receive_response_body"
    )
    assert int(error["response_bytes_observed"]) == (0 if stage == "send" else len(prefix))
    assert b"PRIVATE_TLS_ERROR_SENTINEL" not in database.read_bytes()


@pytest.mark.asyncio
async def test_unrelated_send_exception_is_not_reclassified_as_transport_failure(tmp_path) -> None:
    database = tmp_path / "history.sqlite3"
    settings = Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic"),
        observability=ObservabilityConfig(database_path=database, pricing_enabled=False),
    )
    failure = RuntimeError("fixture programming error")

    async def respond(_request: httpx.Request) -> httpx.Response:
        raise failure

    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        app.state.client = upstream
        with pytest.raises(RuntimeError) as raised:
            await client.post("/v1/responses", json={"model": "fixture-model", "input": "hello"})

    assert raised.value is failure
    listing = HistoryReader(database).requests()["items"]
    saved = HistoryReader(database).request(listing[0]["request_id"])
    assert saved is not None
    assert saved["upstream_error"] is None
