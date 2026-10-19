import asyncio
import json

import anyio
import httpx
import pytest
from starlette.requests import ClientDisconnect

from promptlatch import proxy
from promptlatch.config import ObservabilityConfig, RedactionConfig, Settings, TargetConfig
from promptlatch.history import HistoryReader
from promptlatch.observability import Observability
from promptlatch.response_metrics import ResponseMetrics


def settings_for(**kwargs):
    return Settings(
        target=TargetConfig(
            default_base_url="https://upstream.example/v1", block_private_targets=False
        ),
        redaction=RedactionConfig(engine="basic"),
        observability=ObservabilityConfig(**kwargs),
    )


class WaitingStream(httpx.AsyncByteStream):
    closed = False

    async def __aiter__(self):
        yield b'data: {"type":"response.created"}\n\n'
        await anyio.sleep_forever()

    async def aclose(self):
        # Network cleanup yields, unlike a synchronous fixture flag assignment.
        await anyio.sleep(0)
        self.closed = True


@pytest.mark.parametrize("owned_client", [False, True])
async def test_disconnect_cancel_scope_closes_upstream_without_closing_shared_client(owned_client):
    stream = WaitingStream()
    upstream = httpx.Response(200, stream=stream)
    client = httpx.AsyncClient()
    first_chunk = anyio.Event()

    async def consume():
        async for _ in proxy._stream_upstream(upstream, owned_client, client, decoded=False):
            first_chunk.set()

    try:
        async with anyio.create_task_group() as group:
            group.start_soon(consume)
            await first_chunk.wait()
            group.cancel_scope.cancel()
        assert stream.closed
        assert upstream.is_closed
        assert client.is_closed is owned_client
    finally:
        await client.aclose()


@pytest.mark.parametrize("send_stage", ["http.response.start", "http.response.body"])
async def test_asgi_send_disconnect_closes_upstream_even_before_iteration(monkeypatch, send_stage):
    stream = WaitingStream()
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, headers={"content-type": "text/event-stream"}, stream=stream
            )
        )
    )
    monkeypatch.setattr(proxy, "_client_for_request", lambda *_: (client, True))
    app = proxy.create_app(settings_for(enabled=False))
    body = json.dumps({"input": "hello", "stream": True}).encode()
    received = False

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body}
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == send_stage:
            raise OSError("synthetic downstream disconnect")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/responses",
        "raw_path": b"/v1/responses",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 1234),
        "server": ("proxy", 80),
    }
    try:
        with pytest.raises(ClientDisconnect):
            await app(scope, receive, send)
        assert stream.closed
        assert client.is_closed
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    "failure", [asyncio.CancelledError(), ValueError("synthetic send failure")]
)
async def test_initial_send_failure_closes_owned_client_and_propagates(monkeypatch, failure):
    async def fail(_):
        raise failure

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(fail))
    monkeypatch.setattr(proxy, "_client_for_request", lambda *_: (upstream, True))
    app = proxy.create_app(settings_for(enabled=False))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            with pytest.raises(type(failure)) as raised:
                await client.post("/v1/responses", json={"input": "hello"})
        assert raised.value is failure
        assert upstream.is_closed
    finally:
        await upstream.aclose()


async def test_cleanup_failure_preserves_original_stream_error_and_closes_owned_client():
    failure = httpx.ReadError("synthetic upstream disconnect")

    class FailedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"type":"response.created"}\n\n'
            raise failure

        async def aclose(self):
            await anyio.sleep(0)
            raise ValueError("synthetic cleanup failure")

    upstream = httpx.Response(200, stream=FailedStream())
    client = httpx.AsyncClient()
    try:
        chunks = proxy._stream_upstream(upstream, True, client, decoded=False)
        assert await anext(chunks) == b'data: {"type":"response.created"}\n\n'
        with pytest.raises(httpx.ReadError) as raised:
            await anext(chunks)
        assert raised.value is failure
        assert client.is_closed
    finally:
        await client.aclose()


@pytest.mark.parametrize("stage", ["response_headers", "transport_error"])
async def test_metric_setup_failure_preserves_upstream_result(tmp_path, monkeypatch, stage):
    def fail_metric(*_):
        raise ValueError("synthetic metrics failure")

    monkeypatch.setattr(ResponseMetrics, stage, fail_metric)
    path = tmp_path / "history.sqlite3"
    settings = settings_for(database_path=path, pricing_enabled=False)
    owner = Observability(settings)
    owner.start()
    app = proxy.create_app(settings)
    app.state.observability = owner
    wire = b'{"output":[],"usage":{"input_tokens":1,"output_tokens":0}}'

    async def respond(_):
        if stage == "transport_error":
            raise httpx.ReadError("synthetic upstream failure")
        return httpx.Response(200, stream=httpx.ByteStream(wire))

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
            app.state.client = upstream
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://proxy"
            ) as client:
                response = await client.post(
                    "/v1/responses", json={"model": "fixture-model", "input": "hello"}
                )
        assert response.status_code == (502 if stage == "transport_error" else 200)
        if stage == "response_headers":
            assert response.content == wire
        else:
            assert response.json() == {"detail": "upstream request failed"}
    finally:
        owner.close()
    reader = HistoryReader(path)
    saved = reader.request(reader.requests()["items"][0]["request_id"])
    assert saved is not None
    assert saved["metrics_unavailable_reason"] == "observer_error"
