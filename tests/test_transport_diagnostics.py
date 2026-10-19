import errno
import json

import httpcore
import httpx
import pytest

from promptlatch.transport_diagnostics import UpstreamDiagnostics


async def test_trace_records_failed_phase_timing_and_byte_counts() -> None:
    now = [1.0]
    diagnostics = UpstreamDiagnostics(512, clock=lambda: now[0])
    await diagnostics.trace("http11.receive_response_headers.started", {"request": object()})
    now[0] = 1.125
    await diagnostics.trace("http11.receive_response_headers.complete", {"return_value": object()})
    await diagnostics.trace("http11.receive_response_body.started", {})
    diagnostics.observe(123)
    diagnostics.observe(234)
    now[0] = 1.375
    await diagnostics.trace(
        "http11.receive_response_body.failed", {"exception": httpcore.ReadError()}
    )

    assert diagnostics.details() == {
        "request_body_bytes": "512",
        "response_bytes_observed": "357",
        "transport_phase": "http11.receive_response_body",
        "transport_phase_ms": "250.000",
        "transport_cause": "ReadError",
    }


async def test_original_failure_survives_cleanup_failure() -> None:
    now = [0.0]
    diagnostics = UpstreamDiagnostics(1, clock=lambda: now[0])
    await diagnostics.trace("http2.receive_response_body.started", {})
    now[0] = 0.5
    await diagnostics.trace(
        "http2.receive_response_body.failed", {"exception": httpcore.ReadError()}
    )
    await diagnostics.trace("http2.response_closed.started", {})
    now[0] = 10.0
    await diagnostics.trace("http2.response_closed.failed", {"exception": httpx.WriteError("")})
    diagnostics.transport_error(httpx.ReadError(""))

    details = diagnostics.details()
    assert details["transport_phase"] == "http2.receive_response_body"
    assert details["transport_phase_ms"] == "500.000"
    assert details["transport_cause"] == "ReadError"


async def test_failure_outside_trace_retains_latest_phase() -> None:
    now = [1.0]
    diagnostics = UpstreamDiagnostics(0, clock=lambda: now[0])
    await diagnostics.trace("connection.start_tls.started", {})
    now[0] = 1.025
    diagnostics.transport_error(httpx.ConnectError("must never be retained"))

    assert diagnostics.details()["transport_phase"] == "connection.start_tls"
    assert diagnostics.details()["transport_phase_ms"] == "25.000"


def test_chained_socket_error_records_errno_without_private_exception_data() -> None:
    class PrivateSocketError(ConnectionResetError):
        def __str__(self) -> str:
            raise AssertionError("exception must not be stringified")

    secret = "https://user:password@example.test/private?api_key=secret"
    root = PrivateSocketError(errno.ECONNRESET, secret, "/private/path")
    core = httpcore.ReadError(secret)
    core.__cause__ = root
    outer = httpx.ReadError(secret)
    outer.__cause__ = core
    diagnostics = UpstreamDiagnostics(32)
    diagnostics.transport_error(outer)

    details = diagnostics.details()
    assert details["transport_cause"] == "UnknownError"
    assert details["transport_errno"] == str(errno.ECONNRESET)
    assert "password" not in json.dumps(details)
    assert "private" not in json.dumps(details)


def test_known_socket_cause_and_context_are_recorded() -> None:
    root = ConnectionResetError(errno.ECONNRESET, "private message")
    outer = httpx.ReadError("other private message")
    outer.__context__ = root
    diagnostics = UpstreamDiagnostics(1)
    diagnostics.transport_error(outer)

    assert diagnostics.details()["transport_cause"] == "ConnectionResetError"
    assert diagnostics.details()["transport_errno"] == str(errno.ECONNRESET)


def test_unknown_wrapper_context_does_not_replace_known_socket_cause() -> None:
    root = ConnectionResetError(errno.ECONNRESET, "private socket detail")
    root.__context__ = RuntimeError("private wrapper detail")
    outer = httpx.ConnectError("private transport detail")
    outer.__cause__ = root
    diagnostics = UpstreamDiagnostics(1)
    diagnostics.transport_error(outer)

    assert diagnostics.details()["transport_cause"] == "ConnectionResetError"
    assert diagnostics.details()["transport_errno"] == str(errno.ECONNRESET)


@pytest.mark.parametrize("number", [-1, 0, 65536, 2**128, True])
def test_invalid_errno_is_omitted(number: int) -> None:
    diagnostics = UpstreamDiagnostics(1)
    diagnostics.transport_error(OSError(number, "private socket detail"))

    assert "transport_errno" not in diagnostics.details()


@pytest.mark.parametrize("number", [1, 65535])
def test_valid_errno_boundaries_are_retained(number: int) -> None:
    diagnostics = UpstreamDiagnostics(1)
    diagnostics.transport_error(OSError(number, "private socket detail"))

    assert diagnostics.details()["transport_errno"] == str(number)


def test_exception_chain_is_cycle_safe_and_bounded() -> None:
    errors = [httpx.ReadError("private") for _ in range(100)]
    for current, following in zip(errors, errors[1:], strict=False):
        current.__cause__ = following
    errors[-1].__cause__ = errors[0]
    diagnostics = UpstreamDiagnostics(1)
    diagnostics.transport_error(errors[0])
    assert diagnostics.details()["transport_cause"] == "ReadError"

    errors[0].__cause__ = errors[0]
    diagnostics = UpstreamDiagnostics(1)
    diagnostics.transport_error(errors[0])
    assert diagnostics.details()["transport_cause"] == "ReadError"


async def test_unknown_trace_data_is_not_retained() -> None:
    diagnostics = UpstreamDiagnostics(1)
    await diagnostics.trace("private-secret.started", {"exception": "private-secret"})
    await diagnostics.trace("http11.receive_response_body.secret", {"token": "private-secret"})

    assert diagnostics.details()["transport_phase"] == "send_request"
    assert "private-secret" not in json.dumps(diagnostics.details())


@pytest.mark.parametrize("request_id", ["req_123-abc", "a" * 128])
def test_selected_correlation_headers_are_retained(request_id: str) -> None:
    diagnostics = UpstreamDiagnostics(1)
    diagnostics.response_headers(
        {
            "x-request-id": request_id,
            "request-id": "fallback",
            "cf-ray": "1234567890abcdef-IAD",
            "authorization": "Bearer private-secret",
            "set-cookie": "session=private-secret",
        },
        502,
    )

    details = diagnostics.details()
    assert details["upstream_status"] == "502"
    assert details["upstream_request_id"] == request_id
    assert details["upstream_cf_ray"] == "1234567890abcdef-IAD"
    assert "private-secret" not in json.dumps(details)


@pytest.mark.parametrize(
    "value", ["", "a" * 129, "private secret", "https://private", "x\nsecret", "é"]
)
def test_invalid_correlation_headers_are_omitted(value: str) -> None:
    diagnostics = UpstreamDiagnostics(1)
    diagnostics.response_headers({"x-request-id": value, "cf-ray": value}, 200)

    assert "upstream_request_id" not in diagnostics.details()
    assert "upstream_cf_ray" not in diagnostics.details()


async def test_cleanup_spans_cannot_claim_first_failure_phase() -> None:
    now = [1.0]
    diagnostics = UpstreamDiagnostics(1, clock=lambda: now[0])
    diagnostics.response_headers({}, 200)
    await diagnostics.trace("http11.response_closed.started", {})
    now[0] = 1.050
    await diagnostics.trace("http11.response_closed.failed", {"exception": httpx.WriteError("")})
    diagnostics.transport_error(httpx.ReadError(""))

    assert diagnostics.details()["transport_phase"] == "receive_response_body"
    assert diagnostics.details()["transport_phase_ms"] == "50.000"
    assert diagnostics.details()["transport_cause"] == "ReadError"
