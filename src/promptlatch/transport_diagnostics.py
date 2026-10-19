"""Bounded upstream diagnostics without transport payloads or exception messages."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

_PHASES = frozenset(
    {
        "connection.connect_tcp",
        "connection.connect_unix_socket",
        "connection.start_tls",
        "connection.retry",
        "proxy.start_tls",
        "socks.connect_tcp",
        "socks.setup_socks5_connection",
        "socks.start_tls",
    }
    | {
        f"{protocol}.{phase}"
        for protocol in ("http11", "http2")
        for phase in (
            "send_connection_init",
            "send_request_headers",
            "send_request_body",
            "receive_response_headers",
            "receive_response_body",
            "receive_remote_settings",
        )
    }
)
_CAUSES = frozenset(
    {
        "OSError",
        "ConnectionError",
        "ConnectionResetError",
        "ConnectionAbortedError",
        "ConnectionRefusedError",
        "BrokenPipeError",
        "TimeoutError",
        "SSLError",
        "SSLEOFError",
        "SSLZeroReturnError",
        "SSLCertVerificationError",
        "ConnectError",
        "ReadError",
        "WriteError",
        "CloseError",
        "ConnectTimeout",
        "ReadTimeout",
        "WriteTimeout",
        "PoolTimeout",
        "LocalProtocolError",
        "RemoteProtocolError",
        "ProxyError",
        "UnsupportedProtocol",
        "BrokenResourceError",
        "ClosedResourceError",
        "EndOfStream",
        "CancelledError",
    }
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]+", flags=re.ASCII)
_MAX_NUMBER = 2**63 - 1
_MAX_CHAIN = 16


class UpstreamDiagnostics:
    def __init__(
        self, request_bytes: int, *, clock: Callable[[], float] = time.perf_counter
    ) -> None:
        self._clock = clock
        self._phase = "send_request"
        self._phase_started = clock()
        self._phase_ms = 0.0
        self._phase_active = True
        self._failed = False
        self._values = {"request_body_bytes": str(min(max(request_bytes, 0), _MAX_NUMBER))}
        self._response_bytes = 0

    def _elapsed_ms(self) -> float:
        elapsed = (self._clock() - self._phase_started) * 1000
        return min(max(elapsed, 0.0), float(_MAX_NUMBER)) if math.isfinite(elapsed) else 0.0

    async def trace(self, name: str, info: dict[str, Any]) -> None:
        phase, separator, event = name.rpartition(".")
        if self._failed or not separator or phase not in _PHASES:
            return
        if event == "started":
            self._phase = phase
            self._phase_started = self._clock()
            self._phase_ms = 0.0
            self._phase_active = True
        elif event in {"complete", "failed"}:
            self._phase_ms = self._elapsed_ms() if self._phase == phase else 0.0
            self._phase = phase
            self._phase_active = False
            if event == "failed":
                self._failed = True
                error = info.get("exception")
                if isinstance(error, BaseException):
                    self.transport_error(error)

    def response_headers(self, headers: Mapping[str, str], status_code: int) -> None:
        if not self._failed and self._phase == "send_request":
            self._phase = "receive_response_body"
            self._phase_started = self._clock()
            self._phase_active = True
        if type(status_code) is int and 100 <= status_code <= 599:
            self._values["upstream_status"] = str(status_code)
        for name, field, limit in (
            ("x-request-id", "upstream_request_id", 128),
            ("request-id", "upstream_request_id", 128),
            ("cf-ray", "upstream_cf_ray", 64),
        ):
            value = headers.get(name)
            if isinstance(value, str) and 0 < len(value) <= limit and _IDENTIFIER.fullmatch(value):
                self._values.setdefault(field, value)

    def observe(self, size: int) -> None:
        self._response_bytes = min(self._response_bytes + max(size, 0), _MAX_NUMBER)

    def transport_error(self, error: BaseException) -> None:
        if not self._failed:
            if self._phase_active:
                self._phase_ms = self._elapsed_ms()
            self._phase_active = False
            self._failed = True
        seen: set[int] = set()
        current: BaseException | None = error
        cause = "UnknownError"
        error_number: int | None = None
        for _ in range(_MAX_CHAIN):
            if current is None or id(current) in seen:
                break
            seen.add(id(current))
            name = type(current).__name__
            if name in _CAUSES:
                cause = name
            elif isinstance(current, OSError):
                cause = "UnknownError"
            if isinstance(current, OSError):
                number = OSError.__dict__["errno"].__get__(current)
                if type(number) is int and 1 <= number <= 65535:
                    error_number = number
            chained = BaseException.__getattribute__(current, "__cause__")
            current = (
                chained
                if chained is not None
                else BaseException.__getattribute__(current, "__context__")
            )
        self._values.setdefault("transport_cause", cause)
        if error_number is not None:
            self._values.setdefault("transport_errno", str(error_number))

    def details(self) -> dict[str, str]:
        return {
            **self._values,
            "transport_phase": self._phase,
            "transport_phase_ms": f"{self._phase_ms:.3f}",
            "response_bytes_observed": str(self._response_bytes),
        }
