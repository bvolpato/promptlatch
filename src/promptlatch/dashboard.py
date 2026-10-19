from __future__ import annotations

import hmac
import html
import ipaddress
import re
import secrets
import sqlite3
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from promptlatch.history import HistoryReader

_ASSETS = Path(__file__).with_name("dashboard_assets")
_HOST = re.compile(r"(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(?::([0-9]{1,5}))?\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_SESSION_COOKIE = "promptlatch_dashboard_session"
_SESSION_SECONDS = 30 * 24 * 60 * 60
_SESSION = re.compile(r"v1\.([0-9]{1,12})\.([0-9]{1,12})\.([A-Za-z0-9_-]{43})\.([a-f0-9]{64})\Z")
_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; font-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def dashboard_shell(url_prefix: str = "") -> HTMLResponse:
    """Serve the public sign-in shell with assets scoped to the dashboard mount."""
    prefix = url_prefix.rstrip("/")
    if not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", prefix):
        raise ValueError("dashboard URL prefix must be an absolute path")
    content = (_ASSETS / "index.html").read_text(encoding="utf-8")
    content = content.replace("__PROMPTLATCH_BASE__", html.escape(prefix + "/", quote=True))
    return HTMLResponse(content, headers=_HEADERS)


def _valid_host(host: str, loopback_only: bool) -> bool:
    match = _HOST.fullmatch(host)
    if match is None or (match.group(2) is not None and not 1 <= int(match.group(2)) <= 65535):
        return False
    address = match.group(1)
    if address.startswith("["):
        with suppress(ValueError):
            parsed = ipaddress.IPv6Address(address[1:-1])
            return not loopback_only or (parsed.ipv4_mapped or parsed).is_loopback
        return False
    if len(address) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in address.split(".")):
        return False
    if not loopback_only or address == "localhost":
        return True
    with suppress(ValueError):
        return ipaddress.IPv4Address(address).is_loopback
    return False


def create_dashboard_app(
    database_path: Path, token: str, *, url_prefix: str = "", loopback_only: bool = True
) -> FastAPI:
    """Create an authenticated history viewer, optionally mounted in the proxy."""
    if not token or not token.strip():
        raise ValueError("dashboard token is required")
    prefix = url_prefix.rstrip("/")
    if not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", prefix):
        raise ValueError("dashboard URL prefix must be an absolute path")
    cookie_path = prefix + "/"
    expected_token = token.encode("utf-8")
    session_key = hmac.digest(
        expected_token, b"promptlatch dashboard session v1\0" + cookie_path.encode(), "sha256"
    )
    reader = HistoryReader(database_path)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def protect_local_origin(request: Request, call_next: Any) -> Any:
        hosts = request.headers.getlist("host")
        host = hosts[0] if len(hosts) == 1 else ""
        origin = request.headers.get("origin")
        origins = request.headers.getlist("origin")
        same_origin = not origins or (
            len(origins) == 1 and origin == f"{request.url.scheme}://{host}"
        )
        fetch_site = request.headers.get("sec-fetch-site")
        if (
            not _valid_host(host, loopback_only)
            or not same_origin
            or fetch_site in {"cross-site", "same-site"}
        ):
            response = JSONResponse({"detail": "Dashboard origin rejected"}, status_code=403)
        else:
            response = await call_next(request)
        response.headers.update(_HEADERS)
        return response

    def authentication_required() -> HTTPException:
        return HTTPException(
            status_code=401,
            detail="Dashboard authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    def session_cookie(request: Request) -> str | None:
        cookies = request.headers.getlist("cookie")
        if len(cookies) > 1:
            raise authentication_required()
        found = None
        if cookies:
            for item in cookies[0].split(";"):
                name, separator, value = item.strip().partition("=")
                if not separator or not name:
                    raise authentication_required()
                if name == _SESSION_COOKIE:
                    if found is not None or not _SESSION.fullmatch(value):
                        raise authentication_required()
                    found = value
        return found

    def bootstrap_authorized(request: Request) -> bool:
        headers = request.headers.getlist("authorization")
        if len(headers) > 1:
            raise authentication_required()
        if not headers:
            return False
        scheme, _, supplied = headers[0].partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            supplied.encode("utf-8"), expected_token
        ):
            raise authentication_required()
        return True

    def session_expiry(cookie: str | None) -> int:
        match = _SESSION.fullmatch(cookie or "")
        if match is None:
            raise authentication_required()
        issued, expires = int(match[1]), int(match[2])
        payload, _, signature = (cookie or "").rpartition(".")
        expected = hmac.digest(session_key, payload.encode(), "sha256").hex()
        if (
            not hmac.compare_digest(signature, expected)
            or match[1] != str(issued)
            or match[2] != str(expires)
            or expires - issued != _SESSION_SECONDS
            or not issued <= time.time() < expires
        ):
            raise authentication_required()
        return expires

    async def authorize(request: Request) -> int | None:
        cookie = session_cookie(request)
        if bootstrap_authorized(request):
            return None
        return session_expiry(cookie)

    @app.exception_handler(sqlite3.Error)
    @app.exception_handler(OSError)
    async def history_unavailable(request: Request, exc: Exception) -> JSONResponse:
        # Database errors can contain paths or stored data. Keep those out of responses.
        return JSONResponse({"detail": "History is temporarily unavailable"}, status_code=503)

    @app.get("/", include_in_schema=False)
    async def index() -> HTMLResponse:
        return dashboard_shell(url_prefix)

    @app.get("/assets/{name}", include_in_schema=False)
    async def asset(name: str) -> FileResponse:
        resource = {
            "app.js": (_ASSETS / "app.js", "text/javascript"),
            "style.css": (_ASSETS / "style.css", "text/css"),
            "favicon.svg": (_ASSETS / "favicon.svg", "image/svg+xml"),
        }.get(name)
        if resource is None:
            raise HTTPException(status_code=404, detail="Not found")
        path, media_type = resource
        return FileResponse(path, media_type=media_type)

    protected = [Depends(authorize)]

    @app.post("/api/session")
    async def create_session(request: Request) -> JSONResponse:
        if not bootstrap_authorized(request):
            raise authentication_required()
        issued = int(time.time())
        expires = issued + _SESSION_SECONDS
        payload = f"v1.{issued}.{expires}.{secrets.token_urlsafe(32)}"
        signature = hmac.digest(session_key, payload.encode(), "sha256").hex()
        response = JSONResponse({"expires_at": expires})
        if cookie_path != "/":
            response.delete_cookie(
                _SESSION_COOKIE,
                path="/",
                secure=request.url.scheme == "https",
                httponly=True,
                samesite="strict",
            )
        response.set_cookie(
            _SESSION_COOKIE,
            f"{payload}.{signature}",
            max_age=_SESSION_SECONDS,
            expires=datetime.fromtimestamp(expires, UTC),
            path=cookie_path,
            secure=request.url.scheme == "https",
            httponly=True,
            samesite="strict",
        )
        return response

    @app.get("/api/session")
    async def current_session(request: Request) -> Any:
        return {"expires_at": await authorize(request)}

    @app.delete("/api/session")
    async def delete_session(request: Request) -> JSONResponse:
        response = JSONResponse({"ok": True})
        response.delete_cookie(
            _SESSION_COOKIE,
            path=cookie_path,
            secure=request.url.scheme == "https",
            httponly=True,
            samesite="strict",
        )
        if cookie_path != "/":
            response.delete_cookie(
                _SESSION_COOKIE,
                path="/",
                secure=request.url.scheme == "https",
                httponly=True,
                samesite="strict",
            )
        return response

    @app.get("/api/summary", dependencies=protected)
    async def summary(days: Annotated[int, Query(ge=1, le=36500)] = 30) -> Any:
        return await run_in_threadpool(reader.summary, days=days)

    @app.get("/api/threads", dependencies=protected)
    async def threads(
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
        traffic: Annotated[Literal["all", "inference"], Query()] = "all",
    ) -> Any:
        return await run_in_threadpool(reader.threads, limit=limit, offset=offset, traffic=traffic)

    @app.get("/api/requests", dependencies=protected)
    async def requests(
        thread_id: Annotated[str | None, Query(max_length=256)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
        traffic: Annotated[Literal["all", "inference"], Query()] = "all",
    ) -> Any:
        return await run_in_threadpool(
            reader.requests, thread_id=thread_id, limit=limit, offset=offset, traffic=traffic
        )

    @app.get("/api/threads/{thread_id}/requests", dependencies=protected)
    async def thread_requests(
        thread_id: Annotated[str, PathParam(max_length=256)],
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
        order: Annotated[Literal["asc", "desc"], Query()] = "asc",
        traffic: Annotated[Literal["all", "inference"], Query()] = "all",
    ) -> Any:
        return await run_in_threadpool(
            reader.thread_requests,
            thread_id=thread_id,
            limit=limit,
            offset=offset,
            order=order,
            traffic=traffic,
        )

    @app.get("/api/requests/{request_id}/location", dependencies=protected)
    async def request_location(
        request_id: str,
        traffic: Annotated[Literal["all", "inference"], Query()] = "all",
    ) -> Any:
        if len(request_id) > 256:
            raise HTTPException(status_code=404, detail="Request not found")
        location = await run_in_threadpool(reader.request_location, request_id, traffic=traffic)
        if location is None:
            raise HTTPException(status_code=404, detail="Request not found")
        return location

    @app.get("/api/requests/{request_id}", dependencies=protected)
    async def request_detail(request_id: str) -> Any:
        if len(request_id) > 256:
            raise HTTPException(status_code=404, detail="Request not found")
        record = await run_in_threadpool(reader.request, request_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Request not found")
        return record

    return app
