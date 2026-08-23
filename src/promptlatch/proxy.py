from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import posixpath
import secrets
import socket
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from copy import deepcopy
from typing import Any
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from promptlatch.audit import AuditLogger
from promptlatch.compat import (
    ResponsesInputError,
    chat_response_to_responses,
    chat_stream_to_responses,
    responses_to_chat_payload,
)
from promptlatch.config import RuleConfig, Settings, expand_env_values, get_settings
from promptlatch.patterns import SENSITIVE_FIELD_RE
from promptlatch.redaction import RedactionKeyCollisionError, RedactionStats, SecretRedactor
from promptlatch.version import __version__

logger = logging.getLogger("promptlatch")

DROP_REQUEST_HEADERS = {
    "content-length",
    "cookie",
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
DROP_RESPONSE_HEADERS = {
    "content-length",
    "cookie",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "set-cookie",
    "te",
    "trailer",
    "upgrade",
}
DROP_TRANSFORMED_RESPONSE_HEADERS = {
    "content-digest",
    "content-encoding",
    "content-md5",
    "digest",
    "etag",
    "repr-digest",
}
SENSITIVE_DEBUG_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-target-api-key",
    "x-target-authorization",
}
CLIENT_AUTH_HEADERS = {"authorization", "x-api-key", "x-auth-token"}


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    expanded = Settings.model_validate(expand_env_values(resolved.model_dump()))

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        timeout = httpx.Timeout(expanded.target.timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout) as client:
            _app.state.client = client
            yield

    app = FastAPI(
        title="PromptLatch",
        version=__version__,
        summary="Local OpenAI-compatible proxy that redacts secrets before forwarding requests.",
        lifespan=lifespan,
    )
    app.state.settings = expanded
    app.state.redactor = SecretRedactor(expanded.redaction)
    app.state.audit = AuditLogger(expanded.audit)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {
            "ok": True,
            "redaction": expanded.redaction.enabled,
            "engine": expanded.redaction.engine,
            "telemetry": False,
        }

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def forward(path: str, request: Request) -> Response:
        return await forward_request(request, "/" + path)

    return app


async def forward_request(request: Request, path: str) -> Response:
    settings: Settings = request.app.state.settings
    _check_proxy_auth(request, settings)
    target_url = _target_url(request, path, settings)
    await _validate_target(target_url, settings)

    body = await _read_request_body(request, settings.server.max_request_body_bytes)
    redactor = _redactor_for_request(request, settings)
    audit: AuditLogger = request.app.state.audit
    query_params, query_stats = _redact_query_params(request, redactor)
    audit.redaction(f"query:{path}", query_stats)
    compat_responses_to_chat = _should_bridge_responses_to_chat(request, path, settings)
    content, body_stats, json_payload = _redact_request_body(
        request, body, redactor, parse_json=compat_responses_to_chat
    )
    audit.redaction(path, body_stats)
    stats = query_stats
    stats.merge(body_stats)

    if compat_responses_to_chat:
        if not isinstance(json_payload, dict):
            raise HTTPException(
                status_code=400, detail="responses-to-chat bridge requires JSON body"
            )
        target_url = _target_url(request, "/v1/chat/completions", settings)
        await _validate_target(target_url, settings)
        try:
            chat_payload = responses_to_chat_payload(json_payload)
        except ResponsesInputError:
            _debug_request(request, path, target_url, body, content, stats, settings)
            raise HTTPException(status_code=400, detail="invalid Responses input item") from None
        content = json.dumps(chat_payload, separators=(",", ":")).encode("utf-8")

    _debug_request(request, path, target_url, body, content, stats, settings)

    headers = _forward_headers(request, settings)
    client, close_client = _client_for_request(request, settings)

    try:
        upstream_request = client.build_request(
            request.method,
            target_url,
            content=content,
            headers=headers,
            params=httpx.QueryParams(tuple(query_params)),
        )
        upstream = await client.send(upstream_request, stream=True)
    except httpx.RequestError as exc:
        if close_client:
            await client.aclose()
        raise HTTPException(status_code=502, detail=f"upstream request failed: {exc}") from exc

    if _is_streaming(upstream.headers):
        transform_stream = compat_responses_to_chat and upstream.is_success
        response_headers = _response_headers(upstream.headers, transformed=transform_stream)
        stream = _stream_upstream(upstream, close_client, client, decoded=transform_stream)
        if transform_stream:
            stream = chat_stream_to_responses(stream)
            response_headers["content-type"] = "text/event-stream; charset=utf-8"
        return StreamingResponse(
            stream,
            status_code=upstream.status_code,
            headers=response_headers,
            media_type=response_headers.get("content-type"),
        )

    transform_response = compat_responses_to_chat and upstream.is_success
    response_headers = _response_headers(upstream.headers, transformed=transform_response)
    upstream_content = (
        await upstream.aread() if transform_response else await _read_raw_upstream(upstream)
    )
    await upstream.aclose()
    if close_client:
        await client.aclose()

    upstream_payload: Any | None = None
    if transform_response and _is_json_content(upstream.headers):
        try:
            upstream_payload = json.loads(upstream_content)
        except ValueError:
            upstream_payload = None

    if transform_response and isinstance(upstream_payload, dict):
        response_payload = chat_response_to_responses(upstream_payload)
        return JSONResponse(
            response_payload,
            status_code=upstream.status_code,
            headers=response_headers,
        )

    return Response(
        content=upstream_content,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=upstream.headers.get("content-type"),
    )


def _redactor_for_request(request: Request, settings: Settings) -> SecretRedactor:
    raw_rules = request.headers.get("x-redact-extra-rules")
    if not raw_rules:
        return request.app.state.redactor
    redaction = settings.redaction
    if len(raw_rules.encode("utf-8")) > redaction.max_extra_rules_header_bytes:
        raise HTTPException(status_code=400, detail="X-Redact-Extra-Rules header too large")
    try:
        parsed = json.loads(raw_rules)
        if not isinstance(parsed, list) or len(parsed) > redaction.max_extra_rules:
            raise ValueError
        rules = [RuleConfig.model_validate(rule) for rule in parsed]
        if any(len(rule.value) > redaction.max_extra_rule_chars for rule in rules):
            raise ValueError
        if not redaction.allow_extra_regex_rules and any(rule.type == "regex" for rule in rules):
            raise ValueError
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid X-Redact-Extra-Rules header") from None
    request_redaction = deepcopy(redaction)
    request_redaction.rules.extend(rules)
    return SecretRedactor(request_redaction)


async def _read_request_body(request: Request, limit: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            parsed_length = int(content_length)
            if parsed_length < 0:
                raise ValueError
            if parsed_length > limit:
                raise HTTPException(status_code=413, detail="request body too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length header") from None

    chunks = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail="request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _redact_request_body(
    request: Request,
    body: bytes,
    redactor: SecretRedactor,
    *,
    parse_json: bool = False,
) -> tuple[bytes, RedactionStats, Any | None]:
    stats = RedactionStats()
    if not body:
        return body, stats, None

    encoded = request.headers.get("content-encoding", "identity").strip().lower() != "identity"
    if encoded:
        if redactor.config.enabled:
            raise HTTPException(status_code=415, detail="encoded request bodies are not supported")
        return body, stats, None

    if not redactor.config.enabled:
        if parse_json and _is_json_request(request):
            try:
                return body, stats, json.loads(body)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="invalid JSON request body") from None
        return body, stats, None

    if _is_json_request(request):
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="invalid JSON request body") from None
        try:
            result = redactor.redact_payload(payload)
        except RedactionKeyCollisionError:
            raise HTTPException(
                status_code=400,
                detail="request contains colliding keys after redaction",
            ) from None
        return (
            json.dumps(result.value, separators=(",", ":")).encode("utf-8"),
            result.stats,
            result.value,
        )

    result = redactor.redact_text(body.decode("utf-8", errors="surrogateescape"))
    return result.value.encode("utf-8", errors="surrogateescape"), result.stats, None


def _redact_query_params(
    request: Request, redactor: SecretRedactor
) -> tuple[list[tuple[str, str]], RedactionStats]:
    redacted: list[tuple[str, str]] = []
    stats = RedactionStats()
    for key, value in request.query_params.multi_items():
        result = redactor.redact_payload({key: value})
        stats.merge(result.stats)
        redacted.append(next(iter(result.value.items())))
    return redacted, stats


def _client_for_request(request: Request, settings: Settings) -> tuple[httpx.AsyncClient, bool]:
    client = getattr(request.app.state, "client", None)
    if client is not None:
        return client, False
    timeout = httpx.Timeout(settings.target.timeout_seconds)
    return httpx.AsyncClient(timeout=timeout), True


def _check_proxy_auth(request: Request, settings: Settings) -> None:
    api_key = settings.server.api_key
    if not api_key:
        return
    auth = request.headers.get("authorization", "")
    if not secrets.compare_digest(auth, f"Bearer {api_key}"):
        raise HTTPException(status_code=401, detail="invalid PromptLatch API key")


def _should_bridge_responses_to_chat(request: Request, path: str, settings: Settings) -> bool:
    return (
        settings.compat.responses_to_chat
        and request.method == "POST"
        and path.rstrip("/") == "/v1/responses"
    )


def _target_url(request: Request, path: str, settings: Settings) -> str:
    base_url = request.headers.get("x-target-base-url") or settings.target.default_base_url
    base = base_url.rstrip("/")
    incoming = path if path.startswith("/") else f"/{path}"
    try:
        base_parts = urlsplit(base)
        _ = base_parts.hostname
        _ = base_parts.port
    except (UnicodeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid target URL") from None
    base_path = base_parts.path.rstrip("/")
    if base_path and (incoming == base_path or incoming.startswith(base_path + "/")):
        final_path = incoming
    elif base_path:
        base_tail = "/" + base_path.rsplit("/", 1)[-1]
        if incoming == base_tail or incoming.startswith(base_tail + "/"):
            final_path = base_path + incoming[len(base_tail) :]
        else:
            final_path = f"{base_path}{incoming}"
    else:
        final_path = incoming
    return urlunsplit((base_parts.scheme, base_parts.netloc, final_path, "", ""))


async def _validate_target(target_url: str, settings: Settings) -> None:
    try:
        parsed = urlsplit(target_url)
        hostname = parsed.hostname
        _ = parsed.port
    except (UnicodeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid target URL") from None
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise HTTPException(status_code=400, detail="invalid target URL")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="target URL userinfo not allowed")
    allowed = settings.target.allowed_base_urls
    if allowed and not any(_target_matches_allowed_url(target_url, url) for url in allowed):
        raise HTTPException(status_code=403, detail="target URL not allowed")
    if settings.target.block_private_targets:
        try:
            private = await asyncio.to_thread(_is_private_host, hostname)
        except (OSError, UnicodeError):
            raise HTTPException(
                status_code=400, detail="target host could not be resolved"
            ) from None
        if private:
            raise HTTPException(status_code=403, detail="private target URL blocked")


def _target_matches_allowed_url(target_url: str, allowed_url: str) -> bool:
    target = urlsplit(target_url)
    allowed = urlsplit(allowed_url)
    if (
        target.scheme.lower() != allowed.scheme.lower()
        or target.hostname != allowed.hostname
        or _effective_port(target) != _effective_port(allowed)
    ):
        return False
    target_path = _normalized_url_path(target.path)
    allowed_path = _normalized_url_path(allowed.path).rstrip("/")
    return (
        not allowed_path
        or target_path == allowed_path
        or target_path.startswith(allowed_path + "/")
    )


def _effective_port(parsed: SplitResult) -> int | None:
    if parsed.port:
        return parsed.port
    return {"http": 80, "https": 443}.get(parsed.scheme.lower())


def _normalized_url_path(path: str) -> str:
    return posixpath.normpath("/" + unquote(path).lstrip("/"))


def _is_private_host(host: str) -> bool:
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        addresses = socket.getaddrinfo(host, None)
        ips = [ipaddress.ip_address(address[4][0]) for address in addresses]
    return not ips or any(not ip.is_global for ip in ips)


def _forward_headers(request: Request, settings: Settings) -> dict[str, str]:
    target_api_key = request.headers.get("x-target-api-key")
    target_authorization = request.headers.get("x-target-authorization")
    configured_api_key = (
        settings.target.api_key if _uses_configured_target(request, settings) else None
    )
    target_api_key_header = (
        request.headers.get("x-target-api-key-header") or settings.target.api_key_header
    ).lower()
    if target_api_key_header not in {"authorization", "x-api-key"}:
        raise HTTPException(status_code=400, detail="invalid X-Target-API-Key-Header header")
    headers: dict[str, str] = {}
    dropped = DROP_REQUEST_HEADERS | _connection_header_names(request.headers)
    for key, value in request.headers.items():
        lowered = key.lower()
        if lowered in dropped:
            continue
        if lowered in {
            "x-target-base-url",
            "x-target-api-key",
            "x-target-api-key-header",
            "x-target-authorization",
        }:
            continue
        if lowered in CLIENT_AUTH_HEADERS:
            has_target_auth = configured_api_key or target_api_key or target_authorization
            if (
                settings.server.api_key
                or has_target_auth
                or not settings.target.forward_client_authorization
            ):
                continue
        elif SENSITIVE_FIELD_RE.search(lowered):
            continue
        if lowered.startswith("x-redact-"):
            continue
        headers[key] = value
    headers["accept-encoding"] = request.headers.get("accept-encoding", "identity")
    if target_api_key:
        _set_target_api_key(headers, target_api_key, target_api_key_header)
    elif target_authorization:
        headers["authorization"] = target_authorization
    elif configured_api_key:
        _set_target_api_key(headers, configured_api_key, target_api_key_header)
    return headers


def _uses_configured_target(request: Request, settings: Settings) -> bool:
    override = request.headers.get("x-target-base-url")
    return not override or override.rstrip("/") == settings.target.default_base_url.rstrip("/")


def _set_target_api_key(headers: dict[str, str], api_key: str, header: str) -> None:
    if header == "x-api-key":
        headers["x-api-key"] = api_key
        return
    headers["authorization"] = f"Bearer {api_key}"


def _debug_request(
    request: Request,
    path: str,
    target_url: str,
    raw_body: bytes,
    redacted_body: bytes,
    stats: RedactionStats,
    settings: Settings,
) -> None:
    if not settings.server.debug_requests:
        return
    max_chars = settings.server.debug_max_body_chars
    logger.warning(
        json.dumps(
            {
                "event": "debug_request",
                "method": request.method,
                "path": path,
                "target_url": target_url,
                "headers": _debug_headers(request),
                "redactions": stats.redactions,
                "rules": stats.rule_hits,
                "raw_body": _debug_body(raw_body, max_chars),
                "raw_body_truncated": len(raw_body.decode("utf-8", errors="replace")) > max_chars,
                "redacted_body": _debug_body(redacted_body, max_chars),
                "redacted_body_truncated": len(redacted_body.decode("utf-8", errors="replace"))
                > max_chars,
            },
            sort_keys=True,
        )
    )


def _debug_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        lowered = key.lower()
        if (
            lowered in SENSITIVE_DEBUG_HEADERS
            or lowered.startswith("x-redact-")
            or SENSITIVE_FIELD_RE.search(lowered)
        ):
            headers[key] = "[REDACTED_HEADER]"
        else:
            headers[key] = value
    return headers


def _debug_body(body: bytes, max_chars: int) -> str:
    text = body.decode("utf-8", errors="replace")
    if len(text) <= max_chars:
        return text
    return text[:max_chars]


def _is_json_request(request: Request) -> bool:
    return _is_json_content(request.headers)


def _is_json_content(headers: Mapping[str, str]) -> bool:
    media_type = headers.get("content-type", "").partition(";")[0].strip().lower()
    return media_type == "application/json" or media_type.endswith("+json")


def _is_streaming(headers: httpx.Headers) -> bool:
    return "text/event-stream" in headers.get("content-type", "").lower()


async def _stream_upstream(
    upstream: httpx.Response,
    close_client: bool,
    client: httpx.AsyncClient,
    *,
    decoded: bool,
) -> AsyncIterator[bytes]:
    try:
        iterator = upstream.aiter_bytes() if decoded else upstream.aiter_raw()
        async for chunk in iterator:
            yield chunk
    finally:
        await upstream.aclose()
        if close_client:
            await client.aclose()


async def _read_raw_upstream(upstream: httpx.Response) -> bytes:
    return b"".join([chunk async for chunk in upstream.aiter_raw()])


def _response_headers(headers: httpx.Headers, *, transformed: bool) -> dict[str, str]:
    dropped = (
        DROP_RESPONSE_HEADERS
        | _connection_header_names(headers)
        | (DROP_TRANSFORMED_RESPONSE_HEADERS if transformed else set())
    )
    return {key: value for key, value in headers.items() if key.lower() not in dropped}


def _connection_header_names(headers: Mapping[str, str]) -> set[str]:
    return {
        name.strip().lower() for name in headers.get("connection", "").split(",") if name.strip()
    }
