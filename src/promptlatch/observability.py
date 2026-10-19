"""Server-only request accounting with redacted, bounded upstream error details."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
from contextlib import suppress
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import uuid4

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from promptlatch.config import Settings
from promptlatch.history import HistoryReader, HistoryStore
from promptlatch.patterns import BUILTIN_PATTERNS
from promptlatch.pricing import PricingCatalog
from promptlatch.redaction import MASK, RedactionStats, SecretRedactor
from promptlatch.request_previews import PREVIEW_FIELDS, extract_request_previews
from promptlatch.response_metrics import ResponseMetrics
from promptlatch.transport_diagnostics import UpstreamDiagnostics
from promptlatch.upstream_errors import bound_error_details

logger = logging.getLogger("promptlatch")
_LOCAL_ROUTES = {"/healthz", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}
_ENDPOINTS = {
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/responses/compact",
    "/v1/messages",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/models",
    "/v1/audio/transcriptions",
    "/v1/audio/speech",
    "/v1/images/generations",
    "/chat/completions",
    "/responses",
    "/responses/compact",
    "/messages",
    "/completions",
    "/embeddings",
    "/models",
    "/backend-api/codex/responses",
    "/backend-api/codex/responses/compact",
}
_PROVIDERS = {
    "api.openai.com": "openai",
    "chatgpt.com": "chatgpt",
    "api.anthropic.com": "anthropic",
    "openrouter.ai": "openrouter",
    "generativelanguage.googleapis.com": "gemini",
    "api.groq.com": "groq",
    "api.deepseek.com": "deepseek",
    "api.mistral.ai": "mistral",
    "api.cohere.com": "cohere",
    "api.x.ai": "xai",
    "api.together.xyz": "together_ai",
    "api.fireworks.ai": "fireworks_ai",
    "api.perplexity.ai": "perplexity",
    "api.cerebras.ai": "cerebras",
    "api.sambanova.ai": "sambanova",
}
_AUTH_HEADERS = (
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-target-api-key",
    "x-target-authorization",
)
_BUILTIN_RULES = {name for name, _ in BUILTIN_PATTERNS} | {"sensitive_field"}
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:+-]{0,255}\Z")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _known_secrets(
    request: Request, settings: Settings, redactor: SecretRedactor
) -> tuple[str, ...]:
    values = {settings.server.api_key, settings.target.api_key}
    for name in _AUTH_HEADERS:
        for value in request.headers.getlist(name):
            values.add(value)
            if name.endswith("authorization") and " " in value:
                values.add(value.split(" ", 1)[1])
    values.update(rule.value for rule in redactor.config.rules if rule.type == "exact")
    return tuple(sorted((value for value in values if value), key=len, reverse=True))


def _remove_known(value: Any, credentials: tuple[str, ...]) -> Any:
    if not credentials:
        return value
    if isinstance(value, str):
        for credential in credentials:
            value = value.replace(credential, MASK)
        return value
    if isinstance(value, list):
        return [_remove_known(item, credentials) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            cleaned_key = _remove_known(key, credentials)
            if cleaned_key in result:
                raise ValueError("history key collision")
            result[cleaned_key] = _remove_known(item, credentials)
        return result
    return value


def _unsupported_costs(payload: dict[str, Any]) -> bool:
    if payload.get("web_search_options") or any(
        modality != "text" for modality in (payload.get("modalities") or [])
    ):
        return True
    tools = payload.get("tools")
    if isinstance(tools, list) and any(
        not isinstance(tool, dict) or tool.get("type") not in {"function", "custom"}
        for tool in tools
    ):
        return True
    messages = payload.get("messages", payload.get("input", []))
    if not isinstance(messages, list):
        return False
    for item in messages:
        if not isinstance(item, dict):
            continue
        content = item.get("content", [item])
        if isinstance(content, list) and any(
            isinstance(part, dict)
            and part.get("type")
            in {
                "image_url",
                "input_image",
                "image",
                "input_audio",
                "audio",
                "video",
                "input_file",
                "file",
                "document",
            }
            for part in content
        ):
            return True
    return False


class Observability:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        config = settings.observability
        self.store = HistoryStore(
            config.database_path,
            config.max_database_bytes,
            config.max_body_bytes,
            config.queue_size,
        )
        self.reader = HistoryReader(config.database_path)
        self.pricing = PricingCatalog(
            config.database_path.with_name(config.database_path.name + ".prices.json"),
            enabled=config.pricing_enabled,
            custom_path=config.pricing_file,
        )
        metadata_config = settings.redaction.model_copy(
            update={"enabled": True, "engine": "basic", "redact_mode": "full", "placeholder": MASK}
        )
        self._metadata_redactor = SecretRedactor(metadata_config)
        self._grouping_key = b""
        self._responses: OrderedDict[str, str] = OrderedDict()
        self._lock = threading.Lock()

    def start(self) -> None:
        self.store.start()
        try:
            path = self.settings.observability.database_path
            key_path = path.with_name(path.name + ".grouping-key")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
            try:
                descriptor = os.open(key_path, flags)
            except FileNotFoundError:
                descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.write(descriptor, secrets.token_bytes(32))
                os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_mode & 0o077
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                ):
                    raise ValueError("history grouping key must be a private regular file")
                self._grouping_key = handle.read(33)
            if len(self._grouping_key) != 32:
                raise ValueError("invalid history grouping key")
            self.pricing.load()
        except BaseException:
            self.store.close()
            raise

    def close(self) -> None:
        self.store.close()

    async def refresh_prices(self) -> None:
        if not self.settings.observability.pricing_enabled:
            return
        await self.reprice_subscriptions()
        while True:
            if await self.pricing.refresh():
                await self.reprice_subscriptions()
            await asyncio.sleep(self.settings.observability.pricing_refresh_hours * 3600)

    async def reprice_subscriptions(self) -> None:
        cursor = None
        while True:
            try:
                page = await asyncio.to_thread(
                    self.reader.subscription_pricing_candidates, 100, before=cursor
                )
            except (sqlite3.Error, OSError, ValueError) as exc:
                logger.warning("Subscription repricing deferred (%s)", type(exc).__name__)
                return
            for record in page["items"]:
                quote = self.pricing.estimate(record.get("model"), "chatgpt", record)
                if quote["cost_usd"] is not None and not self.store.submit_reprice(
                    record["request_id"], quote
                ):
                    return
            cursor = page["next_cursor"]
            if cursor is None:
                return
            await asyncio.sleep(0)

    def digest(self, namespace: str, value: str) -> str:
        return hmac.new(
            self._grouping_key,
            (namespace + "\0" + value).encode("utf-8", "surrogatepass"),
            hashlib.sha256,
        ).hexdigest()

    def model(
        self, value: Any, credentials: tuple[str, ...], redactor: SecretRedactor | None = None
    ) -> str | None:
        if not isinstance(value, str) or not _MODEL_NAME.fullmatch(value):
            return None
        cleaned = _remove_known(
            (redactor or self._metadata_redactor).redact_text(value).value, credentials
        )
        return value if cleaned == value else None

    def remember_response(self, response_hash: str, thread_id: str) -> None:
        with self._lock:
            self._responses[response_hash] = thread_id
            self._responses.move_to_end(response_hash)
            while len(self._responses) > 4096:
                self._responses.popitem(last=False)

    def thread(self, request: Request, payload: dict[str, Any], scope: str) -> tuple[str, str]:
        explicit = request.headers.get("x-promptlatch-thread-id")
        metadata = payload.get("metadata")
        if not explicit and isinstance(metadata, dict):
            explicit = next(
                (
                    metadata.get(key)
                    for key in ("thread_id", "conversation_id", "session_id")
                    if isinstance(metadata.get(key), str) and metadata[key]
                ),
                None,
            )
        if explicit:
            return self.digest("thread:" + scope, explicit), "explicit"
        previous = payload.get("previous_response_id")
        if isinstance(previous, str) and previous:
            response_hash = self.digest("response:" + scope, previous)
            with self._lock:
                thread = self._responses.get(response_hash)
            thread = thread or self.reader.thread_for_response(response_hash)
            if thread:
                return thread, "previous_response"
            return response_hash, "unlinked_response"
        messages = payload.get("messages", payload.get("input"))
        if isinstance(messages, list):
            prefix = []
            for message in messages:
                if not isinstance(message, dict) or message.get("role") not in {
                    "system",
                    "developer",
                    "user",
                }:
                    break
                prefix.append(message)
                if message.get("role") == "user":
                    return self.digest("history:" + scope, _json(prefix)), "inferred_history"
        return uuid4().hex, "request"

    def begin(self, request: Request) -> RequestObservation:
        return RequestObservation(self, request)


class RequestObservation:
    def __init__(self, owner: Observability, request: Request) -> None:
        self.owner = owner
        self.started = time.perf_counter()
        self.metrics = ResponseMetrics(self.started)
        self.upstream_diagnostics: UpstreamDiagnostics | None = None
        self.credentials = _known_secrets(request, owner.settings, owner._metadata_redactor)
        self.metadata_redactor = owner._metadata_redactor
        self.scope = ""
        self.service_tier: str | None = None
        self.unsupported_costs = False
        self.submitted = False
        self.finished = False
        self.observer_failed = False
        path = request.scope["path"].rstrip("/")
        method = (
            request.method
            if request.method in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
            else "OTHER"
        )
        self.record: dict[str, Any] = {
            "request_id": uuid4().hex,
            "thread_id": uuid4().hex,
            "thread_source": "request",
            "started_at": time.time(),
            "completed_at": None,
            "method": method,
            "path": path if path in _ENDPOINTS else "/other",
            "provider": "custom",
            "model": None,
            "stream": False,
            "usage_applicable": False,
            "outcome": "active",
            "status_code": None,
            "redactions": 0,
            "rule_hits": {},
            "request_body": None,
            **dict.fromkeys(PREVIEW_FIELDS),
            "body_truncated": False,
            "body_omitted_reason": "not_captured",
        }

    def prepare(
        self,
        request: Request,
        content: bytes,
        payload: Any,
        stats: RedactionStats,
        redactor: SecretRedactor,
    ) -> None:
        """Called with sanitized content in the existing redaction worker thread."""
        self.credentials = _known_secrets(request, self.owner.settings, redactor)
        if redactor.config.rules != self.owner.settings.redaction.rules:
            self.metadata_redactor = SecretRedactor(
                redactor.config.model_copy(
                    update={
                        "enabled": True,
                        "engine": "basic",
                        "redact_mode": "full",
                        "placeholder": MASK,
                    }
                )
            )
        config = self.owner.settings.observability
        target = (
            request.headers.get("x-target-base-url") or self.owner.settings.target.default_base_url
        )
        self.scope = self.owner.digest(
            "scope",
            _json(
                [
                    target,
                    self.owner.settings.target.api_key,
                    [(name, request.headers.getlist(name)) for name in _AUTH_HEADERS],
                ]
            ),
        )
        self.record["provider"] = _PROVIDERS.get(urlsplit(target).hostname or "", "custom")
        media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        encoded = request.headers.get("content-encoding", "identity").lower() != "identity"
        if (
            payload is None
            and not encoded
            and (media_type == "application/json" or media_type.endswith("+json"))
        ):
            with suppress(ValueError, UnicodeError):
                payload = json.loads(content)
        if isinstance(payload, dict):
            self.record["model"] = self.owner.model(
                payload.get("model"), self.credentials, self.metadata_redactor
            )
            self.record["stream"] = payload.get("stream") is True
            self.record["usage_applicable"] = request.method == "POST" and (
                self.record["model"] is not None
                or "input" in payload
                or "messages" in payload
                or self.record["path"] in _ENDPOINTS - {"/models", "/v1/models"}
            )
            self.record["thread_id"], self.record["thread_source"] = self.owner.thread(
                request, payload, self.scope
            )
            self._iteration_metadata(payload)
            tier = payload.get("service_tier")
            self.service_tier = tier if isinstance(tier, str) else None
            self.unsupported_costs = _unsupported_costs(payload)
        else:
            self.record["thread_id"], self.record["thread_source"] = self.owner.thread(
                request, {}, self.scope
            )
        rules: dict[str, int] = {}
        for name, count in stats.rule_hits.items():
            category = name if name in _BUILTIN_RULES else "custom_rule"
            if name.startswith("detect_secrets:"):
                category = "detector:" + name.partition(":")[2]
                category = _remove_known(category, self.credentials)
            rules[category] = rules.get(category, 0) + count
        self.record.update(redactions=stats.redactions, rule_hits=rules)
        reason = None
        if not config.store_request_bodies or not config.max_body_bytes:
            reason = "disabled"
        elif not redactor.config.enabled:
            reason = "redaction_disabled"
        elif redactor.config.redact_mode != "full":
            reason = "partial_redaction"
        elif encoded:
            reason = "encoded_body"
        elif redactor.config.placeholder != MASK:
            reason = "custom_placeholder"
        else:
            try:
                preview_values: dict[str, str | None] = dict.fromkeys(PREVIEW_FIELDS)
                if payload is not None:
                    sanitized_payload = _remove_known(payload, self.credentials)
                    preview_values = extract_request_previews(sanitized_payload)
                    body = _json(sanitized_payload)
                elif media_type == "application/x-www-form-urlencoded":
                    pairs = parse_qsl(content.decode("utf-8"), keep_blank_values=True)
                    body = urlencode(
                        [
                            (_remove_known(k, self.credentials), _remove_known(v, self.credentials))
                            for k, v in pairs
                        ]
                    )
                elif media_type.startswith("text/"):
                    body = _remove_known(content.decode("utf-8"), self.credentials)
                else:
                    body = None
                    reason = "unsupported_body"
                if body is not None:
                    encoded_body = body.encode("utf-8")
                    bounded = encoded_body[: config.max_body_bytes]
                    self.record["request_body"] = bounded.decode("utf-8", errors="ignore")
                    self.record["body_truncated"] = len(bounded) < len(encoded_body)
                    self.record.update(preview_values)
            except (ValueError, UnicodeError):
                self.record.update(dict.fromkeys(PREVIEW_FIELDS))
                reason = "capture_failed"
        self.record["body_omitted_reason"] = reason
        self.submitted = self.owner.store.submit_start(self.record)

    def _iteration_metadata(self, payload: dict[str, Any]) -> None:
        previous = payload.get("previous_response_id")
        if isinstance(previous, str) and previous:
            self.record["parent_response_id_hash"] = self.owner.digest(
                "response:" + self.scope, previous
            )
        messages = payload.get("messages", payload.get("input"))
        if not isinstance(messages, list):
            return
        self.record["message_count"] = len(messages)
        # Incremental Responses input does not expose the session's turn number.
        if previous:
            return
        user_turn = 0
        last_user = None
        for message in messages:
            if isinstance(message, dict) and message.get("role") == "user":
                content = message.get("content")
                if (
                    isinstance(content, list)
                    and content
                    and all(
                        isinstance(part, dict) and part.get("type") == "tool_result"
                        for part in content
                    )
                ):
                    continue
                user_turn += 1
                last_user = message
        if last_user is not None:
            self.record.update(
                user_turn=user_turn,
                turn_source="inferred",
                turn_id=self.owner.digest(
                    "turn:" + self.record["thread_id"], _json([user_turn, last_user])
                ),
            )

    def upstream_request(self, body_bytes: int) -> None:
        self.upstream_diagnostics = UpstreamDiagnostics(body_bytes)

    async def trace(self, name: str, info: dict[str, Any]) -> None:
        if self.observer_failed or self.upstream_diagnostics is None:
            return
        try:
            await self.upstream_diagnostics.trace(name, info)
        except Exception:
            self.upstream_diagnostics = None

    def response_headers(self, headers: Any, status_code: int) -> None:
        if self.observer_failed:
            return
        try:
            if self.upstream_diagnostics is not None:
                self.upstream_diagnostics.response_headers(headers, status_code)
            self.metrics.response_headers(headers, status_code)
        except Exception:
            self.observer_failed = True

    def transport_error(self, error: Exception) -> None:
        if self.observer_failed:
            return
        try:
            if self.upstream_diagnostics is not None:
                self.upstream_diagnostics.transport_error(error)
            self.metrics.transport_error(type(error).__name__)
        except Exception:
            self.observer_failed = True

    def observe(self, body: bytes, *, streaming: bool, decoded: bool) -> None:
        del streaming  # Observation follows the actual bytes, not an unreliable content type.
        if self.observer_failed:
            return
        try:
            if self.upstream_diagnostics is not None:
                self.upstream_diagnostics.observe(len(body))
            self.metrics.feed_response(body, decoded=decoded)
        except Exception:
            # Observability cannot turn a valid upstream response into a proxy failure.
            self.observer_failed = True

    def finish(self, status_code: int, outcome: str) -> None:
        if self.finished:
            return
        self.finished = True
        if not self.submitted:
            self.submitted = self.owner.store.submit_start(self.record)
        if not self.submitted:
            self._discard_preview_memory()
            return
        self.metrics.finish_response(complete=outcome in {"success", "http_error"})
        fields = self.metrics.snapshot()
        fields["upstream_error"] = self._upstream_error()
        self.record["stream"] = fields["response_format"] == "sse"
        if self.observer_failed:
            fields["metrics_incomplete"] = True
            fields["metrics_unavailable_reason"] = "observer_error"
        if not self.record["usage_applicable"]:
            fields.update(
                dict.fromkeys(
                    (
                        "input_tokens",
                        "output_tokens",
                        "total_tokens",
                        "cached_input_tokens",
                        "cache_write_tokens",
                        "reasoning_tokens",
                        "usage_source",
                        "ttft_ms",
                        "generation_ms",
                        "tps",
                        "cost_usd",
                        "cost_source",
                    )
                ),
                metrics_incomplete=False,
                metrics_unavailable_reason="not_applicable",
                cost_unavailable_reason="not_applicable",
            )
        model = self.owner.model(
            fields.pop("model", None), self.credentials, self.metadata_redactor
        )
        response_id = fields.pop("response_id", None)
        if (
            self.record["usage_applicable"]
            and isinstance(response_id, str)
            and len(response_id) <= 1024
        ):
            response_hash = self.owner.digest("response:" + self.scope, response_id)
            self.owner.remember_response(response_hash, self.record["thread_id"])
            fields["response_id_hash"] = response_hash
        override = fields.pop("outcome_override", None)
        if outcome == "success" and (override or self.observer_failed):
            outcome = "stream_error" if override == "stream_error" else "interrupted"
        tier = fields.pop("service_tier", None) or self.service_tier
        fields["unsupported_costs"] = (
            fields.get("unsupported_costs", False)
            or self.unsupported_costs
            or fields.get("metrics_incomplete", False)
        )
        if self.record["usage_applicable"] and fields.get("cost_usd") is None:
            fields.update(
                self.owner.pricing.estimate(
                    model or self.record["model"],
                    self.record["provider"],
                    fields,
                    service_tier=tier,
                )
            )
        fields.update(
            model=model or self.record["model"],
            status_code=status_code,
            outcome=outcome,
            stream=self.record["stream"],
            completed_at=time.time(),
            duration_ms=(time.perf_counter() - self.started) * 1000,
        )
        self.owner.store.submit_finish(self.record["request_id"], fields)
        self._discard_preview_memory()

    def _upstream_error(self) -> dict[str, str] | None:
        details = self.metrics.take_error_details()
        config = self.owner.settings.observability
        if not details or not config.store_request_bodies or not config.max_body_bytes:
            return None
        try:
            if self.upstream_diagnostics is not None:
                context = self.upstream_diagnostics.details()
                if details.get("event") != "transport":
                    context = {
                        key: value
                        for key, value in context.items()
                        if key in {"upstream_request_id", "upstream_cf_ray"}
                    }
                details.update(context)
            redactor = SecretRedactor(
                self.metadata_redactor.config.model_copy(
                    update={"engine": self.owner.settings.redaction.engine}
                ),
                _cache_from=self.metadata_redactor,
            )
            cleaned = {
                key: _remove_known(
                    redactor.redact_text(_remove_known(value, self.credentials)).value,
                    self.credentials,
                )
                for key, value in details.items()
            }
            return bound_error_details(cleaned)
        except Exception:
            return {"message": "Upstream error details unavailable: redaction failed."}

    def _discard_preview_memory(self) -> None:
        self.credentials = ()
        self.record["request_body"] = None
        self.record.update(dict.fromkeys(PREVIEW_FIELDS))


class ObservabilityMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        owner = getattr(scope.get("app", None), "state", None)
        owner = getattr(owner, "observability", None)
        path = scope.get("path", "")
        dashboard_request = (
            path == "/_promptlatch"
            or path.startswith("/_promptlatch/")
            or (
                owner is not None
                and owner.settings.observability.dashboard_enabled
                and path == "/"
                and scope.get("method") == "GET"
            )
        )
        if (
            scope["type"] != "http"
            or scope.get("path") in _LOCAL_ROUTES
            or owner is None
            or dashboard_request
        ):
            await self.app(scope, receive, send)
            return
        observation = owner.begin(Request(scope))
        scope.setdefault("state", {})["observation"] = observation
        status_code = 500
        complete = False
        outcome = "transport_error"

        async def observed_send(message: Message) -> None:
            nonlocal status_code, complete
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                complete = True

        try:
            await self.app(scope, receive, observed_send)
            outcome = "success" if status_code < 400 else "http_error"
            if not complete:
                outcome = "cancelled"
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        finally:
            try:
                observation.finish(status_code, outcome)
            except Exception as exc:
                logger.warning("history observation failed (%s)", type(exc).__name__)
