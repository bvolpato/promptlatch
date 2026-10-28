"""Offline, conservative token-cost estimates from LiteLLM's public catalog."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, TypeGuard

import httpx

from promptlatch.security import write_private_text

CATALOG_URL = (
    "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
)
MAX_CATALOG_BYTES = 16 * 1024 * 1024
_BUNDLED_CATALOG_VERSION = "1.105.0"
_BASE_RATES = frozenset(
    {
        "input_cost_per_token",
        "output_cost_per_token",
        "cache_read_input_token_cost",
        "cache_creation_input_token_cost",
    }
)
_CONTEXT_TIER = re.compile(r"_above_(\d{1,9})(k|m)?_tokens$")
_SEARCH_MODEL = re.compile(r"(?:^|[-/])(?:search|deep-research|perplexity)(?:$|[-/])")
_OPTIONAL_TOOL_RATES = frozenset(
    {
        "code_interpreter_cost_per_session",
        "computer_use_input_cost_per_1k_tokens",
        "computer_use_output_cost_per_1k_tokens",
        "file_search_cost_per_1k_calls",
        "file_search_cost_per_gb_per_day",
        "search_context_cost_per_query",
        "vector_store_cost_per_gb_per_day",
    }
)
_PROVIDERS = {
    "openai": frozenset({"openai", "text-completion-openai"}),
    "anthropic": frozenset({"anthropic"}),
    "openrouter": frozenset({"openrouter"}),
    "gemini": frozenset({"gemini"}),
    "google": frozenset({"gemini"}),
    "groq": frozenset({"groq"}),
    "deepseek": frozenset({"deepseek"}),
    "mistral": frozenset({"mistral"}),
    "cohere": frozenset({"cohere", "cohere_chat"}),
    "xai": frozenset({"xai"}),
    "together_ai": frozenset({"together_ai"}),
    "fireworks_ai": frozenset({"fireworks_ai"}),
    "perplexity": frozenset({"perplexity"}),
    "cerebras": frozenset({"cerebras"}),
    "sambanova": frozenset({"sambanova"}),
}
# ChatGPT subscriptions use equivalent OpenAI API prices, not subscription charges.
_API_PRICING_PROVIDERS = {"chatgpt": "openai"}


@dataclass(frozen=True)
class _Catalog:
    models: dict[str, dict[str, Any]]
    retrieved_at: str | None
    sha256: str
    package_version: str | None = None


def _number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= value <= sys.float_info.max
    )


def _tokens(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1


def _valid_rate_metadata(key: str, value: Any) -> bool:
    if _number(value):
        return True
    return (
        key in _OPTIONAL_TOOL_RATES
        and isinstance(value, dict)
        and all(_number(rate) for rate in value.values())
    )


def _parse_catalog(
    payload: bytes, retrieved_at: str | None, *, package_version: str | None = None
) -> _Catalog:
    raw = json.loads(payload)
    if not isinstance(raw, dict):
        raise ValueError("pricing catalog must be an object")
    models = {}
    for model, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        if not all(
            _number(entry.get(key)) for key in ("input_cost_per_token", "output_cost_per_token")
        ):
            continue
        if any(
            not _valid_rate_metadata(key, value)
            for key, value in entry.items()
            if "cost" in key and value is not None
        ):
            continue
        models[model] = entry
    if not models:
        raise ValueError("pricing catalog has no valid token rates")
    return _Catalog(models, retrieved_at, hashlib.sha256(payload).hexdigest(), package_version)


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        payload = handle.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("pricing catalog exceeds size limit")
    return payload


def _packaged_catalog() -> _Catalog | None:
    try:
        snapshot = files("promptlatch").joinpath(
            "pricing_assets", f"litellm-{_BUNDLED_CATALOG_VERSION}.json.gz"
        )
        with snapshot.open("rb") as compressed, gzip.GzipFile(fileobj=compressed) as handle:
            payload = handle.read(MAX_CATALOG_BYTES + 1)
        if len(payload) > MAX_CATALOG_BYTES:
            raise ValueError("pricing catalog exceeds size limit")
        return _parse_catalog(payload, None, package_version=_BUNDLED_CATALOG_VERSION)
    except (OSError, EOFError, ValueError, TypeError, RecursionError):
        return None


def _has_unhandled_rates(
    entry: dict[str, Any], input_tokens: int, cache_read: int, cache_write: int
) -> bool:
    for key, value in entry.items():
        if "cost" not in key or key in _BASE_RATES or key in _OPTIONAL_TOOL_RATES or not value:
            continue
        if key == "input_cost_per_token_cache_hit" and value == entry.get(
            "cache_read_input_token_cost"
        ):
            continue
        for suffix in ("_batches", "_flex", "_priority", "_ultrafast"):
            if key.endswith(suffix):
                rate_key = key[: -len(suffix)]
                if _CONTEXT_TIER.sub("", rate_key) in _BASE_RATES:
                    break
        else:
            tier = _CONTEXT_TIER.search(key)
            if tier and key[: tier.start()] in _BASE_RATES:
                if key.startswith("cache_read") and not cache_read:
                    continue
                if key.startswith("cache_creation") and not cache_write:
                    continue
                scale = {None: 1, "k": 1000, "m": 1_000_000}[tier[2]]
                if input_tokens <= int(tier[1]) * scale:
                    continue
            if key == "cache_creation_input_token_cost_above_1hr" and not cache_write:
                continue
            return True
    return False


class PricingCatalog:
    """Keep catalog refresh outside requests; never guess provider aliases or usage.

    Usage input_tokens must include cached and cache-write tokens. In particular,
    Anthropic's separate input counters must be added before calling estimate().
    Callers must flag media or hosted tool usage with unsupported_costs=True.
    """

    def __init__(
        self, cache_path: Path, *, enabled: bool = True, custom_path: Path | None = None
    ) -> None:
        self.cache_path = cache_path
        self.enabled = enabled
        self.custom_path = custom_path
        self._catalog: _Catalog | None = None
        self._custom: _Catalog | None = None
        self._refresh_lock = asyncio.Lock()

    def load(self) -> None:
        if not self.enabled:
            return
        try:
            envelope = json.loads(_read_bounded(self.cache_path, MAX_CATALOG_BYTES * 2 + 4096))
            retrieved_at = envelope["retrieved_at"]
            if datetime.fromisoformat(retrieved_at).tzinfo is None:
                raise ValueError("pricing retrieval time must include timezone")
            payload = envelope["payload"].encode("utf-8")
            if len(payload) > MAX_CATALOG_BYTES:
                raise ValueError("pricing catalog exceeds size limit")
            catalog = _parse_catalog(payload, retrieved_at)
            if catalog.sha256 != envelope["sha256"]:
                raise ValueError("pricing catalog checksum mismatch")
            self._catalog = catalog
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            pass
        if self._catalog is None:
            self._catalog = _packaged_catalog()
        if self.custom_path is not None:
            try:
                payload = _read_bounded(self.custom_path, MAX_CATALOG_BYTES)
                modified_at = datetime.fromtimestamp(
                    self.custom_path.stat().st_mtime, UTC
                ).isoformat()
                self._custom = _parse_catalog(payload, modified_at)
            except (OSError, ValueError, TypeError, RecursionError):
                pass

    async def refresh(self) -> bool:
        """Fetch only public pricing; retain last good snapshot on any failure."""
        if not self.enabled:
            return False
        async with self._refresh_lock:
            try:
                async with (
                    asyncio.timeout(20),
                    httpx.AsyncClient(
                        timeout=10, follow_redirects=False, trust_env=False
                    ) as client,
                    client.stream("GET", CATALOG_URL) as response,
                ):
                    response.raise_for_status()
                    payload = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                        payload.extend(chunk)
                        if len(payload) > MAX_CATALOG_BYTES:
                            raise ValueError("pricing catalog exceeds size limit")
                retrieved_at = datetime.now(UTC).isoformat()
                catalog = _parse_catalog(bytes(payload), retrieved_at)
                envelope = json.dumps(
                    {
                        "retrieved_at": retrieved_at,
                        "sha256": catalog.sha256,
                        "payload": payload.decode("utf-8"),
                    },
                    ensure_ascii=False,
                )
                await asyncio.to_thread(self._persist, envelope)
                self._catalog = catalog
                return True
            except (httpx.HTTPError, TimeoutError, OSError, ValueError, TypeError, RecursionError):
                return False

    def _persist(self, envelope: str) -> None:
        self.cache_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_private_text(self.cache_path, envelope)

    def _lookup(self, model: str, provider: str) -> tuple[_Catalog, str, dict[str, Any]] | None:
        if self._custom is not None and model in self._custom.models:
            return self._custom, model, self._custom.models[model]
        provider = _API_PRICING_PROVIDERS.get(provider, provider)
        allowed = _PROVIDERS.get(provider)
        if self._catalog is None or allowed is None:
            return None
        for candidate in (f"{provider}/{model}", model):
            entry = self._catalog.models.get(candidate)
            if entry is not None and entry.get("litellm_provider") in allowed:
                return self._catalog, candidate, entry
        return None

    def estimate(
        self,
        model: str | None,
        provider: str,
        usage: dict,
        *,
        service_tier: str | None = None,
    ) -> dict:
        result: dict[str, Any] = {
            "cost_usd": None,
            "cost_source": None,
            "pricing_as_of": None,
            "pricing_model": None,
            "pricing_rates": None,
            "cost_unavailable_reason": None,
        }
        if not self.enabled:
            result["cost_unavailable_reason"] = "pricing_disabled"
            return result
        if not model:
            result["cost_unavailable_reason"] = "model_missing"
            return result
        if not _tokens(usage.get("input_tokens")) or not _tokens(usage.get("output_tokens")):
            result["cost_unavailable_reason"] = "usage_incomplete"
            return result
        if service_tier not in (None, "default", "standard"):
            result["cost_unavailable_reason"] = "unsupported_service_tier"
            return result
        if usage.get("unsupported_costs", False):
            result["cost_unavailable_reason"] = "unsupported_costs"
            return result
        match = self._lookup(model, provider)
        if match is None:
            if self._catalog is None:
                result["cost_unavailable_reason"] = "catalog_unavailable"
            elif _API_PRICING_PROVIDERS.get(provider, provider) not in _PROVIDERS:
                result["cost_unavailable_reason"] = "provider_unmapped"
            else:
                result["cost_unavailable_reason"] = "model_unpriced"
            return result
        catalog, pricing_model, entry = match
        result["cost_unavailable_reason"] = "unsupported_rates"
        if (
            provider == "perplexity"
            or entry.get("litellm_provider") == "perplexity"
            or entry.get("mode") == "search"
            or _SEARCH_MODEL.search(pricing_model.lower())
        ):
            return result
        input_tokens, output_tokens = usage.get("input_tokens"), usage.get("output_tokens")
        if not _tokens(input_tokens) or not _tokens(output_tokens):
            return result
        input_rate = float(entry["input_cost_per_token"])
        output_rate = float(entry["output_cost_per_token"])
        cache_read, cache_write = usage.get("cached_input_tokens"), usage.get("cache_write_tokens")
        read_rate = entry.get("cache_read_input_token_cost")
        write_rate = entry.get("cache_creation_input_token_cost")
        if cache_read is None and read_rate in (None, input_rate):
            cache_read = 0
        if cache_write is None and write_rate in (None, input_rate):
            cache_write = 0
        if not _tokens(cache_read) or not _tokens(cache_write):
            return result
        if cache_read + cache_write > input_tokens:
            return result
        if (cache_read and read_rate is None) or (cache_write and write_rate is None):
            return result
        if _has_unhandled_rates(entry, input_tokens, cache_read, cache_write):
            return result
        cost = (
            (input_tokens - cache_read - cache_write) * input_rate
            + output_tokens * output_rate
            + cache_read * float(read_rate or 0)
            + cache_write * float(write_rate or 0)
        )
        if not math.isfinite(cost):
            return result
        result.update(
            cost_usd=cost,
            cost_source=(
                "custom_api_equivalent"
                if provider == "chatgpt" and catalog is self._custom
                else "litellm_api_equivalent"
                if provider == "chatgpt"
                else "litellm_estimate"
            ),
            cost_unavailable_reason=None,
            pricing_as_of=catalog.retrieved_at,
            pricing_model=pricing_model,
            pricing_rates={
                **{key: entry[key] for key in _BASE_RATES if key in entry},
                "catalog_sha256": catalog.sha256,
                "retrieved_at": catalog.retrieved_at,
                "source": (
                    "custom"
                    if catalog is self._custom
                    else "litellm_snapshot"
                    if catalog.package_version is not None
                    else CATALOG_URL
                ),
                **(
                    {"package_version": catalog.package_version}
                    if catalog.package_version is not None
                    else {}
                ),
                "scope": "text_tokens",
            },
        )
        return result
