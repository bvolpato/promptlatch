import hashlib
import json
import stat
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import httpx
import pytest
import respx

from promptlatch.pricing import CATALOG_URL, PricingCatalog

RATE = {
    "litellm_provider": "openai",
    "input_cost_per_token": 0.000002,
    "output_cost_per_token": 0.000008,
    "cache_read_input_token_cost": 0.000001,
}
USAGE = {
    "input_tokens": 100,
    "output_tokens": 20,
    "total_tokens": 120,
    "cached_input_tokens": 40,
    "cache_write_tokens": 0,
}


def cached_catalog(tmp_path, entries=None):
    payload = json.dumps(entries or {"fixture-model": RATE})
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps(
            {
                "retrieved_at": "2026-10-10T00:00:00+00:00",
                "sha256": hashlib.sha256(payload.encode()).hexdigest(),
                "payload": payload,
            }
        )
    )
    catalog = PricingCatalog(path)
    catalog.load()
    return catalog


def test_cached_tokens_are_charged_once_with_rate_provenance(tmp_path):
    catalog = cached_catalog(tmp_path)
    result = catalog.estimate("fixture-model", "openai", USAGE)
    assert result["cost_usd"] == pytest.approx(0.00032)
    assert result["cost_source"] == "litellm_estimate"
    assert result["pricing_model"] == "fixture-model"
    assert result["pricing_as_of"] == "2026-10-10T00:00:00+00:00"
    assert len(result["pricing_rates"]["catalog_sha256"]) == 64
    assert result["pricing_rates"]["cache_read_input_token_cost"] == 0.000001


def test_chatgpt_uses_exact_openai_rates_with_api_equivalent_provenance(tmp_path):
    catalog = cached_catalog(tmp_path)
    api = catalog.estimate("fixture-model", "openai", USAGE)
    subscription = catalog.estimate("fixture-model", "chatgpt", USAGE)
    assert subscription["cost_usd"] == api["cost_usd"]
    assert subscription["cost_source"] == "litellm_api_equivalent"
    assert subscription["cost_unavailable_reason"] is None
    assert subscription["pricing_rates"] == api["pricing_rates"]
    assert catalog.estimate("fixture-model-latest", "chatgpt", USAGE)["cost_usd"] is None
    assert (
        catalog.estimate("fixture-model", "chatgpt", USAGE | {"cached_input_tokens": None})[
            "cost_usd"
        ]
        is None
    )


def test_bundled_litellm_catalog_prices_codex_offline_without_sdk_import(tmp_path):
    script = """
import builtins, json, socket, sys
from pathlib import Path

original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == "litellm" or name.startswith("litellm."):
        raise AssertionError("LiteLLM SDK must not be imported")
    return original_import(name, *args, **kwargs)
def no_network(*args, **kwargs):
    raise AssertionError("Pricing startup and estimation must be offline")
class NoNetworkSocket(socket.socket):
    connect = no_network
    connect_ex = no_network
builtins.__import__ = guarded_import
socket.socket = NoNetworkSocket
from promptlatch.pricing import PricingCatalog
catalog = PricingCatalog(Path(sys.argv[1]))
catalog.load()
result = catalog.estimate("gpt-6.1-sol", "chatgpt", {
    "input_tokens": 100, "output_tokens": 20,
    "cached_input_tokens": 40, "cache_write_tokens": 10,
})
assert "litellm" not in sys.modules
print(json.dumps(result))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "missing.json")],
        check=True,
        text=True,
        capture_output=True,
    )
    result = json.loads(completed.stdout)
    distribution = metadata.distribution("litellm")
    payload = Path(
        str(distribution.locate_file("litellm/model_prices_and_context_window_backup.json"))
    ).read_bytes()
    rate = json.loads(payload)["gpt-6.1-sol"]
    expected = (
        50 * rate["input_cost_per_token"]
        + 20 * rate["output_cost_per_token"]
        + 40 * rate["cache_read_input_token_cost"]
        + 10 * rate["cache_creation_input_token_cost"]
    )
    assert result["cost_usd"] == pytest.approx(expected)
    assert result["cost_source"] == "litellm_api_equivalent"
    assert result["pricing_model"] == "gpt-6.1-sol"
    assert result["pricing_as_of"] is None  # Package has no price publication timestamp.
    assert result["pricing_rates"]["source"] == "litellm_package"
    assert result["pricing_rates"]["package_version"] == distribution.version
    assert result["pricing_rates"]["catalog_sha256"] == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    "changes",
    [
        {"input_tokens": None},
        {"output_tokens": None},
        {"cached_input_tokens": None},
        {"cached_input_tokens": 101},
        {"cache_write_tokens": 1},
        {"input_tokens": True},
        {"output_tokens": -1},
        {"input_tokens": 10**1000},
    ],
)
def test_unknown_or_invalid_usage_has_no_estimate(tmp_path, changes):
    catalog = cached_catalog(tmp_path)
    assert catalog.estimate("fixture-model", "openai", USAGE | changes)["cost_usd"] is None


def test_provider_matching_does_not_guess_aliases_or_custom_endpoints(tmp_path):
    catalog = cached_catalog(
        tmp_path,
        {
            "fixture-model": RATE,
            "openrouter/vendor/fixture-model": RATE | {"litellm_provider": "openrouter"},
        },
    )
    for model, provider in (
        ("fixture-model", "custom"),
        ("fixture-model", "anthropic"),
        ("vendor/fixture-model", "openai"),
        ("fixture-model-latest", "openai"),
        ("fixture-model", "openrouter"),
    ):
        assert catalog.estimate(model, provider, USAGE)["cost_usd"] is None
    assert (
        catalog.estimate("vendor/fixture-model", "openrouter", USAGE)["pricing_model"]
        == "openrouter/vendor/fixture-model"
    )


def test_custom_catalog_requires_exact_name_and_supports_cache_writes(tmp_path):
    path = tmp_path / "custom.json"
    path.write_text(
        json.dumps({"private-model": RATE | {"cache_creation_input_token_cost": 0.000003}})
    )
    catalog = PricingCatalog(tmp_path / "missing.json", custom_path=path)
    catalog.load()
    result = catalog.estimate("private-model", "custom", USAGE | {"cache_write_tokens": 10})
    assert result["cost_usd"] == pytest.approx(0.00033)
    assert result["pricing_rates"]["source"] == "custom"
    assert catalog.estimate("private-model-latest", "custom", USAGE)["cost_usd"] is None
    equivalent = catalog.estimate("private-model", "chatgpt", USAGE | {"cache_write_tokens": 10})
    assert equivalent["cost_usd"] == result["cost_usd"]
    assert equivalent["cost_source"] == "custom_api_equivalent"
    assert equivalent["pricing_rates"]["source"] == "custom"


@pytest.mark.parametrize(
    "provider,model,usage,tier,reason",
    [
        ("chatgpt", "fixture-model", USAGE | {"input_tokens": None}, None, "usage_incomplete"),
        ("openai", None, USAGE, None, "model_missing"),
        ("openai", "fixture-model", USAGE | {"input_tokens": None}, None, "usage_incomplete"),
        ("openai", "fixture-model", USAGE, "priority", "unsupported_service_tier"),
        ("openai", "fixture-model", USAGE | {"unsupported_costs": True}, None, "unsupported_costs"),
        ("custom", "fixture-model", USAGE, None, "provider_unmapped"),
        ("openai", "fixture-model-unknown", USAGE, None, "model_unpriced"),
        ("openai", "fixture-model", USAGE | {"cache_write_tokens": 1}, None, "unsupported_rates"),
    ],
)
def test_unknown_price_reason_is_explicit_without_guessing_rates(
    tmp_path, provider, model, usage, tier, reason
):
    result = cached_catalog(tmp_path).estimate(model, provider, usage, service_tier=tier)
    assert result["cost_usd"] is None
    assert result["cost_unavailable_reason"] == reason


def test_disabled_and_missing_catalog_have_distinct_cost_reasons(tmp_path, monkeypatch):
    disabled = PricingCatalog(tmp_path / "missing", enabled=False)
    disabled.load()
    assert disabled.estimate("fixture-model", "openai", USAGE)["cost_unavailable_reason"] == (
        "pricing_disabled"
    )
    monkeypatch.setattr("promptlatch.pricing._packaged_catalog", lambda: None)
    missing = PricingCatalog(tmp_path / "missing")
    missing.load()
    assert missing.estimate("fixture-model", "openai", USAGE)["cost_unavailable_reason"] == (
        "catalog_unavailable"
    )


def test_free_model_is_zero_rather_than_unknown(tmp_path):
    catalog = cached_catalog(
        tmp_path,
        {
            "free": {
                "litellm_provider": "openai",
                "input_cost_per_token": 0,
                "output_cost_per_token": 0,
            }
        },
    )
    result = catalog.estimate("free", "openai", USAGE | {"cached_input_tokens": 0})
    assert result["cost_usd"] == 0
    assert result["cost_source"] == "litellm_estimate"


@pytest.mark.parametrize("service_tier", ["flex", "priority", "ultrafast", "auto", "unknown"])
def test_nonstandard_service_tier_is_unknown(tmp_path, service_tier):
    catalog = cached_catalog(tmp_path)
    assert (
        catalog.estimate("fixture-model", "openai", USAGE, service_tier=service_tier)["cost_usd"]
        is None
    )


def test_context_tier_is_unknown_only_above_threshold(tmp_path):
    catalog = cached_catalog(
        tmp_path,
        {
            "fixture-model": RATE
            | {
                "input_cost_per_token_above_200k_tokens": 0.000004,
                "input_cost_per_token_above_200k_tokens_batches": 0.000002,
            }
        },
    )
    assert catalog.estimate("fixture-model", "openai", USAGE)["cost_usd"] is not None
    assert (
        catalog.estimate("fixture-model", "openai", USAGE | {"input_tokens": 200_001})["cost_usd"]
        is None
    )


def test_ultrafast_alternate_rates_do_not_block_standard_text_estimates(tmp_path):
    rates = RATE | {"cache_creation_input_token_cost": 0.000003}
    entry = rates.copy()
    for key in (
        "input_cost_per_token",
        "output_cost_per_token",
        "cache_read_input_token_cost",
        "cache_creation_input_token_cost",
    ):
        entry[key + "_ultrafast"] = rates[key] * 6
        entry[key + "_above_272k_tokens"] = rates[key] * 2
        entry[key + "_above_272k_tokens_ultrafast"] = rates[key] * 12
    catalog = cached_catalog(tmp_path, {"fixture-model": entry})
    quote = catalog.estimate("fixture-model", "chatgpt", USAGE)
    assert quote["cost_usd"] == pytest.approx(0.00032)
    assert quote["cost_source"] == "litellm_api_equivalent"
    assert quote["pricing_rates"]["input_cost_per_token"] == RATE["input_cost_per_token"]
    assert (
        catalog.estimate("fixture-model", "chatgpt", USAGE | {"input_tokens": 272_001})["cost_usd"]
        is None
    )


def test_unsupported_cache_write_ttl_only_affects_cache_writes(tmp_path):
    catalog = cached_catalog(
        tmp_path,
        {
            "fixture-model": RATE
            | {
                "cache_creation_input_token_cost": 0.000003,
                "cache_creation_input_token_cost_above_1hr": 0.000004,
            }
        },
    )
    assert catalog.estimate("fixture-model", "openai", USAGE)["cost_usd"] is not None
    assert (
        catalog.estimate("fixture-model", "openai", USAGE | {"cache_write_tokens": 10})["cost_usd"]
        is None
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"input_cost_per_audio_token": 0.0001},
        {"input_cost_per_request": 0.01},
        {"citation_cost_per_token": 0.000002},
        {"output_cost_per_reasoning_token": 0.000003},
        {"unknown_cost_per_token": 0.000001},
        {"unknown_cost_per_token_priority": 0.000001},
        {"unknown_cost_per_token_ultrafast": 0.000001},
    ],
)
def test_unsupported_billing_meters_are_unknown(tmp_path, extra):
    catalog = cached_catalog(tmp_path, {"fixture-model": RATE | extra})
    assert catalog.estimate("fixture-model", "openai", USAGE)["cost_usd"] is None


@pytest.mark.parametrize(
    ("model", "provider", "mode"),
    [
        ("sonar-deep-research", "perplexity", "chat"),
        ("sonar", "perplexity", "chat"),
        ("perplexity/sonar", "openrouter", "chat"),
        ("gpt-4o-search-preview", "openai", "chat"),
        ("o3-deep-research", "openai", "responses"),
        ("fixture-model", "openai", "search"),
    ],
)
def test_intrinsic_search_cost_is_not_inferred_from_ordinary_token_usage(
    tmp_path, model, provider, mode
):
    catalog = cached_catalog(
        tmp_path,
        {
            model: RATE
            | {
                "litellm_provider": provider,
                "mode": mode,
                "search_context_cost_per_query": {"search_context_size_low": 0.025},
            }
        },
    )
    assert catalog.estimate(model, provider, USAGE)["cost_usd"] is None


@pytest.mark.parametrize("cache_hit_rate", [0.000001, 0.0000005])
def test_cache_hit_alias_must_match_explicit_cache_read_rate(tmp_path, cache_hit_rate):
    catalog = cached_catalog(
        tmp_path,
        {"fixture-model": RATE | {"input_cost_per_token_cache_hit": cache_hit_rate}},
    )
    cost = catalog.estimate("fixture-model", "openai", USAGE)["cost_usd"]
    if cache_hit_rate == RATE["cache_read_input_token_cost"]:
        assert cost == pytest.approx(0.00032)
    else:
        assert cost is None


def test_optional_tool_rates_allow_plain_text_but_not_hosted_tool_usage(tmp_path):
    catalog = cached_catalog(
        tmp_path,
        {
            "fixture-model": RATE
            | {"search_context_cost_per_query": {"search_context_size_low": 0.025}}
        },
    )
    result = catalog.estimate("fixture-model", "openai", USAGE)
    assert result["cost_usd"] == pytest.approx(0.00032)
    assert result["pricing_rates"]["scope"] == "text_tokens"
    assert (
        catalog.estimate("fixture-model", "openai", USAGE | {"unsupported_costs": True})["cost_usd"]
        is None
    )


@pytest.mark.parametrize("invalid_rate", [-1, float("nan"), float("inf"), True, "0.2"])
def test_invalid_catalog_rates_are_not_loaded(tmp_path, invalid_rate):
    catalog = cached_catalog(
        tmp_path, {"fixture-model": RATE | {"input_cost_per_token": invalid_rate}}
    )
    assert catalog.estimate("fixture-model", "openai", USAGE)["cost_usd"] is None


@respx.mock
async def test_refresh_persists_private_cache_and_can_reload_offline(tmp_path):
    route = respx.get(CATALOG_URL).mock(
        return_value=httpx.Response(200, json={"fixture-model": RATE})
    )
    path = tmp_path / "private" / "catalog.json"
    catalog = PricingCatalog(path)
    assert await catalog.refresh()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert route.call_count == 1
    reloaded = PricingCatalog(path)
    reloaded.load()
    assert reloaded.estimate("fixture-model", "openai", USAGE) == catalog.estimate(
        "fixture-model", "openai", USAGE
    )
    assert route.call_count == 1


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"model": {"input_cost_per_token": -1}}'])
@respx.mock
async def test_malformed_refresh_retains_last_good_snapshot(tmp_path, body):
    catalog = cached_catalog(tmp_path)
    original_cache = catalog.cache_path.read_bytes()
    original_estimate = catalog.estimate("fixture-model", "openai", USAGE)
    respx.get(CATALOG_URL).mock(return_value=httpx.Response(200, content=body))
    assert not await catalog.refresh()
    assert catalog.cache_path.read_bytes() == original_cache
    assert catalog.estimate("fixture-model", "openai", USAGE) == original_estimate


@respx.mock
async def test_refresh_failure_or_redirect_does_not_replace_catalog(tmp_path):
    catalog = cached_catalog(tmp_path)
    expected = catalog.estimate("fixture-model", "openai", USAGE)
    route = respx.get(CATALOG_URL)
    route.mock(side_effect=httpx.ReadTimeout("fixture timeout"))
    assert not await catalog.refresh()
    route.mock(
        return_value=httpx.Response(302, headers={"Location": "https://other.example/catalog"})
    )
    assert not await catalog.refresh()
    assert catalog.estimate("fixture-model", "openai", USAGE) == expected


@respx.mock
async def test_download_size_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr("promptlatch.pricing.MAX_CATALOG_BYTES", 100)
    catalog = PricingCatalog(tmp_path / "catalog.json")
    respx.get(CATALOG_URL).mock(return_value=httpx.Response(200, content=b" " * 101))
    assert not await catalog.refresh()
    assert not catalog.cache_path.exists()


@respx.mock
async def test_disabled_catalog_does_no_io(tmp_path):
    catalog = PricingCatalog(tmp_path / "missing.json", enabled=False)
    catalog.load()
    assert not await catalog.refresh()
    assert catalog.estimate("fixture-model", "openai", USAGE)["cost_usd"] is None


def test_tampered_cache_is_not_used(tmp_path):
    catalog = cached_catalog(tmp_path)
    envelope = json.loads(catalog.cache_path.read_text())
    envelope["sha256"] = "wrong"
    catalog.cache_path.write_text(json.dumps(envelope))
    reloaded = PricingCatalog(catalog.cache_path)
    reloaded.load()
    assert reloaded.estimate("fixture-model", "openai", USAGE)["cost_usd"] is None
