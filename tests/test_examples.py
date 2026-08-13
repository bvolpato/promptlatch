import json
import tomllib
from pathlib import Path

import yaml

from promptlatch.config import Settings

ROOT = Path(__file__).resolve().parents[1]


def test_compose_binds_proxy_to_loopback() -> None:
    data = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

    assert data["services"]["promptlatch"]["ports"] == ["127.0.0.1:8000:8000"]


def test_openrouter_promptlatch_example_is_valid() -> None:
    data = yaml.safe_load((ROOT / "examples" / "promptlatch-openrouter.config.yaml").read_text())
    settings = Settings.model_validate(data)

    assert settings.target.default_base_url == "https://openrouter.ai/api/v1"
    assert settings.target.api_key is None
    assert settings.target.forward_client_authorization is False
    assert settings.target.allowed_base_urls == ["https://openrouter.ai/api/v1"]
    assert settings.compat.responses_to_chat is False


def test_codex_openrouter_profile_uses_dedicated_target_headers() -> None:
    data = tomllib.loads(
        (ROOT / "examples" / "codex-openrouter-promptlatch.config.toml").read_text()
    )
    provider = data["model_providers"]["promptlatch-openrouter"]

    assert data["model_provider"] == "promptlatch-openrouter"
    assert provider["base_url"] == "http://127.0.0.1:8000/v1"
    assert "env_key" not in provider
    assert provider["env_http_headers"] == {"X-Target-API-Key": "OPENROUTER_API_KEY"}
    assert provider["http_headers"] == {"X-Target-Base-URL": "https://openrouter.ai/api/v1"}
    assert provider["wire_api"] == "responses"


def test_opencode_openrouter_profile_uses_dedicated_target_headers() -> None:
    data = json.loads((ROOT / "examples" / "opencode-openrouter-promptlatch.json").read_text())
    provider = data["provider"]["promptlatch-openrouter"]

    assert provider["npm"] == "@ai-sdk/openai-compatible"
    assert provider["options"] == {
        "baseURL": "http://127.0.0.1:8000/v1",
        "headers": {
            "X-Target-Base-URL": "https://openrouter.ai/api/v1",
            "X-Target-API-Key": "{env:OPENROUTER_API_KEY}",
        },
    }
    assert data["model"] == "promptlatch-openrouter/openai/gpt-oss-120b"
