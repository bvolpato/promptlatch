from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def fake_secret(prefix: str, body: str = "FixtureToken000000000000000000000") -> str:
    return prefix + body


PROVIDER_FIXTURES = {
    "github_classic_pat": fake_secret("gh" + "p_"),
    "github_fine_grained_pat": fake_secret("github" + "_pat_11AAABBBB0"),
    "atlassian_api_token": fake_secret("ATATT" + "3xFfGF0"),
    "openai_key": fake_secret("sk-" + "proj-"),
    "gemini_api_key": fake_secret("AI" + "zaSy"),
    "anthropic_api_key": fake_secret("sk-" + "ant-api03-"),
    "openrouter_key": fake_secret("sk-" + "or-v1-"),
    "deepseek_api_key": fake_secret("sk-" + "deepseek-"),
    "minimax_api_key": fake_secret("sk-" + "cp-"),
    "fireworks_api_key": fake_secret("fw" + "_"),
    "xai_api_key": fake_secret("xai" + "-"),
    "gitlab_token": fake_secret("glpat-"),
    "slack_token": fake_secret("xox" + "b-"),
    "stripe_key": fake_secret("sk" + "_test_"),
}

EXPANDED_PROVIDER_FIXTURES = {
    "aws_extended_access_key": "AB" + "IA" + "ABCDEFGHIJKLMNOP",
    "aws_bedrock_api_key": "AB" + "SK" + ("A" * 100),
    "google_oauth_token": "ya" + "29." + ("A" * 30),
    "onepassword_service_account_token": "ops_" + "eyJ" + ("A" * 121),
    "age_secret_key": "AGE-" + "SECRET-KEY-1" + ("Q" * 58),
    "databricks_api_token": "da" + "pi" + ("a" * 32),
    "digitalocean_token": "do" + "p_v1_" + ("a" * 64),
    "huggingface_token": "hf" + "_" + ("a" * 34),
    "linear_api_key": "lin" + "_api_" + ("a" * 40),
    "npm_token": "npm" + "_" + ("a" * 36),
    "pypi_upload_token": "pypi-" + "AgEIcHlwaS5vcmc" + ("A" * 50),
    "sendgrid_token": "SG" + "." + ("A" * 66),
    "slack_webhook": "https://hooks.slack.com/services/" + ("A" * 43),
    "telegram_bot_token": "123456:A" + ("a" * 34),
    "twilio_api_key": "SK" + ("a" * 32),
    "vault_token": "hvs" + "." + ("a" * 90),
    "shopify_token": "sh" + "pat_" + ("a" * 32),
    "sentry_token": "sn" + "tryu_" + ("a" * 40),
    "cloudflare_api_key": fake_secret("cloudflare-"),
}

OPENAI_FAKE = fake_secret("sk-")
GEMINI_FAKE = PROVIDER_FIXTURES["gemini_api_key"]
CUSTOM_TAIL_SECRET = "pl_live_000000000000abcd1234"


def complex_payload() -> dict[str, Any]:
    return {
        "model": "gpt-5.5",
        "input": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": f"Debug env OPENAI_API_KEY={OPENAI_FAKE}",
                    },
                    {
                        "type": "input_text",
                        "text": "comma list: "
                        + ",".join(
                            [
                                PROVIDER_FIXTURES["openai_key"],
                                PROVIDER_FIXTURES["gemini_api_key"],
                                PROVIDER_FIXTURES["anthropic_api_key"],
                            ]
                        ),
                    },
                ],
            }
        ],
        "messages": [
            {
                "role": "user",
                "content": f"GEMINI_API_KEY={PROVIDER_FIXTURES['gemini_api_key']}",
            }
        ],
        "tools": [
            {
                "type": "function",
                "name": "inspect_config",
                "description": f"Repo token {PROVIDER_FIXTURES['github_classic_pat']}",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "token": {
                            "type": "string",
                            "description": f"custom tail {CUSTOM_TAIL_SECRET}",
                        }
                    },
                },
            }
        ],
        "metadata": {
            "openrouter": PROVIDER_FIXTURES["openrouter_key"],
            "atlassian": PROVIDER_FIXTURES["atlassian_api_token"],
        },
    }


def all_fixture_values() -> list[str]:
    return [
        *PROVIDER_FIXTURES.values(),
        *EXPANDED_PROVIDER_FIXTURES.values(),
        OPENAI_FAKE,
        GEMINI_FAKE,
        CUSTOM_TAIL_SECRET,
    ]


def assert_no_fixture_values(value: Any) -> None:
    serialized = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    leaked = [fixture for fixture in all_fixture_values() if fixture in serialized]
    assert leaked == []


def assert_header_absent(headers: Mapping[str, str], name: str) -> None:
    assert name.lower() not in {key.lower() for key in headers}
