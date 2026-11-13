import base64
import binascii
import json
import re
import struct
import tempfile
import zlib
from typing import Literal

import pytest
import requests
from pydantic import BaseModel, ConfigDict

from promptlatch.config import RedactionConfig, RuleConfig
from promptlatch.redaction import RedactionKeyCollisionError, SecretRedactor
from tests.fixtures import EXPANDED_PROVIDER_FIXTURES, OPENAI_FAKE, PROVIDER_FIXTURES


def _tiny_png_url() -> str:
    def chunk(name: bytes, data: bytes) -> bytes:
        return (
            struct.pack("!I", len(data))
            + name
            + data
            + struct.pack("!I", binascii.crc32(name + data))
        )

    image = b"\x89PNG\r\n\x1a\n"
    image += chunk(b"IHDR", struct.pack("!IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
    image += chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff"))
    image += chunk(b"IEND", b"")
    return "data:image/png;base64," + base64.b64encode(image).decode("ascii")


@pytest.mark.parametrize(
    "item",
    [
        {"role": "user"},
        {"type": "message", "role": "user"},
        {"type": "message", "role": "assistant"},
        {"type": "message", "role": "system"},
        {"type": "message", "role": "developer"},
        {"type": "function_call_output", "call_id": "call_fixture"},
        {"type": "custom_tool_call_output", "call_id": "call_fixture"},
    ],
)
@pytest.mark.parametrize("rule_type", ["exact", "regex"])
def test_responses_preserve_image_data_only_in_supported_content_locations(
    item: dict, rule_type: Literal["exact", "regex"]
) -> None:
    image_url = _tiny_png_url()
    rule = RuleConfig(
        type=rule_type,
        value=image_url[-8:] if rule_type == "exact" else "iVBORw0KGgo",
    )
    redactor = SecretRedactor(RedactionConfig(engine="basic", rules=[rule]))
    field = "content" if "role" in item else "output"
    parts = [
        {"type": "input_text", "text": f"API_KEY={OPENAI_FAKE}"},
        {"type": "input_image", "image_url": image_url},
    ]
    payload = {"input": [{**item, field: parts}]}

    assert redactor.redact_payload(payload).value["input"][0][field][1]["image_url"] != image_url
    result = redactor.redact_payload(payload, protocol="openai-responses")

    assert result.value["input"][0][field][1]["image_url"] == image_url
    assert OPENAI_FAKE not in result.value["input"][0][field][0]["text"]
    assert result.stats.redactions == 1
    assert parts[1]["image_url"] == image_url


@pytest.mark.parametrize(
    "item",
    [
        {"type": "function_call_output", "content": []},
        {"type": "message", "role": "tool", "content": []},
        {"type": "other", "role": "user", "content": []},
        {"type": "message", "content": []},
        {"type": "message", "role": "user", "metadata": {"content": []}},
        {"type": "input_image", "image_url": _tiny_png_url()},
    ],
)
def test_responses_image_data_in_arbitrary_fields_remains_scanned(item: dict) -> None:
    image_url = _tiny_png_url()
    parts = [{"type": "input_image", "image_url": image_url}]
    if "content" in item:
        item = {**item, "content": parts}
    elif "metadata" in item:
        item = {**item, "metadata": {"content": parts}}
    redactor = SecretRedactor(
        RedactionConfig(engine="basic", rules=[RuleConfig(type="regex", value="iVBORw0KGgo")])
    )

    result = redactor.redact_payload({"input": [item]}, protocol="openai-responses")

    assert image_url not in json.dumps(result.value)
    assert result.stats.redactions == 1


@pytest.mark.parametrize(
    "image_url",
    [
        _tiny_png_url().replace("image/png", "image/svg+xml"),
        _tiny_png_url().replace("image/png", "image/jpeg"),
        _tiny_png_url() + "!",
        _tiny_png_url() + "=",
        _tiny_png_url()[:-3] + "h==",
        "data:image/png;base64," + base64.b64encode(b"invalid image bytes").decode("ascii"),
        f"https://example.test/image.png?api_key={OPENAI_FAKE}",
    ],
)
def test_responses_invalid_image_data_and_remote_image_urls_remain_scanned(image_url: str) -> None:
    redactor = SecretRedactor(
        RedactionConfig(engine="basic", rules=[RuleConfig(type="regex", value="base64,")])
    )

    result = redactor.redact_payload(
        {"input": [{"role": "user", "content": [{"type": "input_image", "image_url": image_url}]}]},
        protocol="openai-responses",
    )

    assert result.value["input"][0]["content"][0]["image_url"] != image_url
    assert result.stats.redactions >= 1


def test_responses_image_exemption_does_not_propagate_into_other_parts_or_metadata() -> None:
    image_url = _tiny_png_url()
    payload = {
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "image_url": image_url},
                    {
                        "type": "input_image",
                        "image_url": image_url,
                        "metadata": {"type": "input_image", "image_url": image_url},
                    },
                ],
            }
        ]
    }
    redactor = SecretRedactor(
        RedactionConfig(engine="basic", rules=[RuleConfig(type="regex", value="iVBORw0KGgo")])
    )

    result = redactor.redact_payload(payload, protocol="openai-responses")

    parts = result.value["input"][0]["content"]
    assert parts[0]["image_url"] != image_url
    assert parts[1]["image_url"] == image_url
    assert parts[1]["metadata"]["image_url"] != image_url
    assert result.stats.redactions == 2


def test_responses_pydantic_image_content_matches_mapping_scope() -> None:
    class ImagePart(BaseModel):
        type: Literal["input_image"] = "input_image"
        image_url: str

    class Message(BaseModel):
        type: Literal["message"] = "message"
        role: Literal["user"] = "user"
        content: tuple[ImagePart, ...]
        extra_context: str

    class Request(BaseModel):
        input: list[Message]

    image_url = _tiny_png_url()
    request = Request(
        input=[
            Message(content=(ImagePart(image_url=image_url),), extra_context=OPENAI_FAKE),
        ]
    )
    redactor = SecretRedactor(
        RedactionConfig(engine="basic", rules=[RuleConfig(type="regex", value="iVBORw0KGgo")])
    )

    result = redactor.redact_payload(request, protocol="openai-responses")

    assert isinstance(result.value, Request)
    assert result.value.input[0].content[0].image_url == image_url
    assert result.value.input[0].extra_context == "[REDACTED_SECRET]"
    assert request.input[0].extra_context == OPENAI_FAKE
    assert result.stats.redactions == 1


def _opaque_response_fixture(marker: str = OPENAI_FAKE) -> str:
    """Synthetic Fernet-shaped bytes, with a detector match in the encoded value."""
    prefix = f"gAAAAAAAAAAA-{marker}-"
    # 57-byte header/HMAC plus a positive number of 16-byte blocks, without padding.
    blocks = max(1, (len(prefix) - 76 + 63) // 64)
    return prefix.ljust(76 + blocks * 64, "A")


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
@pytest.mark.parametrize("item_type", ["reasoning", "compaction"])
def test_responses_protocol_preserves_only_direct_opaque_input_items(
    engine: Literal["basic", "detect-secrets"], item_type: str
) -> None:
    redactor = SecretRedactor(RedactionConfig(engine=engine))
    ciphertext = _opaque_response_fixture()
    item = {
        "type": item_type,
        "encrypted_content": ciphertext,
        "summary": [{"type": "summary_text", "text": f"API_KEY={OPENAI_FAKE}"}],
        "metadata": {"type": item_type, "encrypted_content": ciphertext},
    }
    payload = {"input": [item], "metadata": {"encrypted_content": ciphertext}}

    assert redactor.redact_payload(payload).value["input"][0]["encrypted_content"] != ciphertext
    result = redactor.redact_payload(payload, protocol="openai-responses")

    retained = result.value["input"][0]
    assert retained["encrypted_content"] == ciphertext
    assert OPENAI_FAKE not in retained["summary"][0]["text"]
    assert retained["metadata"]["encrypted_content"] != ciphertext
    assert result.value["metadata"]["encrypted_content"] != ciphertext
    assert payload["input"][0]["summary"][0]["text"].endswith(OPENAI_FAKE)
    assert item["encrypted_content"] == ciphertext
    assert result.stats.redactions >= 3


@pytest.mark.parametrize(
    "rule",
    [
        RuleConfig(type="exact", value="OpaqueRuleFixture0000"),
        RuleConfig(type="exact", value="AAAAAAAA"),
        RuleConfig(type="regex", value="OpaqueRuleFixture[0-9]+"),
    ],
)
def test_responses_opaque_content_ignores_custom_rules_without_exempting_readable_fields(
    rule: RuleConfig,
) -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic", rules=[rule]))
    ciphertext = _opaque_response_fixture("OpaqueRuleFixture0000")
    payload = {
        "input": [
            {
                "type": "reasoning",
                "encrypted_content": ciphertext,
                "summary": [{"type": "summary_text", "text": ciphertext}],
            }
        ]
    }

    result = redactor.redact_payload(payload, protocol="openai-responses")

    assert result.value["input"][0]["encrypted_content"] == ciphertext
    assert result.value["input"][0]["summary"][0]["text"] != ciphertext
    assert result.stats.redactions >= 1


@pytest.mark.parametrize(
    "content",
    [
        OPENAI_FAKE,
        f"API_KEY={OPENAI_FAKE}",
        _opaque_response_fixture() + "!",
        _opaque_response_fixture()[1:],
        "A" + _opaque_response_fixture()[1:],
        _opaque_response_fixture() + "=",
        _opaque_response_fixture() + "AAAA",
    ],
)
def test_responses_plaintext_and_invalid_envelopes_are_still_redacted(content: str) -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))

    result = redactor.redact_payload(
        {"input": [{"type": "reasoning", "encrypted_content": content}]},
        protocol="openai-responses",
    )

    assert result.value["input"][0]["encrypted_content"] != content
    assert OPENAI_FAKE not in result.value["input"][0]["encrypted_content"]
    assert result.stats.redactions >= 1


@pytest.mark.parametrize("item_type", [None, "message", "function_call", "Reasoning"])
def test_responses_opaque_encoding_does_not_exempt_other_item_types(item_type: str | None) -> None:
    ciphertext = _opaque_response_fixture()

    result = SecretRedactor(RedactionConfig(engine="basic")).redact_payload(
        {"input": [{"type": item_type, "encrypted_content": ciphertext}]},
        protocol="openai-responses",
    )

    assert result.value["input"][0]["encrypted_content"] != ciphertext
    assert result.stats.redactions >= 1


@pytest.mark.parametrize("extra_fields", [False, True])
def test_responses_pydantic_opaque_scope_matches_mapping_scope(extra_fields: bool) -> None:
    class ResponseItem(BaseModel):
        model_config = ConfigDict(extra="allow")
        summary: list[dict[str, str]]

    class ExplicitResponseItem(ResponseItem):
        type: str
        encrypted_content: str

    class ResponseRequest(BaseModel):
        input: tuple[ResponseItem, ...]

    item_class = ResponseItem if extra_fields else ExplicitResponseItem
    ciphertext = _opaque_response_fixture()
    item = item_class.model_validate(
        {
            "type": "reasoning",
            "encrypted_content": ciphertext,
            "summary": [{"type": "summary_text", "text": f"API_KEY={OPENAI_FAKE}"}],
        }
    )
    request = ResponseRequest(input=(item,))

    result = SecretRedactor(RedactionConfig(engine="basic")).redact_payload(
        request, protocol="openai-responses"
    )

    assert isinstance(result.value, ResponseRequest)
    assert isinstance(result.value.input[0], item_class)
    assert result.value.input[0].model_dump()["encrypted_content"] == ciphertext
    assert OPENAI_FAKE not in result.value.input[0].summary[0]["text"]
    assert item.summary[0]["text"].endswith(OPENAI_FAKE)


def test_responses_opaque_capture_preserves_padded_envelope() -> None:
    raw = base64.urlsafe_b64decode(_opaque_response_fixture()) + bytes(16)
    ciphertext = base64.urlsafe_b64encode(raw).decode("ascii")
    redactor = SecretRedactor(
        RedactionConfig(engine="basic", rules=[RuleConfig(type="regex", value="gAAAA")])
    )

    result = redactor.redact_payload(
        {"input": [{"type": "compaction", "encrypted_content": ciphertext}]},
        protocol="openai-responses",
    )

    assert ciphertext.endswith("==")
    assert result.value["input"][0]["encrypted_content"] == ciphertext
    assert result.stats.redactions == 0


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
def test_responses_agent_message_preserves_typed_encrypted_content_only(
    engine: Literal["basic", "detect-secrets"],
) -> None:
    ciphertext = _opaque_response_fixture()
    redactor = SecretRedactor(RedactionConfig(engine=engine))
    payload = {
        "input": [
            {
                "type": "agent_message",
                "id": "amsg_fixture",
                "author": "assistant",
                "recipient": "all",
                "content": [
                    {"type": "input_text", "text": f"API_KEY={OPENAI_FAKE}"},
                    {"type": "encrypted_content", "encrypted_content": ciphertext},
                ],
                "internal_chat_message_metadata_passthrough": {
                    "encrypted_content": ciphertext,
                },
            }
        ]
    }

    result = redactor.redact_payload(payload, protocol="openai-responses")
    message = result.value["input"][0]

    assert message["content"][0]["text"] == "API_KEY=[REDACTED_SECRET]"
    assert message["content"][1]["encrypted_content"] == ciphertext
    assert message["internal_chat_message_metadata_passthrough"]["encrypted_content"] != ciphertext
    assert result.stats.redactions >= 2


@pytest.mark.parametrize("item_type", ["function_call_output", "custom_tool_call_output"])
def test_responses_tool_output_preserves_typed_encrypted_content_part(item_type: str) -> None:
    ciphertext = _opaque_response_fixture("OpaqueToolOutputRule0000")
    redactor = SecretRedactor(
        RedactionConfig(
            engine="basic",
            rules=[RuleConfig(type="exact", value="OpaqueToolOutputRule0000")],
        )
    )
    image_url = _tiny_png_url()
    payload = {
        "input": [
            {
                "type": item_type,
                "call_id": "call_fixture",
                "output": [
                    {"type": "input_text", "text": f"API_KEY={OPENAI_FAKE}"},
                    {"type": "encrypted_content", "encrypted_content": ciphertext},
                    {"type": "input_image", "image_url": image_url},
                ],
            }
        ]
    }

    result = redactor.redact_payload(payload, protocol="openai-responses")
    output = result.value["input"][0]["output"]

    assert output[0]["text"] == "API_KEY=[REDACTED_SECRET]"
    assert output[1]["encrypted_content"] == ciphertext
    assert output[2]["image_url"] == image_url
    assert result.stats.redactions >= 1


def test_responses_encrypted_content_parts_stay_redacted_outside_known_contexts() -> None:
    ciphertext = _opaque_response_fixture("OpaqueUnsafeContentRule0000")
    malformed = ciphertext + "!"
    redactor = SecretRedactor(
        RedactionConfig(
            engine="basic",
            rules=[RuleConfig(type="exact", value="OpaqueUnsafeContentRule0000")],
        )
    )
    payload = {
        "input": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "encrypted_content", "encrypted_content": ciphertext}],
            },
            {
                "type": "agent_message",
                "content": [{"type": "unknown", "encrypted_content": ciphertext}],
                "metadata": {
                    "content": [{"type": "encrypted_content", "encrypted_content": ciphertext}]
                },
            },
            {
                "type": "agent_message",
                "content": [
                    {"type": "encrypted_content", "encrypted_content": ciphertext},
                    {"type": "input_text", "text": ciphertext},
                ],
                "metadata": {
                    "content": [{"type": "encrypted_content", "encrypted_content": ciphertext}]
                },
            },
            {
                "type": "agent_message",
                "content": [{"type": "encrypted_content", "encrypted_content": malformed}],
            },
        ]
    }

    result = redactor.redact_payload(payload, protocol="openai-responses")
    items = result.value["input"]

    assert items[0]["content"][0]["encrypted_content"] != ciphertext
    assert items[1]["content"][0]["encrypted_content"] != ciphertext
    assert items[1]["metadata"]["content"][0]["encrypted_content"] != ciphertext
    assert items[2]["content"][0]["encrypted_content"] == ciphertext
    assert items[2]["content"][1]["text"] != ciphertext
    assert items[2]["metadata"]["content"][0]["encrypted_content"] != ciphertext
    assert items[3]["content"][0]["encrypted_content"] != malformed

    generic = redactor.redact_payload(payload)
    assert generic.value["input"][0]["content"][0]["encrypted_content"] != ciphertext
    assert generic.value["input"][2]["content"][0]["encrypted_content"] != ciphertext


def test_redacts_nested_openai_key() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    payload = {
        "messages": [
            {
                "role": "user",
                "content": f"debug this OPENAI_API_KEY={OPENAI_FAKE}",
            }
        ]
    }

    result = redactor.redact_payload(payload)

    content = result.value["messages"][0]["content"]
    assert OPENAI_FAKE not in content
    assert result.stats.redactions >= 1


def test_provider_api_keys_are_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    text = "\n".join(f"{name}={value}" for name, value in PROVIDER_FIXTURES.items())

    result = redactor.redact_text(text)

    for value in PROVIDER_FIXTURES.values():
        assert value not in result.value
    assert result.stats.redactions >= len(PROVIDER_FIXTURES)


def test_expanded_provider_tokens_are_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    text = "\n".join(f"{name}={value}" for name, value in EXPANDED_PROVIDER_FIXTURES.items())

    result = redactor.redact_text(text)

    for value in EXPANDED_PROVIDER_FIXTURES.values():
        assert value not in result.value
    assert result.stats.redactions >= len(EXPANDED_PROVIDER_FIXTURES)


def test_requested_ai_provider_credentials_are_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    payload = {
        "OPENAI_API_KEY": PROVIDER_FIXTURES["openai_key"],
        "GEMINI_API_KEY": PROVIDER_FIXTURES["gemini_api_key"],
        "ANTHROPIC_API_KEY": PROVIDER_FIXTURES["anthropic_api_key"],
        "DEEPSEEK_API_KEY": PROVIDER_FIXTURES["deepseek_api_key"],
        "MINIMAX_API_KEY": PROVIDER_FIXTURES["minimax_api_key"],
        "FIREWORKS_API_KEY": PROVIDER_FIXTURES["fireworks_api_key"],
        "XAI_API_KEY": PROVIDER_FIXTURES["xai_api_key"],
        "ZAI_API_KEY": "zai-provider-token-without-stable-prefix",
        "CODEX_API_KEY": "codex-provider-token-without-stable-prefix",
        "CODEX_ACCESS_TOKEN": "codex-access-token-without-stable-prefix",
    }

    result = redactor.redact_payload(payload)

    for value in payload.values():
        assert value not in result.value.values()
    assert set(result.value.values()) == {"[REDACTED_SECRET]"}
    assert result.stats.rule_hits["sensitive_field"] == len(payload)


def test_aws_camel_case_secret_fields_are_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    secret = "OpaqueFixtureToken0000000000000000000000"
    payload = {
        "secretKey": secret,
        "secretAccessKey": secret,
        "awsSecretAccessKey": secret,
        "accountKey": secret,
    }

    result = redactor.redact_payload(payload)

    assert set(result.value.values()) == {"[REDACTED_SECRET]"}
    assert result.stats.rule_hits["sensitive_field"] == len(payload)


def test_cloudflare_headers_are_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    cloudflare_key = EXPANDED_PROVIDER_FIXTURES["cloudflare_api_key"]
    text = "\n".join(
        [
            f"X-Auth-Key: {cloudflare_key}",
            f"CF-Access-Token: {cloudflare_key}",
            f"CLOUDFLARE_API_TOKEN={cloudflare_key}",
        ]
    )

    result = redactor.redact_text(text)

    assert cloudflare_key not in result.value
    assert result.value.count("[REDACTED_SECRET]") == 3


def test_signed_url_query_parameters_are_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    aws_signature = "a" * 64
    google_signature = "b" * 64
    azure_signature = "c" * 64
    text = "\n".join(
        [
            "https://bucket.s3.amazonaws.com/object"
            "?X-Amz-" + "Credential=AKIAEXAMPLE%2F20260619%2Fus-east-1%2Fs3%2Faws4_request"
            "&X-Amz-" + f"Signature={aws_signature}",
            "https://storage.googleapis.com/bucket/object"
            "?Google" + "AccessId=service@example.iam.gserviceaccount.com"
            "&X-Goog-" + f"Signature={google_signature}",
            "https://acct.blob.core.windows.net/container/blob?sv=2025-11-05&"
            "si" + f"g={azure_signature}",
        ]
    )

    result = redactor.redact_text(text)

    assert aws_signature not in result.value
    assert google_signature not in result.value
    assert azure_signature not in result.value
    assert "X-Amz-Signature=[REDACTED_SECRET]" in result.value
    assert "X-Goog-Signature=[REDACTED_SECRET]" in result.value
    assert "sig=[REDACTED_SECRET]" in result.value


def test_pgp_and_encrypted_private_keys_are_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    encrypted_key = (
        "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\n"
        "FixtureToken000000000000000000000\n"
        "-----END " + "ENCRYPTED PRIVATE KEY-----"
    )
    pgp_key = (
        "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\n"
        "FixtureToken000000000000000000000\n"
        "-----END " + "PGP PRIVATE KEY BLOCK-----"
    )

    result = redactor.redact_text(f"{encrypted_key}\n{pgp_key}")

    assert encrypted_key not in result.value
    assert pgp_key not in result.value
    assert result.value.count("[REDACTED_SECRET]") == 2


def test_prefixed_labeled_unknown_secret_is_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    unknown_token = "opaque-provider-token-without-known-prefix"

    result = redactor.redact_text(f"CLOUDFLARE_API_KEY={unknown_token}")

    assert unknown_token not in result.value
    assert result.value == "CLOUDFLARE_API_KEY=[REDACTED_SECRET]"


def test_authorization_header_value_is_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    bearer = "opaqueBearerTokenWithoutKnownPrefix"

    result = redactor.redact_text(f"Authorization: Bearer {bearer}")

    assert bearer not in result.value
    assert result.value == "Authorization: Bearer [REDACTED_SECRET]"


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
def test_json_authorization_header_value_is_redacted(
    engine: Literal["basic", "detect-secrets"],
) -> None:
    redactor = SecretRedactor(RedactionConfig(engine=engine))
    bearer = "FixtureToken000000000000000000000"
    text = json.dumps({"Authorization": f"Bearer {bearer}"})

    result = redactor.redact_text(text)

    assert bearer not in result.value
    assert result.value == '{"Authorization": "Bearer [REDACTED_SECRET]"}'


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "Authorization=Bearer FixtureToken000000000000000000000",
            "Authorization=Bearer [REDACTED_SECRET]",
        ),
        (
            'client_secret="FixtureToken000000000000000000000"',
            'client_secret="[REDACTED_SECRET]"',
        ),
        (
            '{"client_secret": "FixtureToken000000000000000000000"}',
            '{"client_secret": "[REDACTED_SECRET]"}',
        ),
    ],
)
def test_auth_and_assignment_redaction_preserves_surrounding_syntax(
    text: str, expected: str
) -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))

    result = redactor.redact_text(text)

    assert result.value == expected


@pytest.mark.parametrize(
    "text",
    [
        '{"AuthorizationMode": "Bearer FixtureToken000000000000000000000"}',
        'Document the "Authorization" header with a Bearer token.',
        '{"client_secret_note": "use a secret from the environment"}',
    ],
)
def test_auth_and_assignment_patterns_avoid_similar_prose_and_fields(text: str) -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))

    result = redactor.redact_text(text)

    assert result.value == text
    assert result.stats.redactions == 0


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
@pytest.mark.parametrize(
    "text",
    [
        'api_key = os.environ["OPENAI_API_KEY"]',
        'token = settings.credentials.get("access_token")',
        "client_secret = load_config().client_secret",
        'authorization = os.getenv("AUTHORIZATION")',
        '```python\napi_key = os.environ["OPENAI_API_KEY"]\n```',
    ],
)
def test_code_references_are_not_credentials(
    engine: Literal["basic", "detect-secrets"], text: str
) -> None:
    result = SecretRedactor(RedactionConfig(engine=engine)).redact_text(text)

    assert result.value == text
    assert result.stats.redactions == 0


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
def test_explicit_credential_placeholder_is_preserved(
    engine: Literal["basic", "detect-secrets"],
) -> None:
    text = 'password = "<your-password-here>"; token = "<OpaqueFixtureCredential>"'
    result = SecretRedactor(RedactionConfig(engine=engine)).redact_text(text)

    assert result.value == 'password = "<your-password-here>"; token = "[REDACTED_SECRET]"'


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
@pytest.mark.parametrize(
    "secret", ["os.environ", "load_config().client_secret", "OpaqueFixtureValue"]
)
def test_quoted_code_shaped_credentials_are_still_redacted(
    engine: Literal["basic", "detect-secrets"], secret: str
) -> None:
    text = f'api_key = "{secret}"'
    result = SecretRedactor(RedactionConfig(engine=engine)).redact_text(text)

    assert result.value == 'api_key = "[REDACTED_SECRET]"'


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
@pytest.mark.parametrize("annotation", [" (production)", " [production]", " (rotated yesterday)"])
def test_unquoted_credential_with_annotation_is_still_redacted(
    engine: Literal["basic", "detect-secrets"], annotation: str
) -> None:
    secret = "OpaqueFixtureValue123"
    result = SecretRedactor(RedactionConfig(engine=engine)).redact_text(
        f"api_key = {secret}{annotation}"
    )

    assert secret not in result.value


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
def test_code_reference_exemption_is_per_occurrence(
    engine: Literal["basic", "detect-secrets"],
) -> None:
    text = 'client_secret = load_config().client_secret; password = "load_config().client_secret"'
    result = SecretRedactor(RedactionConfig(engine=engine)).redact_text(text)

    assert result.value == (
        'client_secret = load_config().client_secret; password = "[REDACTED_SECRET]"'
    )


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
def test_provider_key_inside_code_reference_is_still_redacted(
    engine: Literal["basic", "detect-secrets"],
) -> None:
    text = f'api_key = os.getenv("OPENAI_API_KEY", "{OPENAI_FAKE}")'
    result = SecretRedactor(RedactionConfig(engine=engine)).redact_text(text)

    assert result.value == 'api_key = os.getenv("OPENAI_API_KEY", "[REDACTED_SECRET]")'


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
@pytest.mark.parametrize("secret", ["load_config().client_secret", "<your-password-here>"])
def test_custom_rule_still_redacts_code_references(
    engine: Literal["basic", "detect-secrets"],
    secret: str,
) -> None:
    config = RedactionConfig(engine=engine, rules=[RuleConfig(type="exact", value=secret)])

    result = SecretRedactor(config).redact_text(f"client_secret = {secret}")

    assert result.value == "client_secret = [REDACTED_SECRET]"


def test_connection_string_password_is_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    password = "db-password-without-known-prefix"

    result = redactor.redact_text(f"postgresql://user:{password}@localhost/app")

    assert password not in result.value
    assert result.value == "postgresql://user:[REDACTED_SECRET]@localhost/app"


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
@pytest.mark.parametrize(
    "scheme",
    [
        "rediss",
        "amqp",
        "amqps",
        "mariadb",
        "mariadb+mariadbconnector",
        "postgresql+asyncpg",
        "postgres+psycopg",
        "mysql+pymysql",
        "clickhouse",
        "clickhouses",
        "clickhouse+native",
        "clickhousedb",
        "clickhousedb+connect",
        "POSTGRESQL+ASYNCPG",
    ],
)
def test_expanded_dsn_schemes_redact_url_credentials(
    engine: Literal["basic", "detect-secrets"], scheme: str
) -> None:
    redactor = SecretRedactor(RedactionConfig(engine=engine))
    password = "dsn-password-without-known-prefix"
    dsn = f"{scheme}://service_user:{password}@db.internal:5432/prod"

    result = redactor.redact_text(dsn)

    assert password not in result.value
    assert result.value == f"{scheme}://service_user:[REDACTED_SECRET]@db.internal:5432/prod"
    if engine == "basic":
        assert result.stats.rule_hits == {"url_credentials": 1}
    else:
        assert result.stats.redactions >= 1


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
def test_new_provider_prefixes_redact_standalone_and_comma_separated(
    engine: Literal["basic", "detect-secrets"],
) -> None:
    redactor = SecretRedactor(RedactionConfig(engine=engine))
    tokens: list[tuple[str, str, str]] = [
        ("groq_api_key", "groq_api_key", PROVIDER_FIXTURES["groq_api_key"]),
        ("perplexity_api_key", "perplexity_api_key", PROVIDER_FIXTURES["perplexity_api_key"]),
        ("cerebras_api_key", "cerebras_api_key", PROVIDER_FIXTURES["cerebras_api_key"]),
        ("replicate_api_token", "replicate_api_token", PROVIDER_FIXTURES["replicate_api_token"]),
        ("tavily_api_key", "tavily_api_key", PROVIDER_FIXTURES["tavily_api_key"]),
        ("tavily_bare_key", "tavily_api_key", "tvl" + "y-" + ("B" * 32)),
        ("supabase_pat", "supabase_token", EXPANDED_PROVIDER_FIXTURES["supabase_pat"]),
        ("supabase_pat_v0", "supabase_token", "sb" + "p_v0_" + ("b" * 40)),
        ("supabase_oauth", "supabase_token", "sb" + "p_oauth_" + ("c" * 40)),
        (
            "supabase_secret_key",
            "supabase_token",
            EXPANDED_PROVIDER_FIXTURES["supabase_secret_key"],
        ),
        ("tailscale_key", "tailscale_key", EXPANDED_PROVIDER_FIXTURES["tailscale_key"]),
        (
            "tailscale_auth_tl",
            "tailscale_key",
            "ts" + "key-auth-k123456-" + ("z" * 28) + "--TL" + ("Q" * 32),
        ),
        ("tailscale_scim_single", "tailscale_key", "ts" + "key-scim-" + ("m" * 32)),
        ("tailscale_webhook", "tailscale_key", "ts" + "key-webhook--" + ("w" * 28)),
        ("grafana_sa_token", "grafana_token", EXPANDED_PROVIDER_FIXTURES["grafana_sa_token"]),
        ("grafana_sa_upper", "grafana_token", "gl" + "sa_" + ("A" * 32) + "_" + ("F" * 8)),
        ("grafana_cloud_token", "grafana_token", EXPANDED_PROVIDER_FIXTURES["grafana_cloud_token"]),
        ("postman_api_key", "postman_api_key", EXPANDED_PROVIDER_FIXTURES["postman_api_key"]),
        ("planetscale_token", "planetscale_token", EXPANDED_PROVIDER_FIXTURES["planetscale_token"]),
        (
            "planetscale_oauth_padded",
            "planetscale_token",
            "psc" + "ale_oauth_" + ("B" * 16) + ".-" + ("C" * 18) + "=",
        ),
        ("neon_api_key", "neon_api_key", EXPANDED_PROVIDER_FIXTURES["neon_api_key"]),
        (
            "vercel_access_token",
            "vercel_access_token",
            EXPANDED_PROVIDER_FIXTURES["vercel_access_token"],
        ),
    ]

    for label, expected_rule, token in tokens:
        standalone = redactor.redact_text(f"seen in log {token} after.")
        assert token not in standalone.value, label
        assert standalone.value == "seen in log [REDACTED_SECRET] after.", label
        if engine == "basic":
            assert standalone.stats.rule_hits == {expected_rule: 1}, label

    comma_joined = ",".join(token for _, _, token in tokens)
    comma_result = redactor.redact_text(comma_joined)
    for label, _, token in tokens:
        assert token not in comma_result.value, label
    assert comma_result.value == ",".join("[REDACTED_SECRET]" for _ in tokens)


def test_comma_separated_provider_api_keys_are_redacted() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    text = ", ".join(PROVIDER_FIXTURES.values())

    result = redactor.redact_text(text)

    for value in PROVIDER_FIXTURES.values():
        assert value not in result.value
    assert result.value.count("[REDACTED_SECRET]") >= len(PROVIDER_FIXTURES)


def test_gemini_key_is_fully_redacted_by_default() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    fake_gemini_key = PROVIDER_FIXTURES["gemini_api_key"]

    result = redactor.redact_text(f"GEMINI_API_KEY={fake_gemini_key}")

    assert fake_gemini_key not in result.value
    assert result.value == "GEMINI_API_KEY=[REDACTED_SECRET]"


def test_comma_separated_assignment_redacts_each_provider_key() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    values = [
        PROVIDER_FIXTURES["openai_key"],
        PROVIDER_FIXTURES["gemini_api_key"],
        PROVIDER_FIXTURES["anthropic_api_key"],
    ]

    result = redactor.redact_text(f"API_KEYS={','.join(values)}")

    for value in values:
        assert value not in result.value
    assert result.value.count("[REDACTED_SECRET]") >= len(values)


def test_detect_secrets_engine_redacts_api_key_assignment() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))

    result = redactor.redact_text(f"OPENAI_API_KEY={OPENAI_FAKE}")

    assert OPENAI_FAKE not in result.value
    assert any(name.startswith("detect_secrets:") for name in result.stats.rule_hits)


def test_detect_secrets_scans_in_memory(monkeypatch) -> None:
    def reject_temp_file(*_args, **_kwargs):
        raise AssertionError("redaction attempted to write a temporary file")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", reject_temp_file)
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))

    result = redactor.redact_text(f"OPENAI_API_KEY={OPENAI_FAKE}")

    assert OPENAI_FAKE not in result.value


def test_detect_secrets_scans_multiline_text_in_memory() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    text = f"first=value\nOPENAI_API_KEY={OPENAI_FAKE}\nlast=value"

    result = redactor.redact_text(text)

    assert OPENAI_FAKE not in result.value
    assert result.value.splitlines()[0] == "first=value"
    assert result.value.splitlines()[2] == "last=value"


def test_detect_secrets_scan_does_not_make_network_requests(monkeypatch) -> None:
    def reject_network(*_args, **_kwargs):
        raise AssertionError("redaction attempted a network request")

    monkeypatch.setattr(requests.sessions.Session, "request", reject_network)
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    stripe_fixture = "sk_" + "live_" + ("A" * 24)

    result = redactor.redact_text(f"STRIPE_API_KEY={stripe_fixture}")

    assert stripe_fixture not in result.value


def test_detect_secrets_engine_does_not_redact_entropy_only_string() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="detect-secrets"))
    token_like_text = "value=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    result = redactor.redact_text(token_like_text)

    assert result.value == token_like_text
    assert result.stats.redactions == 0


def test_tail_rule_redacts_full_token() -> None:
    redactor = SecretRedactor(
        RedactionConfig(
            engine="basic",
            rules=[RuleConfig(type="exact", value="abcd1234", name="tail")],
        )
    )

    result = redactor.redact_text("token=pl_live_9999999999999999abcd1234")

    assert "9999999999999999abcd1234" not in result.value
    assert result.stats.rule_hits["tail"] == 1


def test_tail_rule_supports_non_word_base64_endings() -> None:
    redactor = SecretRedactor(
        RedactionConfig(
            engine="basic",
            rules=[RuleConfig(type="exact", value="abcd123=", name="base64-tail")],
        )
    )

    result = redactor.redact_text("secret=FixtureToken000000abcd123=")

    assert result.value == "secret=[REDACTED_SECRET]"
    assert result.stats.rule_hits["base64-tail"] == 1


def test_custom_rule_names_cannot_select_builtin_replacement_logic() -> None:
    redactor = SecretRedactor(
        RedactionConfig(
            engine="basic",
            rules=[RuleConfig(type="regex", value="fixture-[0-9]+", name="assigned_secret")],
        )
    )

    result = redactor.redact_text("fixture-123456")

    assert result.value == "[REDACTED_SECRET]"
    assert result.stats.rule_hits["assigned_secret"] == 1


def test_payload_redacts_secret_shaped_mapping_keys() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    secret_key = "sk-" + "FixtureToken" + ("0" * 24)

    result = redactor.redact_payload({secret_key: "value"})

    assert result.value == {"[REDACTED_SECRET]": "value"}
    assert result.stats.rule_hits["openai_key"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        {
            OPENAI_FAKE: "first",
            PROVIDER_FIXTURES["deepseek_api_key"]: "second",
        },
        {
            "nested": {
                OPENAI_FAKE: "first",
                PROVIDER_FIXTURES["deepseek_api_key"]: "second",
            }
        },
    ],
)
def test_payload_rejects_redacted_mapping_key_collisions(payload: dict) -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))

    with pytest.raises(RedactionKeyCollisionError):
        redactor.redact_payload(payload)


def test_explicit_secret_fields_redact_short_and_numeric_values() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic"))
    secret_key = "sk-" + "FixtureToken" + ("0" * 24)

    result = redactor.redact_payload(
        {
            "password": "short",
            "databasePassword": 123456,
            "credentials": {secret_key: "value"},
            "max_tokens": 1024,
        }
    )

    assert result.value == {
        "password": "[REDACTED_SECRET]",
        "databasePassword": "[REDACTED_SECRET]",
        "credentials": {"[REDACTED_SECRET]": "[REDACTED_SECRET]"},
        "max_tokens": 1024,
    }


def test_generic_assignment_preserves_key_name() -> None:
    redactor = SecretRedactor(RedactionConfig(engine="basic", redact_mode="full"))

    result = redactor.redact_text('password = "correct-horse-battery-staple"')

    assert "password" in result.value
    assert "correct-horse" not in result.value
    assert "[REDACTED_SECRET]" in result.value


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
def test_tagged_mode_emits_consistent_hmac_tags_across_rules_and_turns(
    engine: Literal["basic", "detect-secrets"],
) -> None:
    redactor = SecretRedactor(
        RedactionConfig(
            engine=engine,
            redact_mode="tagged",
            rules=[RuleConfig(type="exact", value="abcd1234", name="internal-tail")],
        )
    )
    other_openai = "sk-" + "proj-DifferentFixtureToken000000000000"
    shared_password = "shared-db-password-998877"

    payload = {
        "api_key": OPENAI_FAKE,
        "databasePassword": 987654321,
        "messages": [
            {"role": "user", "content": f"first={OPENAI_FAKE} second={other_openai}"},
            {
                "role": "user",
                "content": (
                    f"postgresql://svc:{shared_password}@db.internal/app "
                    f'password="{shared_password}" '
                    f"Authorization: Bearer {shared_password} "
                    "https://storage.example/obj?si"
                    f"g={shared_password}&ok=1 "
                    "custom=pl_live_999999999999abcd1234"
                ),
            },
        ],
        "key_map": {
            OPENAI_FAKE: "primary",
            other_openai: "secondary",
        },
    }

    first = redactor.redact_payload(payload)
    serialized = json.dumps(first.value)
    assert OPENAI_FAKE not in serialized
    assert other_openai not in serialized
    assert shared_password not in serialized
    assert "999999999999abcd1234" not in serialized

    field_match = re.fullmatch(
        r"\[REDACTED:sensitive_field#([0-9a-f]{8})\]", first.value["api_key"]
    )
    assert field_match is not None
    openai_tag = field_match.group(1)

    msg0 = first.value["messages"][0]["content"]
    msg0_tags = re.findall(r"\[REDACTED:([A-Za-z0-9_.-]+)#([0-9a-f]{8})\]", msg0)
    assert len(msg0_tags) == 2
    assert msg0_tags[0][1] == openai_tag
    assert msg0_tags[1][1] != openai_tag

    msg1 = first.value["messages"][1]["content"]
    msg1_matches = re.findall(r"\[REDACTED:([A-Za-z0-9_.-]+)#([0-9a-f]{8})\]", msg1)
    assert len(msg1_matches) == 5
    shared_tags = {tag for _, tag in msg1_matches[:4]}
    assert len(shared_tags) == 1
    assert msg1_matches[4][0] == "internal-tail"

    # Re-scanning already-redacted multi-turn payload is strictly idempotent.
    rescan = redactor.redact_payload(first.value)
    assert rescan.value == first.value
    assert rescan.stats.redactions == 0
    assert rescan.stats.rule_hits == {}

    # Also verify idempotency on a fresh redactor sharing tag_key (bypassing in-memory cache).
    keyed_config = RedactionConfig(
        engine=engine,
        redact_mode="tagged",
        tag_key="deterministic-test-tag-key-0123",
        rules=[RuleConfig(type="exact", value="abcd1234", name="internal-tail")],
    )
    first_keyed = SecretRedactor(keyed_config).redact_payload(payload)
    second_keyed = SecretRedactor(keyed_config).redact_payload(first_keyed.value)
    assert second_keyed.value == first_keyed.value
    assert second_keyed.stats.redactions == 0


def test_tagged_mode_key_isolation_inheritance_and_validation(monkeypatch) -> None:
    one = SecretRedactor(RedactionConfig(engine="basic", redact_mode="tagged"))
    two = SecretRedactor(RedactionConfig(engine="basic", redact_mode="tagged"))
    child = SecretRedactor(RedactionConfig(engine="basic", redact_mode="tagged"), _cache_from=one)

    out_one = one.redact_text(OPENAI_FAKE).value
    out_two = two.redact_text(OPENAI_FAKE).value
    out_child = child.redact_text(OPENAI_FAKE).value
    assert out_one == out_child
    assert out_one != out_two

    monkeypatch.setenv("TEST_TAG_KEY_ENV", "01234567890123456789")
    env_cfg = RedactionConfig(engine="basic", redact_mode="tagged", tag_key="${TEST_TAG_KEY_ENV}")
    direct_cfg = RedactionConfig(
        engine="basic", redact_mode="tagged", tag_key="01234567890123456789"
    )
    assert (
        SecretRedactor(env_cfg).redact_text(OPENAI_FAKE).value
        == SecretRedactor(direct_cfg).redact_text(OPENAI_FAKE).value
    )

    with pytest.raises(ValueError, match="at least 16 characters"):
        RedactionConfig(redact_mode="tagged", tag_key="too-short")

    monkeypatch.setenv("SHORT_TAG_KEY", "short")
    with pytest.raises(ValueError, match="at least 16 characters"):
        SecretRedactor(RedactionConfig(redact_mode="tagged", tag_key="${SHORT_TAG_KEY}"))

    monkeypatch.delenv("UNSET_TAG_KEY_ENV", raising=False)
    with pytest.raises(ValueError, match="UNSET_TAG_KEY_ENV is not set"):
        SecretRedactor(RedactionConfig(redact_mode="tagged", tag_key="${UNSET_TAG_KEY_ENV}"))

    monkeypatch.setenv("EMPTY_TAG_KEY_ENV", "")
    with pytest.raises(ValueError, match="EMPTY_TAG_KEY_ENV is not set"):
        SecretRedactor(RedactionConfig(redact_mode="tagged", tag_key="${EMPTY_TAG_KEY_ENV}"))

    with pytest.raises(ValueError, match="at least 16 characters"):
        RedactionConfig(redact_mode="tagged", tag_key="")


@pytest.mark.parametrize("engine", ["basic", "detect-secrets"])
def test_tagged_mode_rejects_smuggled_secrets_and_protects_existing_tags(
    engine: Literal["basic", "detect-secrets"],
) -> None:
    redactor = SecretRedactor(
        RedactionConfig(
            engine=engine,
            redact_mode="tagged",
            rules=[RuleConfig(type="regex", value=r"CORP_SECRET\{[^}]+\}", name="corp_secret")],
        )
    )
    smuggled = f"[REDACTED:{OPENAI_FAKE}#00000000]"
    result = redactor.redact_text(smuggled)
    assert OPENAI_FAKE not in result.value
    assert result.stats.redactions >= 1

    # Fake-tag prefix smuggling inside wider secrets or custom rules must still redact fully.
    fake_tag = "[REDACTED:openai_key#00000000]"
    custom_smuggled = f"CORP_SECRET{{{fake_tag}InnerSecret999}}"
    custom_out = redactor.redact_text(custom_smuggled)
    assert "InnerSecret999" not in custom_out.value
    assert re.fullmatch(r"\[REDACTED:corp_secret#[0-9a-f]{8}\]", custom_out.value)

    begin_rsa = "-----BEGIN RSA " + "PRIVATE KEY-----"
    end_rsa = "-----END RSA " + "PRIVATE KEY-----"
    pem_escaped = (
        f"{begin_rsa}\\nMIIEpAIBAAKCAQEA\\nDEK-Info: AES-128-CBC\\n"
        f"SUPER_SECRET_PRIVATE_KEY_MATERIAL_999999999999\\n{end_rsa}"
    )
    pem_out = redactor.redact_text(pem_escaped)
    assert "SUPER_SECRET_PRIVATE_KEY_MATERIAL" not in pem_out.value
    assert re.fullmatch(r"\[REDACTED:private_key#[0-9a-f]{8}\]", pem_out.value)

    pem_smuggled = f"{begin_rsa}\nComment: {fake_tag}\nSECRET_PEM_BODY_123456\n{end_rsa}"
    pem_smuggled_out = redactor.redact_text(pem_smuggled)
    assert "SECRET_PEM_BODY_123456" not in pem_smuggled_out.value
    assert re.fullmatch(r"\[REDACTED:private_key#[0-9a-f]{8}\]", pem_smuggled_out.value)

    # Signed URL query parameters with embedded tags, prefixes, or suffixes must not leak or slice.
    aws_id = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    url_suffix = "https://example.com/hook?si" + f"g={aws_id}.secret_hmac_tail_9999&ok=1"
    url_suffix_out = redactor.redact_text(url_suffix).value
    assert "secret_hmac_tail_9999" not in url_suffix_out
    assert re.fullmatch(
        r"https://example\.com/hook\?si"
        + r"g=\[REDACTED:signed_url_query_param#[0-9a-f]{8}\]&ok=1",
        url_suffix_out,
    )

    url_prefix = "https://example.com/hook?si" + f"g=v1:{OPENAI_FAKE}&ok=1#frag"
    url_prefix_out = redactor.redact_text(url_prefix).value
    assert OPENAI_FAKE not in url_prefix_out
    assert re.fullmatch(
        r"https://example\.com/hook\?si"
        + r"g=\[REDACTED:signed_url_query_param#[0-9a-f]{8}\]&ok=1#frag",
        url_prefix_out,
    )
    assert redactor.redact_text(url_prefix_out).stats.redactions == 0

    # A secret matching a valid tag label word must not corrupt an earlier emitted tag.
    tricky = f'first={OPENAI_FAKE}\npassword="openai_key"'
    tricky_result = redactor.redact_text(tricky)
    lines = tricky_result.value.splitlines()
    assert re.fullmatch(r"first=\[REDACTED:[A-Za-z0-9_.-]+#[0-9a-f]{8}\]", lines[0])
    assert re.fullmatch(r'password="\[REDACTED:[A-Za-z0-9_.-]+#[0-9a-f]{8}\]"', lines[1])


def test_tagged_mode_detect_secrets_edge_cases_and_extra_rule_idempotency() -> None:
    tag_key = "deterministic-edge-case-tag-key-01"
    cfg = RedactionConfig(
        engine="detect-secrets",
        redact_mode="tagged",
        tag_key=tag_key,
        rules=[RuleConfig(type="exact", value="srvr9999", name="server-tail")],
    )
    parent = SecretRedactor(cfg)

    # Fake-tag prefix inside quoted keyword secret and comma-separated secrets.
    fake_tag = "[REDACTED:openai_key#00000000]"
    kw_smuggled = f'password = "{fake_tag}MyRealDatabasePassword999!"'
    kw_out = parent.redact_text(kw_smuggled)
    assert "MyRealDatabasePassword999" not in kw_out.value
    assert re.fullmatch(r'password = "\[REDACTED:[A-Za-z0-9_.-]+#[0-9a-f]{8}\]"', kw_out.value)
    assert SecretRedactor(cfg).redact_text(kw_out.value).stats.redactions == 0

    # Protected tag adjacent to AWS secret key, Cloudant, or SoftLayer must preserve \W boundaries.
    aws_sec = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
    aws_adj = parent.redact_text(f"aws_key={fake_tag}{aws_sec}").value
    assert "EXAMPLEKEY" not in aws_adj

    hex64 = "a1b2c3d4" * 8
    cloudant_adj = parent.redact_text(f"{fake_tag}cloudant_key={hex64}").value
    assert hex64 not in cloudant_adj
    softlayer_adj = parent.redact_text(f"{fake_tag}softlayer_key={hex64}").value
    assert hex64 not in softlayer_adj

    comma_text = f'api_key = "{OPENAI_FAKE},{PROVIDER_FIXTURES["gemini_api_key"]}"'
    comma_out = parent.redact_text(comma_text)
    assert OPENAI_FAKE not in comma_out.value
    assert PROVIDER_FIXTURES["gemini_api_key"] not in comma_out.value
    comma_rescan = SecretRedactor(cfg).redact_text(comma_out.value)
    assert comma_rescan.value == comma_out.value
    assert comma_rescan.stats.redactions == 0

    # Emitted [REDACTED:label#hex] must not flip detect-secrets INI transformers on Turn 2.
    prose_and_short = f"Here is {OPENAI_FAKE}\nsecret = short1"
    turn1 = parent.redact_text(prose_and_short)
    assert turn1.stats.redactions == 1
    assert turn1.value.endswith("\nsecret = short1")
    turn2 = SecretRedactor(cfg).redact_text(turn1.value)
    assert turn2.value == turn1.value
    assert turn2.stats.redactions == 0

    # Child redactors (_cache_from) register safe extra rule labels for later turns
    # without the header, while sanitizing builtin and server-custom secret-shaped rule names.
    child_cfg = RedactionConfig(
        engine="detect-secrets",
        redact_mode="tagged",
        tag_key=tag_key,
        rules=[
            *cfg.rules,
            RuleConfig(type="exact", value="abcd1234", name="extra-tail"),
            RuleConfig(type="exact", value="efgh5678", name=OPENAI_FAKE[:40]),
            RuleConfig(type="exact", value="ijkl9012", name="pl_live_99999999srvr9999"),
        ],
    )
    child = SecretRedactor(child_cfg, _cache_from=parent)
    extra_input = (
        "https://storage.example/obj?si"
        + "g=pl_live_99999999abcd1234&ok=1 "
        + "other=pl_live_99999999efgh5678 "
        + "third=pl_live_99999999ijkl9012"
    )
    child_turn1 = child.redact_text(extra_input)
    assert OPENAI_FAKE[:20] not in child_turn1.value
    assert "srvr9999" not in child_turn1.value
    assert "[REDACTED:extra-tail#" in child_turn1.value
    assert "[REDACTED:custom_rule#" in child_turn1.value
    parent_turn2 = parent.redact_text(child_turn1.value)
    assert parent_turn2.value == child_turn1.value
    assert parent_turn2.stats.redactions == 0
    smuggled_server_tail = parent.redact_text("[REDACTED:pl_live_99999999srvr9999#00000000]")
    assert "srvr9999" not in smuggled_server_tail.value
    assert smuggled_server_tail.stats.redactions >= 1


def test_detect_secrets_plugin_captures_preserve_full_pat_and_clean_delimiters() -> None:
    pat40 = "gh" + "p_" + ("A" * 36)
    for mode in ("full", "tagged"):
        redactor = SecretRedactor(RedactionConfig(engine="detect-secrets", redact_mode=mode))
        out = redactor.redact_text(f"token={pat40}").value
        assert "AAAA" not in out
        if mode == "full":
            assert out == "token=[REDACTED_SECRET]"
        else:
            assert re.fullmatch(r"token=\[REDACTED:github_token#[0-9a-f]{8}\]", out)

    tagged = SecretRedactor(RedactionConfig(engine="detect-secrets", redact_mode="tagged"))
    artifactory = "AK" + "C" + ("aB3" * 8)
    art1 = tagged.redact_text(f"artifactory: {artifactory}").value
    art2 = tagged.redact_text(f'artifactory="{artifactory}"').value
    art3 = tagged.redact_payload({"api_key": artifactory}).value["api_key"]
    assert art1.startswith("artifactory: [REDACTED:")
    assert art2.startswith('artifactory="[REDACTED:') and art2.endswith(']"')
    tag1 = re.search(r"#([0-9a-f]{8})\]", art1)
    tag2 = re.search(r"#([0-9a-f]{8})\]", art2)
    tag3 = re.search(r"#([0-9a-f]{8})\]", art3)
    assert tag1 and tag2 and tag3
    assert tag1.group(1) == tag2.group(1) == tag3.group(1)

    import random

    rng = random.Random(42)
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    azure = "".join(rng.choice(b64) for _ in range(86)) + "=="
    az1 = tagged.redact_text(f"AccountKey={azure};").value
    az2 = tagged.redact_text(f'AccountKey="{azure}"').value
    az_tag1 = re.search(r"#([0-9a-f]{8})\]", az1)
    az_tag2 = re.search(r"#([0-9a-f]{8})\]", az2)
    assert az2.startswith('AccountKey="[REDACTED:') and az2.endswith(']"')
    assert az_tag1 and az_tag2
    assert az_tag1.group(1) == az_tag2.group(1)


def test_tagged_mode_derivation_cap_degrades_safely_without_poisoning_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("promptlatch.redaction._MAX_TAG_DERIVATIONS_PER_CALL", 2)
    redactor = SecretRedactor(
        RedactionConfig(engine="basic", redact_mode="tagged", placeholder="CUSTOM_MASK")
    )
    tok1 = "sk-" + ("A" * 24)
    tok2 = "sk-" + ("B" * 24)
    tok3 = "sk-" + ("C" * 24)
    tok4 = "sk-" + ("D" * 24)
    sig_q = "?si" + "g=[REDACTED_SECRET]"
    result = redactor.redact_payload(
        {
            "api_key": "[REDACTED_SECRET]",
            "items": [
                f"a {tok1} {tok1}",
                f"b {tok2}",
                f"https://u:{tok3}@example.com/1 https://u:{tok4}@example.com/2",
                f"https://storage.example/obj{sig_q}",
            ],
        }
    )
    assert result.value["api_key"] == "[REDACTED_SECRET]"
    items = result.value["items"]
    assert items[0].count("[REDACTED:openai_key#") == 2
    assert items[1].startswith("b [REDACTED:openai_key#")
    assert items[2] == (
        "https://u:[REDACTED_SECRET]@example.com/1 https://u:[REDACTED_SECRET]@example.com/2"
    )
    assert items[3] == f"https://storage.example/obj{sig_q}"
    rescan = SecretRedactor(RedactionConfig(engine="basic", redact_mode="tagged")).redact_payload(
        result.value
    )
    assert rescan.value == result.value
    assert rescan.stats.redactions == 0
    # Because items[2] hit the per-call cap, it was not cached and derives a tag on a fresh call.
    fresh = redactor.redact_text(f"c {tok3}")
    assert fresh.value.startswith("c [REDACTED:openai_key#")

    cfg = RedactionConfig(engine="basic", redact_mode="tagged", tag_key="first-tag-key-0123456789")
    mutable = SecretRedactor(cfg)
    first_out = mutable.redact_text(OPENAI_FAKE).value
    cfg.tag_key = "second-tag-key-9876543210"
    second_out = mutable.redact_text(OPENAI_FAKE).value
    assert first_out != second_out

    full_with_key = SecretRedactor(
        RedactionConfig(engine="basic", redact_mode="full", tag_key="unused-tag-key-0123456789")
    )
    assert full_with_key._derived_tag_pair is None

    partial = SecretRedactor(RedactionConfig(engine="basic", redact_mode="partial"))
    assert partial.redact_payload({"password": "my-long-secret-password"}).value == {
        "password": "[REDACTED_SECRET]"
    }
