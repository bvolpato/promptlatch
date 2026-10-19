import base64
import binascii
import json
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
