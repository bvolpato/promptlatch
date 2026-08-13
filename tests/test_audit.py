from promptlatch.patterns import AUDIT_EXCLUDED_PATTERN_NAMES, BUILTIN_PATTERNS
from scripts.audit_secrets import PATTERNS


def test_history_audit_uses_runtime_patterns() -> None:
    runtime_names = {
        name for name, _pattern in BUILTIN_PATTERNS if name not in AUDIT_EXCLUDED_PATTERN_NAMES
    }

    assert {name for name, _pattern in PATTERNS} == runtime_names
    assert {
        "aws_bedrock_api_key",
        "digitalocean_token",
        "npm_token",
        "pypi_upload_token",
        "sendgrid_token",
        "vault_token",
    } <= runtime_names
