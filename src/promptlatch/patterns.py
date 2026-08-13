from __future__ import annotations

import re

SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(?:^|[_.-])(?:api[_-]?keys?|client[_-]?secrets?|secrets?|passwords?|passwd|"
    r"pwd|tokens?|access[_-]?tokens?|refresh[_-]?tokens?|id[_-]?tokens?|auth|"
    r"authorization|auth[_-]?tokens?|session[_-]?tokens?|private[_-]?keys?|"
    r"secret[_-]?(?:access[_-]?)?keys?|access[_-]?keys?|account[_-]?keys?|"
    r"signing[_-]?keys?|encryption[_-]?keys?|credentials?|webhook[_-]?urls?|"
    r"x[_-]?api[_-]?key|api[_-]?key|x[_-]?auth[_-]?key|x[_-]?auth[_-]?token|"
    r"cf[_-]?access[_-]?token|cloudflare[_-]?api[_-]?(?:key|token)|"
    r"signed[_-]?urls?|presigned[_-]?urls?|sas[_-]?tokens?|dockerconfigjson|"
    r"signature|sig)(?:$|[_.-])"
)

STRICT_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(?:^|[_.-])(?:api[_-]?keys?|client[_-]?secrets?|secrets?|passwords?|passwd|pwd|"
    r"access[_-]?tokens?|refresh[_-]?tokens?|id[_-]?tokens?|auth[_-]?tokens?|"
    r"session[_-]?tokens?|private[_-]?keys?|secret[_-]?(?:access[_-]?)?keys?|"
    r"access[_-]?keys?|account[_-]?keys?|signing[_-]?keys?|encryption[_-]?keys?|"
    r"credentials?|authorization)$"
)

BUILTIN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openrouter_key", re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{20,}\b")),
    ("minimax_key", re.compile(r"\bsk-cp-[A-Za-z0-9_-]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("fireworks_key", re.compile(r"\bfw_[A-Za-z0-9_-]{20,}\b")),
    ("xai_key", re.compile(r"\bxai-[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("atlassian_api_token", re.compile(r"\bATATT3xFfGF0[A-Za-z0-9_-]{20,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{20,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("aws_access_key_extended", re.compile(r"\b(?:A3T[A-Z0-9]|ABIA|ACCA)[A-Z2-7]{16}\b")),
    ("aws_bedrock_api_key", re.compile(r"\bABSK[A-Za-z0-9+/]{80,}={0,2}\b")),
    ("gemini_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("google_oauth_token", re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}\b")),
    ("onepassword_service_account_token", re.compile(r"\bops_eyJ[A-Za-z0-9+/]{120,}={0,3}\b")),
    ("age_secret_key", re.compile(r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b")),
    ("databricks_api_token", re.compile(r"\bdapi[a-f0-9]{32}(?:-\d)?\b")),
    ("digitalocean_token", re.compile(r"\bd(?:op|oo|or)_v1_[a-f0-9]{64}\b")),
    ("huggingface_token", re.compile(r"\b(?:hf_|api_org_)[A-Za-z0-9]{34,}\b")),
    ("linear_api_key", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi_upload_token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000}\b")),
    ("sendgrid_token", re.compile(r"\bSG\.[A-Za-z0-9_.=-]{66}\b")),
    (
        "slack_webhook",
        re.compile(
            r"\bhttps?://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,80}\b"
        ),
    ),
    ("telegram_bot_token", re.compile(r"\b[0-9]{5,16}:A[A-Za-z0-9_-]{34}\b")),
    ("twilio_api_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("vault_token", re.compile(r"\bhv[bs]\.[A-Za-z0-9_-]{80,300}\b")),
    ("shopify_token", re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b")),
    ("sentry_token", re.compile(r"\bsntry[su]_[A-Za-z0-9]{40,}\b")),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
            r"[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    (
        "pgp_private_key",
        re.compile(
            r"-----BEGIN PGP "
            r"PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP "
            r"PRIVATE KEY BLOCK-----"
        ),
    ),
    (
        "signed_url_query_param",
        re.compile(
            r"(?i)([?&](?:x-amz-signature|x-amz-credential|x-amz-security-token|"
            r"x-goog-signature|x-goog-credential|googleaccessid|signature|sig)=)"
            r"([^&#\s]+)"
        ),
    ),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?keys?|client[_-]?secrets?|"
            r"secrets?|passwords?|passwd|pwd|tokens?|access[_-]?tokens?|"
            r"refresh[_-]?tokens?|id[_-]?tokens?|auth[_-]?tokens?|session[_-]?tokens?|"
            r"private[_-]?keys?|credentials?|webhook[_-]?urls?)[A-Za-z0-9_.-]*)"
            r"(\s*[:=]\s*)([\"']?)([^\"'\s;\[\]]{8,})([\"']?)"
        ),
    ),
    (
        "auth_header",
        re.compile(
            r"(?i)\b((?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|"
            r"x-auth-key|cf-access-token)"
            r"\s*[:=]\s*(?:(?:bearer|token|basic|key)\s+)?)([A-Za-z0-9._~+/=-]{8,})"
        ),
    ),
    (
        "url_credentials",
        re.compile(
            r"\b((?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
            r"[^:\s/@]+:)([^@\s/]+)(@)"
        ),
    ),
]

AUDIT_EXCLUDED_PATTERN_NAMES = frozenset({"assigned_secret", "auth_header", "url_credentials"})
