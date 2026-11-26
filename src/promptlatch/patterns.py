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

# `\b` reads the letter of a `\n` escape, a color code, a percent escape, or CJK text as
# part of the token, so a key right after one of them would not match. Accented Latin
# letters still count as part of a word.
TOKEN_START = (
    r"(?:(?<![A-Za-z0-9_\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u024F])|"
    r"(?<=[\\\[;0-9A-Fa-f].)(?:(?<=\\[nrtbfv])|"
    r"(?<=%[0-9A-Fa-f]{2})|(?<=\\x[0-9A-Fa-f]{2})|(?<=\\u[0-9A-Fa-f]{4})|"
    r"(?<=[\[;0-9][mK])))"
)
_TOKEN_END = r"(?<=[A-Za-z0-9_=-])(?![A-Za-z0-9_])"


def _token(
    head: str, tail: str, *, start: str = TOKEN_START, end: str = _TOKEN_END
) -> re.Pattern[str]:
    # Look for the head first. The boundary check is too slow to run at every position.
    return re.compile(rf"(?={head}){start}{head}{tail}{end}")


# JSON can escape `/` and base64 characters. An escaped delimiter still ends the value.
SIGNED_VALUE_CHAR = r"(?:[^&#\s\"'<>`\\)]|\\/|\\u(?!00(?:2[0-9]|3[CcEe]))[0-9A-Fa-f]{4})"

BUILTIN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic_key", _token(r"sk-ant-", r"[A-Za-z0-9_-]{20,}")),
    ("openrouter_key", _token(r"sk-or-v1-", r"[A-Za-z0-9_-]{20,}")),
    ("minimax_key", _token(r"sk-cp-", r"[A-Za-z0-9_-]{20,}")),
    ("openai_key", _token(r"sk-", r"(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("fireworks_key", _token(r"fw_", r"[A-Za-z0-9_-]{20,}")),
    ("xai_key", _token(r"xai-", r"[A-Za-z0-9_-]{20,}")),
    ("groq_api_key", _token(r"gsk_", r"[A-Za-z0-9]{48,}")),
    ("perplexity_api_key", _token(r"pplx-", r"[A-Za-z0-9]{40,}")),
    ("cerebras_api_key", _token(r"csk-", r"[A-Za-z0-9]{40,}")),
    ("replicate_api_token", _token(r"r8_", r"[A-Za-z0-9]{35,}")),
    ("tavily_api_key", _token(r"tvly-", r"(?:dev-|prod-)?[A-Za-z0-9]{24,}")),
    ("github_token", _token(r"gh[pousr]_", r"[A-Za-z0-9_]{30,}")),
    ("github_fine_grained_pat", _token(r"github_pat_", r"[A-Za-z0-9_]{30,}")),
    ("atlassian_api_token", _token(r"ATATT3xFfGF0", r"[A-Za-z0-9_-]{20,}(?:=[A-F0-9]{8})?")),
    ("gitlab_token", _token(r"glpat-", r"[A-Za-z0-9_-]{20,}(?:\.[0-9a-z]{9})?")),
    ("slack_token", _token(r"xox[abpors]-", r"[A-Za-z0-9-]{20,}")),
    ("stripe_key", _token(r"(?:sk|rk)_(?:live|test)_", r"[A-Za-z0-9]{20,}")),
    ("aws_access_key", _token(r"(?:AKIA|ASIA)", r"[A-Z0-9]{16}")),
    ("aws_access_key_extended", _token(r"(?:A3T[A-Z0-9]|ABIA|ACCA)", r"[A-Z2-7]{16}")),
    ("aws_bedrock_api_key", _token(r"ABSK", r"[A-Za-z0-9+/]{80,}={0,2}")),
    ("gemini_api_key", _token(r"AIza", r"[0-9A-Za-z_-]{35,}")),
    ("jwt", _token(r"eyJ", r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("google_oauth_token", _token(r"ya29\.", r"[A-Za-z0-9._-]{20,}")),
    ("onepassword_service_account_token", _token(r"ops_eyJ", r"[A-Za-z0-9+/]{120,}={0,3}")),
    ("age_secret_key", _token(r"AGE-SECRET-KEY-1", r"[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")),
    ("databricks_api_token", _token(r"dapi", r"[a-f0-9]{32}(?:-\d)?")),
    ("digitalocean_token", _token(r"d(?:op|oo|or)_v1_", r"[a-f0-9]{64}")),
    ("huggingface_token", _token(r"(?:hf_|api_org_)", r"[A-Za-z0-9]{34,}")),
    ("linear_api_key", _token(r"lin_api_", r"[A-Za-z0-9]{40}")),
    ("npm_token", _token(r"npm_", r"[A-Za-z0-9]{36}")),
    ("pypi_upload_token", _token(r"pypi-AgEIcHlwaS5vcmc", r"[A-Za-z0-9_-]{50,}")),
    ("sendgrid_token", _token(r"SG\.", r"[A-Za-z0-9_.=-]{66}")),
    (
        "slack_webhook",
        _token(
            r"https?://hooks\.slack\.com/",
            r"(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,}",
        ),
    ),
    (
        "telegram_bot_token",
        # Bot API URLs join the token to a literal `bot`.
        _token(r"[0-9]{5,16}:A", r"[A-Za-z0-9_-]{34}", start=rf"(?:{TOKEN_START}|(?<=/bot))"),
    ),
    ("twilio_api_key", _token(r"SK", r"[0-9a-fA-F]{32}")),
    ("vault_token", _token(r"hv[bs]\.", r"[A-Za-z0-9_-]{80,}")),
    ("shopify_token", _token(r"shp(?:at|ca|pa|ss)_", r"[a-fA-F0-9]{32}")),
    (
        "sentry_token",
        # Organization tokens are base64 JSON, an underscore, and the secret.
        _token(r"sntry[su]_", r"[A-Za-z0-9+/]{40,}(?:={0,2}_[A-Za-z0-9+/]{40,})?"),
    ),
    (
        "supabase_token",
        _token(
            r"sb",
            r"(?:p_(?:v0_|oauth_)?[a-f0-9]{40}|_secret_[A-Za-z0-9_-]{30,})",
        ),
    ),
    (
        "tailscale_key",
        _token(
            r"tskey-",
            r"(?:auth|api|client|scim|webhook)-(?:[A-Za-z0-9]{1,32}-|-)?"
            r"[A-Za-z0-9_]{16,}(?:--TL[A-Za-z0-9+/=_-]+)?",
            end=r"(?![A-Za-z0-9+/=_-])",
        ),
    ),
    (
        "grafana_token",
        _token(
            r"gl",
            r"(?:sa_[A-Za-z0-9]{32}_[a-fA-F0-9]{8}(?![A-Za-z0-9_])|"
            r"c_eyJ[A-Za-z0-9+/_-]{32,}={0,3}(?![A-Za-z0-9+/=_-]))",
            end="",
        ),
    ),
    ("postman_api_key", _token(r"PMAK-", r"[a-fA-F0-9]{24}-[a-fA-F0-9]{34}")),
    (
        "planetscale_token",
        _token(
            r"pscale_",
            r"(?:tkn|pw|oauth)_[A-Za-z0-9_-][A-Za-z0-9_.-]{30,}[A-Za-z0-9_-]={0,2}",
            end=r"(?![A-Za-z0-9_=-])",
        ),
    ),
    ("neon_api_key", _token(r"napi_", r"[A-Za-z0-9]{50,}")),
    ("vercel_access_token", _token(r"vcp_", r"[A-Za-z0-9]{48,}")),
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
            r"(?i)((?:[?&](?:amp;)?|\\u0026)(?:x-amz-signature|x-amz-credential|"
            r"x-amz-security-token|x-goog-signature|x-goog-credential|googleaccessid|"
            rf"signature|sig)=)({SIGNED_VALUE_CHAR}+)"
        ),
    ),
    (
        "assigned_secret",
        re.compile(
            r"(?i)(?P<prefix>(?<![A-Za-z0-9_.-])(?P<key_quote>[\"']?)"
            r"(?P<field>[A-Za-z0-9_.-]{0,128}(?:api[_-]?keys?|client[_-]?secrets?|"
            r"secrets?|passwords?|passwd|pwd|tokens?|access[_-]?tokens?|"
            r"refresh[_-]?tokens?|id[_-]?tokens?|auth[_-]?tokens?|session[_-]?tokens?|"
            r"private[_-]?keys?|credentials?|webhook[_-]?urls?|"
            # Code uses these names for other things, so the value must look like a key.
            r"(?:account|access)[_-]?keys?(?![_-]?(?:id|name))"
            r"(?=[A-Za-z0-9_.-]{0,128}\\*[\"']?[ \t]*[:=][ \t]*\\*[\"']?"
            r"(?=[A-Za-z+/_=-]{0,64}[0-9])[A-Za-z0-9+/_=-]{16,}(?![A-Za-z0-9.(\[])))"
            r"[A-Za-z0-9_.-]{0,128})"
            r"\\*(?P=key_quote)\s*[:=]\s*(?P<value_quote>(?:\\*[\"'])?))"
            r"(?P<secret>[^\"'\s;\[\]]{8,})(?P=value_quote)"
        ),
    ),
    (
        "auth_header",
        re.compile(
            r"(?i)(?P<prefix>(?<![A-Za-z0-9_.-])(?P<key_quote>[\"']?)"
            r"(?:authorization|proxy-authorization|x-api-key|x-goog-api-key|api-key|x-auth-token|"
            r"x-auth-key|cf-access-token)"
            r"\\*(?P=key_quote)\s*[:=]\s*(?:\[\s*(?=\\*[\"']|bearer\s|basic\s))?"
            r"(?P<value_quote>(?:\\*[\"'])?)"
            r"(?:(?:bearer|token|basic|key|api-?key|geniekey|splunk|ssws)\s+)?)"
            r"(?P<secret>(?!geniekey\s)[A-Za-z0-9._~+/=-]{8,})(?P=value_quote)"
        ),
    ),
    (
        "url_credentials",
        re.compile(
            rf"(?=(?i:[acmpr]|https?:)){TOKEN_START}"
            # A database password can hold a raw `/`. In HTTP that starts a path.
            r"(?!(?i:https?)://[^\s/@]*/)"
            r"((?i:https?|postgres(?:ql)?(?:\+[a-z0-9_]+)?|mysql(?:\+[a-z0-9_]+)?|"
            r"mariadb(?:\+[a-z0-9_]+)?|mongodb(?:\+srv)?|rediss?|amqps?|"
            r"clickhouse(?:s|db)?(?:\+[a-z0-9_]+)?)://"
            r"[^:\s/@]*:)(?![0-9]+/)"
            # A quote can be part of the password. Before JSON punctuation it ends the string.
            r"((?:[^@\s/\"]|\"(?!\s*[,:}\]]))+(?:/[^@\s/?#\"'<>`,\\]+)*(?:@[^@\s/?#\"'<>`,\\]+)*)(@)"
        ),
    ),
]

AUDIT_EXCLUDED_PATTERN_NAMES = frozenset({"assigned_secret", "auth_header", "url_credentials"})
