# Redaction

PromptLatch uses `bc-detect-secrets`, provider token patterns, and user-defined
exact-tail or regex matches. It does not load or call a model.

Coverage includes fixture-shaped examples for:

- AI provider keys: OpenAI/Codex, Anthropic, Gemini, OpenRouter, Z.AI,
  MiniMax, DeepSeek, xAI/Grok, Fireworks, Groq, Perplexity, Cerebras, Replicate,
  and Tavily.
- Developer and cloud credentials: GitHub, GitLab, Atlassian, AWS,
  Cloudflare, Slack, Stripe, Google Cloud, Azure, Supabase, Tailscale, Grafana,
  Postman, PlanetScale, Neon, Vercel, npm, PyPI, and other common service tokens.
- Structured credentials: JWTs, signed URLs, URL/DSN userinfo (HTTP, Postgres,
  MySQL, MariaDB, MongoDB, Redis, AMQP, ClickHouse, and `+driver` schemes), PEM
  keys, encrypted PEM keys, and PGP private keys.
- Labeled values and JSON fields such as `password`, `token`, `api_key`,
  `authorization`, `credentials`, `signed_url`, and `sas_token`.
- User-defined exact-tail and regex rules for private formats.

JSON, query parameters, and URL-encoded form fields are scanned structurally.
A body that parses as a JSON object or array is scanned as JSON even without a JSON
content type.
Other unencoded text bodies are scanned without changing unrelated bytes.
Multipart uploads are rejected with `415` while redaction is enabled: raw byte
scanning cannot reliably protect attachment contents or form fields. Incoming
`gzip` and `zstd` request bodies are decompressed with bounded expansion checks
before scanning; unsupported or stacked `Content-Encoding` values are rejected
with `415`.

Every scan runs locally without an LLM. Entropy-only matching is disabled; use
custom rules for opaque internal formats.

Scan results are cached per string in a bounded, in-memory record. Repeated text,
such as conversation history, is scanned once per process. The record is keyed by
digest and holds redacted output only, never the original input. One redactor is
safe to share between threads.

## Verify redaction

A model reply cannot verify the forwarded request. Send a fixture token to an echo
endpoint and inspect the echoed body:

```bash
FAKE_GEMINI_KEY="AI""zaSyFixtureToken000000000000000000000"

curl --compressed -fsS http://127.0.0.1:8000/post \
  -H "X-Target-Base-URL: https://postman-echo.com" \
  -H "Content-Type: application/json" \
  --data "$(jq -nc --arg key "$FAKE_GEMINI_KEY" \
    '{messages:[{role:"user",content:("GEMINI_API_KEY=" + $key)}]}')" \
  | jq -r '.data.messages[0].content'
```

Expected output:

```text
GEMINI_API_KEY=[REDACTED_SECRET]
```

Audit logs omit matched values and include counts and rule names. Test rules
directly from the terminal or in pre-commit scripts without starting the proxy:

```bash
promptlatch scan --file .env.example --mode tagged
git diff --cached | promptlatch scan --check --quiet
promptlatch doctor --strict
```

`scan` accepts an inline string, `--file`, or piped stdin (`-`), supports
`--mode full|partial|tagged`, and exits with code `1` under `--check` when a
secret is matched. `doctor` inspects configuration, read-only SQLite storage,
and any loopback proxy `/healthz` endpoint (including running-version drift);
`--strict` exits `1` if redaction, storage, or the local proxy is unhealthy.

## Security boundary

- Request bodies and query parameters are scanned before they leave your machine.
- Audit logs record redaction counts and rule names without storing secret values.
- Local request history stores redacted bodies and metrics. Redacted prompts can
  still contain private information; use metadata-only storage when needed.
- When request history is enabled, it can also retain a small allowlist of upstream
  error fields after full redaction. Full upstream response bodies and raw headers
  are not stored.
- PromptLatch strips cookies and secret-named client headers. Provider credentials are
  added from config or dedicated `X-Target-*` headers after that filtering step.
- Unknown private token formats need a custom exact-tail or regex rule.

See [SECURITY.md](../SECURITY.md) for deployment defaults and remaining limits.
