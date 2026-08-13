# Integrate PromptLatch

Add PromptLatch to redact secrets from LLM request content before it leaves this
machine or application process.

## Inspect integration

1. Inspect current LLM clients, agent configs, package manager, runtime, and deployment model.
2. Read current PromptLatch README and use release commands shown there. PromptLatch is
   not published to PyPI; install release wheel or use Homebrew, Docker, or source.
3. Choose proxy mode or Python library mode based on where requests are created.

Use proxy mode for coding agents, non-Python applications, or clients that accept
a custom OpenAI or Anthropic base URL. Use library mode when Python code can
redact request values immediately before an SDK call.

## Install

Choose one proxy installation method.

Homebrew:

```bash
brew tap bvolpato/tap
brew install promptlatch
promptlatch version
```

uv tool:

```bash
uv tool install \
  https://github.com/bvolpato/promptlatch/releases/download/v0.2.0/promptlatch-0.2.0-py3-none-any.whl
promptlatch version
```

Docker:

```bash
docker pull ghcr.io/bvolpato/promptlatch:0.2.0
docker run --rm --entrypoint promptlatch \
  ghcr.io/bvolpato/promptlatch:0.2.0 version
```

Source checkout:

```bash
git clone https://github.com/bvolpato/promptlatch.git
cd promptlatch
uv sync --extra dev --locked
uv run promptlatch version
```

For Python library mode, add release wheel to existing uv project:

```bash
uv add \
  https://github.com/bvolpato/promptlatch/releases/download/v0.2.0/promptlatch-0.2.0-py3-none-any.whl
```

## Security rules

- Leave real credentials in existing environment variables or secret managers. Never print, paste, move, or commit them.
- Use fixture-only values containing `FixtureToken` for tests and examples.
- Bind proxy to `127.0.0.1` unless remote access is explicitly required.
- Require `server.api_key` before binding beyond loopback.
- Keep `block_private_targets: true` unless a trusted local upstream is required.
- Leave `debug_requests: false` and do not add telemetry.
- Use full redaction. Add custom tail-only rules for unknown internal formats.
- Detection must remain deterministic; do not add entropy-only matching.
- Provider authentication belongs outside request content. PromptLatch forwards
  configured upstream credentials and masks sensitive headers in debug output.
- Use `X-Target-API-Key` or `X-Target-Authorization` for client-selected targets.
  Do not enable generic client authorization forwarding when proxy auth is enabled.

## Proxy mode

Create config without placing literal keys in it:

```yaml
server:
  host: 127.0.0.1
  port: 8000
  api_key: null
  debug_requests: false

target:
  default_base_url: https://api.example.com/v1
  api_key: ${UPSTREAM_API_KEY}
  api_key_header: authorization
  forward_client_authorization: false
  allowed_base_urls: []
  block_private_targets: true

redaction:
  enabled: true
  engine: detect-secrets
  redact_mode: full
```

Use `api_key_header: x-api-key` for Anthropic-compatible upstreams. For
per-request routing, add trusted public base URLs to the allowlist and send matching
`X-Target-Base-URL` and `X-Target-API-Key` headers. Never forward the configured
target key to a different host.

Point OpenAI-compatible clients at `http://127.0.0.1:8000/v1`. Set Claude Code
`ANTHROPIC_BASE_URL` to `http://127.0.0.1:8000`. Some SDKs require a local API-key
value even when PromptLatch has no `server.api_key`; use a non-secret placeholder.
Do not invent a PromptLatch key unless local proxy auth is enabled.

For Codex and OpenCode with OpenRouter, start from checked-in files under
`examples/`. They use dedicated target headers, keep key in environment, and leave
Responses-to-Chat bridge off because OpenRouter supports native Responses. Claude
Code uses Anthropic Messages; set provider key on PromptLatch and send separate
local bearer token through `ANTHROPIC_AUTH_TOKEN` when proxy auth is enabled.

## Python library mode

Install current PromptLatch release from README, then redact immediately before
each SDK call:

```python
from promptlatch import redact_messages, redact_params, redact_payload

safe_messages = redact_messages(messages)
safe_params = redact_params(model=model, messages=messages, tools=tools)
safe_payload = redact_payload(payload)
```

Pick the helper that matches the call shape:

- `redact_messages` for message arrays, including LangChain message objects.
- `redact_params` for OpenAI, LiteLLM, and similar keyword arguments.
- `redact_payload` for raw JSON-compatible request bodies.

Do not mutate caller-owned data or redact provider authentication passed outside
request content. Cover every LLM call path, including retries, streaming calls,
tool payloads, and background jobs.

## Verification

1. Run project lint, type checks, and focused tests.
2. In proxy mode, confirm `GET /healthz` reports redaction enabled and telemetry disabled.
3. Send a fixture request to the echo endpoint and inspect the forwarded body:

```bash
FAKE_KEY="AI""zaSyFixtureToken000000000000000000000"

curl --compressed -fsS http://127.0.0.1:8000/post \
  -H "X-Target-Base-URL: https://postman-echo.com" \
  -H "Content-Type: application/json" \
  --data "$(jq -nc --arg key "$FAKE_KEY" \
    '{messages:[{role:"user",content:("GEMINI_API_KEY=" + $key)}]}')" \
  | jq -r '.data.messages[0].content'
```

Expected output:

```text
GEMINI_API_KEY=[REDACTED_SECRET]
```

Confirm fixture value is absent from logs. Report mode, changed files, credential
handling, commands run, and exact verification result.
