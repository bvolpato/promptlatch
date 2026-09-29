# PromptLatch

[![CI](https://github.com/bvolpato/promptlatch/actions/workflows/ci.yml/badge.svg)](https://github.com/bvolpato/promptlatch/actions/workflows/ci.yml)
[![CodeQL](https://github.com/bvolpato/promptlatch/actions/workflows/codeql.yml/badge.svg)](https://github.com/bvolpato/promptlatch/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/bvolpato/promptlatch)](https://github.com/bvolpato/promptlatch/releases)
[![License: MIT](https://img.shields.io/github/license/bvolpato/promptlatch)](https://github.com/bvolpato/promptlatch/blob/main/LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776ab)](https://github.com/bvolpato/promptlatch/blob/main/pyproject.toml)
[![Docker](https://img.shields.io/badge/GHCR-promptlatch-54d6a0)](https://github.com/bvolpato/promptlatch/pkgs/container/promptlatch)

**Redact secrets before prompts reach an LLM provider.**

PromptLatch is a local proxy and a Python redaction library. Use the proxy for
coding agents and clients that support a custom base URL. Use the library to redact
prompt text, message arrays, SDK parameters, and structured request payloads before
your application calls an LLM SDK.

Scanning stays local. PromptLatch has no telemetry or phone-home behavior.

![PromptLatch site preview](https://raw.githubusercontent.com/bvolpato/promptlatch/main/site/hero.png)

Website: `https://bvolpato.github.io/promptlatch/`

Agent integration prompt: [`PROMPT.md`](https://github.com/bvolpato/promptlatch/blob/main/PROMPT.md)

## Choose a mode

| Need | Use |
| --- | --- |
| Protect coding agents and IDEs | Run `promptlatch serve` and point OpenAI-compatible clients at `http://127.0.0.1:8000/v1`. |
| Protect SDK calls in Python | Import `redact_text`, `redact_messages`, `redact_params`, or `redact_payload` and pass each returned value to the SDK. |

## Coverage

Default rules cover provider keys, personal access tokens, passwords, JWTs,
signed URLs, URL credentials, PEM/PGP private keys, and common secret fields such
as `api_key`, `token`, `authorization`, `password`, `signed_url`, and
`credentials`.

Detection uses deterministic provider rules plus your exact-tail or regex rules.
Entropy-only matching is disabled to avoid unpredictable false positives.

## Security boundary

- Request bodies and query parameters are scanned before they leave your machine.
- Audit logs record redaction counts and rule names without storing secret values.
- PromptLatch strips cookies and secret-named client headers. Provider credentials are
  added from config or dedicated `X-Target-*` headers after that filtering step.
- Unknown private token formats need a custom exact-tail or regex rule.

See [SECURITY.md](SECURITY.md) for deployment defaults and remaining limits.

## Install

Python package: [promptlatch on PyPI](https://pypi.org/project/promptlatch/).

Homebrew:

```bash
brew tap bvolpato/tap
brew install promptlatch
promptlatch version
```

uv:

```bash
uv tool install promptlatch
promptlatch doctor
```

Python library:

```bash
uv add promptlatch
# or
python -m pip install promptlatch
```

Source:

```bash
git clone https://github.com/bvolpato/promptlatch.git
cd promptlatch
uv sync --extra dev --locked
uv run promptlatch doctor
```

ASGI servers can load `promptlatch.asgi:app` directly. Importing CLI or proxy
helpers does not load user config until a command or app requests it.

### Upgrading from PromptCloak

Version 0.2 renamed package, command, environment variables, config directory,
container image, and Helm chart. Old Python imports, environment variables, and default
config path remain compatible through 0.2.x and emit migration warnings.

Remove old uv tool so stale `promptcloak` command cannot shadow new install:

```bash
uv tool uninstall promptcloak
```

Move local config before switching services:

```bash
mv ~/.config/promptcloak ~/.config/promptlatch
```

Existing Helm releases can upgrade in place without changing immutable selectors or
rotating chart-managed proxy key:

```bash
helm upgrade <existing-release-name> ./charts/promptlatch \
  --set migration.preserveLegacyNames=true
```

Keep migration flag on later upgrades for that release. Fresh installs should omit it
and use release name `promptlatch`. Existing external Secrets may keep
`PROMPTCLOAK_SERVER_API_KEY` for this upgrade, then rename key to
`PROMPTLATCH_SERVER_API_KEY`.

## Run proxy

Configure an upstream, keep its key in your shell, and start PromptLatch:

```bash
promptlatch init --target-base-url https://api.openai.com/v1
export OPENAI_API_KEY="<openai-upstream-key>"
promptlatch serve
```

Point clients at `http://127.0.0.1:8000/v1`. For example:

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-6-sol",
    "messages": [{
      "role": "user",
      "content": "Here is my .env: OPENAI_API_KEY=<api-key-like-value>"
    }]
  }'
```

Provider receives `OPENAI_API_KEY=[REDACTED_SECRET]` in request content.

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

Audit logs omit matched values and include counts and rule names. Homebrew users
can run PromptLatch as a background service after configuring its environment:

```bash
brew services start bvolpato/tap/promptlatch
```

## Use as a Python library

Use PromptLatch without starting the proxy. Redact each prompt or request value in
the same process, immediately before passing it to your SDK or HTTP client. Install
the SDK you use separately; PromptLatch has no OpenAI, LiteLLM, LangChain, Anthropic,
or LlamaIndex SDK dependency.

Choose a helper for the shape of the value you send:

| Input | Helper | Result |
| --- | --- | --- |
| One prompt or text field | `redact_text(text)` | Redacted string |
| Chat messages, including nested tool data | `redact_messages(messages)` | Redacted message list |
| SDK keyword arguments | `redact_params(**params)` | Redacted dictionary ready to unpack into an SDK call |
| Raw mapping/list request body | `redact_payload(payload)` | Redacted structure with its shape preserved |

All four helpers are exported from `promptlatch`. They return the safe value. They do
not send the request or change an SDK client for you. **Pass the returned value to the
SDK call; never pass the original value after redaction.** If redaction raises an
error, do not retry by sending the original input.

### Redact a standalone prompt

Use `redact_text` when the prompt is assembled as a string, before passing it as
`input`, `prompt`, or another SDK field:

```python
from openai import OpenAI
from promptlatch import redact_text

client = OpenAI()
prompt = "Inspect this config: OPENAI_API_KEY=example-secret-value-123456"

response = client.responses.create(
    model="gpt-6-sol",
    input=redact_text(prompt),
)
```

### Redact a message array

Use `redact_messages` for chat-style `messages` arrays. It supports mapping-based
messages, `(role, content)` tuples, Pydantic/OpenAI message models, and LangChain
message objects:

```python
from openai import OpenAI
from promptlatch import redact_messages

client = OpenAI()
messages = [
    {"role": "system", "content": "Summarize the user's log."},
    {"role": "user", "content": "Authorization: Bearer FixtureToken000000000000000000000"},
]

safe_messages = redact_messages(messages)
response = client.chat.completions.create(
    model="gpt-6-sol",
    messages=safe_messages,
)
```

For non-Pydantic message objects, PromptLatch copies the object and redacts its
`content` field. For Pydantic messages, it recursively redacts fields, including
tool calls, and preserves the model type. Inputs are left unchanged.

### Redact SDK parameters or structured payloads

Use `redact_params` when assembling SDK keyword arguments. It returns a dictionary
you can unpack directly into the SDK call. A `messages` argument is treated as a
message array; other values, including `input`, `tools`, and nested parameter
objects, are scanned recursively.

```python
from openai import OpenAI
from promptlatch import redact_params

client = OpenAI()
safe_params = redact_params(
    model="gpt-6-sol",
    input="Summarize this: GITHUB_TOKEN=example-token-value-123456",
)
response = client.responses.create(**safe_params)
```

For raw JSON-compatible bodies, use `redact_payload` and pass its result to the
transport. It recursively scans strings in mappings and lists without reshaping the
request schema:

```python
import os
import httpx
from promptlatch import redact_payload

payload = {
    "model": "gpt-6-sol",
    "input": [
        {
            "role": "user",
            "content": [
                {
                    "type": "input_text",
                    "text": "OPENAI_API_KEY=example-secret-value-123456",
                }
            ],
        }
    ],
    "metadata": {"job": "support-triage"},
}
response = httpx.post(
    "https://api.openai.com/v1/responses",
    headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
    json=redact_payload(payload),
)
```

### Use with other SDKs

Call the same helpers at each SDK boundary. Keep provider authentication in the
SDK's normal environment/configuration; PromptLatch redacts prompt and payload
content, not credentials held in the SDK's transport configuration.

LiteLLM:

```python
from litellm import completion
from promptlatch import redact_params

response = completion(
    **redact_params(
        model="openai/gpt-6-sol",
        messages=[{"role": "user", "content": "GEMINI_API_KEY=example-key-value-123456"}],
    )
)
```

Anthropic:

```python
from anthropic import Anthropic
from promptlatch import redact_messages

client = Anthropic()
response = client.messages.create(
    model="claude-opus-4-8",
    max_tokens=1024,
    messages=redact_messages([{"role": "user", "content": "token=example-token-value-123456"}]),
)
```

LangChain:

```python
from langchain_openai import ChatOpenAI
from promptlatch import redact_messages

llm = ChatOpenAI(model="gpt-6-sol")
response = llm.invoke(
    redact_messages(
        [
            ("human", "Here is my token: example-token-value-123456"),
        ]
    )
)
```

### Inspect redaction results

`scan_text`, `scan_messages`, `scan_params`, and `scan_payload` return a
`RedactionResult` with `.value` and `.stats`. Use `.value` for the SDK call, and use
`.stats.redactions` or `.stats.rule_hits` for counts by rule. Stats do not contain
matched secret values.

```python
from promptlatch import scan_text

result = scan_text("OPENAI_API_KEY=example-secret-value-123456")
print(result.stats.redactions)
safe_text = result.value
```

### Configure custom rules

The default helpers use the default `RedactionConfig`. For per-application rules,
create a `PromptLatch` instance. Exact rules of 16 characters or fewer match a
secret tail inside a longer value. Prefer storing only that tail in config.

```python
from promptlatch import PromptLatch
from promptlatch.config import RedactionConfig, RuleConfig

latch = PromptLatch(
    RedactionConfig(
        rules=[
            RuleConfig(type="exact", value="abcd1234", name="internal-token"),
        ]
    )
)
safe_prompt = latch.text("internal token: private-abcd1234")
```

Redaction copies mappings, lists, tuples, and Pydantic models rather than mutating
caller-owned values. A detected secret in a Pydantic model's extra field name or
mapping-key collision raises `ValueError`; fail closed and do not send the original
input. Unknown private token formats need a custom exact-tail or regex rule.

## Configuration

Default config: `~/.config/promptlatch/config.yaml`

```yaml
server:
  host: 127.0.0.1
  port: 8000
  api_key: null
  max_request_body_bytes: 33554432

target:
  default_base_url: https://api.openai.com/v1
  api_key: ${OPENAI_API_KEY}
  api_key_header: authorization
  forward_client_authorization: false
  timeout_seconds: 180
  allowed_base_urls: []
  block_private_targets: true

redaction:
  enabled: true
  engine: detect-secrets
  redact_mode: full
  encrypted: false
  max_extra_rules: 20
  max_extra_rule_chars: 1024
  allow_extra_regex_rules: false
  rules:
    - type: exact
      value: abcd1234
      name: tail-only-example
    - type: regex
      value: sk-[A-Za-z0-9_-]{20,}
      name: openai-style-token
```

Store only key tails in exact rules. Full masking is default; partial masking is
available through `redact_mode: partial`.

## Supported routes

PromptLatch forwards any path, with first-class tests for:

- `/v1/chat/completions`
- `/v1/responses`
- `/v1/completions`
- `/v1/models`
- `/v1/messages` for Claude-compatible gateways

Tests cover streaming responses, tool payloads, and vision payloads. PromptLatch
redacts recursively without reshaping JSON request schemas.

## Provider targets

Set default backend in config, or choose one per request:

```bash
curl http://127.0.0.1:8000/v1/responses \
  -H "X-Target-Base-URL: https://api.openai.com/v1" \
  -H "X-Target-API-Key: $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-6-sol","input":"scan this <api-key-like-value>"}'
```

Set `X-Target-API-Key-Header: x-api-key` for Anthropic-style upstream authentication.

Configured target keys are bound to `target.default_base_url`. A dynamic target that
requires authentication must receive its key through `X-Target-API-Key` or
`X-Target-Authorization`; PromptLatch never reuses configured key for another host.

An empty `target.allowed_base_urls` permits any public target. Add URLs to restrict
dynamic routing. Set `block_private_targets: false` only for trusted local targets.

Per-request rules are exact matches by default. Regex rules remain available in trusted config.
Set `redaction.allow_extra_regex_rules: true` only for authenticated clients you trust.

PromptLatch forwards routes without reshaping provider payloads.

| Target | Base URL | Auth header | Notes |
| --- | --- | --- | --- |
| OpenAI | `https://api.openai.com/v1` | `authorization` | Native Chat Completions, Responses API, models, tools, streaming. |
| OpenRouter | `https://openrouter.ai/api/v1` | `authorization` | Native Chat Completions and Responses. Use provider-prefixed model names. |
| Anthropic / Claude-compatible | `https://api.anthropic.com` | `x-api-key` | Forward `/v1/messages`; PromptLatch does not translate OpenAI JSON into Anthropic JSON. |
| Local Ollama or vLLM | `http://127.0.0.1:11434/v1` or another local `/v1` endpoint | provider-specific | Set `block_private_targets: false` only for local-only configs. |

OpenRouter per request:

```yaml
target:
  allowed_base_urls:
    - https://openrouter.ai/api/v1
```

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "X-Target-Base-URL: https://openrouter.ai/api/v1" \
  -H "X-Target-API-Key: $OPENROUTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"openai/gpt-oss-120b","messages":[{"role":"user","content":"scan this <api-key-like-value>"}]}'
```

Anthropic-compatible target:

```bash
curl http://127.0.0.1:8000/v1/messages \
  -H "X-Target-Base-URL: https://api.anthropic.com" \
  -H "X-Target-API-Key: $ANTHROPIC_API_KEY" \
  -H "X-Target-API-Key-Header: x-api-key" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-opus-4-8","max_tokens":256,"messages":[{"role":"user","content":"scan this <api-key-like-value>"}]}'
```

Local OpenAI-compatible target:

```yaml
target:
  default_base_url: http://127.0.0.1:11434/v1
  api_key: null
  allowed_base_urls:
    - http://127.0.0.1:11434/v1
  block_private_targets: false
```

## Codex with OpenRouter

OpenRouter accepts native Responses requests, so no compatibility bridge is needed.
Keep OpenRouter key in environment and send it through PromptLatch's dedicated target
header. Generic client `Authorization` is not forwarded.

Start PromptLatch:

```bash
mkdir -p ~/.config/promptlatch
cp examples/promptlatch-openrouter.config.yaml ~/.config/promptlatch/config.yaml
export OPENROUTER_API_KEY="<openrouter-upstream-key>"
promptlatch serve
```

The checked-in PromptLatch config restricts dynamic routing to OpenRouter and leaves
`forward_client_authorization` and `responses_to_chat` disabled.

Install Codex profile:

```bash
mkdir -p ~/.codex
cp examples/codex-openrouter-promptlatch.config.toml \
  ~/.codex/openrouter-promptlatch.config.toml
```

Profile contents:

```toml
model = "openai/gpt-oss-120b"
model_provider = "promptlatch-openrouter"

[model_providers.promptlatch-openrouter]
name = "PromptLatch OpenRouter"
base_url = "http://127.0.0.1:8000/v1"
wire_api = "responses"
env_http_headers = { "X-Target-API-Key" = "OPENROUTER_API_KEY" }
http_headers = { "X-Target-Base-URL" = "https://openrouter.ai/api/v1" }
request_max_retries = 0
stream_max_retries = 0
```

Run interactive Codex:

```bash
codex -p openrouter-promptlatch
```

Non-interactive smoke test:

```bash
codex exec -p openrouter-promptlatch --strict-config \
  --sandbox read-only --ephemeral --cd "$PWD" \
  "Reply with exactly: promptlatch-openrouter-ok"
```

Use any OpenRouter Responses-capable model by changing profile `model`. Current Codex
requests include Responses-only custom tool descriptors, so Codex needs a backend with
native Responses support. `compat.responses_to_chat` remains available for simpler
Responses clients limited to text, messages, and standard function tools.

## OpenCode

Current stable OpenCode config supports custom Chat Completions providers through
`@ai-sdk/openai-compatible`. Copy checked-in example into project, or merge provider
block into existing `opencode.json`:

```bash
cp examples/opencode-openrouter-promptlatch.json opencode.json
export OPENROUTER_API_KEY="<openrouter-upstream-key>"
```

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "promptlatch-openrouter": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "PromptLatch OpenRouter",
      "options": {
        "baseURL": "http://127.0.0.1:8000/v1",
        "headers": {
          "X-Target-Base-URL": "https://openrouter.ai/api/v1",
          "X-Target-API-Key": "{env:OPENROUTER_API_KEY}"
        }
      },
      "models": {
        "openai/gpt-oss-120b": {
          "name": "gpt-oss via PromptLatch"
        }
      }
    }
  },
  "model": "promptlatch-openrouter/openai/gpt-oss-120b"
}
```

Run:

```bash
opencode run -m promptlatch-openrouter/openai/gpt-oss-120b \
  --format json --dir "$PWD" \
  "Reply with exactly: promptlatch-opencode-ok"
```

For another Chat Completions target, replace base URL, environment variable, and
model ID. Use `PROMPTLATCH_TARGET_BASE_URL` and `PROMPTLATCH_TARGET_API_KEY` instead
when PromptLatch owns one fixed upstream.

## Claude Code

Claude Code sends Anthropic Messages requests. Configure provider key on PromptLatch,
then use separate local bearer token for proxy authentication:

```bash
export ANTHROPIC_UPSTREAM_API_KEY="<anthropic-upstream-key>"
export PROMPTLATCH_TARGET_BASE_URL="https://api.anthropic.com"
export PROMPTLATCH_TARGET_API_KEY="$ANTHROPIC_UPSTREAM_API_KEY"
export PROMPTLATCH_TARGET_API_KEY_HEADER="x-api-key"
export PROMPTLATCH_SERVER_API_KEY="<local-proxy-key>"

promptlatch serve

export ANTHROPIC_BASE_URL="http://127.0.0.1:8000"
export ANTHROPIC_AUTH_TOKEN="$PROMPTLATCH_SERVER_API_KEY"
export DISABLE_TELEMETRY=1
export DO_NOT_TRACK=1
claude
```

PromptLatch validates local bearer token, removes it, then adds upstream `x-api-key`.
It forwards `/v1/messages` without translating between OpenAI and Anthropic schemas.

## Redaction engine

PromptLatch uses `bc-detect-secrets`, provider token patterns, and user-defined
exact-tail or regex matches. It does not load or call a model.

Coverage includes fixture-shaped examples for:

- AI provider keys: OpenAI/Codex, Anthropic, Gemini, OpenRouter, Z.AI,
  MiniMax, DeepSeek, xAI/Grok, and Fireworks.
- Developer and cloud credentials: GitHub, GitLab, Atlassian, AWS,
  Cloudflare, Slack, Stripe, Google Cloud, Azure, npm, PyPI, and other common
  service tokens.
- Structured credentials: JWTs, signed URLs, URL userinfo, PEM keys, encrypted
  PEM keys, and PGP private keys.
- Labeled values and JSON fields such as `password`, `token`, `api_key`,
  `authorization`, `credentials`, `signed_url`, and `sas_token`.
- User-defined exact-tail and regex rules for private formats.

JSON, query parameters, and URL-encoded form fields are scanned structurally.
Other unencoded text bodies are scanned without changing unrelated bytes.
Multipart uploads are rejected with `415` while redaction is enabled: raw byte
scanning cannot reliably protect attachment contents or form fields. Compressed
request bodies are also rejected; decompress them before sending.

Every scan runs locally without an LLM. Entropy-only matching is disabled; use
custom rules for opaque internal formats.

## Encrypt rules at rest

```bash
uv run promptlatch encrypt-rules
```

This creates `~/.config/promptlatch/key` with mode `0600`, encrypts
`redaction.rules` with AES-GCM, writes `redaction.encrypted_rules`, and clears
plain rules.

You can also provide key material through:

```bash
export PROMPTLATCH_CONFIG_KEY="base64-url-safe-32-byte-key"
```

## Docker

Published image:

```bash
# ~/.config/promptlatch/provider.env, mode 0600
PROMPTLATCH_TARGET_BASE_URL=https://api.openai.com/v1
PROMPTLATCH_TARGET_API_KEY=<openai-upstream-key>
```

```bash
docker run -d --name promptlatch --rm \
  -p 127.0.0.1:8000:8000 \
  --env-file "$HOME/.config/promptlatch/provider.env" \
  ghcr.io/bvolpato/promptlatch:0.2.3

curl --retry 10 --retry-connrefused --retry-delay 1 \
  -fsS http://127.0.0.1:8000/healthz
docker stop promptlatch
```

Build current checkout:

```bash
docker build -t promptlatch:local .
```

Compose:

```bash
export OPENAI_API_KEY="<openai-upstream-key>"
docker compose up --build
```

## Helm

Local chart:

```bash
kubectl create secret generic promptlatch-env \
  --from-env-file="$HOME/.config/promptlatch/kubernetes.env"

helm install promptlatch ./charts/promptlatch \
  --set env.PROMPTLATCH_TARGET_DEFAULT_BASE_URL=https://api.openai.com/v1 \
  --set existingSecret=promptlatch-env

kubectl wait deployment/promptlatch --for=condition=Available --timeout=90s
export PROMPTLATCH_SERVER_API_KEY="$(
  kubectl get secret promptlatch-env \
    -o jsonpath='{.data.PROMPTLATCH_SERVER_API_KEY}' | base64 --decode
)"
kubectl port-forward svc/promptlatch 8000:8000
```

In another shell:

```bash
curl -fsS http://127.0.0.1:8000/healthz
helm uninstall promptlatch
```

Release asset:

```bash
helm pull https://github.com/bvolpato/promptlatch/releases/download/v0.2.3/promptlatch-0.2.3.tgz
helm install promptlatch ./promptlatch-0.2.3.tgz \
  --set env.PROMPTLATCH_TARGET_DEFAULT_BASE_URL=https://api.openai.com/v1 \
  --set existingSecret=promptlatch-env
```

`kubernetes.env` must contain `PROMPTLATCH_TARGET_API_KEY` and
`PROMPTLATCH_SERVER_API_KEY`; keep file outside repository with mode `0600`.
Without `existingSecret`, chart generates proxy key and stores `secretEnv` values in
chart-managed Secret. Send `Authorization: Bearer $PROMPTLATCH_SERVER_API_KEY` on
proxied requests. Health probes remain unauthenticated.

Services route only to pods from their own release. Connected Helm upgrades preserve
the existing Deployment selector. For offline upgrades of charts through 0.2.2, set
`migration.preserveSelector=true` and retain it on later offline upgrades. Omit it on
fresh installs. Old Deployments keep their broad immutable selectors; replacing them
is required for controller isolation, even though Service routing is isolated.

## Emergency request tracing

`promptlatch serve --debug-requests` logs raw request bodies before redaction. Restrict it to local fixture data and cases where an echo target is insufficient. Auth, target-key, and redaction-rule headers are masked; body text is visible.

Uvicorn access logs are disabled in both normal and debug mode to avoid logging query-string secrets.

## Development

```bash
uv sync --extra dev
uv run scripts/audit_secrets.py
uv run pytest
uv run ruff check .
uv build
uv run promptlatch scan 'OPENAI_API_KEY=<api-key-like-value>'
```

Fixtures are split in source so no real or contiguous fake keys are committed.
Release and test commands live in [CONTRIBUTING.md](CONTRIBUTING.md). Report
security problems through the private path in [SECURITY.md](SECURITY.md), without
posting real secrets.
