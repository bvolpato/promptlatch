# Providers and routes

## Supported routes

PromptLatch forwards any path, with first-class tests for:

- `/v1/chat/completions`
- `/v1/responses`
- `/v1/completions`
- `/v1/models` and `/v1beta/models`
- `/v1/messages` for Claude-compatible gateways
- `/v1beta/models/{model}:generateContent` and `:streamGenerateContent` for Google Gemini

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

Set `X-Target-API-Key-Header: x-api-key` for Anthropic-style upstream authentication,
or `X-Target-API-Key-Header: x-goog-api-key` for Google Gemini API keys (do not pass
API keys in `?key=` query parameters, as PromptLatch redacts query-string secrets).

Configured target keys are bound to `target.default_base_url`. A dynamic target that
requires authentication must receive its key through `X-Target-API-Key` or
`X-Target-Authorization`; PromptLatch never reuses configured key for another host.

An empty `target.allowed_base_urls` permits any public target. Add URLs to restrict
dynamic routing. Set `block_private_targets: false` only for trusted local targets.

For custom rules per request, see [custom rules](configuration.md#custom-rules).

| Target | Base URL | Auth header | Notes |
| --- | --- | --- | --- |
| OpenAI | `https://api.openai.com/v1` | `authorization` | Native Chat Completions, Responses API, models, tools, streaming. |
| OpenRouter | `https://openrouter.ai/api/v1` | `authorization` | Native Chat Completions and Responses. Use provider-prefixed model names. |
| Anthropic / Claude-compatible | `https://api.anthropic.com` | `x-api-key` | Forward `/v1/messages`; PromptLatch does not translate OpenAI JSON into Anthropic JSON. |
| Google Gemini | `https://generativelanguage.googleapis.com` | `x-goog-api-key` | Forward `/v1beta/models/{model}:generateContent` and `:streamGenerateContent` (`?alt=sse`). |
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

Google Gemini target:

```bash
curl http://127.0.0.1:8000/v1beta/models/gemini-2.5-pro:generateContent \
  -H "X-Target-Base-URL: https://generativelanguage.googleapis.com" \
  -H "X-Target-API-Key: $GEMINI_API_KEY" \
  -H "X-Target-API-Key-Header: x-goog-api-key" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"role":"user","parts":[{"text":"scan this <api-key-like-value>"}]}]}'
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

## Streaming and opaque data

Native Responses requests preserve recognized encrypted reasoning and compaction
envelopes unchanged. Typed image parts in OpenAI Responses and canonical `inlineData`
image blobs in Google Gemini `generateContent` requests also preserve canonical PNG,
JPEG, GIF, and WebP payloads with matching binary signatures. Typed canonical Fernet
encrypted content parts in `agent_message.content` and tool outputs are preserved
unchanged on forwarding. Readable text parts, summaries, prompts, and other fields
still pass through redaction. The stored troubleshooting copy can apply
additional credential masking; it is never reused as the forwarded request.
An `invalid_encrypted_content` error identifies rejected encrypted conversation
state, rather than a connection timeout. Existing corrupted history cannot be
repaired from a truncated or redacted capture.

Streams close upstream connections on client disconnect, including cancellation
during cleanup. Native response bytes and upstream errors remain unchanged;
PromptLatch does not replay partially delivered generations or invent a
successful completion event. `target.timeout_seconds` limits upstream read
inactivity, not the total generation time.
