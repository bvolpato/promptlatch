# Configuration

PromptLatch reads `~/.config/promptlatch/config.yaml` by default. Pass `--config <path>` to use another file. To create a starting file, run `promptlatch init`.

`${NAME}` values are read from the environment, so keep keys out of the file.

```yaml
server:
  host: 127.0.0.1
  port: 8000
  api_key: null
  max_request_body_bytes: 0
  max_decompressed_request_body_bytes: 67108864

target:
  default_base_url: https://api.openai.com/v1
  api_key: ${OPENAI_API_KEY}
  api_key_header: authorization
  forward_client_authorization: false
  timeout_seconds: 180
  allowed_base_urls: []
  block_private_targets: true
  request_compression:
    enabled: true
    min_bytes: 16384
    endpoints: {}

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

observability:
  enabled: true
  max_database_bytes: 1073741824
  max_body_bytes: 262144
  store_request_bodies: true
  pricing_enabled: true
  dashboard_enabled: false
```

## Redaction modes

| `redaction.redact_mode` | Placeholder | Use it for |
| --- | --- | --- |
| `full` (default) | `[REDACTED_SECRET]` | Most setups. |
| `tagged` | `[REDACTED:<rule>#<8-hex-hmac>]` | Multi-turn prompts and traces that must tell identical credentials from different ones. |
| `partial` | First and last characters plus a digest | Local debugging. History does not store request bodies in this mode. |

Tagged placeholders expose no secret characters. The HMAC key is random per process by default. For tags that stay the same across restarts, set `redaction.tag_key` or `PROMPTLATCH_REDACTION_TAG_KEY` to at least 16 characters.

## Custom rules

Add a rule for each private token format. Store only the tail of a key in an exact rule. Exact values of 16 characters or fewer match as a tail inside a longer value.

Per-request rules are exact matches by default. Regex rules remain available in trusted config. Set `redaction.allow_extra_regex_rules: true` only for authenticated clients that you trust.

## Request size limits

Request size is unlimited by default (`0`), including inline base64 images and conversation history. To impose a limit, set `server.max_request_body_bytes` or `PROMPTLATCH_MAX_REQUEST_BODY_BYTES` to a positive byte count. Existing configs retain their explicit limit. Set it to `0` to remove it.

Decompressed `gzip` and `zstd` client request bodies are capped at 64 MiB by default. Change the cap with `server.max_decompressed_request_body_bytes` or `PROMPTLATCH_MAX_DECOMPRESSED_REQUEST_BODY_BYTES`. Set it to `0` to disable it.

Requests are buffered for redaction, so available memory and upstream provider limits still apply. History capture remains capped at 256 KiB per request and SQLite storage at 1 GiB. For all `observability` settings, see [local monitoring](monitoring.md).

## Upload compression

Large JSON POST requests use fast zstd compression for these exact upstream endpoints:

- `https://api.openai.com/v1/responses`
- `https://chatgpt.com/backend-api/codex/responses`

Compression runs after redaction and any Responses-to-Chat conversion. Unknown
endpoints receive uncompressed requests. Small requests and compression results
that would increase the upload size also remain uncompressed. Request compression
does not change response compression negotiation or native SSE streaming.

Configure gzip or zstd for another endpoint only after verifying provider support.
Use `identity` to disable compression for one endpoint:

```yaml
target:
  request_compression:
    enabled: true
    min_bytes: 16384
    endpoints:
      https://provider.example/v1/responses: gzip
      https://api.openai.com/v1/responses: identity
```

Endpoint overrides match the exact scheme, host, port, and path. Set
`PROMPTLATCH_REQUEST_COMPRESSION_ENABLED=false` to disable upload compression, or
`PROMPTLATCH_REQUEST_COMPRESSION_MIN_BYTES` to change the size threshold.

Request history records the redacted body size before compression, encoded body
size, codec, and compression time. Byte counts describe the prepared HTTP body.
Compression failures fall back to uncompressed bytes
before sending; failed upstream POSTs are never replayed automatically. Incoming
`gzip` and `zstd` client request bodies are decompressed in bounded chunks before
redaction and re-compressed for configured upstream endpoints when eligible.

Provider token and decompressed-body limits still apply. For the public OpenAI
Responses endpoint, PromptLatch skips zstd when it would exceed the documented
100:1 expansion ratio. See [OpenAI's request compression limits](https://developers.openai.com/api/docs/guides/production-best-practices#compress-request-bodies).

## Encrypt rules at rest

```bash
promptlatch encrypt-rules
```

This creates `~/.config/promptlatch/key` with mode `0600`, encrypts
`redaction.rules` with AES-GCM, writes `redaction.encrypted_rules`, and clears
plain rules.

You can also provide key material through:

```bash
export PROMPTLATCH_CONFIG_KEY="base64-url-safe-32-byte-key"
```

## Emergency request tracing

`promptlatch serve --debug-requests` logs raw request bodies before redaction. Restrict it to local fixture data and cases where an echo target is insufficient. Auth, target-key, and redaction-rule headers are masked; body text is visible.

Uvicorn access logs are disabled in both normal and debug mode to avoid logging query-string secrets.
