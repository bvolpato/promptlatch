# Security policy

PromptLatch redacts secrets from LLM request content before forwarding it.

## Reporting

Do not include real secrets, credential-bearing logs, or private prompts in public
issues.

Report vulnerabilities privately through GitHub Security Advisories for this repository. If advisories are unavailable, open a minimal issue asking for a private contact path without details.

## What it does

- No telemetry or analytics. The only outside request that PromptLatch makes on its own is a daily download of a public price list, which sends no prompts, keys, or usage. `observability.pricing_enabled: false` turns it off.
- Redaction runs locally with deterministic `bc-detect-secrets` plugins plus provider rules.
- Request scanning stays in memory and does not write prompt bodies to temporary files.
- Local history stores redacted request bodies by default. `observability.store_request_bodies: false` keeps metadata only.
- Audit logs contain the request path, redaction counts, and rule names. They do not contain the matched values.
- Client-supplied auth headers are dropped unless forwarding is explicitly configured.
- Private/loopback target URLs are blocked by default to reduce SSRF risk.

## Limits

- Upstream credentials remain in provider-bound auth headers because the provider
  needs them. PromptLatch masks these headers in debug output.
- Incoming `gzip` and `zstd` request bodies are decompressed with bounded expansion limits before redaction; other or stacked `Content-Encoding` values are rejected with `415` while redaction is enabled.
- Multipart uploads are rejected while redaction is enabled. Attachments are not scanned.
- Private-target checks validate DNS before connection but do not pin that resolution. Allow only trusted upstream hostnames.
- Emergency request tracing can print raw request bodies locally.
- Provider responses pass through without scanning or redaction.
- URL paths and header values are forwarded without scanning. A secret in a URL path also reaches the audit log and history.
- Base64 and other encoded text is not decoded before scanning. Binary and image content is not scanned.
- Detection quality depends on known provider formats, labeled values, connection-string shapes, and configured tail/regex rules.
- Entropy-only matching is disabled to avoid unpredictable false positives.

## Deployment defaults

- Bind to `127.0.0.1`.
- Keep `target.forward_client_authorization: false`.
- Keep `target.block_private_targets: true`.
- Set `target.allowed_base_urls` when shared by teams.
- Store only secret tails in custom rules.
- Use full redaction mode.
- Add custom regex or tail rules for private/internal token formats.
