# Security review

Last reviewed: 2026-08-12

This maintainer review covers proxy, redaction engine, library helpers, config,
debug logging, release workflow, and public git history. It is not an independent
penetration test.

## Checks

- Request tests cover nested JSON, query strings, text bodies, multipart bodies,
  provider-shaped fixtures, custom rules, and comma-separated values.
- Forwarding tests cover OpenAI-compatible and Anthropic routes, streaming,
  dynamic targets, auth-header handling, and response pass-through.
- Debug tests verify masking for auth, target-key, proxy-auth, and redaction-rule
  headers. Raw body logging remains deliberate and fixture-only.
- Release checks use locked dependencies, isolated publish permissions, signed
  tags, checksums, provenance attestations, and secret audit.
- Upgrade checks preserve proxy authentication across legacy environment variables,
  config paths, and existing Helm releases.
- Fixtures contain `FixtureToken` markers and split provider prefixes. No real or
  contiguous provider-shaped keys are committed.

## Residual risks

- New or private credential formats may need custom exact-tail or regex rules.
- DNS private-target validation is not connection-pinned. Allow only trusted
  upstream hostnames.
- Provider auth headers must reach their provider. PromptLatch masks them in debug
  output but cannot remove them from the upstream request.
- Provider responses pass through without scanning.
- Emergency tracing prints raw request bodies. Use it only with local fixture data.
