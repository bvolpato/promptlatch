# Monitor

Verify each published surface after deployment.

## GitHub

- `ci`, `codeql`, and `release` workflows passed for release commit/tag.
- Release includes wheel, source archive, Helm chart, and `SHA256SUMS`.
- Downloaded assets match `SHA256SUMS`; build provenance verifies.
- Dependabot, secret-scanning, and code-scanning alerts remain empty.

## Container and Helm

```bash
docker pull ghcr.io/bvolpato/promptlatch:0.2.0
docker run --rm --entrypoint promptlatch ghcr.io/bvolpato/promptlatch:0.2.0 version
helm lint ./charts/promptlatch
```

## Homebrew and site

- `brew info bvolpato/tap/promptlatch` reports release version.
- Formula install/test passes.
- `https://bvolpato.github.io/promptlatch/` matches `site/` and loads assets.

## Local service

```bash
systemctl --user is-enabled promptlatch.service
systemctl --user is-active promptlatch.service
curl --retry 10 --retry-connrefused --retry-delay 1 -fsS http://127.0.0.1:8000/healthz
curl --retry 10 --retry-connrefused --retry-delay 1 -fsS http://127.0.0.1:8000/openapi.json | jq -r .info.version
docker exec promptlatch-local promptlatch version
curl --retry 10 --retry-connrefused --retry-delay 1 -fsS http://127.0.0.1:8787/healthz
```

Both health endpoints must report redaction enabled, `detect-secrets`, and `telemetry:false`.
Both runtimes must report release version. `promptlatch-local` must bind loopback, restart unless
stopped, and run with raw-request debug off.
