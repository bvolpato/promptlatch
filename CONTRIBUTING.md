# Contributing

Changes to redaction, forwarding, config, logs, or tracing need an explicit privacy review.

## Setup

```bash
uv sync --extra dev --group audit --locked
uv run promptlatch doctor
```

## Checks

```bash
uv run scripts/audit_secrets.py
uv run ruff check .
uv run pytest
uv build
```

## Release

Release tags create GitHub releases through `.github/workflows/release.yml`.

```bash
VERSION=0.2.1
uv run scripts/check_release.py --tag "v${VERSION}"
uv run scripts/audit_secrets.py
uv run ruff check .
uv run pytest
uv build
git tag -s "v${VERSION}" -m "PromptLatch ${VERSION}"
git push origin main "v${VERSION}"
```

Before tagging, keep these versions identical:

- `pyproject.toml`
- `src/promptlatch/version.py`
- `charts/promptlatch/Chart.yaml`
- `charts/promptlatch/values.yaml`
- `uv.lock`

Release workflow reruns checks, builds source, wheel, and Helm artifacts, writes
`SHA256SUMS`, attests build provenance, publishes SBOM-backed container image, and
uploads release assets.

If publishing fails after release creation, fix workflow on `main` and rerun
existing immutable tag:

```bash
gh workflow run release.yml --ref main -f tag="v${VERSION}"
```

## Secret hygiene

- Do not put real secrets, customer prompts, credentials, or private config in issues, tests, docs, commits, or screenshots.
- Use split fixture strings like `"sk-" + "FixtureToken..."` when tests need provider-shaped values.
- Prefer full masking in examples: `[REDACTED_SECRET]`.
- Run secret audit before opening a pull request.

## Redaction rules

- Keep detection local and deterministic. Do not add model calls.
- Do not enable entropy-only detectors without tightly bounded false positives.
- Tests for new provider patterns must prove full redaction and comma-separated redaction.

## Emergency request tracing

`promptlatch serve --debug-requests` logs raw request bodies. Use only with local fixture values.
