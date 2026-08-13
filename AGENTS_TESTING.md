# Testing

Run from repository root. Never use real credentials in tests or logs.

```bash
uv sync --extra dev --group audit --locked
uv run scripts/check_release.py
uv run scripts/audit_secrets.py
uv run ruff check .
uv run ruff format --check .
uv run pyright src tests scripts
uv run pytest
uv run pip-audit
uv build
helm lint ./charts/promptlatch
helm template promptlatch ./charts/promptlatch >/dev/null
uv run scripts/check_helm.py
docker build -t promptlatch:release-check .
docker run --rm --entrypoint promptlatch promptlatch:release-check version
```

Before release, also run checks under Python 3.12, 3.13, and 3.14:

```bash
UV_PROJECT_ENVIRONMENT=/tmp/promptlatch-py312 uv sync --python 3.12 --extra dev --locked
UV_PROJECT_ENVIRONMENT=/tmp/promptlatch-py312 uv run pytest
UV_PROJECT_ENVIRONMENT=/tmp/promptlatch-py313 uv sync --python 3.13 --extra dev --locked
UV_PROJECT_ENVIRONMENT=/tmp/promptlatch-py313 uv run pytest
UV_PROJECT_ENVIRONMENT=/tmp/promptlatch-py314 uv sync --python 3.14 --extra dev --locked
UV_PROJECT_ENVIRONMENT=/tmp/promptlatch-py314 uv run pytest
```
