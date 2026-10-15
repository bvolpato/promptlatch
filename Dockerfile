FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 AS builder

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --no-dev --no-editable --locked

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PATH="/app/.venv/bin:$PATH" \
    PROMPTLATCH_HOST=0.0.0.0 \
    PROMPTLATCH_PORT=8000

WORKDIR /app
RUN groupadd --gid 10001 promptlatch \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin promptlatch
COPY --from=builder --chown=promptlatch:promptlatch /app /app
USER 10001:10001
EXPOSE 8000
CMD ["promptlatch", "serve", "--host", "0.0.0.0", "--port", "8000"]
