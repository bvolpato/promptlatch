FROM ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f AS uv
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS builder

WORKDIR /app
COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock uv.toml README.md ./
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
