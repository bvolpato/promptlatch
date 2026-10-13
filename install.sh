#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Install PromptLatch and its Codex and Claude Code shims with uv.

Usage: ./install.sh [--help]

The installer adds codex-latch and claude-latch to uv's tool bin directory.
It does not edit client configuration, PromptLatch server settings, or shell startup files.
EOF
}

if [[ $# -gt 0 ]]; then
  if [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]]; then
    usage
    exit 0
  fi
  printf 'Unexpected argument: %s\n' "$1" >&2
  usage >&2
  exit 2
fi

if ! command -v uv >/dev/null 2>&1; then
  printf 'uv is required. Install uv from https://docs.astral.sh/uv/getting-started/installation/ and rerun ./install.sh.\n' >&2
  exit 127
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
uv tool install --reinstall "$script_dir"
