# Coding agents

Run Codex, Claude Code, Antigravity CLI, or OpenCode through a local PromptLatch proxy.

- [Wrapper commands](#wrapper-commands) for Codex, Claude Code, and Antigravity CLI
- [Antigravity CLI](#antigravity-cli)
- [Claude Code manual configuration](#claude-code-manual-configuration)
- [Codex with OpenRouter](#codex-with-openrouter)
- [OpenCode](#opencode)

## Wrapper commands

Run Codex, Claude Code, and Antigravity CLI through one local PromptLatch server, using
their own provider credentials and the official upstream endpoints:

```bash
uv tool install promptlatch
curl -fsSL -o agents.yaml \
  https://raw.githubusercontent.com/bvolpato/promptlatch/main/examples/promptlatch-agents.config.yaml
promptlatch serve --config agents.yaml
```

In another terminal, run one of the wrappers:

```bash
codex-latch
claude-latch
agy-latch
```

Install the original CLIs first. Sign in to Codex and Claude Code (`codex login`,
`claude auth login`), and set `GEMINI_API_KEY` for Antigravity CLI. Requires Codex 0.162.1+,
Claude Code 2.1.220+, and Antigravity CLI 1.5.8+.
These versions support the configuration checks and provider settings used to keep
requests on the proxy. The shims preserve client credentials and configuration files.
The example binds to loopback, enables client-auth forwarding, restricts targets to
the official endpoints below, and enables the inspector at `http://127.0.0.1:8000/`.
Use your existing server instead if it has equivalent authentication and native
Responses settings. Do not start a second server on an occupied port.

| Command / authentication | Upstream |
| --- | --- |
| `codex-latch`, saved ChatGPT login | `https://chatgpt.com/backend-api/codex` |
| `codex-latch`, OpenAI API key | `https://api.openai.com/v1` |
| `claude-latch`, Claude login or Anthropic API key | `https://api.anthropic.com` |
| `agy-latch`, Gemini API key (`GEMINI_API_KEY`) | `https://generativelanguage.googleapis.com` |

Codex detects the saved login mode using `codex login status`; its output is never
printed by the shim. Set `PROMPTLATCH_CODEX_AUTH=chatgpt` or `api-key` to select
explicitly. API-key mode uses `OPENAI_API_KEY` when set, otherwise Codex's saved
API-key login. Claude keeps its normal authentication precedence, including
`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, and its saved login.

```bash
codex-latch exec "Review this repository"
PROMPTLATCH_CODEX_AUTH=api-key codex-latch
PROMPTLATCH_PROXY_URL=http://127.0.0.1:8001 claude-latch
agy-latch -p "Summarize recent changes"
codex-latch --latch-help
claude-latch --latch-help
agy-latch --latch-help
```

The shims check proxy readiness and redaction before launching. They stop if the
proxy is unavailable, redaction is disabled, or native client authentication cannot
be forwarded. This mode requires no `server.api_key` or `target.api_key`; keep the
listener local. Normal keyed-proxy configuration remains available for other clients.
`PROMPTLATCH_PROXY_URL` accepts loopback addresses only. Use
`PROMPTLATCH_CODEX_BIN`, `PROMPTLATCH_CLAUDE_BIN`, or `PROMPTLATCH_AGY_BIN` to
select a CLI executable explicitly.

Codex's effective provider configuration is checked before launch. Conflicting
provider settings, managed routing requirements, and Codex Cloud commands stop with
an error. Profiles work unless they redefine the reserved `promptlatch-official`
provider. Claude's host-managed provider setting prevents settings files from
replacing the proxy route. For Antigravity CLI, see [Antigravity CLI](#antigravity-cli).

Codex uses a local process and HTTP Responses streaming. `codex-latch` and `claude-latch` disable request
compression so request bodies remain scannable. Claude's nonessential traffic is
disabled for the invocation. These wrappers cover model-provider requests, including
conversation history and tool outputs sent back to the model. Login, MCP servers,
tool subprocesses, plugins, and other network connections are separate. Files and
images embedded as binary or encoded content are not scanned. See [SECURITY.md](../SECURITY.md).

Configuration references: [Codex gateway authentication](https://learn.chatgpt.com/docs/enterprise/sign-in-with-chatgpt-through-a-gateway),
[Claude Code gateways](https://code.claude.com/docs/en/llm-gateway), and
[Claude Code networking](https://code.claude.com/docs/en/corporate-proxy).

## Antigravity CLI

Google replaced Gemini CLI with Antigravity CLI (`agy`). Start the proxy as in
[Wrapper commands](#wrapper-commands). Then run the wrapper with a Gemini API key:

```bash
export GEMINI_API_KEY="<gemini-api-key>"
agy-latch
```

Account sign-in is not supported, because `agy` documents no way to send those requests to a
proxy.
`agy-latch` uses the [gateway variables](https://docs.cloud.google.com/gemini/enterprise/docs/ai-developer-tools/connect-enterprise-gateway)
of Antigravity CLI and applies only to one run. It changes no settings file:

- `AGY_LLM_GATEWAY_URL` points to the proxy, and `AGY_LLM_GATEWAY_HEADERS` names the Gemini API
  as the target and carries the API key.
- `--settings` clears `modelProvider`, because a saved `gemini` provider sends requests straight
  to Google.
- `GEMINI_API_KEY`, `GOOGLE_GEMINI_BASE_URL`, and other variables that select a different route
  are removed from the environment of `agy`.

`agy-latch` stops with an error if any of these could bypass the proxy:

- The proxy is down, or redaction is off.
- The arguments contain `--settings`, `--remote-agent`, `--remote-control`, `acp`, or
  `remote-control`.
- `AGY_ADC_AUTH` is on, or `AGY_LLM_GATEWAY_URL` names another gateway.
- The managed `admin_settings.json` file or `~/.antigravity/settings.json` has `gateway` or
  `proxy` settings.

Web page reads, MCP servers, tool subprocesses, and updates use separate connections that
PromptLatch does not scan.

## Claude Code manual configuration

Claude Code sends Anthropic Messages requests. Configure the provider key on PromptLatch,
and use a separate local bearer token for proxy authentication:

```bash
export ANTHROPIC_UPSTREAM_API_KEY="<anthropic-upstream-key>"
export PROMPTLATCH_TARGET_BASE_URL="https://api.anthropic.com"
export PROMPTLATCH_TARGET_API_KEY="$ANTHROPIC_UPSTREAM_API_KEY"
export PROMPTLATCH_TARGET_API_KEY_HEADER="x-api-key"
export PROMPTLATCH_SERVER_API_KEY="<local-proxy-key>"
promptlatch serve
```

In another terminal:

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8000"
export ANTHROPIC_AUTH_TOKEN="<local-proxy-key>"
export DISABLE_TELEMETRY=1
export DO_NOT_TRACK=1
claude
```

PromptLatch validates the local bearer token, removes it, then adds the upstream `x-api-key`.
It forwards `/v1/messages` without translating between OpenAI and Anthropic schemas.

## Codex with OpenRouter

OpenRouter accepts native Responses requests, so no compatibility bridge is needed.
Keep the OpenRouter key in the environment and send it through PromptLatch's dedicated target
header. Generic client `Authorization` is not forwarded.

Start PromptLatch:

```bash
curl -fsSL -o openrouter.yaml \
  https://raw.githubusercontent.com/bvolpato/promptlatch/main/examples/promptlatch-openrouter.config.yaml
promptlatch serve --config openrouter.yaml
```

This config restricts dynamic routing to OpenRouter and leaves
`forward_client_authorization` and `responses_to_chat` disabled.

Install the Codex profile:

```bash
mkdir -p ~/.codex
curl -fsSL -o ~/.codex/openrouter-promptlatch.config.toml \
  https://raw.githubusercontent.com/bvolpato/promptlatch/main/examples/codex-openrouter-promptlatch.config.toml
export OPENROUTER_API_KEY="<openrouter-upstream-key>"
```

Profile contents:

```toml
model = "openai/gpt-oss-120b"
model_provider = "promptlatch-openrouter"
model_reasoning_effort = "high"

[model_providers.promptlatch-openrouter]
name = "PromptLatch OpenRouter"
base_url = "http://127.0.0.1:8000/v1"
wire_api = "responses"
env_http_headers = { "X-Target-API-Key" = "OPENROUTER_API_KEY" }
http_headers = { "X-Target-Base-URL" = "https://openrouter.ai/api/v1" }
request_max_retries = 0
stream_max_retries = 0
```

Run interactive Codex:

```bash
codex -p openrouter-promptlatch
```

Non-interactive smoke test:

```bash
codex exec -p openrouter-promptlatch --strict-config \
  --sandbox read-only --ephemeral --cd "$PWD" \
  "Reply with exactly: promptlatch-openrouter-ok"
```

Use any OpenRouter Responses-capable model by changing `model` in the profile. Current Codex
requests include Responses-only custom tool descriptors, so Codex needs a backend with
native Responses support. `compat.responses_to_chat` remains available for simpler
Responses clients limited to text, messages, and standard function tools.

## OpenCode

The current stable OpenCode config supports custom Chat Completions providers through
`@ai-sdk/openai-compatible`. Start the proxy as in [Codex with OpenRouter](#codex-with-openrouter). Then
download the example into your project, or merge the provider block into an existing `opencode.json`:

```bash
curl -fsSL -o opencode.json \
  https://raw.githubusercontent.com/bvolpato/promptlatch/main/examples/opencode-openrouter-promptlatch.json
export OPENROUTER_API_KEY="<openrouter-upstream-key>"
```

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "promptlatch-openrouter": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "PromptLatch OpenRouter",
      "options": {
        "baseURL": "http://127.0.0.1:8000/v1",
        "headers": {
          "X-Target-Base-URL": "https://openrouter.ai/api/v1",
          "X-Target-API-Key": "{env:OPENROUTER_API_KEY}"
        }
      },
      "models": {
        "openai/gpt-oss-120b": {
          "name": "gpt-oss via PromptLatch"
        }
      }
    }
  },
  "model": "promptlatch-openrouter/openai/gpt-oss-120b"
}
```

Run:

```bash
opencode run -m promptlatch-openrouter/openai/gpt-oss-120b \
  --format json --dir "$PWD" \
  "Reply with exactly: promptlatch-opencode-ok"
```

For another Chat Completions target, replace the base URL, environment variable, and
model ID. Use `PROMPTLATCH_TARGET_BASE_URL` and `PROMPTLATCH_TARGET_API_KEY` instead
when PromptLatch owns one fixed upstream.
