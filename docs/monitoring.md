# Local monitoring

Server mode records request metrics on your machine. Python library calls do not create monitoring databases.

- [Terminal](#terminal)
- [Dashboard](#dashboard)
- [What is stored](#what-is-stored)
- [Metrics](#metrics)
- [Conversation grouping](#conversation-grouping)
- [Storage](#storage)
- [Settings](#settings)

## Terminal

Inspect usage, cost estimates, redaction counts, and live traffic without a browser:

```bash
promptlatch stats --days 7
promptlatch tail --limit 20 --traffic inference
promptlatch tail --follow --errors
```

`stats` and `tail` open the history databases read-only, never create state files, and support `--json`. `tail --json` emits metadata-only JSON Lines without request bodies, upstream error text, or prompt previews.

## Dashboard

Enable the optional dashboard on the same server:

```bash
promptlatch serve --dashboard
```

Open `http://127.0.0.1:8000/`. The command prints the path of a private dashboard token file. Enter that file's token in the app. The token is separate from the proxy API key, is not printed in logs, and is never added to a URL. To enable the dashboard through config, set `observability.dashboard_enabled: true`.

The dashboard shares the proxy's bind address and port. Keep the default loopback binding for local use. Remote access requires a protected transport such as an HTTPS reverse proxy or SSH tunnel.

### Sign-in

Signing in creates a browser session that expires 30 days after authentication. The session uses an HttpOnly cookie and survives page reloads, browser restarts, and server restarts. Activity does not extend its expiry. The app does not retain the file token in browser storage.

Lock removes the browser session cookie. Changing the file token and restarting the server invalidates all sessions. Otherwise, a copied session cookie remains valid until its expiry.

Cookies belong to one hostname and browser profile. Keep using the same address, because `localhost` and `127.0.0.1` have separate cookies. Signing in clears a stale root-path dashboard cookie that could otherwise collide with the current cookie.

### Routes

When enabled, `/` serves the app and `/_promptlatch/` is reserved for its assets and authenticated monitoring API. These requests are not proxied or included in request history. Provider routes continue on their existing paths.

The monitoring namespace remains local when the dashboard is disabled, so stale browser tabs cannot forward their access token upstream. With the dashboard enabled, forwarded responses receive a browser sandbox policy that prevents upstream HTML or scripts from accessing its origin. API response bodies are unchanged.

### Sessions and requests

The dashboard opens a compact request inspector with a session tree in the sidebar. Sessions show status, model, combined request time, estimated API cost, and message previews. Combined request time sums retained request durations, including overlaps. Token totals show a `+` when some retained requests have unknown usage.

Requests and captured conversation history appear newest first. Search and status, provider, and model filters apply to loaded sessions.

Expand a session to browse user turns and request iterations. Select an iteration to inspect its conversation history, raw payload, metrics, and redactions in the main pane. User-turn groups are inferred from submitted history, and tool-result iterations stay under the preceding user turn. Incremental Responses requests expose retained parent links when available. Older records without turn metadata remain ungrouped iterations.

Each selected request has a `#request=<request-id>` deep link. Copy link copies that address. Opening it restores the request after sign-in, including older session and iteration pages. Evicted requests show an unavailable notice.

Session and turn rows include the beginning of the user request. Each iteration also previews the latest user text and previous assistant answer from its captured request history. Previews are redacted, capped at 200 characters each, and evicted with request details. They are not part of long-lived usage statistics. A positive body capture limit allows previews even when the body is truncated. Setting `max_body_bytes: 0` disables both. Incremental requests may omit the previous answer from their context.

The request tree defaults to inference calls. Select **All HTTP traffic** to inspect ancillary GETs and other proxy calls. Their records remain retained, and deep links to those requests open the matching traffic view automatically.

Conversation omits entries without readable content, including encrypted-only reasoning and tool metadata declarations. Payload preserves the captured data, with JSON formatting, syntax highlighting, line wrapping, and a copy control. The capture badge distinguishes complete, partial, and unavailable request bodies.

### Stats

Stats is global, independent of the selected request and sidebar filters. It shows token totals, latency, estimated cost, and redaction counts by rule. Active requests enter statistics when they finish. All time uses preserved lifetime totals. Daily, model, and rule breakdowns cover retained aggregate history.

## What is stored

Counts describe matches, not unique leaked credentials. Request details contain the redacted payload, capped at 256 KiB by default, without secret samples, raw headers, or response bodies. Bodies are omitted when redaction is disabled, partial masking is selected, or content is binary or encoded.

Redaction is not anonymization. Stored prompts can retain source code, personal information, and unrecognized credentials. For metadata-only monitoring, set `observability.store_request_bodies: false`. To disable recording, set `observability.enabled: false`. These settings affect future requests, and existing history remains on disk. Keep the state directory private.

### Upstream errors

Request details can retain allowlisted upstream error `event`, `type`, `code`, `message`, and `param` fields. These fields are always fully redacted, regardless of request redaction settings. `message` is capped at 2 KiB, `event` at 128 bytes, and `type`, `code`, and `param` at 256 bytes each, with all error fields under 4 KiB total.

Capture is disabled when `store_request_bodies: false` or `max_body_bytes: 0`. Error fields are stored with request details, evicted with them, and excluded from long-lived aggregates. Full upstream response bodies and raw headers are never retained.

### Transport failures

Transport failures, including TLS and socket errors, retain the exception type, safe reason, first failed transport phase and elapsed milliseconds, socket cause and errno when available, request body size, and observed response byte count. Diagnostics identify connection setup as `new`. For HTTP/1, they infer `reused` when request headers start without a connect phase. Known TLS reason constants are retained. Arbitrary exception text is excluded. These fields help investigate connection failures. They do not establish the cause or eliminate resets.

Selected provider request IDs and Cloudflare ray IDs are bounded, validated, and fully redacted before storage. Raw exception text, URLs, and trace payloads are never retained or included in proxy-generated 502 responses.

Recognized LLM streams that end without a completion event show `stream_incomplete` when no more specific provider or transport error is available. Provider-declared incomplete generations retain known stop reasons, including output limits and content filtering, without being classified as connection failures. Older records cannot recover these details.

## Metrics

- **TTFT:** elapsed time from request start to first generated output, rather than upstream response headers. Nonstreaming responses do not provide TTFT.
- **TPS after first output:** `(output_tokens - 1) / (last_output - first_output)`. Stream chunks can contain multiple tokens, so this is approximate. Missing usage or fewer than two timed output events leaves TPS unknown.
- **Usage:** provider-reported input, output, and total tokens. Missing usage stays unknown. PromptLatch does not substitute character counts. Reasoning, cached input, and cache-write tokens appear when supplied. Response parsing recognizes JSON and SSE even when the content type is missing or incorrect. Requests show why metrics are unavailable. Old captures cannot recover unrecorded usage.
- **Cost:** estimates from a bundled [LiteLLM pricing catalog](https://github.com/BerriAI/litellm/blob/main/model_prices_and_context_window.json) snapshot and its public pricing map for supported exact model matches. The LiteLLM SDK is not required. Catalog version and checksum identify offline rates. Unknown models, usage, or unsupported pricing remain unknown. Estimates are not invoices.

The pricing map refreshes in the background daily. No prompts, keys, model selections, or usage are sent to the pricing source. To disable the download and all cost estimates, set `observability.pricing_enabled: false`.

ChatGPT subscription calls use equivalent OpenAI API token rates, labeled **API-price equivalent**. These estimates compare API usage costs and are not subscription charges. Non-LLM requests do not count as missing LLM usage or pricing.

Retained subscription requests with complete usage can also receive estimates in background batches. Request details and aggregate costs update together, and missing usage remains unknown. Historical comparisons use current standard API text-token rates, excluding extra media and hosted-tool charges. They do not reconstruct an earlier bill or service tier.

## Conversation grouping

For reliable grouping, send `X-PromptLatch-Thread-ID` with a stable conversation identifier. PromptLatch strips this header before forwarding and HMAC-hashes thread identifiers locally.

Metadata thread, conversation, and session IDs and Responses `previous_response_id` links also group related requests. Without those, matching first-user-message and preceding system content provides best-effort grouping, labeled as inferred. Requests without usable history remain ungrouped.

## Storage

Storage defaults to `$XDG_STATE_HOME/promptlatch/requests.sqlite3`, or `~/.local/state/promptlatch/requests.sqlite3` when `XDG_STATE_HOME` is unset. Set `observability.database_path` to choose another location.

Both the request database and `<database_path>.stats.sqlite3` share the configured physical cap, 1 GiB by default, including rollback journals. SQLite page limits reserve journal headroom, leaving roughly half the budget for database pages. Oldest request details are evicted first, then oldest daily and model aggregates if needed. Lifetime request, token, cost, latency, and redaction totals survive eviction. The dashboard shows combined storage and pruning counts.

Startup checks existing files and installs page limits before writing. Legacy files without room for safe journal copies are refused without growth and require offline compaction. Startup does not create a temporary `VACUUM` copy.

A bounded background writer keeps SQLite work off the request event loop. Dropped records are reported when storage cannot keep up. Graceful shutdown drains queued events. Abrupt process termination can lose events that have not reached SQLite.

One server process can write to each history database, guarded by `<database_path>.lock`. Use separate database paths for multiple proxy workers. Starting a second writer against the same path fails.

For containers, mount a persistent writable volume and set `XDG_STATE_HOME` or `PROMPTLATCH_OBSERVABILITY_DATABASE_PATH` inside it. The Helm chart has no value for a persistent volume and uses `emptyDir`. Enable the dashboard on that server when needed. It uses the same history and listening port.

## Settings

The main settings are in the [configuration reference](configuration.md). Additional `observability` settings are `queue_size` (default 1024), `pricing_refresh_hours` (24), and `pricing_file` for a local LiteLLM-format JSON price map. Environment overrides use `PROMPTLATCH_OBSERVABILITY_` followed by the uppercase setting name. The dashboard override is `PROMPTLATCH_DASHBOARD_ENABLED`.
