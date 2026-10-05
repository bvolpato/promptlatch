#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["promptlatch"]
#
# [tool.uv.sources]
# promptlatch = { path = "..", editable = true }
# ///
"""Measure PromptLatch redaction and local ASGI proxy overhead."""

from __future__ import annotations

import argparse
import asyncio
import cProfile
import hashlib
import json
import math
import pstats
import resource
import statistics
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from functools import partial
from importlib import metadata
from pathlib import Path
from typing import Any

MESSAGE_COUNT = 120
CONVERSATION_CHARS = 426_000
MESSAGE_CHARS = CONVERSATION_CHARS // MESSAGE_COUNT
HEARTBEAT_INTERVAL_SECONDS = 0.002
HEALTH_CHECKS = 8
STREAM_DELTA_CHARS = 64
STREAM_DELTA_COUNT = 16_384
STREAM_PAYLOAD_CHARS = STREAM_DELTA_CHARS * STREAM_DELTA_COUNT


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Profile large-history redaction and PromptLatch's in-process proxy path."
    )
    parser.add_argument("--samples", type=int, default=20, help="timed requests per scenario")
    parser.add_argument(
        "--stream-samples",
        type=int,
        default=1,
        help="1-3 timing samples per synthetic 1 MiB stream conversion",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        help="repository root whose src/ tree should be imported (for baseline comparisons)",
    )
    parser.add_argument(
        "--stream-chunk-bytes",
        type=int,
        help="rechunk synthetic streams to this size; 0 puts all events in one chunk",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--profile",
        action="store_true",
        help="run separate cProfile passes and print top cumulative functions to stderr",
    )
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be at least 1")
    if not 1 <= args.stream_samples <= 3:
        parser.error("--stream-samples must be between 1 and 3")
    if args.stream_chunk_bytes is not None and args.stream_chunk_bytes < 0:
        parser.error("--stream-chunk-bytes must be nonnegative")
    return args


def configure_source_path(source_root: Path | None) -> Path:
    repository_root = (source_root or Path(__file__).resolve().parent.parent).resolve()
    source_path = repository_root / "src"
    if not (source_path / "promptlatch" / "__init__.py").is_file():
        raise SystemExit(f"no PromptLatch package found under {source_path}")
    path = str(source_path)
    if path in sys.path:
        sys.path.remove(path)
    sys.path.insert(0, path)
    return repository_root


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(p * len(ordered)) - 1)]


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "median": statistics.median(values),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
    }


def measurement_summary(wall_ms: list[float], cpu_ms: list[float]) -> dict[str, Any]:
    return {
        "samples": len(wall_ms),
        "wall_ms_per_request": summarize(wall_ms),
        "process_cpu_ms_per_request": summarize(cpu_ms),
    }


def make_fake_secret() -> str:
    # Split prefix keeps secret scanners from treating this source expression as a credential.
    suffix = hashlib.sha256(b"PromptLatch profile synthetic credential").hexdigest()
    return "sk-" + "proj-" + suffix


def make_message(index: int, tag: str, fake_secret: str, target_chars: int) -> dict[str, str]:
    lines = [
        f"Review request {index:03d} ({tag}): trace how client credentials reach the transport.",
        "Please keep the redaction boundary before JSON encoding and upstream dispatch.",
        "```python",
        "def forward_request(payload, settings, client):",
        "    headers = build_headers(settings, payload.get('headers', {}))",
        "    token = settings.credentials.get('access_token', '')",
        "    if token and 'authorization' not in headers:",
        "        headers['authorization'] = f'Bearer {token}'",
        "    request = client.build_request('POST', target_url, json=payload, headers=headers)",
        "    return await client.send(request, stream=True)",
        "```",
        "The cache key must cover the complete message so repeated history can reuse scans.",
        "An appended user turn should leave prior message strings eligible for cache hits.",
        "The test transport returns an unconsumed response stream to match production reads.",
    ]
    if index == 17:
        lines.extend(
            [
                "```text",
                f"synthetic credential fixture: {fake_secret}",
                "```",
            ]
        )

    content = "\n".join(lines)
    note_index = 0
    while len(content) < target_chars:
        note_index += 1
        code_line = (
            "    result = redact_payload(request_body)  # preserve trace fields and token context; "
            f"message={index:03d} pass={note_index:03d} run={tag}"
        )
        extra = "\n" + code_line
        if len(content) + len(extra) > target_chars:
            remaining = target_chars - len(content)
            if remaining > 1:
                content += "\n" + code_line[: remaining - 1]
            else:
                content += " " * remaining
            break
        content += extra
    return {"role": "user" if index % 2 == 0 else "assistant", "content": content}


def make_messages(tag: str, fake_secret: str) -> list[dict[str, str]]:
    messages = [
        make_message(index, tag, fake_secret, MESSAGE_CHARS) for index in range(MESSAGE_COUNT)
    ]
    if sum(len(message["content"]) for message in messages) != CONVERSATION_CHARS:
        raise AssertionError("synthetic conversation has unexpected character count")
    if len({message["content"] for message in messages}) != MESSAGE_COUNT:
        raise AssertionError("synthetic conversation messages must be unique")
    return messages


def new_redaction_config(RedactionConfig: type, RuleConfig: type, fake_secret: str) -> Any:
    return RedactionConfig(
        engine="detect-secrets",
        redact_mode="full",
        rules=[RuleConfig(type="exact", value=fake_secret, name="synthetic-profile-secret")],
    )


def time_sync_samples(
    samples: int,
    factory: Callable[[], tuple[Callable[[], Any], Callable[[Any], None]]],
) -> tuple[list[float], list[float]]:
    wall_ms: list[float] = []
    cpu_ms: list[float] = []
    for _ in range(samples):
        operation, validate = factory()
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        result = operation()
        cpu_ms.append((time.process_time_ns() - cpu_start) / 1_000_000)
        wall_ms.append((time.perf_counter_ns() - wall_start) / 1_000_000)
        validate(result)
    return wall_ms, cpu_ms


def profile_sync(label: str, operation: Callable[[], Any]) -> None:
    profile = cProfile.Profile()
    profile.enable()
    operation()
    profile.disable()
    print(f"\n=== cProfile: {label} ===", file=sys.stderr)
    pstats.Stats(profile, stream=sys.stderr).strip_dirs().sort_stats("cumulative").print_stats(20)


def make_stream_input(kind: str) -> tuple[list[bytes], str]:
    if kind == "text":
        expected = "t" * STREAM_PAYLOAD_CHARS
    else:
        prefix = '{"payload":"'
        suffix = '"}'
        expected = prefix + "a" * (STREAM_PAYLOAD_CHARS - len(prefix) - len(suffix)) + suffix
        if len(expected) != STREAM_PAYLOAD_CHARS:
            raise AssertionError("synthetic tool argument has unexpected character count")

    chunks: list[bytes] = []
    for index in range(STREAM_DELTA_COUNT):
        delta = expected[index * STREAM_DELTA_CHARS : (index + 1) * STREAM_DELTA_CHARS]
        if kind == "text":
            choice_delta = {"content": delta}
        else:
            function: dict[str, str] = {"arguments": delta}
            tool_call: dict[str, Any] = {"index": 0, "function": function}
            if index == 0:
                tool_call["id"] = "call_synthetic_profile"
                function["name"] = "consume_fixture"
            choice_delta = {"tool_calls": [tool_call]}
        event = {"choices": [{"delta": choice_delta}]}
        chunks.append(b"data: " + json.dumps(event, separators=(",", ":")).encode() + b"\n\n")

    finish_reason = "stop" if kind == "text" else "tool_calls"
    finish = {"choices": [{"delta": {}, "finish_reason": finish_reason}]}
    chunks.append(b"data: " + json.dumps(finish, separators=(",", ":")).encode() + b"\n\n")
    chunks.append(b"data: [DONE]\n\n")
    return chunks, expected


async def convert_chat_stream(chunks: list[bytes], request_payload: dict[str, Any]) -> bytes:
    from promptlatch.compat import chat_stream_to_responses

    async def source() -> AsyncIterator[bytes]:
        for chunk in chunks:
            yield chunk

    return b"".join([part async for part in chat_stream_to_responses(source(), request_payload)])


def parse_response_events(stream: bytes) -> list[dict[str, Any]]:
    events = []
    for line in stream.decode("utf-8").splitlines():
        if line.startswith("data:"):
            payload = line.removeprefix("data:").strip()
            if payload and payload != "[DONE]":
                events.append(json.loads(payload))
    return events


def validate_stream_output(kind: str, output: bytes, expected: str) -> None:
    events = parse_response_events(output)
    completed = next(
        (event for event in reversed(events) if event.get("type") == "response.completed"),
        None,
    )
    if completed is None:
        raise AssertionError(f"synthetic {kind} stream did not complete")
    if kind == "text":
        deltas = [
            event["delta"] for event in events if event.get("type") == "response.output_text.delta"
        ]
        if len(deltas) != STREAM_DELTA_COUNT or "".join(deltas) != expected:
            raise AssertionError("synthetic text delta reconstruction failed")
        done = next(event for event in events if event.get("type") == "response.output_text.done")
        final_text = completed["response"]["output"][0]["content"][0]["text"]
        if done.get("text") != expected or final_text != expected:
            raise AssertionError("synthetic text final content is incomplete")
    else:
        deltas = [
            event["delta"]
            for event in events
            if event.get("type") == "response.function_call_arguments.delta"
        ]
        if len(deltas) != STREAM_DELTA_COUNT or "".join(deltas) != expected:
            raise AssertionError("synthetic tool argument delta reconstruction failed")
        done = next(
            event
            for event in events
            if event.get("type") == "response.function_call_arguments.done"
        )
        final_arguments = completed["response"]["output"][0]["arguments"]
        if done.get("arguments") != expected or final_arguments != expected:
            raise AssertionError("synthetic tool final arguments are incomplete")


def rechunk_stream(chunks: list[bytes], chunk_bytes: int | None) -> list[bytes]:
    if chunk_bytes is None:
        return chunks
    combined = b"".join(chunks)
    if chunk_bytes == 0:
        return [combined]
    return [combined[index : index + chunk_bytes] for index in range(0, len(combined), chunk_bytes)]


async def benchmark_stream_conversions(
    samples: int, chunk_bytes: int | None = None
) -> dict[str, Any]:
    request_payload = {"model": "synthetic-profile-model"}
    result: dict[str, Any] = {
        "network": False,
        "payload_chars_per_kind": STREAM_PAYLOAD_CHARS,
        "deltas_per_kind": STREAM_DELTA_COUNT,
        "chars_per_delta": STREAM_DELTA_CHARS,
        "samples_per_kind": samples,
        "input_chunk_bytes": chunk_bytes,
    }
    for kind in ("text", "tool_arguments"):
        chunks, expected = make_stream_input(kind)
        chunks = rechunk_stream(chunks, chunk_bytes)
        wall_ms: list[float] = []
        cpu_ms: list[float] = []
        output = b""
        for _ in range(samples):
            wall_start = time.perf_counter_ns()
            cpu_start = time.process_time_ns()
            output = await convert_chat_stream(chunks, request_payload)
            cpu_ms.append((time.process_time_ns() - cpu_start) / 1_000_000)
            wall_ms.append((time.perf_counter_ns() - wall_start) / 1_000_000)
            validate_stream_output(kind, output, expected)
        result[kind] = measurement_summary(wall_ms, cpu_ms)
        result[kind].update(
            input_bytes=sum(map(len, chunks)),
            input_chunks=len(chunks),
            output_bytes=len(output),
        )
    return result


def source_fingerprints(repository_root: Path) -> dict[str, str]:
    fingerprints = {}
    for name in ("redaction.py", "proxy.py", "compat.py", "_config_transform.py"):
        path = repository_root / "src" / "promptlatch" / name
        if path.is_file():
            fingerprints[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return fingerprints


def dependency_versions() -> dict[str, str | None]:
    versions = {}
    for distribution in ("bc-detect-secrets", "fastapi", "httpx"):
        try:
            versions[distribution] = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            versions[distribution] = None
    return versions


async def profile_stream_case(kind: str, chunks: list[bytes], expected: str) -> bytes:
    output = await convert_chat_stream(chunks, {"model": "synthetic-profile-model"})
    validate_stream_output(kind, output, expected)
    return output


async def profile_async(
    label: str,
    operation: Callable[[], Awaitable[Any]],
    *,
    body_preprocessing: bool = False,
) -> None:
    profile = cProfile.Profile()
    if body_preprocessing:
        from promptlatch import proxy

        original = proxy._redact_request_body

        def profiled_body(*args: Any, **kwargs: Any) -> Any:
            return profile.runcall(original, *args, **kwargs)

        proxy._redact_request_body = profiled_body
        try:
            await operation()
        finally:
            proxy._redact_request_body = original
        label += " body preprocessing"
    else:
        profile.enable()
        try:
            await operation()
        finally:
            profile.disable()
    print(f"\n=== cProfile: {label} ===", file=sys.stderr)
    pstats.Stats(profile, stream=sys.stderr).strip_dirs().sort_stats("cumulative").print_stats(20)


async def run_http_benchmarks(
    samples: int,
    fake_secret: str,
    extra_secret: str,
    messages: list[dict[str, str]],
    appended_messages: list[dict[str, str]],
    cold_messages: list[dict[str, str]],
    settings: Any,
    SecretRedactor: type,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    Callable[..., Awaitable[Any]],
    Callable[[], Awaitable[None]],
]:
    import httpx

    from promptlatch.proxy import create_app

    body = json.dumps(
        {"model": "synthetic-coding-model", "messages": messages, "stream": False},
        separators=(",", ":"),
    ).encode("utf-8")
    cold_body = json.dumps(
        {"model": "synthetic-coding-model", "messages": cold_messages, "stream": False},
        separators=(",", ":"),
    ).encode("utf-8")
    extra_messages = [dict(message) for message in messages]
    extra_messages[17]["content"] += f"\nsynthetic request-specific rule fixture: {extra_secret}"
    extra_body = json.dumps(
        {"model": "synthetic-coding-model", "messages": extra_messages, "stream": False},
        separators=(",", ":"),
    ).encode("utf-8")
    appended_bodies = [
        json.dumps(
            {
                "model": "synthetic-coding-model",
                "messages": [*messages, appended_message],
                "stream": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        for appended_message in appended_messages
    ]
    extra_rule_header = json.dumps(
        [{"type": "exact", "value": extra_secret, "name": "synthetic-header-secret"}],
        separators=(",", ":"),
    )
    response_bytes = b'{"ok":true}'
    forwarded_requests = 0

    async def upstream_handler(request: httpx.Request) -> httpx.Response:
        nonlocal forwarded_requests
        forwarded_body = await request.aread()
        if any(secret.encode("utf-8") in forwarded_body for secret in (fake_secret, extra_secret)):
            raise AssertionError("synthetic credential reached mocked upstream payload")
        if any(
            secret in value
            for secret in (fake_secret, extra_secret)
            for value in request.headers.values()
        ):
            raise AssertionError("synthetic credential reached mocked upstream headers")
        forwarded_requests += 1
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=httpx.ByteStream(response_bytes),
        )

    app = create_app(settings)
    app.state.client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    asgi_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://promptlatch.profile"
    )

    async def post_body(
        request_body: bytes,
        *,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        response = await asgi_client.post(
            "/v1/chat/completions",
            content=request_body,
            headers={"content-type": "application/json", **(headers or {})},
        )
        if response.status_code != 200:
            raise AssertionError(f"proxy benchmark request returned HTTP {response.status_code}")
        return response

    async def verify_error_response() -> None:
        nonlocal forwarded_requests
        before = forwarded_requests
        response = await post_error_request()
        if response.status_code != 400:
            raise AssertionError(
                f"invalid rule header returned HTTP {response.status_code}, expected 400"
            )
        if forwarded_requests != before:
            raise AssertionError("invalid rule header reached mocked upstream")

    async def post_error_request() -> httpx.Response:
        return await asgi_client.post(
            "/v1/chat/completions",
            content=b'{"model":"synthetic-coding-model","messages":[]}',
            headers={
                "content-type": "application/json",
                "x-redact-extra-rules": "[invalid-json",
            },
        )

    await verify_error_response()

    proxy_cold_wall: list[float] = []
    proxy_cold_cpu: list[float] = []
    proxy_warm_wall: list[float] = []
    proxy_warm_cpu: list[float] = []
    proxy_appended_wall: list[float] = []
    proxy_appended_cpu: list[float] = []
    proxy_extra_wall: list[float] = []
    proxy_extra_cpu: list[float] = []
    concurrent_cold_wall: list[float] = []

    for _ in range(samples):
        app.state.redactor = SecretRedactor(settings.redaction.model_copy(deep=True))
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        await post_body(body)
        proxy_cold_cpu.append((time.process_time_ns() - cpu_start) / 1_000_000)
        proxy_cold_wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)

    app.state.redactor = SecretRedactor(settings.redaction.model_copy(deep=True))
    await post_body(body)
    await post_body(extra_body, headers={"x-redact-extra-rules": extra_rule_header})
    for _ in range(samples):
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        await post_body(body)
        proxy_warm_cpu.append((time.process_time_ns() - cpu_start) / 1_000_000)
        proxy_warm_wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)

    for appended_body in appended_bodies:
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        await post_body(appended_body)
        proxy_appended_cpu.append((time.process_time_ns() - cpu_start) / 1_000_000)
        proxy_appended_wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)

    for _ in range(samples):
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        await post_body(extra_body, headers={"x-redact-extra-rules": extra_rule_header})
        proxy_extra_cpu.append((time.process_time_ns() - cpu_start) / 1_000_000)
        proxy_extra_wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)

    app.state.redactor = SecretRedactor(settings.redaction.model_copy(deep=True))
    health_latencies: list[float] = []
    heartbeat_lags: list[float] = []
    heartbeat_stop = asyncio.Event()
    heartbeat_started = asyncio.Event()

    async def heartbeat() -> None:
        loop = asyncio.get_running_loop()
        due = loop.time() + HEARTBEAT_INTERVAL_SECONDS
        heartbeat_started.set()
        while not heartbeat_stop.is_set():
            await asyncio.sleep(max(0.0, due - loop.time()))
            now = loop.time()
            heartbeat_lags.append(max(0.0, now - due) * 1000)
            due = now + HEARTBEAT_INTERVAL_SECONDS

    async def cold_request() -> None:
        wall_start = time.perf_counter_ns()
        await post_body(cold_body)
        concurrent_cold_wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)

    async def health_request(started: int) -> None:
        response = await asgi_client.get("/healthz")
        health_latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        if response.status_code != 200:
            raise AssertionError(f"concurrent /healthz returned HTTP {response.status_code}")

    heartbeat_task = asyncio.create_task(heartbeat())
    await heartbeat_started.wait()
    tasks = [asyncio.create_task(cold_request())]
    for _ in range(HEALTH_CHECKS):
        scheduled_at = time.perf_counter_ns()
        tasks.append(asyncio.create_task(health_request(scheduled_at)))
    await asyncio.gather(*tasks)
    heartbeat_stop.set()
    await heartbeat_task

    http_results = {
        "proxy_cold": measurement_summary(proxy_cold_wall, proxy_cold_cpu),
        "proxy_warm_repeated_history": measurement_summary(proxy_warm_wall, proxy_warm_cpu),
        "proxy_appended_message": measurement_summary(proxy_appended_wall, proxy_appended_cpu),
        "proxy_repeated_extra_rule_header": measurement_summary(proxy_extra_wall, proxy_extra_cpu),
    }
    concurrency_results = {
        "cold_proxy_request_wall_ms": concurrent_cold_wall[0] if concurrent_cold_wall else None,
        "healthz_requests": len(health_latencies),
        "healthz_wall_ms": summarize(health_latencies),
        "heartbeat_interval_ms": HEARTBEAT_INTERVAL_SECONDS * 1000,
        "heartbeat_lag_ms": summarize(heartbeat_lags) if heartbeat_lags else None,
        "heartbeat_max_lag_ms": max(heartbeat_lags, default=0.0),
        "mocked_upstream_requests": forwarded_requests,
    }

    async def one_proxy_profile(*, with_extra_rules: bool = False) -> httpx.Response:
        app.state.redactor = SecretRedactor(settings.redaction.model_copy(deep=True))
        headers = {"x-redact-extra-rules": extra_rule_header} if with_extra_rules else None
        return await post_body(extra_body if with_extra_rules else body, headers=headers)

    async def close_clients() -> None:
        await app.state.client.aclose()
        await asgi_client.aclose()

    return http_results, concurrency_results, one_proxy_profile, close_clients


async def main_async(args: argparse.Namespace, repository_root: Path) -> dict[str, Any]:
    from promptlatch.config import AuditConfig, RedactionConfig, RuleConfig, Settings, TargetConfig
    from promptlatch.library import PromptLatch
    from promptlatch.redaction import SecretRedactor

    fake_secret = make_fake_secret()
    extra_secret = (
        "profile-rule-" + hashlib.sha256(b"PromptLatch profile request-specific rule").hexdigest()
    )
    stream_results = await benchmark_stream_conversions(
        args.stream_samples, args.stream_chunk_bytes
    )
    config = new_redaction_config(RedactionConfig, RuleConfig, fake_secret)
    messages = make_messages("serial", fake_secret)
    appended_messages = [
        make_message(MESSAGE_COUNT + sample, f"append-{sample:03d}", fake_secret, MESSAGE_CHARS)
        for sample in range(args.samples)
    ]
    cold_messages = make_messages("concurrent-cold", fake_secret)

    def fresh_library_factory() -> tuple[Callable[[], Any], Callable[[Any], None]]:
        latch = PromptLatch(config=config.model_copy(deep=True))

        def validate(result: Any) -> None:
            encoded = json.dumps(result.value, separators=(",", ":"))
            if fake_secret in encoded:
                raise AssertionError("synthetic credential remained in library result")

        return lambda: latch.scan_messages(messages), validate

    library_wall, library_cpu = time_sync_samples(args.samples, fresh_library_factory)

    warm_latch = PromptLatch(config=config.model_copy(deep=True))
    warm_result = warm_latch.scan_messages(messages)
    if fake_secret in json.dumps(warm_result.value, separators=(",", ":")):
        raise AssertionError("synthetic credential remained during library warm-up")

    def validate_warm_result(result: Any) -> None:
        if fake_secret in json.dumps(result.value, separators=(",", ":")):
            raise AssertionError("synthetic credential remained in warmed library result")

    repeated_wall, repeated_cpu = time_sync_samples(
        args.samples,
        lambda: (lambda: warm_latch.scan_messages(messages), validate_warm_result),
    )
    appended_wall: list[float] = []
    appended_cpu: list[float] = []
    for appended_message in appended_messages:
        payload = [*messages, appended_message]
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        result = warm_latch.scan_messages(payload)
        appended_cpu.append((time.process_time_ns() - cpu_start) / 1_000_000)
        appended_wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)
        validate_warm_result(result)
    library_results = {
        "library_fresh_cache": measurement_summary(library_wall, library_cpu),
        "library_repeated_history": measurement_summary(repeated_wall, repeated_cpu),
        "library_appended_message": measurement_summary(appended_wall, appended_cpu),
    }

    settings = Settings(
        redaction=config.model_copy(deep=True),
        target=TargetConfig(
            default_base_url="https://benchmark.invalid/v1",
            block_private_targets=False,
        ),
        audit=AuditConfig(enabled=False),
    )
    close_clients: Callable[[], Awaitable[None]] | None = None
    try:
        http_results, concurrency_results, profile_proxy, close_clients = await run_http_benchmarks(
            args.samples,
            fake_secret,
            extra_secret,
            messages,
            appended_messages,
            cold_messages,
            settings,
            SecretRedactor,
        )

        if args.profile:
            for stream_kind in ("text", "tool_arguments"):
                chunks, expected = make_stream_input(stream_kind)
                chunks = rechunk_stream(chunks, args.stream_chunk_bytes)
                await profile_async(
                    f"chat stream {stream_kind} 1 MiB",
                    partial(profile_stream_case, stream_kind, chunks, expected),
                )
            profile_sync(
                "library fresh-cache scan",
                lambda: PromptLatch(config=config.model_copy(deep=True)).scan_messages(messages),
            )
            await profile_async("ASGI proxy cold request", profile_proxy, body_preprocessing=True)
            await profile_async(
                "ASGI proxy request with extra-rule header",
                lambda: profile_proxy(with_extra_rules=True),
                body_preprocessing=True,
            )
    finally:
        if close_clients is not None:
            await close_clients()

    module_file = sys.modules["promptlatch"].__file__
    assert module_file is not None
    return {
        "environment": {
            "python": sys.version.split()[0],
            "source_root": str(repository_root),
            "source_commit": source_commit(repository_root),
            "source_sha256": source_fingerprints(repository_root),
            "promptlatch_module": str(Path(module_file).resolve()),
            "dependency_versions": dependency_versions(),
            "synthetic_messages": MESSAGE_COUNT,
            "synthetic_message_chars": CONVERSATION_CHARS,
            "synthetic_secret_redacted": True,
            "samples_per_scenario": args.samples,
            "stream_samples_per_kind": args.stream_samples,
        },
        "stream_conversion": stream_results,
        "library": library_results,
        "proxy": http_results,
        "event_loop_probe": concurrency_results,
    }


def source_commit(repository_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    return result.stdout.strip() or None


def peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def main() -> int:
    args = parse_args()
    repository_root = configure_source_path(args.source_root)
    started = time.perf_counter()
    cpu_started = time.process_time()
    results = asyncio.run(main_async(args, repository_root))
    results["process"] = {
        "wall_seconds": time.perf_counter() - started,
        "cpu_seconds": time.process_time() - cpu_started,
        "peak_rss_bytes": peak_rss_bytes(),
    }
    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0

    print(f"Imported {results['environment']['promptlatch_module']}")
    print(
        f"Measured {MESSAGE_COUNT} unique messages, {CONVERSATION_CHARS:,} content characters, "
        f"{args.samples} samples per timed scenario."
    )
    for section in ("library", "proxy"):
        print(f"\n{section.title()} scenarios:")
        for name, scenario in results[section].items():
            wall = scenario["wall_ms_per_request"]
            cpu = scenario["process_cpu_ms_per_request"]
            print(
                f"  {name}: wall median/p95/p99 {wall['median']:.2f}/"
                f"{wall['p95']:.2f}/{wall['p99']:.2f} ms; CPU median "
                f"{cpu['median']:.2f} ms"
            )
    print("\nSynthetic 1 MiB chat stream conversion, no network:")
    for name in ("text", "tool_arguments"):
        scenario = results["stream_conversion"][name]
        wall = scenario["wall_ms_per_request"]
        cpu = scenario["process_cpu_ms_per_request"]
        print(
            f"  {name}: {scenario['samples']} sample(s), wall median/p95/p99 "
            f"{wall['median']:.2f}/{wall['p95']:.2f}/{wall['p99']:.2f} ms; CPU "
            f"median {cpu['median']:.2f} ms"
        )
    probe = results["event_loop_probe"]
    lag = probe["heartbeat_lag_ms"]
    if lag is not None:
        print(
            "\nConcurrent event-loop probe: "
            f"/healthz median/p95/p99 {probe['healthz_wall_ms']['median']:.2f}/"
            f"{probe['healthz_wall_ms']['p95']:.2f}/{probe['healthz_wall_ms']['p99']:.2f} ms; "
            f"heartbeat lag median/p95/p99 {lag['median']:.2f}/{lag['p95']:.2f}/"
            f"{lag['p99']:.2f} ms; max {probe['heartbeat_max_lag_ms']:.2f} ms"
        )
    process = results["process"]
    print(
        f"\nProcess: wall {process['wall_seconds']:.2f}s, CPU "
        f"{process['cpu_seconds']:.2f}s, peak RSS {process['peak_rss_bytes'] / 1024 / 1024:.1f} MiB"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
