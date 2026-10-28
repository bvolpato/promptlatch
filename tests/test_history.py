from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path

import pytest

from promptlatch.history import HistoryReader, HistoryStore


def directory_bytes(path):
    total = 0
    for item in path.iterdir():
        with suppress(FileNotFoundError):
            total += item.stat().st_size
    return total


def start_record(request_id: str, **fields):
    return {
        "request_id": request_id,
        "thread_id": "thread-a",
        "thread_source": "header",
        "started_at": time.time(),
        "method": "POST",
        "path": "/v1/chat/completions",
        "model": "fixture-model",
        "provider": "fixture-provider",
        "stream": True,
        "redactions": 2,
        "rule_hits": {"provider_key": 2},
        "request_body": '{"messages":[{"role":"user","content":"[REDACTED_SECRET]"}]}',
        **fields,
    }


def finish_record(**fields):
    return {
        "completed_at": time.time(),
        "outcome": "success",
        "status_code": 200,
        "duration_ms": 100,
        "ttft_ms": 20,
        "generation_ms": 80,
        "tps": 125,
        "input_tokens": 20,
        "output_tokens": 10,
        "total_tokens": 30,
        "cached_input_tokens": 5,
        "cache_write_tokens": 0,
        "reasoning_tokens": 3,
        "usage_source": "upstream",
        "cost_usd": 0.0001,
        "cost_source": "litellm_snapshot",
        "pricing_as_of": "2026-10-10",
        "pricing_rates": {"input_cost_per_token": 0.000002},
        **fields,
    }


def equivalent_quote(**fields):
    return {
        "cost_usd": 0.25,
        "cost_source": "litellm_api_equivalent",
        "pricing_as_of": "2026-10-13T00:00:00+00:00",
        "pricing_model": "gpt-test",
        "pricing_rates": {
            "input_cost_per_token": 0.001,
            "output_cost_per_token": 0.002,
            "scope": "text_tokens",
        },
        "cost_unavailable_reason": None,
        **fields,
    }


def test_missing_history_has_no_filesystem_side_effects(tmp_path):
    path = tmp_path / "absent" / "history.sqlite3"
    HistoryStore(path)
    reader = HistoryReader(path)
    assert reader.requests()["items"] == []
    assert reader.threads()["total"] == 0
    assert reader.thread_requests("missing")["items"] == []
    assert reader.request("missing") is None
    summary = reader.summary()
    assert summary["totals"]["requests"] == 0
    assert summary["totals"]["total_tokens"] is None
    assert summary["totals"]["cost_usd"] is None
    assert not path.parent.exists()


def test_private_storage_roundtrip_and_aggregate_unknown_values(tmp_path):
    path = tmp_path / "private" / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    assert store.submit_start(start_record("one"))
    assert store.submit_finish("one", finish_record())
    assert store.submit_start(
        start_record("two", thread_id="thread-b", stream=False, redactions=0, rule_hits={})
    )
    assert store.submit_finish("two", {"outcome": "transport_error", "duration_ms": 200})
    store.close()
    reader = HistoryReader(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.with_name(path.name + ".stats.sqlite3").stat().st_mode & 0o777 == 0o600
    totals = reader.summary()["totals"]
    assert totals["requests"] == 2
    assert totals["successes"] == 1
    assert totals["errors"] == 1
    assert totals["total_tokens"] == 30
    assert totals["reasoning_tokens"] == 3
    assert totals["output_tokens"] == 10
    assert totals["total_tokens_known_requests"] == 1
    assert totals["unknown_usage_requests"] == 1
    assert totals["unknown_cost_requests"] == 1
    assert totals["cost_usd"] == 0.0001
    assert totals["avg_duration_ms"] == 150
    assert totals["avg_ttft_ms"] == 20
    assert totals["avg_tps"] == 125
    assert totals["rule_hits"] == {"provider_key": 2}
    assert "request_body" not in reader.requests()["items"][0]
    detail = reader.request("one")
    assert detail is not None
    assert detail["request_body"] == start_record("one")["request_body"]
    assert detail["pricing_rates"] == {"input_cost_per_token": 0.000002}
    assert reader.requests(thread_id="thread-a")["total"] == 1
    assert reader.requests(thread_id="' OR 1=1 --")["total"] == 0
    assert reader.request("' OR 1=1 --") is None
    assert reader.threads()["total"] == 2
    assert store.status["write_errors"] == 0
    assert store.submit_start(start_record("closed")) is False


def test_upload_compression_metrics_persist_with_unknown_coverage(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    assert store.submit_start(
        start_record(
            "gzip",
            request_uncompressed_bytes=100,
            request_wire_bytes=40,
            request_compression="gzip",
            request_compression_ms=1.25,
        )
    )
    assert store.submit_finish("gzip", finish_record())
    assert store.submit_start(
        start_record(
            "encoded",
            request_uncompressed_bytes=None,
            request_wire_bytes=55,
            request_compression="identity",
            request_compression_ms=0.25,
        )
    )
    assert store.submit_finish("encoded", finish_record())
    assert store.submit_start(start_record("old-format"))
    assert store.submit_finish("old-format", finish_record())
    assert store.submit_start(
        start_record(
            "invalid-metadata",
            request_wire_bytes=True,
            request_compression=["NOT_A_METRIC"],
            request_compression_ms=float("nan"),
        )
    )
    assert store.submit_finish("invalid-metadata", finish_record())
    store.close()

    reader = HistoryReader(path)
    compressed = reader.request("gzip")
    assert compressed is not None
    assert compressed["request_uncompressed_bytes"] == 100
    assert compressed["request_wire_bytes"] == 40
    assert compressed["request_compression"] == "gzip"
    assert compressed["request_compression_ms"] == 1.25
    encoded = reader.request("encoded")
    assert encoded is not None
    assert encoded["request_uncompressed_bytes"] is None
    assert encoded["request_wire_bytes"] == 55
    invalid = reader.request("invalid-metadata")
    assert invalid is not None
    assert "request_wire_bytes" not in invalid
    assert "request_compression" not in invalid
    assert "request_compression_ms" not in invalid

    totals = reader.summary()["lifetime_totals"]
    assert totals["requests"] == 4
    assert totals["request_uncompressed_bytes"] == 100
    assert totals["request_uncompressed_bytes_known_requests"] == 1
    assert totals["request_uncompressed_bytes_unknown_requests"] == 3
    assert totals["request_wire_bytes"] == 95
    assert totals["request_wire_bytes_known_requests"] == 2
    assert totals["request_wire_bytes_unknown_requests"] == 2
    assert totals["request_compression_ms"] == 1.5
    assert totals["request_compression_ms_known_requests"] == 2
    assert totals["request_compression_ms_unknown_requests"] == 2
    assert totals["avg_request_compression_ms"] == 0.75
    assert totals["request_compression_counts"] == {
        "identity": 1,
        "gzip": 1,
        "zstd": 0,
        "other": 0,
    }
    assert totals["request_compression_unknown_requests"] == 2
    assert b"NOT_A_METRIC" not in path.read_bytes()


def test_duplicate_finishes_and_restarts_count_once(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    store.submit_start(start_record("one"))
    store.submit_finish("one", finish_record())
    store.submit_finish("one", finish_record())
    store.submit_start(start_record("unfinished"))
    store.close()
    restarted = HistoryStore(path)
    restarted.start()
    restarted.submit_finish("one", finish_record())
    restarted.submit_finish("unfinished", finish_record())
    restarted.close()
    reader = HistoryReader(path)
    assert reader.summary()["totals"]["requests"] == 2
    assert reader.summary()["totals"]["interrupted"] == 1
    assert reader.summary()["storage"]["active_requests"] == 0
    detail = reader.request("unfinished")
    assert detail is not None
    assert detail["outcome"] == "interrupted"


def test_retention_caps_files_preserves_rollups_and_finishes_evicted_active_requests(tmp_path):
    path = tmp_path / "history.sqlite3"
    budget = 512 * 1024
    store = HistoryStore(path, max_database_bytes=budget)
    store.start()
    store.submit_start(start_record("evicted-active", request_body="x" * 8000))
    for index in range(150):
        request_id = str(index)
        assert store.submit_start(start_record(request_id, request_body="x" * 8000))
        assert store.submit_finish(request_id, finish_record())
    store.submit_finish("evicted-active", finish_record())
    store.close()
    reader = HistoryReader(path)
    summary = reader.summary()
    assert 0 < summary["storage"]["retained_requests"] < 150
    assert summary["storage"]["total_bytes"] <= budget
    assert summary["totals"]["requests"] == 151
    assert summary["totals"]["total_tokens"] == 151 * 30
    assert reader.request("evicted-active") is None
    detail = reader.request("149")
    assert detail is not None
    assert detail["outcome"] == "success"
    assert store.status["write_errors"] == 0
    assert not Path(str(path) + "-wal").exists()
    restarted = HistoryStore(path, max_database_bytes=budget)
    restarted.start()
    restarted.close()
    assert reader.summary()["storage"]["total_bytes"] <= budget
    assert reader.summary()["totals"]["requests"] == 151


def test_transaction_failure_cannot_partially_increment_totals(tmp_path, monkeypatch, caplog):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    store.submit_start(start_record("one"))
    store._queue.join()
    original = store._write_detail

    def fail_detail(connection, record):
        raise OSError("do not log body or credentials from exception messages")

    monkeypatch.setattr(store, "_write_detail", fail_detail)
    store.submit_finish("one", finish_record())
    store._queue.join()
    reader = HistoryReader(path)
    assert reader.summary()["totals"]["requests"] == 0
    assert reader.summary()["storage"]["active_requests"] == 1
    assert store.status["last_error"] == "OSError"
    monkeypatch.setattr(store, "_write_detail", original)
    store.submit_finish("one", finish_record())
    store.close()
    assert reader.summary()["totals"]["requests"] == 1
    assert reader.summary()["storage"]["write_errors"] == 1
    assert "do not log body or credentials" not in caplog.text
    assert "History capture incomplete" in caplog.text
    restarted = HistoryStore(path)
    restarted.start()
    assert restarted.status["write_errors"] == 1
    restarted.close()


def test_combined_budget_bounds_stats_and_live_journals_preserving_lifetime_totals(
    tmp_path, monkeypatch
):
    path = tmp_path / "history.sqlite3"
    budget = 256 * 1024
    store = HistoryStore(path, max_database_bytes=budget)
    maximum_bytes = 0
    journal_observed = False
    original = store._open_writer

    def observed_open():
        connection = original()

        def observe(_statement):
            nonlocal maximum_bytes, journal_observed
            files = list(tmp_path.iterdir())
            maximum_bytes = max(maximum_bytes, sum(item.stat().st_size for item in files))
            journal_observed |= any(item.name.endswith("-journal") for item in files)

        connection.set_trace_callback(observe)
        return connection

    monkeypatch.setattr(store, "_open_writer", observed_open)
    store.start()
    started_at = time.time() - 500 * 86400
    for index in range(160):
        request_id = str(index)
        store.submit_start(
            start_record(
                request_id,
                started_at=started_at + index * 86400,
                model=f"model-{index}",
                request_body="x" * 8000,
            )
        )
        store.submit_finish(request_id, finish_record())
    store.close()
    summary = HistoryReader(path).summary(days=36500)
    assert summary["storage"]["total_bytes"] <= budget
    assert maximum_bytes <= budget
    assert journal_observed
    assert summary["storage"]["pruned_requests"] > 0
    assert summary["storage"]["pruned_aggregate_rows"] > 0
    assert summary["totals"]["requests"] < 160
    assert summary["lifetime_totals"]["requests"] == 160
    assert summary["lifetime_totals"]["total_tokens"] == 160 * 30
    assert store.status["write_errors"] == 0
    assert not any(item.name.endswith(("-wal", "-shm")) for item in tmp_path.iterdir())
    restarted = HistoryStore(path, max_database_bytes=budget)
    restarted.start()
    restarted.close()
    assert HistoryReader(path).summary()["lifetime_totals"]["requests"] == 160


def test_existing_aggregate_history_initializes_lifetime_without_double_counting(tmp_path):
    path = tmp_path / "history.sqlite3"
    first = HistoryStore(path)
    first.start()
    first.submit_start(start_record("old"))
    first.submit_finish("old", finish_record())
    first.close()
    with sqlite3.connect(path.with_name(path.name + ".stats.sqlite3")) as connection:
        connection.execute("DROP TABLE lifetime")
        encoded = connection.execute("SELECT metrics FROM aggregates").fetchone()[0]
        legacy = json.loads(encoded)
        legacy.pop("usage_applicable_requests")
        legacy.pop("usage_applicability_unknown_requests")
        for key in (
            "request_uncompressed_bytes",
            "request_uncompressed_bytes_samples",
            "request_wire_bytes",
            "request_wire_bytes_samples",
            "request_compression_ms",
            "request_compression_ms_samples",
            "request_compression_counts",
            "request_uncompressed_bytes_unknown_requests",
            "request_wire_bytes_unknown_requests",
            "request_compression_ms_unknown_requests",
            "request_compression_unknown_requests",
        ):
            legacy.pop(key, None)
        connection.execute("UPDATE aggregates SET metrics=?", (json.dumps(legacy),))
    migrated = HistoryStore(path)
    migrated.start()
    migrated.submit_finish("old", finish_record())
    migrated.submit_start(start_record("new"))
    migrated.submit_finish("new", finish_record())
    migrated.close()
    summary = HistoryReader(path).summary()
    assert summary["lifetime_totals"]["requests"] == 2
    assert summary["lifetime_totals"]["total_tokens"] == 60
    assert summary["lifetime_totals"]["rule_hits"] == {}
    assert summary["lifetime_totals"]["usage_applicable_requests"] == 2
    assert summary["lifetime_totals"]["usage_applicability_unknown_requests"] == 2
    assert summary["lifetime_totals"]["request_uncompressed_bytes_unknown_requests"] == 2
    assert summary["lifetime_totals"]["request_wire_bytes_unknown_requests"] == 2
    assert summary["lifetime_totals"]["request_compression_unknown_requests"] == 2


def test_non_generation_requests_do_not_count_as_missing_usage(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    store.submit_start(start_record("poll", method="GET", usage_applicable=False))
    store.submit_finish("poll", finish_record(duration_ms=20))
    store.submit_start(start_record("generation", usage_applicable=True))
    store.submit_finish("generation", {"outcome": "success", "duration_ms": 30})
    store.close()
    summary = HistoryReader(path).summary()
    assert summary["totals"]["requests"] == 2
    assert summary["totals"]["unknown_usage_requests"] == 1
    assert summary["totals"]["unknown_cost_requests"] == 1
    assert summary["totals"]["usage_applicable_requests"] == 1
    assert summary["totals"]["usage_applicability_unknown_requests"] == 0
    assert summary["totals"]["cost_usd_known_requests"] == 0
    assert summary["totals"]["total_tokens_known_requests"] == 0
    assert summary["lifetime_totals"]["unknown_usage_requests"] == 1


def test_reader_contention_fails_bounded_capture_and_recovers(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    budget = 256 * 1024
    store = HistoryStore(path, max_database_bytes=budget)
    original = store._open_writer

    def short_busy_timeout():
        connection = original()
        connection.execute("PRAGMA busy_timeout=25")
        return connection

    monkeypatch.setattr(store, "_open_writer", short_busy_timeout)
    store.start()
    store.submit_start(start_record("first"))
    store.submit_finish("first", finish_record())
    store._queue.join()
    reader = sqlite3.connect(path.with_name(path.name + ".stats.sqlite3"))
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM settings").fetchall()
        store.submit_start(start_record("blocked", request_body="x" * 8000))
        store.submit_finish("blocked", finish_record())
        store._queue.join()
        assert store.status["write_errors"] > 0
        assert sum(item.stat().st_size for item in tmp_path.iterdir()) <= budget
    finally:
        reader.close()
    store.submit_start(start_record("recovered"))
    store.submit_finish("recovered", finish_record())
    store.close()
    assert HistoryReader(path).summary()["lifetime_totals"]["requests"] == 2
    assert HistoryReader(path).summary()["storage"]["total_bytes"] <= budget


def test_legacy_startup_is_bounded_before_migration_and_pending_recovery(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    budget = 1024 * 1024
    store = HistoryStore(path, max_database_bytes=budget)
    store.start()
    for index in range(8):
        store.submit_start(start_record(str(index), request_body="x" * 8000))
        if index < 4:
            store.submit_finish(str(index), finish_record())
    store.close()
    stats_path = path.with_name(path.name + ".stats.sqlite3")
    with sqlite3.connect(stats_path) as connection:
        connection.execute("DROP TABLE lifetime")
        connection.execute("PRAGMA auto_vacuum=NONE")
        connection.execute("VACUUM")
    orphan = Path(str(stats_path) + "-mj000000900")
    orphan.write_bytes(b"\0" * 32768)

    maximum_bytes = 0
    statements = []
    original_connect = sqlite3.connect
    observation_lock = threading.Lock()

    def observe():
        nonlocal maximum_bytes
        with observation_lock:
            maximum_bytes = max(maximum_bytes, directory_bytes(tmp_path))

    def observed_connect(*args, **kwargs):
        observe()
        connection = original_connect(*args, **kwargs)

        def trace(statement):
            statements.append(statement.strip())
            observe()

        connection.set_trace_callback(trace)
        return connection

    monkeypatch.setattr(sqlite3, "connect", observed_connect)
    migrated = HistoryStore(path, max_database_bytes=budget)
    finished = threading.Event()

    def sample_startup():
        while not finished.wait(0.0002):
            observe()

    sampler = threading.Thread(target=sample_startup)
    sampler.start()
    try:
        migrated.start()
        migrated.close()
    finally:
        finished.set()
        sampler.join()
    observe()
    first_mutation = next(
        index
        for index, statement in enumerate(statements)
        if statement.startswith(("CREATE ", "INSERT ", "UPDATE ", "DELETE ", "VACUUM"))
    )
    assert any(
        statement.startswith("PRAGMA main.max_page_count=")
        for statement in statements[:first_mutation]
    )
    assert any(
        statement.startswith("PRAGMA history.max_page_count=")
        for statement in statements[:first_mutation]
    )
    assert maximum_bytes <= budget
    summary = HistoryReader(path).summary()
    assert summary["lifetime_totals"]["requests"] == 8
    assert summary["lifetime_totals"]["interrupted"] == 4
    assert summary["storage"]["active_requests"] == 0
    assert migrated.status["write_errors"] == 0
    assert orphan.stat().st_size == 32768


def test_near_budget_legacy_startup_refuses_without_opening_writable_sqlite(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    budget = 1024 * 1024
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE legacy(value BLOB)")
        connection.execute("INSERT INTO legacy VALUES (?)", (b"x" * 900_000,))
    original = path.read_bytes()
    assert len(original) < budget

    def unexpected_open(*args, **kwargs):
        pytest.fail("Unsafe legacy startup opened writable SQLite before rejecting storage budget")

    monkeypatch.setattr(sqlite3, "connect", unexpected_open)
    with pytest.raises(RuntimeError, match="offline compaction.*No database writes performed"):
        HistoryStore(path, max_database_bytes=budget).start()
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("sidecar_suffix", ["-journal", "-mj000000900"])
def test_near_budget_stale_sidecar_refuses_before_migration(tmp_path, monkeypatch, sidecar_suffix):
    path = tmp_path / "history.sqlite3"
    budget = 1024 * 1024
    store = HistoryStore(path, max_database_bytes=budget)
    store.start()
    store.close()
    stats_path = path.with_name(path.name + ".stats.sqlite3")
    with sqlite3.connect(stats_path) as connection:
        connection.execute("DROP TABLE lifetime")
        connection.execute("PRAGMA auto_vacuum=NONE")
        connection.execute("VACUUM")
    journal = Path(str(stats_path) + sidecar_suffix)
    journal.write_bytes(b"\0" * (budget - directory_bytes(tmp_path) - 128))
    original = {item.name: item.read_bytes() for item in tmp_path.iterdir()}
    assert directory_bytes(tmp_path) < budget

    def unexpected_open(*args, **kwargs):
        pytest.fail("Stale journal consumes migration headroom before writable SQLite open")

    monkeypatch.setattr(sqlite3, "connect", unexpected_open)
    with pytest.raises(RuntimeError, match="offline .*No database writes"):
        HistoryStore(path, max_database_bytes=budget).start()
    assert {item.name: item.read_bytes() for item in tmp_path.iterdir()} == original


def test_bounded_startup_recovers_hot_delete_journal_after_abrupt_exit(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    budget = 4 * 1024 * 1024
    store = HistoryStore(path, max_database_bytes=budget)
    store.start()
    store.submit_start(start_record("unfinished"))
    store.close()
    stats_path = path.with_name(path.name + ".stats.sqlite3")
    with sqlite3.connect(stats_path) as connection:
        connection.execute("CREATE TABLE legacy_padding(value BLOB)")
        connection.execute("INSERT INTO legacy_padding VALUES (?)", (b"a" * 512_000,))
    script = """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA journal_mode=DELETE')
connection.execute('PRAGMA synchronous=FULL')
connection.execute('PRAGMA cache_size=1')
connection.execute('PRAGMA cache_spill=ON')
connection.execute('BEGIN IMMEDIATE')
connection.execute('UPDATE legacy_padding SET value=?', (b'b' * 512_000,))
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", script, str(stats_path)], check=True)
    journal = Path(str(stats_path) + "-journal")
    assert journal.read_bytes()[:8] == b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"
    maximum_bytes = directory_bytes(tmp_path)
    original_connect = sqlite3.connect
    observation_lock = threading.Lock()

    def observe():
        nonlocal maximum_bytes
        with observation_lock:
            maximum_bytes = max(maximum_bytes, directory_bytes(tmp_path))

    def observed_connect(*args, **kwargs):
        observe()
        connection = original_connect(*args, **kwargs)

        def trace(_statement):
            observe()

        connection.set_trace_callback(trace)
        return connection

    monkeypatch.setattr(sqlite3, "connect", observed_connect)
    recovered = HistoryStore(path, max_database_bytes=budget)
    finished = threading.Event()

    def sample_startup():
        while not finished.wait(0.0002):
            observe()

    sampler = threading.Thread(target=sample_startup)
    sampler.start()
    try:
        recovered.start()
        recovered.close()
    finally:
        finished.set()
        sampler.join()
    assert maximum_bytes <= budget
    assert not journal.exists()
    with sqlite3.connect(stats_path) as connection:
        assert (
            connection.execute("SELECT value FROM legacy_padding").fetchone()[0] == b"a" * 512_000
        )
    summary = HistoryReader(path).summary()
    assert summary["lifetime_totals"]["requests"] == 1
    assert summary["lifetime_totals"]["interrupted"] == 1
    assert summary["storage"]["active_requests"] == 0


def test_queue_pressure_is_nonblocking_and_bodies_are_byte_bounded(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path, queue_size=1, max_body_bytes=5)
    entered = threading.Event()
    release = threading.Event()
    original = store._start

    def blocked_start(connection, record):
        entered.set()
        assert release.wait(5)
        original(connection, record)

    monkeypatch.setattr(store, "_start", blocked_start)
    store.start()
    try:
        assert store.submit_start(start_record("one", request_body="ééééé"))
        assert entered.wait(5)
        assert store.submit_start(start_record("two"))
        assert not store.submit_start(start_record("three"))
        assert store.dropped_writes == 1
    finally:
        release.set()
        store.close()
    detail = HistoryReader(path).request("one")
    assert detail is not None
    assert detail["request_body"] == "éé"
    assert detail["body_truncated"] is True
    assert HistoryReader(path).summary()["storage"]["dropped_writes"] == 1
    restarted = HistoryStore(path)
    restarted.start()
    assert restarted.dropped_writes == 1
    restarted.close()


def test_body_memory_pressure_omits_content_without_losing_metrics(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store._queue_body_limit = 2
    store.start()
    store.submit_start(
        start_record(
            "one",
            request_body=None,
            session_preview="private session preview",
            user_preview="private user preview",
            assistant_preview="private assistant preview",
        )
    )
    store.submit_finish("one", finish_record())
    store.close()
    detail = HistoryReader(path).request("one")
    assert detail is not None
    assert detail["request_body"] is None
    assert detail["body_omitted_reason"] == "queue_pressure"
    assert detail["session_preview"] is None
    assert detail["user_preview"] is None
    assert detail["assistant_preview"] is None
    assert HistoryReader(path).summary()["totals"]["total_tokens"] == 30


def test_stats_never_contain_request_bodies_or_extra_fields(tmp_path):
    path = tmp_path / "history.sqlite3"
    body = "private request conversation fixture"
    store = HistoryStore(path)
    store.start()
    store.submit_start(
        start_record(
            "one",
            request_body=body,
            session_preview="private session preview",
            user_preview="private user preview",
            assistant_preview="private assistant preview",
            response_body="never persist me",
        )
    )
    store._queue.join()
    stats_path = path.with_name(path.name + ".stats.sqlite3")
    with sqlite3.connect(stats_path) as connection:
        pending = json.loads(connection.execute("SELECT record FROM pending").fetchone()[0])
    assert "request_body" not in pending
    assert "session_preview" not in pending
    assert "user_preview" not in pending
    assert "assistant_preview" not in pending
    store.submit_finish("one", finish_record())
    store.close()
    assert body.encode() not in stats_path.read_bytes()
    assert b"never persist me" not in path.read_bytes()
    detail = HistoryReader(path).request("one")
    assert detail is not None
    assert "response_body" not in detail


def test_preview_fields_live_only_in_bounded_detail_and_not_after_zero_budget(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path, max_body_bytes=0)
    store.start()
    store.submit_start(
        start_record(
            "zero-budget",
            request_body=None,
            session_preview="must not persist",
            user_preview="must not persist",
            assistant_preview="must not persist",
        )
    )
    store.submit_finish("zero-budget", finish_record())
    store.close()
    detail = HistoryReader(path).request("zero-budget")
    assert detail is not None
    assert all(
        detail[field] is None for field in ("session_preview", "user_preview", "assistant_preview")
    )
    stats_path = path.with_name(path.name + ".stats.sqlite3")
    assert b"must not persist" not in stats_path.read_bytes()


def test_storage_budget_omission_clears_preview_fields(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path, max_database_bytes=256 * 1024, max_body_bytes=32 * 1024)
    store._queue_body_limit = 64 * 1024
    store.start()
    store.submit_start(
        start_record(
            "large",
            request_body="x" * 28_000,
            session_preview="private storage preview",
            user_preview="private storage preview",
            assistant_preview="private storage preview",
        )
    )
    store.submit_finish("large", finish_record())
    store.close()
    detail = HistoryReader(path).request("large")
    assert detail is not None
    assert detail["request_body"] is None
    assert detail["body_omitted_reason"] == "storage_budget"
    assert all(
        detail[field] is None for field in ("session_preview", "user_preview", "assistant_preview")
    )


@pytest.mark.parametrize(
    "body,truncated,expected",
    [
        ('{"messages":[{"role":"user","content":"legacy prompt"}]}', False, "legacy prompt"),
        ('{"messages":[{"role":"user","content":"cut"', True, None),
        ("not json", False, None),
    ],
)
def test_old_rows_derive_previews_only_from_bounded_complete_json(
    tmp_path, body, truncated, expected
):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    store.submit_start(start_record("old", request_body=body, body_truncated=truncated))
    store.submit_finish("old", finish_record())
    store.close()
    with sqlite3.connect(path) as connection:
        row = connection.execute("SELECT record FROM requests WHERE request_id='old'").fetchone()
        record = json.loads(row[0])
        for field in ("session_preview", "user_preview", "assistant_preview"):
            record.pop(field, None)
        connection.execute(
            "UPDATE requests SET record=? WHERE request_id='old'",
            (json.dumps(record),),
        )
    result = HistoryReader(path).request("old")
    assert result is not None
    assert result["user_preview"] == expected
    assert result["session_preview"] == expected
    assert result["assistant_preview"] is None
    listed = HistoryReader(path).requests()["items"][0]
    assert listed["user_preview"] == expected
    assert "request_body" not in listed
    assert HistoryReader(path).threads()["items"][0]["session_preview"] == expected


@pytest.mark.parametrize("outcome", ["http_error", "stream_error", "cancelled"])
def test_non_success_outcomes_remain_visible_in_aggregates(tmp_path, outcome):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    store.submit_start(start_record("one"))
    store.submit_finish("one", {"outcome": outcome})
    store.close()
    totals = HistoryReader(path).summary()["totals"]
    assert totals["requests"] == 1
    assert totals["successes"] == 0
    assert totals["cost_usd"] is None
    assert totals["total_tokens"] is None
    assert totals["cancelled" if outcome == "cancelled" else "errors"] == 1


def test_exclusive_writer_lock_allows_readers_and_releases_on_close(tmp_path):
    path = tmp_path / "history.sqlite3"
    first = HistoryStore(path)
    first.start()
    first.submit_start(start_record("one"))
    first._queue.join()
    second = HistoryStore(path)
    with pytest.raises(RuntimeError, match="Another history writer"):
        second.start()
    assert HistoryReader(path).summary()["storage"]["active_requests"] == 1
    first.submit_finish("one", finish_record())
    first.close()
    second.start()
    second.close()
    assert HistoryReader(path).summary()["totals"]["requests"] == 1


def test_response_thread_link_is_indexed_and_survives_restart(tmp_path):
    path = tmp_path / "history.sqlite3"
    store = HistoryStore(path)
    store.start()
    store.submit_start(start_record("one"))
    store.submit_finish("one", finish_record(response_id_hash="private-hmac-fixture"))
    store.close()
    reader = HistoryReader(path)
    assert reader.thread_for_response("private-hmac-fixture") == "thread-a"
    assert reader.thread_for_response("missing") is None
    assert reader.thread_for_response("' OR 1=1 --") is None
    restarted = HistoryStore(path)
    restarted.start()
    restarted.close()
    assert reader.thread_for_response("private-hmac-fixture") == "thread-a"


def test_thread_tree_orders_pages_and_links_only_retained_earlier_session_requests(tmp_path):
    path = tmp_path / "history.sqlite3"
    started_at = time.time()
    records = [
        ("b-child", 0, "root", "child", "thread-a"),
        ("c-fork", 1, "root", "fork", "thread-a"),
        ("a-root", 0, "child", "root", "thread-a"),
        ("d-future-parent", 2, "future", "past", "thread-a"),
        ("e-future", 3, "past", "future", "thread-a"),
        ("f-cross-session", 4, "foreign", None, "thread-a"),
        ("g-evicted-parent", 5, "evicted", None, "thread-a"),
        ("evicted", -1, None, "evicted", "thread-a"),
        ("other-session", -3, None, "foreign", "thread-b"),
    ]
    store = HistoryStore(path)
    store.start()
    for request_id, seconds, parent, response, thread_id in records:
        store.submit_start(
            start_record(
                request_id,
                started_at=started_at + seconds,
                thread_id=thread_id,
                turn_id="opaque-turn",
                user_turn=2,
                message_count=4,
                turn_source="message_history",
                parent_response_id_hash=parent,
            )
        )
        store.submit_finish(request_id, finish_record(response_id_hash=response))
    store.submit_start(start_record("old-row", started_at=started_at - 2))
    store.submit_finish("old-row", finish_record())
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM requests WHERE request_id='evicted'")
    reader = HistoryReader(path)
    tree = reader.thread_requests("thread-a")
    assert tree["total"] == 8
    assert [row["request_id"] for row in tree["items"]] == [
        "old-row",
        "a-root",
        "b-child",
        "c-fork",
        "d-future-parent",
        "e-future",
        "f-cross-session",
        "g-evicted-parent",
    ]
    assert [row["ordinal"] for row in tree["items"]] == list(range(1, 9))
    assert {row["request_id"]: row["parent_request_id"] for row in tree["items"]} == {
        "old-row": None,
        "a-root": None,
        "b-child": "a-root",
        "c-fork": "a-root",
        "d-future-parent": None,
        "e-future": "d-future-parent",
        "f-cross-session": None,
        "g-evicted-parent": None,
    }
    page = reader.thread_requests("thread-a", limit=2, offset=2)
    assert page["total"] == 8
    assert [row["request_id"] for row in page["items"]] == ["b-child", "c-fork"]
    assert [row["ordinal"] for row in page["items"]] == [3, 4]
    assert page["items"][0]["turn_id"] == "opaque-turn"
    assert page["items"][0]["user_turn"] == 2
    assert page["items"][0]["message_count"] == 4
    assert page["items"][0]["turn_source"] == "message_history"
    assert all("request_body" not in row for row in tree["items"])
    assert tree["items"][0].get("turn_id") is None
    assert reader.thread_requests("' OR 1=1 --")["items"] == []
    assert reader.thread_requests("missing")["total"] == 0
    assert reader.thread_requests("thread-a", offset=8)["items"] == []

    newest_first = reader.thread_requests("thread-a", order="desc")
    assert [row["request_id"] for row in newest_first["items"]] == [
        "g-evicted-parent",
        "f-cross-session",
        "e-future",
        "d-future-parent",
        "c-fork",
        "b-child",
        "a-root",
        "old-row",
    ]
    assert [row["ordinal"] for row in newest_first["items"]] == list(range(8, 0, -1))
    assert {row["request_id"]: row["parent_request_id"] for row in newest_first["items"]} == {
        row["request_id"]: row["parent_request_id"] for row in tree["items"]
    }
    newest_page = reader.thread_requests("thread-a", limit=2, offset=2, order="desc")
    assert [row["request_id"] for row in newest_page["items"]] == [
        "e-future",
        "d-future-parent",
    ]
    assert [row["ordinal"] for row in newest_page["items"]] == [6, 5]
    assert newest_page["items"][0]["parent_request_id"] == "d-future-parent"
    with pytest.raises(ValueError, match="order must be 'asc' or 'desc'"):
        reader.thread_requests("thread-a", order="sideways")


def test_thread_summaries_use_retained_metrics_and_latest_metadata(tmp_path):
    path = tmp_path / "thread-summary.sqlite3"
    store = HistoryStore(path)
    store.start()
    records = (
        (
            "older",
            {
                "started_at": 100.0,
                "model": "older-model",
                "provider": "older-provider",
                "session_preview": "opening request",
                "user_preview": "older user",
                "assistant_preview": "older answer",
            },
            finish_record(duration_ms=100, total_tokens=8, cost_usd=0.01),
        ),
        (
            "middle",
            {"started_at": 200.0, "model": "middle-model", "provider": "middle-provider"},
            finish_record(duration_ms=200, total_tokens=None, cost_usd=None),
        ),
        (
            "latest",
            {
                "started_at": 300.0,
                "model": "latest-model",
                "provider": "latest-provider",
                "user_preview": "latest user request",
                "assistant_preview": "latest prior answer",
                "request_body": "latest body must stay private",
            },
            finish_record(outcome="http_error", duration_ms=0, total_tokens=None, cost_usd=0.02),
        ),
    )
    for request_id, fields, finish in records:
        store.submit_start(start_record(request_id, thread_id="thread-metrics", **fields))
        store.submit_finish(request_id, finish)

    store.submit_start(
        start_record(
            "unknown",
            thread_id="thread-unknown",
            started_at=400.0,
            model="unknown-model",
            provider="unknown-provider",
            request_body='{"messages":[{"role":"user","content":"opening only fallback"}]}',
        )
    )
    store.submit_finish(
        "unknown",
        finish_record(
            outcome="interrupted",
            completed_at=400.0,
            duration_ms=None,
            total_tokens=None,
            cost_usd=None,
        ),
    )
    store.close()

    summaries = {item["thread_id"]: item for item in HistoryReader(path).threads()["items"]}
    measured = summaries["thread-metrics"]
    assert measured["duration_ms"] == 300
    assert measured["total_tokens"] == 8
    assert measured["known_token_requests"] == 1
    assert measured["cost_usd"] == pytest.approx(0.03)
    assert measured["known_cost_requests"] == 2
    assert measured["latest_model"] == "latest-model"
    assert measured["latest_provider"] == "latest-provider"
    assert measured["latest_outcome"] == "http_error"
    assert measured["latest_started_at"] == 300
    assert measured["last_started_at"] == measured["latest_started_at"]
    assert measured["session_preview"] == "opening request"
    assert measured["last_user_preview"] == "latest user request"
    assert measured["last_assistant_preview"] == "latest prior answer"
    assert "request_body" not in measured
    assert "latest body must stay private" not in str(measured)

    unknown = summaries["thread-unknown"]
    assert unknown["duration_ms"] is None
    assert unknown["total_tokens"] is None
    assert unknown["known_token_requests"] == 0
    assert unknown["cost_usd"] is None
    assert unknown["known_cost_requests"] == 0
    assert unknown["session_preview"] is None
    assert unknown["last_user_preview"] is None
    assert unknown["last_assistant_preview"] is None


def test_inference_traffic_filters_counts_summaries_and_visible_parent_links(tmp_path):
    path = tmp_path / "traffic.sqlite3"
    store = HistoryStore(path)
    store.start()
    records = [
        start_record(
            "poll-first",
            started_at=50,
            method="GET",
            usage_applicable=False,
            session_preview="poll opening",
        ),
        start_record(
            "root",
            started_at=100,
            usage_applicable=True,
            session_preview="inference opening",
            model="inference-model",
        ),
        start_record("poll-parent", started_at=200, method="GET", usage_applicable=False),
        start_record(
            "child",
            started_at=300,
            model="latest-inference",
            user_preview="latest question",
            assistant_preview="previous answer",
            parent_response_id_hash="poll-response",
        ),
        start_record("post-ancillary", started_at=350, usage_applicable=False),
        start_record("poll-last", started_at=400, method="GET", path="/other", model=None),
        start_record("poll-only", thread_id="poll-only", method="GET"),
        start_record("legacy-post", thread_id="legacy", method="post"),
        start_record("legacy-head", thread_id="legacy", method="HEAD"),
        start_record("legacy-unknown", thread_id="legacy", method="OTHER"),
        start_record("legacy-missing", thread_id="legacy"),
        start_record("explicit-true", thread_id="legacy", method="GET", usage_applicable=True),
        start_record("null-flag", thread_id="legacy", usage_applicable=None),
    ]
    records[10].pop("method")
    for record in records:
        assert store.submit_start(record)
        assert store.submit_finish(
            record["request_id"],
            finish_record(
                cost_usd=0.01,
                response_id_hash="poll-response" if record["request_id"] == "poll-parent" else None,
            ),
        )
    store.close()
    reader = HistoryReader(path)
    filtered = reader.requests(traffic="inference")
    assert filtered["total"] == 7
    assert {item["request_id"] for item in filtered["items"]} == {
        "root",
        "child",
        "legacy-post",
        "legacy-unknown",
        "legacy-missing",
        "explicit-true",
        "null-flag",
    }
    assert all("request_body" not in item for item in filtered["items"])
    assert reader.requests()["total"] == len(records)
    assert reader.requests(thread_id="poll-only", traffic="inference")["total"] == 0

    summaries = reader.threads(traffic="inference")
    assert summaries["total"] == 2
    summary = next(item for item in summaries["items"] if item["thread_id"] == "thread-a")
    assert summary["requests"] == 2
    assert summary["started_at"] == 100
    assert summary["last_started_at"] == 300
    assert summary["session_preview"] == "inference opening"
    assert summary["latest_model"] == "latest-inference"
    assert summary["latest_method"] == "POST"
    assert summary["latest_path"] == "/v1/chat/completions"
    assert summary["last_user_preview"] == "latest question"
    assert summary["last_assistant_preview"] == "previous answer"
    assert summary["total_tokens"] == 60
    assert summary["cost_usd"] == pytest.approx(0.02)
    assert summary["known_cost_requests"] == 2
    all_summary = next(
        item for item in reader.threads()["items"] if item["thread_id"] == "thread-a"
    )
    assert all_summary["latest_method"] == "GET"
    assert all_summary["latest_path"] == "/other"
    assert all_summary["session_preview"] == "poll opening"

    filtered_tree = reader.thread_requests("thread-a", order="desc", traffic="inference")
    assert filtered_tree["total"] == 2
    assert [item["request_id"] for item in filtered_tree["items"]] == ["child", "root"]
    assert [item["ordinal"] for item in filtered_tree["items"]] == [2, 1]
    assert filtered_tree["items"][0]["parent_request_id"] is None
    all_tree = reader.thread_requests("thread-a")
    child = next(item for item in all_tree["items"] if item["request_id"] == "child")
    assert child["parent_request_id"] == "poll-parent"
    poll = reader.request("poll-last")
    explicit = reader.request("explicit-true")
    assert poll is not None and explicit is not None
    assert poll["usage_applicable"] is False
    assert explicit["usage_applicable"] is True
    with sqlite3.connect(path) as connection:
        retained = json.loads(
            connection.execute(
                "SELECT record FROM requests WHERE request_id='poll-last'"
            ).fetchone()[0]
        )
    assert "usage_applicable" not in retained
    for query in (
        lambda: reader.requests(traffic="invalid"),
        lambda: reader.threads(traffic="invalid"),
        lambda: reader.thread_requests("thread-a", traffic="invalid"),
        lambda: reader.request_location("child", traffic="invalid"),
    ):
        with pytest.raises(ValueError, match="traffic must be 'all' or 'inference'"):
            query()


def test_inference_locations_rank_filtered_pages_and_fall_back_for_poll_deep_links(tmp_path):
    path = tmp_path / "traffic-pages.sqlite3"
    store = HistoryStore(path)
    store.start()
    for index in range(110):
        for kind, delta, usage_applicable in (("call", 0, True), ("poll", 0.5, False)):
            request_id = f"{kind}-{index:03d}"
            assert store.submit_start(
                start_record(
                    request_id,
                    thread_id="target",
                    started_at=index + delta,
                    method="POST" if usage_applicable else "GET",
                    usage_applicable=usage_applicable,
                )
            )
            assert store.submit_finish(request_id, finish_record())
    for index in range(55):
        for kind, usage_applicable in (("session", True), ("poll-session", False)):
            request_id = f"{kind}-{index:03d}"
            assert store.submit_start(
                start_record(
                    request_id,
                    thread_id=request_id,
                    started_at=1000 + index,
                    method="POST" if usage_applicable else "GET",
                    usage_applicable=usage_applicable,
                )
            )
            assert store.submit_finish(request_id, finish_record())
    store.close()
    reader = HistoryReader(path)
    location = reader.request_location("call-000", traffic="inference")
    assert location is not None
    assert location["traffic"] == "inference"
    assert location["thread_offset"] == 50
    assert location["request_offset"] == 100
    assert location["thread"]["requests"] == 110
    assert location["thread"]["last_started_at"] == 109
    sessions = reader.threads(offset=location["thread_offset"], traffic="inference")
    assert sessions["total"] == 56
    assert location["thread"] == sessions["items"][-1]
    calls = reader.thread_requests("target", offset=100, order="desc", traffic="inference")
    assert calls["total"] == 110
    assert [item["ordinal"] for item in calls["items"]] == list(range(10, 0, -1))
    assert calls["items"][-1]["request_id"] == "call-000"
    page = reader.requests(thread_id="target", limit=2, offset=100, traffic="inference")
    assert [item["request_id"] for item in page["items"]] == ["call-009", "call-008"]
    assert reader.threads(offset=56, traffic="inference")["items"] == []
    assert reader.thread_requests("target", offset=110, traffic="inference")["items"] == []

    poll_location = reader.request_location("poll-000", traffic="inference")
    assert poll_location is not None
    assert poll_location["traffic"] == "all"
    assert poll_location["thread_offset"] == 100
    assert poll_location["request_offset"] == 200
    assert poll_location["thread"]["requests"] == 220
    assert poll_location["thread"]["last_started_at"] == 109.5
    assert poll_location == reader.request_location("poll-000")
    assert reader.request_location("missing", traffic="inference") is None
    assert reader.threads()["total"] == 111
    assert store.status["write_errors"] == 0


def test_subscription_repricing_is_metadata_only_idempotent_and_preserves_usage(
    tmp_path, monkeypatch
):
    path = tmp_path / "repricing.sqlite3"
    store = HistoryStore(path)
    store.start()
    records = {
        "a-old": {},
        "z-new": {},
        "priced": {"cost_usd": 0.1},
        "missing-usage": {"output_tokens": None},
        "incomplete": {"metrics_incomplete": True},
        "media": {"unsupported_costs": True},
        "tier": {"cost_unavailable_reason": "unsupported_service_tier"},
        "poll": {"method": "GET"},
        "ancillary-post": {"usage_applicable": False},
        "other-provider": {"provider": "openai"},
        "evicted": {},
    }
    for request_id, fields in records.items():
        assert store.submit_start(
            start_record(
                request_id,
                started_at=100,
                provider=fields.get("provider", "chatgpt"),
                method=fields.get("method", "POST"),
                usage_applicable=fields.get("usage_applicable", request_id != "poll"),
                model="gpt-test",
                user_preview="preview must stay out of pricing candidates",
                request_body="retained redacted body",
            )
        )
        assert store.submit_finish(
            request_id,
            finish_record(
                **{
                    "cost_usd": None,
                    "cost_source": None,
                    "cost_unavailable_reason": "subscription",
                    **{
                        key: value
                        for key, value in fields.items()
                        if key not in ("method", "provider", "usage_applicable")
                    },
                }
            ),
        )
    assert store.submit_start(start_record("active", provider="chatgpt", model="gpt-test"))
    store._queue.join()
    reader = HistoryReader(path)
    original = reader.request("a-old")
    assert original is not None
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM requests WHERE request_id='evicted'")
    original_connect = reader._connect

    def no_body_connect(database_path):
        connection = original_connect(database_path)
        assert connection is not None
        connection.set_authorizer(
            lambda action, table, column, *_: (
                sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_READ
                and table == "requests"
                and column == "request_body"
                else sqlite3.SQLITE_OK
            )
        )
        return connection

    with monkeypatch.context() as patch:
        patch.setattr(reader, "_connect", no_body_connect)
        first = reader.subscription_pricing_candidates(limit=1)
        assert [item["request_id"] for item in first["items"]] == ["z-new"]
        assert first["items"][0]["usage_applicable"] is True
        assert first["items"][0]["metrics_incomplete"] is False
        assert first["next_cursor"] == {"started_at": 100, "request_id": "z-new"}
        second = reader.subscription_pricing_candidates(limit=1, before=first["next_cursor"])
        assert [item["request_id"] for item in second["items"]] == ["a-old"]
        assert second["next_cursor"] is None
        assert "retained redacted body" not in str(first)
        assert "preview must stay out" not in str(first)
    store = HistoryStore(path)
    store.start()
    before = reader.summary(days=36500)
    for request_id in records:
        assert store.submit_reprice(
            request_id,
            equivalent_quote(
                request_body="injected body",
                output_tokens=999,
                provider="changed",
                pricing_rates={
                    "input_cost_per_token": 0.001,
                    "output_cost_per_token": 0.002,
                    "scope": "text_tokens",
                    "authorization": "must not persist",
                },
            ),
        )
    assert store.submit_reprice("a-old", equivalent_quote(cost_usd=99))
    assert store.submit_reprice("z-new", equivalent_quote(cost_usd=99))
    assert store.submit_reprice("missing", equivalent_quote())
    store.close()
    after = reader.summary(days=36500)
    cost_fields = {"cost_usd", "cost_usd_known_requests", "unknown_cost_requests"}
    for name in ("totals", "lifetime_totals"):
        assert after[name]["cost_usd"] == pytest.approx(before[name]["cost_usd"] + 0.5)
        assert after[name]["cost_usd_known_requests"] == before[name]["cost_usd_known_requests"] + 2
        assert after[name]["unknown_cost_requests"] == before[name]["unknown_cost_requests"] - 2
        assert {key: value for key, value in after[name].items() if key not in cost_fields} == {
            key: value for key, value in before[name].items() if key not in cost_fields
        }
    updated = reader.request("a-old")
    assert updated is not None
    pricing_fields = {
        "cost_usd",
        "cost_source",
        "pricing_as_of",
        "pricing_model",
        "pricing_rates",
        "cost_unavailable_reason",
    }
    assert updated["cost_usd"] == 0.25
    assert {key: value for key, value in updated.items() if key not in pricing_fields} == {
        key: value for key, value in original.items() if key not in pricing_fields
    }
    assert "authorization" not in updated["pricing_rates"]
    new = reader.request("z-new")
    priced = reader.request("priced")
    assert new is not None and priced is not None
    assert new["cost_usd"] == 0.25
    assert priced["cost_usd"] == 0.1
    assert reader.request("evicted") is None
    assert reader.request("missing") is None
    assert reader.subscription_pricing_candidates()["items"] == []
    assert store.status["write_errors"] == 0


def test_subscription_repricing_does_not_recreate_evicted_daily_aggregates(tmp_path):
    path = tmp_path / "repricing-pruned-stats.sqlite3"
    store = HistoryStore(path)
    store.start()
    assert store.submit_start(start_record("one", provider="chatgpt", model="gpt-test"))
    assert store.submit_finish(
        "one", finish_record(cost_usd=None, cost_unavailable_reason="subscription")
    )
    store.close()
    with sqlite3.connect(path.with_name(path.name + ".stats.sqlite3")) as connection:
        connection.execute("DELETE FROM aggregates")
    store = HistoryStore(path)
    store.start()
    assert store.submit_reprice("one", equivalent_quote(cost_source="custom_api_equivalent"))
    store.close()
    reader = HistoryReader(path)
    summary = reader.summary()
    assert summary["totals"]["requests"] == 0
    assert summary["daily"] == []
    assert summary["lifetime_totals"]["requests"] == 1
    assert summary["lifetime_totals"]["cost_usd"] == 0.25
    assert summary["lifetime_totals"]["cost_usd_known_requests"] == 1
    assert summary["lifetime_totals"]["unknown_cost_requests"] == 0
    detail = reader.request("one")
    assert detail is not None
    assert detail["cost_source"] == "custom_api_equivalent"


def test_subscription_repricing_rolls_back_detail_and_lifetime_on_aggregate_failure(tmp_path):
    path = tmp_path / "repricing-rollback.sqlite3"
    store = HistoryStore(path)
    store.start()
    assert store.submit_start(start_record("one", provider="chatgpt", model="gpt-test"))
    assert store.submit_finish(
        "one", finish_record(cost_usd=None, cost_unavailable_reason="subscription")
    )
    store.close()
    with sqlite3.connect(path.with_name(path.name + ".stats.sqlite3")) as connection:
        connection.execute("""CREATE TRIGGER reject_reprice BEFORE UPDATE ON aggregates
            BEGIN SELECT RAISE(ABORT,'fixture repricing failure'); END""")
    reader = HistoryReader(path)
    original = reader.request("one")
    before = reader.summary()
    store = HistoryStore(path)
    store.start()
    assert store.submit_reprice("one", equivalent_quote())
    store.close()
    after = reader.summary()
    assert reader.request("one") == original
    assert after["totals"] == before["totals"]
    assert after["lifetime_totals"] == before["lifetime_totals"]
    assert store.status["write_errors"] == 1
    assert after["storage"]["write_errors"] == 1


def test_subscription_repricing_rejects_unbounded_or_invalid_quotes(tmp_path):
    path = tmp_path / "invalid-repricing.sqlite3"
    store = HistoryStore(path, max_database_bytes=256 * 1024)
    store.start()
    for fields in (
        {"cost_usd": None},
        {"cost_usd": -1},
        {"cost_usd": float("nan")},
        {"cost_usd": float("inf")},
        {"cost_usd": True},
        {"cost_usd": 10**1000},
        {"cost_source": "actual_bill"},
        {"cost_unavailable_reason": "subscription"},
        {"pricing_model": "x" * 5000},
        {"pricing_rates": {"scope": "unknown"}},
    ):
        assert not store.submit_reprice("one", equivalent_quote(**fields))
    store.close()
    assert directory_bytes(tmp_path) <= 256 * 1024
    assert store.status["write_errors"] == 0


def test_subscription_repricing_keeps_live_journals_within_combined_budget(tmp_path, monkeypatch):
    path = tmp_path / "repricing-budget.sqlite3"
    budget = 512 * 1024
    store = HistoryStore(path, max_database_bytes=budget)
    maximum_bytes = 0
    journal_observed = False
    original = store._open_writer

    def observed_open():
        connection = original()

        def observe(_statement):
            nonlocal maximum_bytes, journal_observed
            maximum_bytes = max(maximum_bytes, directory_bytes(tmp_path))
            journal_observed |= any(item.name.endswith("-journal") for item in tmp_path.iterdir())

        connection.set_trace_callback(observe)
        return connection

    monkeypatch.setattr(store, "_open_writer", observed_open)
    store.start()
    for index in range(64):
        request_id = f"call-{index:03d}"
        assert store.submit_start(
            start_record(
                request_id,
                provider="chatgpt",
                model="gpt-test",
                started_at=time.time() + index,
            )
        )
        assert store.submit_finish(request_id, finish_record(cost_usd=None))
    store._queue.join()
    reader = HistoryReader(path)
    candidates = reader.subscription_pricing_candidates(limit=100)["items"]
    assert len(candidates) == 64
    for item in candidates:
        assert store.submit_reprice(item["request_id"], equivalent_quote(pricing_model="x" * 3000))
    store.close()
    summary = reader.summary()
    assert maximum_bytes <= budget
    assert journal_observed
    assert summary["storage"]["total_bytes"] <= budget
    assert summary["storage"]["pruned_requests"] > 0
    assert summary["lifetime_totals"]["requests"] == 64
    assert summary["lifetime_totals"]["total_tokens"] == 64 * 30
    assert 0 < summary["lifetime_totals"]["cost_usd_known_requests"] <= 64
    assert store.status["write_errors"] == 0


def test_storage_rejects_symlinks_without_modifying_the_target(tmp_path):
    target = tmp_path / "unrelated"
    target.write_text("unchanged")
    target.chmod(0o644)
    path = tmp_path / "history.sqlite3"
    path.symlink_to(target)
    store = HistoryStore(path)
    with pytest.raises(OSError):
        store.start()
    with pytest.raises(OSError):
        HistoryReader(path).request("one")
    assert target.read_text() == "unchanged"
    assert target.stat().st_mode & 0o777 == 0o644
    path.unlink()
    store.start()
    store.close()


@pytest.mark.parametrize("kind", ["fifo", "hardlink", "stats_symlink"])
def test_storage_rejects_nonregular_or_aliased_files(tmp_path, kind):
    path = tmp_path / "history.sqlite3"
    target = tmp_path / "unrelated"
    target.write_text("unchanged")
    target.chmod(0o644)
    if kind == "fifo":
        os.mkfifo(path, 0o644)
    elif kind == "hardlink":
        path.hardlink_to(target)
    else:
        path.with_name(path.name + ".stats.sqlite3").symlink_to(target)
    store = HistoryStore(path)
    with pytest.raises((PermissionError, OSError)):
        store.start()
    assert target.read_text() == "unchanged"
    assert target.stat().st_mode & 0o777 == 0o644


def test_storage_rejects_unsafe_directory_and_foreign_owner(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    tmp_path.chmod(0o777)
    with pytest.raises(PermissionError, match="directory"):
        HistoryStore(path).start()
    tmp_path.chmod(0o700)
    foreign_uid = os.getuid() + 1
    monkeypatch.setattr("promptlatch.history.os.getuid", lambda: foreign_uid)
    with pytest.raises(PermissionError, match="owned by this user"):
        HistoryStore(path).start()
