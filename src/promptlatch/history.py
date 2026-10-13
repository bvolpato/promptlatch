"""Bounded local request history and durable, content-free usage aggregates."""

from __future__ import annotations

import json
import logging
import math
import os
import queue
import sqlite3
import stat
import threading
import time
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from promptlatch.request_previews import (
    MAX_LEGACY_BODY_BYTES,
    PREVIEW_FIELDS,
    bound_preview_text,
    legacy_request_previews,
)

_PAGE_SIZE = 4096
_MIN_DATABASE_BYTES = 256 * 1024
logger = logging.getLogger("promptlatch")
_FIELDS = frozenset(
    [
        "request_id",
        "thread_id",
        "thread_source",
        "turn_id",
        "user_turn",
        "message_count",
        "turn_source",
        "parent_response_id_hash",
        "started_at",
        "completed_at",
        "method",
        "path",
        "model",
        "provider",
        "stream",
        "outcome",
        "status_code",
        "duration_ms",
        "ttft_ms",
        "generation_ms",
        "tps",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cached_input_tokens",
        "cache_write_tokens",
        "usage_source",
        "cost_usd",
        "cost_source",
        "pricing_as_of",
        "pricing_model",
        "pricing_rates",
        "redactions",
        "rule_hits",
        "request_body",
        *PREVIEW_FIELDS,
        "body_truncated",
        "body_omitted_reason",
        "response_id_hash",
        "metrics_incomplete",
        "metrics_unavailable_reason",
        "response_format",
        "reasoning_tokens",
        "usage_applicable",
        "cost_unavailable_reason",
        "unsupported_costs",
    ]
)
_TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
)
_SUM_FIELDS = (
    "requests",
    "successes",
    "errors",
    "cancelled",
    "interrupted",
    "streamed_requests",
    "redacted_requests",
    "redactions",
    "unknown_usage_requests",
    "unknown_cost_requests",
    "usage_applicable_requests",
    "usage_applicability_unknown_requests",
)
_AVERAGE_FIELDS = ("duration_ms", "ttft_ms", "tps")
_FINAL_OUTCOMES = frozenset(
    ("success", "http_error", "transport_error", "stream_error", "cancelled", "interrupted")
)
_NON_INFERENCE_METHODS = ("GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT")
_REPRICE_FIELDS = frozenset(
    (
        "cost_usd",
        "cost_source",
        "pricing_as_of",
        "pricing_model",
        "pricing_rates",
        "cost_unavailable_reason",
    )
)
_PRICING_RATE_FIELDS = frozenset(
    (
        "input_cost_per_token",
        "output_cost_per_token",
        "cache_read_input_token_cost",
        "cache_creation_input_token_cost",
        "catalog_sha256",
        "retrieved_at",
        "source",
        "package_version",
        "scope",
    )
)
_REPRICE_BLOCKED_REASONS = (
    "usage_incomplete",
    "unsupported_costs",
    "unsupported_service_tier",
    "not_applicable",
)
_PRICING_CANDIDATE_FIELDS = (
    "model",
    "provider",
    "method",
    "outcome",
    "usage_applicable",
    "metrics_incomplete",
    "unsupported_costs",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "cache_write_tokens",
    "cost_usd",
    "cost_unavailable_reason",
)


def _stats_path(path: Path) -> Path:
    return path.with_name(path.name + ".stats.sqlite3")


def _file_bytes(path: Path) -> int:
    total = 0
    for suffix in ("", "-journal", "-wal", "-shm"):
        with suppress(FileNotFoundError):
            total += Path(str(path) + suffix).stat().st_size
    for super_journal in path.parent.glob(path.name + "-mj*"):
        with suppress(FileNotFoundError):
            total += super_journal.stat().st_size
    return total


def _validate_file(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        raise PermissionError("History files must be single-link regular files owned by this user")


def _validate_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise PermissionError(
            "History directory must be owned by this user and not writable by others"
        )


def _encode(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _empty_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = dict.fromkeys(_SUM_FIELDS, 0)
    for field in (*_TOKEN_FIELDS, "cost_usd", *_AVERAGE_FIELDS):
        metrics[field] = 0
        metrics[field + "_samples"] = 0
    metrics["rule_hits"] = {}
    return metrics


def _merge_metrics(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if key == "rule_hits":
            for rule, count in value.items():
                target[key][rule] = target[key].get(rule, 0) + count
        else:
            target[key] += value


def _load_metrics(encoded: str) -> dict[str, Any]:
    recorded = json.loads(encoded)
    recorded.setdefault("usage_applicable_requests", recorded.get("requests", 0))
    recorded.setdefault("usage_applicability_unknown_requests", recorded.get("requests", 0))
    metrics = _empty_metrics()
    _merge_metrics(metrics, recorded)
    return metrics


def _public_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    result = {field: metrics[field] for field in _SUM_FIELDS}
    for field in (*_TOKEN_FIELDS, "cost_usd"):
        samples = metrics[field + "_samples"]
        result[field] = metrics[field] if samples else None
        result[field + "_known_requests"] = samples
    for field in _AVERAGE_FIELDS:
        samples = metrics[field + "_samples"]
        result["avg_" + field] = metrics[field] / samples if samples else None
    result["rule_hits"] = metrics["rule_hits"]
    return result


def _record_metrics(record: dict[str, Any]) -> dict[str, Any]:
    result = _empty_metrics()
    outcome = record["outcome"]
    result.update(
        requests=1,
        successes=int(outcome == "success"),
        errors=int(outcome in ("http_error", "transport_error", "stream_error")),
        cancelled=int(outcome == "cancelled"),
        interrupted=int(outcome == "interrupted"),
        streamed_requests=int(bool(record.get("stream"))),
        redacted_requests=int(bool(record.get("redactions"))),
        redactions=record.get("redactions", 0),
        unknown_usage_requests=int(
            record.get("usage_applicable") is not False and record.get("total_tokens") is None
        ),
        unknown_cost_requests=int(
            record.get("usage_applicable") is not False and record.get("cost_usd") is None
        ),
        usage_applicable_requests=int(record.get("usage_applicable") is not False),
        usage_applicability_unknown_requests=int(
            not isinstance(record.get("usage_applicable"), bool)
        ),
        rule_hits=record.get("rule_hits", {}),
    )
    for field in (*_TOKEN_FIELDS, "cost_usd", *_AVERAGE_FIELDS):
        if record.get("usage_applicable") is False and field != "duration_ms":
            continue
        if record.get(field) is not None:
            result[field] = record[field]
            result[field + "_samples"] = 1
    return result


def _subscription_pricing_eligible(record: dict[str, Any]) -> bool:
    if (
        record.get("provider") != "chatgpt"
        or record.get("outcome") not in _FINAL_OUTCOMES
        or record.get("cost_usd") is not None
        or record.get("metrics_incomplete") not in (None, False)
        or record.get("unsupported_costs") not in (None, False)
        or record.get("cost_unavailable_reason") in _REPRICE_BLOCKED_REASONS
        or record.get("usage_applicable") is False
        or (
            not isinstance(record.get("usage_applicable"), bool)
            and str(record.get("method", "")).upper() in _NON_INFERENCE_METHODS
        )
    ):
        return False
    for key in ("input_tokens", "output_tokens", "cached_input_tokens", "cache_write_tokens"):
        value = record.get(key)
        if value is None and key not in ("input_tokens", "output_tokens"):
            continue
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
            return False
    return (record.get("cached_input_tokens") or 0) + (
        record.get("cache_write_tokens") or 0
    ) <= record["input_tokens"]


class HistoryStore:
    """Single background writer. Call start/close outside the request event loop.

    Producers must use unique request IDs and submit each start once. Finishes are
    idempotent: a durable pending row is consumed in the aggregate transaction.
    Bodies and sibling stats share one physical budget, including rollback
    journals. Details expire first, then daily/model counters. Lifetime totals
    survive retention; pending metadata never contains bodies or previews.
    """

    def __init__(
        self,
        database_path: Path,
        max_database_bytes: int = 1024 * 1024 * 1024,
        max_body_bytes: int = 256 * 1024,
        queue_size: int = 1024,
    ) -> None:
        if max_database_bytes < _MIN_DATABASE_BYTES:
            raise ValueError("max_database_bytes must be at least 262144")
        if max_body_bytes < 0 or queue_size < 1:
            raise ValueError("max_body_bytes must be nonnegative and queue_size positive")
        self.database_path = Path(database_path).expanduser()
        self.max_database_bytes = max_database_bytes
        self.max_body_bytes = max_body_bytes
        self._queue: queue.Queue[tuple[str, dict[str, Any], int] | None] = queue.Queue(queue_size)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._accepting = False
        self._dropped_writes = 0
        self._write_errors = 0
        self._persisted_counts = (0, 0)
        self._warned_counts = (0, 0)
        self._last_warning = float("-inf")
        self._last_error: str | None = None
        self._writer_lock_fd: int | None = None
        self._queued_body_bytes = 0
        self._queue_body_limit = min(32 * 1024 * 1024, max_database_bytes // 8)
        # Reserve both databases plus a full rollback copy of each page. The
        # remaining headroom covers Unix journal headers, FULL-sync sector
        # padding before super-journal names, and all journal names.
        # Cache spilling is disabled so transactions do not add journal headers.
        path_bytes = sum(
            len(os.fsencode(path.absolute()))
            for path in (self.database_path, _stats_path(self.database_path))
        )
        journal_headroom = max(32768, 4 * _PAGE_SIZE + 2 * path_bytes + 512)
        self._storage_capacity_bytes = max_database_bytes - journal_headroom
        self._max_storage_pages = self._storage_capacity_bytes // (2 * _PAGE_SIZE + 8)
        self._detail_target = int(self._max_storage_pages * _PAGE_SIZE * 0.85)
        self._batch_limit = min(32, max(2, self._max_storage_pages // 32))

    @property
    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._accepting,
                "dropped_writes": self._dropped_writes,
                "write_errors": self._write_errors,
                "last_error": self._last_error,
                "queue_depth": self._queue.qsize(),
                "queued_body_bytes": self._queued_body_bytes,
            }

    @property
    def dropped_writes(self) -> int:
        return self.status["dropped_writes"]

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            try:
                connection = self._open_writer()
            except BaseException:
                self._release_writer_lock()
                raise
            self._accepting = True
            self._thread = threading.Thread(
                target=self._run, args=(connection,), name="promptlatch-history", daemon=True
            )
            self._thread.start()

    def _prepare_record(self, record: dict[str, Any]) -> tuple[dict[str, Any], int]:
        result = {key: value for key, value in record.items() if key in _FIELDS}
        for key in ("rule_hits", "pricing_rates"):
            if isinstance(result.get(key), dict):
                result[key] = dict(result[key])
        for key in PREVIEW_FIELDS:
            if key in result:
                value = result[key]
                result[key] = bound_preview_text(value) if isinstance(value, str) else None
        body = result.get("request_body")
        body_bytes = 0
        if isinstance(body, str):
            bounded = body[: self.max_body_bytes].encode("utf-8")[: self.max_body_bytes]
            trimmed = bounded.decode("utf-8", errors="ignore")
            if len(trimmed) < len(body):
                result["body_truncated"] = True
            result["request_body"] = trimmed if self.max_body_bytes else None
            if not self.max_body_bytes:
                result["body_omitted_reason"] = "disabled"
            body_bytes = len(bounded)
        if not self.max_body_bytes:
            for key in PREVIEW_FIELDS:
                result[key] = None
        body_bytes += sum(
            len(value.encode("utf-8")) for key in PREVIEW_FIELDS if (value := result.get(key))
        )
        return result, body_bytes

    def _submit(self, kind: str, record: dict[str, Any]) -> bool:
        record, body_bytes = self._prepare_record(record)
        with self._lock:
            if not self._accepting:
                self._dropped_writes += 1
                return False
            if body_bytes + self._queued_body_bytes > self._queue_body_limit:
                record.update(
                    request_body=None, body_truncated=True, body_omitted_reason="queue_pressure"
                )
                record.update(dict.fromkeys(PREVIEW_FIELDS))
                body_bytes = 0
            try:
                self._queue.put_nowait((kind, record, body_bytes))
            except queue.Full:
                self._dropped_writes += 1
                return False
            self._queued_body_bytes += body_bytes
            return True

    def submit_start(self, record: dict[str, Any]) -> bool:
        return self._submit("start", {**record, **{key: record.get(key) for key in PREVIEW_FIELDS}})

    def submit_finish(self, request_id: str, fields: dict[str, Any]) -> bool:
        return self._submit("finish", {**fields, "request_id": request_id})

    def submit_reprice(self, request_id: str, quote: dict[str, Any]) -> bool:
        fields = {key: value for key, value in quote.items() if key in _REPRICE_FIELDS}
        cost = fields.get("cost_usd")
        rates = fields.get("pricing_rates")
        if (
            not isinstance(cost, (int, float))
            or isinstance(cost, bool)
            or cost < 0
            or fields.get("cost_source") not in ("litellm_api_equivalent", "custom_api_equivalent")
            or fields.get("cost_unavailable_reason") is not None
            or not isinstance(rates, dict)
            or rates.get("scope") != "text_tokens"
        ):
            return False
        try:
            fields["cost_usd"] = float(cost)
        except OverflowError:
            return False
        if not math.isfinite(fields["cost_usd"]):
            return False
        fields["pricing_rates"] = {
            key: value for key, value in rates.items() if key in _PRICING_RATE_FIELDS
        }
        fields["cost_unavailable_reason"] = None
        try:
            if len(_encode(fields).encode("utf-8")) > 4096:
                return False
        except (ValueError, TypeError, RecursionError):
            return False
        return self._submit("reprice", {**fields, "request_id": request_id})

    def close(self) -> None:
        with self._lock:
            thread = self._thread
            if thread is None or not self._accepting:
                return
            self._accepting = False
        self._queue.put(None)
        thread.join()
        with self._lock:
            self._thread = None

    def _acquire_writer_lock(self) -> None:
        try:
            import fcntl
        except ImportError as exc:
            raise RuntimeError("Local history requires POSIX advisory file locks") from exc
        path = _stats_path(self.database_path)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            _validate_file(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise RuntimeError("Another history writer is already using this database") from None
        except BaseException:
            os.close(fd)
            raise
        self._writer_lock_fd = fd

    def _release_writer_lock(self) -> None:
        if self._writer_lock_fd is not None:
            os.close(self._writer_lock_fd)
            self._writer_lock_fd = None

    def _startup_pages(self, path: Path) -> int:
        """Inspect SQLite headers without triggering journal recovery or writes."""
        original_pages = 0
        journal_pages = 0
        for suffix in ("-wal", "-shm"):
            with suppress(FileNotFoundError):
                if Path(str(path) + suffix).stat().st_size:
                    raise RuntimeError(
                        "History has WAL recovery sidecars; "
                        "offline recovery required before bounded startup"
                    )
        try:
            journal_fd = os.open(
                str(path) + "-journal", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            )
        except FileNotFoundError:
            journal_fd = None
        if journal_fd is not None:
            try:
                _validate_file(journal_fd)
                journal_pages = (os.fstat(journal_fd).st_size + _PAGE_SIZE - 1) // _PAGE_SIZE
                journal_header = os.pread(journal_fd, 28, 0)
                if journal_header[:8] == b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
                    if len(journal_header) != 28 or int.from_bytes(
                        journal_header[24:28], "big"
                    ) not in (0, _PAGE_SIZE):
                        raise RuntimeError("History rollback journal requires offline recovery")
                    original_pages = int.from_bytes(journal_header[16:20], "big")
                elif any(journal_header[:8]):
                    raise RuntimeError("History rollback journal requires offline recovery")
            finally:
                os.close(journal_fd)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return max(original_pages, journal_pages)
        try:
            _validate_file(fd)
            size = os.fstat(fd).st_size
            if not size:
                return max(original_pages, journal_pages)
            header = os.pread(fd, 100, 0)
            if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
                raise RuntimeError("History has an invalid SQLite header")
            if int.from_bytes(header[16:18], "big") != _PAGE_SIZE or size % _PAGE_SIZE:
                raise RuntimeError("History requires offline conversion to 4096-byte SQLite pages")
            return max(size // _PAGE_SIZE, original_pages, journal_pages)
        finally:
            os.close(fd)

    def _startup_limits(self, paths: tuple[Path, Path]) -> tuple[int, int]:
        history_pages, main_pages = (self._startup_pages(path) for path in paths)
        sidecar_bytes = 0
        super_journal_bytes = 0
        for path in paths:
            size = path.stat().st_size if path.exists() else 0
            sidecar_bytes += _file_bytes(path) - size
            for super_journal in path.parent.glob(path.name + "-mj*"):
                with suppress(FileNotFoundError):
                    super_journal_bytes += super_journal.stat().st_size
        # Recovery can leave unrelated orphan super-journals. Keep their bytes
        # reserved until the next startup rather than deleting recovery files.
        self._max_storage_pages = (self._storage_capacity_bytes - super_journal_bytes) // (
            2 * _PAGE_SIZE + 8
        )
        if (history_pages + main_pages) * _PAGE_SIZE + sidecar_bytes > self.max_database_bytes:
            raise RuntimeError(
                "History startup or rollback recovery cannot fit storage budget; "
                "offline recovery or compaction required. "
                "No database writes performed"
            )
        stats_limit = max(main_pages + 4, 12)
        if stats_limit + max(history_pages, 7) > self._max_storage_pages:
            raise RuntimeError(
                "Existing history cannot reserve bounded startup and rollback journal space; "
                "offline compaction or a larger storage budget required. "
                "No database writes performed"
            )
        return stats_limit, self._max_storage_pages - stats_limit

    def _set_page_limits(
        self, connection: sqlite3.Connection, stats_limit: int, history_limit: int
    ) -> None:
        actual_main = connection.execute(f"PRAGMA main.max_page_count={stats_limit}").fetchone()[0]
        actual_history = connection.execute(
            f"PRAGMA history.max_page_count={history_limit}"
        ).fetchone()[0]
        if actual_main + actual_history > self._max_storage_pages:
            raise sqlite3.OperationalError("History storage page limits exceed budget")
        self._detail_target = int(history_limit * _PAGE_SIZE * 0.85)

    def _open_writer(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _validate_directory(self.database_path.parent)
        paths = (self.database_path, _stats_path(self.database_path))
        self._startup_limits(paths)
        self._acquire_writer_lock()
        stats_limit, history_limit = self._startup_limits(paths)
        for path in paths:
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            try:
                _validate_file(fd)
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        connection = sqlite3.connect(paths[1], timeout=2, check_same_thread=False)
        try:
            connection.execute("ATTACH DATABASE ? AS history", (str(paths[0]),))
            self._set_page_limits(connection, stats_limit, history_limit)
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA cache_spill=OFF")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA history.journal_mode=DELETE")
            connection.execute("PRAGMA history.synchronous=FULL")
            for schema in ("main", "history"):
                if connection.execute(f"PRAGMA {schema}.page_count").fetchone()[0] == 0:
                    connection.execute(f"PRAGMA {schema}.page_size={_PAGE_SIZE}")
                    connection.execute(f"PRAGMA {schema}.auto_vacuum=FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS pending (
                    request_id TEXT PRIMARY KEY, record TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS aggregates (
                    day TEXT NOT NULL, model TEXT NOT NULL, provider TEXT NOT NULL,
                    metrics TEXT NOT NULL, PRIMARY KEY (day, model, provider)
                );
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS lifetime (
                    id INTEGER PRIMARY KEY CHECK (id=1), metrics TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS history.requests (
                    request_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL,
                    started_at REAL NOT NULL, record TEXT NOT NULL,
                    response_id_hash TEXT, request_body TEXT
                );
                CREATE INDEX IF NOT EXISTS history.requests_started ON requests(started_at);
                CREATE INDEX IF NOT EXISTS history.requests_thread_order
                    ON requests(thread_id, started_at, request_id);
                CREATE INDEX IF NOT EXISTS history.requests_response
                    ON requests(response_id_hash) WHERE response_id_hash IS NOT NULL;
                """
            )
            with connection:
                connection.executemany(
                    "INSERT OR IGNORE INTO settings(key,value) VALUES (?,0)",
                    (
                        ("dropped_writes",),
                        ("write_errors",),
                        ("pruned_requests",),
                        ("pruned_aggregate_rows",),
                    ),
                )
                stored = dict(connection.execute("SELECT key,value FROM settings"))
                self._dropped_writes += max(0, stored["dropped_writes"] - self._persisted_counts[0])
                self._write_errors += max(0, stored["write_errors"] - self._persisted_counts[1])
                self._persisted_counts = (stored["dropped_writes"], stored["write_errors"])
                connection.executemany(
                    "INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)",
                    (
                        ("max_database_bytes", self.max_database_bytes),
                        ("max_body_bytes", self.max_body_bytes),
                    ),
                )
                if connection.execute("SELECT 1 FROM lifetime WHERE id=1").fetchone() is None:
                    lifetime = _empty_metrics()
                    for (encoded,) in connection.execute("SELECT metrics FROM aggregates"):
                        metrics = _load_metrics(encoded)
                        metrics["rule_hits"] = {}
                        _merge_metrics(lifetime, metrics)
                    connection.execute(
                        "INSERT INTO lifetime(id,metrics) VALUES (1,?)", (_encode(lifetime),)
                    )
            self._reserve(connection, [])
            while row := connection.execute("SELECT request_id FROM pending LIMIT 1").fetchone():
                event = {
                    "request_id": row[0],
                    "completed_at": time.time(),
                    "outcome": "interrupted",
                }
                self._reserve(connection, [("finish", event, 0)])
                with connection:
                    self._finish(connection, event)
            self._reserve(connection, [])
            return connection
        except BaseException:
            connection.close()
            self._release_writer_lock()
            raise

    def _run(self, connection: sqlite3.Connection) -> None:
        try:
            while True:
                try:
                    item = self._queue.get(timeout=1)
                except queue.Empty:
                    self._persist_counters(connection)
                    continue
                batch = []
                stopping = item is None
                if item is not None:
                    batch.append(item)
                    while len(batch) < self._batch_limit:
                        try:
                            item = self._queue.get_nowait()
                        except queue.Empty:
                            break
                        if item is None:
                            stopping = True
                            break
                        batch.append(item)
                with self._lock:
                    self._queued_body_bytes -= sum(item[2] for item in batch)
                try:
                    self._reserve(connection, batch)
                    with connection:
                        connection.execute("BEGIN IMMEDIATE")
                        for kind, record, _ in batch:
                            connection.execute("SAVEPOINT history_event")
                            try:
                                if kind == "start":
                                    self._start(connection, record)
                                elif kind == "reprice":
                                    self._reprice(connection, record)
                                else:
                                    self._finish(connection, record)
                            except Exception as exc:
                                connection.execute("ROLLBACK TO history_event")
                                self._record_error(exc)
                            connection.execute("RELEASE history_event")
                except Exception as exc:
                    self._record_error(exc, len(batch))
                finally:
                    self._persist_counters(connection)
                    for _ in range(len(batch) + int(stopping)):
                        self._queue.task_done()
                if stopping:
                    return
        finally:
            connection.close()
            self._release_writer_lock()

    def _record_error(self, exc: Exception, count: int = 1) -> None:
        with self._lock:
            self._write_errors += count
            self._last_error = type(exc).__name__

    def _persist_counters(self, connection: sqlite3.Connection) -> None:
        with self._lock:
            counts = (self._dropped_writes, self._write_errors)
        if counts == self._persisted_counts:
            return
        now = time.monotonic()
        if counts != self._warned_counts and now - self._last_warning >= 30:
            logger.warning(
                "History capture incomplete: %d dropped writes, %d write errors",
                *counts,
            )
            self._last_warning = now
            self._warned_counts = counts
        try:
            with connection:
                connection.executemany(
                    "UPDATE settings SET value=? WHERE key=?",
                    ((counts[0], "dropped_writes"), (counts[1], "write_errors")),
                )
            self._persisted_counts = counts
        except sqlite3.Error as exc:
            self._record_error(exc)

    def _start(self, connection: sqlite3.Connection, record: dict[str, Any]) -> None:
        request_id = record["request_id"]
        if connection.execute(
            "SELECT 1 FROM history.requests WHERE request_id=?", (request_id,)
        ).fetchone():
            return
        record.setdefault("started_at", time.time())
        record.setdefault("thread_id", request_id)
        record.setdefault("thread_source", "request")
        record.setdefault("redactions", 0)
        record.setdefault("rule_hits", {})
        record.setdefault("metrics_incomplete", False)
        record["outcome"] = "active"
        metadata = {
            key: value
            for key, value in record.items()
            if key != "request_body" and key not in PREVIEW_FIELDS
        }
        cursor = connection.execute(
            "INSERT OR IGNORE INTO pending(request_id,record) VALUES (?,?)",
            (request_id, _encode(metadata)),
        )
        if cursor.rowcount:
            self._write_detail(connection, record)

    def _finish(self, connection: sqlite3.Connection, fields: dict[str, Any]) -> None:
        request_id = fields["request_id"]
        row = connection.execute(
            "SELECT record FROM pending WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            return
        record = json.loads(row[0])
        detail = connection.execute(
            "SELECT record,request_body FROM history.requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if detail:
            record.update(json.loads(detail[0]))
            record["request_body"] = detail[1]
        else:
            record.update(request_body=None, body_omitted_reason="detail_evicted")
        record.update(fields)
        if record.get("outcome") not in _FINAL_OUTCOMES:
            raise ValueError("finish requires a final outcome")
        record.setdefault("completed_at", time.time())
        if record.get("completed_at") is None:
            record["completed_at"] = time.time()
        if record.get("duration_ms") is None and record["outcome"] != "interrupted":
            record["duration_ms"] = max(0, record["completed_at"] - record["started_at"]) * 1000
        day = datetime.fromtimestamp(record["started_at"], UTC).date().isoformat()
        dimensions = (day, record.get("model") or "", record.get("provider") or "")
        row = connection.execute(
            "SELECT metrics FROM aggregates WHERE day=? AND model=? AND provider=?", dimensions
        ).fetchone()
        metrics = _load_metrics(row[0]) if row else _empty_metrics()
        _merge_metrics(metrics, _record_metrics(record))
        connection.execute(
            "INSERT OR REPLACE INTO aggregates(day,model,provider,metrics) VALUES (?,?,?,?)",
            (*dimensions, _encode(metrics)),
        )
        lifetime = _load_metrics(
            connection.execute("SELECT metrics FROM lifetime WHERE id=1").fetchone()[0]
        )
        contribution = _record_metrics(record)
        contribution["rule_hits"] = {}
        _merge_metrics(lifetime, contribution)
        connection.execute("UPDATE lifetime SET metrics=? WHERE id=1", (_encode(lifetime),))
        connection.execute("DELETE FROM pending WHERE request_id=?", (request_id,))
        # Do not revive already-evicted old requests at the expense of newer traffic.
        if detail:
            self._write_detail(connection, record)

    def _reprice(self, connection: sqlite3.Connection, fields: dict[str, Any]) -> None:
        row = connection.execute(
            "SELECT record FROM history.requests WHERE request_id=?", (fields["request_id"],)
        ).fetchone()
        if row is None:
            return
        record = json.loads(row[0])
        if not _subscription_pricing_eligible(record):
            return
        lifetime = _load_metrics(
            connection.execute("SELECT metrics FROM lifetime WHERE id=1").fetchone()[0]
        )
        day = datetime.fromtimestamp(record["started_at"], UTC).date().isoformat()
        dimensions = (day, record.get("model") or "", record.get("provider") or "")
        row = connection.execute(
            "SELECT metrics FROM aggregates WHERE day=? AND model=? AND provider=?", dimensions
        ).fetchone()
        aggregate = _load_metrics(row[0]) if row else None
        if lifetime["unknown_cost_requests"] < 1 or (
            aggregate is not None and aggregate["unknown_cost_requests"] < 1
        ):
            return
        for metrics in (lifetime, aggregate):
            if metrics is not None:
                metrics["cost_usd"] += fields["cost_usd"]
                metrics["cost_usd_samples"] += 1
                metrics["unknown_cost_requests"] -= 1
        record.update({key: value for key, value in fields.items() if key in _REPRICE_FIELDS})
        connection.execute(
            "UPDATE history.requests SET record=? WHERE request_id=?",
            (_encode(record), fields["request_id"]),
        )
        connection.execute("UPDATE lifetime SET metrics=? WHERE id=1", (_encode(lifetime),))
        if aggregate is not None:
            connection.execute(
                "UPDATE aggregates SET metrics=? WHERE day=? AND model=? AND provider=?",
                (_encode(aggregate), *dimensions),
            )

    @staticmethod
    def _used_pages(connection: sqlite3.Connection, schema: str) -> int:
        return (
            connection.execute(f"PRAGMA {schema}.page_count").fetchone()[0]
            - connection.execute(f"PRAGMA {schema}.freelist_count").fetchone()[0]
        )

    @staticmethod
    def _journal_pages(path: Path) -> int:
        try:
            size = Path(str(path) + "-journal").stat().st_size
        except FileNotFoundError:
            return 0
        return (size + _PAGE_SIZE - 1) // _PAGE_SIZE

    def _reserve(
        self, connection: sqlite3.Connection, batch: list[tuple[str, dict[str, Any], int]]
    ) -> None:
        """Commit retention before writes, then bound both databases' page growth."""
        needed_bytes = 0
        protected: set[tuple[str, str, str]] = set()
        starts = {record["request_id"]: record for kind, record, _ in batch if kind == "start"}
        for kind, record, _ in batch:
            metadata = {
                key: value
                for key, value in record.items()
                if key != "request_body" and key not in PREVIEW_FIELDS
            }
            needed_bytes += len(_encode(metadata).encode("utf-8"))
            if kind == "finish":
                row = connection.execute(
                    "SELECT record FROM pending WHERE request_id=?", (record["request_id"],)
                ).fetchone()
                pending = json.loads(row[0]) if row else starts.get(record["request_id"])
                if pending is None:
                    continue
                pending = {
                    key: value
                    for key, value in pending.items()
                    if key != "request_body" and key not in PREVIEW_FIELDS
                }
                pending.update(metadata)
                pending.setdefault("started_at", time.time())
                day = datetime.fromtimestamp(pending["started_at"], UTC).date().isoformat()
                dimensions = (
                    day,
                    pending.get("model") or "",
                    pending.get("provider") or "",
                )
                protected.add(dimensions)
                row = connection.execute(
                    "SELECT length(CAST(metrics AS BLOB)) FROM aggregates "
                    "WHERE day=? AND model=? AND provider=?",
                    dimensions,
                ).fetchone()
                needed_bytes += row[0] if row else 0
                needed_bytes += len(_encode(pending).encode("utf-8"))
            elif kind == "reprice":
                row = connection.execute(
                    "SELECT record FROM history.requests WHERE request_id=?",
                    (record["request_id"],),
                ).fetchone()
                if row is None:
                    continue
                retained = json.loads(row[0])
                if not _subscription_pricing_eligible(retained):
                    continue
                day = datetime.fromtimestamp(retained["started_at"], UTC).date().isoformat()
                dimensions = (day, retained.get("model") or "", retained.get("provider") or "")
                protected.add(dimensions)
                row = connection.execute(
                    "SELECT length(CAST(metrics AS BLOB)) FROM aggregates "
                    "WHERE day=? AND model=? AND provider=?",
                    dimensions,
                ).fetchone()
                needed_bytes += row[0] if row else 0

        # B-tree splits, overflow pages and the fixed lifetime counter row. Hard
        # SQLite page limits still bound an unusually large record or counter.
        needed_pages = (needed_bytes + _PAGE_SIZE - 1) // _PAGE_SIZE + (4 if batch else 0)

        target = int(self._max_storage_pages * 0.9)
        with connection:
            while (
                self._used_pages(connection, "main")
                + self._used_pages(connection, "history")
                + needed_pages
                > target
            ):
                cursor = connection.execute(
                    "DELETE FROM history.requests WHERE request_id IN "
                    "(SELECT request_id FROM history.requests "
                    "ORDER BY started_at,request_id LIMIT 32)"
                )
                if cursor.rowcount:
                    connection.execute(
                        "UPDATE settings SET value=value+? WHERE key='pruned_requests'",
                        (cursor.rowcount,),
                    )
                    continue
                candidates = connection.execute(
                    "SELECT day,model,provider FROM aggregates ORDER BY day,model,provider LIMIT ?",
                    (len(protected) + 32,),
                ).fetchall()
                removable = [tuple(row) for row in candidates if tuple(row) not in protected]
                if not removable:
                    break
                connection.executemany(
                    "DELETE FROM aggregates WHERE day=? AND model=? AND provider=?", removable
                )
                connection.execute(
                    "UPDATE settings SET value=value+? WHERE key='pruned_aggregate_rows'",
                    (len(removable),),
                )

        main_pages = connection.execute("PRAGMA main.page_count").fetchone()[0]
        history_pages = connection.execute("PRAGMA history.page_count").fetchone()[0]
        history_pages = max(history_pages, self._journal_pages(self.database_path))
        free_pages = connection.execute("PRAGMA main.freelist_count").fetchone()[0]
        stats_limit = min(
            max(
                main_pages + max(0, needed_pages - free_pages),
                self._journal_pages(_stats_path(self.database_path)),
            ),
            self._max_storage_pages - history_pages,
        )
        if stats_limit < main_pages:
            raise sqlite3.OperationalError("History storage budget exhausted by pending metadata")
        history_limit = self._max_storage_pages - stats_limit
        self._set_page_limits(connection, stats_limit, history_limit)

    def _prune(self, connection: sqlite3.Connection, needed: int) -> None:
        while True:
            pages = connection.execute("PRAGMA history.page_count").fetchone()[0]
            free = connection.execute("PRAGMA history.freelist_count").fetchone()[0]
            if (pages - free) * _PAGE_SIZE + needed <= self._detail_target:
                return
            cursor = connection.execute(
                "DELETE FROM history.requests WHERE request_id IN "
                "(SELECT request_id FROM history.requests ORDER BY started_at,request_id LIMIT 32)"
            )
            if not cursor.rowcount:
                return
            connection.execute(
                "UPDATE settings SET value=value+? WHERE key='pruned_requests'", (cursor.rowcount,)
            )

    def _write_detail(self, connection: sqlite3.Connection, record: dict[str, Any]) -> None:
        metadata = {key: value for key, value in record.items() if key != "request_body"}
        encoded = _encode(metadata)
        body = record.get("request_body")
        needed = len(encoded.encode("utf-8")) + len((body or "").encode("utf-8")) + 5 * _PAGE_SIZE
        if needed > self._detail_target // 2:
            metadata.update(
                {
                    "body_truncated": True,
                    "body_omitted_reason": "storage_budget",
                }
            )
            metadata.update(dict.fromkeys(PREVIEW_FIELDS))
            body = None
            encoded = _encode(metadata)
            needed = len(encoded.encode("utf-8")) + 5 * _PAGE_SIZE
        self._prune(connection, needed)
        if needed > self._detail_target:
            return
        connection.execute(
            "INSERT OR REPLACE INTO history.requests"
            "(request_id,thread_id,started_at,record,response_id_hash,request_body) "
            "VALUES (?,?,?,?,?,?)",
            (
                record["request_id"],
                record["thread_id"],
                record["started_at"],
                encoded,
                record.get("response_id_hash"),
                body,
            ),
        )


class HistoryReader:
    """Read-only connections opened per query; constructing or reading never creates files."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path).expanduser()

    def _connect(self, path: Path) -> sqlite3.Connection | None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        try:
            _validate_file(fd)
            _validate_directory(path.parent)
        finally:
            os.close(fd)
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _pagination(limit: int, offset: int) -> tuple[int, int]:
        return max(1, min(int(limit), 200)), max(0, int(offset))

    @staticmethod
    def _traffic_condition(traffic: str, record: str = "record") -> str:
        if traffic not in ("all", "inference"):
            raise ValueError("traffic must be 'all' or 'inference'")
        if traffic == "all":
            return "1"
        methods = ",".join(f"'{method}'" for method in _NON_INFERENCE_METHODS)
        return (
            f"CASE json_type({record},'$.usage_applicable') "
            "WHEN 'false' THEN 0 WHEN 'true' THEN 1 "
            f"ELSE COALESCE(UPPER(json_extract({record},'$.method')) NOT IN ({methods}),1) END"
        )

    def requests(
        self,
        limit: int = 50,
        offset: int = 0,
        thread_id: str | None = None,
        *,
        traffic: str = "all",
    ) -> dict[str, Any]:
        condition = self._traffic_condition(traffic)
        limit, offset = self._pagination(limit, offset)
        result: dict[str, Any] = {"items": [], "total": 0, "limit": limit, "offset": offset}
        connection = self._connect(self.database_path)
        if connection is None:
            return result
        try:
            where = f" WHERE {condition}" + (" AND thread_id=?" if thread_id is not None else "")
            args = (thread_id,) if thread_id is not None else ()
            result["total"] = connection.execute(
                "SELECT COUNT(*) FROM requests" + where, args
            ).fetchone()[0]
            rows = connection.execute(
                "SELECT record FROM requests"
                + where
                + " ORDER BY started_at DESC,request_id DESC LIMIT ? OFFSET ?",
                (*args, limit, offset),
            )
            for row in rows:
                record = self._record_with_legacy_previews(connection, json.loads(row[0]))
                record.pop("request_body", None)
                result["items"].append(record)
            return result
        finally:
            connection.close()

    def threads(self, limit: int = 50, offset: int = 0, *, traffic: str = "all") -> dict[str, Any]:
        self._traffic_condition(traffic)
        limit, offset = self._pagination(limit, offset)
        result: dict[str, Any] = {"items": [], "total": 0, "limit": limit, "offset": offset}
        connection = self._connect(self.database_path)
        if connection is None:
            return result
        try:
            connection.execute("BEGIN")
            return self._thread_page(connection, limit, offset, traffic=traffic)
        finally:
            connection.close()

    def _thread_page(
        self, connection: sqlite3.Connection, limit: int, offset: int, *, traffic: str = "all"
    ) -> dict[str, Any]:
        condition = self._traffic_condition(traffic)
        result: dict[str, Any] = {
            "items": [],
            "total": connection.execute(
                f"SELECT COUNT(DISTINCT thread_id) FROM requests WHERE {condition}"
            ).fetchone()[0],
            "limit": limit,
            "offset": offset,
        }
        rows = connection.execute(
            f"""SELECT thread_id, MIN(started_at) AS started_at,
                    MAX(started_at) AS last_started_at, COUNT(*) AS requests,
                    MAX(json_extract(record,'$.thread_source')) AS thread_source,
                    SUM(json_extract(record,'$.outcome')='active') AS active_requests,
                    COALESCE(SUM(json_extract(record,'$.redactions')),0) AS redactions,
                    SUM(json_extract(record,'$.duration_ms')) AS duration_ms,
                    SUM(json_extract(record,'$.total_tokens')) AS total_tokens,
                    SUM(json_extract(record,'$.cost_usd')) AS cost_usd,
                    COUNT(json_extract(record,'$.cost_usd')) AS known_cost_requests
                    FROM requests WHERE {condition} GROUP BY thread_id
                    ORDER BY last_started_at DESC,thread_id DESC LIMIT ? OFFSET ?
                """,
            (limit, offset),
        )
        result["items"] = [dict(row) for row in rows]
        for item in result["items"]:
            endpoints = connection.execute(
                f"""SELECT
                        (SELECT record FROM requests WHERE thread_id=? AND {condition}
                         ORDER BY started_at,request_id LIMIT 1) AS first_record,
                        (SELECT record FROM requests WHERE thread_id=? AND {condition}
                         ORDER BY started_at DESC,request_id DESC LIMIT 1) AS latest_record""",
                (item["thread_id"], item["thread_id"]),
            ).fetchone()
            if endpoints is None or endpoints["first_record"] is None:
                item["session_preview"] = None
                continue
            record = self._record_with_legacy_previews(
                connection, json.loads(endpoints["first_record"])
            )
            item["session_preview"] = record.get("session_preview") or record.get("user_preview")
            latest = json.loads(endpoints["latest_record"])
            item["latest_model"] = latest.get("model")
            item["latest_provider"] = latest.get("provider")
            item["latest_outcome"] = latest.get("outcome")
            item["latest_started_at"] = latest.get("started_at")
            item["latest_method"] = latest.get("method")
            item["latest_path"] = latest.get("path")
            item["last_user_preview"] = latest.get("user_preview")
            item["last_assistant_preview"] = latest.get("assistant_preview")
        return result

    def request_location(self, request_id: str, *, traffic: str = "all") -> dict[str, Any] | None:
        condition = self._traffic_condition(traffic)
        connection = self._connect(self.database_path)
        if connection is None:
            return None
        try:
            connection.execute("BEGIN")
            row = connection.execute(
                f"SELECT thread_id,started_at,{condition} AS included "
                "FROM requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                return None
            if not row["included"]:
                traffic = "all"
                condition = self._traffic_condition(traffic)
            thread_id, started_at = row["thread_id"], row["started_at"]
            thread_rank = connection.execute(
                f"""WITH sessions AS (
                       SELECT thread_id,MAX(started_at) AS last_started_at
                       FROM requests WHERE {condition} GROUP BY thread_id)
                   SELECT COUNT(*) FROM sessions
                   WHERE (last_started_at,thread_id)>
                       ((SELECT last_started_at FROM sessions WHERE thread_id=?),?)""",
                (thread_id, thread_id),
            ).fetchone()[0]
            request_rank = connection.execute(
                f"""SELECT COUNT(*) FROM requests WHERE thread_id=? AND {condition}
                   AND (started_at,request_id)>(?,?)""",
                (thread_id, started_at, request_id),
            ).fetchone()[0]
            thread_offset = thread_rank // 50 * 50
            page = self._thread_page(connection, 50, thread_offset, traffic=traffic)
            return {
                "traffic": traffic,
                "thread": next(item for item in page["items"] if item["thread_id"] == thread_id),
                "thread_offset": thread_offset,
                "request_offset": request_rank // 100 * 100,
            }
        finally:
            connection.close()

    def thread_requests(
        self,
        thread_id: str,
        limit: int = 100,
        offset: int = 0,
        order: str = "asc",
        *,
        traffic: str = "all",
    ) -> dict[str, Any]:
        if order not in ("asc", "desc"):
            raise ValueError("order must be 'asc' or 'desc'")
        condition = self._traffic_condition(traffic)
        child_condition = self._traffic_condition(traffic, "child.record")
        parent_condition = self._traffic_condition(traffic, "parent.record")
        limit, offset = self._pagination(limit, offset)
        result: dict[str, Any] = {"items": [], "total": 0, "limit": limit, "offset": offset}
        connection = self._connect(self.database_path)
        if connection is None:
            return result
        try:
            connection.execute("BEGIN")
            result["total"] = connection.execute(
                f"SELECT COUNT(*) FROM requests WHERE thread_id=? AND {condition}", (thread_id,)
            ).fetchone()[0]
            direction = order.upper()
            rows = connection.execute(
                f"""SELECT child.record,
                    (SELECT parent.request_id FROM requests AS parent INDEXED BY requests_response
                     WHERE parent.thread_id=child.thread_id
                       AND {parent_condition}
                       AND parent.response_id_hash=
                           json_extract(child.record,'$.parent_response_id_hash')
                       AND (parent.started_at,parent.request_id)<(child.started_at,child.request_id)
                     ORDER BY parent.started_at DESC,parent.request_id DESC LIMIT 1)
                    AS parent_request_id
                    FROM requests AS child WHERE child.thread_id=? AND {child_condition}
                    ORDER BY child.started_at {direction},child.request_id {direction}
                    LIMIT ? OFFSET ?""",
                (thread_id, limit, offset),
            )
            for index, row in enumerate(rows):
                record = self._record_with_legacy_previews(connection, json.loads(row["record"]))
                record.pop("request_body", None)
                record["ordinal"] = (
                    offset + index + 1 if order == "asc" else result["total"] - offset - index
                )
                record["parent_request_id"] = row["parent_request_id"]
                result["items"].append(record)
            return result
        finally:
            connection.close()

    def request(self, request_id: str) -> dict[str, Any] | None:
        connection = self._connect(self.database_path)
        if connection is None:
            return None
        try:
            row = connection.execute(
                "SELECT record,request_body FROM requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if row is None:
                return None
            record = self._record_with_legacy_previews(connection, json.loads(row[0]), row[1])
            record["request_body"] = row[1]
            return record
        finally:
            connection.close()

    def subscription_pricing_candidates(
        self, limit: int = 100, *, before: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        limit, _ = self._pagination(limit, 0)
        cursor = ""
        args: tuple[Any, ...] = ()
        if before is not None:
            started_at, request_id = before.get("started_at"), before.get("request_id")
            if (
                not isinstance(started_at, (int, float))
                or isinstance(started_at, bool)
                or not isinstance(request_id, str)
            ):
                raise ValueError("before requires started_at and request_id")
            try:
                valid_time = math.isfinite(float(started_at))
            except OverflowError:
                valid_time = False
            if not valid_time:
                raise ValueError("before requires finite started_at")
            cursor = " AND (started_at,request_id)<(?,?)"
            args = (started_at, request_id)
        result: dict[str, Any] = {"items": [], "next_cursor": None}
        connection = self._connect(self.database_path)
        if connection is None:
            return result
        try:
            outcomes = ",".join(f"'{outcome}'" for outcome in sorted(_FINAL_OUTCOMES))
            blocked = ",".join(f"'{reason}'" for reason in _REPRICE_BLOCKED_REASONS)
            columns = ",".join(
                f"json_extract(record,'$.{key}') AS {key}" for key in _PRICING_CANDIDATE_FIELDS
            )
            booleans = ("usage_applicable", "metrics_incomplete", "unsupported_costs")
            types = ",".join(f"json_type(record,'$.{key}') AS {key}_type" for key in booleans)
            condition = self._traffic_condition("inference")
            rows = connection.execute(
                f"""SELECT request_id,started_at,{columns},{types} FROM requests
                    WHERE json_extract(record,'$.provider')='chatgpt'
                      AND json_extract(record,'$.cost_usd') IS NULL
                      AND json_extract(record,'$.outcome') IN ({outcomes})
                      AND COALESCE(json_extract(record,'$.metrics_incomplete'),0)=0
                      AND COALESCE(json_extract(record,'$.unsupported_costs'),0)=0
                      AND COALESCE(json_extract(record,'$.cost_unavailable_reason'),'')
                          NOT IN ({blocked})
                      AND json_type(record,'$.input_tokens')='integer'
                      AND json_extract(record,'$.input_tokens')>=0
                      AND json_type(record,'$.output_tokens')='integer'
                      AND json_extract(record,'$.output_tokens')>=0
                      AND (json_extract(record,'$.cached_input_tokens') IS NULL OR
                           (json_type(record,'$.cached_input_tokens')='integer' AND
                            json_extract(record,'$.cached_input_tokens')>=0))
                      AND (json_extract(record,'$.cache_write_tokens') IS NULL OR
                           (json_type(record,'$.cache_write_tokens')='integer' AND
                            json_extract(record,'$.cache_write_tokens')>=0))
                      AND COALESCE(json_extract(record,'$.cached_input_tokens'),0)+
                          COALESCE(json_extract(record,'$.cache_write_tokens'),0)<=
                          json_extract(record,'$.input_tokens')
                      AND {condition}{cursor}
                    ORDER BY started_at DESC,request_id DESC LIMIT ?""",
                (*args, limit + 1),
            ).fetchall()
            for row in rows[:limit]:
                record = dict(row)
                for key in booleans:
                    kind = record.pop(key + "_type")
                    if kind in ("true", "false"):
                        record[key] = kind == "true"
                result["items"].append(record)
            if len(rows) > limit:
                last = rows[limit - 1]
                result["next_cursor"] = {
                    "started_at": last["started_at"],
                    "request_id": last["request_id"],
                }
            return result
        finally:
            connection.close()

    @staticmethod
    def _record_with_legacy_previews(
        connection: sqlite3.Connection, record: dict[str, Any], body: str | None = None
    ) -> dict[str, Any]:
        if (
            not isinstance(record.get("usage_applicable"), bool)
            and isinstance(record.get("method"), str)
            and record["method"].upper() in _NON_INFERENCE_METHODS
        ):
            record["usage_applicable"] = False
        if any(key in record for key in PREVIEW_FIELDS):
            return record
        if body is None:
            row = connection.execute(
                "SELECT substr(request_body,1,?) FROM requests WHERE request_id=?",
                (MAX_LEGACY_BODY_BYTES + 1, record.get("request_id")),
            ).fetchone()
            body = row[0] if row else None
        record.update(legacy_request_previews(record, body))
        return record

    def thread_for_response(self, response_id_hash: str) -> str | None:
        connection = self._connect(self.database_path)
        if connection is None:
            return None
        try:
            row = connection.execute(
                "SELECT thread_id FROM requests WHERE response_id_hash=? "
                "ORDER BY started_at DESC LIMIT 1",
                (response_id_hash,),
            ).fetchone()
            return row[0] if row else None
        finally:
            connection.close()

    def summary(self, days: int = 30) -> dict[str, Any]:
        days = max(1, min(int(days), 36500))
        result: dict[str, Any] = {
            "days": days,
            "totals": _public_metrics(_empty_metrics()),
            "lifetime_totals": _public_metrics(_empty_metrics()),
            "daily": [],
            "models": [],
            "storage": {
                "detail_bytes": _file_bytes(self.database_path),
                "stats_bytes": _file_bytes(_stats_path(self.database_path)),
                "retained_requests": 0,
                "active_requests": 0,
                "max_database_bytes": None,
                "max_body_bytes": None,
                "dropped_writes": 0,
                "write_errors": 0,
                "pruned_requests": 0,
                "pruned_aggregate_rows": 0,
            },
        }
        result["storage"]["total_bytes"] = (
            result["storage"]["detail_bytes"] + result["storage"]["stats_bytes"]
        )
        detail = self._connect(self.database_path)
        if detail:
            try:
                result["storage"]["retained_requests"] = detail.execute(
                    "SELECT COUNT(*) FROM requests"
                ).fetchone()[0]
            finally:
                detail.close()
        connection = self._connect(_stats_path(self.database_path))
        if connection is None:
            return result
        try:
            result["storage"]["active_requests"] = connection.execute(
                "SELECT COUNT(*) FROM pending"
            ).fetchone()[0]
            result["storage"].update(dict(connection.execute("SELECT key,value FROM settings")))
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifetime'"
            ).fetchone():
                row = connection.execute("SELECT metrics FROM lifetime WHERE id=1").fetchone()
                if row:
                    result["lifetime_totals"] = _public_metrics(_load_metrics(row[0]))
            since = (datetime.now(UTC).date() - timedelta(days=days - 1)).isoformat()
            rows = connection.execute(
                "SELECT day,model,provider,metrics FROM aggregates WHERE day>=? ORDER BY day",
                (since,),
            )
            total = _empty_metrics()
            daily: dict[str, dict[str, Any]] = {}
            models: dict[tuple[str, str], dict[str, Any]] = {}
            for row in rows:
                metrics = _load_metrics(row["metrics"])
                _merge_metrics(total, metrics)
                _merge_metrics(daily.setdefault(row["day"], _empty_metrics()), metrics)
                key = (row["model"], row["provider"])
                _merge_metrics(models.setdefault(key, _empty_metrics()), metrics)
            result["totals"] = _public_metrics(total)
            result["daily"] = [
                {"day": day, **_public_metrics(metrics)} for day, metrics in daily.items()
            ]
            result["models"] = [
                {"model": model or None, "provider": provider or None, **_public_metrics(metrics)}
                for (model, provider), metrics in models.items()
            ]
            return result
        finally:
            connection.close()
