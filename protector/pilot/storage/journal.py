"""Bounded on-disk SQLite WAL spool for control-plane outage recovery."""

from __future__ import annotations

import errno
import json
import math
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from sqlalchemy.exc import (
    DataError,
    DBAPIError,
    IntegrityError,
    OperationalError,
    ProgrammingError,
)

from protector.pilot.domain import CandidateEventV1

JournalKind = Literal["candidate_event", "evidence"]
SUPPORTED_JOURNAL_SCHEMA_VERSIONS: dict[JournalKind, str] = {
    "candidate_event": "candidate-event.v1",
    "evidence": "evidence-work.v1",
}
_EVIDENCE_METADATA_FIELDS = frozenset(
    {
        "schema_version",
        "evidence_id",
        "event_id",
        "object_key",
        "sha256",
        "codec",
        "start_at",
        "end_at",
        "source_reference",
        "status",
    }
)


def validate_journal_work(
    kind: JournalKind,
    schema_version: str,
    payload: dict[str, Any],
) -> None:
    expected_version = SUPPORTED_JOURNAL_SCHEMA_VERSIONS[kind]
    if schema_version != expected_version:
        raise ValueError(f"unsupported journal schema version for {kind}: {schema_version}")
    if payload.get("schema_version") != schema_version:
        raise ValueError("journal schema version does not match payload")


class JournalFullError(RuntimeError):
    """The bounded spool is full; callers must enter a visible degraded state."""


class JournalPayloadConflictError(ValueError):
    """An idempotency key was reused for a different journal payload."""


def is_retryable_database_error(error: BaseException) -> bool:
    """Recognise connection/availability failures without retrying bad data or SQL."""
    if isinstance(error, (IntegrityError, DataError, ProgrammingError)):
        return False
    if isinstance(error, sqlite3.OperationalError):
        message = str(error).lower()
        return any(
            marker in message
            for marker in (
                "database is locked",
                "database is busy",
                "unable to open database file",
            )
        )
    if isinstance(error, OSError) and not isinstance(error, DBAPIError):
        retryable_errno = {
            getattr(errno, name)
            for name in (
                "EAGAIN",
                "EBUSY",
                "ECONNABORTED",
                "ECONNREFUSED",
                "ECONNRESET",
                "ENETDOWN",
                "ENETUNREACH",
                "ETIMEDOUT",
            )
        }
        message = str(error).lower()
        return error.errno in retryable_errno or any(
            marker in message
            for marker in (
                "database unavailable",
                "database is locked",
                "database is busy",
                "connection refused",
                "connection reset",
                "connection timed out",
            )
        )
    if not isinstance(error, DBAPIError):
        return False
    if error.connection_invalidated:
        return True
    original = error.orig
    sqlstate = (
        getattr(original, "sqlstate", None)
        or getattr(original, "pgcode", None)
        or ""
    )
    if str(sqlstate).startswith("08") or str(sqlstate) in {
        "40001",
        "40P01",
        "55P03",
        "57P01",
        "57P02",
        "57P03",
    }:
        return True
    message = str(original).lower()
    if isinstance(error, OperationalError):
        return any(
            marker in message
            for marker in (
                "database is locked",
                "database is busy",
                "unable to open database file",
                "connection refused",
                "could not connect",
                "connection is closed",
                "server closed the connection",
                "terminating connection",
                "connection timed out",
            )
        )
    return False


@dataclass(frozen=True, slots=True)
class JournalItem:
    item_id: int
    kind: JournalKind
    schema_version: str
    idempotency_key: str
    payload: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class EvidenceJournalReplayStatus:
    depth: int
    quarantine_depth: int
    degraded: bool
    last_error: str | None
    processed_total: int
    retry_attempts_total: int
    next_retry_in_seconds: float | None


class SQLiteWALJournal:
    """Durable crash spool; successful processors must commit before returning."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_items: int,
        max_payload_bytes: int = 1_000_000,
        max_quarantine_items: int | None = None,
    ) -> None:
        if max_items < 1:
            raise ValueError("max_items must be positive")
        if max_payload_bytes < 1:
            raise ValueError("max_payload_bytes must be positive")
        if max_quarantine_items is not None and max_quarantine_items < 1:
            raise ValueError("max_quarantine_items must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_items = max_items
        self.max_payload_bytes = max_payload_bytes
        self.max_quarantine_items = max_quarantine_items or max_items
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout=5000")
        mode = self._connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        self.journal_mode = str(mode).lower()
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS journal_items (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL CHECK (kind IN ('candidate_event', 'evidence')),
                schema_version TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS journal_quarantine (
                quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_item_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                error_type TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                UNIQUE(original_item_id, idempotency_key)
            )
            """
        )
        self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> SQLiteWALJournal:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def enqueue_event(self, event: CandidateEventV1) -> JournalItem:
        return self.enqueue(
            kind="candidate_event",
            schema_version=event.schema_version,
            idempotency_key=event.dedupe_key,
            payload=event.model_dump(mode="json"),
        )

    def enqueue(
        self,
        *,
        kind: JournalKind,
        schema_version: str,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> JournalItem:
        if not schema_version or not idempotency_key:
            raise ValueError("schema_version and idempotency_key must be non-empty")
        validate_journal_work(kind, schema_version, payload)
        if kind == "evidence" and not set(payload) <= _EVIDENCE_METADATA_FIELDS:
            raise ValueError("evidence journal payload must contain metadata only")
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(payload_json.encode("utf-8")) > self.max_payload_bytes:
            raise ValueError(f"journal payload exceeds {self.max_payload_bytes} bytes")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    """
                    SELECT item_id, kind, schema_version, idempotency_key, payload_json, created_at
                    FROM journal_items WHERE idempotency_key = ?
                    """,
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["kind"] != kind
                        or existing["schema_version"] != schema_version
                        or existing["payload_json"] != payload_json
                    ):
                        raise JournalPayloadConflictError(
                            "journal idempotency key was reused with different data"
                        )
                    self._connection.commit()
                    return self._row_to_item(existing)
                count = self._connection.execute("SELECT count(*) FROM journal_items").fetchone()[0]
                if count >= self.max_items:
                    raise JournalFullError(f"journal capacity {self.max_items} reached")
                created_at = datetime.now(timezone.utc).isoformat()
                cursor = self._connection.execute(
                    """
                    INSERT INTO journal_items
                        (kind, schema_version, idempotency_key, payload_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (kind, schema_version, idempotency_key, payload_json, created_at),
                )
                item_id = int(cursor.lastrowid)
                self._connection.commit()
                return JournalItem(
                    item_id=item_id,
                    kind=kind,
                    schema_version=schema_version,
                    idempotency_key=idempotency_key,
                    payload=json.loads(payload_json),
                    created_at=datetime.fromisoformat(created_at),
                )
            except BaseException:
                self._connection.rollback()
                raise

    def depth(self) -> int:
        with self._lock:
            return int(self._connection.execute("SELECT count(*) FROM journal_items").fetchone()[0])

    def quarantine_depth(self) -> int:
        with self._lock:
            return int(
                self._connection.execute(
                    "SELECT count(*) FROM journal_quarantine"
                ).fetchone()[0]
            )

    def items(self, *, limit: int) -> tuple[JournalItem, ...]:
        if limit < 1:
            raise ValueError("limit must be positive")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT item_id, kind, schema_version, idempotency_key,
                       payload_json, created_at
                FROM journal_items ORDER BY item_id LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(self._row_to_item(row) for row in rows)

    def acknowledge(self, item_id: int) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM journal_items WHERE item_id = ?",
                (item_id,),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def quarantine(self, item: JournalItem, *, error_type: str) -> None:
        safe_error_type = error_type[:128] or "ReplayError"
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT item_id, kind, schema_version, idempotency_key,
                           payload_json, created_at
                    FROM journal_items WHERE item_id = ?
                    """,
                    (item.item_id,),
                ).fetchone()
                if row is None:
                    self._connection.commit()
                    return
                count = self._connection.execute(
                    "SELECT count(*) FROM journal_quarantine"
                ).fetchone()[0]
                if count >= self.max_quarantine_items:
                    raise JournalFullError(
                        f"journal quarantine capacity {self.max_quarantine_items} reached"
                    )
                self._connection.execute(
                    """
                    INSERT INTO journal_quarantine
                        (original_item_id, kind, schema_version, idempotency_key,
                         payload_json, created_at, error_type, quarantined_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["item_id"],
                        row["kind"],
                        row["schema_version"],
                        row["idempotency_key"],
                        row["payload_json"],
                        row["created_at"],
                        safe_error_type,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                self._connection.execute(
                    "DELETE FROM journal_items WHERE item_id = ?",
                    (item.item_id,),
                )
                self._connection.commit()
            except BaseException:
                self._connection.rollback()
                raise

    def replay(
        self,
        processor: Callable[[JournalItem], None],
        *,
        limit: int | None = None,
    ) -> int:
        """Process oldest-first and acknowledge only after the processor returns."""
        if limit is not None and limit < 1:
            raise ValueError("limit must be positive")
        query = """
            SELECT item_id, kind, schema_version, idempotency_key, payload_json, created_at
            FROM journal_items ORDER BY item_id
        """
        parameters: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            parameters = (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        acknowledged = 0
        for row in rows:
            item = self._row_to_item(row)
            validate_journal_work(item.kind, item.schema_version, item.payload)
            processor(item)
            self.acknowledge(item.item_id)
            acknowledged += 1
        return acknowledged

    @staticmethod
    def _row_to_item(row: sqlite3.Row) -> JournalItem:
        malformed = False
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError):
            malformed = True
            payload = {"schema_version": "__malformed_json__"}
        if not isinstance(payload, dict):
            malformed = True
            payload = {"schema_version": "__malformed_json__"}
        try:
            created_at = datetime.fromisoformat(row["created_at"])
        except (TypeError, ValueError):
            malformed = True
            created_at = datetime.fromtimestamp(0, timezone.utc)
        if malformed:
            payload = {"schema_version": "__malformed_json__"}
        return JournalItem(
            item_id=int(row["item_id"]),
            kind=row["kind"],
            schema_version=row["schema_version"],
            idempotency_key=row["idempotency_key"],
            payload=payload,
            created_at=created_at,
        )


class EvidenceJournalReplayWorker:
    """Bounded oldest-first replay with retry backoff and durable poison quarantine."""

    def __init__(
        self,
        *,
        journal: SQLiteWALJournal,
        processor: Callable[[JournalItem], None],
        batch_size: int,
        retry_backoff_seconds: float,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        if batch_size < 1:
            raise ValueError("replay batch_size must be positive")
        if (
            not math.isfinite(retry_backoff_seconds)
            or retry_backoff_seconds <= 0
        ):
            raise ValueError("retry_backoff_seconds must be finite and positive")
        self._journal = journal
        self._processor = processor
        self.batch_size = batch_size
        self.retry_backoff_seconds = retry_backoff_seconds
        self._monotonic = monotonic_clock or time.monotonic
        self._processed_total = 0
        self._retry_attempts_total = 0
        self._last_error: str | None = None
        self._retry_at: float | None = None
        self._retry_degraded = False
        self._lock = threading.Lock()

    @property
    def status(self) -> EvidenceJournalReplayStatus:
        now = self._monotonic()
        quarantine_depth = self._journal.quarantine_depth()
        return EvidenceJournalReplayStatus(
            depth=self._journal.depth(),
            quarantine_depth=quarantine_depth,
            degraded=self._retry_degraded or quarantine_depth > 0,
            last_error=self._last_error,
            processed_total=self._processed_total,
            retry_attempts_total=self._retry_attempts_total,
            next_retry_in_seconds=(
                None
                if self._retry_at is None
                else max(0.0, self._retry_at - now)
            ),
        )

    def startup_drain(self) -> int:
        """Drain at most one configured batch during startup."""
        return self._run_batch()

    def run_periodic_batch(self) -> int:
        """Run one finite periodic batch unless retry backoff is still active."""
        return self._run_batch()

    def _run_batch(self) -> int:
        with self._lock:
            now = self._monotonic()
            if self._retry_at is not None and now < self._retry_at:
                return 0
            processed = 0
            for item in self._journal.items(limit=self.batch_size):
                try:
                    validate_journal_work(item.kind, item.schema_version, item.payload)
                    self._processor(item)
                    self._journal.acknowledge(item.item_id)
                except Exception as exc:
                    self._last_error = type(exc).__name__
                    if is_retryable_database_error(exc):
                        self._retry_attempts_total += 1
                        self._retry_degraded = True
                        self._retry_at = now + self.retry_backoff_seconds
                        break
                    try:
                        self._journal.quarantine(
                            item,
                            error_type=type(exc).__name__,
                        )
                    except JournalFullError:
                        self._retry_degraded = True
                        self._retry_at = now + self.retry_backoff_seconds
                        break
                    continue
                processed += 1
                self._processed_total += 1
                self._retry_degraded = False
                self._retry_at = None
            return processed
