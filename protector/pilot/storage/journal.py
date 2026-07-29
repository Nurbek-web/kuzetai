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

JournalKind = Literal["candidate_event", "evidence", "evidence_intent"]
SUPPORTED_JOURNAL_SCHEMA_VERSIONS: dict[JournalKind, str] = {
    "candidate_event": "candidate-event.v1",
    "evidence": "evidence-work.v1",
    "evidence_intent": "evidence-intent.v1",
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
_EVIDENCE_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "evidence_id",
        "event_id",
        "object_key",
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
class PendingEvidenceJournalItem:
    """One finite crash-recovery record outside the replay FIFO."""

    event_id: str
    reservation_id: str
    phase: Literal["seed", "reserved", "active"]
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
                kind TEXT NOT NULL CHECK (
                    kind IN ('candidate_event', 'evidence', 'evidence_intent')
                ),
                schema_version TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        table_sql = self._connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='journal_items'"
        ).fetchone()[0]
        needs_kind_migration = "evidence_intent" not in str(table_sql)
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
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_evidence_work (
                event_id TEXT PRIMARY KEY,
                reservation_id TEXT NOT NULL UNIQUE,
                phase TEXT NOT NULL CHECK (phase IN ('seed', 'reserved', 'active')),
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        pending_table_sql = self._connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type='table' AND name='pending_evidence_work'
            """
        ).fetchone()[0]
        if "'seed'" not in str(pending_table_sql):
            self._migrate_pending_evidence_phase_constraint()
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_evidence_quarantine (
                quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                error_type TEXT NOT NULL,
                quarantined_at TEXT NOT NULL
            )
            """
        )
        self._normalise_candidate_identities(
            rebuild_kind_constraint=needs_kind_migration
        )
        self._connection.commit()

    def _migrate_pending_evidence_phase_constraint(self) -> None:
        """Add the crash-safe seed phase without changing existing rows."""
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute("DROP TABLE IF EXISTS pending_evidence_work_v2")
            self._connection.execute(
                """
                CREATE TABLE pending_evidence_work_v2 (
                    event_id TEXT PRIMARY KEY,
                    reservation_id TEXT NOT NULL UNIQUE,
                    phase TEXT NOT NULL CHECK (
                        phase IN ('seed', 'reserved', 'active')
                    ),
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                INSERT INTO pending_evidence_work_v2
                    (event_id, reservation_id, phase, payload_json, created_at)
                SELECT event_id, reservation_id, phase, payload_json, created_at
                FROM pending_evidence_work
                """
            )
            self._connection.execute("DROP TABLE pending_evidence_work")
            self._connection.execute(
                "ALTER TABLE pending_evidence_work_v2 RENAME TO pending_evidence_work"
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _normalise_candidate_identities(
        self,
        *,
        rebuild_kind_constraint: bool,
    ) -> None:
        """Atomically migrate pre-event-UUID candidate keys and payloads.

        Older pilots derived the queue key without ``event_id`` and also
        serialised that derived value into the JSON payload.  Canonicalising
        both fields before accepting new work lets an exact retry converge
        even when the bounded journal is already full.
        """

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            if rebuild_kind_constraint:
                self._connection.execute("DROP TABLE IF EXISTS journal_items_v2")
                self._connection.execute(
                    """
                    CREATE TABLE journal_items_v2 (
                        item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        kind TEXT NOT NULL CHECK (
                            kind IN ('candidate_event', 'evidence', 'evidence_intent')
                        ),
                        schema_version TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL UNIQUE,
                        payload_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    INSERT INTO journal_items_v2
                        (item_id, kind, schema_version, idempotency_key,
                         payload_json, created_at)
                    SELECT item_id, kind, schema_version, idempotency_key,
                           payload_json, created_at
                    FROM journal_items
                    """
                )
                self._connection.execute("DROP TABLE journal_items")
                self._connection.execute(
                    "ALTER TABLE journal_items_v2 RENAME TO journal_items"
                )
            rows = self._connection.execute(
                """
                SELECT item_id, idempotency_key, payload_json
                FROM journal_items
                WHERE kind = 'candidate_event'
                ORDER BY item_id
                """
            ).fetchall()
            groups: dict[str, list[tuple[sqlite3.Row, str]]] = {}
            raw_key_owners: dict[str, int] = {}
            for row in rows:
                raw_key_owners[str(row["idempotency_key"])] = int(row["item_id"])
                try:
                    event = CandidateEventV1.model_validate_json(row["payload_json"])
                except (TypeError, ValueError):
                    # Poison work is handled by the bounded replay quarantine.
                    continue
                canonical_json = json.dumps(
                    event.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                groups.setdefault(event.dedupe_key, []).append((row, canonical_json))

            for canonical_key, entries in groups.items():
                owner_id = raw_key_owners.get(canonical_key)
                entry_ids = {int(row["item_id"]) for row, _payload in entries}
                if owner_id is not None and owner_id not in entry_ids:
                    raise JournalPayloadConflictError(
                        "candidate journal migration found a material key conflict"
                    )
                if len({payload for _row, payload in entries}) != 1:
                    raise JournalPayloadConflictError(
                        "candidate journal migration found conflicting payloads"
                    )

            canonical_rows: list[tuple[int, str, str]] = []
            duplicate_ids: list[int] = []
            for canonical_key, entries in groups.items():
                canonical_row, canonical_payload = entries[0]
                canonical_rows.append(
                    (
                        int(canonical_row["item_id"]),
                        canonical_key,
                        canonical_payload,
                    )
                )
                duplicate_ids.extend(
                    int(row["item_id"]) for row, _payload in entries[1:]
                )

            if duplicate_ids:
                self._connection.executemany(
                    "DELETE FROM journal_items WHERE item_id = ?",
                    ((item_id,) for item_id in duplicate_ids),
                )
            self._connection.executemany(
                """
                UPDATE journal_items
                SET idempotency_key = ?, payload_json = ?
                WHERE item_id = ?
                """,
                (
                    (canonical_key, canonical_payload, item_id)
                    for item_id, canonical_key, canonical_payload in canonical_rows
                ),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

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

    def seed_pending_evidence_work(
        self,
        *,
        event_id: str,
        reservation_id: str,
        payload: dict[str, Any],
    ) -> PendingEvidenceJournalItem:
        """Persist recovery identity before candidate replay or fragment pinning."""
        if not event_id or not reservation_id:
            raise ValueError("pending evidence identities must be non-empty")
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(payload_json.encode("utf-8")) > self.max_payload_bytes:
            raise ValueError(
                f"pending evidence payload exceeds {self.max_payload_bytes} bytes"
            )
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    """
                    SELECT event_id, reservation_id, phase, payload_json, created_at
                    FROM pending_evidence_work WHERE event_id = ? OR reservation_id = ?
                    """,
                    (event_id, reservation_id),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["event_id"] != event_id
                        or existing["reservation_id"] != reservation_id
                        or (
                            existing["phase"] == "seed"
                            and existing["payload_json"] != payload_json
                        )
                    ):
                        raise JournalPayloadConflictError(
                            "pending evidence seed identity was reused with different data"
                        )
                    self._connection.commit()
                    return self._row_to_pending_evidence(existing)
                count = self._connection.execute(
                    "SELECT count(*) FROM pending_evidence_work"
                ).fetchone()[0]
                if count >= self.max_items:
                    raise JournalFullError(
                        f"pending evidence capacity {self.max_items} reached"
                    )
                self._connection.execute(
                    """
                    INSERT INTO pending_evidence_work
                        (event_id, reservation_id, phase, payload_json, created_at)
                    VALUES (?, ?, 'seed', ?, ?)
                    """,
                    (event_id, reservation_id, payload_json, created_at),
                )
                row = self._connection.execute(
                    """
                    SELECT event_id, reservation_id, phase, payload_json, created_at
                    FROM pending_evidence_work WHERE event_id = ?
                    """,
                    (event_id,),
                ).fetchone()
                self._connection.commit()
                assert row is not None
                return self._row_to_pending_evidence(row)
            except BaseException:
                self._connection.rollback()
                raise

    def reserve_pending_evidence_work(
        self,
        *,
        event_id: str,
        reservation_id: str,
        payload: dict[str, Any],
    ) -> PendingEvidenceJournalItem:
        """Persist immutable lifecycle identity before preview work begins."""
        if not event_id or not reservation_id:
            raise ValueError("pending evidence identities must be non-empty")
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(payload_json.encode("utf-8")) > self.max_payload_bytes:
            raise ValueError(
                f"pending evidence payload exceeds {self.max_payload_bytes} bytes"
            )
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    """
                    SELECT event_id, reservation_id, phase, payload_json, created_at
                    FROM pending_evidence_work WHERE event_id = ? OR reservation_id = ?
                    """,
                    (event_id, reservation_id),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["event_id"] != event_id
                        or existing["reservation_id"] != reservation_id
                    ):
                        raise JournalPayloadConflictError(
                            "pending evidence identity was reused with different data"
                        )
                    if existing["phase"] == "seed":
                        self._connection.execute(
                            """
                            UPDATE pending_evidence_work
                            SET phase = 'reserved', payload_json = ?
                            WHERE event_id = ? AND reservation_id = ? AND phase = 'seed'
                            """,
                            (payload_json, event_id, reservation_id),
                        )
                        existing = self._connection.execute(
                            """
                            SELECT event_id, reservation_id, phase, payload_json, created_at
                            FROM pending_evidence_work WHERE event_id = ?
                            """,
                            (event_id,),
                        ).fetchone()
                    elif existing["payload_json"] != payload_json:
                        raise JournalPayloadConflictError(
                            "pending evidence identity was reused with different data"
                        )
                    self._connection.commit()
                    assert existing is not None
                    return self._row_to_pending_evidence(existing)
                count = self._connection.execute(
                    "SELECT count(*) FROM pending_evidence_work"
                ).fetchone()[0]
                if count >= self.max_items:
                    raise JournalFullError(
                        f"pending evidence capacity {self.max_items} reached"
                    )
                self._connection.execute(
                    """
                    INSERT INTO pending_evidence_work
                        (event_id, reservation_id, phase, payload_json, created_at)
                    VALUES (?, ?, 'reserved', ?, ?)
                    """,
                    (event_id, reservation_id, payload_json, created_at),
                )
                row = self._connection.execute(
                    """
                    SELECT event_id, reservation_id, phase, payload_json, created_at
                    FROM pending_evidence_work WHERE event_id = ?
                    """,
                    (event_id,),
                ).fetchone()
                self._connection.commit()
                assert row is not None
                return self._row_to_pending_evidence(row)
            except BaseException:
                self._connection.rollback()
                raise

    def activate_pending_evidence_work(
        self,
        *,
        event_id: str,
        reservation_id: str,
        payload: dict[str, Any],
    ) -> PendingEvidenceJournalItem:
        """Atomically publish one exact persisted record to the periodic drain."""
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(payload_json.encode("utf-8")) > self.max_payload_bytes:
            raise ValueError(
                f"pending evidence payload exceeds {self.max_payload_bytes} bytes"
            )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT event_id, reservation_id, phase, payload_json, created_at
                    FROM pending_evidence_work WHERE event_id = ?
                    """,
                    (event_id,),
                ).fetchone()
                if row is None or row["reservation_id"] != reservation_id:
                    raise JournalPayloadConflictError(
                        "pending evidence activation identity changed"
                    )
                if row["phase"] == "reserved":
                    self._connection.execute(
                        """
                        UPDATE pending_evidence_work
                        SET phase = 'active', payload_json = ?
                        WHERE event_id = ? AND reservation_id = ? AND phase = 'reserved'
                        """,
                        (payload_json, event_id, reservation_id),
                    )
                    row = self._connection.execute(
                        """
                        SELECT event_id, reservation_id, phase, payload_json, created_at
                        FROM pending_evidence_work WHERE event_id = ?
                        """,
                        (event_id,),
                    ).fetchone()
                elif row["payload_json"] != payload_json:
                    raise JournalPayloadConflictError(
                        "active pending evidence payload changed"
                    )
                self._connection.commit()
                assert row is not None
                return self._row_to_pending_evidence(row)
            except BaseException:
                self._connection.rollback()
                raise

    def pending_evidence_work_items(
        self,
        *,
        limit: int,
    ) -> tuple[PendingEvidenceJournalItem, ...]:
        if limit < 1:
            raise ValueError("limit must be positive")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT event_id, reservation_id, phase, payload_json, created_at
                FROM pending_evidence_work ORDER BY created_at, event_id LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(self._row_to_pending_evidence(row) for row in rows)

    def acknowledge_pending_evidence_work(
        self,
        *,
        event_id: str,
        reservation_id: str,
    ) -> bool:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT event_id, reservation_id
                    FROM pending_evidence_work
                    WHERE event_id = ? OR reservation_id = ?
                    """,
                    (event_id, reservation_id),
                ).fetchone()
                if row is None:
                    self._connection.commit()
                    return True
                if (
                    row["event_id"] != event_id
                    or row["reservation_id"] != reservation_id
                ):
                    self._connection.rollback()
                    return False
                cursor = self._connection.execute(
                    """
                    DELETE FROM pending_evidence_work
                    WHERE event_id = ? AND reservation_id = ?
                    """,
                    (event_id, reservation_id),
                )
                self._connection.commit()
                return cursor.rowcount == 1
            except BaseException:
                self._connection.rollback()
                raise

    def pending_evidence_work_depth(self) -> int:
        with self._lock:
            return int(
                self._connection.execute(
                    "SELECT count(*) FROM pending_evidence_work"
                ).fetchone()[0]
            )

    def candidate_events_without_pending_evidence(self) -> int:
        """Count valid candidate rows that have no crash-recovery seed."""
        return len(self.candidate_items_without_pending_evidence())

    def candidate_items_without_pending_evidence(self) -> tuple[JournalItem, ...]:
        """Return bounded candidate metadata that cannot safely create evidence."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT item_id, kind, schema_version, idempotency_key,
                       payload_json, created_at
                FROM journal_items
                WHERE kind = 'candidate_event'
                ORDER BY item_id
                """
            ).fetchall()
            pending_ids = {
                str(row["event_id"])
                for row in self._connection.execute(
                    "SELECT event_id FROM pending_evidence_work"
                ).fetchall()
            }
        missing: list[JournalItem] = []
        for row in rows:
            try:
                event = CandidateEventV1.model_validate_json(row["payload_json"])
            except (TypeError, ValueError):
                continue
            if str(event.event_id) not in pending_ids:
                missing.append(self._row_to_item(row))
        return tuple(missing)

    def quarantine_pending_evidence_work(
        self,
        *,
        event_id: str,
        reservation_id: str,
        error_type: str,
    ) -> bool:
        """Move poison lifecycle work out of the active finite-capacity table."""
        safe_error_type = error_type[:128] or "RecoveryError"
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT event_id, reservation_id, phase, payload_json, created_at
                    FROM pending_evidence_work
                    WHERE event_id = ? AND reservation_id = ?
                    """,
                    (event_id, reservation_id),
                ).fetchone()
                if row is None:
                    self._connection.commit()
                    return False
                count = self._connection.execute(
                    "SELECT count(*) FROM pending_evidence_quarantine"
                ).fetchone()[0]
                if count >= self.max_quarantine_items:
                    raise JournalFullError(
                        "pending evidence quarantine capacity "
                        f"{self.max_quarantine_items} reached"
                    )
                self._connection.execute(
                    """
                    INSERT INTO pending_evidence_quarantine
                        (event_id, reservation_id, phase, payload_json, created_at,
                         error_type, quarantined_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["event_id"],
                        row["reservation_id"],
                        row["phase"],
                        row["payload_json"],
                        row["created_at"],
                        safe_error_type,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                self._connection.execute(
                    """
                    DELETE FROM pending_evidence_work
                    WHERE event_id = ? AND reservation_id = ?
                    """,
                    (event_id, reservation_id),
                )
                self._connection.commit()
                return True
            except BaseException:
                self._connection.rollback()
                raise

    def pending_evidence_quarantine_depth(self) -> int:
        with self._lock:
            return int(
                self._connection.execute(
                    "SELECT count(*) FROM pending_evidence_quarantine"
                ).fetchone()[0]
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
        if kind == "evidence_intent" and not set(payload) <= _EVIDENCE_INTENT_FIELDS:
            raise ValueError("evidence-intent journal payload must contain metadata only")
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

    def replay_items(
        self,
        *,
        limit: int,
        excluded_item_ids: frozenset[int] = frozenset(),
    ) -> tuple[JournalItem, ...]:
        """Return the oldest eligible finite replay batch."""
        if limit < 1:
            raise ValueError("limit must be positive")
        if len(excluded_item_ids) > self.max_items:
            raise ValueError("excluded item IDs exceed journal capacity")
        if any(item_id < 1 for item_id in excluded_item_ids):
            raise ValueError("excluded item IDs must be positive")
        query = """
            SELECT item_id, kind, schema_version, idempotency_key,
                   payload_json, created_at
            FROM journal_items
        """
        parameters: tuple[Any, ...] = ()
        if excluded_item_ids:
            ordered_ids = tuple(sorted(excluded_item_ids))
            placeholders = ",".join("?" for _ in ordered_ids)
            query += f" WHERE item_id NOT IN ({placeholders})"
            parameters = ordered_ids
        query += " ORDER BY item_id LIMIT ?"
        parameters += (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
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

    @staticmethod
    def _row_to_pending_evidence(
        row: sqlite3.Row,
    ) -> PendingEvidenceJournalItem:
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
        return PendingEvidenceJournalItem(
            event_id=str(row["event_id"]),
            reservation_id=str(row["reservation_id"]),
            phase=row["phase"],
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

    def startup_drain(
        self,
        *,
        excluded_item_ids: frozenset[int] = frozenset(),
    ) -> int:
        """Drain at most one configured batch during startup."""
        return self._run_batch(excluded_item_ids=excluded_item_ids)

    def run_periodic_batch(
        self,
        *,
        excluded_item_ids: frozenset[int] = frozenset(),
    ) -> int:
        """Run one finite periodic batch unless retry backoff is still active."""
        return self._run_batch(excluded_item_ids=excluded_item_ids)

    def _run_batch(
        self,
        *,
        excluded_item_ids: frozenset[int],
    ) -> int:
        with self._lock:
            now = self._monotonic()
            if self._retry_at is not None and now < self._retry_at:
                return 0
            processed = 0
            for item in self._journal.replay_items(
                limit=self.batch_size,
                excluded_item_ids=excluded_item_ids,
            ):
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
