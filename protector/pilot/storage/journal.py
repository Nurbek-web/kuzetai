"""Bounded on-disk SQLite WAL spool for control-plane outage recovery."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

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


@dataclass(frozen=True)
class JournalItem:
    item_id: int
    kind: JournalKind
    schema_version: str
    idempotency_key: str
    payload: dict[str, Any]
    created_at: datetime


class SQLiteWALJournal:
    """Durable crash spool; successful processors must commit before returning."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_items: int,
        max_payload_bytes: int = 1_000_000,
    ) -> None:
        if max_items < 1:
            raise ValueError("max_items must be positive")
        if max_payload_bytes < 1:
            raise ValueError("max_payload_bytes must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_items = max_items
        self.max_payload_bytes = max_payload_bytes
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
            with self._lock:
                self._connection.execute(
                    "DELETE FROM journal_items WHERE item_id = ?", (item.item_id,)
                )
                self._connection.commit()
            acknowledged += 1
        return acknowledged

    @staticmethod
    def _row_to_item(row: sqlite3.Row) -> JournalItem:
        return JournalItem(
            item_id=int(row["item_id"]),
            kind=row["kind"],
            schema_version=row["schema_version"],
            idempotency_key=row["idempotency_key"],
            payload=json.loads(row["payload_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )
