from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, OperationalError

from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.journal import (
    EvidenceJournalReplayWorker,
    JournalFullError,
    JournalPayloadConflictError,
    SQLiteWALJournal,
    is_retryable_database_error,
)
from protector.pilot.storage.models import Base, CandidateEventModel
from protector.pilot.storage.repositories import EvidenceIntent, PilotRepository

UTC = timezone.utc
NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)


def _event() -> CandidateEventV1:
    return CandidateEventV1(
        schema_version="candidate-event.v1",
        event_id=uuid4(),
        camera_id="cam-01",
        module="person",
        opened_at=NOW,
        last_seen_at=NOW + timedelta(seconds=2),
        peak_confidence=0.91,
        reason="restricted zone intrusion",
        model_artifact_id="person-v1",
        gate_mode="operator",
        evidence_status="pending",
        review_status="candidate",
    )


def _repository() -> PilotRepository:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    repo = PilotRepository(create_session_factory(engine))
    repo.add_site(site_id="site-1", name="Pilot School")
    repo.add_camera(
        camera_id="cam-01",
        site_id="site-1",
        name="Entrance",
        source_reference="nvr://camera/01",
        codec="h264",
    )
    repo.add_model_artifact(
        ModelArtifactV1(
            schema_version="model-artifact.v1",
            artifact_id="person-v1",
            sha256="a" * 64,
            source="s3://models/person-v1.onnx",
            commercial_rights=CommercialRightsRecordV1(
                schema_version="commercial-rights.v1",
                record_id="rights-1",
                terms_reference="legal://rights/1",
                commercial_use_approved=True,
            ),
            class_list=("person",),
            preprocessing="letterbox 640x640",
            analytic="person",
        )
    )
    return repo


def test_journal_survives_restart_and_replays_idempotently(tmp_path: Path) -> None:
    path = tmp_path / "runtime-journal.sqlite3"
    item_event = _event()
    first_process = SQLiteWALJournal(path, max_items=10)
    first_process.enqueue_event(item_event)
    first_process.close()

    repository = _repository()
    restarted = SQLiteWALJournal(path, max_items=10)

    def commit_then_crash(item: object) -> None:
        repository.persist_journal_item(item)
        raise RuntimeError("process terminated before journal acknowledgement")

    with pytest.raises(RuntimeError, match="before journal acknowledgement"):
        restarted.replay(commit_then_crash)
    assert restarted.depth() == 1
    with repository.session_factory() as session:
        assert len(session.scalars(select(CandidateEventModel)).all()) == 1
    restarted.close()

    second_restart = SQLiteWALJournal(path, max_items=10)
    assert second_restart.replay(repository.persist_journal_item) == 1
    assert second_restart.depth() == 0
    with repository.session_factory() as session:
        assert len(session.scalars(select(CandidateEventModel)).all()) == 1


def test_journal_migrates_legacy_kind_constraint_without_losing_work(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-kind-constraint.sqlite3"
    event_contract = _event()
    payload_json = json.dumps(
        event_contract.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE journal_items (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL CHECK (kind IN ('candidate_event', 'evidence')),
                schema_version TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO journal_items
                (kind, schema_version, idempotency_key, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "candidate_event",
                event_contract.schema_version,
                event_contract.dedupe_key,
                payload_json,
                NOW.isoformat(),
            ),
        )

    migrated = SQLiteWALJournal(path, max_items=4)
    replayed: list[object] = []

    assert migrated.depth() == 1
    assert migrated.replay(replayed.append) == 1
    assert replayed[0].payload["event_id"] == str(event_contract.event_id)  # type: ignore[attr-defined]
    intent = EvidenceIntent(
        schema_version="evidence-intent.v1",
        evidence_id=uuid4(),
        event_id=event_contract.event_id,
        object_key=f"events/{event_contract.event_id}.mp4",
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=4),
        source_reference="nvr://camera/01",
        status="failed",
    )
    migrated.enqueue(
        kind="evidence_intent",
        schema_version=intent.schema_version,
        idempotency_key=f"evidence-intent:{intent.evidence_id}:failed",
        payload=intent.to_payload(),
    )
    assert migrated.depth() == 1


def test_journal_normalizes_actual_old_candidate_key_and_payload_at_full_capacity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "old-candidate-key.sqlite3"
    event_contract = _event()
    old_key = (
        f"{event_contract.camera_id}:{event_contract.module}:"
        f"{event_contract.model_artifact_id}:{event_contract.opened_at.isoformat()}"
    )
    payload = event_contract.model_dump(mode="json")
    payload["dedupe_key"] = old_key
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE journal_items (
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
        connection.execute(
            """
            INSERT INTO journal_items
                (kind, schema_version, idempotency_key, payload_json, created_at)
            VALUES ('candidate_event', ?, ?, ?, ?)
            """,
            (
                event_contract.schema_version,
                old_key,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                NOW.isoformat(),
            ),
        )

    journal = SQLiteWALJournal(path, max_items=1)
    item = journal.enqueue_event(event_contract)

    assert journal.depth() == 1
    assert item.item_id == 1
    assert item.idempotency_key == event_contract.dedupe_key
    assert item.payload == event_contract.model_dump(mode="json")


def test_journal_candidate_key_migration_converges_exact_duplicates_in_original_order(
    tmp_path: Path,
) -> None:
    path = tmp_path / "duplicate-candidate-keys.sqlite3"
    duplicate = _event()
    later = _event().model_copy(update={"opened_at": NOW + timedelta(seconds=20)})
    old_key = (
        f"{duplicate.camera_id}:{duplicate.module}:"
        f"{duplicate.model_artifact_id}:{duplicate.opened_at.isoformat()}"
    )
    duplicate_payload = duplicate.model_dump(mode="json")
    duplicate_payload["dedupe_key"] = old_key
    rows = (
        (old_key, duplicate_payload),
        (duplicate.dedupe_key, duplicate.model_dump(mode="json")),
        (later.dedupe_key, later.model_dump(mode="json")),
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE journal_items (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO journal_items
                (kind, schema_version, idempotency_key, payload_json, created_at)
            VALUES ('candidate_event', 'candidate-event.v1', ?, ?, ?)
            """,
            [
                (
                    key,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    (NOW + timedelta(seconds=index)).isoformat(),
                )
                for index, (key, payload) in enumerate(rows)
            ],
        )

    journal = SQLiteWALJournal(path, max_items=3)
    items = journal.items(limit=3)

    assert [item.item_id for item in items] == [1, 3]
    assert [item.idempotency_key for item in items] == [
        duplicate.dedupe_key,
        later.dedupe_key,
    ]


def test_journal_candidate_key_migration_rolls_back_on_material_conflict(
    tmp_path: Path,
) -> None:
    path = tmp_path / "conflicting-candidate-keys.sqlite3"
    original = _event()
    conflict = original.model_copy(update={"reason": "different material"})
    old_key = (
        f"{original.camera_id}:{original.module}:"
        f"{original.model_artifact_id}:{original.opened_at.isoformat()}"
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE journal_items (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO journal_items
                (kind, schema_version, idempotency_key, payload_json, created_at)
            VALUES ('candidate_event', 'candidate-event.v1', ?, ?, ?)
            """,
            (
                (
                    old_key,
                    json.dumps(original.model_dump(mode="json"), sort_keys=True),
                    NOW.isoformat(),
                ),
                (
                    original.dedupe_key,
                    json.dumps(conflict.model_dump(mode="json"), sort_keys=True),
                    (NOW + timedelta(seconds=1)).isoformat(),
                ),
            ),
        )

    with pytest.raises(JournalPayloadConflictError, match="migration"):
        SQLiteWALJournal(path, max_items=2)
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT item_id, idempotency_key FROM journal_items ORDER BY item_id"
        ).fetchall()
    assert rows == [(1, old_key), (2, original.dedupe_key)]


def test_terminal_evidence_intent_replay_marks_candidate_failed(
    tmp_path: Path,
) -> None:
    repository = _repository()
    event_contract = _event().model_copy(update={"evidence_status": "unavailable"})
    repository.add_event(event_contract)
    intent = EvidenceIntent(
        schema_version="evidence-intent.v1",
        evidence_id=uuid4(),
        event_id=event_contract.event_id,
        object_key=f"events/{event_contract.event_id}.mp4",
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=4),
        source_reference="nvr://camera/01",
        status="failed",
    )
    journal = SQLiteWALJournal(tmp_path / "intent-replay.sqlite3", max_items=2)
    journal.enqueue(
        kind="evidence_intent",
        schema_version=intent.schema_version,
        idempotency_key=f"evidence-intent:{intent.evidence_id}:failed",
        payload=intent.to_payload(),
    )

    assert journal.replay(repository.persist_journal_item) == 1
    assert repository.get_event(event_contract.event_id).evidence_status == "failed"


def test_journal_acknowledges_only_after_repository_commit(tmp_path: Path) -> None:
    path = tmp_path / "commit-gate.sqlite3"
    journal = SQLiteWALJournal(path, max_items=10)
    journal.enqueue_event(_event())
    repository = _repository()

    def fail_commit(session: object) -> None:
        raise RuntimeError("database commit failed")

    event.listen(repository.session_factory, "before_commit", fail_commit, once=True)
    with pytest.raises(RuntimeError, match="database commit failed"):
        journal.replay(repository.persist_journal_item)

    assert journal.depth() == 1
    with repository.session_factory() as session:
        assert len(session.scalars(select(CandidateEventModel)).all()) == 0

    assert journal.replay(repository.persist_journal_item) == 1
    assert journal.depth() == 0


def test_journal_is_bounded_idempotent_and_reports_wal_depth(tmp_path: Path) -> None:
    journal = SQLiteWALJournal(tmp_path / "bounded.sqlite3", max_items=1)
    queued = journal.enqueue(
        kind="evidence",
        schema_version="evidence-work.v1",
        idempotency_key="evidence-1",
        payload={
            "schema_version": "evidence-work.v1",
            "evidence_id": str(uuid4()),
            "event_id": str(uuid4()),
            "object_key": "events/cam-01/clip.mp4",
            "sha256": "b" * 64,
            "codec": "h264",
            "start_at": NOW.isoformat(),
            "end_at": (NOW + timedelta(seconds=8)).isoformat(),
            "source_reference": "nvr://camera/01?segment=42",
            "status": "ready",
        },
    )
    replayed = journal.enqueue(
        kind="evidence",
        schema_version="evidence-work.v1",
        idempotency_key="evidence-1",
        payload=queued.payload,
    )

    assert replayed.item_id == queued.item_id
    assert journal.depth() == 1
    assert journal.journal_mode == "wal"

    with pytest.raises(JournalPayloadConflictError):
        journal.enqueue(
            kind="evidence",
            schema_version="evidence-work.v1",
            idempotency_key="evidence-1",
            payload={**queued.payload, "codec": "h265"},
        )
    with pytest.raises(JournalFullError):
        journal.enqueue(
            kind="candidate_event",
            schema_version="candidate-event.v1",
            idempotency_key="event-2",
            payload=_event().model_dump(mode="json"),
        )


def test_journal_keeps_distinct_same_timestamp_candidates_and_converges_exact_replay(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "candidate-identities.sqlite3", max_items=4)
    first = _event()
    second = _event().model_copy(update={"reason": "second track"})

    first_item = journal.enqueue_event(first)
    second_item = journal.enqueue_event(second)
    replayed_first = journal.enqueue_event(first)
    replayed_second = journal.enqueue_event(second)

    assert first.dedupe_key != second.dedupe_key
    assert first_item.item_id != second_item.item_id
    assert replayed_first.item_id == first_item.item_id
    assert replayed_second.item_id == second_item.item_id
    assert journal.depth() == 2


def test_evidence_journal_rejects_raw_or_oversized_payloads(tmp_path: Path) -> None:
    journal = SQLiteWALJournal(
        tmp_path / "metadata-only.sqlite3",
        max_items=2,
        max_payload_bytes=600,
    )
    metadata = {
        "schema_version": "evidence-work.v1",
        "evidence_id": str(uuid4()),
        "event_id": str(uuid4()),
        "object_key": "events/cam-01/clip.mp4",
        "sha256": "b" * 64,
        "codec": "h264",
        "start_at": NOW.isoformat(),
        "end_at": (NOW + timedelta(seconds=8)).isoformat(),
        "source_reference": "nvr://camera/01?segment=42",
        "status": "ready",
    }

    with pytest.raises(ValueError, match="metadata"):
        journal.enqueue(
            kind="evidence",
            schema_version="evidence-work.v1",
            idempotency_key="raw-evidence",
            payload={**metadata, "raw_video": "base64-data"},
        )
    with pytest.raises(ValueError, match="payload exceeds"):
        journal.enqueue(
            kind="candidate_event",
            schema_version="candidate-event.v1",
            idempotency_key="oversized-event",
            payload={"schema_version": "candidate-event.v1", "reason": "x" * 700},
        )
    assert journal.depth() == 0


def test_journal_rejects_unknown_or_mismatched_schema_versions(tmp_path: Path) -> None:
    path = tmp_path / "versions.sqlite3"
    journal = SQLiteWALJournal(path, max_items=4)
    event_payload = _event().model_dump(mode="json")

    with pytest.raises(ValueError, match="unsupported journal schema version"):
        journal.enqueue(
            kind="candidate_event",
            schema_version="candidate-event.v2",
            idempotency_key="unknown-event-version",
            payload={**event_payload, "schema_version": "candidate-event.v2"},
        )
    with pytest.raises(ValueError, match="does not match payload"):
        journal.enqueue(
            kind="candidate_event",
            schema_version="candidate-event.v1",
            idempotency_key="mismatched-event-version",
            payload={**event_payload, "schema_version": "candidate-event.v2"},
        )
    with pytest.raises(ValueError, match="unsupported journal schema version"):
        journal.enqueue(
            kind="evidence",
            schema_version="evidence-work.v2",
            idempotency_key="unknown-evidence-version",
            payload={
                "schema_version": "evidence-work.v2",
                "evidence_id": str(uuid4()),
            },
        )
    journal.close()

    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO journal_items
                (kind, schema_version, idempotency_key, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "evidence",
                "evidence-work.v2",
                "tampered-version",
                json.dumps(
                    {
                        "schema_version": "evidence-work.v2",
                        "evidence_id": str(uuid4()),
                    }
                ),
                NOW.isoformat(),
            ),
        )
    restarted = SQLiteWALJournal(path, max_items=4)
    processed: list[object] = []
    with pytest.raises(ValueError, match="unsupported journal schema version"):
        restarted.replay(processed.append)
    assert processed == []
    assert restarted.depth() == 1


@pytest.mark.parametrize(
    "ordered_statuses",
    (("ready", "failed"), ("failed", "ready")),
)
def test_evidence_finalization_replay_orders_converge_to_ready(
    tmp_path: Path,
    ordered_statuses: tuple[str, str],
) -> None:
    repository = _repository()
    event_contract = _event()
    repository.add_event(event_contract)
    journal = SQLiteWALJournal(tmp_path / "evidence-order.sqlite3", max_items=4)
    evidence_id = uuid4()
    base_payload = {
        "schema_version": "evidence-work.v1",
        "evidence_id": str(evidence_id),
        "event_id": str(event_contract.event_id),
        "object_key": "events/cam-01/replay-order.mp4",
        "sha256": "c" * 64,
        "codec": "h264",
        "start_at": NOW.isoformat(),
        "end_at": (NOW + timedelta(seconds=6)).isoformat(),
        "source_reference": "nvr://camera/01?segment=replay-order",
    }
    for status in ordered_statuses:
        journal.enqueue(
            kind="evidence",
            schema_version="evidence-work.v1",
            idempotency_key=f"evidence-finalize:{evidence_id}:{status}",
            payload={**base_payload, "status": status},
        )

    assert journal.replay(repository.persist_journal_item) == 2
    assert journal.depth() == 0
    assert repository.get_event(event_contract.event_id).evidence_status == "ready"


def test_replay_worker_backs_off_retryable_database_lock_without_busy_loop(
    tmp_path: Path,
) -> None:
    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    journal = SQLiteWALJournal(tmp_path / "retry-worker.sqlite3", max_items=4)
    journal.enqueue_event(_event())
    calls: list[int] = []

    def processor(item: object) -> None:
        calls.append(item.item_id)  # type: ignore[attr-defined]
        if len(calls) == 1:
            raise OperationalError(
                "UPDATE candidate_events",
                {},
                sqlite3.OperationalError("database is locked"),
            )

    worker = EvidenceJournalReplayWorker(
        journal=journal,
        processor=processor,
        batch_size=2,
        retry_backoff_seconds=5,
        monotonic_clock=clock,
    )

    assert worker.startup_drain() == 0
    assert worker.status.degraded is True
    assert worker.status.depth == 1
    assert worker.run_periodic_batch() == 0
    assert calls == [1]
    clock.now = 5
    assert worker.run_periodic_batch() == 1
    assert worker.status.degraded is False
    assert worker.status.depth == 0
    assert worker.status.processed_total == 1


def test_replay_worker_quarantines_poison_and_processes_later_valid_work(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(
        tmp_path / "poison-worker.sqlite3",
        max_items=4,
        max_quarantine_items=4,
    )
    poison = journal.enqueue_event(_event())
    valid = journal.enqueue_event(
        _event().model_copy(
            update={
                "opened_at": NOW + timedelta(minutes=1),
                "last_seen_at": NOW + timedelta(minutes=1, seconds=2),
            }
        )
    )
    processed: list[int] = []

    def processor(item: object) -> None:
        if item.item_id == poison.item_id:  # type: ignore[attr-defined]
            raise IntegrityError("INSERT", {}, ValueError("deterministic constraint"))
        processed.append(item.item_id)  # type: ignore[attr-defined]

    worker = EvidenceJournalReplayWorker(
        journal=journal,
        processor=processor,
        batch_size=4,
        retry_backoff_seconds=5,
    )

    assert worker.startup_drain() == 1
    assert processed == [valid.item_id]
    assert journal.depth() == 0
    assert journal.quarantine_depth() == 1
    assert worker.status.quarantine_depth == 1
    assert worker.status.last_error == "IntegrityError"


def test_replay_exclusions_preserve_eligible_fifo_batching_and_exact_ack(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "eligible-replay.sqlite3", max_items=4)
    items = tuple(
        journal.enqueue_event(
            _event().model_copy(
                update={
                    "opened_at": NOW + timedelta(minutes=index),
                    "last_seen_at": NOW
                    + timedelta(minutes=index, seconds=2),
                }
            )
        )
        for index in range(4)
    )
    excluded = frozenset((items[0].item_id, items[2].item_id))
    selected = journal.replay_items(
        limit=2,
        excluded_item_ids=excluded,
    )
    processed: list[int] = []
    worker = EvidenceJournalReplayWorker(
        journal=journal,
        processor=lambda item: processed.append(item.item_id),
        batch_size=1,
        retry_backoff_seconds=1,
    )

    assert tuple(item.item_id for item in selected) == (
        items[1].item_id,
        items[3].item_id,
    )
    assert worker.startup_drain(excluded_item_ids=excluded) == 1
    assert worker.run_periodic_batch(excluded_item_ids=excluded) == 1
    assert processed == [items[1].item_id, items[3].item_id]
    assert tuple(item.item_id for item in journal.items(limit=4)) == (
        items[0].item_id,
        items[2].item_id,
    )


def test_replay_worker_quarantines_legacy_schema_poison_without_blocking_queue(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-poison-worker.sqlite3"
    journal = SQLiteWALJournal(path, max_items=4, max_quarantine_items=4)
    poison = journal.enqueue_event(_event())
    valid = journal.enqueue_event(
        _event().model_copy(
            update={
                "opened_at": NOW + timedelta(minutes=2),
                "last_seen_at": NOW + timedelta(minutes=2, seconds=2),
            }
        )
    )
    journal.close()
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            UPDATE journal_items
            SET schema_version = ?, payload_json = ?
            WHERE item_id = ?
            """,
            (
                "candidate-event.v0",
                json.dumps({"schema_version": "candidate-event.v0"}),
                poison.item_id,
            ),
        )
    restarted = SQLiteWALJournal(path, max_items=4, max_quarantine_items=4)
    processed: list[int] = []
    worker = EvidenceJournalReplayWorker(
        journal=restarted,
        processor=lambda item: processed.append(item.item_id),
        batch_size=4,
        retry_backoff_seconds=5,
    )

    assert worker.startup_drain() == 1
    assert processed == [valid.item_id]
    assert restarted.depth() == 0
    assert restarted.quarantine_depth() == 1


def test_replay_worker_quarantines_malformed_json_and_continues(
    tmp_path: Path,
) -> None:
    path = tmp_path / "malformed-json-worker.sqlite3"
    journal = SQLiteWALJournal(path, max_items=4, max_quarantine_items=4)
    poison = journal.enqueue_event(_event())
    valid = journal.enqueue_event(
        _event().model_copy(
            update={
                "opened_at": NOW + timedelta(minutes=3),
                "last_seen_at": NOW + timedelta(minutes=3, seconds=2),
            }
        )
    )
    journal.close()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE journal_items SET payload_json = ? WHERE item_id = ?",
            ("{not-json", poison.item_id),
        )
    restarted = SQLiteWALJournal(path, max_items=4, max_quarantine_items=4)
    processed: list[int] = []
    worker = EvidenceJournalReplayWorker(
        journal=restarted,
        processor=lambda item: processed.append(item.item_id),
        batch_size=4,
        retry_backoff_seconds=5,
    )

    assert worker.startup_drain() == 1
    assert processed == [valid.item_id]
    assert restarted.depth() == 0
    assert restarted.quarantine_depth() == 1


def test_replay_worker_never_swallows_process_control_exceptions(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "interrupt-worker.sqlite3", max_items=2)
    journal.enqueue_event(_event())
    worker = EvidenceJournalReplayWorker(
        journal=journal,
        processor=lambda _: (_ for _ in ()).throw(KeyboardInterrupt()),
        batch_size=1,
        retry_backoff_seconds=5,
    )

    with pytest.raises(KeyboardInterrupt):
        worker.startup_drain()
    assert journal.depth() == 1
    assert journal.quarantine_depth() == 0


def test_retry_classifier_rejects_deterministic_sql_and_accepts_connection_states() -> None:
    assert not is_retryable_database_error(
        IntegrityError("INSERT", {}, ValueError("unique constraint"))
    )
    assert is_retryable_database_error(
        OperationalError(
            "UPDATE evidence",
            {},
            sqlite3.OperationalError("database is locked"),
        )
    )
    assert is_retryable_database_error(sqlite3.OperationalError("database is busy"))
    assert not is_retryable_database_error(
        sqlite3.OperationalError("no such table: evidence")
    )

    class PostgreSQLConnectionFailure(Exception):
        pgcode = "08006"

    assert is_retryable_database_error(
        OperationalError("SELECT 1", {}, PostgreSQLConnectionFailure())
    )


@pytest.mark.parametrize("sqlstate", ["40001", "40P01", "55P03"])
def test_postgresql_concurrency_states_stay_live_with_bounded_backoff(
    tmp_path: Path,
    sqlstate: str,
) -> None:
    class PostgreSQLConcurrencyFailure(Exception):
        pass

    failure = PostgreSQLConcurrencyFailure(f"transient PostgreSQL state {sqlstate}")
    failure.sqlstate = sqlstate  # type: ignore[attr-defined]
    error = OperationalError("UPDATE evidence", {}, failure)
    assert is_retryable_database_error(error)

    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    journal = SQLiteWALJournal(
        tmp_path / f"postgres-{sqlstate}.sqlite3",
        max_items=2,
        max_quarantine_items=2,
    )
    item = journal.enqueue_event(_event())
    attempts: list[int] = []

    def processor(work: object) -> None:
        attempts.append(work.item_id)  # type: ignore[attr-defined]
        if len(attempts) == 1:
            raise error

    worker = EvidenceJournalReplayWorker(
        journal=journal,
        processor=processor,
        batch_size=1,
        retry_backoff_seconds=3,
        monotonic_clock=clock,
    )

    assert worker.startup_drain() == 0
    assert attempts == [item.item_id]
    assert worker.status.depth == 1
    assert worker.status.quarantine_depth == 0
    assert worker.status.degraded is True
    assert worker.status.next_retry_in_seconds == 3
    assert worker.status.retry_attempts_total == 1
    assert worker.run_periodic_batch() == 0
    assert worker.status.retry_attempts_total == 1
    clock.now = 3
    assert worker.run_periodic_batch() == 1
    assert attempts == [item.item_id, item.item_id]
    assert worker.status.depth == 0
    assert worker.status.quarantine_depth == 0
    assert worker.status.retry_attempts_total == 1


def test_pending_evidence_seed_is_promoted_atomically_to_reserved_work(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "pending-seed.sqlite3", max_items=2)
    event_id = str(uuid4())
    reservation_id = f"event-{event_id}"
    seed = {
        "schema_version": "pending-evidence-seed.v1",
        "event_id": event_id,
        "reservation_id": reservation_id,
        "stream_epoch": str(uuid4()),
        "event_at": NOW.isoformat(),
        "target_start_at": (NOW - timedelta(seconds=2)).isoformat(),
        "target_end_at": (NOW + timedelta(seconds=2)).isoformat(),
        "expires_at": (NOW + timedelta(seconds=17)).isoformat(),
        "source_reference": "nvr://cam-01",
        "pre_roll_seconds": 2.0,
        "post_roll_seconds": 2.0,
        "pending_timeout_seconds": 15.0,
    }
    full = {**seed, "schema_version": "pending-evidence-work.v1", "intent": {}}

    seeded = journal.seed_pending_evidence_work(
        event_id=event_id,
        reservation_id=reservation_id,
        payload=seed,
    )
    promoted = journal.reserve_pending_evidence_work(
        event_id=event_id,
        reservation_id=reservation_id,
        payload=full,
    )

    assert seeded.phase == "seed"
    assert seeded.payload == seed
    assert promoted.phase == "reserved"
    assert promoted.payload == full
    assert journal.pending_evidence_work_items(limit=2) == (promoted,)


def test_pending_evidence_quarantine_refuses_overflow_without_eviction(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(
        tmp_path / "pending-quarantine-bound.sqlite3",
        max_items=3,
        max_quarantine_items=1,
    )

    def reserve(event_id: str) -> None:
        journal.reserve_pending_evidence_work(
            event_id=event_id,
            reservation_id=f"event-{event_id}",
            payload={"schema_version": "pending-evidence-work.v1", "event_id": event_id},
        )

    reserve("event-1")
    assert journal.quarantine_pending_evidence_work(
        event_id="event-1",
        reservation_id="event-event-1",
        error_type="FirstPoison",
    )
    reserve("event-2")

    with pytest.raises(JournalFullError, match="quarantine capacity"):
        journal.quarantine_pending_evidence_work(
            event_id="event-2",
            reservation_id="event-event-2",
            error_type="SecondPoison",
        )

    assert journal.pending_evidence_quarantine_depth() == 1
    assert journal.pending_evidence_work_depth() == 1


def test_pending_evidence_ack_rolls_back_abort_and_is_idempotent_after_commit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pending-ack-transaction.sqlite3"
    journal = SQLiteWALJournal(path, max_items=2)
    event_id = str(uuid4())
    reservation_id = f"event-{event_id}"
    journal.reserve_pending_evidence_work(
        event_id=event_id,
        reservation_id=reservation_id,
        payload={"schema_version": "pending-evidence-work.v1"},
    )
    journal._connection.execute(
        """
        CREATE TRIGGER abort_pending_ack
        BEFORE DELETE ON pending_evidence_work
        BEGIN
            SELECT RAISE(ABORT, 'forced pending ACK abort');
        END
        """
    )
    journal._connection.commit()

    with pytest.raises(sqlite3.IntegrityError, match="forced pending ACK abort"):
        journal.acknowledge_pending_evidence_work(
            event_id=event_id,
            reservation_id=reservation_id,
        )

    assert journal._connection.in_transaction is False
    assert journal.pending_evidence_work_depth() == 1
    journal._connection.execute("DROP TRIGGER abort_pending_ack")
    journal._connection.commit()
    assert journal.acknowledge_pending_evidence_work(
        event_id=event_id,
        reservation_id=reservation_id,
    )
    journal.close()

    restarted = SQLiteWALJournal(path, max_items=2)
    assert restarted.acknowledge_pending_evidence_work(
        event_id=event_id,
        reservation_id=reservation_id,
    )
    assert restarted.pending_evidence_work_depth() == 0


def test_existing_pending_lifecycle_table_migrates_to_seed_phase(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pending-phase-migration.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE pending_evidence_work (
            event_id TEXT PRIMARY KEY,
            reservation_id TEXT NOT NULL UNIQUE,
            phase TEXT NOT NULL CHECK (phase IN ('reserved', 'active')),
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO pending_evidence_work
            (event_id, reservation_id, phase, payload_json, created_at)
        VALUES ('legacy-event', 'event-legacy-event', 'active', '{}', ?)
        """,
        (NOW.isoformat(),),
    )
    connection.commit()
    connection.close()

    journal = SQLiteWALJournal(path, max_items=2)
    seeded = journal.seed_pending_evidence_work(
        event_id="new-event",
        reservation_id="event-new-event",
        payload={"schema_version": "pending-evidence-seed.v1"},
    )

    assert journal.pending_evidence_work_items(limit=2)[0].phase == "active"
    assert seeded.phase == "seed"


@pytest.mark.skipif(
    os.getenv("PILOT_TEST_DATABASE_URL") is None,
    reason="requires disposable PostgreSQL *_test database",
)
def test_disposable_postgresql_serialization_failure_remains_live_until_retry(
    tmp_path: Path,
) -> None:
    database_url = os.environ["PILOT_TEST_DATABASE_URL"]
    parsed_url = make_url(database_url)
    if (
        parsed_url.get_backend_name() != "postgresql"
        or parsed_url.database is None
        or not parsed_url.database.endswith("_test")
    ):
        pytest.fail(
            "PILOT_TEST_DATABASE_URL must target a disposable PostgreSQL *_test database"
        )
    engine = create_engine(database_url)
    journal = SQLiteWALJournal(
        tmp_path / "postgres-serialization.sqlite3",
        max_items=2,
        max_quarantine_items=2,
    )
    item = journal.enqueue_event(_event())
    attempts: list[int] = []
    clock = [0.0]

    def processor(work: object) -> None:
        attempts.append(work.item_id)  # type: ignore[attr-defined]
        if len(attempts) == 1:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        DO $$
                        BEGIN
                            RAISE EXCEPTION 'forced serialization retry'
                                USING ERRCODE = '40001';
                        END
                        $$;
                        """
                    )
                )

    worker = EvidenceJournalReplayWorker(
        journal=journal,
        processor=processor,
        batch_size=1,
        retry_backoff_seconds=1,
        monotonic_clock=lambda: clock[0],
    )
    try:
        assert worker.startup_drain() == 0
        assert attempts == [item.item_id]
        assert journal.depth() == 1
        assert journal.quarantine_depth() == 0
        clock[0] = 1
        assert worker.run_periodic_batch() == 1
        assert attempts == [item.item_id, item.item_id]
        assert journal.depth() == 0
    finally:
        engine.dispose()
