from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import event, select

from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.journal import (
    JournalFullError,
    JournalPayloadConflictError,
    SQLiteWALJournal,
)
from protector.pilot.storage.models import Base, CandidateEventModel
from protector.pilot.storage.repositories import PilotRepository

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
