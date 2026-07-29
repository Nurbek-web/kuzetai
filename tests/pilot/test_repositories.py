from __future__ import annotations

import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, inspect, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from protector.pilot.domain import CandidateEventV1, ObservationV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    AuditEntryModel,
    Base,
    CandidateEventModel,
    EvidenceModel,
    NotificationOutboxModel,
    ReviewModel,
)
from protector.pilot.storage.repositories import (
    AuditEntryInput,
    EvidenceInput,
    IdempotencyConflictError,
    PilotRepository,
)

UTC = timezone.utc
NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)


@pytest.fixture
def repository() -> PilotRepository:
    database_url = os.getenv("PILOT_TEST_DATABASE_URL")
    if database_url is None:
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
    else:
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
        table_names = ", ".join(table.name for table in reversed(Base.metadata.sorted_tables))
        with engine.begin() as connection:
            connection.exec_driver_sql(f"TRUNCATE TABLE {table_names} RESTART IDENTITY CASCADE")
    repo = PilotRepository(create_session_factory(engine))
    repo.add_site(site_id="site-1", name="Pilot School")
    repo.add_camera(
        camera_id="cam-01",
        site_id="site-1",
        name="North entrance",
        source_reference="nvr://camera/01",
        codec="h264",
    )
    repo.add_camera(
        camera_id="cam-02",
        site_id="site-1",
        name="South entrance",
        source_reference="nvr://camera/02",
        codec="h265",
        state="degraded",
    )
    repo.add_model_artifact(_artifact())
    return repo


def _artifact() -> ModelArtifactV1:
    return ModelArtifactV1(
        schema_version="model-artifact.v1",
        artifact_id="person-v1",
        sha256="a" * 64,
        source="s3://model-registry/person-v1.onnx",
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


def _observation(
    *,
    observation_id: UUID | None = None,
    monotonic_seq: int = 1,
) -> ObservationV1:
    return ObservationV1(
        schema_version="observation.v1",
        observation_id=observation_id or uuid4(),
        camera_id="cam-01",
        stream_epoch=UUID("11111111-1111-1111-1111-111111111111"),
        source_time=NOW,
        timestamp_quality="camera_rtcp",
        monotonic_seq=monotonic_seq,
        module="person",
        class_name="person",
        confidence=0.91,
        bbox=(0.1, 0.2, 0.5, 0.8),
        track_id="track-4",
        model_artifact_id="person-v1",
        sample_kind="fresh",
        runtime_state="online",
        received_at=NOW + timedelta(milliseconds=30),
    )


def _event(
    *,
    event_id: UUID | None = None,
    camera_id: str = "cam-01",
    gate_mode: str = "operator",
    review_status: str = "candidate",
    transition_history: tuple[str, ...] = ("observation", "candidate"),
    opened_at: datetime = NOW,
) -> CandidateEventV1:
    return CandidateEventV1(
        schema_version="candidate-event.v1",
        event_id=event_id or uuid4(),
        camera_id=camera_id,
        module="person",
        opened_at=opened_at,
        last_seen_at=opened_at + timedelta(seconds=2),
        peak_confidence=0.93,
        reason="restricted zone intrusion",
        model_artifact_id="person-v1",
        gate_mode=gate_mode,
        evidence_status="pending",
        review_status=review_status,
        transition_history=transition_history,
    )


def _run_concurrently(operation: Callable[[], object]) -> list[object]:
    barrier = Barrier(2)

    def synchronized() -> object:
        barrier.wait(timeout=5)
        return operation()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(synchronized) for _ in range(2)]
        return [future.result() for future in futures]


def test_observation_id_and_dedupe_key_are_independently_unique(
    repository: PilotRepository,
) -> None:
    first = _observation()
    repository.add_observation(first)

    with pytest.raises(IntegrityError):
        repository.add_observation(
            _observation(observation_id=first.observation_id, monotonic_seq=2)
        )

    with pytest.raises(IntegrityError):
        repository.add_observation(_observation(monotonic_seq=1))

    assert repository.count_observations() == 1


def test_camera_and_event_filters_return_only_matching_records(
    repository: PilotRepository,
) -> None:
    repository.add_event(_event(camera_id="cam-01"))
    repository.add_event(
        _event(camera_id="cam-02", opened_at=NOW + timedelta(minutes=1), gate_mode="shadow")
    )

    assert [camera.camera_id for camera in repository.list_cameras(state="degraded")] == ["cam-02"]
    assert [event.camera_id for event in repository.list_events(camera_id="cam-01")] == ["cam-01"]
    assert [event.gate_mode for event in repository.list_events(gate_mode="shadow")] == ["shadow"]
    assert repository.list_events(module="weapon") == []


def test_audit_entries_are_append_only_through_the_orm(
    repository: PilotRepository,
) -> None:
    entry = repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="camera.created",
            entity_type="camera",
            entity_id="cam-01",
            payload={"site_id": "site-1"},
            idempotency_key="audit-camera-1",
            occurred_at=NOW,
        )
    )

    with repository.session_factory() as session:
        stored = session.get(AuditEntryModel, entry.audit_id)
        assert stored is not None
        stored.action = "camera.deleted"
        with pytest.raises(ValueError, match="append-only"):
            session.commit()
        session.rollback()

    with repository.session_factory() as session:
        stored = session.get(AuditEntryModel, entry.audit_id)
        assert stored is not None
        session.delete(stored)
        with pytest.raises(ValueError, match="append-only"):
            session.commit()


def test_audit_entries_reject_bulk_database_updates(repository: PilotRepository) -> None:
    entry = repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="camera.created",
            entity_type="camera",
            entity_id="cam-01",
            payload={"site_id": "site-1"},
            idempotency_key="audit-bulk-update",
            occurred_at=NOW,
        )
    )

    with repository.session_factory.begin() as session:
        with pytest.raises(IntegrityError, match="append-only"):
            session.execute(
                update(AuditEntryModel)
                .where(AuditEntryModel.audit_id == entry.audit_id)
                .values(action="camera.deleted")
            )


def test_review_transition_is_atomic_legal_and_idempotent(
    repository: PilotRepository,
) -> None:
    event = _event()
    repository.add_event(event)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )

    first = repository.review_event(
        event_id=event.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        idempotency_key="review-request-1",
        notes="Confirmed from clip",
        reviewed_at=NOW + timedelta(minutes=1),
    )
    replay = repository.review_event(
        event_id=event.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        idempotency_key="review-request-1",
        notes="Confirmed from clip",
        reviewed_at=NOW + timedelta(minutes=1),
    )

    assert first.review_id == replay.review_id
    assert repository.get_event(event.event_id).review_status == "confirmed"
    with repository.session_factory() as session:
        assert len(session.scalars(select(ReviewModel)).all()) == 1
        audits = session.scalars(select(AuditEntryModel)).all()
        assert len(audits) == 1
        assert audits[0].payload == {
            "from_status": "candidate",
            "to_status": "confirmed",
            "notes_present": True,
            "notes_sha256": "c531fbdf353a5bb201922e78c03665c99d644e4a5e998654f7ddfa4f908fa7f7",
        }
        assert "Confirmed from clip" not in repr(audits[0].payload)

    with pytest.raises(ValueError, match="illegal event transition"):
        repository.review_event(
            event_id=event.event_id,
            reviewer_id="operator-1",
            target_status="rejected",
            idempotency_key="review-request-2",
            notes=None,
            reviewed_at=NOW + timedelta(minutes=2),
        )

    assert repository.get_event(event.event_id).review_status == "confirmed"
    with repository.session_factory() as session:
        assert len(session.scalars(select(ReviewModel)).all()) == 1
        assert len(session.scalars(select(AuditEntryModel)).all()) == 1


def test_review_idempotency_compares_review_timestamp(repository: PilotRepository) -> None:
    event = _event()
    repository.add_event(event)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )
    repository.review_event(
        event_id=event.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        idempotency_key="review-material-fields",
        notes="same note",
        reviewed_at=NOW + timedelta(minutes=1),
    )

    with pytest.raises(IdempotencyConflictError, match="different data"):
        repository.review_event(
            event_id=event.event_id,
            reviewer_id="operator-1",
            target_status="confirmed",
            idempotency_key="review-material-fields",
            notes="same note",
            reviewed_at=NOW + timedelta(minutes=2),
        )


def test_database_rejects_illegal_review_pairs(repository: PilotRepository) -> None:
    event = _event()
    repository.add_event(event)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )

    with repository.session_factory.begin() as session:
        session.add(
            ReviewModel(
                review_id=str(uuid4()),
                event_id=str(event.event_id),
                reviewer_id="operator-1",
                from_status="candidate",
                to_status="escalated",
                notes=None,
                idempotency_key="illegal-pair",
                reviewed_at=NOW,
            )
        )
        with pytest.raises(IntegrityError, match="legal_transition"):
            session.flush()


def test_review_rejects_corrupt_lifecycle_provenance_without_partial_writes(
    repository: PilotRepository,
) -> None:
    event = _event()
    repository.add_event(event)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )
    with pytest.raises(IntegrityError, match="lifecycle"):
        with repository.session_factory.begin() as session:
            stored = session.get(CandidateEventModel, str(event.event_id))
            assert stored is not None
            stored.transition_history = "candidate"
            session.flush()

    assert repository.get_event(event.event_id).review_status == "candidate"
    with repository.session_factory() as session:
        assert len(session.scalars(select(ReviewModel)).all()) == 0
        assert len(session.scalars(select(AuditEntryModel)).all()) == 0


def test_outbox_accepts_one_confirmed_operator_event_only(
    repository: PilotRepository,
) -> None:
    operator_event = _event()
    shadow_event = _event(
        gate_mode="shadow",
        review_status="confirmed",
        transition_history=("observation", "candidate", "confirmed"),
        opened_at=NOW + timedelta(minutes=2),
    )
    repository.add_event(operator_event)
    repository.add_event(shadow_event)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )

    with pytest.raises(ValueError, match="only confirmed"):
        repository.enqueue_notification(
            event_id=operator_event.event_id,
            idempotency_key="notify-candidate",
        )

    repository.review_event(
        event_id=operator_event.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        idempotency_key="review-confirm",
        notes=None,
        reviewed_at=NOW + timedelta(minutes=1),
    )
    first = repository.enqueue_notification(
        event_id=operator_event.event_id,
        idempotency_key="notify-confirmed",
    )
    replay = repository.enqueue_notification(
        event_id=operator_event.event_id,
        idempotency_key="notify-confirmed",
    )

    assert first.outbox_id == replay.outbox_id
    with repository.session_factory() as session:
        assert len(session.scalars(select(NotificationOutboxModel)).all()) == 1

    with pytest.raises(ValueError, match="only operator"):
        repository.enqueue_notification(
            event_id=shadow_event.event_id,
            idempotency_key="notify-shadow",
        )
    with pytest.raises(IdempotencyConflictError):
        repository.enqueue_notification(
            event_id=shadow_event.event_id,
            idempotency_key="notify-confirmed",
        )


def test_outbox_idempotency_compares_payload(repository: PilotRepository) -> None:
    event = _event()
    repository.add_event(event)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )
    repository.review_event(
        event_id=event.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        idempotency_key="review-for-payload",
        notes=None,
        reviewed_at=NOW,
    )
    repository.enqueue_notification(
        event_id=event.event_id,
        idempotency_key="notify-material-fields",
        payload={"connector": "telegram"},
    )

    with pytest.raises(IdempotencyConflictError, match="different data"):
        repository.enqueue_notification(
            event_id=event.event_id,
            idempotency_key="notify-material-fields",
            payload={"connector": "email"},
        )


def test_database_rejects_outbox_insert_for_unconfirmed_event(
    repository: PilotRepository,
) -> None:
    event = _event()
    repository.add_event(event)

    with repository.session_factory.begin() as session:
        session.add(
            NotificationOutboxModel(
                outbox_id=str(uuid4()),
                event_id=str(event.event_id),
                idempotency_key="direct-candidate-insert",
                status="pending",
                payload={},
                available_at=NOW,
            )
        )
        with pytest.raises(IntegrityError, match="confirmed operator"):
            session.flush()


def test_database_rejects_confirmed_outbox_without_review_provenance(
    repository: PilotRepository,
) -> None:
    event = _event(
        review_status="confirmed",
        transition_history=("observation", "candidate", "confirmed"),
    )
    repository.add_event(event)

    with repository.session_factory.begin() as session:
        session.add(
            NotificationOutboxModel(
                outbox_id=str(uuid4()),
                event_id=str(event.event_id),
                idempotency_key="confirmed-without-review",
                status="pending",
                payload={},
                available_at=NOW,
            )
        )
        with pytest.raises(IntegrityError, match="review provenance"):
            session.flush()


def test_database_rejects_corrupt_confirmed_transition_history(
    repository: PilotRepository,
) -> None:
    with repository.session_factory.begin() as session:
        session.add(
            CandidateEventModel(
                event_id=str(uuid4()),
                schema_version="candidate-event.v1",
                dedupe_key="corrupt-confirmed-history",
                camera_id="cam-01",
                module="person",
                opened_at=NOW,
                last_seen_at=NOW,
                peak_confidence=0.8,
                reason="test",
                model_artifact_id="person-v1",
                gate_mode="operator",
                evidence_status="pending",
                review_status="confirmed",
                transition_history="observation>confirmed",
            )
        )
        with pytest.raises(IntegrityError, match="lifecycle"):
            session.flush()


def test_evidence_persists_only_bounded_metadata(repository: PilotRepository) -> None:
    event = _event()
    repository.add_event(event)
    evidence = EvidenceInput(
        evidence_id=uuid4(),
        event_id=event.event_id,
        object_key="events/cam-01/clip.mp4",
        sha256="b" * 64,
        codec="h264",
        start_at=NOW - timedelta(seconds=2),
        end_at=NOW + timedelta(seconds=6),
        source_reference="nvr://camera/01?segment=42",
        status="ready",
    )

    stored = repository.add_evidence(evidence)

    assert stored.object_key == "events/cam-01/clip.mp4"
    assert stored.end_at > stored.start_at
    assert {column.name for column in EvidenceModel.__table__.columns}.isdisjoint(
        {"raw_video", "video_bytes", "frames", "payload"}
    )


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        ("codec", "h265"),
        ("start_at", NOW - timedelta(seconds=1)),
        ("end_at", NOW + timedelta(seconds=7)),
        ("source_reference", "nvr://camera/01?segment=99"),
        ("status", "failed"),
    ],
)
def test_evidence_idempotency_compares_all_material_fields(
    repository: PilotRepository,
    changed_field: str,
    changed_value: object,
) -> None:
    event = _event()
    repository.add_event(event)
    evidence = EvidenceInput(
        evidence_id=uuid4(),
        event_id=event.event_id,
        object_key="events/cam-01/material.mp4",
        sha256="b" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=5),
        source_reference="nvr://camera/01?segment=42",
        status="ready",
    )
    repository.add_evidence(evidence)

    with pytest.raises(IdempotencyConflictError, match="different data"):
        repository.add_evidence(
            EvidenceInput(
                **{
                    **evidence.__dict__,
                    changed_field: changed_value,
                }
            )
        )


def test_database_bounds_evidence_time_range(repository: PilotRepository) -> None:
    event = _event()
    repository.add_event(event)
    cases = (
        ("zero", NOW, NOW, "pending"),
        ("continuous", NOW, NOW + timedelta(seconds=11), "pending"),
        ("short-ready", NOW, NOW + timedelta(seconds=3), "ready"),
    )

    for label, start_at, end_at, status in cases:
        with repository.session_factory.begin() as session:
            session.add(
                EvidenceModel(
                    evidence_id=str(uuid4()),
                    event_id=str(event.event_id),
                    object_key=f"events/{label}.mp4",
                    sha256="c" * 64,
                    codec="h264",
                    start_at=start_at,
                    end_at=end_at,
                    source_reference="nvr://camera/01",
                    status=status,
                )
            )
            with pytest.raises(IntegrityError, match="evidence duration"):
                session.flush()


def test_database_checks_reject_invalid_persisted_state(repository: PilotRepository) -> None:
    with repository.session_factory.begin() as session:
        session.add(
            CandidateEventModel(
                event_id=str(uuid4()),
                schema_version="candidate-event.v1",
                dedupe_key="invalid-state-event",
                camera_id="cam-01",
                module="person",
                opened_at=NOW,
                last_seen_at=NOW,
                peak_confidence=0.8,
                reason="test",
                model_artifact_id="person-v1",
                gate_mode="automatic",
                evidence_status="pending",
                review_status="candidate",
                transition_history="observation>candidate",
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()


def test_alembic_upgrade_is_repeat_safe_and_matches_core_metadata(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database}")

    command.upgrade(config, "head")
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    migrated_tables = set(inspect(engine).get_table_names())
    expected_tables = set(Base.metadata.tables)
    assert expected_tables <= migrated_tables
    assert migrated_tables - expected_tables == {"alembic_version"}
    inspector = inspect(engine)
    for table_name in expected_tables:
        assert {column["name"] for column in inspector.get_columns(table_name)} == {
            column.name for column in Base.metadata.tables[table_name].columns
        }

    event_id = str(uuid4())
    with engine.begin() as connection:
        connection.execute(
            Base.metadata.tables["sites"].insert(),
            {
                "site_id": "migration-site",
                "name": "Migration School",
                "timezone_name": "Asia/Almaty",
                "created_at": NOW,
            },
        )
        connection.execute(
            Base.metadata.tables["model_artifacts"].insert(),
            {
                "artifact_id": "migration-artifact",
                "schema_version": "model-artifact.v1",
                "analytic": "person",
                "sha256": "a" * 64,
                "source": "s3://models/person.onnx",
                "commercial_rights": {},
                "class_list": ["person"],
                "preprocessing": "letterbox",
                "created_at": NOW,
            },
        )
        connection.execute(
            Base.metadata.tables["cameras"].insert(),
            {
                "camera_id": "migration-camera",
                "site_id": "migration-site",
                "name": "Migration Camera",
                "source_reference": "nvr://camera/migration",
                "codec": "h264",
                "state": "online",
                "enabled": True,
                "created_at": NOW,
            },
        )
        connection.execute(
            Base.metadata.tables["candidate_events"].insert(),
            {
                "event_id": event_id,
                "schema_version": "candidate-event.v1",
                "dedupe_key": "migration-candidate",
                "camera_id": "migration-camera",
                "module": "person",
                "opened_at": NOW,
                "last_seen_at": NOW,
                "peak_confidence": 0.8,
                "reason": "test",
                "model_artifact_id": "migration-artifact",
                "gate_mode": "operator",
                "evidence_status": "pending",
                "review_status": "candidate",
                "transition_history": "observation>candidate",
                "created_at": NOW,
            },
        )
        connection.execute(
            Base.metadata.tables["audit_entries"].insert(),
            {
                "audit_id": str(uuid4()),
                "occurred_at": NOW,
                "actor_user_id": None,
                "action": "migration.created",
                "entity_type": "migration",
                "entity_id": "0001",
                "payload": {},
                "idempotency_key": "migration-audit",
            },
        )

    with engine.begin() as connection:
        with pytest.raises(IntegrityError, match="append-only"):
            connection.execute(
                Base.metadata.tables["audit_entries"]
                .update()
                .where(Base.metadata.tables["audit_entries"].c.idempotency_key == "migration-audit")
                .values(action="migration.changed")
            )
    with engine.begin() as connection:
        with pytest.raises(IntegrityError, match="confirmed operator"):
            connection.execute(
                Base.metadata.tables["notification_outbox"].insert(),
                {
                    "outbox_id": str(uuid4()),
                    "event_id": event_id,
                    "idempotency_key": "migration-outbox",
                    "status": "pending",
                    "payload": {},
                    "available_at": NOW,
                    "created_at": NOW,
                },
            )
    with engine.begin() as connection:
        with pytest.raises(IntegrityError, match="evidence duration"):
            connection.execute(
                Base.metadata.tables["evidence"].insert(),
                {
                    "evidence_id": str(uuid4()),
                    "event_id": event_id,
                    "object_key": "events/migration-continuous.mp4",
                    "sha256": "e" * 64,
                    "codec": "h264",
                    "start_at": NOW,
                    "end_at": NOW + timedelta(seconds=11),
                    "source_reference": "nvr://camera/migration",
                    "status": "pending",
                    "created_at": NOW,
                },
            )


def test_postgresql_offline_migration_uses_integrity_sqlstates() -> None:
    output = StringIO()
    config = Config("alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+psycopg://localhost/kuzet_pilot_test",
    )

    command.upgrade(config, "head", sql=True)

    assert output.getvalue().count("ERRCODE = '23514'") >= 3


def test_concurrent_idempotent_retries_return_single_rows(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'concurrent.sqlite3'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name="Pilot School")
    repository.add_camera(
        camera_id="cam-01",
        site_id="site-1",
        name="Entrance",
        source_reference="nvr://camera/01",
        codec="h264",
    )
    repository.add_model_artifact(_artifact())
    event_contract = _event()

    event_rows = _run_concurrently(lambda: repository.store_event_idempotent(event_contract))
    assert {row.event_id for row in event_rows} == {str(event_contract.event_id)}

    evidence = EvidenceInput(
        evidence_id=uuid4(),
        event_id=event_contract.event_id,
        object_key="events/concurrent.mp4",
        sha256="d" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=5),
        source_reference="nvr://camera/01?segment=5",
        status="ready",
    )
    evidence_rows = _run_concurrently(lambda: repository.add_evidence(evidence))
    assert {row.evidence_id for row in evidence_rows} == {str(evidence.evidence_id)}

    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )
    reviews = _run_concurrently(
        lambda: repository.review_event(
            event_id=event_contract.event_id,
            reviewer_id="operator-1",
            target_status="confirmed",
            idempotency_key="concurrent-review",
            notes="same review",
            reviewed_at=NOW,
        )
    )
    assert len({review.review_id for review in reviews}) == 1

    outbox_rows = _run_concurrently(
        lambda: repository.enqueue_notification(
            event_id=event_contract.event_id,
            idempotency_key="concurrent-outbox",
            payload={"connector": "telegram"},
        )
    )
    assert len({row.outbox_id for row in outbox_rows}) == 1


def test_concurrent_ready_and_failed_evidence_can_never_downgrade_ready(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'evidence-race.sqlite3'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name="Pilot School")
    repository.add_camera(
        camera_id="cam-01",
        site_id="site-1",
        name="Entrance",
        source_reference="nvr://camera/01",
        codec="h264",
    )
    repository.add_model_artifact(_artifact())
    event_contract = _event()
    repository.add_event(event_contract)
    evidence = EvidenceInput(
        evidence_id=uuid4(),
        event_id=event_contract.event_id,
        object_key="events/concurrent-finalize.mp4",
        sha256="e" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=5),
        source_reference="nvr://camera/01?segment=finalize",
        status="pending",
    )
    barrier = Barrier(2)
    outcomes: list[object] = []

    def finalize(status: str) -> None:
        barrier.wait(timeout=5)
        try:
            outcomes.append(repository.finalize_evidence(evidence, status=status))  # type: ignore[arg-type]
        except BaseException as exc:  # pragma: no cover - asserted below
            outcomes.append(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(finalize, "ready"),
            executor.submit(finalize, "failed"),
        ]
        for future in futures:
            future.result(timeout=5)

    assert repository.get_event(event_contract.event_id).evidence_status == "ready"
    with repository.session_factory() as session:
        row = session.scalar(select(EvidenceModel))
        assert row is not None
        assert row.status == "ready"
    assert len(outcomes) == 2


@pytest.mark.skipif(
    os.getenv("PILOT_TEST_DATABASE_URL") is None,
    reason="requires disposable PostgreSQL *_test database",
)
def test_postgresql_concurrent_retry_contract(repository: PilotRepository) -> None:
    event_contract = _event()
    event_rows = _run_concurrently(lambda: repository.store_event_idempotent(event_contract))
    assert len({row.event_id for row in event_rows}) == 1

    evidence = EvidenceInput(
        evidence_id=uuid4(),
        event_id=event_contract.event_id,
        object_key="events/postgresql-concurrent.mp4",
        sha256="f" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=5),
        source_reference="nvr://camera/01?segment=postgresql",
        status="ready",
    )
    assert (
        len(
            {
                row.evidence_id
                for row in _run_concurrently(lambda: repository.add_evidence(evidence))
            }
        )
        == 1
    )
    ready_event = _event()
    repository.add_event(ready_event)
    ready_evidence = EvidenceInput(
        evidence_id=uuid4(),
        event_id=ready_event.event_id,
        object_key="events/postgresql-ready-retry.mp4",
        sha256="2" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=5),
        source_reference="nvr://camera/01?segment=postgresql-ready-retry",
        status="pending",
    )
    ready_rows = _run_concurrently(
        lambda: repository.finalize_evidence(ready_evidence, status="ready")
    )
    assert {row.evidence_id for row in ready_rows} == {
        str(ready_evidence.evidence_id)
    }
    assert repository.get_event(ready_event.event_id).evidence_status == "ready"
    finalized_event = _event()
    repository.add_event(finalized_event)
    finalized = EvidenceInput(
        evidence_id=uuid4(),
        event_id=finalized_event.event_id,
        object_key="events/postgresql-finalize.mp4",
        sha256="1" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=5),
        source_reference="nvr://camera/01?segment=postgresql-finalize",
        status="pending",
    )
    barrier = Barrier(2)

    def finalize(status: str) -> object:
        barrier.wait(timeout=5)
        return repository.finalize_evidence(finalized, status=status)  # type: ignore[arg-type]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(finalize, "ready"),
            executor.submit(finalize, "failed"),
        ]
        for future in futures:
            try:
                future.result(timeout=5)
            except ValueError:
                pass
    assert repository.get_event(finalized_event.event_id).evidence_status == "ready"
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )
    assert (
        len(
            {
                row.review_id
                for row in _run_concurrently(
                    lambda: repository.review_event(
                        event_id=event_contract.event_id,
                        reviewer_id="operator-1",
                        target_status="confirmed",
                        idempotency_key="postgresql-concurrent-review",
                        notes="same review",
                        reviewed_at=NOW,
                    )
                )
            }
        )
        == 1
    )
    assert (
        len(
            {
                row.outbox_id
                for row in _run_concurrently(
                    lambda: repository.enqueue_notification(
                        event_id=event_contract.event_id,
                        idempotency_key="postgresql-concurrent-outbox",
                        payload={"connector": "telegram"},
                    )
                )
            }
        )
        == 1
    )


def test_distinct_same_timestamp_candidates_persist_and_exact_replay_converges(
    repository: PilotRepository,
) -> None:
    first = _event(
        event_id=UUID("81000000-0000-0000-0000-000000000001"),
        opened_at=NOW,
    ).model_copy(update={"reason": "track-a"})
    second = _event(
        event_id=UUID("82000000-0000-0000-0000-000000000002"),
        opened_at=NOW,
    ).model_copy(update={"reason": "track-b"})

    first_row = repository.store_event_idempotent(first)
    second_row = repository.store_event_idempotent(second)
    replayed_first = repository.store_event_idempotent(first)
    replayed_second = repository.store_event_idempotent(second)

    assert first.dedupe_key != second.dedupe_key
    assert first_row.event_id != second_row.event_id
    assert replayed_first.event_id == first_row.event_id
    assert replayed_second.event_id == second_row.event_id
    assert len(repository.list_events(opened_from=NOW, opened_to=NOW)) == 2


def test_hashless_evidence_intent_transitions_candidate_without_creating_evidence(
    repository: PilotRepository,
) -> None:
    event = _event().model_copy(update={"evidence_status": "unavailable"})
    repository.add_event(event)

    pending = repository.mark_candidate_evidence_pending(event.event_id)
    failed = repository.mark_candidate_evidence_failed(event.event_id)

    assert pending.evidence_status == "pending"
    assert failed.evidence_status == "failed"
    with repository.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceModel)) == 0
