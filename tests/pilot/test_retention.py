from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import yaml
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from protector.pilot import retention_service
from protector.pilot.audit_archive import EncryptedAuditArchiveStore
from protector.pilot.config import load_site_config
from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.retention import (
    AuditArchiveCoordinator,
    EvidenceRetentionCoordinator,
    PublishedAuditArchive,
)
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    AuditArchiveItemModel,
    AuditArchiveReceiptModel,
    AuditEntryModel,
    Base,
    CandidateEventModel,
    EvidenceModel,
)
from protector.pilot.storage.object_store import ObjectPublishError
from protector.pilot.storage.repositories import AuditEntryInput, EvidenceInput, PilotRepository

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
REPO_ROOT = Path(__file__).parents[2]


class RecordingStore:
    def __init__(self, *, fail_keys: set[str] | None = None) -> None:
        self.deleted: list[str] = []
        self.fail_keys = fail_keys or set()

    def delete(self, key: str) -> None:
        if key in self.fail_keys:
            raise ObjectPublishError("generic retention failure")
        self.deleted.append(key)


class RecordingAuditArchiveStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.published: list[tuple[str, bytes]] = []

    def publish(self, *, object_key: str, plaintext: bytes) -> PublishedAuditArchive:
        if self.fail:
            raise ObjectPublishError("archive publish failed")
        self.published.append((object_key, plaintext))
        encrypted_sha256 = hashlib.sha256(b"encrypted:" + plaintext).hexdigest()
        return PublishedAuditArchive(
            object_key=object_key,
            encrypted_sha256=encrypted_sha256,
            detached_signature="signed-archive",
            signing_key_id="audit-signing-key-1",
            canonical_receipt=(
                "schema=kuzet-audit-archive-receipt.v1\n"
                f"object_key={object_key}\n"
                f"encrypted_sha256={encrypted_sha256}\n"
                "signing_key_id=audit-signing-key-1\n"
            ),
        )


def _repository(tmp_path: Path) -> PilotRepository:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'retention.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    for site_id in ("site-1", "site-2"):
        repository.add_site(site_id=site_id, name=site_id)
        repository.add_camera(
            camera_id=f"{site_id}-cam",
            site_id=site_id,
            name="Camera",
            source_reference=f"rtsp://private/{site_id}",
            codec="h264",
        )
    repository.add_model_artifact(
        ModelArtifactV1(
            schema_version="model-artifact.v1",
            artifact_id="person-v1",
            analytic="person",
            sha256="a" * 64,
            source="registry://private",
            commercial_rights=CommercialRightsRecordV1(
                schema_version="commercial-rights.v1",
                record_id="rights",
                terms_reference="legal://rights",
                commercial_use_approved=True,
            ),
            class_list=("person",),
            preprocessing="letterbox",
        )
    )
    return repository


def _add_evidence(
    repository: PilotRepository,
    *,
    site_id: str,
    created_at: datetime,
    suffix: str,
) -> tuple[str, str]:
    event_id = uuid4()
    evidence_id = uuid4()
    repository.add_event(
        CandidateEventV1(
            schema_version="candidate-event.v1",
            event_id=event_id,
            camera_id=f"{site_id}-cam",
            module="person",
            opened_at=created_at,
            last_seen_at=created_at + timedelta(seconds=2),
            peak_confidence=0.8,
            reason="candidate",
            model_artifact_id="person-v1",
            gate_mode="operator",
            evidence_status="ready",
            review_status="candidate",
        )
    )
    key = f"events/{site_id}/{suffix}.mp4"
    repository.add_evidence(
        EvidenceInput(
            evidence_id=evidence_id,
            event_id=event_id,
            object_key=key,
            sha256="b" * 64,
            codec="h264",
            start_at=created_at,
            end_at=created_at + timedelta(seconds=4),
            source_reference="encoded-ring://private",
            status="ready",
        )
    )
    with repository.session_factory.begin() as session:
        session.get(EvidenceModel, str(evidence_id)).created_at = created_at
    return str(event_id), key


def test_retention_is_bounded_site_scoped_exact_cutoff_and_idempotent(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    old_one = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=31, seconds=1),
        suffix="old-1",
    )
    old_two = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=32),
        suffix="old-2",
    )
    exact = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=30),
        suffix="exact",
    )
    foreign = _add_evidence(
        repository,
        site_id="site-2",
        created_at=NOW - timedelta(days=90),
        suffix="foreign",
    )
    store = RecordingStore()
    coordinator = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=store,
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=1,
        clock=lambda: NOW,
    )

    first = coordinator.run_once()
    second = coordinator.run_once()
    third = coordinator.run_once()

    assert first.scanned == second.scanned == 1
    assert first.deleted == second.deleted == 1
    assert third.scanned == third.deleted == third.failed == 0
    assert set(store.deleted) == {old_one[1], old_two[1]}
    assert exact[1] not in store.deleted
    assert foreign[1] not in store.deleted
    with repository.session_factory() as session:
        rows = list(session.scalars(select(EvidenceModel)))
        states = {row.object_key: row.status for row in rows}
        event_states = {
            row.event_id: row.evidence_status
            for row in session.scalars(select(CandidateEventModel))
        }
    assert old_one[1] not in states
    assert old_two[1] not in states
    assert states[exact[1]] == "ready"
    assert states[foreign[1]] == "ready"
    assert event_states[old_one[0]] == "unavailable"
    assert event_states[old_two[0]] == "unavailable"


def test_retention_partial_failure_fails_closed_and_never_mutates_audit(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    failed = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=60),
        suffix="failed",
    )
    succeeded = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=50),
        suffix="succeeded",
    )
    repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="retention.guard",
            entity_type="site",
            entity_id="site-1",
            payload={"bounded": True},
            idempotency_key="retention-audit",
            occurred_at=NOW - timedelta(days=400),
        )
    )
    store = RecordingStore(fail_keys={failed[1]})
    result = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=store,
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=10,
        clock=lambda: NOW,
    ).run_once()

    assert result.scanned == 2
    assert result.deleted == 1
    assert result.failed == 1
    assert result.retained == 1
    assert result.failure_reasons == ("object_delete_failed",)
    with repository.session_factory() as session:
        rows = {row.object_key: row.status for row in session.scalars(select(EvidenceModel))}
        audit = list(session.scalars(select(AuditEntryModel)))
    assert rows[failed[1]] == "unavailable"
    assert succeeded[1] not in rows
    assert len(audit) == 1

    store.fail_keys.clear()
    retried = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=store,
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=10,
        clock=lambda: NOW,
    ).run_once()
    assert retried.deleted == 1
    with repository.session_factory() as session:
        assert session.scalar(
            select(EvidenceModel).where(EvidenceModel.object_key == failed[1])
        ) is None


def test_audit_archive_commits_exact_receipt_before_narrow_idempotent_prune(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    old_ids = [
        repository.append_audit(
            AuditEntryInput(
                actor_user_id=None,
                action="retention.audit",
                entity_type="site",
                entity_id="site-1",
                payload={"index": index},
                idempotency_key=f"audit-old-{index}",
                occurred_at=NOW - timedelta(days=100, seconds=index),
            )
        ).audit_id
        for index in range(3)
    ]
    foreign = repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="retention.foreign",
            entity_type="site",
            entity_id="site-2",
            payload={},
            idempotency_key="audit-foreign",
            occurred_at=NOW - timedelta(days=200),
        )
    ).audit_id
    store = RecordingAuditArchiveStore()
    pruned: list[tuple[str, tuple[str, ...]]] = []

    def prune(receipt_id: str, audit_ids: tuple[str, ...]) -> int:
        with repository.session_factory() as session:
            receipt = session.get(AuditArchiveReceiptModel, receipt_id)
            items = tuple(
                session.scalars(
                    select(AuditArchiveItemModel.audit_id)
                    .where(AuditArchiveItemModel.receipt_id == receipt_id)
                    .order_by(AuditArchiveItemModel.audit_id)
                )
            )
        assert receipt is not None
        assert receipt.archive_sha256
        assert receipt.canonical_receipt.startswith(
            "schema=kuzet-audit-archive-receipt.v1\n"
        )
        assert f"object_key={receipt.archive_object_key}\n" in receipt.canonical_receipt
        assert items == tuple(sorted(audit_ids))
        with repository.session_factory.begin() as session:
            session.execute(
                update(AuditArchiveReceiptModel)
                .where(AuditArchiveReceiptModel.receipt_id == receipt_id)
                .values(pruned_at=NOW)
            )
        pruned.append((receipt_id, audit_ids))
        return len(audit_ids)

    coordinator = AuditArchiveCoordinator(
        session_factory=repository.session_factory,
        archive_store=store,
        pruner=prune,
        pilot_site_id="site-1",
        retention_days=90,
        batch_size=2,
        clock=lambda: NOW,
    )

    first = coordinator.run_once()
    second = coordinator.run_once()
    third = coordinator.run_once()

    assert (first.archived, second.archived, third.archived) == (2, 1, 0)
    assert (first.pruned, second.pruned, third.pruned) == (2, 1, 0)
    assert len(store.published) == 2
    assert set(pruned[0][1] + pruned[1][1]) == set(old_ids)
    assert foreign not in set(pruned[0][1] + pruned[1][1])
    assert all(b'"site_id":"site-1"' in payload for _, payload in store.published)


def test_audit_archive_publish_failure_creates_no_receipt_and_never_prunes(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="retention.audit",
            entity_type="site",
            entity_id="site-1",
            payload={},
            idempotency_key="audit-failed-publish",
            occurred_at=NOW - timedelta(days=100),
        )
    )
    pruned: list[str] = []
    result = AuditArchiveCoordinator(
        session_factory=repository.session_factory,
        archive_store=RecordingAuditArchiveStore(fail=True),
        pruner=lambda receipt_id, _ids: pruned.append(receipt_id) or 0,
        pilot_site_id="site-1",
        retention_days=90,
        batch_size=10,
        clock=lambda: NOW,
    ).run_once()

    assert result.failed == 1
    assert result.archived == result.pruned == 0
    assert pruned == []
    with repository.session_factory() as session:
        assert list(session.scalars(select(AuditArchiveReceiptModel))) == []


def test_operational_migration_uses_receipt_bound_postgres_prune_without_general_flag() -> None:
    from io import StringIO

    output = StringIO()
    config = Config("alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+psycopg://localhost/kuzet_pilot_test",
    )

    command.upgrade(config, "head", sql=True)

    sql = output.getvalue()
    assert "runtime_session_id" in sql
    assert "audit_archive_receipts" in sql
    assert "audit_archive_items" in sql
    assert "audit_item_compaction_authorizations" in sql
    assert "pilot_prune_archived_audit" in sql
    assert "SECURITY DEFINER" in sql
    assert "audit_prune_authorizations" in sql
    assert "pg_backend_pid()" in sql and "txid_current()" in sql
    assert "audit.occurred_at IS DISTINCT FROM item.occurred_at" in sql
    assert "audit.occurred_at >= receipt_cutoff" in sql
    assert "site_count = 1" in sql
    assert "pilot_reject_audit_archive_receipt_mutation" in sql
    assert sql.index("receipt.pruned_at IS NOT NULL") < sql.index(
        "audit archive receipt item count is inconsistent"
    )
    assert "REVOKE ALL ON FUNCTION pilot_prune_archived_audit(text) FROM PUBLIC" in sql
    scope_check = sql.index("audit archive receipt scope is inconsistent")
    audit_delete = sql.index("DELETE FROM public.audit_entries AS audit")
    item_delete = sql.index("DELETE FROM public.audit_archive_items AS item")
    receipt_update = sql.index("UPDATE public.audit_archive_receipts")
    assert scope_check < audit_delete < item_delete < receipt_update
    assert "authorization.receipt_id = OLD.receipt_id" in sql
    assert (
        "REVOKE ALL ON TABLE audit_item_compaction_authorizations FROM PUBLIC"
        in sql
    )
    assert "TO kuzet_retention" in sql
    assert "TO kuzet;" not in sql
    assert "session_replication_role" not in sql
    assert "DISABLE TRIGGER" not in sql


def test_pending_audit_prune_retry_compacts_items_and_keeps_idempotent_receipt(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    audit_id = repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="retention.retry",
            entity_type="site",
            entity_id="site-1",
            payload={},
            idempotency_key="audit-prune-retry",
            occurred_at=NOW - timedelta(days=100),
        )
    ).audit_id
    attempts = 0

    def prune(receipt_id: str, audit_ids: tuple[str, ...]) -> int:
        nonlocal attempts
        attempts += 1
        with repository.session_factory() as session:
            receipt = session.get(AuditArchiveReceiptModel, receipt_id)
            assert receipt is not None
            if receipt.pruned_at is not None:
                return receipt.row_count
        if attempts == 1:
            return 0
        assert audit_ids == (audit_id,)
        # Portable simulation of the migration-owned transaction. Generated
        # PostgreSQL SQL separately proves the exact trigger authorization.
        with repository.session_factory.begin() as session:
            session.execute(
                delete(AuditArchiveItemModel).where(
                    AuditArchiveItemModel.receipt_id == receipt_id
                )
            )
            session.execute(
                update(AuditArchiveReceiptModel)
                .where(AuditArchiveReceiptModel.receipt_id == receipt_id)
                .values(pruned_at=NOW)
            )
        return len(audit_ids)

    store = RecordingAuditArchiveStore()
    coordinator = AuditArchiveCoordinator(
        session_factory=repository.session_factory,
        archive_store=store,
        pruner=prune,
        pilot_site_id="site-1",
        retention_days=90,
        batch_size=10,
        clock=lambda: NOW,
    )

    failed = coordinator.run_once()
    with repository.session_factory() as session:
        pending = session.scalar(select(AuditArchiveReceiptModel))
        assert pending is not None and pending.pruned_at is None
        assert session.query(AuditArchiveItemModel).count() == 1
    retried = coordinator.run_once()

    assert failed.failure_reasons == ("receipt_bound_prune_incomplete",)
    assert (retried.archived, retried.pruned, retried.failed) == (0, 1, 0)
    assert len(store.published) == 1
    with repository.session_factory() as session:
        receipt = session.scalar(select(AuditArchiveReceiptModel))
        assert receipt is not None and receipt.pruned_at is not None
        assert receipt.canonical_receipt.startswith(
            "schema=kuzet-audit-archive-receipt.v1\n"
        )
        assert session.query(AuditArchiveItemModel).count() == 0
    assert prune(receipt.receipt_id, (audit_id,)) == 1


def test_audit_item_staging_compacts_each_cycle_but_receipt_roots_remain_bounded(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    for cycle in range(5):
        receipt_id = str(uuid4())
        with repository.session_factory.begin() as session:
            session.add(
                AuditArchiveReceiptModel(
                    receipt_id=receipt_id,
                    site_id="site-1",
                    cutoff_at=NOW,
                    archive_object_key=f"audit/site-1/{cycle}.jsonl.age",
                    archive_sha256=f"{cycle:x}".rjust(64, "0"),
                    detached_signature="bounded-signature",
                    signing_key_id="audit-key",
                    canonical_receipt=(
                        "schema=kuzet-audit-archive-receipt.v1\n"
                        f"object_key=audit/site-1/{cycle}.jsonl.age\n"
                    ),
                    row_count=100,
                    created_at=NOW,
                )
            )
            session.flush()
            session.add_all(
                AuditArchiveItemModel(
                    receipt_id=receipt_id,
                    audit_id=str(uuid4()),
                    occurred_at=NOW - timedelta(days=100),
                    row_sha256=f"{item:x}".rjust(64, "0"),
                )
                for item in range(100)
            )
        with repository.session_factory() as session:
            protected = session.scalar(
                select(AuditArchiveItemModel).where(
                    AuditArchiveItemModel.receipt_id == receipt_id
                )
            )
            assert protected is not None
            with pytest.raises(ValueError, match="append-only"):
                session.delete(protected)
                session.flush()
            session.rollback()
        # Simulate the narrowly authorized migration function after its exact
        # receipt/site/cutoff checks and audit-row deletion have succeeded.
        with repository.session_factory.begin() as session:
            session.execute(
                delete(AuditArchiveItemModel).where(
                    AuditArchiveItemModel.receipt_id == receipt_id
                )
            )
            session.execute(
                update(AuditArchiveReceiptModel)
                .where(AuditArchiveReceiptModel.receipt_id == receipt_id)
                .values(pruned_at=NOW)
            )
        with repository.session_factory() as session:
            assert session.query(AuditArchiveItemModel).count() == 0
            receipts = session.query(AuditArchiveReceiptModel).all()
            assert len(receipts) == cycle + 1
            assert all(receipt.row_count <= 10_000 for receipt in receipts)
            assert all(
                len(receipt.canonical_receipt.encode("utf-8")) <= 16_384
                and len(receipt.detached_signature.encode("utf-8")) <= 16_384
                for receipt in receipts
            )


@pytest.mark.parametrize(
    ("row_count", "signature", "canonical"),
    (
        (10_001, "signature", "receipt"),
        (1, "x" * 16_385, "receipt"),
        (1, "signature", "x" * 16_385),
    ),
)
def test_durable_receipt_root_has_enforced_row_and_archive_batch_bounds(
    tmp_path: Path,
    row_count: int,
    signature: str,
    canonical: str,
) -> None:
    repository = _repository(tmp_path)
    with pytest.raises(IntegrityError):
        with repository.session_factory.begin() as session:
            session.add(
                AuditArchiveReceiptModel(
                    receipt_id=str(uuid4()),
                    site_id="site-1",
                    cutoff_at=NOW,
                    archive_object_key=f"audit/site-1/{uuid4()}.jsonl.age",
                    archive_sha256="a" * 64,
                    detached_signature=signature,
                    signing_key_id="audit-key",
                    canonical_receipt=canonical,
                    row_count=row_count,
                    created_at=NOW,
                )
            )


def test_audit_archive_caps_bytes_and_fails_closed_on_multisite_unattributed_rows(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="retention.attributed",
            entity_type="site",
            entity_id="site-1",
            payload={},
            idempotency_key="audit-attributed",
            occurred_at=NOW - timedelta(days=100),
        )
    )
    with repository.session_factory.begin() as session:
        session.add(
            AuditEntryModel(
                audit_id=str(uuid4()),
                site_id=None,
                occurred_at=NOW - timedelta(days=100),
                actor_user_id=None,
                action="legacy.unknown",
                entity_type="unknown",
                entity_id="unknown",
                payload={},
                idempotency_key="legacy-unknown",
            )
        )
    store = RecordingAuditArchiveStore()
    coordinator = AuditArchiveCoordinator(
        session_factory=repository.session_factory,
        archive_store=store,
        pruner=lambda _receipt_id, audit_ids: len(audit_ids),
        pilot_site_id="site-1",
        retention_days=90,
        batch_size=10,
        max_archive_bytes=1_024,
        clock=lambda: NOW,
    )

    unattributed = coordinator.run_once()
    assert unattributed.failure_reasons == ("unattributed_audit_rows",)

    oversized_root = tmp_path / "oversized"
    oversized_root.mkdir()
    oversized_repository = _repository(oversized_root)
    attributed = oversized_repository.append_audit(
        AuditEntryInput(
            actor_user_id=None,
            action="retention.large",
            entity_type="site",
            entity_id="site-1",
            payload={"bounded": "x" * 2_000},
            idempotency_key="audit-large",
            occurred_at=NOW - timedelta(days=100),
        )
    )
    oversized = AuditArchiveCoordinator(
        session_factory=oversized_repository.session_factory,
        archive_store=store,
        pruner=lambda _receipt_id, audit_ids: len(audit_ids),
        pilot_site_id="site-1",
        retention_days=90,
        batch_size=10,
        max_archive_bytes=1_024,
        clock=lambda: NOW,
    ).run_once()

    assert attributed.site_id == "site-1"
    assert oversized.failure_reasons == ("audit_row_exceeds_archive_bound",)
    assert store.published == []


def test_failed_tombstone_retry_cannot_starve_newer_ready_expiry(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    oldest = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=90),
        suffix="permanent-failure",
    )
    newer = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=60),
        suffix="newer-ready",
    )
    store = RecordingStore(fail_keys={oldest[1]})
    coordinator = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=store,
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=1,
        clock=lambda: NOW,
    )

    assert coordinator.run_once().failed == 1
    assert coordinator.run_once().deleted == 1
    assert newer[1] in store.deleted


def test_expiring_one_clip_keeps_event_ready_while_another_ready_clip_remains(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    event_id, old_key = _add_evidence(
        repository,
        site_id="site-1",
        created_at=NOW - timedelta(days=60),
        suffix="old-clip",
    )
    newer_evidence_id = uuid4()
    newer_key = "events/site-1/newer-clip.mp4"
    repository.add_evidence(
        EvidenceInput(
            evidence_id=newer_evidence_id,
            event_id=UUID(event_id),
            object_key=newer_key,
            sha256="c" * 64,
            codec="h264",
            start_at=NOW - timedelta(days=1),
            end_at=NOW - timedelta(days=1) + timedelta(seconds=4),
            source_reference="encoded-ring://private",
            status="ready",
        )
    )
    with repository.session_factory.begin() as session:
        session.get(EvidenceModel, str(newer_evidence_id)).created_at = NOW - timedelta(days=1)

    result = EvidenceRetentionCoordinator(
        session_factory=repository.session_factory,
        object_store=RecordingStore(),
        pilot_site_id="site-1",
        retention_days=30,
        batch_size=10,
        clock=lambda: NOW,
    ).run_once()

    assert result.deleted == 1
    with repository.session_factory() as session:
        event = session.get(CandidateEventModel, event_id)
        keys = set(session.scalars(select(EvidenceModel.object_key)))
    assert event.evidence_status == "ready"
    assert old_key not in keys
    assert newer_key in keys


@pytest.mark.parametrize(
    ("site_id", "retention_days", "batch_size"),
    (("", 30, 10), ("site-1", 0, 10), ("site-1", 30, 0), ("x" * 129, 30, 10)),
)
def test_retention_configuration_is_finite_and_bounded(
    tmp_path: Path,
    site_id: str,
    retention_days: int,
    batch_size: int,
) -> None:
    repository = _repository(tmp_path)
    with pytest.raises(ValueError):
        EvidenceRetentionCoordinator(
            session_factory=repository.session_factory,
            object_store=RecordingStore(),
            pilot_site_id=site_id,
            retention_days=retention_days,
            batch_size=batch_size,
            clock=lambda: NOW,
        )


def test_backup_and_restore_refuse_unsafe_targets_before_invoking_tools(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    (unsafe / "unrelated").write_text("preserve")
    common = {
        **os.environ,
        "PILOT_SITE_ID": "site-1",
        "PILOT_BACKUP_TARGET": str(unsafe),
    }

    backup = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/pilot/backup.sh")],
        env=common,
        text=True,
        capture_output=True,
        check=False,
    )
    assert backup.returncode != 0
    assert "marker" in backup.stderr.lower()
    assert (unsafe / "unrelated").read_text() == "preserve"

    restore_target = tmp_path / "existing-restore"
    restore_target.mkdir()
    (restore_target / "keep").write_text("keep")
    restore = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/pilot/restore.sh")],
        env={
            **common,
            "PILOT_RESTORE_SOURCE": str(tmp_path / "missing-backup"),
            "PILOT_RESTORE_DATABASE_NAME": "fresh_restore",
            "PILOT_RESTORE_EVIDENCE_TARGET": str(restore_target),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert restore.returncode != 0
    assert (restore_target / "keep").read_text() == "keep"


def test_fake_tools_prove_backup_pending_then_fresh_restore_receipt(tmp_path: Path) -> None:
    secret_root = tmp_path / "fixed-secrets"
    secret_root.mkdir()
    for name, value in {
        "pg_service.conf": "[kuzet_backup]\ndbname=source_db\n",
        "pg_restore_service.conf": "[kuzet_restore]\ndbname=fresh_restore\n",
        "pgpass": "*:*:*:*:fixture-only\n",
        "backup_age_recipient": "age1fixture\n",
        "backup_age_identity": "AGE-SECRET-KEY-FIXTURE\n",
        "backup_signing_private_key": "fixture-private-signing-key\n",
        "backup_signing_public_key": "fixture-public-signing-key\n",
        "restore_receipt_signing_private_key": "fixture-restore-private-key\n",
        "restore_receipt_signing_public_key": "fixture-restore-public-key\n",
        "aws_credentials": "[default]\nfixture=yes\n",
        "kz_storage_attestation_public_key": "fixture-public-key\n",
        "kz_storage_verifier_record": "fixture-volume-verifier-record\n",
    }.items():
        (secret_root / name).write_text(value)

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()

    def tool(name: str, body: str) -> None:
        path = fake_bin / name
        path.write_text(body)
        path.chmod(0o700)

    tool(
        "age",
        """#!/bin/bash
set -eu
out=
input=
while (($#)); do
  case "$1" in
    --output) out=$2; shift 2 ;;
    --recipients-file|--identity) shift 2 ;;
    --decrypt) shift ;;
    *) input=$1; shift ;;
  esac
done
if [[ -n ${FAKE_TOOL_TRACE:-} ]]; then
  printf 'age\n' >> "$FAKE_TOOL_TRACE"
fi
cp "$input" "$out"
if [[ -n ${FAKE_DECRYPT_DATABASE_BYTES:-} && "$input" = *database.dump.age ]]; then
  python3 - "$out" "$FAKE_DECRYPT_DATABASE_BYTES" <<'PY'
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("r+b") as output:
    output.truncate(int(sys.argv[2]))
PY
fi
""",
    )
    tool(
        "openssl",
        """#!/bin/bash
set -eu
mode=
key=
signature=
output=
input=
while (($#)); do
  case "$1" in
    dgst|-sha256) shift ;;
    -sign) mode=sign; key=$2; shift 2 ;;
    -verify) mode=verify; key=$2; shift 2 ;;
    -signature) signature=$2; shift 2 ;;
    -out) output=$2; shift 2 ;;
    *) input=$1; shift ;;
  esac
done
case "$mode" in
  sign)
    case "$key" in
      */backup_signing_private_key|*/restore_receipt_signing_private_key) : ;;
      *) exit 3 ;;
    esac
    sha256sum "$input" | awk '{print $1}' > "$output"
    ;;
  verify)
    case "$key" in
      */backup_signing_public_key|*/restore_receipt_signing_public_key)
        expected=$(sha256sum "$input" | awk '{print $1}')
        actual=$(cat "$signature")
        [[ "$actual" = "$expected" ]]
        ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 2 ;;
esac
""",
    )
    tool(
        "findmnt",
        """#!/bin/bash
set -eu
target=
while (($#)); do
  case "$1" in
    -T) target=$2; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$target" ]]
printf '%s fixture-volume-uuid\n' "$target"
""",
    )
    tool(
        "pg_dump",
        """#!/bin/bash
set -eu
for argument in "$@"; do
  case "$argument" in --file=*) output=${argument#--file=} ;; esac
done
if [[ -n ${FAKE_DUMP_BYTES:-} ]]; then
  python3 - "$output" "$FAKE_DUMP_BYTES" <<'PY'
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("wb") as output:
    output.truncate(int(sys.argv[2]))
PY
else
  printf FAKE_DATABASE_DUMP > "$output"
fi
""",
    )
    tool(
        "backup-snapshot",
        """#!/usr/bin/env python3
import argparse
import hashlib
import os

parser = argparse.ArgumentParser()
parser.add_argument("--dump", required=True)
parser.add_argument("--metadata", required=True)
parser.add_argument("--evidence-manifest", required=True)
parser.add_argument("--service")
parser.add_argument("--site-id")
parser.add_argument("--max-database-bytes")
parser.add_argument("--max-evidence-objects")
parser.add_argument("--max-manifest-bytes")
arguments = parser.parse_args()
dump_bytes = int(os.environ.get("FAKE_DUMP_BYTES", "0"))
with open(arguments.dump, "wb") as output:
    if dump_bytes:
        output.truncate(dump_bytes)
    else:
        output.write(b"FAKE_DATABASE_DUMP")
database_bytes = os.environ.get("FAKE_DATABASE_BYTES", "18")
with open(arguments.metadata, "w", encoding="utf-8") as output:
    output.write(
        "source_database=source_db\\n"
        "schema_revision=0004_operational_retention\\n"
        f"database_bytes={database_bytes}\\n"
    )
with open(arguments.evidence_manifest, "w", encoding="utf-8") as output:
    output.write(f"{hashlib.sha256(b'video').hexdigest()}\\tevent.mp4\\n")
""",
    )
    tool(
        "psql",
        """#!/bin/bash
set -eu
if [[ -n ${FAKE_TOOL_TRACE:-} ]]; then
  printf 'psql\n' >> "$FAKE_TOOL_TRACE"
fi
arguments="$*"
case "$arguments" in
  *pg_database_size*) printf '%s\n' "${FAKE_DATABASE_BYTES:-18}" ;;
  *current_database*) printf '%s\n' "${FAKE_TARGET_DB:-source_db}" ;;
  *fresh_database_gate*) printf '%s\n' "${FAKE_DATABASE_OBJECT_COUNT:-0}" ;;
  *restored_evidence_manifest*) printf '%s\tevent.mp4\n' "$(printf video | sha256sum | awk '{print $1}')" ;;
  *version_num*) printf '0004_operational_retention\n' ;;
  *"SELECT site_id"*) printf 'site-1\n' ;;
  *) exit 2 ;;
esac
""",
    )
    tool(
        "pg_restore",
        """#!/bin/bash
set -eu
case " $* " in
  *" --list "*)
    if [[ -n ${FAKE_TOOL_TRACE:-} ]]; then printf 'pg_restore-list\n' >> "$FAKE_TOOL_TRACE"; fi
    printf 'fixture archive\n'
    ;;
  *)
    if [[ -n ${FAKE_TOOL_TRACE:-} ]]; then printf 'pg_restore-apply\n' >> "$FAKE_TOOL_TRACE"; fi
    ;;
esac
""",
    )
    tool(
        "aws",
        """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

arguments = sys.argv[1:]
if "list-objects-v2" in arguments:
    assert arguments[arguments.index("--prefix") + 1] == "pilot-evidence/site-1/"
    assert "--max-items" in arguments
    key = os.environ.get("FAKE_INVENTORY_KEY", "event.mp4")
    contents = [{
        "Key": f"pilot-evidence/site-1/{key}",
        "Size": 5,
        "ETag": '"0123456789abcdef0123456789abcdef"',
    }]
    if os.environ.get("FAKE_INVENTORY_OVER_LIMIT"):
        contents.append(
            {
                "Key": "pilot-evidence/site-1/second.mp4",
                "Size": 5,
                "ETag": '"fedcba9876543210fedcba9876543210"',
            }
        )
    print(json.dumps({"Contents": contents}))
elif "get-object" in arguments:
    key = arguments[arguments.index("--key") + 1]
    assert key.startswith("pilot-evidence/site-1/")
    assert arguments[arguments.index("--if-match") + 1] == '"0123456789abcdef0123456789abcdef"'
    assert arguments[arguments.index("--range") + 1] == "bytes=0-5"
    destination = pathlib.Path(arguments[-1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(
        b"growth" if os.environ.get("FAKE_OBJECT_GROWS_AFTER_LIST") else b"video"
    )
    print(json.dumps({"ChecksumSHA256": "fixture"}))
else:
    raise SystemExit(2)
""",
    )

    fixture_scripts = tmp_path / "scripts"
    fixture_scripts.mkdir()
    for name in ("backup.sh", "restore.sh"):
        source = REPO_ROOT / "scripts/pilot" / name
        fixture = fixture_scripts / name
        fixture.write_text(source.read_text().replace("/run/secrets", str(secret_root)))
        fixture.chmod(0o700)

    def write_storage_marker(directory: Path, filename: str, schema: str) -> None:
        now_epoch = int(datetime.now(UTC).timestamp())
        verifier_digest = hashlib.sha256(
            (secret_root / "kz_storage_verifier_record").read_bytes()
        ).hexdigest()
        marker = directory / filename
        marker.write_text(
            f"schema={schema}\n"
            "site_id=site-1\n"
            "country=KZ\n"
            f"target_path={directory}\n"
            f"mount_path={directory}\n"
            "volume_uuid=fixture-volume-uuid\n"
            "encryption=luks2\n"
            f"verifier_record_sha256={verifier_digest}\n"
            f"attested_at_epoch={now_epoch - 60}\n"
            f"valid_until_epoch={now_epoch + 3600}\n"
        )
        marker.with_name(f"{marker.name}.sig").write_text("fixture-signature\n")

    backup_target = tmp_path / "encrypted-backups"
    backup_target.mkdir()
    write_storage_marker(
        backup_target,
        ".kuzet-pilot-backup-target.v1",
        "kuzet-pilot-backup-target.v1",
    )
    config = tmp_path / "site.yaml"
    model = tmp_path / "model-register.json"
    config.write_text("site: site-1\n")
    model.write_text('{"model":"person-v1"}\n')
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "PILOT_SITE_ID": "site-1",
        "PILOT_BACKUP_TARGET": str(backup_target),
        "PILOT_KZ_OBJECT_ENDPOINT": "https://objects.example.kz",
        "PILOT_EVIDENCE_BUCKET": "pilot-evidence",
        "PILOT_EVIDENCE_PREFIX": "pilot-evidence/site-1",
        "PILOT_CONFIG_MANIFEST": str(config),
        "PILOT_MODEL_MANIFEST": str(model),
        "PILOT_BACKUP_SNAPSHOT_HELPER": str(fake_bin / "backup-snapshot"),
    }
    replay_target = tmp_path / "replayed-marker-backups"
    replay_target.mkdir()
    original_marker = backup_target / ".kuzet-pilot-backup-target.v1"
    shutil.copy2(original_marker, replay_target / original_marker.name)
    shutil.copy2(
        original_marker.with_name(f"{original_marker.name}.sig"),
        replay_target / f"{original_marker.name}.sig",
    )
    replay_trace = tmp_path / "replayed-marker-tools.log"
    replay = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(replay_target),
            "FAKE_TOOL_TRACE": str(replay_trace),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert replay.returncode != 0
    assert "attestation" in replay.stderr
    assert not replay_trace.exists()
    assert not list(replay_target.glob("backup-*"))
    mismatch_target = tmp_path / "mismatch-backups"
    mismatch_target.mkdir()
    write_storage_marker(
        mismatch_target,
        ".kuzet-pilot-backup-target.v1",
        "kuzet-pilot-backup-target.v1",
    )
    mismatch = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(mismatch_target),
            "FAKE_INVENTORY_KEY": "same-size-substitute.mp4",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert mismatch.returncode != 0
    assert "database evidence manifest" in mismatch.stderr
    assert not list(mismatch_target.glob("backup-*"))

    reserved_target = tmp_path / "reserved-key-backups"
    reserved_target.mkdir()
    write_storage_marker(
        reserved_target,
        ".kuzet-pilot-backup-target.v1",
        "kuzet-pilot-backup-target.v1",
    )
    reserved = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(reserved_target),
            "FAKE_INVENTORY_KEY": "evidence-files.sha256",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert reserved.returncode != 0
    assert "reserved" in reserved.stderr

    bounded_listing_target = tmp_path / "bounded-listing-backups"
    bounded_listing_target.mkdir()
    write_storage_marker(
        bounded_listing_target,
        ".kuzet-pilot-backup-target.v1",
        "kuzet-pilot-backup-target.v1",
    )
    bounded_listing = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(bounded_listing_target),
            "PILOT_BACKUP_MAX_EVIDENCE_OBJECTS": "1",
            "FAKE_INVENTORY_OVER_LIMIT": "1",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert bounded_listing.returncode != 0
    assert "object inventory" in bounded_listing.stderr
    assert not list(bounded_listing_target.glob("backup-*"))

    growth_target = tmp_path / "post-inventory-growth-backups"
    growth_target.mkdir()
    write_storage_marker(
        growth_target,
        ".kuzet-pilot-backup-target.v1",
        "kuzet-pilot-backup-target.v1",
    )
    growth = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(growth_target),
            "FAKE_OBJECT_GROWS_AFTER_LIST": "1",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert growth.returncode != 0
    assert "size changed after inventory" in growth.stderr
    assert not list(growth_target.glob("backup-*"))

    oversized_database_target = tmp_path / "oversized-database-backups"
    oversized_database_target.mkdir()
    write_storage_marker(
        oversized_database_target,
        ".kuzet-pilot-backup-target.v1",
        "kuzet-pilot-backup-target.v1",
    )
    oversized_database = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(oversized_database_target),
            "FAKE_DATABASE_BYTES": "10737418241",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert oversized_database.returncode != 0
    assert "database size exceeds" in oversized_database.stderr
    assert not list(oversized_database_target.glob("backup-*"))

    oversized_dump_target = tmp_path / "oversized-dump-backups"
    oversized_dump_target.mkdir()
    write_storage_marker(
        oversized_dump_target,
        ".kuzet-pilot-backup-target.v1",
        "kuzet-pilot-backup-target.v1",
    )
    oversized_dump = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={
            **environment,
            "PILOT_BACKUP_TARGET": str(oversized_dump_target),
            "PILOT_BACKUP_MAX_DATABASE_BYTES": "16",
            "FAKE_DATABASE_BYTES": "16",
            "FAKE_DUMP_BYTES": "17",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert oversized_dump.returncode != 0
    assert "database dump exceeds" in oversized_dump.stderr
    assert not list(oversized_dump_target.glob("backup-*"))

    backup = subprocess.run(
        [str(fixture_scripts / "backup.sh")],
        env={**environment, "FAKE_POST_INVENTORY_EXTRA_OBJECT": "1"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert backup.returncode == 0, backup.stderr
    assert "acceptance remains pending" in backup.stdout
    backup_runs = list(backup_target.glob("backup-*"))
    assert len(backup_runs) == 1
    assert {path.name for path in backup_runs[0].iterdir()} == {
        "backup-receipt.txt.age",
        "checksums.sha256",
        "checksums.sha256.sig",
        "config-manifest.age",
        "database.dump.age",
        "database-evidence.tsv.age",
        "evidence.tar.age",
        "manifest.txt.age",
        "model-manifest.age",
    }
    assert "pending_fresh_target_restore" in (
        backup_runs[0] / "backup-receipt.txt.age"
    ).read_text()

    volume = tmp_path / "encrypted-volume"
    volume.mkdir()
    write_storage_marker(
        volume,
        ".kuzet-pilot-encrypted-volume.v1",
        "kuzet-pilot-encrypted-volume.v1",
    )
    receipts = tmp_path / "restore-receipts"
    receipts.mkdir()
    write_storage_marker(
        receipts,
        ".kuzet-pilot-restore-receipts.v1",
        "kuzet-pilot-restore-receipts.v1",
    )
    restore_environment = {
        **environment,
        "FAKE_TARGET_DB": "fresh_restore",
        "PILOT_RESTORE_SOURCE": str(backup_runs[0]),
        "PILOT_RESTORE_DATABASE_NAME": "fresh_restore",
        "PILOT_RESTORE_EVIDENCE_TARGET": str(volume / "restored-site-1"),
        "PILOT_RESTORE_RECEIPT_TARGET": str(receipts),
        "PILOT_EXPECTED_SCHEMA_REVISION": "0004_operational_retention",
        "PILOT_EXPECTED_CONFIG_SHA256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "PILOT_EXPECTED_MODEL_SHA256": hashlib.sha256(model.read_bytes()).hexdigest(),
    }

    forged_backup = tmp_path / "forged-backup"
    shutil.copytree(backup_runs[0], forged_backup)
    canonical_artifacts = (
        "database.dump.age",
        "database-evidence.tsv.age",
        "evidence.tar.age",
        "manifest.txt.age",
        "backup-receipt.txt.age",
        "config-manifest.age",
        "model-manifest.age",
    )
    for artifact in canonical_artifacts:
        (forged_backup / artifact).write_bytes(f"attacker-replaced-{artifact}".encode())
    (forged_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((forged_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    forged_trace = tmp_path / "forged-restore-tools.log"
    forged_restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_TOOL_TRACE": str(forged_trace),
            "PILOT_RESTORE_SOURCE": str(forged_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(volume / "rejected-forged"),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert forged_restore.returncode != 0
    assert "signature" in forged_restore.stderr
    assert not forged_trace.exists()
    assert not (volume / "rejected-forged").exists()

    oversized_ciphertext_backup = tmp_path / "oversized-ciphertext-backup"
    shutil.copytree(backup_runs[0], oversized_ciphertext_backup)
    with (oversized_ciphertext_backup / "database.dump.age").open("r+b") as artifact:
        artifact.truncate(1_048_593)
    (oversized_ciphertext_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((oversized_ciphertext_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    (oversized_ciphertext_backup / "checksums.sha256.sig").write_text(
        hashlib.sha256(
            (oversized_ciphertext_backup / "checksums.sha256").read_bytes()
        ).hexdigest()
        + "\n"
    )
    oversized_ciphertext_trace = tmp_path / "oversized-ciphertext-tools.log"
    oversized_ciphertext_restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_TOOL_TRACE": str(oversized_ciphertext_trace),
            "PILOT_RESTORE_SOURCE": str(oversized_ciphertext_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(
                volume / "rejected-oversized-ciphertext"
            ),
            "PILOT_RESTORE_MAX_DATABASE_BYTES": "16",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert oversized_ciphertext_restore.returncode != 0
    assert "encrypted database dump exceeds" in oversized_ciphertext_restore.stderr
    assert not oversized_ciphertext_trace.exists()
    assert not (volume / "rejected-oversized-ciphertext").exists()

    oversized_plaintext_trace = tmp_path / "oversized-plaintext-tools.log"
    oversized_plaintext_restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_TOOL_TRACE": str(oversized_plaintext_trace),
            "FAKE_DECRYPT_DATABASE_BYTES": "33",
            "PILOT_RESTORE_EVIDENCE_TARGET": str(
                volume / "rejected-oversized-plaintext"
            ),
            "PILOT_RESTORE_MAX_DATABASE_BYTES": "32",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert oversized_plaintext_restore.returncode != 0
    assert "decrypted database dump exceeds" in oversized_plaintext_restore.stderr
    assert set(oversized_plaintext_trace.read_text().splitlines()) == {"age"}
    assert not (volume / "rejected-oversized-plaintext").exists()

    inconsistent_manifest_backup = tmp_path / "inconsistent-manifest-backup"
    shutil.copytree(backup_runs[0], inconsistent_manifest_backup)
    (inconsistent_manifest_backup / "config-manifest.age").write_text(
        "site: attacker-replacement\n"
    )
    (inconsistent_manifest_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((inconsistent_manifest_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    (inconsistent_manifest_backup / "checksums.sha256.sig").write_text(
        hashlib.sha256(
            (inconsistent_manifest_backup / "checksums.sha256").read_bytes()
        ).hexdigest()
        + "\n"
    )
    inconsistent_trace = tmp_path / "inconsistent-manifest-tools.log"
    inconsistent_restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_TOOL_TRACE": str(inconsistent_trace),
            "PILOT_RESTORE_SOURCE": str(inconsistent_manifest_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(
                volume / "rejected-inconsistent-manifest"
            ),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert inconsistent_restore.returncode != 0
    assert "configuration/model manifest integrity" in inconsistent_restore.stderr
    assert set(inconsistent_trace.read_text().splitlines()) == {"age"}
    assert not (volume / "rejected-inconsistent-manifest").exists()

    malicious_backup = tmp_path / "malicious-backup"
    shutil.copytree(backup_runs[0], malicious_backup)
    unpacked = tmp_path / "malicious-evidence"
    unpacked.mkdir()
    with tarfile.open(malicious_backup / "evidence.tar.age") as archive:
        archive.extractall(unpacked, filter="data")
    (unpacked / "unexpected-same-bound.mp4").write_bytes(b"")
    with tarfile.open(malicious_backup / "evidence.tar.age", "w") as archive:
        archive.add(unpacked, arcname=".")
    (malicious_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((malicious_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    (malicious_backup / "checksums.sha256.sig").write_text(
        hashlib.sha256(
            (malicious_backup / "checksums.sha256").read_bytes()
        ).hexdigest()
        + "\n"
    )
    rejected = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "PILOT_RESTORE_SOURCE": str(malicious_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(volume / "rejected-extra"),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "file set does not match" in rejected.stderr
    assert not (volume / "rejected-extra").exists()

    member_bomb_backup = tmp_path / "member-bomb-backup"
    shutil.copytree(backup_runs[0], member_bomb_backup)
    member_bomb = tmp_path / "member-bomb-evidence"
    member_bomb.mkdir()
    with tarfile.open(member_bomb_backup / "evidence.tar.age") as archive:
        archive.extractall(member_bomb, filter="data")
    for index in range(40):
        (member_bomb / f"empty-{index:02d}").mkdir()
    with tarfile.open(member_bomb_backup / "evidence.tar.age", "w") as archive:
        archive.add(member_bomb, arcname=".")
    (member_bomb_backup / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((member_bomb_backup / name).read_bytes()).hexdigest()}  {name}\n"
            for name in canonical_artifacts
        )
    )
    (member_bomb_backup / "checksums.sha256.sig").write_text(
        hashlib.sha256(
            (member_bomb_backup / "checksums.sha256").read_bytes()
        ).hexdigest()
        + "\n"
    )
    member_bomb_result = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "PILOT_RESTORE_SOURCE": str(member_bomb_backup),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(volume / "rejected-member-bomb"),
            "PILOT_RESTORE_MAX_EVIDENCE_OBJECTS": "1",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert member_bomb_result.returncode != 0
    assert "member bound" in member_bomb_result.stderr
    assert not (volume / "rejected-member-bomb").exists()

    nonempty_database_trace = tmp_path / "nonempty-database-tools.log"
    nonempty_database = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env={
            **restore_environment,
            "FAKE_DATABASE_OBJECT_COUNT": "1",
            "FAKE_TOOL_TRACE": str(nonempty_database_trace),
            "PILOT_RESTORE_EVIDENCE_TARGET": str(
                volume / "rejected-nonempty-database"
            ),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert nonempty_database.returncode != 0
    assert "non-baseline" in nonempty_database.stderr
    assert "pg_restore-apply" not in nonempty_database_trace.read_text()
    assert not (volume / "rejected-nonempty-database").exists()

    restore = subprocess.run(
        [str(fixture_scripts / "restore.sh")],
        env=restore_environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert restore.returncode == 0, restore.stderr
    assert (volume / "restored-site-1/event.mp4").read_bytes() == b"video"
    restore_receipts = list(receipts.glob("restore-drill-*/restore-drill-receipt.age"))
    assert len(restore_receipts) == 1
    assert "status=verified_fresh_target_restore" in restore_receipts[0].read_text()
    assert "source_database_dump_sha256=" in restore_receipts[0].read_text()
    assert "restored_state_sha256=" in restore_receipts[0].read_text()
    assert "restored_database_sha256=" not in restore_receipts[0].read_text()
    assert restore_receipts[0].with_suffix(".age.sig").exists()
    assert restore_receipts[0].with_suffix(".age.sha256").exists()


def test_audit_archive_is_client_encrypted_immutable_and_retry_idempotent(
    tmp_path: Path,
) -> None:
    class Missing(Exception):
        response = {"ResponseMetadata": {"HTTPStatusCode": 404}}

    class Client:
        def __init__(self) -> None:
            self.objects: dict[str, dict[str, object]] = {}

        def head_object(
            self,
            *,
            Bucket: str,
            Key: str,
            ChecksumMode: str,
        ) -> dict[str, object]:
            assert Bucket == "audit-bucket"
            assert ChecksumMode == "ENABLED"
            try:
                stored = self.objects[Key]
            except KeyError as exc:
                raise Missing from exc
            return {
                "Metadata": stored["Metadata"],
                "ContentLength": len(stored["Body"]),
                "ChecksumSHA256": stored["ChecksumSHA256"],
                "ServerSideEncryption": stored["ServerSideEncryption"],
                "SSEKMSKeyId": stored.get("SSEKMSKeyId"),
            }

        def get_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
            assert Bucket == "audit-bucket"
            return {"Body": io.BytesIO(self.objects[Key]["Body"])}

        def put_object(self, **arguments: object) -> None:
            key = str(arguments["Key"])
            assert arguments["IfNoneMatch"] == "*"
            assert arguments["ServerSideEncryption"] == "AES256"
            if key in self.objects:
                raise RuntimeError("precondition failed")
            self.objects[key] = {
                "Metadata": arguments["Metadata"],
                "Body": arguments["Body"],
                "ChecksumSHA256": arguments["ChecksumSHA256"],
                "ServerSideEncryption": arguments["ServerSideEncryption"],
                "SSEKMSKeyId": arguments.get("SSEKMSKeyId"),
            }

    class AgeResult:
        stdout = b"age-encryption.org/v1\nclient-encrypted-audit"

    recipient = tmp_path / "archive-age-recipient"
    private_key = tmp_path / "archive-signing-private.pem"
    public_key = tmp_path / "archive-signing-public.pem"
    wrong_private_key = tmp_path / "wrong-private.pem"
    wrong_public_key = tmp_path / "wrong-public.pem"
    recipient.write_text("age1fixture-recipient-for-tests\n")
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(private_key),
        ],
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(wrong_private_key),
        ],
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(wrong_private_key),
            "-pubout",
            "-out",
            str(wrong_public_key),
        ],
        check=True,
    )
    client = Client()
    encryptions = 0

    def commands(arguments: list[str], **kwargs: object) -> object:
        nonlocal encryptions
        if arguments[0] == "age":
            encryptions += 1
            return AgeResult()
        return subprocess.run(arguments, **kwargs)

    store = EncryptedAuditArchiveStore(
        client=client,
        bucket="audit-bucket",
        archive_prefix="audit-archive/site-1",
        site_id="site-1",
        age_recipient_file=recipient,
        signing_private_key_file=private_key,
        signing_public_key_file=public_key,
        signing_key_id="audit-ed25519-2026",
        server_side_encryption="AES256",
        command_runner=commands,
    )
    plaintext = b'{"audit":"bounded"}\n'
    digest = hashlib.sha256(plaintext).hexdigest()
    object_key = f"audit/site-1/{digest}.jsonl.age"

    first = store.publish(object_key=object_key, plaintext=plaintext)
    retry = store.publish(object_key=object_key, plaintext=plaintext)

    assert first == retry
    assert encryptions == 1
    stored = client.objects[f"audit-archive/site-1/{object_key}"]
    assert stored["Body"] != plaintext
    assert first.object_key == object_key
    assert first.detached_signature

    metadata = dict(stored["Metadata"])
    stored["Metadata"]["encrypted-sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="identity"):
        store.publish(object_key=object_key, plaintext=plaintext)
    stored["Metadata"] = metadata
    original_body = stored["Body"]
    stored["Body"] = b"x" * len(original_body)
    with pytest.raises(RuntimeError, match="ciphertext integrity"):
        store.publish(object_key=object_key, plaintext=plaintext)
    stored["Body"] = original_body

    wrong_verifier = EncryptedAuditArchiveStore(
        client=client,
        bucket="audit-bucket",
        archive_prefix="audit-archive/site-1",
        site_id="site-1",
        age_recipient_file=recipient,
        signing_private_key_file=private_key,
        signing_public_key_file=wrong_public_key,
        signing_key_id="audit-ed25519-2026",
        server_side_encryption="AES256",
        command_runner=commands,
    )
    with pytest.raises(RuntimeError, match="sender signature verification"):
        wrong_verifier.publish(object_key=object_key, plaintext=plaintext)


def test_deployment_and_backup_artifacts_are_hardened_and_secret_free() -> None:
    compose = (REPO_ROOT / "deploy/pilot/docker-compose.yml").read_text()
    dockerfile = (REPO_ROOT / "deploy/pilot/Dockerfile.api").read_text()
    prometheus = (REPO_ROOT / "deploy/pilot/prometheus.yml").read_text()
    backup = (REPO_ROOT / "scripts/pilot/backup.sh").read_text()
    backup_snapshot = (
        REPO_ROOT / "scripts/pilot/backup_snapshot.py"
    ).read_text()
    restore = (REPO_ROOT / "scripts/pilot/restore.sh").read_text()
    nginx = (REPO_ROOT / "deploy/pilot/nginx.conf").read_text()
    api_lock = (REPO_ROOT / "deploy/pilot/api-requirements.lock").read_text()
    dockerignore = (REPO_ROOT / ".dockerignore").read_text().splitlines()
    parsed = yaml.safe_load(compose)

    assert "network_mode: host" not in compose
    assert "privileged: true" not in compose
    assert "/var/run/docker.sock" not in compose
    assert "read_only: true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "@sha256:" in compose
    assert "PILOT_API_IMAGE_SHA256" in compose
    assert "internal: true" in compose
    assert "/run/secrets" in compose
    assert "resources:" in compose
    assert "max-size:" in compose
    assert "0.0.0.0:" not in compose
    assert "USER 10001:10001" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "api-requirements.lock" in dockerfile
    assert "@sha256:" in dockerfile
    assert "retention" in prometheus
    assert "credentials_file" in prometheus
    assert parsed["services"]["tls-proxy"]["ports"]
    assert set(parsed["services"]) == {
        "postgres",
        "role-bootstrap",
        "migrate",
        "role-grants",
        "provision",
        "api",
        "notifications",
        "retention",
        "tls-proxy",
        "prometheus",
    }
    assert all(
        service.get("pids_limit", 0) > 0 for service in parsed["services"].values()
    )
    assert "TLSv1.2 TLSv1.3" in nginx
    assert "location ^~ /internal/" in nginx
    assert "location ^~ /api/internal/" in nginx
    assert nginx.index("location ^~ /api/internal/") < nginx.index("location / {")
    assert "X-Forwarded-Proto https" in nginx
    assert "torch==" not in api_lock
    assert "opencv" not in api_lock
    assert "gradio" not in api_lock
    assert "backup_snapshot.py" in backup
    assert "pg_dump" in backup_snapshot and "--format=custom" in backup_snapshot
    assert "--page-size 1000" in backup
    assert "--max-items" in backup
    assert "s3api get-object" in backup and "s3 sync" not in backup
    assert "age" in backup and "sha256sum" in backup
    assert "openssl dgst -sha256 -verify" in backup
    assert "pg_restore" in restore and "--exit-on-error" in restore
    assert "openssl dgst -sha256 -verify" in restore
    assert "--single-transaction" in restore
    assert "restore-drill-receipt" in restore
    assert "pilot_health" not in compose
    assert "kuzet_owner" in (
        REPO_ROOT / "scripts/pilot/bootstrap_roles.py"
    ).read_text()
    role_bootstrap = (REPO_ROOT / "scripts/pilot/bootstrap_roles.py").read_text()
    assert "ALTER DATABASE" in role_bootstrap and "ALTER SCHEMA public OWNER" in role_bootstrap
    assert "REVOKE CONNECT" in role_bootstrap
    assert "INSERT, UPDATE, DELETE ON ALL TABLES" not in role_bootstrap
    assert "ALTER DEFAULT PRIVILEGES" not in role_bootstrap
    assert "GRANT DELETE ON TABLE audit_archive_items" not in role_bootstrap
    assert "audit_item_compaction_authorizations" in role_bootstrap
    assert "PILOT_MEASURED_CAPACITY_SHA256" in compose
    assert "service_completed_successfully" in compose
    audit_retention_policy = (
        REPO_ROOT / "deploy/pilot/AUDIT_RETENTION.md"
    ).read_text()
    assert "at most 24" in audit_retention_policy
    assert "not a zero-growth claim" in audit_retention_policy
    assert parsed["networks"]["storage-egress"]["external"] is True
    network_policy = (REPO_ROOT / "deploy/pilot/NETWORK_POLICY.md").read_text()
    target_acceptance = (
        REPO_ROOT / "deploy/pilot/TARGET_ACCEPTANCE.md"
    ).read_text()
    assert "DOCKER-USER" in network_policy
    assert "0.0.0.0/0" in network_policy and "Never substitute" in network_policy
    assert "validate_runtime_mounts.py" in target_acceptance
    assert "PILOT_RUNTIME_MOUNT_ARGV" in target_acceptance
    assert '"$PILOT_RUNTIME_IMAGE_ID" \\' in target_acceptance
    assert "runtime-mount-contract.v1" in target_acceptance
    assert "all 20 `/run/secrets/<safe-name>`" in target_acceptance
    assert dockerignore[0] == "**"
    assert "!protector/**" in dockerignore
    assert "!deploy/pilot/**" in dockerignore
    assert not any(
        rule.startswith("!demos")
        or rule.startswith("!data")
        or rule.startswith("!.git")
        or rule.startswith("!.env")
        for rule in dockerignore
    )
    assert 'runtime_lock_path="/tmp/kuzet-api.lock"' in (
        REPO_ROOT / "protector/pilot/api/production.py"
    ).read_text()
    combined = "\n".join(
        (compose, dockerfile, prometheus, backup, backup_snapshot, restore)
    )
    assert "POSTGRES_PASSWORD=" not in combined
    assert "PILOT_SESSION_SECRET=" not in combined
    assert "AKIA" not in combined

    for script in ("backup.sh", "restore.sh"):
        syntax = subprocess.run(
            ["bash", "-n", str(REPO_ROOT / "scripts/pilot" / script)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert syntax.returncode == 0, syntax.stderr


def _resolved_retention_command() -> list[str]:
    compose = yaml.safe_load(
        (REPO_ROOT / "deploy/pilot/docker-compose.yml").read_text()
    )
    replacements = {
        "--archive-signing-key-id": "audit-key-1",
        "--archive-prefix": "audit/site-1",
        "--site-id": "site-1",
        "--site-config-sha256": "a" * 64,
    }
    resolved: list[str] = []
    for item in compose["services"]["retention"]["command"]:
        name = item.split("=", 1)[0]
        value = replacements.get(name)
        resolved.append(f"{name}={value}" if value is not None else item)
    return resolved


def test_production_retention_command_builds_distinct_bounded_real_coordinators() -> None:
    arguments = retention_service.parse_retention_arguments(
        _resolved_retention_command()
    )
    site = load_site_config(REPO_ROOT / "configs/pilot.example.yaml")
    evidence, audit = retention_service.build_retention_coordinators(
        arguments=arguments,
        site=site,
        sessions=object(),  # constructors only retain the session-factory boundary
        evidence_store=RecordingStore(),
        archive_store=RecordingAuditArchiveStore(),
        clock=lambda: NOW,
    )

    assert arguments.interval_seconds == 3_600
    assert evidence.batch_size == 1_000
    assert audit.batch_size == 10_000


@pytest.mark.parametrize(
    ("argument", "invalid_value"),
    (
        ("--evidence-batch-size", "0"),
        ("--evidence-batch-size", "1001"),
        ("--audit-batch-size", "0"),
        ("--audit-batch-size", "10001"),
    ),
)
def test_retention_cli_rejects_batch_bounds_before_reviewed_or_external_inputs(
    argument: str,
    invalid_value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = [
        (
            f"{argument}={invalid_value}"
            if item.split("=", 1)[0] == argument
            else item
        )
        for item in _resolved_retention_command()
    ]
    reviewed_config_called = False

    def unexpected_reviewed_config(*args: object, **kwargs: object) -> object:
        nonlocal reviewed_config_called
        reviewed_config_called = True
        raise AssertionError("invalid CLI reached reviewed or external inputs")

    monkeypatch.setattr(
        retention_service,
        "_reviewed_config",
        unexpected_reviewed_config,
    )

    with pytest.raises(SystemExit) as exit_status:
        retention_service.main(command)

    assert exit_status.value.code == 2
    assert reviewed_config_called is False
