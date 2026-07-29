"""Finite, site-scoped retention for Kuzet-owned evidence only."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import and_, case, exists, or_, select, text

from protector.pilot.storage.db import SessionFactory
from protector.pilot.storage.models import (
    AuditArchiveItemModel,
    AuditArchiveReceiptModel,
    AuditEntryModel,
    CameraModel,
    CandidateEventModel,
    DeliveryAttemptModel,
    EvidenceModel,
    NotificationOutboxModel,
    ReviewModel,
    SiteModel,
)

_SAFE_SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class EvidenceDeleteStore(Protocol):
    def delete(self, key: str) -> None: ...


@dataclass(frozen=True, slots=True)
class RetentionResult:
    scanned: int
    deleted: int
    retained: int
    failed: int
    failure_reasons: tuple[str, ...]


class EvidenceRetentionCoordinator:
    """Mark expired metadata unavailable before deleting bounded evidence objects."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        object_store: EvidenceDeleteStore,
        pilot_site_id: str,
        retention_days: int,
        batch_size: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        normalised_site_id = pilot_site_id.strip()
        if not normalised_site_id or len(normalised_site_id) > 128:
            raise ValueError("pilot site identity must contain 1 to 128 characters")
        if not 1 <= retention_days <= 365:
            raise ValueError("retention days must be finite and between 1 and 365")
        if not 1 <= batch_size <= 1_000:
            raise ValueError("retention batch must be finite and between 1 and 1000")
        if clock is not None and not callable(clock):
            raise ValueError("retention clock must be callable")
        self._session_factory = session_factory
        self._object_store = object_store
        self.pilot_site_id = normalised_site_id
        self.retention_days = retention_days
        self.batch_size = batch_size
        self._clock = clock or (lambda: datetime.now(UTC))

    def run_once(self) -> RetentionResult:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None or now.utcoffset() != timedelta(0):
            raise ValueError("retention clock must return UTC-aware time")
        cutoff = now.astimezone(UTC) - timedelta(days=self.retention_days)
        with self._session_factory.begin() as session:
            rows = list(
                session.scalars(
                    select(EvidenceModel)
                    .join(
                        CandidateEventModel,
                        CandidateEventModel.event_id == EvidenceModel.event_id,
                    )
                    .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                    .where(
                        CameraModel.site_id == self.pilot_site_id,
                        EvidenceModel.status.in_(("ready", "unavailable")),
                        EvidenceModel.created_at < cutoff,
                    )
                    .order_by(
                        case((EvidenceModel.status == "ready", 0), else_=1),
                        EvidenceModel.created_at,
                        EvidenceModel.evidence_id,
                    )
                    .limit(self.batch_size)
                )
            )
            for row in rows:
                if row.status == "ready":
                    row.status = "unavailable"
                    other_ready = session.scalar(
                        select(EvidenceModel.evidence_id)
                        .where(
                            EvidenceModel.event_id == row.event_id,
                            EvidenceModel.evidence_id != row.evidence_id,
                            EvidenceModel.status == "ready",
                        )
                        .limit(1)
                    )
                    if other_ready is None:
                        event = session.get(CandidateEventModel, row.event_id)
                        if event is not None:
                            event.evidence_status = "unavailable"

        deleted = 0
        failed = 0
        failure_reasons: set[str] = set()
        for row in rows:
            try:
                self._object_store.delete(row.object_key)
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                failed += 1
                failure_reasons.add("object_delete_failed")
                continue
            with self._session_factory.begin() as session:
                current = session.scalar(
                    select(EvidenceModel)
                    .join(
                        CandidateEventModel,
                        CandidateEventModel.event_id == EvidenceModel.event_id,
                    )
                    .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                    .where(
                        EvidenceModel.evidence_id == row.evidence_id,
                        EvidenceModel.status == "unavailable",
                        CameraModel.site_id == self.pilot_site_id,
                    )
                )
                if current is None:
                    continue
                session.delete(current)
                deleted += 1
        return RetentionResult(
            scanned=len(rows),
            deleted=deleted,
            retained=failed,
            failed=failed,
            failure_reasons=tuple(sorted(failure_reasons)),
        )


@dataclass(frozen=True, slots=True)
class PublishedAuditArchive:
    object_key: str
    encrypted_sha256: str
    detached_signature: str
    signing_key_id: str
    canonical_receipt: str

    def __post_init__(self) -> None:
        if (
            len(self.encrypted_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.encrypted_sha256)
        ):
            raise ValueError("encrypted audit archive requires a SHA-256 digest")
        if not self.object_key or len(self.object_key) > 2048 or ".." in self.object_key:
            raise ValueError("audit archive object key is invalid")
        if not self.detached_signature or len(self.detached_signature) > 16_384:
            raise ValueError("audit archive detached signature is invalid")
        if not self.signing_key_id or len(self.signing_key_id) > 128:
            raise ValueError("audit archive signing key identity is invalid")
        if (
            not self.canonical_receipt.startswith(
                "schema=kuzet-audit-archive-receipt.v1\n"
            )
            or len(self.canonical_receipt.encode("utf-8")) > 16_384
            or f"object_key={self.object_key}\n" not in self.canonical_receipt
            or f"encrypted_sha256={self.encrypted_sha256}\n"
            not in self.canonical_receipt
            or f"signing_key_id={self.signing_key_id}\n"
            not in self.canonical_receipt
        ):
            raise ValueError("audit archive canonical signed receipt is invalid")


class AuditArchiveStore(Protocol):
    def publish(self, *, object_key: str, plaintext: bytes) -> PublishedAuditArchive: ...


AuditPruner = Callable[[str, tuple[str, ...]], int]


@dataclass(frozen=True, slots=True)
class AuditArchiveResult:
    scanned: int
    archived: int
    pruned: int
    failed: int
    failure_reasons: tuple[str, ...]


class PostgresReceiptBoundAuditPruner:
    """Expose only the migration-owned exact-receipt prune function."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def __call__(self, receipt_id: str, audit_ids: tuple[str, ...]) -> int:
        if not receipt_id or not audit_ids:
            raise ValueError("receipt and exact audit identities are required")
        with self._session_factory.begin() as session:
            if session.get_bind().dialect.name != "postgresql":
                raise RuntimeError("audit pruning is enabled only on PostgreSQL")
            result = session.scalar(
                text("SELECT pilot_prune_archived_audit(:receipt_id)"),
                {"receipt_id": receipt_id},
            )
        if not isinstance(result, int) or isinstance(result, bool):
            raise RuntimeError("receipt-bound audit prune returned an invalid count")
        return result


def _audit_site_attribution(site_id: str) -> object:
    return or_(
        and_(
            AuditEntryModel.entity_type == "site",
            exists(
                select(SiteModel.site_id).where(
                    SiteModel.site_id == AuditEntryModel.entity_id,
                    SiteModel.site_id == site_id,
                )
            ).correlate(AuditEntryModel),
        ),
        and_(
            AuditEntryModel.entity_type == "camera",
            exists(
                select(CameraModel.camera_id).where(
                    CameraModel.camera_id == AuditEntryModel.entity_id,
                    CameraModel.site_id == site_id,
                )
            ).correlate(AuditEntryModel),
        ),
        and_(
            AuditEntryModel.entity_type == "candidate_event",
            exists(
                select(CandidateEventModel.event_id)
                .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                .where(
                    CandidateEventModel.event_id == AuditEntryModel.entity_id,
                    CameraModel.site_id == site_id,
                )
            ).correlate(AuditEntryModel),
        ),
        and_(
            AuditEntryModel.entity_type == "evidence",
            exists(
                select(EvidenceModel.evidence_id)
                .join(
                    CandidateEventModel,
                    CandidateEventModel.event_id == EvidenceModel.event_id,
                )
                .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                .where(
                    EvidenceModel.evidence_id == AuditEntryModel.entity_id,
                    CameraModel.site_id == site_id,
                )
            ).correlate(AuditEntryModel),
        ),
        and_(
            AuditEntryModel.entity_type == "review",
            exists(
                select(ReviewModel.review_id)
                .join(
                    CandidateEventModel,
                    CandidateEventModel.event_id == ReviewModel.event_id,
                )
                .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                .where(
                    ReviewModel.review_id == AuditEntryModel.entity_id,
                    CameraModel.site_id == site_id,
                )
            ).correlate(AuditEntryModel),
        ),
        and_(
            AuditEntryModel.entity_type == "notification_outbox",
            exists(
                select(NotificationOutboxModel.outbox_id)
                .join(
                    CandidateEventModel,
                    CandidateEventModel.event_id == NotificationOutboxModel.event_id,
                )
                .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                .where(
                    NotificationOutboxModel.outbox_id == AuditEntryModel.entity_id,
                    CameraModel.site_id == site_id,
                )
            ).correlate(AuditEntryModel),
        ),
        and_(
            AuditEntryModel.entity_type == "delivery_attempt",
            exists(
                select(DeliveryAttemptModel.delivery_attempt_id)
                .join(
                    NotificationOutboxModel,
                    NotificationOutboxModel.outbox_id == DeliveryAttemptModel.outbox_id,
                )
                .join(
                    CandidateEventModel,
                    CandidateEventModel.event_id == NotificationOutboxModel.event_id,
                )
                .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                .where(
                    DeliveryAttemptModel.delivery_attempt_id == AuditEntryModel.entity_id,
                    CameraModel.site_id == site_id,
                )
            ).correlate(AuditEntryModel),
        ),
    )


class AuditArchiveCoordinator:
    """Archive exact site-scoped audit rows before receipt-bound pruning."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        archive_store: AuditArchiveStore,
        pruner: AuditPruner,
        pilot_site_id: str,
        retention_days: int,
        batch_size: int,
        max_archive_bytes: int = 8 * 1024 * 1024,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if _SAFE_SITE_ID.fullmatch(pilot_site_id) is None:
            raise ValueError("pilot site identity must be a bounded identifier")
        if not 1 <= retention_days <= 3_650:
            raise ValueError("audit retention days must be between 1 and 3650")
        if not 1 <= batch_size <= 10_000:
            raise ValueError("audit archive batch must be between 1 and 10000")
        if not 1_024 <= max_archive_bytes <= 64 * 1024 * 1024:
            raise ValueError("audit archive byte bound must be between 1 KiB and 64 MiB")
        if not callable(getattr(archive_store, "publish", None)) or not callable(pruner):
            raise ValueError("audit archive store and pruner are required")
        if clock is not None and not callable(clock):
            raise ValueError("audit archive clock must be callable")
        self._session_factory = session_factory
        self._archive_store = archive_store
        self._pruner = pruner
        self.pilot_site_id = pilot_site_id
        self.retention_days = retention_days
        self.batch_size = batch_size
        self.max_archive_bytes = max_archive_bytes
        self._clock = clock or (lambda: datetime.now(UTC))

    def run_once(self) -> AuditArchiveResult:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("audit archive clock must return UTC-aware time")
        now = now.astimezone(UTC)
        pending = self._pending_receipt()
        if pending is not None:
            receipt_id, audit_ids = pending
            return self._prune(receipt_id, audit_ids, scanned=0, archived=0)
        cutoff = now - timedelta(days=self.retention_days)
        with self._session_factory() as session:
            site_ids = tuple(
                session.scalars(select(SiteModel.site_id).order_by(SiteModel.site_id))
            )
            if self.pilot_site_id not in site_ids:
                return AuditArchiveResult(0, 0, 0, 1, ("pilot_site_missing",))
            known_legacy_scope = or_(
                *(_audit_site_attribution(site_id) for site_id in site_ids)
            )
            unattributed_exists = session.scalar(
                select(
                    exists(
                        select(AuditEntryModel.audit_id).where(
                            AuditEntryModel.site_id.is_(None),
                            AuditEntryModel.occurred_at < cutoff,
                            ~known_legacy_scope,
                        )
                    )
                )
            )
            if unattributed_exists and len(site_ids) != 1:
                return AuditArchiveResult(
                    0,
                    0,
                    0,
                    1,
                    ("unattributed_audit_rows",),
                )
            legacy_site_scope = (
                AuditEntryModel.site_id.is_(None)
                if len(site_ids) == 1
                else and_(
                    AuditEntryModel.site_id.is_(None),
                    _audit_site_attribution(self.pilot_site_id),
                )
            )
            rows = list(
                session.scalars(
                    select(AuditEntryModel)
                    .where(
                        AuditEntryModel.occurred_at < cutoff,
                        or_(
                            AuditEntryModel.site_id == self.pilot_site_id,
                            legacy_site_scope,
                        ),
                        ~exists(
                            select(AuditArchiveItemModel.audit_id).where(
                                AuditArchiveItemModel.audit_id == AuditEntryModel.audit_id
                            )
                        ),
                    )
                    .order_by(AuditEntryModel.occurred_at, AuditEntryModel.audit_id)
                    .limit(self.batch_size)
                )
            )
        if not rows:
            return AuditArchiveResult(0, 0, 0, 0, ())
        selected_rows: list[AuditEntryModel] = []
        canonical_rows: list[dict[str, object]] = []
        encoded_rows: list[bytes] = []
        total_bytes = 0
        for row in rows:
            canonical = self._canonical_row(row)
            encoded = (
                json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
                + b"\n"
            )
            if len(encoded) > self.max_archive_bytes:
                return AuditArchiveResult(
                    1,
                    0,
                    0,
                    1,
                    ("audit_row_exceeds_archive_bound",),
                )
            if total_bytes + len(encoded) > self.max_archive_bytes:
                break
            selected_rows.append(row)
            canonical_rows.append(canonical)
            encoded_rows.append(encoded)
            total_bytes += len(encoded)
        plaintext = b"".join(encoded_rows)
        plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
        receipt_id = str(
            uuid5(
                NAMESPACE_URL,
                f"kuzet-audit:{self.pilot_site_id}:{plaintext_sha256}",
            )
        )
        expected_key = (
            f"audit/{self.pilot_site_id}/{plaintext_sha256}.jsonl.age"
        )
        try:
            published = self._archive_store.publish(
                object_key=expected_key,
                plaintext=plaintext,
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return AuditArchiveResult(
                len(selected_rows),
                0,
                0,
                1,
                ("archive_publish_failed",),
            )
        if published.object_key != expected_key:
            return AuditArchiveResult(
                len(selected_rows),
                0,
                0,
                1,
                ("archive_identity_mismatch",),
            )
        with self._session_factory.begin() as session:
            session.add(
                AuditArchiveReceiptModel(
                    receipt_id=receipt_id,
                    site_id=self.pilot_site_id,
                    cutoff_at=cutoff,
                    archive_object_key=published.object_key,
                    archive_sha256=published.encrypted_sha256,
                    detached_signature=published.detached_signature,
                    signing_key_id=published.signing_key_id,
                    canonical_receipt=published.canonical_receipt,
                    row_count=len(selected_rows),
                    created_at=now,
                )
            )
            session.flush()
            session.add_all(
                AuditArchiveItemModel(
                    receipt_id=receipt_id,
                    audit_id=row.audit_id,
                    occurred_at=row.occurred_at,
                    row_sha256=hashlib.sha256(
                        json.dumps(
                            canonical,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest(),
                )
                for row, canonical in zip(selected_rows, canonical_rows, strict=True)
            )
        return self._prune(
            receipt_id,
            tuple(row.audit_id for row in selected_rows),
            scanned=len(selected_rows),
            archived=len(selected_rows),
        )

    def _pending_receipt(self) -> tuple[str, tuple[str, ...]] | None:
        with self._session_factory() as session:
            receipt = session.scalar(
                select(AuditArchiveReceiptModel)
                .where(
                    AuditArchiveReceiptModel.site_id == self.pilot_site_id,
                    AuditArchiveReceiptModel.pruned_at.is_(None),
                )
                .order_by(AuditArchiveReceiptModel.created_at)
                .limit(1)
            )
            if receipt is None:
                return None
            audit_ids = tuple(
                session.scalars(
                    select(AuditArchiveItemModel.audit_id)
                    .where(AuditArchiveItemModel.receipt_id == receipt.receipt_id)
                    .order_by(AuditArchiveItemModel.audit_id)
                )
            )
            if len(audit_ids) != receipt.row_count:
                raise RuntimeError("audit archive receipt item count is inconsistent")
            return receipt.receipt_id, audit_ids

    def _prune(
        self,
        receipt_id: str,
        audit_ids: tuple[str, ...],
        *,
        scanned: int,
        archived: int,
    ) -> AuditArchiveResult:
        try:
            pruned = self._pruner(receipt_id, audit_ids)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return AuditArchiveResult(
                scanned,
                archived,
                0,
                1,
                ("receipt_bound_prune_failed",),
            )
        if pruned != len(audit_ids):
            return AuditArchiveResult(
                scanned,
                archived,
                0,
                1,
                ("receipt_bound_prune_incomplete",),
            )
        with self._session_factory.begin() as session:
            receipt = session.get(AuditArchiveReceiptModel, receipt_id)
            if receipt is None:
                raise RuntimeError("audit archive receipt state changed")
            if receipt.pruned_at is None:
                return AuditArchiveResult(
                    scanned,
                    archived,
                    0,
                    1,
                    ("receipt_bound_prune_state_missing",),
                )
        return AuditArchiveResult(scanned, archived, pruned, 0, ())

    def _canonical_row(self, row: AuditEntryModel) -> dict[str, object]:
        occurred_at = row.occurred_at
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=UTC)
        return {
            "schema_version": "audit-archive-row.v1",
            "site_id": self.pilot_site_id,
            "audit_id": row.audit_id,
            "occurred_at": occurred_at.astimezone(UTC).isoformat(),
            "actor_user_id": row.actor_user_id,
            "action": row.action,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "payload": row.payload,
            "idempotency_key": row.idempotency_key,
        }
