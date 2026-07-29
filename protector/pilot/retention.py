"""Finite, site-scoped retention for Kuzet-owned evidence only."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import case, select

from protector.pilot.storage.db import SessionFactory
from protector.pilot.storage.models import CameraModel, CandidateEventModel, EvidenceModel


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
