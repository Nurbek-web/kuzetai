"""Transactional repositories enforcing pilot lifecycle and notification invariants."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import Select, and_, or_, select, update

from protector.pilot.domain import (
    CandidateEventV1,
    NotificationOutboxRecordV1,
    ObservationV1,
    ReviewStatus,
)
from protector.pilot.gates import ModelArtifactV1
from protector.pilot.storage.db import SessionFactory
from protector.pilot.storage.models import (
    AuditEntryModel,
    CameraModel,
    CandidateEventModel,
    EvidenceModel,
    ModelArtifactModel,
    NotificationOutboxModel,
    ObservationModel,
    ReviewModel,
    SiteModel,
    UserModel,
)


class IdempotencyConflictError(ValueError):
    """An idempotency key was reused for different work."""


@dataclass(frozen=True)
class AuditEntryInput:
    actor_user_id: str | None
    action: str
    entity_type: str
    entity_id: str
    payload: dict[str, Any]
    idempotency_key: str | None
    occurred_at: datetime


@dataclass(frozen=True)
class EvidenceInput:
    evidence_id: UUID
    event_id: UUID
    object_key: str
    sha256: str
    codec: Literal["h264", "h265"]
    start_at: datetime
    end_at: datetime
    source_reference: str
    status: Literal["pending", "ready", "failed", "unavailable"]

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> EvidenceInput:
        return cls(
            evidence_id=UUID(payload["evidence_id"]),
            event_id=UUID(payload["event_id"]),
            object_key=payload["object_key"],
            sha256=payload["sha256"],
            codec=payload["codec"],
            start_at=datetime.fromisoformat(payload["start_at"]),
            end_at=datetime.fromisoformat(payload["end_at"]),
            source_reference=payload["source_reference"],
            status=payload["status"],
        )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _event_from_row(row: CandidateEventModel) -> CandidateEventV1:
    return CandidateEventV1(
        schema_version=row.schema_version,
        event_id=row.event_id,
        camera_id=row.camera_id,
        module=row.module,
        opened_at=_as_utc(row.opened_at),
        last_seen_at=_as_utc(row.last_seen_at),
        peak_confidence=row.peak_confidence,
        reason=row.reason,
        model_artifact_id=row.model_artifact_id,
        gate_mode=row.gate_mode,
        evidence_status=row.evidence_status,
        review_status=row.review_status,
        transition_history=tuple(row.transition_history),
    )


class PilotRepository:
    """Small transactional boundary shared by the API and journal replay worker."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self.session_factory = session_factory

    def add_site(self, *, site_id: str, name: str, timezone_name: str = "Asia/Almaty") -> SiteModel:
        with self.session_factory.begin() as session:
            row = SiteModel(site_id=site_id, name=name, timezone_name=timezone_name)
            session.add(row)
            session.flush()
            return row

    def add_camera(
        self,
        *,
        camera_id: str,
        site_id: str,
        name: str,
        source_reference: str,
        codec: Literal["h264", "h265"],
        state: str = "starting",
        enabled: bool = True,
    ) -> CameraModel:
        with self.session_factory.begin() as session:
            row = CameraModel(
                camera_id=camera_id,
                site_id=site_id,
                name=name,
                source_reference=source_reference,
                codec=codec,
                state=state,
                enabled=enabled,
            )
            session.add(row)
            session.flush()
            return row

    def list_cameras(
        self,
        *,
        site_id: str | None = None,
        state: str | None = None,
        enabled: bool | None = None,
    ) -> list[CameraModel]:
        statement: Select[tuple[CameraModel]] = select(CameraModel).order_by(CameraModel.camera_id)
        if site_id is not None:
            statement = statement.where(CameraModel.site_id == site_id)
        if state is not None:
            statement = statement.where(CameraModel.state == state)
        if enabled is not None:
            statement = statement.where(CameraModel.enabled == enabled)
        with self.session_factory() as session:
            return list(session.scalars(statement))

    def add_model_artifact(self, artifact: ModelArtifactV1) -> ModelArtifactModel:
        with self.session_factory.begin() as session:
            row = ModelArtifactModel(
                artifact_id=artifact.artifact_id,
                schema_version=artifact.schema_version,
                analytic=artifact.analytic,
                sha256=artifact.sha256,
                source=artifact.source,
                commercial_rights=(
                    artifact.commercial_rights.model_dump(mode="json")
                    if artifact.commercial_rights is not None
                    else None
                ),
                class_list=list(artifact.class_list),
                preprocessing=artifact.preprocessing,
            )
            session.add(row)
            session.flush()
            return row

    def add_observation(self, observation: ObservationV1) -> ObservationModel:
        with self.session_factory.begin() as session:
            row = ObservationModel(
                observation_id=str(observation.observation_id),
                schema_version=observation.schema_version,
                dedupe_key=observation.dedupe_key,
                camera_id=observation.camera_id,
                stream_epoch=str(observation.stream_epoch),
                source_time=observation.source_time,
                timestamp_quality=observation.timestamp_quality,
                monotonic_seq=observation.monotonic_seq,
                module=observation.module,
                class_name=observation.class_name,
                confidence=observation.confidence,
                bbox=list(observation.bbox),
                track_id=observation.track_id,
                model_artifact_id=observation.model_artifact_id,
                sample_kind=observation.sample_kind,
                runtime_state=observation.runtime_state,
                received_at=observation.received_at,
            )
            session.add(row)
            session.flush()
            return row

    def count_observations(self) -> int:
        with self.session_factory() as session:
            return len(session.scalars(select(ObservationModel.observation_id)).all())

    def add_event(self, event: CandidateEventV1) -> CandidateEventModel:
        with self.session_factory.begin() as session:
            row = self._new_event_row(event)
            session.add(row)
            session.flush()
            return row

    def store_event_idempotent(self, event: CandidateEventV1) -> CandidateEventModel:
        with self.session_factory.begin() as session:
            existing = session.scalar(
                select(CandidateEventModel).where(
                    or_(
                        CandidateEventModel.event_id == str(event.event_id),
                        CandidateEventModel.dedupe_key == event.dedupe_key,
                    )
                )
            )
            if existing is not None:
                persisted = _event_from_row(existing)
                if persisted.model_dump(mode="json", exclude={"dedupe_key"}) != event.model_dump(
                    mode="json", exclude={"dedupe_key"}
                ):
                    raise IdempotencyConflictError("event identity was reused with different data")
                return existing
            row = self._new_event_row(event)
            session.add(row)
            session.flush()
            return row

    @staticmethod
    def _new_event_row(event: CandidateEventV1) -> CandidateEventModel:
        return CandidateEventModel(
            event_id=str(event.event_id),
            schema_version=event.schema_version,
            dedupe_key=event.dedupe_key,
            camera_id=event.camera_id,
            module=event.module,
            opened_at=event.opened_at,
            last_seen_at=event.last_seen_at,
            peak_confidence=event.peak_confidence,
            reason=event.reason,
            model_artifact_id=event.model_artifact_id,
            gate_mode=event.gate_mode,
            evidence_status=event.evidence_status,
            review_status=event.review_status,
            transition_history=list(event.transition_history),
        )

    def get_event(self, event_id: UUID) -> CandidateEventV1:
        with self.session_factory() as session:
            row = session.get(CandidateEventModel, str(event_id))
            if row is None:
                raise KeyError(f"unknown event: {event_id}")
            return _event_from_row(row)

    def list_events(
        self,
        *,
        camera_id: str | None = None,
        module: str | None = None,
        gate_mode: str | None = None,
        review_status: str | None = None,
        opened_from: datetime | None = None,
        opened_to: datetime | None = None,
    ) -> list[CandidateEventV1]:
        statement: Select[tuple[CandidateEventModel]] = select(CandidateEventModel).order_by(
            CandidateEventModel.opened_at
        )
        filters = [
            value
            for value in (
                CandidateEventModel.camera_id == camera_id if camera_id is not None else None,
                CandidateEventModel.module == module if module is not None else None,
                CandidateEventModel.gate_mode == gate_mode if gate_mode is not None else None,
                (
                    CandidateEventModel.review_status == review_status
                    if review_status is not None
                    else None
                ),
                CandidateEventModel.opened_at >= opened_from if opened_from is not None else None,
                CandidateEventModel.opened_at <= opened_to if opened_to is not None else None,
            )
            if value is not None
        ]
        if filters:
            statement = statement.where(and_(*filters))
        with self.session_factory() as session:
            return [_event_from_row(row) for row in session.scalars(statement)]

    def add_user(
        self,
        *,
        user_id: str,
        username: str,
        password_hash: str,
        role: Literal["viewer", "operator", "admin"],
        totp_secret_encrypted: str | None = None,
        is_active: bool = True,
    ) -> UserModel:
        with self.session_factory.begin() as session:
            row = UserModel(
                user_id=user_id,
                username=username,
                password_hash=password_hash,
                role=role,
                totp_secret_encrypted=totp_secret_encrypted,
                is_active=is_active,
            )
            session.add(row)
            session.flush()
            return row

    def append_audit(self, entry: AuditEntryInput) -> AuditEntryModel:
        with self.session_factory.begin() as session:
            if entry.idempotency_key is not None:
                existing = session.scalar(
                    select(AuditEntryModel).where(
                        AuditEntryModel.idempotency_key == entry.idempotency_key
                    )
                )
                if existing is not None:
                    if (
                        existing.action,
                        existing.entity_type,
                        existing.entity_id,
                        existing.payload,
                    ) != (
                        entry.action,
                        entry.entity_type,
                        entry.entity_id,
                        entry.payload,
                    ):
                        raise IdempotencyConflictError(
                            "audit idempotency key was reused with different data"
                        )
                    return existing
            row = AuditEntryModel(
                audit_id=str(uuid4()),
                occurred_at=entry.occurred_at,
                actor_user_id=entry.actor_user_id,
                action=entry.action,
                entity_type=entry.entity_type,
                entity_id=entry.entity_id,
                payload=dict(entry.payload),
                idempotency_key=entry.idempotency_key,
            )
            session.add(row)
            session.flush()
            return row

    def review_event(
        self,
        *,
        event_id: UUID,
        reviewer_id: str,
        target_status: ReviewStatus,
        idempotency_key: str,
        notes: str | None,
        reviewed_at: datetime,
    ) -> ReviewModel:
        with self.session_factory.begin() as session:
            existing = session.scalar(
                select(ReviewModel).where(
                    ReviewModel.event_id == str(event_id),
                    ReviewModel.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if (
                    existing.reviewer_id,
                    existing.to_status,
                    existing.notes,
                ) != (reviewer_id, target_status, notes):
                    raise IdempotencyConflictError(
                        "review idempotency key was reused with different data"
                    )
                return existing

            row = session.scalar(
                select(CandidateEventModel)
                .where(CandidateEventModel.event_id == str(event_id))
                .with_for_update()
            )
            if row is None:
                raise KeyError(f"unknown event: {event_id}")
            current = _event_from_row(row)
            transitioned = current.transition_to(target_status)
            result = session.execute(
                update(CandidateEventModel)
                .where(
                    CandidateEventModel.event_id == str(event_id),
                    CandidateEventModel.review_status == current.review_status,
                )
                .values(
                    review_status=transitioned.review_status,
                    transition_history=list(transitioned.transition_history),
                )
            )
            if result.rowcount != 1:
                raise RuntimeError("event was reviewed concurrently")

            review = ReviewModel(
                review_id=str(uuid4()),
                event_id=str(event_id),
                reviewer_id=reviewer_id,
                from_status=current.review_status,
                to_status=target_status,
                notes=notes,
                idempotency_key=idempotency_key,
                reviewed_at=reviewed_at,
            )
            session.add(review)
            session.add(
                AuditEntryModel(
                    audit_id=str(uuid4()),
                    occurred_at=reviewed_at,
                    actor_user_id=reviewer_id,
                    action=f"event.{target_status}",
                    entity_type="candidate_event",
                    entity_id=str(event_id),
                    payload={
                        "from_status": current.review_status,
                        "to_status": target_status,
                        "notes": notes,
                    },
                    idempotency_key=f"review:{event_id}:{idempotency_key}",
                )
            )
            session.flush()
            return review

    def enqueue_notification(
        self,
        *,
        event_id: UUID,
        idempotency_key: str,
        payload: dict[str, Any] | None = None,
    ) -> NotificationOutboxModel:
        with self.session_factory.begin() as session:
            existing = session.scalar(
                select(NotificationOutboxModel).where(
                    or_(
                        NotificationOutboxModel.event_id == str(event_id),
                        NotificationOutboxModel.idempotency_key == idempotency_key,
                    )
                )
            )
            if existing is not None:
                if (
                    existing.event_id != str(event_id)
                    or existing.idempotency_key != idempotency_key
                ):
                    raise IdempotencyConflictError(
                        "notification identity was reused with different data"
                    )
                return existing
            event_row = session.get(CandidateEventModel, str(event_id))
            if event_row is None:
                raise KeyError(f"unknown event: {event_id}")
            event_contract = _event_from_row(event_row)
            NotificationOutboxRecordV1.from_confirmed_event(
                event_contract, idempotency_key=idempotency_key
            )
            row = NotificationOutboxModel(
                outbox_id=str(uuid4()),
                event_id=str(event_id),
                idempotency_key=idempotency_key,
                status="pending",
                payload=dict(payload or {}),
                available_at=datetime.now(timezone.utc),
            )
            session.add(row)
            session.flush()
            return row

    def add_evidence(self, evidence: EvidenceInput) -> EvidenceModel:
        with self.session_factory.begin() as session:
            existing = session.get(EvidenceModel, str(evidence.evidence_id))
            if existing is not None:
                if (
                    existing.event_id,
                    existing.object_key,
                    existing.sha256,
                ) != (
                    str(evidence.event_id),
                    evidence.object_key,
                    evidence.sha256,
                ):
                    raise IdempotencyConflictError(
                        "evidence identity was reused with different data"
                    )
                return existing
            row = EvidenceModel(
                evidence_id=str(evidence.evidence_id),
                event_id=str(evidence.event_id),
                object_key=evidence.object_key,
                sha256=evidence.sha256,
                codec=evidence.codec,
                start_at=evidence.start_at,
                end_at=evidence.end_at,
                source_reference=evidence.source_reference,
                status=evidence.status,
            )
            session.add(row)
            session.flush()
            return row

    def persist_journal_item(self, item: Any) -> None:
        """Commit one journal item before returning so the journal may acknowledge it."""
        if item.kind == "candidate_event":
            self.store_event_idempotent(CandidateEventV1.model_validate(item.payload))
            return
        if item.kind == "evidence":
            self.add_evidence(EvidenceInput.from_payload(item.payload))
            return
        raise ValueError(f"unsupported journal item kind: {item.kind}")
