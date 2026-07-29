"""Event review and append-only audit APIs."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.sql.elements import ColumnElement

from protector.pilot.api.auth import ServerSession
from protector.pilot.api.dependencies import (
    ApiContext,
    get_context,
    get_current_session,
    redact_secrets,
    require_csrf,
    require_idempotency_key,
    require_pilot_site_id,
    require_roles,
)
from protector.pilot.domain import CandidateEventV1
from protector.pilot.storage.models import (
    AuditEntryModel,
    CameraModel,
    CandidateEventModel,
    DeliveryAttemptModel,
    EvidenceModel,
    NotificationOutboxModel,
    ReviewModel,
    SiteModel,
)
from protector.pilot.storage.repositories import IdempotencyConflictError, StaleStateError

router = APIRouter(prefix="/api", tags=["events"])


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
        transition_history=tuple(row.transition_history.split(">")),
    )


def _event_payload(event: CandidateEventV1) -> dict[str, object]:
    return redact_secrets(
        {
            "schema_version": event.schema_version,
            "event_id": str(event.event_id),
            "camera_id": event.camera_id,
            "module": event.module,
            "opened_at": event.opened_at.isoformat(),
            "last_seen_at": event.last_seen_at.isoformat(),
            "peak_confidence": event.peak_confidence,
            "reason": event.reason,
            "model_artifact_id": event.model_artifact_id,
            "gate_mode": event.gate_mode,
            "evidence_status": event.evidence_status,
            "review_status": event.review_status,
        }
    )


def _notification_key(event_id: UUID, idempotency_key: str) -> str:
    material = f"{event_id}:{idempotency_key}".encode()
    return f"review-notification:{hashlib.sha256(material).hexdigest()}"


def _audit_site_attribution(pilot_site_id: str) -> ColumnElement[bool]:
    return or_(
        and_(
            AuditEntryModel.entity_type == "site",
            exists(
                select(SiteModel.site_id).where(
                    SiteModel.site_id == AuditEntryModel.entity_id,
                    SiteModel.site_id == pilot_site_id,
                )
            ).correlate(AuditEntryModel),
        ),
        and_(
            AuditEntryModel.entity_type == "camera",
            exists(
                select(CameraModel.camera_id).where(
                    CameraModel.camera_id == AuditEntryModel.entity_id,
                    CameraModel.site_id == pilot_site_id,
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
                    CameraModel.site_id == pilot_site_id,
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
                    CameraModel.site_id == pilot_site_id,
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
                    CameraModel.site_id == pilot_site_id,
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
                    CameraModel.site_id == pilot_site_id,
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
                    CameraModel.site_id == pilot_site_id,
                )
            ).correlate(AuditEntryModel),
        ),
    )


@router.get("/events")
def list_events(
    current: Annotated[ServerSession, Depends(get_current_session)],
    context: Annotated[ApiContext, Depends(get_context)],
    pilot_site_id: Annotated[str, Depends(require_pilot_site_id)],
    camera_id: Annotated[str | None, Query(max_length=128)] = None,
    module: Annotated[str | None, Query(max_length=128)] = None,
    gate_mode: Literal["disabled", "shadow", "operator"] | None = None,
    review_status: (
        Literal["observation", "candidate", "confirmed", "rejected", "expired", "escalated"] | None
    ) = None,
    opened_from: datetime | None = None,
    opened_to: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> dict[str, object]:
    del current
    filters = [
        expression
        for expression in (
            CameraModel.site_id == pilot_site_id,
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
        if expression is not None
    ]
    statement = select(CandidateEventModel).join(
        CameraModel,
        CameraModel.camera_id == CandidateEventModel.camera_id,
    )
    count_statement = (
        select(func.count())
        .select_from(CandidateEventModel)
        .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
    )
    if filters:
        statement = statement.where(*filters)
        count_statement = count_statement.where(*filters)
    statement = (
        statement.order_by(CandidateEventModel.opened_at, CandidateEventModel.event_id)
        .offset(offset)
        .limit(limit)
    )
    with context.repository.session_factory() as session:
        events = [_event_from_row(row) for row in session.scalars(statement)]
        total = int(session.scalar(count_statement) or 0)
    return {
        "items": [_event_payload(event) for event in events],
        "limit": limit,
        "offset": offset,
        "total": total,
    }


@router.get("/events/{event_id}")
def get_event(
    event_id: UUID,
    current: Annotated[ServerSession, Depends(get_current_session)],
    context: Annotated[ApiContext, Depends(get_context)],
    pilot_site_id: Annotated[str, Depends(require_pilot_site_id)],
) -> dict[str, object]:
    del current
    try:
        event = context.repository.get_event(event_id, expected_site_id=pilot_site_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="event not found"
        ) from exc
    return _event_payload(event)


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_status: Literal["candidate"]
    target_status: Literal["confirmed", "rejected"]
    notes: str | None = Field(default=None, max_length=2_000)
    reviewed_at: datetime

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reviewed_at must be UTC-aware")
        return value.astimezone(timezone.utc)


@router.post("/events/{event_id}/review")
def review_event(
    event_id: UUID,
    body: ReviewRequest,
    csrf_session: Annotated[ServerSession, Depends(require_csrf)],
    role_session: Annotated[
        ServerSession,
        Depends(require_roles("operator", "admin")),
    ],
    idempotency_key: Annotated[str, Depends(require_idempotency_key)],
    context: Annotated[ApiContext, Depends(get_context)],
    pilot_site_id: Annotated[str, Depends(require_pilot_site_id)],
) -> dict[str, object]:
    if csrf_session.session_id != role_session.session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session mismatch")
    current = role_session
    try:
        result = context.repository.review_event_and_enqueue_notification(
            event_id=event_id,
            reviewer_id=current.user.user_id,
            target_status=body.target_status,
            expected_status=body.expected_status,
            review_idempotency_key=idempotency_key,
            notification_idempotency_key=_notification_key(event_id, idempotency_key),
            notes=body.notes,
            reviewed_at=body.reviewed_at,
            expected_site_id=pilot_site_id,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="event not found"
        ) from exc
    except IdempotencyConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "idempotency_conflict"},
        ) from exc
    except StaleStateError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "stale_state",
                "expected": exc.expected,
                "actual": exc.actual,
            },
        ) from exc

    event = context.repository.get_event(event_id, expected_site_id=pilot_site_id)
    return {
        "review_id": result.review.review_id,
        "event": _event_payload(event),
    }


@router.get("/audit")
def list_audit(
    current: Annotated[ServerSession, Depends(get_current_session)],
    context: Annotated[ApiContext, Depends(get_context)],
    pilot_site_id: Annotated[str, Depends(require_pilot_site_id)],
    entity_type: Annotated[str | None, Query(max_length=128)] = None,
    entity_id: Annotated[str | None, Query(max_length=255)] = None,
    action: Annotated[str | None, Query(max_length=255)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> dict[str, object]:
    del current
    site_attribution = _audit_site_attribution(pilot_site_id)
    filters = [
        expression
        for expression in (
            site_attribution,
            AuditEntryModel.entity_type == entity_type if entity_type is not None else None,
            AuditEntryModel.entity_id == entity_id if entity_id is not None else None,
            AuditEntryModel.action == action if action is not None else None,
        )
        if expression is not None
    ]
    statement = select(AuditEntryModel)
    count_statement = select(func.count()).select_from(AuditEntryModel)
    if filters:
        statement = statement.where(*filters)
        count_statement = count_statement.where(*filters)
    statement = (
        statement.order_by(AuditEntryModel.occurred_at.desc(), AuditEntryModel.audit_id)
        .offset(offset)
        .limit(limit)
    )
    with context.repository.session_factory() as session:
        rows = list(session.scalars(statement))
        total = int(session.scalar(count_statement) or 0)
    return {
        "items": [
            redact_secrets(
                {
                    "audit_id": row.audit_id,
                    "occurred_at": row.occurred_at,
                    "actor_user_id": row.actor_user_id,
                    "action": row.action,
                    "entity_type": row.entity_type,
                    "entity_id": row.entity_id,
                    "payload": redact_secrets(row.payload),
                }
            )
            for row in rows
        ],
        "limit": limit,
        "offset": offset,
        "total": total,
    }
