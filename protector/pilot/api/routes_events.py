"""Event review and append-only audit APIs."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select

from protector.pilot.api.auth import ServerSession
from protector.pilot.api.dependencies import (
    ApiContext,
    get_context,
    get_current_session,
    redact_secrets,
    require_csrf,
    require_idempotency_key,
    require_roles,
)
from protector.pilot.domain import CandidateEventV1
from protector.pilot.storage.models import AuditEntryModel, CandidateEventModel, ReviewModel
from protector.pilot.storage.repositories import IdempotencyConflictError

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
    return redact_secrets(event.model_dump(mode="json"))


def _notification_key(event_id: UUID, idempotency_key: str) -> str:
    material = f"{event_id}:{idempotency_key}".encode()
    return f"review-notification:{hashlib.sha256(material).hexdigest()}"


@router.get("/events")
def list_events(
    current: Annotated[ServerSession, Depends(get_current_session)],
    context: Annotated[ApiContext, Depends(get_context)],
    camera_id: str | None = None,
    module: str | None = None,
    gate_mode: Literal["disabled", "shadow", "operator"] | None = None,
    review_status: (
        Literal["observation", "candidate", "confirmed", "rejected", "expired", "escalated"]
        | None
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
    statement = select(CandidateEventModel)
    count_statement = select(func.count()).select_from(CandidateEventModel)
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
) -> dict[str, object]:
    del current
    try:
        event = context.repository.get_event(event_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="event not found") from exc
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


def _matching_review_response(
    *,
    existing: ReviewModel,
    event_id: UUID,
    current: ServerSession,
    body: ReviewRequest,
    context: ApiContext,
    idempotency_key: str,
) -> dict[str, object]:
    if (
        existing.reviewer_id,
        existing.to_status,
        existing.notes,
        _as_utc(existing.reviewed_at),
    ) != (
        current.user.user_id,
        body.target_status,
        body.notes,
        body.reviewed_at,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "idempotency_conflict"},
        )
    event = context.repository.get_event(event_id)
    if event.gate_mode == "operator" and event.review_status == "confirmed":
        context.repository.enqueue_notification(
            event_id=event_id,
            idempotency_key=_notification_key(event_id, idempotency_key),
        )
    return {
        "review_id": existing.review_id,
        "event": _event_payload(event),
    }


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
) -> dict[str, object]:
    if csrf_session.session_id != role_session.session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session mismatch")
    current = role_session
    with context.repository.session_factory() as session:
        existing = session.scalar(
            select(ReviewModel).where(
                ReviewModel.event_id == str(event_id),
                ReviewModel.idempotency_key == idempotency_key,
            )
        )
    if existing is not None:
        return _matching_review_response(
            existing=existing,
            event_id=event_id,
            current=current,
            body=body,
            context=context,
            idempotency_key=idempotency_key,
        )

    try:
        event = context.repository.get_event(event_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="event not found") from exc
    if event.review_status != body.expected_status:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "stale_state",
                "expected": body.expected_status,
                "actual": event.review_status,
            },
        )

    try:
        review = context.repository.review_event(
            event_id=event_id,
            reviewer_id=current.user.user_id,
            target_status=body.target_status,
            idempotency_key=idempotency_key,
            notes=body.notes,
            reviewed_at=body.reviewed_at,
        )
    except IdempotencyConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "idempotency_conflict"},
        ) from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "stale_state"},
        ) from exc

    event = context.repository.get_event(event_id)
    if event.gate_mode == "operator" and event.review_status == "confirmed":
        context.repository.enqueue_notification(
            event_id=event_id,
            idempotency_key=_notification_key(event_id, idempotency_key),
        )
    return {
        "review_id": review.review_id,
        "event": _event_payload(event),
    }


@router.get("/audit")
def list_audit(
    current: Annotated[ServerSession, Depends(get_current_session)],
    context: Annotated[ApiContext, Depends(get_context)],
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> dict[str, object]:
    del current
    filters = [
        expression
        for expression in (
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
            {
                "audit_id": row.audit_id,
                "occurred_at": row.occurred_at,
                "actor_user_id": row.actor_user_id,
                "action": row.action,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "payload": redact_secrets(row.payload),
            }
            for row in rows
        ],
        "limit": limit,
        "offset": offset,
        "total": total,
    }
