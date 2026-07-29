"""Server-rendered operator console with a same-origin evidence boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, Protocol
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select

from protector.pilot.api.auth import ServerSession
from protector.pilot.api.dependencies import (
    ApiContext,
    PilotSiteConfigurationError,
    get_context,
    get_current_session,
    resolve_pilot_site_id,
)
from protector.pilot.storage.models import (
    CameraHealthSampleModel,
    CameraModel,
    CandidateEventModel,
    DeliveryAttemptModel,
    EvidenceModel,
    NotificationOutboxModel,
    ReviewModel,
    UserModel,
)

WEB_ROOT = Path(__file__).parent.parent / "web"
STATIC_ROOT = WEB_ROOT / "static"
MAX_EVENT_ROWS = 50
MAX_PREVIEW_BYTES = 16 * 1024 * 1024
EXPECTED_PILOT_CAMERA_COUNT = 20
ALLOWED_PREVIEW_MEDIA_TYPES = frozenset(("video/mp4",))

templates = Jinja2Templates(directory=WEB_ROOT / "templates")
router = APIRouter(prefix="/pilot", tags=["operator-console"])


def _utc_iso(value: datetime | None) -> str:
    if value is None:
        return "Never"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


templates.env.globals["utc_iso"] = _utc_iso


@dataclass(frozen=True, slots=True)
class EvidencePreview:
    """Bounded preview bytes returned without any backing-store reference."""

    content: bytes
    media_type: str


class EvidencePreviewProvider(Protocol):
    """Resolve an opaque event identity to bounded evidence bytes."""

    def get_preview(self, event_id: UUID, *, max_bytes: int) -> EvidencePreview | None: ...


@dataclass(frozen=True, slots=True)
class CameraCard:
    camera: CameraModel
    health: CameraHealthSampleModel | None


@dataclass(frozen=True, slots=True)
class EventRow:
    event: CandidateEventModel
    camera_name: str


@dataclass(frozen=True, slots=True)
class NotificationState:
    status: str
    attempt_count: int
    last_error: str | None


def _current_view_session(request: Request, context: ApiContext) -> ServerSession | None:
    try:
        return get_current_session(request, context)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            return None
        raise


def _redirect_to_login() -> RedirectResponse:
    return RedirectResponse("/pilot/login", status_code=status.HTTP_303_SEE_OTHER)


def _latest_camera_cards(context: ApiContext, *, pilot_site_id: str) -> list[CameraCard]:
    latest_health_id = (
        select(CameraHealthSampleModel.health_sample_id)
        .where(CameraHealthSampleModel.camera_id == CameraModel.camera_id)
        .order_by(
            CameraHealthSampleModel.observed_at.desc(),
            CameraHealthSampleModel.health_sample_id.desc(),
        )
        .limit(1)
        .correlate(CameraModel)
        .scalar_subquery()
    )
    with context.repository.session_factory() as database_session:
        statement = (
            select(CameraModel, CameraHealthSampleModel)
            .outerjoin(
                CameraHealthSampleModel,
                CameraHealthSampleModel.health_sample_id == latest_health_id,
            )
            .where(
                CameraModel.site_id == pilot_site_id,
                CameraModel.enabled.is_(True),
            )
            .order_by(CameraModel.camera_id)
        )
        cards = [
            CameraCard(camera=camera, health=health)
            for camera, health in database_session.execute(statement)
        ]
    if len(cards) != EXPECTED_PILOT_CAMERA_COUNT:
        raise RuntimeError("pilot site must have exactly 20 enabled cameras")
    return cards


def _filtered_events(
    context: ApiContext,
    *,
    pilot_site_id: str,
    query: str | None,
    module: str | None,
    gate_mode: str | None,
    review_status: str | None,
) -> list[EventRow]:
    statement = (
        select(CandidateEventModel, CameraModel.name)
        .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
        .where(CameraModel.site_id == pilot_site_id)
        .order_by(
            CandidateEventModel.opened_at.desc(),
            CandidateEventModel.event_id,
        )
        .limit(MAX_EVENT_ROWS)
    )
    filters = []
    normalized_query = query.strip() if query is not None else ""
    if normalized_query:
        search = normalized_query.casefold()
        filters.append(
            or_(
                func.lower(CandidateEventModel.reason).contains(search, autoescape=True),
                func.lower(CandidateEventModel.camera_id).contains(search, autoescape=True),
                func.lower(CameraModel.name).contains(search, autoescape=True),
                func.lower(CandidateEventModel.model_artifact_id).contains(
                    search, autoescape=True
                ),
            )
        )
    if module is not None:
        filters.append(CandidateEventModel.module == module)
    if gate_mode is not None:
        filters.append(CandidateEventModel.gate_mode == gate_mode)
    if review_status is not None:
        filters.append(CandidateEventModel.review_status == review_status)
    if filters:
        statement = statement.where(*filters)
    with context.repository.session_factory() as database_session:
        return [
            EventRow(event=event, camera_name=camera_name)
            for event, camera_name in database_session.execute(statement)
        ]


@router.get("/login")
def login_page(
    request: Request,
    context: Annotated[ApiContext, Depends(get_context)],
) -> Response:
    if _current_view_session(request, context) is not None:
        return RedirectResponse("/pilot", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"current": None},
        headers={"Cache-Control": "no-store"},
    )


@router.get("")
def dashboard(
    request: Request,
    context: Annotated[ApiContext, Depends(get_context)],
    q: Annotated[str | None, Query(max_length=100)] = None,
    module: Annotated[str | None, Query(max_length=128)] = None,
    gate_mode: Literal["disabled", "shadow", "operator"] | None = None,
    review_status: (
        Literal["observation", "candidate", "confirmed", "rejected", "expired", "escalated"] | None
    ) = None,
) -> Response:
    current = _current_view_session(request, context)
    if current is None:
        return _redirect_to_login()
    try:
        pilot_site_id = resolve_pilot_site_id(context)
        cameras = _latest_camera_cards(context, pilot_site_id=pilot_site_id)
        events = _filtered_events(
            context,
            pilot_site_id=pilot_site_id,
            query=q,
            module=module,
            gate_mode=gate_mode,
            review_status=review_status,
        )
    except Exception:
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "current": current,
                "cameras": (),
                "events": (),
                "filters": {
                    "q": q or "",
                    "module": module or "",
                    "gate_mode": gate_mode or "",
                    "review_status": review_status or "",
                },
                "load_error": True,
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Cache-Control": "no-store"},
        )
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "current": current,
            "cameras": cameras,
            "events": events,
            "filters": {
                "q": q or "",
                "module": module or "",
                "gate_mode": gate_mode or "",
                "review_status": review_status or "",
            },
            "load_error": False,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.get("/events/{event_id}")
def event_detail(
    event_id: UUID,
    request: Request,
    context: Annotated[ApiContext, Depends(get_context)],
) -> Response:
    current = _current_view_session(request, context)
    if current is None:
        return _redirect_to_login()
    if request.url.query:
        try:
            valid_signed_query = (
                context.evidence_link_signer is not None
                and context.evidence_link_signer.verify(
                    str(request.url),
                    event_id=event_id,
                    now=context.evidence_link_now(),
                )
            )
        except Exception:
            valid_signed_query = False
        if not valid_signed_query:
            return templates.TemplateResponse(
                request=request,
                name="event_detail.html",
                context={"current": current, "event": None},
                status_code=status.HTTP_404_NOT_FOUND,
                headers={"Cache-Control": "no-store"},
            )
    try:
        pilot_site_id = resolve_pilot_site_id(context)
    except PilotSiteConfigurationError:
        return templates.TemplateResponse(
            request=request,
            name="event_detail.html",
            context={"current": current, "event": None},
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Cache-Control": "no-store"},
        )
    with context.repository.session_factory() as database_session:
        event_row = database_session.execute(
            select(CandidateEventModel, CameraModel.name)
            .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
            .where(
                CandidateEventModel.event_id == str(event_id),
                CameraModel.site_id == pilot_site_id,
            )
        ).one_or_none()
        if event_row is None:
            return templates.TemplateResponse(
                request=request,
                name="event_detail.html",
                context={"current": current, "event": None},
                status_code=status.HTTP_404_NOT_FOUND,
                headers={"Cache-Control": "no-store"},
            )
        event, camera_name = event_row
        history = list(
            database_session.execute(
                select(ReviewModel, UserModel.username)
                .join(UserModel, UserModel.user_id == ReviewModel.reviewer_id)
                .where(ReviewModel.event_id == str(event_id))
                .order_by(ReviewModel.reviewed_at, ReviewModel.review_id)
            )
        )
        evidence = database_session.scalar(
            select(EvidenceModel)
            .where(EvidenceModel.event_id == str(event_id))
            .order_by(EvidenceModel.created_at.desc(), EvidenceModel.evidence_id)
            .limit(1)
        )
        outbox = database_session.scalar(
            select(NotificationOutboxModel).where(
                NotificationOutboxModel.event_id == str(event_id)
            )
        )
        notification: NotificationState | None = None
        if outbox is not None:
            attempt_count = int(
                database_session.scalar(
                    select(func.max(DeliveryAttemptModel.attempt_number)).where(
                        DeliveryAttemptModel.outbox_id == outbox.outbox_id
                    )
                )
                or 0
            )
            latest_attempt = database_session.scalar(
                select(DeliveryAttemptModel)
                .where(DeliveryAttemptModel.outbox_id == outbox.outbox_id)
                .order_by(
                    DeliveryAttemptModel.attempt_number.desc(),
                    DeliveryAttemptModel.delivery_attempt_id,
                )
                .limit(1)
            )
            notification = NotificationState(
                status=outbox.status,
                attempt_count=attempt_count,
                last_error=(
                    latest_attempt.error[:256]
                    if latest_attempt is not None and latest_attempt.error
                    else None
                ),
            )
    can_review = (
        current.user.role in ("operator", "admin")
        and event.gate_mode == "operator"
        and event.review_status == "candidate"
    )
    preview_available = bool(
        event.evidence_status == "ready"
        and evidence is not None
        and evidence.status == "ready"
        and context.evidence_preview_provider is not None
    )
    return templates.TemplateResponse(
        request=request,
        name="event_detail.html",
        context={
            "current": current,
            "event": event,
            "camera_name": camera_name,
            "history": history,
            "evidence": evidence,
            "preview_available": preview_available,
            "can_review": can_review,
            "notification": notification,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.get("/evidence/{event_id}")
def evidence_preview(
    event_id: UUID,
    current: Annotated[ServerSession, Depends(get_current_session)],
    context: Annotated[ApiContext, Depends(get_context)],
) -> Response:
    del current
    provider = context.evidence_preview_provider
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="preview unavailable")
    try:
        pilot_site_id = resolve_pilot_site_id(context)
    except PilotSiteConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="preview unavailable",
        ) from exc
    with context.repository.session_factory() as database_session:
        evidence_is_ready = database_session.scalar(
            select(EvidenceModel.evidence_id)
            .join(
                CandidateEventModel,
                CandidateEventModel.event_id == EvidenceModel.event_id,
            )
            .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
            .where(
                CandidateEventModel.event_id == str(event_id),
                CameraModel.site_id == pilot_site_id,
                CandidateEventModel.evidence_status == "ready",
                EvidenceModel.status == "ready",
            )
            .limit(1)
        )
    if evidence_is_ready is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="preview unavailable")
    try:
        preview = provider.get_preview(event_id, max_bytes=MAX_PREVIEW_BYTES)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="preview provider failed",
        ) from exc
    if (
        preview is None
        or not isinstance(preview.content, bytes)
        or not preview.content
        or len(preview.content) > MAX_PREVIEW_BYTES
        or preview.media_type not in ALLOWED_PREVIEW_MEDIA_TYPES
    ):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="invalid preview response",
        )
    return Response(
        content=preview.content,
        media_type=preview.media_type,
        headers={"Cache-Control": "no-store"},
    )
