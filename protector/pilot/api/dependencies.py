"""FastAPI dependencies for sessions, roles, CSRF, and machine authentication."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select

from protector.pilot.api.auth import (
    LoginThrottle,
    PasswordService,
    Role,
    ServerSession,
    SessionManager,
    TotpService,
    machine_token_matches,
)
from protector.pilot.metrics import PilotHealthService, PilotMetrics
from protector.pilot.notifications.base import EvidenceLinkSigner
from protector.pilot.storage.models import CameraModel, SiteModel, UserModel
from protector.pilot.storage.repositories import PilotRepository


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ApiContext:
    repository: PilotRepository
    sessions: SessionManager
    passwords: PasswordService
    totp: TotpService
    throttle: LoginThrottle
    machine_token: str = field(repr=False)
    evidence_preview_provider: Any | None = field(default=None, repr=False)
    pilot_site_id: str | None = None
    evidence_link_signer: EvidenceLinkSigner | None = field(default=None, repr=False)
    evidence_link_now: Callable[[], datetime] = field(default=utc_now, repr=False)
    metrics: PilotMetrics | None = field(default=None, repr=False)
    metrics_refresh: Callable[[], None] | None = field(default=None, repr=False)
    health: PilotHealthService | None = field(default=None, repr=False)


class PilotSiteConfigurationError(RuntimeError):
    """The control plane cannot identify one authoritative pilot site."""


def resolve_pilot_site_id(context: ApiContext) -> str:
    configured_site_id = context.pilot_site_id
    with context.repository.session_factory() as database_session:
        if configured_site_id is not None:
            persisted_site_id = database_session.scalar(
                select(SiteModel.site_id).where(SiteModel.site_id == configured_site_id)
            )
            if persisted_site_id is None:
                raise PilotSiteConfigurationError("configured pilot site is missing")
            return persisted_site_id
        enabled_site_ids = list(
            database_session.scalars(
                select(CameraModel.site_id)
                .where(CameraModel.enabled.is_(True))
                .distinct()
                .order_by(CameraModel.site_id)
            )
        )
    if len(enabled_site_ids) != 1:
        raise PilotSiteConfigurationError("pilot site identity is ambiguous")
    return enabled_site_ids[0]


def get_context(request: Request) -> ApiContext:
    return request.app.state.pilot_context


def require_pilot_site_id(
    context: Annotated[ApiContext, Depends(get_context)],
) -> str:
    try:
        return resolve_pilot_site_id(context)
    except PilotSiteConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pilot site unavailable",
        ) from exc


def get_current_session(
    request: Request,
    context: Annotated[ApiContext, Depends(get_context)],
) -> ServerSession:
    token = request.cookies.get(context.sessions.cookie_name)
    current = context.sessions.resolve(token)
    if current is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required"
        )
    with context.repository.session_factory() as database_session:
        user = database_session.get(UserModel, current.user.user_id)
        if (
            user is None
            or not user.is_active
            or user.username != current.user.username
            or user.role != current.user.role
        ):
            context.sessions.revoke(token)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
            )
    return current


def require_roles(*allowed: Role) -> Any:
    def dependency(
        current: Annotated[ServerSession, Depends(get_current_session)],
    ) -> ServerSession:
        if current.user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return current

    return dependency


def require_csrf(
    current: Annotated[ServerSession, Depends(get_current_session)],
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> ServerSession:
    if csrf_token is None or not machine_token_matches(csrf_token, current.csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid CSRF token")
    return current


def require_idempotency_key(
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> str:
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "idempotency_key_required"},
        )
    normalized = idempotency_key.strip()
    if len(normalized) > 255:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "idempotency_key_invalid"},
        )
    return normalized


def require_machine_auth(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    context: Annotated[ApiContext, Depends(get_context)] = None,  # type: ignore[assignment]
) -> None:
    scheme, separator, credential = (authorization or "").partition(" ")
    if (
        separator != " "
        or scheme.casefold() != "bearer"
        or not credential
        or not machine_token_matches(credential, context.machine_token)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="machine authentication required"
        )


_CREDENTIAL_KEY_MARKERS = frozenset(
    {
        "authorization",
        "credential",
        "password",
        "secret",
        "token",
        "accesskey",
        "apikey",
        "rtsp",
        "objectstore",
        "objectkey",
        "sourcereference",
        "url",
        "uri",
        "header",
        "cookie",
    }
)
_URI = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
_BEARER = re.compile(r"\bbearer\s+\S+", re.IGNORECASE)
_INLINE_SECRET = re.compile(
    r"\b(access[_-]?key|secret[_-]?key|password|token|authorization)=\S+",
    re.IGNORECASE,
)


def _credential_like_key(key: object) -> bool:
    collapsed = re.sub(r"[^a-z0-9]", "", str(key).casefold())
    return any(marker in collapsed for marker in _CREDENTIAL_KEY_MARKERS)


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if _credential_like_key(key) else redact_secrets(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        if _URI.search(value) or _BEARER.search(value) or _INLINE_SECRET.search(value):
            return "[REDACTED]"
        return value
    return value
