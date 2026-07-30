"""Password-plus-TOTP browser session routes."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from protector.pilot.api.auth import (
    ServerSession,
    SessionUser,
    normalize_username,
)
from protector.pilot.api.dependencies import (
    ApiContext,
    get_context,
    redact_secrets,
    require_csrf,
    require_roles,
    utc_now,
)
from protector.pilot.storage.models import UserModel
from protector.pilot.storage.repositories import (
    LastActiveAdminError,
    SoleSiteRequiredError,
    StaleAuthGenerationError,
    UsernameConflictError,
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024, repr=False)
    totp_code: str = Field(pattern=r"^\d{6}$")


def _client_context(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


@router.post("/login")
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    try:
        username = normalize_username(body.username)
    except ValueError:
        username = ""
    client_context = _client_context(request)
    if not context.throttle.admit_attempt(body.username, client_context):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="login throttled")

    with context.repository.session_factory() as database_session:
        user = database_session.scalar(
            select(UserModel).where(UserModel.normalized_username == username)
        )

    encoded = user.password_hash if user is not None else context.passwords.dummy_hash
    password_valid = context.passwords.verify(encoded, body.password)
    counter: int | None = None
    if user is not None and user.totp_secret_encrypted:
        try:
            counter = context.totp.match_current_counter(
                user.totp_secret_encrypted,
                body.totp_code,
            )
        except ValueError:
            counter = None
    credentials_valid = bool(
        user is not None and user.is_active and password_valid and counter is not None
    )
    counter_accepted = bool(
        credentials_valid
        and context.repository.accept_totp_counter(
            user_id=user.user_id,
            counter=counter,
            expected_password_hash=user.password_hash,
            expected_encrypted_secret=user.totp_secret_encrypted,
        )
    )
    if not credentials_valid or not counter_accepted:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    context.throttle.record_success(username)
    context.sessions.revoke(request.cookies.get(context.sessions.cookie_name))
    token, session = context.sessions.create(
        SessionUser(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            auth_generation=user.auth_generation,
        )
    )
    response.set_cookie(
        key=context.sessions.cookie_name,
        value=token,
        max_age=context.sessions.ttl_seconds,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return {
        "user": redact_secrets(
            {
                "user_id": user.user_id,
                "username": user.username,
                "role": user.role,
            }
        ),
        "csrf_token": session.csrf_token,
        "expires_in": context.sessions.ttl_seconds,
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    current: Annotated[object, Depends(require_csrf)],
    context: Annotated[ApiContext, Depends(get_context)],
) -> None:
    del current
    context.sessions.revoke(request.cookies.get(context.sessions.cookie_name))
    response.delete_cookie(
        context.sessions.cookie_name,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024, repr=False)
    role: Literal["viewer", "operator", "admin"]


class RoleChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["viewer", "operator", "admin"]
    expected_auth_generation: int = Field(ge=1)


class ActiveChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool
    expected_auth_generation: int = Field(ge=1)


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=1024, repr=False)
    expected_auth_generation: int = Field(ge=1)


class GenerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_auth_generation: int = Field(ge=1)


def _require_admin_csrf(
    current: Annotated[ServerSession, Depends(require_csrf)],
) -> ServerSession:
    if current.user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="insufficient role",
        )
    return current


def _user_payload(user: UserModel) -> dict[str, object]:
    return {
        "user_id": user.user_id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
        "auth_generation": user.auth_generation,
        "created_at": user.created_at,
    }


def _raise_lifecycle_error(exc: BaseException) -> None:
    if isinstance(exc, StaleAuthGenerationError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "stale_auth_generation",
                "expected": exc.expected,
                "actual": exc.actual,
            },
        ) from exc
    if isinstance(exc, LastActiveAdminError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "last_active_admin"},
        ) from exc
    if isinstance(exc, UsernameConflictError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "username_conflict"},
        ) from exc
    if isinstance(exc, KeyError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "user_not_found"},
        ) from exc
    if isinstance(exc, SoleSiteRequiredError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "pilot_site_unavailable"},
        ) from exc
    raise exc


@router.get("/users")
def list_users(
    current: Annotated[ServerSession, Depends(require_roles("admin"))],
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    del current
    try:
        users = context.repository.list_users()
    except SoleSiteRequiredError as exc:
        _raise_lifecycle_error(exc)
        raise AssertionError("unreachable")
    return {"items": [_user_payload(user) for user in users], "total": len(users)}


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    body: CreateUserRequest,
    current: Annotated[ServerSession, Depends(_require_admin_csrf)],
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    enrolment = context.totp.enrol(body.username)
    try:
        user = context.repository.create_user(
            actor_user_id=current.user.user_id,
            user_id=str(uuid4()),
            username=body.username,
            password_hash=context.passwords.hash(body.password),
            role=body.role,
            totp_secret_encrypted=context.totp.encrypt_secret(enrolment.secret),
            occurred_at=utc_now(),
        )
    except (SoleSiteRequiredError, UsernameConflictError) as exc:
        _raise_lifecycle_error(exc)
        raise AssertionError("unreachable")
    return {
        "user": _user_payload(user),
        "totp_enrolment": {
            "secret": enrolment.secret,
            "provisioning_uri": enrolment.provisioning_uri,
        },
    }


def _mutation_response(context: ApiContext, user: UserModel) -> dict[str, object]:
    context.sessions.revoke_user(user.user_id)
    return {"user": _user_payload(user)}


@router.put("/users/{user_id}/role")
def change_user_role(
    user_id: str,
    body: RoleChangeRequest,
    current: Annotated[ServerSession, Depends(_require_admin_csrf)],
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    try:
        user = context.repository.set_user_role(
            actor_user_id=current.user.user_id,
            user_id=user_id,
            role=body.role,
            expected_auth_generation=body.expected_auth_generation,
            occurred_at=utc_now(),
        )
    except (KeyError, LastActiveAdminError, SoleSiteRequiredError, StaleAuthGenerationError) as exc:
        _raise_lifecycle_error(exc)
        raise AssertionError("unreachable")
    return _mutation_response(context, user)


@router.put("/users/{user_id}/active")
def change_user_active(
    user_id: str,
    body: ActiveChangeRequest,
    current: Annotated[ServerSession, Depends(_require_admin_csrf)],
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    try:
        user = context.repository.set_user_active(
            actor_user_id=current.user.user_id,
            user_id=user_id,
            is_active=body.is_active,
            expected_auth_generation=body.expected_auth_generation,
            occurred_at=utc_now(),
        )
    except (KeyError, LastActiveAdminError, SoleSiteRequiredError, StaleAuthGenerationError) as exc:
        _raise_lifecycle_error(exc)
        raise AssertionError("unreachable")
    return _mutation_response(context, user)


@router.put("/users/{user_id}/password")
def change_user_password(
    user_id: str,
    body: PasswordChangeRequest,
    current: Annotated[ServerSession, Depends(_require_admin_csrf)],
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    try:
        user = context.repository.set_user_password(
            actor_user_id=current.user.user_id,
            user_id=user_id,
            password_hash=context.passwords.hash(body.password),
            expected_auth_generation=body.expected_auth_generation,
            occurred_at=utc_now(),
        )
    except (KeyError, SoleSiteRequiredError, StaleAuthGenerationError) as exc:
        _raise_lifecycle_error(exc)
        raise AssertionError("unreachable")
    return _mutation_response(context, user)


@router.post("/users/{user_id}/totp-reset")
def reset_user_totp(
    user_id: str,
    body: GenerationRequest,
    current: Annotated[ServerSession, Depends(_require_admin_csrf)],
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    enrolment = context.totp.enrol(user_id)
    try:
        user = context.repository.reset_user_totp(
            actor_user_id=current.user.user_id,
            user_id=user_id,
            totp_secret_encrypted=context.totp.encrypt_secret(enrolment.secret),
            expected_auth_generation=body.expected_auth_generation,
            occurred_at=utc_now(),
        )
    except (KeyError, SoleSiteRequiredError, StaleAuthGenerationError) as exc:
        _raise_lifecycle_error(exc)
        raise AssertionError("unreachable")
    response = _mutation_response(context, user)
    response["totp_enrolment"] = {
        "secret": enrolment.secret,
        "provisioning_uri": enrolment.provisioning_uri,
    }
    return response


@router.post("/users/{user_id}/sessions/revoke")
def revoke_user_sessions(
    user_id: str,
    body: GenerationRequest,
    current: Annotated[ServerSession, Depends(_require_admin_csrf)],
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    try:
        user = context.repository.revoke_user_sessions(
            actor_user_id=current.user.user_id,
            user_id=user_id,
            expected_auth_generation=body.expected_auth_generation,
            occurred_at=utc_now(),
        )
    except (KeyError, SoleSiteRequiredError, StaleAuthGenerationError) as exc:
        _raise_lifecycle_error(exc)
        raise AssertionError("unreachable")
    return _mutation_response(context, user)
