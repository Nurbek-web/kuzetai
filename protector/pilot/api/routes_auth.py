"""Password-plus-TOTP browser session routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from protector.pilot.api.auth import SessionUser
from protector.pilot.api.dependencies import ApiContext, get_context, redact_secrets, require_csrf
from protector.pilot.storage.models import UserModel

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
    username = body.username.strip().casefold()
    client_context = _client_context(request)
    if not context.throttle.admit_attempt(username, client_context):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="login throttled")

    with context.repository.session_factory() as database_session:
        user = database_session.scalar(
            select(UserModel).where(func.lower(UserModel.username) == username)
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
        SessionUser(user_id=user.user_id, username=user.username, role=user.role)
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
