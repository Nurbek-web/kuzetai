"""FastAPI application factory for the pilot control plane."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from protector.pilot.api.auth import LoginThrottle, PasswordService, SessionManager, TotpService
from protector.pilot.api.dependencies import ApiContext
from protector.pilot.api.routes_auth import router as auth_router
from protector.pilot.api.routes_cameras import router as cameras_router
from protector.pilot.api.routes_events import router as events_router
from protector.pilot.api.routes_internal import router as internal_router
from protector.pilot.storage.repositories import PilotRepository

MAX_REQUEST_BODY_BYTES = 64 * 1024


class RequestBodyLimitMiddleware:
    """Buffer at most one bounded body before routing or validation."""

    def __init__(self, app: Any, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
                if declared_length < 0:
                    await self._reject(send, status_code=400)
                    return
                if declared_length > self.max_body_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send, status_code=400)
                return

        buffered: list[dict[str, Any]] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > self.max_body_bytes:
                await self._reject(send)
                return
            buffered.append(message)
            if not message.get("more_body", False):
                break

        iterator = iter(buffered)

        async def replay() -> dict[str, Any]:
            try:
                return next(iterator)
            except StopIteration:
                return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(
        send: Callable[[dict[str, Any]], Awaitable[None]],
        *,
        status_code: int = 413,
    ) -> None:
        body = b'{"detail":"request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _configured_worker_count(explicit: int | None) -> int:
    configured = [
        value
        for value in (
            str(explicit) if explicit is not None else None,
            os.getenv("PILOT_API_WORKERS"),
            os.getenv("WEB_CONCURRENCY"),
        )
        if value is not None
    ]
    counts: list[int] = []
    for raw in configured or ["1"]:
        try:
            counts.append(int(raw))
        except ValueError as exc:
            raise ValueError("API worker count must be an integer") from exc
    return next((count for count in counts if count != 1), 1)


def create_app(
    *,
    repository: PilotRepository,
    session_secret: str,
    totp_encryption_key: str,
    machine_token: str,
    throttle: LoginThrottle | None = None,
    worker_count: int | None = None,
    max_request_body_bytes: int = MAX_REQUEST_BODY_BYTES,
) -> FastAPI:
    """Construct an explicitly configured app; secrets have no committed defaults."""

    if len(machine_token) < 16:
        raise ValueError("machine token must contain at least 16 characters")
    if session_secret == totp_encryption_key:
        raise ValueError("TOTP encryption key must be separate from the session signing key")
    if _configured_worker_count(worker_count) != 1:
        raise ValueError("in-process sessions and throttling require exactly one API worker")
    if max_request_body_bytes < 1:
        raise ValueError("request body limit must be positive")
    app = FastAPI(
        title="Kuzet AI Pilot Control Plane",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.pilot_context = ApiContext(
        repository=repository,
        sessions=SessionManager(session_secret),
        passwords=PasswordService(),
        totp=TotpService(encryption_key=totp_encryption_key),
        throttle=throttle or LoginThrottle(),
        machine_token=machine_token,
    )
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=max_request_body_bytes,
    )

    @app.exception_handler(RequestValidationError)
    async def redacted_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        del request
        errors = [
            {
                "type": error["type"],
                "loc": error["loc"],
                "msg": error["msg"],
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    app.include_router(auth_router)
    app.include_router(cameras_router)
    app.include_router(events_router)
    app.include_router(internal_router)
    return app
