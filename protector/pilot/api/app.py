"""FastAPI application factory for the pilot control plane."""

from __future__ import annotations

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


def create_app(
    *,
    repository: PilotRepository,
    session_secret: str,
    machine_token: str,
    throttle: LoginThrottle | None = None,
) -> FastAPI:
    """Construct an explicitly configured app; secrets have no committed defaults."""

    if len(machine_token) < 16:
        raise ValueError("machine token must contain at least 16 characters")
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
        totp=TotpService(),
        throttle=throttle or LoginThrottle(),
        machine_token=machine_token,
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
