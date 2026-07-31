"""FastAPI application factory for the pilot control plane."""

from __future__ import annotations

import fcntl
import os
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from protector.pilot.api.auth import (
    LoginThrottle,
    PasswordService,
    SessionManager,
    TotpService,
)
from protector.pilot.api.dependencies import (
    ApiContext,
    get_context,
    require_monitoring_machine_auth,
    utc_now,
)
from protector.pilot.api.routes_auth import router as auth_router
from protector.pilot.api.routes_cameras import router as cameras_router
from protector.pilot.api.routes_events import router as events_router
from protector.pilot.api.routes_internal import router as internal_router
from protector.pilot.api.web import (
    STATIC_ROOT,
    EvidencePreviewProvider,
)
from protector.pilot.api.web import (
    router as web_router,
)
from protector.pilot.metrics import PilotHealthService, PilotMetrics, PilotTelemetryState
from protector.pilot.notifications.base import EvidenceLinkSigner
from protector.pilot.storage.repositories import PilotRepository

MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_PILOT_SITE_ID_LENGTH = 128
DEFAULT_RUNTIME_LOCK_PATH = Path("/tmp/kuzet-ai-pilot-api.lock")


class ProcessSingletonLock:
    """Non-blocking inter-process lock released automatically on process exit."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._file_descriptor: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.ftruncate(descriptor, 0)
            os.write(descriptor, str(os.getpid()).encode())
            os.fsync(descriptor)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise RuntimeError(
                f"API singleton lock is already held: {self.path}; "
                "shared session/throttle state is required for extra workers"
            ) from exc
        except BaseException:
            os.close(descriptor)
            raise
        self._file_descriptor = descriptor

    def release(self) -> None:
        if self._file_descriptor is None:
            return
        descriptor = self._file_descriptor
        self._file_descriptor = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


class RequestBodyLimitMiddleware:
    """Buffer at most one bounded body before routing or validation."""

    def __init__(self, app: Any, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    def _limit_for_scope(self, scope: dict[str, Any]) -> int:
        return self.max_body_bytes

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        max_body_bytes = self._limit_for_scope(scope)
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
                if declared_length < 0:
                    await self._reject(send, status_code=400)
                    return
                if declared_length > max_body_bytes:
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
            if total > max_body_bytes:
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
                return await receive()

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


class PilotWebSecurityHeadersMiddleware:
    """Apply a closed content policy to console and same-origin static responses."""

    _headers = (
        (
            b"content-security-policy",
            (
                b"default-src 'none'; script-src 'self'; style-src 'self'; "
                b"img-src 'self' data:; media-src 'self'; connect-src 'self'; "
                b"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            ),
        ),
        (b"x-frame-options", b"DENY"),
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"no-referrer"),
        (b"cache-control", b"no-store"),
    )

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/pilot"):
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                protected_names = {name for name, _ in self._headers}
                message["headers"] = [
                    (name, value)
                    for name, value in message.get("headers", ())
                    if name.lower() not in protected_names
                ] + list(self._headers)
            await send(message)

        await self.app(scope, receive, send_with_headers)


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
    machine_token: str | None = None,
    runtime_machine_token: str | None = None,
    notification_machine_token: str | None = None,
    monitoring_machine_token: str | None = None,
    throttle: LoginThrottle | None = None,
    worker_count: int | None = None,
    max_request_body_bytes: int = MAX_REQUEST_BODY_BYTES,
    runtime_lock_path: str | Path | None = None,
    evidence_preview_provider: EvidencePreviewProvider | None = None,
    pilot_site_id: str | None = None,
    evidence_link_signer: EvidenceLinkSigner | None = None,
    evidence_link_now: Callable[[], datetime] | None = None,
    metrics: PilotMetrics | None = None,
    metrics_refresh: Callable[[], None] | None = None,
    telemetry: PilotTelemetryState | None = None,
    health: PilotHealthService | None = None,
) -> FastAPI:
    """Construct an explicitly configured app; secrets have no committed defaults.

    ``machine_token`` exists only for legacy test/demo construction. Production
    callers provide the scoped token arguments instead.
    """

    scoped_tokens = (
        runtime_machine_token,
        notification_machine_token,
        monitoring_machine_token,
    )
    if machine_token is not None:
        if any(token is not None for token in scoped_tokens):
            raise ValueError("legacy and scoped machine tokens cannot be mixed")
        runtime_machine_token = machine_token
        notification_machine_token = machine_token
        monitoring_machine_token = machine_token
    elif runtime_machine_token is None or monitoring_machine_token is None:
        raise ValueError("runtime and monitoring machine tokens are required")
    assert runtime_machine_token is not None
    assert monitoring_machine_token is not None
    configured_tokens = (runtime_machine_token, monitoring_machine_token)
    if notification_machine_token is not None:
        configured_tokens += (notification_machine_token,)
    if any(len(token) < 16 for token in configured_tokens):
        raise ValueError("machine tokens must contain at least 16 characters")
    if machine_token is None and len(set(configured_tokens)) != len(configured_tokens):
        raise ValueError("scoped machine tokens must be distinct")
    if session_secret == totp_encryption_key:
        raise ValueError("TOTP encryption key must be separate from the session signing key")
    if _configured_worker_count(worker_count) != 1:
        raise ValueError("in-process sessions and throttling require exactly one API worker")
    if max_request_body_bytes < 1:
        raise ValueError("request body limit must be positive")
    if evidence_link_now is not None and not callable(evidence_link_now):
        raise ValueError("evidence link clock must be callable")
    if metrics_refresh is not None and (metrics is None or not callable(metrics_refresh)):
        raise ValueError("metrics refresh requires metrics and must be callable")
    if telemetry is not None and metrics is None:
        raise ValueError("telemetry ingestion requires metrics")
    if pilot_site_id is not None:
        pilot_site_id = pilot_site_id.strip()
        if not pilot_site_id or len(pilot_site_id) > MAX_PILOT_SITE_ID_LENGTH:
            raise ValueError("pilot site identity must contain 1 to 128 characters")
    singleton = ProcessSingletonLock(
        runtime_lock_path or os.getenv("PILOT_API_LOCK_PATH") or DEFAULT_RUNTIME_LOCK_PATH
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> Any:
        singleton.acquire()
        try:
            yield
        finally:
            singleton.release()

    app = FastAPI(
        title="Kuzet AI Pilot Control Plane",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.pilot_context = ApiContext(
        repository=repository,
        sessions=SessionManager(session_secret),
        passwords=PasswordService(),
        totp=TotpService(encryption_key=totp_encryption_key),
        throttle=throttle or LoginThrottle(),
        runtime_machine_token=runtime_machine_token,
        notification_machine_token=notification_machine_token,
        monitoring_machine_token=monitoring_machine_token,
        evidence_preview_provider=evidence_preview_provider,
        pilot_site_id=pilot_site_id,
        evidence_link_signer=evidence_link_signer,
        evidence_link_now=evidence_link_now if evidence_link_now is not None else utc_now,
        metrics=metrics,
        metrics_refresh=metrics_refresh,
        telemetry=telemetry,
        health=health,
    )
    app.add_middleware(PilotWebSecurityHeadersMiddleware)
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

    @app.get(
        "/internal/metrics",
        include_in_schema=False,
        dependencies=[Depends(require_monitoring_machine_auth)],
    )
    def internal_metrics(context: ApiContext = Depends(get_context)) -> Response:
        if context.metrics is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="metrics unavailable",
            )
        if context.metrics_refresh is not None:
            try:
                context.metrics_refresh()
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="metrics unavailable",
                ) from None
        return Response(
            content=context.metrics.render(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get(
        "/internal/health/live",
        include_in_schema=False,
        dependencies=[Depends(require_monitoring_machine_auth)],
    )
    def internal_liveness(
        response: Response,
        context: ApiContext = Depends(get_context),
    ) -> dict[str, str]:
        if context.health is None:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "dead", "control_plane": "failed"}
        result = context.health.liveness()
        if result["status"] != "alive":
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return result

    @app.get(
        "/internal/health/ready",
        include_in_schema=False,
        dependencies=[Depends(require_monitoring_machine_auth)],
    )
    def internal_readiness(
        response: Response,
        context: ApiContext = Depends(get_context),
    ) -> dict[str, object]:
        if context.health is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="health unavailable",
            )
        result = context.health.readiness()
        if result["status"] != "ready":
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return result

    @app.get(
        "/internal/health",
        include_in_schema=False,
        dependencies=[Depends(require_monitoring_machine_auth)],
    )
    def internal_health(context: ApiContext = Depends(get_context)) -> dict[str, object]:
        if context.health is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="health unavailable",
            )
        return context.health.readiness()

    app.mount("/pilot/static", StaticFiles(directory=STATIC_ROOT), name="pilot-static")
    app.include_router(web_router)
    return app
