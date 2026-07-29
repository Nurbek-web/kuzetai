"""Fail-closed production factory for the pilot API container."""

from __future__ import annotations

import base64
import binascii
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from protector.pilot.api.app import create_app
from protector.pilot.metrics import HealthProbeSnapshot, PilotHealthService, PilotMetrics
from protector.pilot.notifications.base import EvidenceLinkSigner
from protector.pilot.storage.db import SessionFactory, create_engine, create_session_factory
from protector.pilot.storage.models import (
    CameraHealthSampleModel,
    CameraModel,
    ModelArtifactModel,
    SiteModel,
)
from protector.pilot.storage.repositories import PilotRepository

_SECRETS_ROOT = Path("/run/secrets")
_HEALTH_ROOT = Path("/run/kuzet/health")
_FINITE_COMPONENT_STATES = frozenset({"healthy", "degraded", "failed"})
_MAX_SECRET_BYTES = 16 * 1024


def read_component_state(path: Path) -> str:
    """Read one tiny local state token; missing, linked, or verbose files fail closed."""
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > 32:
            return "failed"
        value = os.read(descriptor, 33).decode("ascii").strip()
    except (OSError, UnicodeError):
        return "failed"
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return value if value in _FINITE_COMPONENT_STATES else "failed"


def build_evidence_link_signer(
    *,
    encoded_secret: str,
    application_origin: str,
    ttl_seconds: int,
) -> EvidenceLinkSigner:
    """Decode a Docker-secret key and build the bounded notification-link signer."""
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
        raise ValueError("signed link TTL must be an integer")
    try:
        secret = base64.b64decode(encoded_secret, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("evidence link secret must be URL-safe base64") from exc
    return EvidenceLinkSigner(
        secret=secret,
        application_origin=application_origin,
        ttl=timedelta(seconds=ttl_seconds),
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def source_health_state(
    *,
    camera_state: str,
    sample_state: str | None,
    last_frame_at: datetime | None,
    observed_at: datetime | None,
    now: datetime,
    stale_after_seconds: int,
) -> str:
    """Return a bounded source state only when the latest source sample is fresh."""
    if (
        not isinstance(stale_after_seconds, int)
        or isinstance(stale_after_seconds, bool)
        or not 1 <= stale_after_seconds <= 30
    ):
        raise ValueError("source stale threshold must be between 1 and 30 seconds")
    if sample_state is None or last_frame_at is None or observed_at is None:
        return "offline"
    if camera_state != "online" or sample_state != "online":
        return sample_state if sample_state in {"starting", "degraded", "offline", "reconnecting"} else "degraded"
    current = _as_utc(now)
    frame_age = (current - _as_utc(last_frame_at)).total_seconds()
    sample_age = (current - _as_utc(observed_at)).total_seconds()
    if not 0 <= frame_age <= stale_after_seconds or not 0 <= sample_age <= stale_after_seconds:
        return "degraded"
    return "online"


def refresh_camera_metrics(
    *,
    metrics: PilotMetrics,
    session_factory: SessionFactory,
    site_id: str,
    camera_ids: tuple[str, ...],
    stale_after_seconds: int,
    now: datetime,
) -> None:
    """Refresh DB-backed source metrics for the authoritative configured camera set."""
    with session_factory() as session:
        camera_rows = list(
            session.scalars(
                select(CameraModel)
                .where(CameraModel.site_id == site_id, CameraModel.enabled.is_(True))
                .order_by(CameraModel.camera_id)
            )
        )
        if {row.camera_id for row in camera_rows} != set(camera_ids):
            raise RuntimeError("authoritative pilot camera set changed")
        latest_health = {
            row.camera_id: session.scalar(
                select(CameraHealthSampleModel)
                .where(CameraHealthSampleModel.camera_id == row.camera_id)
                .order_by(
                    CameraHealthSampleModel.observed_at.desc(),
                    CameraHealthSampleModel.health_sample_id.desc(),
                )
                .limit(1)
            )
            for row in camera_rows
        }
    current = _as_utc(now)
    for row in camera_rows:
        sample = latest_health[row.camera_id]
        state = source_health_state(
            camera_state=row.state,
            sample_state=sample.state if sample is not None else None,
            last_frame_at=sample.last_frame_at if sample is not None else None,
            observed_at=sample.observed_at if sample is not None else None,
            now=current,
            stale_after_seconds=stale_after_seconds,
        )
        frame_age = (
            max(0.0, (current - _as_utc(sample.last_frame_at)).total_seconds())
            if sample is not None and sample.last_frame_at is not None
            else float(stale_after_seconds + 1)
        )
        metrics.update_camera(
            row.camera_id,
            available=state == "online",
            last_frame_age_seconds=frame_age,
            reconnects_total=sample.reconnect_count if sample is not None else 0,
        )


def _read_secret(name: str) -> str:
    path = _SECRETS_ROOT / name
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("required API secret is unavailable") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or not 0 < file_stat.st_size <= _MAX_SECRET_BYTES:
            raise RuntimeError("required API secret is invalid")
        payload = os.read(descriptor, _MAX_SECRET_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeError as exc:
        raise RuntimeError("required API secret is invalid") from exc
    if not value:
        raise RuntimeError("required API secret is invalid")
    return value


def create_production_app() -> object:
    """Build one exact-site API process from fixed Docker-secret locations."""
    site_id = os.environ.get("PILOT_SITE_ID", "").strip()
    public_origin = os.environ.get("PILOT_PUBLIC_ORIGIN", "").strip()
    try:
        link_ttl_seconds = int(os.environ.get("PILOT_EVIDENCE_LINK_TTL_SECONDS", "900"))
        stale_after_seconds = int(os.environ.get("PILOT_SOURCE_STALE_AFTER_SECONDS", "5"))
    except ValueError as exc:
        raise RuntimeError("pilot timing bounds must be integers") from exc
    if not site_id or len(site_id) > 128:
        raise RuntimeError("PILOT_SITE_ID must identify one configured pilot site")
    if not public_origin:
        raise RuntimeError("PILOT_PUBLIC_ORIGIN is required")

    engine = create_engine(_read_secret("database_url"))
    session_factory = create_session_factory(engine)
    repository = PilotRepository(
        session_factory,
        totp_encryption_key=_read_secret("totp_encryption_key"),
    )
    with session_factory() as session:
        if session.get(SiteModel, site_id) is None:
            raise RuntimeError("configured pilot site is unavailable")
        camera_ids = tuple(
            session.scalars(
                select(CameraModel.camera_id)
                .where(CameraModel.site_id == site_id, CameraModel.enabled.is_(True))
                .order_by(CameraModel.camera_id)
            )
        )
        artifact_ids = tuple(
            session.scalars(select(ModelArtifactModel.artifact_id).order_by(ModelArtifactModel.artifact_id))
        )

    def probe() -> HealthProbeSnapshot:
        try:
            with session_factory() as session:
                persisted_site = session.get(SiteModel, site_id)
                camera_rows = list(
                    session.scalars(
                        select(CameraModel)
                        .where(CameraModel.site_id == site_id, CameraModel.enabled.is_(True))
                        .order_by(CameraModel.camera_id)
                    )
                )
                latest_health = {
                    row.camera_id: session.scalar(
                        select(CameraHealthSampleModel)
                        .where(CameraHealthSampleModel.camera_id == row.camera_id)
                        .order_by(
                            CameraHealthSampleModel.observed_at.desc(),
                            CameraHealthSampleModel.health_sample_id.desc(),
                        )
                        .limit(1)
                    )
                    for row in camera_rows
                }
            database = "healthy" if persisted_site is not None else "failed"
            now = datetime.now(UTC)
            camera_states = {
                row.camera_id: source_health_state(
                    camera_state=row.state,
                    sample_state=latest_health[row.camera_id].state
                    if latest_health[row.camera_id] is not None
                    else None,
                    last_frame_at=latest_health[row.camera_id].last_frame_at
                    if latest_health[row.camera_id] is not None
                    else None,
                    observed_at=latest_health[row.camera_id].observed_at
                    if latest_health[row.camera_id] is not None
                    else None,
                    now=now,
                    stale_after_seconds=stale_after_seconds,
                )
                for row in camera_rows
            }
        except Exception:
            database = "failed"
            camera_states = {}
        return HealthProbeSnapshot(
            site_id=site_id,
            camera_states=camera_states,  # type: ignore[arg-type]
            control_plane="healthy",
            database=database,  # type: ignore[arg-type]
            analytics=read_component_state(_HEALTH_ROOT / "analytics"),
            evidence=read_component_state(_HEALTH_ROOT / "evidence"),
            notifications=read_component_state(_HEALTH_ROOT / "notifications"),
        )

    metrics = PilotMetrics(
        site_id=site_id,
        camera_ids=camera_ids,
        model_artifact_ids=artifact_ids,
    )

    def refresh_metrics() -> None:
        refresh_camera_metrics(
            metrics=metrics,
            session_factory=session_factory,
            site_id=site_id,
            camera_ids=camera_ids,
            stale_after_seconds=stale_after_seconds,
            now=datetime.now(UTC),
        )

    signer = build_evidence_link_signer(
        encoded_secret=_read_secret("evidence_link_secret"),
        application_origin=public_origin,
        ttl_seconds=link_ttl_seconds,
    )
    return create_app(
        repository=repository,
        session_secret=_read_secret("session_secret"),
        totp_encryption_key=_read_secret("totp_encryption_key"),
        machine_token=_read_secret("machine_token"),
        pilot_site_id=site_id,
        evidence_link_signer=signer,
        evidence_link_now=lambda: datetime.now(UTC),
        metrics=metrics,
        metrics_refresh=refresh_metrics,
        health=PilotHealthService(
            site_id=site_id,
            camera_ids=camera_ids,
            probe=probe,
        ),
        runtime_lock_path="/tmp/kuzet-api.lock",
    )
