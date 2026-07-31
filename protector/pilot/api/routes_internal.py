"""Machine-authenticated runtime ingestion routes."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from protector.pilot.api.dependencies import (
    ApiContext,
    PilotSiteConfigurationError,
    authorize_machine_role,
    get_context,
    get_machine_credential,
    require_runtime_machine_auth,
    resolve_pilot_site_id,
)
from protector.pilot.domain import ObservationV1
from protector.pilot.storage.models import CameraHealthSampleModel, CameraModel

router = APIRouter(prefix="/api/internal", tags=["internal"])


@router.post(
    "/observations",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_runtime_machine_auth)],
)
def ingest_observation(
    observation: ObservationV1,
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, str]:
    if context.telemetry is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "legacy_observation_ingest_disabled"},
        )
    if not observation.is_fresh:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="cached display samples cannot be ingested as fresh votes",
        )
    try:
        context.repository.add_observation(observation)
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "duplicate_or_invalid_observation"},
        ) from exc
    return {"observation_id": str(observation.observation_id), "status": "accepted"}


class HealthSampleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    camera_id: str = Field(min_length=1, max_length=128)
    runtime_session_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
    )
    observed_at: datetime
    state: Literal["starting", "online", "degraded", "offline", "reconnecting"]
    last_frame_at: datetime | None = None
    reconnect_count: int = Field(ge=0)
    dropped_samples: int = Field(ge=0)
    degraded_reason: str | None = Field(default=None, max_length=2_000)

    @field_validator("observed_at", "last_frame_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("health timestamps must be UTC-aware")
        return value.astimezone(timezone.utc)


@router.post(
    "/health",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_runtime_machine_auth)],
)
def ingest_health(
    sample: HealthSampleRequest,
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    if context.telemetry is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "authoritative_telemetry_required"},
        )
    row_ids = _persist_health_samples((sample,), context)
    return {"health_sample_id": row_ids[0], "status": "accepted"}


def _persist_health_samples(
    samples: tuple[HealthSampleRequest, ...] | list[HealthSampleRequest],
    context: ApiContext,
) -> tuple[int, ...]:
    try:
        site_id = resolve_pilot_site_id(context)
    except PilotSiteConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pilot site unavailable",
        ) from exc
    with context.repository.session_factory.begin() as session:
        return _persist_health_samples_in_session(
            samples,
            context,
            session,
            site_id=site_id,
        )


def _persist_health_samples_in_session(
    samples: tuple[HealthSampleRequest, ...] | list[HealthSampleRequest],
    context: ApiContext,
    session: Session,
    *,
    site_id: str,
) -> tuple[int, ...]:
    camera_ids = [sample.camera_id for sample in samples]
    if len(set(camera_ids)) != len(camera_ids):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"code": "duplicate_camera_health"},
        )
    cameras = list(
        session.scalars(
            select(CameraModel)
            .where(
                CameraModel.camera_id.in_(camera_ids),
                CameraModel.site_id == site_id,
                CameraModel.enabled.is_(True),
            )
            .with_for_update()
        )
    )
    cameras_by_id = {camera.camera_id: camera for camera in cameras}
    if set(cameras_by_id) != set(camera_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "camera_not_found"},
        )
    latest_observed = {
        camera_id: session.scalar(
            select(CameraHealthSampleModel.observed_at)
            .where(CameraHealthSampleModel.camera_id == camera_id)
            .order_by(
                CameraHealthSampleModel.observed_at.desc(),
                CameraHealthSampleModel.health_sample_id.desc(),
            )
            .limit(1)
        )
        for camera_id in camera_ids
    }
    for sample in samples:
        latest_observed_at = latest_observed[sample.camera_id]
        if latest_observed_at is not None and latest_observed_at.tzinfo is None:
            latest_observed_at = latest_observed_at.replace(tzinfo=UTC)
        if (
            latest_observed_at is not None
            and sample.observed_at < latest_observed_at.astimezone(UTC)
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "stale_health_sample"},
            )
    if session.get_bind().dialect.name == "postgresql":
        row_ids: list[int] = []
        for sample in samples:
            row_id = session.scalar(
                text(
                    """
                    SELECT public.pilot_upsert_camera_health_sample(
                        :site_id,
                        CAST(:sample AS jsonb)
                    )
                    """
                ),
                {
                    "site_id": site_id,
                    "sample": json.dumps(
                        sample.model_dump(mode="json"),
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            )
            if type(row_id) is not int or row_id <= 0:
                raise RuntimeError(
                    "camera health upsert returned an invalid identity"
                )
            row_ids.append(row_id)
        for sample in samples:
            cameras_by_id[sample.camera_id].state = sample.state
        return tuple(row_ids)
    rows = [CameraHealthSampleModel(**sample.model_dump()) for sample in samples]
    session.add_all(rows)
    for sample in samples:
        cameras_by_id[sample.camera_id].state = sample.state
    try:
        session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "invalid_health_sample"},
        ) from exc
    return tuple(row.health_sample_id for row in rows)


ModuleName = Literal[
    "person",
    "restricted_zone",
    "intrusion",
    "loitering",
    "line_crossing",
    "fire",
    "fire_smoke",
    "weapon",
    "fight",
    "fall",
    "violence",
    "xclip",
    "vit",
]


class ComponentTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal["analytics", "evidence", "notifications"]
    state: Literal["healthy", "degraded", "failed"]


class SampleTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    camera_id: str = Field(min_length=1, max_length=128)
    module: ModuleName
    scheduled_total: int = Field(ge=0)
    processed_total: int = Field(ge=0)
    dropped_total: int = Field(ge=0)

    @field_validator("dropped_total")
    @classmethod
    def outcomes_fit_schedule(cls, value: int, info: object) -> int:
        data = getattr(info, "data", {})
        scheduled = data.get("scheduled_total")
        processed = data.get("processed_total")
        if scheduled is not None and processed is not None and processed + value > scheduled:
            raise ValueError("processed and dropped samples cannot exceed scheduled samples")
        return value


class QueueTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal["decode", "analytics", "verifier", "events", "evidence", "notifications"]
    age_seconds: float = Field(ge=0, allow_inf_nan=False)


class ModelLatencyTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: ModuleName
    model_artifact_id: str = Field(min_length=1, max_length=128)
    latency_seconds: float = Field(ge=0, allow_inf_nan=False)


class CounterTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: ModuleName
    total: int = Field(ge=0)


class ResultTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: Literal[
        "ready",
        "failed",
        "unavailable",
        "attempted",
        "delivered",
        "dead_letter",
    ]
    total: int = Field(ge=0)


class GpuTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    utilization_percent: float = Field(ge=0, le=100, allow_inf_nan=False)
    vram_used_bytes: int = Field(ge=0)
    vram_capacity_bytes: int = Field(gt=0)


class DiskTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    used_bytes: int = Field(ge=0)
    capacity_bytes: int = Field(gt=0)


class TelemetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    publisher: Literal["runtime", "notifications"]
    runtime_session_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
    )
    publisher_generation: int = Field(ge=1, le=9_223_372_036_854_775_807)
    sequence: int = Field(ge=0)
    observed_at: datetime
    components: list[ComponentTelemetry] = Field(min_length=1, max_length=3)
    health: list[HealthSampleRequest] = Field(default_factory=list, max_length=20)
    samples: list[SampleTelemetry] = Field(default_factory=list, max_length=500)
    queues: list[QueueTelemetry] = Field(default_factory=list, max_length=12)
    model_latencies: list[ModelLatencyTelemetry] = Field(default_factory=list, max_length=500)
    candidate_totals: list[CounterTelemetry] = Field(default_factory=list, max_length=32)
    evidence_results: list[ResultTelemetry] = Field(default_factory=list, max_length=8)
    evidence_latencies_seconds: list[float] = Field(default_factory=list, max_length=500)
    gpu: GpuTelemetry | None = None
    disk: DiskTelemetry | None = None
    notification_results: list[ResultTelemetry] = Field(default_factory=list, max_length=8)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("telemetry timestamp must be UTC-aware")
        return value.astimezone(UTC)

    @field_validator("evidence_latencies_seconds")
    @classmethod
    def evidence_latencies_are_finite(cls, values: list[float]) -> list[float]:
        if any(value < 0 or value == float("inf") or value != value for value in values):
            raise ValueError("evidence latency must be finite and non-negative")
        return values

    @field_validator("gpu")
    @classmethod
    def gpu_usage_fits_capacity(cls, value: GpuTelemetry | None) -> GpuTelemetry | None:
        if value is not None and value.vram_used_bytes > value.vram_capacity_bytes:
            raise ValueError("VRAM use must fit capacity")
        return value

    @field_validator("disk")
    @classmethod
    def disk_usage_fits_capacity(cls, value: DiskTelemetry | None) -> DiskTelemetry | None:
        if value is not None and value.used_bytes > value.capacity_bytes:
            raise ValueError("disk use must fit capacity")
        return value

    @model_validator(mode="after")
    def publisher_owns_fields_and_finite_keys_are_unique(self) -> TelemetryRequest:
        runtime_fields_present = any(
            (
                self.health,
                self.samples,
                self.queues,
                self.model_latencies,
                self.candidate_totals,
                self.evidence_results,
                self.evidence_latencies_seconds,
                self.gpu is not None,
                self.disk is not None,
            )
        )
        if self.publisher == "runtime" and self.notification_results:
            raise ValueError("runtime publisher cannot report notification metrics")
        if self.publisher == "notifications" and runtime_fields_present:
            raise ValueError("notification publisher cannot report runtime metrics")
        if any(
            item.result not in {"ready", "failed", "unavailable"}
            for item in self.evidence_results
        ):
            raise ValueError("runtime evidence result is invalid")
        if any(
            item.result not in {"attempted", "delivered", "failed", "dead_letter"}
            for item in self.notification_results
        ):
            raise ValueError("notification result is invalid")
        finite_keys = (
            [("component", item.name) for item in self.components]
            + [("health", item.camera_id) for item in self.health]
            + [("sample", item.camera_id, item.module) for item in self.samples]
            + [("queue", item.name) for item in self.queues]
            + [("candidate", item.module) for item in self.candidate_totals]
            + [("evidence", item.result) for item in self.evidence_results]
            + [("notification", item.result) for item in self.notification_results]
        )
        if len(set(finite_keys)) != len(finite_keys):
            raise ValueError("telemetry finite keys must be unique")
        return self


@router.post(
    "/telemetry",
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_telemetry(
    payload: TelemetryRequest,
    context: Annotated[ApiContext, Depends(get_context)],
    credential: Annotated[str, Depends(get_machine_credential)],
) -> dict[str, str]:
    authorize_machine_role(
        credential=credential,
        context=context,
        role="notification" if payload.publisher == "notifications" else "runtime",
    )
    if context.metrics is None or context.telemetry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="telemetry unavailable",
        )
    components = {item.name: item.state for item in payload.components}
    snapshot_values: list[tuple[tuple[str, ...], int]] = []
    for item in payload.samples:
        if item.camera_id not in context.metrics.camera_ids:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "invalid_telemetry", "message": "camera is not configured"},
            )
        snapshot_values.extend(
            (
                (("sample", item.camera_id, item.module, "scheduled"), item.scheduled_total),
                (("sample", item.camera_id, item.module, "processed"), item.processed_total),
                (("sample", item.camera_id, item.module, "dropped"), item.dropped_total),
            )
        )
    if payload.publisher == "runtime" and (
        len(payload.health) != 20
        or {item.camera_id for item in payload.health} != context.metrics.camera_ids
        or any(
            item.runtime_session_id != payload.runtime_session_id
            or item.observed_at != payload.observed_at
            for item in payload.health
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "invalid_telemetry",
                "message": "runtime health must cover the exact configured camera set",
            },
        )
    for item in payload.model_latencies:
        if item.model_artifact_id not in context.metrics.model_artifact_ids:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "invalid_telemetry",
                    "message": "model artifact is not configured",
                },
            )
    snapshot_values.extend(
        (("candidate", item.module), item.total) for item in payload.candidate_totals
    )
    snapshot_values.extend(
        (("evidence", item.result), item.total) for item in payload.evidence_results
    )
    snapshot_values.extend(
        (("notification", item.result), item.total)
        for item in payload.notification_results
    )
    try:
        context.metrics.validate_snapshot_values(
            snapshot_values,
            runtime_session_id=payload.runtime_session_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"code": "invalid_telemetry", "message": str(exc)},
        ) from exc

    def update_metrics() -> None:
        assert context.metrics is not None
        # Revalidate while PilotTelemetryState holds the publisher lock.  The
        # earlier pass rejects bad envelopes before lock contention; this pass
        # closes the race with another request advancing a cumulative snapshot.
        context.metrics.validate_snapshot_values(
            snapshot_values,
            runtime_session_id=payload.runtime_session_id,
        )
        for item in payload.samples:
            context.metrics.update_samples(
                item.camera_id,
                module=item.module,
                scheduled_total=item.scheduled_total,
                processed_total=item.processed_total,
                dropped_total=item.dropped_total,
                runtime_session_id=payload.runtime_session_id,
            )
        for item in payload.queues:
            context.metrics.set_queue_age(queue=item.name, age_seconds=item.age_seconds)
        for item in payload.model_latencies:
            context.metrics.observe_model_latency(
                module=item.module,
                model_artifact_id=item.model_artifact_id,
                latency_seconds=item.latency_seconds,
            )
        for item in payload.candidate_totals:
            context.metrics.update_candidate_total(
                module=item.module,
                total=item.total,
                runtime_session_id=payload.runtime_session_id,
            )
        for item in payload.evidence_results:
            if item.result not in {"ready", "failed", "unavailable"}:
                raise ValueError("evidence result is not a finite state")
            context.metrics.update_evidence_total(
                result=item.result,
                total=item.total,
                runtime_session_id=payload.runtime_session_id,
            )
        for latency in payload.evidence_latencies_seconds:
            context.metrics.observe_evidence_latency(latency)
        if payload.gpu is not None:
            context.metrics.set_gpu(
                utilization_percent=payload.gpu.utilization_percent,
                vram_used_bytes=payload.gpu.vram_used_bytes,
                vram_capacity_bytes=payload.gpu.vram_capacity_bytes,
            )
        if payload.disk is not None:
            context.metrics.set_disk(
                used_bytes=payload.disk.used_bytes,
                capacity_bytes=payload.disk.capacity_bytes,
            )
        for item in payload.notification_results:
            if item.result not in {"attempted", "delivered", "failed", "dead_letter"}:
                raise ValueError("notification result is not a finite state")
            context.metrics.update_notification_total(
                result=item.result,
                total=item.total,
                runtime_session_id=payload.runtime_session_id,
            )

    try:
        site_id = resolve_pilot_site_id(context)
    except PilotSiteConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pilot site unavailable",
        ) from exc
    payload_digest = hashlib.sha256(
        payload.model_dump_json().encode("utf-8")
    ).hexdigest()
    try:
        accepted = context.telemetry.apply(
            publisher=payload.publisher,
            runtime_session_id=payload.runtime_session_id,
            sequence=payload.sequence,
            observed_at=payload.observed_at,
            components=components,  # type: ignore[arg-type]
            payload_digest=payload_digest,
            update=update_metrics,
            authorize=lambda: context.repository.authorize_telemetry_epoch(
                site_id=site_id,
                publisher=payload.publisher,
                runtime_session_id=payload.runtime_session_id,
                publisher_generation=payload.publisher_generation,
                sequence=payload.sequence,
                observed_at=payload.observed_at,
                payload_digest=payload_digest,
                persist=(
                    lambda session: _persist_health_samples_in_session(
                        payload.health,
                        context,
                        session,
                        site_id=site_id,
                    )
                    if payload.health
                    else None
                ),
            ),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"code": "invalid_telemetry", "message": str(exc)},
        ) from exc
    return {"status": "accepted" if accepted else "duplicate"}
