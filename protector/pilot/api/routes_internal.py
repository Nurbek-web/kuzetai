"""Machine-authenticated runtime ingestion routes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import IntegrityError

from protector.pilot.api.dependencies import ApiContext, get_context, require_machine_auth
from protector.pilot.domain import ObservationV1
from protector.pilot.storage.models import CameraHealthSampleModel

router = APIRouter(prefix="/api/internal", tags=["internal"])


@router.post(
    "/observations",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_machine_auth)],
)
def ingest_observation(
    observation: ObservationV1,
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, str]:
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
    dependencies=[Depends(require_machine_auth)],
)
def ingest_health(
    sample: HealthSampleRequest,
    context: Annotated[ApiContext, Depends(get_context)],
) -> dict[str, object]:
    with context.repository.session_factory.begin() as session:
        row = CameraHealthSampleModel(**sample.model_dump())
        session.add(row)
        try:
            session.flush()
        except IntegrityError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "invalid_health_sample"},
            ) from exc
    return {"health_sample_id": row.health_sample_id, "status": "accepted"}
