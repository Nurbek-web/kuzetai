"""Versioned, immutable messages shared by the pilot runtime and control plane."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, computed_field, field_validator, model_validator

from protector.pilot.config import FrozenModel, NonEmptyString

TimestampQuality = Literal["camera_rtcp", "host_ntp_fallback"]
RuntimeState = Literal[
    "fresh",
    "cached_display",
    "starting",
    "online",
    "degraded",
    "offline",
    "reconnecting",
]
GateMode = Literal["disabled", "shadow", "operator"]
EvidenceStatus = Literal["pending", "ready", "failed", "unavailable"]
ReviewStatus = Literal["observation", "candidate", "confirmed", "rejected", "expired", "escalated"]
NormalisedBoundingBox = tuple[float, float, float, float]

_EVENT_TRANSITIONS: dict[ReviewStatus, frozenset[ReviewStatus]] = {
    "observation": frozenset({"candidate"}),
    "candidate": frozenset({"confirmed", "rejected", "expired"}),
    "confirmed": frozenset({"escalated"}),
    "rejected": frozenset(),
    "expired": frozenset(),
    "escalated": frozenset(),
}


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be UTC-aware")
    return value.astimezone(timezone.utc)


class ObservationV1(FrozenModel):
    """One unique inference sample; display-cache entries are never fresh votes."""

    schema_version: Literal["observation.v1"]
    observation_id: UUID
    camera_id: NonEmptyString
    stream_epoch: UUID
    source_time: datetime
    timestamp_quality: TimestampQuality
    monotonic_seq: Annotated[int, Field(ge=0)]
    module: NonEmptyString
    class_name: NonEmptyString
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    bbox: NormalisedBoundingBox
    track_id: NonEmptyString | None = None
    model_artifact_id: NonEmptyString
    runtime_state: RuntimeState
    received_at: datetime

    @model_validator(mode="before")
    @classmethod
    def discard_serialized_dedupe_key(cls, value: object) -> object:
        """Accept a normal JSON round-trip while retaining one derived identity."""
        if isinstance(value, Mapping) and "dedupe_key" in value:
            payload = dict(value)
            payload.pop("dedupe_key")
            return payload
        return value

    @field_validator("source_time", "received_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @field_validator("bbox")
    @classmethod
    def bbox_is_normalised(cls, bbox: NormalisedBoundingBox) -> NormalisedBoundingBox:
        left, top, right, bottom = bbox
        if not all(0.0 <= coordinate <= 1.0 for coordinate in bbox):
            raise ValueError("bbox coordinates must be normalised to [0, 1]")
        if left >= right or top >= bottom:
            raise ValueError("bbox must have positive area")
        return bbox

    @computed_field(return_type=str)
    @property
    def dedupe_key(self) -> str:
        """Stable identity across retries, including a source restart epoch."""
        return (
            f"{self.camera_id}:{self.stream_epoch}:{self.monotonic_seq}:"
            f"{self.module}:{self.model_artifact_id}"
        )

    @property
    def is_fresh(self) -> bool:
        """Cached display data cannot count as an event-engine observation."""
        return self.runtime_state == "fresh"


class CandidateEventV1(FrozenModel):
    """A human-review candidate; no event can autonomously take an external action."""

    schema_version: Literal["candidate-event.v1"]
    event_id: UUID
    camera_id: NonEmptyString
    module: NonEmptyString
    opened_at: datetime
    last_seen_at: datetime
    peak_confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    reason: NonEmptyString
    model_artifact_id: NonEmptyString
    gate_mode: GateMode
    evidence_status: EvidenceStatus
    review_status: ReviewStatus

    @model_validator(mode="before")
    @classmethod
    def discard_serialized_dedupe_key(cls, value: object) -> object:
        if isinstance(value, Mapping) and "dedupe_key" in value:
            payload = dict(value)
            payload.pop("dedupe_key")
            return payload
        return value

    @field_validator("opened_at", "last_seen_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @model_validator(mode="after")
    def event_time_is_ordered(self) -> CandidateEventV1:
        if self.last_seen_at < self.opened_at:
            raise ValueError("last_seen_at must not precede opened_at")
        return self

    @computed_field(return_type=str)
    @property
    def dedupe_key(self) -> str:
        return (
            f"{self.camera_id}:{self.module}:{self.model_artifact_id}:"
            f"{self.opened_at.isoformat()}"
        )

    def transition_to(self, target: ReviewStatus) -> CandidateEventV1:
        if target not in _EVENT_TRANSITIONS[self.review_status]:
            raise ValueError(f"illegal event transition: {self.review_status} -> {target}")
        return self.model_copy(update={"review_status": target})


class NotificationOutboxRecordV1(FrozenModel):
    """A notification request that can originate only from a confirmed operator event."""

    schema_version: Literal["notification-outbox.v1"] = "notification-outbox.v1"
    event: CandidateEventV1
    idempotency_key: NonEmptyString

    @model_validator(mode="after")
    def only_confirmed_operator_events_notify(self) -> NotificationOutboxRecordV1:
        if self.event.gate_mode != "operator":
            raise ValueError("only operator gate mode events can enter the notification outbox")
        if self.event.review_status != "confirmed":
            raise ValueError("only confirmed events can enter the notification outbox")
        return self

    @property
    def event_id(self) -> UUID:
        return self.event.event_id

    @classmethod
    def from_confirmed_event(
        cls, event: CandidateEventV1, *, idempotency_key: str
    ) -> NotificationOutboxRecordV1:
        return cls(event=event, idempotency_key=idempotency_key)
