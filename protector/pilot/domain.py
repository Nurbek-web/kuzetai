"""Versioned, immutable messages shared by the pilot runtime and control plane."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    Field,
    StringConstraints,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)

from protector.pilot.config import FrozenModel, NonEmptyString

TimestampQuality = Literal["camera_rtcp", "host_ntp_fallback"]
SampleKind = Literal["fresh", "cached_display"]
RuntimeState = Literal[
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
Identifier128 = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)
]
Identifier255 = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)
]

_EVENT_TRANSITIONS: dict[ReviewStatus, frozenset[ReviewStatus]] = {
    "observation": frozenset({"candidate"}),
    "candidate": frozenset({"confirmed", "rejected", "expired"}),
    "confirmed": frozenset({"escalated"}),
    "rejected": frozenset(),
    "expired": frozenset(),
    "escalated": frozenset(),
}
_RUNTIME_WRITER_RECEIPT_AUTHORITY = object()


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be UTC-aware")
    return value.astimezone(timezone.utc)


class ObservationV1(FrozenModel):
    """One unique inference sample; display-cache entries are never fresh votes."""

    schema_version: Literal["observation.v1"]
    observation_id: UUID
    camera_id: Identifier128
    stream_epoch: UUID
    source_time: datetime
    timestamp_quality: TimestampQuality
    monotonic_seq: Annotated[int, Field(ge=0)]
    module: Identifier128
    class_name: Identifier128
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    bbox: NormalisedBoundingBox
    track_id: Identifier255 | None = None
    model_artifact_id: Identifier255
    sample_kind: SampleKind
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
        return self.sample_kind == "fresh"


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
    transition_history: tuple[ReviewStatus, ...] = ("observation", "candidate")

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
        if not self.transition_history:
            raise ValueError("transition_history must contain the initial observation")
        if self.transition_history[0] != "observation":
            raise ValueError("transition_history must start at observation")
        for source, target in zip(self.transition_history, self.transition_history[1:]):
            if target not in _EVENT_TRANSITIONS[source]:
                raise ValueError(f"illegal transition_history transition: {source} -> {target}")
        if self.transition_history[-1] != self.review_status:
            raise ValueError("transition_history must end at review_status")
        return self

    @computed_field(return_type=str)
    @property
    def dedupe_key(self) -> str:
        return (
            f"{self.event_id}:{self.camera_id}:{self.module}:"
            f"{self.model_artifact_id}:{self.opened_at.isoformat()}"
        )

    def transition_to(self, target: ReviewStatus) -> CandidateEventV1:
        if target not in _EVENT_TRANSITIONS[self.review_status]:
            raise ValueError(f"illegal event transition: {self.review_status} -> {target}")
        return self.model_copy(
            update={
                "review_status": target,
                "transition_history": (*self.transition_history, target),
            }
        )


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


def _provenance_digest(value: str, *, field_name: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{field_name} must be a 64-character hexadecimal digest")
    return normalized


class RuntimeWriterReceiptV1(FrozenModel):
    """Durable writer authority bound to one active configuration generation."""

    schema_version: Literal["runtime-writer-receipt.v1"] = (
        "runtime-writer-receipt.v1"
    )
    site_id: Identifier128
    runtime_session_id: Identifier128
    runtime_writer_generation: Annotated[int, Field(strict=True, ge=1)]
    configuration_activation_generation: Annotated[int, Field(strict=True, ge=1)]
    config_revision_id: Identifier128
    site_config_sha256: str
    ruleset_revision_id: Identifier128
    ruleset_sha256: str
    rule_revision_digests: Mapping[Identifier128, str]
    issued_at: datetime

    def __init__(self, **data: object) -> None:
        authority = data.pop("_authority", None)
        if authority is not _RUNTIME_WRITER_RECEIPT_AUTHORITY:
            raise TypeError("runtime writer receipt must be issued by the repository")
        super().__init__(**data)

    def __copy__(self) -> object:
        raise TypeError("runtime writer receipt capability cannot be copied")

    def __deepcopy__(self, _: object) -> object:
        raise TypeError("runtime writer receipt capability cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("runtime writer receipt capability cannot be serialized")

    def __reduce_ex__(self, _: int) -> object:
        raise TypeError("runtime writer receipt capability cannot be serialized")

    def model_copy(self, *, update: Mapping[str, object] | None = None, deep: bool = False) -> object:
        del update, deep
        raise TypeError("runtime writer receipt capability cannot be copied")

    @field_validator("site_config_sha256", "ruleset_sha256")
    @classmethod
    def receipt_digests_are_valid(cls, value: str, info: object) -> str:
        return _provenance_digest(
            value,
            field_name=getattr(info, "field_name", "digest"),
        )

    @field_validator("rule_revision_digests")
    @classmethod
    def rule_digests_are_bounded(
        cls, value: Mapping[str, str]
    ) -> Mapping[str, str]:
        if not 1 <= len(value) <= 512:
            raise ValueError("runtime receipt must contain 1..512 rule digests")
        normalized = {
            rule_id: _provenance_digest(
                digest,
                field_name=f"rule_revision_digests[{rule_id}]",
            )
            for rule_id, digest in value.items()
        }
        return MappingProxyType(dict(sorted(normalized.items())))

    @field_serializer("rule_revision_digests")
    def serialize_rule_digests(self, value: Mapping[str, str]) -> dict[str, str]:
        return dict(value)

    @field_validator("issued_at")
    @classmethod
    def receipt_time_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    def rule_revision_sha256(self, rule_id: str) -> str:
        try:
            return self.rule_revision_digests[rule_id]
        except KeyError as exc:
            raise KeyError(f"runtime receipt does not authorize rule: {rule_id}") from exc

    @property
    def authority_sha256(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def _issue_runtime_writer_receipt(
    **data: object,
) -> RuntimeWriterReceiptV1:
    """Repository-only constructor; callers receive but cannot construct authority."""

    return RuntimeWriterReceiptV1(
        _authority=_RUNTIME_WRITER_RECEIPT_AUTHORITY,
        **data,
    )


class ConfigurationActivationReceiptV1(FrozenModel):
    """Immutable, secret-free receipt for one exact activation request."""

    schema_version: Literal["configuration-activation-receipt.v1"] = (
        "configuration-activation-receipt.v1"
    )
    site_id: Identifier128
    expected_activation_generation: Annotated[int, Field(strict=True, ge=0)]
    activation_generation: Annotated[int, Field(strict=True, ge=1)]
    runtime_writer_generation: Annotated[int, Field(strict=True, ge=1)]
    config_revision_id: Identifier128
    site_config_sha256: str
    ruleset_revision_id: Identifier128
    ruleset_sha256: str
    activated_by: Identifier128
    activated_at: datetime
    idempotency_key: Identifier255
    force_new_generation: Annotated[bool, Field(strict=True)]

    @field_validator("site_config_sha256", "ruleset_sha256")
    @classmethod
    def activation_digests_are_valid(cls, value: str, info: object) -> str:
        return _provenance_digest(
            value,
            field_name=getattr(info, "field_name", "digest"),
        )

    @field_validator("activated_at")
    @classmethod
    def activation_time_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)


class CameraEpochActivationReceiptV1(FrozenModel):
    """Immutable receipt for a camera-local epoch CAS transition."""

    schema_version: Literal["camera-epoch-activation-receipt.v1"] = (
        "camera-epoch-activation-receipt.v1"
    )
    site_id: Identifier128
    camera_id: Identifier128
    source_epoch: UUID
    previous_source_epoch: UUID | None
    runtime_session_id: Identifier128
    runtime_writer_generation: Annotated[int, Field(strict=True, ge=1)]
    configuration_activation_generation: Annotated[int, Field(strict=True, ge=1)]
    activated_at: datetime

    @field_validator("activated_at")
    @classmethod
    def camera_epoch_time_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)


class LegacyCandidateImportV1(FrozenModel):
    """Explicit marker for a candidate that predates provenance migration 0006."""

    schema_version: Literal["legacy-candidate-import.v1"] = (
        "legacy-candidate-import.v1"
    )
    event_id: UUID
    imported_at: datetime
    legacy_cutoff_at: datetime
    migration_revision: Literal["0006_event_provenance"] = "0006_event_provenance"

    @field_validator("imported_at", "legacy_cutoff_at")
    @classmethod
    def legacy_times_are_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @model_validator(mode="after")
    def import_precedes_cutoff(self) -> LegacyCandidateImportV1:
        if self.imported_at < self.legacy_cutoff_at:
            raise ValueError("legacy candidate import cannot precede its cutoff")
        return self


class CandidateEventProvenanceV1(FrozenModel):
    """Exact runtime, source, configuration, rule, model, and gate provenance."""

    schema_version: Literal["candidate-event-provenance.v1"] = (
        "candidate-event-provenance.v1"
    )
    site_id: Identifier128
    runtime_session_id: Identifier128
    runtime_writer_generation: Annotated[int, Field(strict=True, ge=1)]
    configuration_activation_generation: Annotated[int, Field(strict=True, ge=1)]
    source_epoch: UUID
    rule_id: Identifier128
    rule_revision: Annotated[int, Field(strict=True, ge=1)]
    rule_revision_sha256: str
    ruleset_sha256: str
    site_config_sha256: str
    model_gate_decision_sha256: str
    gate_mode: GateMode

    @field_validator(
        "rule_revision_sha256",
        "ruleset_sha256",
        "site_config_sha256",
        "model_gate_decision_sha256",
    )
    @classmethod
    def provenance_digests_are_valid(cls, value: str, info: object) -> str:
        return _provenance_digest(
            value,
            field_name=getattr(info, "field_name", "digest"),
        )


class ProvenancedCandidateEventV2(FrozenModel):
    """Candidate event plus the provenance required for production-pilot writes."""

    schema_version: Literal["provenanced-candidate-event.v2"] = (
        "provenanced-candidate-event.v2"
    )
    event: CandidateEventV1
    provenance: CandidateEventProvenanceV1

    @model_validator(mode="before")
    @classmethod
    def discard_serialized_body_digest(cls, value: object) -> object:
        if isinstance(value, Mapping) and "body_sha256" in value:
            payload = dict(value)
            payload.pop("body_sha256")
            return payload
        return value

    @model_validator(mode="after")
    def event_and_provenance_agree(self) -> ProvenancedCandidateEventV2:
        if (
            self.event.evidence_status != "pending"
            or self.event.review_status != "candidate"
            or self.event.transition_history != ("observation", "candidate")
        ):
            raise ValueError(
                "runtime provenance may originate only an initial pending candidate"
            )
        if self.event.gate_mode == "disabled":
            raise ValueError("disabled gate mode cannot emit a candidate")
        if self.event.gate_mode != self.provenance.gate_mode:
            raise ValueError("event gate mode does not match provenance")
        return self

    @computed_field(return_type=str)
    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.canonical_body_json.encode("utf-8")).hexdigest()

    @property
    def canonical_body_json(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "event": self.event.model_dump(
                mode="json",
                exclude={"dedupe_key"},
            ),
            "provenance": self.provenance.model_dump(mode="json"),
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


class PersistedCandidateEventV2(FrozenModel):
    """Read model that leaves historical V1 provenance explicitly absent."""

    schema_version: Literal["persisted-candidate-event.v2"] = (
        "persisted-candidate-event.v2"
    )
    event: CandidateEventV1
    provenance: CandidateEventProvenanceV1 | None
