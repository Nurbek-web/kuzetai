"""Validated, immutable configuration for the bounded 20-camera pilot."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    SecretStr,
    StringConstraints,
    field_serializer,
    field_validator,
    model_validator,
)

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
PositiveBitrate = Annotated[int, Field(gt=0)]
AnalyticsHz = Annotated[float, Field(ge=0.0, le=30.0)]
QueueSize = Annotated[int, Field(ge=1, le=10_000)]
RingBufferSeconds = Annotated[int, Field(ge=1, le=15)]
EvidenceRetentionDays = Annotated[int, Field(ge=1, le=90)]
MetadataRetentionDays = Annotated[int, Field(ge=1, le=365)]
DOCKER_SECRETS_DIR = Path("/run/secrets")


class FrozenModel(BaseModel):
    """Configuration models reject unknown values and cannot be changed at runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Resolution(FrozenModel):
    width: PositiveBitrate
    height: PositiveBitrate


class SecretReference(FrozenModel):
    """A non-secret reference resolved only from process environment or Docker secrets."""

    environment: Annotated[str | None, Field(pattern=r"^[A-Z][A-Z0-9_]*$")] = None
    docker_secret: Path | None = None

    @model_validator(mode="after")
    def exactly_one_source(self) -> SecretReference:
        if (self.environment is None) == (self.docker_secret is None):
            raise ValueError("provide exactly one of environment or docker_secret")
        if self.docker_secret is not None and not self.docker_secret.is_relative_to("/run/secrets"):
            raise ValueError("docker_secret must be under /run/secrets")
        return self

    def resolve(self) -> SecretStr:
        if self.environment is not None:
            value = os.environ.get(self.environment)
            if not value:
                raise ValueError(f"missing required environment secret: {self.environment}")
            return SecretStr(value)
        assert self.docker_secret is not None
        try:
            value = self.docker_secret.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError(f"unable to read Docker secret: {self.docker_secret}") from exc
        if not value:
            raise ValueError(f"Docker secret is empty: {self.docker_secret}")
        return SecretStr(value)


class CameraFeed(FrozenModel):
    camera_id: NonEmptyString
    rtsp_url: SecretReference
    codec: Literal["h264", "h265"]
    resolution: Resolution
    bitrate_kbps: PositiveBitrate
    analytics_hz: Mapping[NonEmptyString, AnalyticsHz]

    @field_validator("analytics_hz")
    @classmethod
    def freeze_analytics_schedule(cls, analytics_hz: Mapping[str, float]) -> Mapping[str, float]:
        return MappingProxyType(dict(analytics_hz))

    @field_serializer("analytics_hz")
    def serialize_analytics_schedule(self, analytics_hz: Mapping[str, float]) -> dict[str, float]:
        return dict(analytics_hz)

    @model_validator(mode="after")
    def includes_person_analytics(self) -> CameraFeed:
        if "person" not in self.analytics_hz:
            raise ValueError("analytics_hz must declare the core person module")
        return self


class ReadyToStart(FrozenModel):
    """Inputs that must be signed off before the pilot starts."""

    feeds: Annotated[tuple[CameraFeed, ...], Field(min_length=20, max_length=20)]
    ntp_source: NonEmptyString
    camera_map: NonEmptyString
    site_access: NonEmptyString
    compute: NonEmptyString
    notification_channel: NonEmptyString
    model_rights_decisions: NonEmptyString

    @field_validator("feeds")
    @classmethod
    def camera_ids_are_unique(cls, feeds: tuple[CameraFeed, ...]) -> tuple[CameraFeed, ...]:
        if len({feed.camera_id for feed in feeds}) != len(feeds):
            raise ValueError("camera IDs must be unique")
        return feeds


class EvidenceRetention(FrozenModel):
    """The pilot retains bounded evidence and metadata; the customer NVR owns video."""

    continuous_video_owner: Literal["customer_nvr"]
    continuous_video_storage_enabled: Literal[False]
    encoded_ring_buffer_seconds: RingBufferSeconds
    evidence_retention_days: EvidenceRetentionDays
    metadata_retention_days: MetadataRetentionDays


class KazakhstanStorage(FrozenModel):
    country_code: Literal["KZ"]
    endpoint: HttpUrl
    bucket: NonEmptyString
    retention: EvidenceRetention

    @field_validator("endpoint")
    @classmethod
    def endpoint_must_use_https(cls, endpoint: HttpUrl) -> HttpUrl:
        if endpoint.scheme != "https":
            raise ValueError("storage endpoint must use HTTPS")
        return endpoint


class QueueLimits(FrozenModel):
    """Explicit bounded queue capacities for the shared data plane."""

    decode: QueueSize
    analytics: QueueSize
    verifier: QueueSize
    events: QueueSize


class SiteConfig(FrozenModel):
    ready_to_start: ReadyToStart
    storage: KazakhstanStorage
    queues: QueueLimits


class PilotSecrets(FrozenModel):
    """Runtime credentials loaded from environment variables or Docker secret files only."""

    database_url: SecretStr
    object_store_access_key: SecretStr
    object_store_secret_key: SecretStr
    session_secret: SecretStr
    totp_encryption_key: SecretStr

    @classmethod
    def required_names(cls) -> tuple[str, ...]:
        return (
            "database_url",
            "object_store_access_key",
            "object_store_secret_key",
            "session_secret",
            "totp_encryption_key",
        )

    @classmethod
    def from_environment(cls) -> PilotSecrets:
        values: dict[str, SecretStr] = {}
        for name in cls.required_names():
            environment_name = f"PILOT_{name.upper()}"
            value = os.environ.get(environment_name)
            if value is None:
                secret_file = DOCKER_SECRETS_DIR / name
                try:
                    value = secret_file.read_text(encoding="utf-8").strip()
                except FileNotFoundError as exc:
                    raise ValueError(
                        f"missing required secret {environment_name} or {secret_file}"
                    ) from exc
            if not value:
                raise ValueError(f"secret {environment_name} must not be empty")
            values[name] = SecretStr(value)
        return cls.model_validate(values)


def load_site_config(path: Path) -> SiteConfig:
    """Load non-secret site settings; credential values are deliberately not a YAML field."""
    with path.open(encoding="utf-8") as config_file:
        raw_config = yaml.safe_load(config_file)
    return SiteConfig.model_validate(raw_config)
