"""Validated, immutable configuration for the bounded 20-camera pilot."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
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
FiniteStorageBytes = Annotated[int, Field(gt=0, le=1_000_000_000_000)]
DOCKER_SECRETS_DIR = Path("/run/secrets")
MAX_SECRET_BYTES = 16 * 1024
_SECRET_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


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
        if self.docker_secret is not None:
            expected_parent = DOCKER_SECRETS_DIR
            if (
                not self.docker_secret.is_absolute()
                or self.docker_secret.parent != expected_parent
                or _SECRET_FILE_NAME.fullmatch(self.docker_secret.name) is None
                or self.docker_secret != expected_parent / self.docker_secret.name
            ):
                raise ValueError("docker_secret must be one canonical direct secret file")
        return self

    def resolve(self) -> SecretStr:
        if self.environment is not None:
            value = os.environ.get(self.environment)
            if not value or len(value.encode("utf-8")) > MAX_SECRET_BYTES:
                raise ValueError(f"missing required environment secret: {self.environment}")
            return SecretStr(value)
        assert self.docker_secret is not None
        descriptor = -1
        try:
            descriptor = os.open(
                self.docker_secret,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= MAX_SECRET_BYTES
            ):
                raise ValueError("Docker secret is invalid")
            payload = os.read(descriptor, MAX_SECRET_BYTES + 1)
        except OSError as exc:
            raise ValueError(f"unable to read Docker secret: {self.docker_secret}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        try:
            value = payload.decode("utf-8").strip()
        except UnicodeError as exc:
            raise ValueError("Docker secret is invalid") from exc
        if not value:
            raise ValueError(f"Docker secret is empty: {self.docker_secret}")
        return SecretStr(value)


class CameraFeed(FrozenModel):
    camera_id: NonEmptyString
    source_index: Annotated[int, Field(ge=0, lt=20)]
    rtsp_url: SecretReference
    codec: Literal["h264", "h265"]
    resolution: Resolution
    fps: Annotated[float, Field(gt=0, le=120)]
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
        if (
            len({feed.camera_id for feed in feeds}) != len(feeds)
            or tuple(feed.source_index for feed in feeds)
            != tuple(range(len(feeds)))
        ):
            raise ValueError("camera IDs and source indices must be exact and unique")
        return feeds


class EvidenceRetention(FrozenModel):
    """The pilot retains bounded evidence and metadata; the customer NVR owns video."""

    continuous_video_owner: Literal["customer_nvr"]
    continuous_video_storage_enabled: Literal[False]
    encoded_ring_buffer_seconds: RingBufferSeconds
    encoded_ring_max_camera_bytes: FiniteStorageBytes = 64_000_000
    encoded_ring_max_spool_bytes: FiniteStorageBytes = 1_280_000_000
    encoded_spool_root: Path = Path("/srv/kuzet/evidence-spool")
    encoded_fragment_seconds: Literal[1, 2] = 2
    encoded_fragment_max_bytes: FiniteStorageBytes = 8_000_000
    evidence_retention_days: EvidenceRetentionDays
    metadata_retention_days: MetadataRetentionDays

    @model_validator(mode="after")
    def total_spool_covers_one_camera(self) -> EvidenceRetention:
        if self.encoded_ring_max_spool_bytes < self.encoded_ring_max_camera_bytes:
            raise ValueError("total encoded ring byte bound must cover one camera")
        if not self.encoded_spool_root.is_absolute():
            raise ValueError("encoded_spool_root must be an absolute target path")
        if self.encoded_fragment_max_bytes > self.encoded_ring_max_camera_bytes:
            raise ValueError("encoded fragment byte bound must fit one camera spool")
        return self


class KazakhstanStorage(FrozenModel):
    country_code: Literal["KZ"]
    endpoint: HttpUrl
    bucket: NonEmptyString
    evidence_prefix: NonEmptyString = "pilot-evidence"
    max_evidence_object_bytes: FiniteStorageBytes = 64_000_000
    server_side_encryption: Literal["AES256", "aws:kms"] = "AES256"
    kms_key_id: NonEmptyString | None = None
    retention: EvidenceRetention

    @field_validator("endpoint")
    @classmethod
    def endpoint_must_use_https(cls, endpoint: HttpUrl) -> HttpUrl:
        if endpoint.scheme != "https":
            raise ValueError("storage endpoint must use HTTPS")
        if (
            endpoint.username is not None
            or endpoint.password is not None
            or endpoint.query is not None
            or endpoint.fragment is not None
            or endpoint.path not in (None, "", "/")
        ):
            raise ValueError(
                "storage endpoint must not contain credentials or ambiguous components"
            )
        return endpoint

    @model_validator(mode="after")
    def evidence_object_policy_is_canonical(self) -> KazakhstanStorage:
        prefix = self.evidence_prefix
        path = PurePosixPath(prefix)
        if (
            prefix.startswith("/")
            or "\\" in prefix
            or "//" in prefix
            or any(part in ("", ".", "..") for part in path.parts)
            or path.as_posix() != prefix
            or prefix == ".incomplete"
            or prefix.startswith(".incomplete/")
        ):
            raise ValueError("evidence_prefix must be a canonical scoped object prefix")
        if self.server_side_encryption == "aws:kms" and self.kms_key_id is None:
            raise ValueError("aws:kms storage requires kms_key_id")
        if self.server_side_encryption == "AES256" and self.kms_key_id is not None:
            raise ValueError("kms_key_id is only valid with aws:kms")
        return self


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
