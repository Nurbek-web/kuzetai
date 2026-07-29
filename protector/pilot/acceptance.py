"""Fail-closed contracts for the exact-site pilot acceptance record."""

from __future__ import annotations

import hashlib
import html
import json
import math
import os
import stat
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

import yaml
from pydantic import Field, field_validator, model_validator

from protector.pilot.config import FrozenModel
from protector.pilot.gates import ConditionalModelGateResultV1

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ModuleMode = Literal["pass/operator", "shadow", "disabled"]
FaultKind = Literal[
    "camera_loss",
    "malformed_timestamp",
    "network_pause",
    "runtime_restart",
    "api_restart",
    "object_store_outage",
    "model_timeout",
    "verifier_full",
]
_SHADOW_ONLY = frozenset({"xclip", "vit", "violence", "fight", "fall"})
_SENSITIVE_KEYS = frozenset(
    {
        "rtsp_url",
        "object_url",
        "token",
        "password",
        "secret",
        "notes",
        "username",
        "provider_body",
        "raw_video",
        "frame",
    }
)
_SENSITIVE_NORMALIZED_KEYS = frozenset(
    {
        *("".join(character for character in key if character.isalnum()) for key in _SENSITIVE_KEYS),
        "apikey",
        "accesstoken",
        "refreshtoken",
        "machinecredential",
        "objectstoreurl",
        "objectstoreuri",
        "objectstoreendpoint",
    }
)
_MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
_CANONICAL_FAULT_POLICY: dict[FaultKind, tuple[str, str, str, float, float]] = {
    "camera_loss": ("source_index:0", "offline", "online", 10.0, 5.0),
    "malformed_timestamp": ("source_index:1", "degraded", "online", 20.0, 1.0),
    "network_pause": ("source_index:2", "offline", "online", 30.0, 5.0),
    "runtime_restart": ("shared-runtime", "offline", "online", 40.0, 3.0),
    "api_restart": ("control-api", "degraded", "ready", 50.0, 3.0),
    "object_store_outage": ("evidence-store", "degraded", "ready", 60.0, 5.0),
    "model_timeout": ("person-primary", "degraded", "ready", 70.0, 2.0),
    "verifier_full": ("weapon-verifier", "degraded", "ready", 80.0, 2.0),
}


def canonical_fault_policy(kind: FaultKind) -> tuple[str, str, str, float, float]:
    """Return immutable target/degraded/recovery policy owned by acceptance."""
    return _CANONICAL_FAULT_POLICY[kind]


def _utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be UTC-aware")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be UTC")
    normalized = value.astimezone(timezone.utc)
    return normalized


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_secret_like(value: Any, *, path: str = "record") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = "".join(character for character in str(key).lower() if character.isalnum())
            if normalized_key in _SENSITIVE_NORMALIZED_KEYS:
                raise ValueError(f"{path} contains forbidden sensitive field")
            _reject_secret_like(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_like(item, path=f"{path}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        if (
            "rtsp://" in lowered
            or "rtsps://" in lowered
            or "s3://" in lowered
            or "minio://" in lowered
            or "gs://" in lowered
            or "az://" in lowered
            or "://user:" in lowered
            or ("://" in lowered and "@" in lowered.split("://", maxsplit=1)[1].split("/", maxsplit=1)[0])
            or "bearer " in lowered
            or "password=" in lowered
            or "token=" in lowered
        ):
            raise ValueError(f"{path} contains secret-like data")


class LocalFixtureSourceV1(FrozenModel):
    kind: Literal["local_fixture"]
    path: Annotated[str, Field(min_length=1, max_length=4096)]


class TargetSecretSourceV1(FrozenModel):
    kind: Literal["target_secret"]
    secret_reference: Annotated[
        str, Field(pattern=r"^/run/secrets/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    ]


class SourceManifestV1(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    source_index: Annotated[int, Field(ge=0, lt=20)]
    source: LocalFixtureSourceV1 | TargetSecretSourceV1 = Field(discriminator="kind")
    codec: Literal["h264", "h265"]
    width: Annotated[int, Field(ge=320, le=7680)]
    height: Annotated[int, Field(ge=240, le=4320)]
    fps: Annotated[float, Field(gt=0, le=120)]
    bitrate_kbps: Annotated[int, Field(gt=0, le=200_000)]
    analytics_hz: dict[Annotated[str, Field(min_length=1, max_length=64)], float]
    sha256: Digest | None
    provenance_reference: Annotated[str, Field(min_length=1, max_length=512)]

    @field_validator("fps")
    @classmethod
    def finite_fps(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("fps must be finite")
        return value

    @field_validator("analytics_hz")
    @classmethod
    def schedule_is_bounded(cls, value: dict[str, float]) -> dict[str, float]:
        if not value or len(value) > 32 or "person" not in value:
            raise ValueError("analytics schedule must be bounded and include person")
        if any(not math.isfinite(rate) or rate < 0 or rate > 30 for rate in value.values()):
            raise ValueError("analytics schedule rates must be finite and bounded")
        return value

    @field_validator("provenance_reference")
    @classmethod
    def provenance_is_scoped(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            value != value.strip()
            or value.startswith("/")
            or "\\" in value
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != value
        ):
            raise ValueError("provenance reference must be canonical and scoped")
        return value

    @model_validator(mode="after")
    def source_hash_contract(self) -> SourceManifestV1:
        if isinstance(self.source, LocalFixtureSourceV1) and self.sha256 is None:
            raise ValueError("local fixture requires sha256")
        if isinstance(self.source, TargetSecretSourceV1) and self.sha256 is not None:
            raise ValueError("target secret source must not claim a captured-file hash")
        return self


class ModuleDispositionV1(FrozenModel):
    module: Annotated[str, Field(min_length=1, max_length=64)]
    mode: ModuleMode
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    evidence_reference: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    artifact_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    registry_entry_sha256: Digest | None = None
    rights_sha256: Digest | None = None
    artifact_sha256: Digest | None = None
    site_matrix_sha256: Digest | None = None
    gate_decision_sha256: Digest | None = None

    @model_validator(mode="after")
    def conditional_operator_requires_signed_exact_evidence(self) -> ModuleDispositionV1:
        if self.mode == "pass/operator" and self.module in {"fire_smoke", "weapon"}:
            if (
                self.rights_sha256 is None
                or self.artifact_id is None
                or self.registry_entry_sha256 is None
                or self.artifact_sha256 is None
                or self.site_matrix_sha256 is None
                or self.evidence_reference is None
            ):
                raise ValueError("conditional operator mode requires rights/artifact/site matrix")
        return self


class AcceptanceManifestV1(FrozenModel):
    schema_version: Literal["acceptance-manifest.v1"]
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    sources: Annotated[tuple[SourceManifestV1, ...], Field(min_length=20, max_length=20)]
    modules: Annotated[tuple[ModuleDispositionV1, ...], Field(min_length=1, max_length=64)]
    config_sha256: Digest
    model_sha256: Digest
    engine_sha256: Digest
    image_sha256: Digest

    @model_validator(mode="after")
    def exact_identities_and_modes(self) -> AcceptanceManifestV1:
        camera_ids = tuple(source.camera_id for source in self.sources)
        indices = tuple(source.source_index for source in self.sources)
        modules = tuple(item.module for item in self.modules)
        if len(set(camera_ids)) != 20:
            raise ValueError("exactly 20 unique camera IDs are required")
        if set(indices) != set(range(20)):
            raise ValueError("source indices must be the exact unique range 0..19")
        if len(set(modules)) != len(modules):
            raise ValueError("module identities must be unique")
        for item in self.modules:
            if item.mode == "pass/operator" and item.module in _SHADOW_ONLY:
                raise ValueError(f"{item.module} cannot become operator through acceptance tooling")
        _reject_secret_like(self.model_dump(mode="json"), path="manifest")
        return self

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.model_dump(mode="json"))).hexdigest()


def _read_regular_bounded(path: Path, *, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"symlink is forbidden: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError(f"file is not regular and bounded: {path}")
        payload = os.read(descriptor, limit + 1)
        if len(payload) != metadata.st_size:
            raise ValueError(f"file changed while reading: {path}")
        return payload
    finally:
        os.close(descriptor)


def _sha256_regular_bounded(path: Path, *, limit: int) -> str:
    if path.is_symlink():
        raise ValueError(f"symlink is forbidden: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError(f"file is not regular and bounded: {path}")
        consumed = 0
        while chunk := os.read(descriptor, min(1024 * 1024, limit + 1 - consumed)):
            digest.update(chunk)
            consumed += len(chunk)
            if consumed > limit:
                raise ValueError(f"file exceeds finite bound: {path}")
        if consumed != metadata.st_size:
            raise ValueError(f"file changed while hashing: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def load_acceptance_manifest(path: Path) -> AcceptanceManifestV1:
    if path.is_symlink():
        raise ValueError("acceptance manifest symlink is forbidden")
    payload = _read_regular_bounded(path.resolve(strict=True), limit=2 * 1024 * 1024)
    manifest = AcceptanceManifestV1.model_validate(yaml.safe_load(payload))
    for item in manifest.sources:
        if not isinstance(item.source, LocalFixtureSourceV1):
            continue
        fixture = Path(item.source.path)
        if not fixture.is_absolute():
            if any(part == ".." for part in fixture.parts):
                raise ValueError(f"local fixture traversal is forbidden: {item.camera_id}")
            fixture = path.parent / fixture
        if fixture.is_symlink():
            raise ValueError(f"local fixture symlink is forbidden: {fixture}")
        resolved = fixture.resolve(strict=True)
        if _sha256_regular_bounded(resolved, limit=_MAX_FILE_BYTES) != item.sha256:
            raise ValueError(f"local fixture hash mismatch: {item.camera_id}")
    return manifest


def load_conditional_gate_decisions(
    paths: tuple[Path, ...] | list[Path],
) -> tuple[ConditionalModelGateResultV1, ...]:
    """Load exact manifest-bound decisions from bounded operator-supplied files."""
    decisions: list[ConditionalModelGateResultV1] = []
    for path in paths:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("conditional gate decision must be an absolute non-symlink path")
        decision = ConditionalModelGateResultV1.model_validate_json(
            _read_regular_bounded(path, limit=1024 * 1024)
        )
        decisions.append(decision)
    modules = tuple(item.module for item in decisions)
    if len(set(modules)) != len(modules):
        raise ValueError("duplicate conditional gate decision module")
    return tuple(decisions)


def load_run_record(path: Path) -> AcceptanceRunRecordV1:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("run record must be an absolute non-symlink path")
    return AcceptanceRunRecordV1.model_validate_json(
        _read_regular_bounded(path, limit=64 * 1024 * 1024)
    )


class CameraRunRecordV1(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    scheduled_samples: Annotated[int, Field(ge=0)]
    processed_samples: Annotated[int, Field(ge=0)]
    dropped_samples: Annotated[int, Field(ge=0)]
    availability_seconds: Annotated[float, Field(ge=0)]
    source_outage_seconds: Annotated[float, Field(ge=0)]
    queue_age_seconds: tuple[Annotated[float, Field(ge=0)], ...]
    reconnect_seconds: tuple[Annotated[float, Field(ge=0)], ...]
    observed_records: Annotated[int, Field(ge=0)]
    last_health_at: datetime
    runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("availability_seconds", "source_outage_seconds")
    @classmethod
    def finite_times(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("duration must be finite")
        return value

    @field_validator("queue_age_seconds", "reconnect_seconds")
    @classmethod
    def finite_samples(cls, values: tuple[float, ...]) -> tuple[float, ...]:
        if len(values) > 10_000_000 or any(not math.isfinite(value) for value in values):
            raise ValueError("metric samples must be finite and bounded")
        return values

    @field_validator("last_health_at")
    @classmethod
    def health_time_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "last_health_at")

    @model_validator(mode="after")
    def accounting_is_possible(self) -> CameraRunRecordV1:
        if self.processed_samples + self.dropped_samples != self.scheduled_samples:
            raise ValueError("processed plus dropped must equal scheduled samples")
        if self.observed_records != self.processed_samples:
            raise ValueError("observed records must equal processed samples")
        return self


class FaultRecordV1(FrozenModel):
    fault_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: FaultKind
    target: Annotated[str, Field(min_length=1, max_length=128)]
    injected_at: datetime
    monotonic_offset_seconds: Annotated[float, Field(ge=0, le=604_800)]
    duration_seconds: Annotated[float, Field(gt=0, le=3600)]
    expected_degraded: Annotated[str, Field(min_length=1, max_length=64)]
    expected_recovery: Annotated[str, Field(min_length=1, max_length=64)]
    observed_degraded: Annotated[str, Field(min_length=1, max_length=64)] | None
    observed_recovery: Annotated[str, Field(min_length=1, max_length=64)] | None
    recovered_at: datetime | None

    @field_validator("injected_at", "recovered_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value, "fault timestamp")


class FaultStateTraceV1(FrozenModel):
    fault_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: FaultKind
    phase: Literal["degraded", "recovered"]
    observed_at: datetime
    component: Annotated[str, Field(min_length=1, max_length=64)]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "fault trace timestamp")


class QueueStateTraceV1(FrozenModel):
    queue: Literal["decode", "analytics", "verifier", "events", "evidence"]
    observed_at: datetime
    depth: Annotated[int, Field(ge=0, le=1_000_000)]
    capacity: Annotated[int, Field(gt=0, le=1_000_000)]
    state: Literal["ready", "full", "timeout", "unavailable"]
    runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "queue trace timestamp")

    @model_validator(mode="after")
    def depth_is_bounded(self) -> QueueStateTraceV1:
        if self.depth > self.capacity:
            raise ValueError("queue depth exceeds its finite capacity")
        if self.state == "full" and self.depth != self.capacity:
            raise ValueError("full queue trace must be at capacity")
        return self


class CapacityTraceV1(FrozenModel):
    observed_at: datetime
    manifest_sha256: Digest
    config_sha256: Digest
    model_sha256: Digest
    engine_sha256: Digest
    image_sha256: Digest
    effective_throughput_hz: Annotated[float, Field(gt=0)]
    required_throughput_hz: Annotated[float, Field(gt=0)]
    stream_count: Literal[20]

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "capacity trace timestamp")

    @field_validator("effective_throughput_hz", "required_throughput_hz")
    @classmethod
    def throughput_is_finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("capacity throughput must be finite")
        return value


class ExceptionRecordV1(FrozenModel):
    exception_id: Annotated[str, Field(min_length=1, max_length=128)]
    occurred_at: datetime
    component: Annotated[str, Field(min_length=1, max_length=64)]
    category: Literal["handled", "crash", "oom"]
    code: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "exception timestamp")


class BoundaryTraceV1(FrozenModel):
    component: Literal["event_engine", "repository", "evidence", "metrics"]
    observed_at: datetime
    consumed_records: Annotated[int, Field(ge=0)]
    succeeded: bool
    detail_code: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "boundary timestamp")


class LifecycleTraceV1(FrozenModel):
    trace_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: Literal["event", "evidence", "review", "audit", "notification"]
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    event_id: Annotated[str, Field(min_length=1, max_length=128)]
    occurred_at: datetime
    state: Annotated[str, Field(min_length=1, max_length=64)]
    actor_type: Literal["system", "human"]

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "lifecycle timestamp")


class ResourceSampleV1(FrozenModel):
    sampled_at: datetime
    gpu_percent: Annotated[float, Field(ge=0, le=100)]
    vram_percent: Annotated[float, Field(ge=0, le=100)]
    disk_bytes: Annotated[int, Field(ge=0)]
    disk_limit_bytes: Annotated[int, Field(gt=0)]

    @field_validator("sampled_at")
    @classmethod
    def sampled_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "resource timestamp")


class AcceptanceRunRecordV1(FrozenModel):
    schema_version: Literal["acceptance-run-record.v1"]
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    environment: Literal["test_only", "target"]
    gate: Literal["contract", "8h", "72h"]
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    manifest_sha256: Digest
    started_at: datetime
    ended_at: datetime
    cameras: Annotated[tuple[CameraRunRecordV1, ...], Field(min_length=20, max_length=20)]
    candidate_to_event_seconds: tuple[Annotated[float, Field(ge=0)], ...]
    first_preview_seconds: tuple[Annotated[float, Field(ge=0)], ...]
    gpu_percent: tuple[Annotated[float, Field(ge=0, le=100)], ...]
    vram_percent: tuple[Annotated[float, Field(ge=0, le=100)], ...]
    disk_bytes: tuple[Annotated[int, Field(ge=0)], ...]
    disk_limit_bytes: Annotated[int, Field(gt=0)]
    disk_bounded: bool
    faults: tuple[FaultRecordV1, ...]
    fault_traces: tuple[FaultStateTraceV1, ...] = ()
    exceptions: tuple[ExceptionRecordV1, ...]
    boundaries: tuple[BoundaryTraceV1, ...]
    lifecycle: tuple[LifecycleTraceV1, ...]
    resources: tuple[ResourceSampleV1, ...]
    queue_traces: tuple[QueueStateTraceV1, ...] = ()
    capacity: CapacityTraceV1 | None = None
    runtime_boot_ids: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = ()
    api_boot_ids: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = ()
    events_evidence_complete: bool
    reviews_audited: bool
    notifications_after_confirmation: bool
    cross_camera_leakage: bool
    queues_drained: bool
    consumers_connected: bool
    measured_effective_throughput_hz: Annotated[float, Field(ge=0)]
    required_throughput_hz: Annotated[float, Field(gt=0)]
    config_sha256: Digest
    model_sha256: Digest
    engine_sha256: Digest
    image_sha256: Digest

    @field_validator("started_at", "ended_at")
    @classmethod
    def run_times_are_utc(cls, value: datetime) -> datetime:
        return _utc(value, "run timestamp")

    @field_validator(
        "candidate_to_event_seconds",
        "first_preview_seconds",
        "gpu_percent",
        "vram_percent",
    )
    @classmethod
    def numeric_samples_are_finite(cls, values: tuple[float, ...]) -> tuple[float, ...]:
        if len(values) > 10_000_000 or any(not math.isfinite(value) for value in values):
            raise ValueError("run samples must be finite and bounded")
        return values

    @field_validator("measured_effective_throughput_hz", "required_throughput_hz")
    @classmethod
    def throughput_is_finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("throughput must be finite")
        return value

    @model_validator(mode="after")
    def run_is_consistent(self) -> AcceptanceRunRecordV1:
        if self.ended_at <= self.started_at:
            raise ValueError("ended_at must be after started_at")
        camera_ids = tuple(camera.camera_id for camera in self.cameras)
        if len(set(camera_ids)) != 20:
            raise ValueError("run requires exactly 20 unique camera records")
        fault_ids = tuple(fault.fault_id for fault in self.faults)
        if len(set(fault_ids)) != len(fault_ids):
            raise ValueError("fault IDs must be unique")
        exception_ids = tuple(item.exception_id for item in self.exceptions)
        if len(set(exception_ids)) != len(exception_ids):
            raise ValueError("exception IDs must be unique")
        lifecycle_ids = tuple(item.trace_id for item in self.lifecycle)
        if len(set(lifecycle_ids)) != len(lifecycle_ids):
            raise ValueError("lifecycle trace IDs must be unique")
        fault_trace_ids = tuple((item.fault_id, item.phase) for item in self.fault_traces)
        if len(set(fault_trace_ids)) != len(fault_trace_ids):
            raise ValueError("fault trace phase IDs must be unique")
        if len(set(self.runtime_boot_ids)) != len(self.runtime_boot_ids):
            raise ValueError("runtime boot IDs must be unique and append-only")
        if len(set(self.api_boot_ids)) != len(self.api_boot_ids):
            raise ValueError("API boot IDs must be unique and append-only")
        if not self.runtime_boot_ids or not self.api_boot_ids:
            raise ValueError("runtime and API boot IDs must be recorded")
        if any(
            current.injected_at <= previous.injected_at
            or current.monotonic_offset_seconds <= previous.monotonic_offset_seconds
            for previous, current in zip(self.faults, self.faults[1:])
        ):
            raise ValueError("fault records must be strictly append-ordered")
        for camera in self.cameras:
            if not self.started_at <= camera.last_health_at <= self.ended_at:
                raise ValueError("camera health timestamp is outside run")
            duration = (self.ended_at - self.started_at).total_seconds()
            if camera.source_outage_seconds > duration:
                raise ValueError("source outage exceeds run duration")
            if camera.availability_seconds > duration - camera.source_outage_seconds:
                raise ValueError("availability exceeds eligible run duration")
        faults_by_id = {fault.fault_id: fault for fault in self.faults}
        for fault in self.faults:
            if not self.started_at <= fault.injected_at <= self.ended_at:
                raise ValueError("fault timestamp is outside run")
            if fault.injected_at != self.started_at + timedelta(
                seconds=fault.monotonic_offset_seconds
            ):
                raise ValueError("fault injection timestamp is not monotonic-bound")
            if fault.recovered_at is not None and not (
                fault.injected_at <= fault.recovered_at <= self.ended_at
            ):
                raise ValueError("fault recovery timestamp is outside run")
        known_fault_ids = set(fault_ids)
        for trace in self.fault_traces:
            if (
                trace.fault_id not in known_fault_ids
                or not self.started_at <= trace.observed_at <= self.ended_at
            ):
                raise ValueError("fault trace is unknown or outside run")
            if self.runtime_boot_ids and trace.runtime_boot_id not in self.runtime_boot_ids:
                raise ValueError("fault trace has an unknown runtime boot ID")
            if self.api_boot_ids and trace.api_boot_id not in self.api_boot_ids:
                raise ValueError("fault trace has an unknown API boot ID")
            fault = faults_by_id[trace.fault_id]
            if trace.kind != fault.kind or trace.component != fault.target:
                raise ValueError("fault trace binding differs from its fault record")
            source_return_at = fault.injected_at + timedelta(seconds=fault.duration_seconds)
            if trace.phase == "degraded" and not (
                fault.injected_at <= trace.observed_at <= source_return_at
            ):
                raise ValueError("degraded fault trace is outside the fault interval")
            if trace.phase == "recovered" and trace.observed_at < source_return_at:
                raise ValueError("recovery trace precedes source return")
        for exception in self.exceptions:
            if not self.started_at <= exception.occurred_at <= self.ended_at:
                raise ValueError("exception timestamp is outside run")
        for trace in self.boundaries:
            if not self.started_at <= trace.observed_at <= self.ended_at:
                raise ValueError("boundary timestamp is outside run")
        for trace in self.lifecycle:
            if (
                trace.camera_id not in set(camera_ids)
                or not self.started_at <= trace.occurred_at <= self.ended_at
            ):
                raise ValueError("lifecycle trace has cross-camera or out-of-run identity")
        for sample in self.resources:
            if not self.started_at <= sample.sampled_at <= self.ended_at:
                raise ValueError("resource timestamp is outside run")
        for trace in self.queue_traces:
            if not self.started_at <= trace.observed_at <= self.ended_at:
                raise ValueError("queue trace is outside run")
            if self.runtime_boot_ids and trace.runtime_boot_id not in self.runtime_boot_ids:
                raise ValueError("queue trace has an unknown runtime boot ID")
            if self.api_boot_ids and trace.api_boot_id not in self.api_boot_ids:
                raise ValueError("queue trace has an unknown API boot ID")
        if self.capacity is not None and not (
            self.started_at <= self.capacity.observed_at <= self.ended_at
        ):
            raise ValueError("capacity trace is outside run")
        ordered_groups = (
            ("fault traces", tuple(item.observed_at for item in self.fault_traces)),
            ("lifecycle traces", tuple(item.occurred_at for item in self.lifecycle)),
            ("resource traces", tuple(item.sampled_at for item in self.resources)),
            ("queue traces", tuple(item.observed_at for item in self.queue_traces)),
            ("exception traces", tuple(item.occurred_at for item in self.exceptions)),
        )
        for label, timestamps in ordered_groups:
            if any(current < previous for previous, current in zip(timestamps, timestamps[1:])):
                raise ValueError(f"{label} must be append-ordered")
        if any(
            camera.runtime_boot_id != self.runtime_boot_ids[-1]
            or camera.api_boot_id != self.api_boot_ids[-1]
            for camera in self.cameras
        ):
            raise ValueError("camera records must bind the latest runtime and API boot IDs")
        latest_queue: dict[str, QueueStateTraceV1] = {}
        for trace in self.queue_traces:
            latest_queue[trace.queue] = trace
        if any(
            trace.runtime_boot_id != self.runtime_boot_ids[-1]
            or trace.api_boot_id != self.api_boot_ids[-1]
            for trace in latest_queue.values()
        ):
            raise ValueError("latest queue traces must bind the latest runtime and API boot IDs")
        ordered = sorted(self.lifecycle, key=lambda item: item.occurred_at)
        confirmed_at: dict[str, datetime] = {}
        audited: set[tuple[str, str]] = set()
        for item in ordered:
            if item.kind == "review" and item.state == "confirmed":
                if item.actor_type != "human":
                    raise ValueError("confirmation requires a human actor")
                confirmed_at[item.event_id] = item.occurred_at
            if item.kind == "audit":
                audited.add((item.event_id, item.state))
            if item.kind == "notification" and (
                item.event_id not in confirmed_at
                or confirmed_at[item.event_id] > item.occurred_at
            ):
                raise ValueError("notification precedes human confirmation")
        for item in ordered:
            if item.kind == "review" and (item.event_id, item.state) not in audited:
                raise ValueError("review transition lacks audit trace")
        _reject_secret_like(self.model_dump(mode="json"), path="run record")
        return self


class AcceptanceReportV1(FrozenModel):
    schema_version: Literal["acceptance-report.v1"] = "acceptance-report.v1"
    run_id: str
    site_id: str
    manifest_sha256: Digest
    generated_at: datetime
    gate: Literal["contract", "8h", "72h"]
    environment: Literal["test_only", "target"]
    passed: bool
    reasons: tuple[str, ...]
    metrics: dict[str, float]
    modules: tuple[ModuleDispositionV1, ...]
    exceptions: tuple[ExceptionRecordV1, ...]

    @model_validator(mode="after")
    def report_contains_no_serialized_secrets(self) -> AcceptanceReportV1:
        _reject_secret_like(self.model_dump(mode="json"), path="acceptance report")
        return self


def percentile_nearest_rank(values: list[float] | tuple[float, ...], quantile: float) -> float:
    """Nearest-rank percentile: sorted[ceil(q*n)-1]; empty input is explicitly zero."""
    if not 0 < quantile <= 1:
        raise ValueError("quantile must be in (0, 1]")
    if not values:
        return 0.0
    if any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("percentile values must be finite and non-negative")
    ordered = sorted(values)
    return float(ordered[math.ceil(quantile * len(ordered)) - 1])


def evaluate_acceptance(
    manifest: AcceptanceManifestV1,
    run: AcceptanceRunRecordV1,
    *,
    verified_gate_decisions: tuple[ConditionalModelGateResultV1, ...] = (),
) -> AcceptanceReportV1:
    reasons: list[str] = []
    if run.site_id != manifest.site_id or run.manifest_sha256 != manifest.manifest_sha256:
        reasons.append("run is not bound to the exact manifest/site")
    manifest_ids = {source.camera_id for source in manifest.sources}
    run_ids = {camera.camera_id for camera in run.cameras}
    if run_ids != manifest_ids:
        reasons.append("camera identities do not match the manifest")
    expected_hashes = (
        manifest.config_sha256,
        manifest.model_sha256,
        manifest.engine_sha256,
        manifest.image_sha256,
    )
    if expected_hashes != (
        run.config_sha256,
        run.model_sha256,
        run.engine_sha256,
        run.image_sha256,
    ):
        reasons.append("config/model/engine/image hash binding failed")
    duration = (run.ended_at - run.started_at).total_seconds()
    minimum = {"contract": 0.0, "8h": 8 * 3600, "72h": 72 * 3600}[run.gate]
    if duration < minimum:
        reasons.append(f"run is shorter than selected {run.gate} gate")
    if run.environment == "test_only" and run.gate != "contract":
        reasons.append("test_only portable run cannot satisfy 8h/72h gates")

    scheduled = sum(camera.scheduled_samples for camera in run.cameras)
    dropped = sum(camera.dropped_samples for camera in run.cameras)
    eligible_seconds = sum(
        max(0.0, duration - camera.source_outage_seconds) for camera in run.cameras
    )
    available_seconds = sum(camera.availability_seconds for camera in run.cameras)
    availability = 100.0 if eligible_seconds == 0 else 100 * available_seconds / eligible_seconds
    drop_percent = 0.0 if scheduled == 0 else 100 * dropped / scheduled
    queue = tuple(value for camera in run.cameras for value in camera.queue_age_seconds)
    source_recovery_seconds = tuple(
        max(
            0.0,
            (
                fault.recovered_at
                - (fault.injected_at + timedelta(seconds=fault.duration_seconds))
            ).total_seconds(),
        )
        for fault in run.faults
        if fault.kind in {"camera_loss", "network_pause"} and fault.recovered_at is not None
    )
    queue_p95 = percentile_nearest_rank(queue, 0.95)
    queue_p99 = percentile_nearest_rank(queue, 0.99)
    reconnect_p95 = percentile_nearest_rank(source_recovery_seconds, 0.95)
    reconnect_max = max(source_recovery_seconds, default=0.0)
    ordered_lifecycle = sorted(run.lifecycle, key=lambda item: item.occurred_at)
    candidates: dict[str, datetime] = {}
    persisted: dict[str, datetime] = {}
    evidence_ready: dict[str, datetime] = {}
    reviews: set[tuple[str, str]] = set()
    audits: set[tuple[str, str]] = set()
    confirmed_at: dict[str, datetime] = {}
    notification_safe = True
    notification_count = 0
    for item in ordered_lifecycle:
        if item.kind == "event" and item.state == "candidate":
            candidates.setdefault(item.event_id, item.occurred_at)
        elif item.kind == "event" and item.state == "persisted":
            persisted.setdefault(item.event_id, item.occurred_at)
        elif item.kind == "evidence" and item.state == "ready":
            evidence_ready.setdefault(item.event_id, item.occurred_at)
        elif item.kind == "review":
            reviews.add((item.event_id, item.state))
            if item.state == "confirmed":
                confirmed_at[item.event_id] = item.occurred_at
        elif item.kind == "audit":
            audits.add((item.event_id, item.state))
        elif item.kind == "notification":
            notification_count += 1
            confirmed = confirmed_at.get(item.event_id)
            notification_safe = notification_safe and confirmed is not None and confirmed <= item.occurred_at
    candidate_latencies = tuple(
        (persisted[event_id] - opened_at).total_seconds()
        for event_id, opened_at in candidates.items()
        if event_id in persisted and persisted[event_id] >= opened_at
    )
    preview_latencies = tuple(
        (evidence_ready[event_id] - opened_at).total_seconds()
        for event_id, opened_at in candidates.items()
        if event_id in evidence_ready and evidence_ready[event_id] >= opened_at
    )
    candidate_p95 = percentile_nearest_rank(candidate_latencies, 0.95)
    preview_p95 = percentile_nearest_rank(preview_latencies, 0.95)
    typed_gpu = tuple(sample.gpu_percent for sample in run.resources)
    typed_vram = tuple(sample.vram_percent for sample in run.resources)
    typed_disk = tuple(sample.disk_bytes for sample in run.resources)
    gpu_max = max(typed_gpu, default=0.0)
    vram_max = max(typed_vram, default=0.0)
    disk_growth = 0.0 if len(typed_disk) < 2 else float(typed_disk[-1] - typed_disk[0])
    boundary_map: dict[str, list[BoundaryTraceV1]] = {}
    for item in run.boundaries:
        boundary_map.setdefault(item.component, []).append(item)
    boundary_complete = all(
        component in boundary_map
        and any(item.succeeded and item.consumed_records > 0 for item in boundary_map[component])
        for component in ("event_engine", "repository", "evidence", "metrics")
    )
    event_evidence_complete = bool(candidates) and all(
        event_id in persisted and event_id in evidence_ready for event_id in candidates
    )
    reviews_audited = bool(reviews) and reviews.issubset(audits)
    notification_safe = notification_count > 0 and notification_safe
    latest_queues: dict[str, QueueStateTraceV1] = {}
    for item in sorted(run.queue_traces, key=lambda trace: trace.observed_at):
        latest_queues[item.queue] = item
    queue_traces_complete = set(latest_queues) == {
        "decode",
        "analytics",
        "verifier",
        "events",
        "evidence",
    } and all(
        item.state == "ready" and item.depth == 0 for item in latest_queues.values()
    )
    disk_traces_bounded = (
        len(run.resources) >= 2
        and all(
            item.disk_limit_bytes == run.disk_limit_bytes
            and item.disk_bytes <= item.disk_limit_bytes
            for item in run.resources
        )
    )
    resource_cadence_complete = (
        bool(run.resources)
        and run.resources[0].sampled_at == run.started_at
        and run.resources[-1].sampled_at == run.ended_at
        and all(
            (current.sampled_at - previous.sampled_at).total_seconds() <= 65
            for previous, current in zip(run.resources, run.resources[1:])
        )
    )
    capacity_bound = run.capacity is not None and (
        run.capacity.manifest_sha256,
        run.capacity.config_sha256,
        run.capacity.model_sha256,
        run.capacity.engine_sha256,
        run.capacity.image_sha256,
    ) == (
        manifest.manifest_sha256,
        manifest.config_sha256,
        manifest.model_sha256,
        manifest.engine_sha256,
        manifest.image_sha256,
    )
    measured_throughput = (
        0.0 if run.capacity is None else run.capacity.effective_throughput_hz
    )
    required_throughput = (
        run.required_throughput_hz
        if run.capacity is None
        else run.capacity.required_throughput_hz
    )
    supported_outage_by_camera: dict[str, float] = {}
    for fault in run.faults:
        if (
            fault.kind in {"camera_loss", "network_pause"}
            and fault.observed_degraded == fault.expected_degraded
            and fault.observed_recovery == fault.expected_recovery
            and fault.recovered_at is not None
        ):
            supported_outage_by_camera[fault.target] = (
                supported_outage_by_camera.get(fault.target, 0.0) + fault.duration_seconds
            )
    unsupported_outage = any(
        camera.source_outage_seconds
        > supported_outage_by_camera.get(camera.camera_id, 0.0) + 1e-9
        for camera in run.cameras
    )
    derived_claims_match = (
        tuple(run.candidate_to_event_seconds) == candidate_latencies
        and tuple(run.first_preview_seconds) == preview_latencies
        and tuple(run.gpu_percent) == typed_gpu
        and tuple(run.vram_percent) == typed_vram
        and tuple(run.disk_bytes) == typed_disk
        and run.events_evidence_complete == event_evidence_complete
        and run.reviews_audited == reviews_audited
        and run.notifications_after_confirmation == notification_safe
        and run.queues_drained == queue_traces_complete
        and run.consumers_connected == boundary_complete
        and run.disk_bounded == disk_traces_bounded
        and (
            run.capacity is None
            or (
                run.measured_effective_throughput_hz
                == run.capacity.effective_throughput_hz
                and run.required_throughput_hz == run.capacity.required_throughput_hz
            )
        )
    )
    metrics = {
        "availability_percent": availability,
        "scheduled_drop_percent": drop_percent,
        "queue_age_p95_seconds": queue_p95,
        "queue_age_p99_seconds": queue_p99,
        "reconnect_p95_seconds": reconnect_p95,
        "reconnect_max_seconds": reconnect_max,
        "candidate_to_event_p95_seconds": candidate_p95,
        "first_preview_p95_seconds": preview_p95,
        "gpu_percent_max": gpu_max,
        "vram_percent_max": vram_max,
        "disk_growth_bytes": disk_growth,
        "duration_seconds": duration,
        "throughput_headroom_fraction": (
            measured_throughput / required_throughput - 1
        ),
    }
    gates = (
        (availability < 99.5, "analytic availability is below 99.5%"),
        (drop_percent >= 1.0, "scheduled drops are not below 1%"),
        (queue_p95 >= 1.0, "queue p95 is not below 1 second"),
        (queue_p99 >= 2.0, "queue p99 is not below 2 seconds"),
        (reconnect_max > 30.0, "reconnect recovery exceeds 30 seconds"),
        (gpu_max > 75.0, "GPU utilization exceeds 75%"),
        (vram_max > 80.0, "VRAM utilization exceeds 80%"),
        (candidate_p95 > 1.0, "candidate-to-event p95 exceeds 1 second"),
        (preview_p95 > 2.0, "first preview p95 exceeds 2 seconds"),
        (
            measured_throughput < required_throughput * 1.25,
            "measured capacity lacks 25% throughput headroom",
        ),
        (not event_evidence_complete, "required event evidence is incomplete"),
        (not reviews_audited, "review transitions are not fully audited"),
        (
            not notification_safe,
            "notification occurred without confirmed human review",
        ),
        (run.cross_camera_leakage, "cross-camera identity leakage was observed"),
        (not queue_traces_complete, "bounded queue traces are missing or not drained"),
        (not disk_traces_bounded, "disk growth was not proven bounded by resource traces"),
        (
            not typed_disk or max(typed_disk, default=0) > run.disk_limit_bytes,
            "disk samples are missing or exceed the reviewed bound",
        ),
        (not queue, "queue-age samples are missing"),
        (not typed_gpu, "GPU samples are missing"),
        (not typed_vram, "VRAM samples are missing"),
        (not candidate_latencies or not preview_latencies, "required latency samples are missing"),
        (not boundary_complete, "required observed boundary traces are incomplete"),
        (
            run.environment == "target"
            and run.gate in {"8h", "72h"}
            and not resource_cadence_complete,
            "target resource sampling cadence does not cover the endurance run",
        ),
        (not derived_claims_match, "self-asserted summary differs from typed traces"),
        (not capacity_bound, "capacity evidence binding failed or is missing"),
        (unsupported_outage, "unsupported source-outage exclusion was claimed"),
        (
            any(camera.observed_records == 0 for camera in run.cameras),
            "one or more cameras emitted no observed records",
        ),
        (
            any((run.ended_at - camera.last_health_at).total_seconds() > 30 for camera in run.cameras),
            "camera health publication became stale",
        ),
        (
            any(exception.category in {"crash", "oom"} for exception in run.exceptions),
            "crash or OOM occurred",
        ),
    )
    reasons.extend(reason for failed, reason in gates if failed)
    if run.gate in {"8h", "72h"} and {fault.kind for fault in run.faults} != {
        "camera_loss",
        "malformed_timestamp",
        "network_pause",
        "runtime_restart",
        "api_restart",
        "object_store_outage",
        "model_timeout",
        "verifier_full",
    }:
        reasons.append("endurance gate lacks the complete canonical fault set")
    traces_by_fault: dict[str, list[FaultStateTraceV1]] = {}
    for trace in run.fault_traces:
        traces_by_fault.setdefault(trace.fault_id, []).append(trace)
    if run.gate in {"8h", "72h"} and (
        len(run.faults) != len(_CANONICAL_FAULT_POLICY)
        or {fault.kind for fault in run.faults} != set(_CANONICAL_FAULT_POLICY)
    ):
        reasons.append("endurance faults violate the exact canonical fault schedule")
    source_targets = {
        source.source_index: source.camera_id for source in manifest.sources
    }
    for fault in run.faults:
        (
            canonical_target,
            canonical_degraded,
            canonical_recovery,
            canonical_offset,
            canonical_duration,
        ) = canonical_fault_policy(fault.kind)
        traces = sorted(traces_by_fault.get(fault.fault_id, ()), key=lambda item: item.observed_at)
        degraded = next((item for item in traces if item.phase == "degraded"), None)
        recovered = next((item for item in traces if item.phase == "recovered"), None)
        if canonical_target.startswith("source_index:"):
            expected_target = source_targets[int(canonical_target.rsplit(":", maxsplit=1)[1])]
        else:
            expected_target = canonical_target
        target_valid = fault.target == expected_target
        if (
            fault.expected_degraded != canonical_degraded
            or fault.expected_recovery != canonical_recovery
            or not target_valid
            or fault.monotonic_offset_seconds != canonical_offset
            or fault.duration_seconds != canonical_duration
        ):
            reasons.append(
                f"fault {fault.fault_id} violates canonical fault policy and canonical fault schedule"
            )
        if fault.injected_at != run.started_at + timedelta(
            seconds=fault.monotonic_offset_seconds
        ):
            reasons.append(f"fault {fault.fault_id} injection timing is not monotonic-bound")
        if any(
            trace.kind != fault.kind or trace.component != fault.target for trace in traces
        ):
            reasons.append(f"fault {fault.fault_id} trace binding is inconsistent")
        source_return_at = fault.injected_at + timedelta(seconds=fault.duration_seconds)
        if (
            degraded is None
            or recovered is None
            or len(traces) != 2
            or degraded.state != fault.expected_degraded
            or recovered.state != fault.expected_recovery
            or recovered.observed_at < degraded.observed_at
            or not fault.injected_at <= degraded.observed_at <= source_return_at
            or recovered.observed_at < source_return_at
            or fault.observed_degraded != degraded.state
            or fault.observed_recovery != recovered.state
            or fault.recovered_at != recovered.observed_at
        ):
            reasons.append(f"fault {fault.fault_id} has incomplete degraded/recovery evidence")
        if (
            fault.kind in {"camera_loss", "network_pause"}
            and fault.recovered_at is not None
            and (fault.recovered_at - source_return_at).total_seconds() > 30
        ):
            reasons.append(f"fault {fault.fault_id} recovery after source return exceeds 30 seconds")
        if (
            fault.kind == "runtime_restart"
            and degraded is not None
            and recovered is not None
            and degraded.runtime_boot_id == recovered.runtime_boot_id
        ):
            reasons.append("runtime restart boot evidence did not change")
        if (
            fault.kind == "api_restart"
            and degraded is not None
            and recovered is not None
            and degraded.api_boot_id == recovered.api_boot_id
        ):
            reasons.append("API restart boot evidence did not change")
    if run.gate in {"8h", "72h"} and (
        len(run.runtime_boot_ids) < 2 or len(run.api_boot_ids) < 2
    ):
        reasons.append("endurance restart boot evidence requires distinct runtime and API boots")

    core_passed = (
        not reasons
        and run.environment == "target"
        and run.gate in {"8h", "72h"}
        and capacity_bound
        and measured_throughput >= required_throughput * 1.25
    )
    decision_modules = tuple(item.module for item in verified_gate_decisions)
    decisions = {item.module: item for item in verified_gate_decisions}
    duplicate_decisions = {
        module for module in decision_modules if decision_modules.count(module) > 1
    }
    report_modules: list[ModuleDispositionV1] = []
    for disposition in manifest.modules:
        if disposition.mode != "pass/operator":
            report_modules.append(disposition)
            continue
        demotion_reason: str | None = None
        if not core_passed:
            demotion_reason = "target core/capacity acceptance is missing or failed"
        elif disposition.module in {"fire_smoke", "weapon"}:
            decision = decisions.get(disposition.module)
            if (
                decision is None
                or disposition.module in duplicate_decisions
                or decision.mode != "operator"
                or decision.site_id != manifest.site_id
                or disposition.gate_decision_sha256 is None
                or decision.decision_sha256 != disposition.gate_decision_sha256
            ):
                demotion_reason = "verified conditional gate decision is missing or unbound"
            elif (
                decision.artifact_id != disposition.artifact_id
                or decision.registry_entry_sha256
                != disposition.registry_entry_sha256
            ):
                demotion_reason = "verified conditional gate artifact/registry identity mismatch"
        if demotion_reason is None:
            report_modules.append(disposition)
        else:
            report_modules.append(
                disposition.model_copy(
                    update={
                        "mode": "shadow",
                        "reason": f"{disposition.reason}; demoted: {demotion_reason}",
                    }
                )
            )
    return AcceptanceReportV1(
        run_id=run.run_id,
        site_id=run.site_id,
        manifest_sha256=run.manifest_sha256,
        generated_at=run.ended_at,
        gate=run.gate,
        environment=run.environment,
        passed=not reasons,
        reasons=tuple(reasons),
        metrics=metrics,
        modules=tuple(report_modules),
        exceptions=run.exceptions,
    )


def render_acceptance_html(report: AcceptanceReportV1, *, title: str = "Kuzet AI acceptance") -> str:
    rows = "".join(
        f"<tr><th>{html.escape(name)}</th><td>{value:.6g}</td></tr>"
        for name, value in sorted(report.metrics.items())
    )
    reasons = "".join(f"<li>{html.escape(reason)}</li>" for reason in report.reasons)
    modules = "".join(
        "<tr>"
        f"<td>{html.escape(item.module)}</td><td>{html.escape(item.mode)}</td>"
        f"<td>{html.escape(item.reason)}</td></tr>"
        for item in report.modules
    )
    exceptions = "".join(
        "<tr>"
        f"<td>{html.escape(item.exception_id)}</td>"
        f"<td>{html.escape(item.component)}</td>"
        f"<td>{html.escape(item.category)}</td><td>{html.escape(item.code)}</td></tr>"
        for item in report.exceptions
    )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui;max-width:1000px;margin:2rem auto}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:.4rem}"
        ".pass{color:#176b29}.fail{color:#a01818}</style></head><body>"
        f"<h1>{html.escape(title)}</h1><p class=\"{'pass' if report.passed else 'fail'}\">"
        f"{'PASS' if report.passed else 'PENDING/FAIL'}</p><ul>{reasons}</ul>"
        f"<h2>Metrics</h2><table>{rows}</table>"
        f"<h2>Modules</h2><table>{modules}</table>"
        f"<h2>Exceptions</h2><table>{exceptions}</table></body></html>"
    )


class SignedReportPaths(FrozenModel):
    report_json: Path
    report_html: Path
    signature: Path
    metadata: Path


def _exclusive_write(path: Path, payload: bytes, *, mode: int = 0o640) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise


def write_signed_report(
    report: AcceptanceReportV1,
    *,
    output_dir: Path,
    private_key: Path,
    public_key: Path,
) -> SignedReportPaths:
    if (
        not private_key.is_absolute()
        or not public_key.is_absolute()
        or private_key.is_symlink()
        or public_key.is_symlink()
    ):
        raise ValueError("signing key paths must be absolute non-symlinks")
    _read_regular_bounded(private_key, limit=64_000)
    _read_regular_bounded(public_key, limit=64_000)
    if output_dir.is_symlink():
        raise ValueError("report output directory must not be a symlink")
    report_payload = report.model_dump(mode="json")
    html_payload = render_acceptance_html(report).encode("utf-8")
    html_digest = hashlib.sha256(html_payload).hexdigest()
    signed_payload = _canonical_json(
        {
            "schema_version": "signed-acceptance-envelope.v1",
            "report": report_payload,
            "html_sha256": html_digest,
        }
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise ValueError("report output directory must be a non-symlink directory")
    report_json = output_dir / "acceptance-report.json"
    report_html = output_dir / "acceptance-report.html"
    signature = output_dir / "acceptance-report.sig"
    metadata = output_dir / "acceptance-verification.json"
    targets = (report_json, report_html, signature, metadata)
    if any(path.exists() or path.is_symlink() for path in targets):
        raise ValueError("acceptance report targets must be fresh")

    created: list[Path] = []
    temporary_signature: Path | None = None
    try:
        _exclusive_write(report_json, signed_payload)
        created.append(report_json)
        _exclusive_write(report_html, html_payload)
        created.append(report_html)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".acceptance-report.sig.",
            dir=output_dir,
        )
        temporary_signature = Path(temporary)
        os.close(descriptor)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(report_json),
                "-out",
                str(temporary_signature),
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        if result.returncode:
            raise ValueError("OpenSSL could not sign the acceptance report")
        signature_payload = _read_regular_bounded(temporary_signature, limit=64 * 1024)
        _exclusive_write(signature, signature_payload)
        created.append(signature)
        verification = {
            "schema_version": "acceptance-verification.v1",
            "algorithm": "Ed25519",
            "signed_file": report_json.name,
            "signature_file": signature.name,
            "html_file": report_html.name,
            "signed_sha256": hashlib.sha256(signed_payload).hexdigest(),
            "html_sha256": html_digest,
            "public_key_sha256": hashlib.sha256(
                _read_regular_bounded(public_key, limit=64_000)
            ).hexdigest(),
        }
        _exclusive_write(metadata, _canonical_json(verification))
        created.append(metadata)
        paths = SignedReportPaths(
            report_json=report_json,
            report_html=report_html,
            signature=signature,
            metadata=metadata,
        )
        if not verify_signed_report(metadata, public_key=public_key):
            raise ValueError("new acceptance signature did not verify")
        return paths
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    finally:
        if temporary_signature is not None:
            temporary_signature.unlink(missing_ok=True)


def verify_signed_report(metadata_path: Path, *, public_key: Path) -> bool:
    try:
        metadata = json.loads(_read_regular_bounded(metadata_path, limit=64_000))
        if metadata.get("schema_version") != "acceptance-verification.v1":
            return False
        if metadata.get("algorithm") != "Ed25519":
            return False
        if (
            hashlib.sha256(_read_regular_bounded(public_key, limit=64_000)).hexdigest()
            != metadata.get("public_key_sha256")
        ):
            return False
        base = metadata_path.parent
        for field in ("signed_file", "signature_file", "html_file"):
            name = metadata.get(field)
            if (
                not isinstance(name, str)
                or not name
                or Path(name).name != name
                or "/" in name
                or "\\" in name
            ):
                return False
        signed = base / metadata["signed_file"]
        signature = base / metadata["signature_file"]
        html_path = base / metadata["html_file"]
        signed_payload = _read_regular_bounded(signed, limit=8 * 1024 * 1024)
        html_payload = _read_regular_bounded(html_path, limit=8 * 1024 * 1024)
        _read_regular_bounded(signature, limit=64 * 1024)
        if hashlib.sha256(signed_payload).hexdigest() != metadata["signed_sha256"]:
            return False
        if hashlib.sha256(html_payload).hexdigest() != metadata["html_sha256"]:
            return False
        envelope = json.loads(signed_payload)
        if _canonical_json(envelope) != signed_payload:
            return False
        if envelope.get("html_sha256") != metadata["html_sha256"]:
            return False
        AcceptanceReportV1.model_validate(envelope.get("report"))
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key),
                "-in",
                str(signed),
                "-sigfile",
                str(signature),
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError):
        return False
