"""Fail-closed contracts for the exact-site pilot acceptance record."""

from __future__ import annotations

import hashlib
import html
import json
import math
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated, Any, Literal

import yaml
from pydantic import ConfigDict, Field, field_serializer, field_validator, model_validator

from protector.pilot.acceptance_legacy_v1 import verify_signed_report_v1
from protector.pilot.config import FrozenModel
from protector.pilot.gates import ConditionalModelGateResultV1
from protector.pilot.trusted_artifacts import (
    CapturedRegularArtifact,
    capture_regular_bounded,
    ed25519_public_key_spki_sha256,
)

MAX_ACCEPTANCE_RECORD_BYTES = 32 * 1024 * 1024
MAX_ACCEPTANCE_ENVELOPE_BYTES = MAX_ACCEPTANCE_RECORD_BYTES + 1024 * 1024

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ModuleMode = Literal["pass/operator", "shadow", "disabled"]
AnalyticName = Literal[
    "person",
    "restricted_zone",
    "intrusion",
    "loitering",
    "line_crossing",
    "fire_smoke",
    "weapon",
    "fight",
    "fall",
    "violence",
    "xclip",
    "vit",
]
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
_CONDITIONAL = frozenset({"fire_smoke", "weapon"})
_OPERATOR_CORE = frozenset(
    {"person", "restricted_zone", "intrusion", "loitering", "line_crossing"}
)
_URI_SCHEME = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,31}:(?=\S)")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
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


class ScheduledFaultV2(FrozenModel):
    fault_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: FaultKind
    target: Annotated[str, Field(min_length=1, max_length=128)]
    offset_seconds: Annotated[float, Field(ge=0, le=604_800)]
    duration_seconds: Annotated[float, Field(gt=0, le=3600)]
    expected_degraded: Annotated[str, Field(min_length=1, max_length=64)]
    expected_recovery: Annotated[str, Field(min_length=1, max_length=64)]


def build_canonical_fault_schedule(
    camera_ids: tuple[str, ...],
) -> tuple[ScheduledFaultV2, ...]:
    if len(camera_ids) != 20 or len(set(camera_ids)) != 20:
        raise ValueError("fault schedule requires exact 20 unique cameras")
    result: list[ScheduledFaultV2] = []
    names = {
        "camera_loss": "camera-loss",
        "malformed_timestamp": "malformed-timestamp",
        "network_pause": "network-pause",
        "runtime_restart": "runtime-restart",
        "api_restart": "api-restart",
        "object_store_outage": "object-outage",
        "model_timeout": "model-timeout",
        "verifier_full": "verifier-full",
    }
    for index, kind in enumerate(_CANONICAL_FAULT_POLICY):
        target, degraded, recovery, offset, duration = canonical_fault_policy(kind)
        if target.startswith("source_index:"):
            target = camera_ids[int(target.rsplit(":", maxsplit=1)[1])]
        result.append(
            ScheduledFaultV2(
                fault_id=f"fault-{index:02}-{names[kind]}",
                kind=kind,
                target=target,
                offset_seconds=offset,
                duration_seconds=duration,
                expected_degraded=degraded,
                expected_recovery=recovery,
            )
        )
    return tuple(result)


def canonical_fault_schedule_sha256(schedule: tuple[ScheduledFaultV2, ...]) -> str:
    return hashlib.sha256(
        _canonical_json([item.model_dump(mode="json") for item in schedule])
    ).hexdigest()


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
            _URI_SCHEME.search(value)
            or "rtsp://" in lowered
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
            or "x-amz-" in lowered
            or "x-goog-" in lowered
            or "sig=" in lowered
            or "signature=" in lowered
        ):
            raise ValueError(f"{path} contains secret-like data")


def _credential_free_reference(value: str, *, label: str) -> str:
    path = PurePosixPath(value)
    if (
        value != value.strip()
        or _SAFE_REFERENCE.fullmatch(value) is None
        or value.startswith("/")
        or "\\" in value
        or "//" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError(f"{label} must be a canonical credential-free reference")
    return value


class LocalFixtureSourceV2(FrozenModel):
    kind: Literal["local_fixture"]
    path: Annotated[str, Field(min_length=1, max_length=4096)]


class TargetSecretSourceV2(FrozenModel):
    kind: Literal["target_secret"]
    secret_reference: Annotated[
        str, Field(pattern=r"^/run/secrets/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    ]


class SourceManifestV2(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    source_index: Annotated[int, Field(ge=0, lt=20)]
    source: LocalFixtureSourceV2 | TargetSecretSourceV2 = Field(discriminator="kind")
    codec: Literal["h264", "h265"]
    width: Annotated[int, Field(ge=320, le=7680)]
    height: Annotated[int, Field(ge=240, le=4320)]
    fps: Annotated[float, Field(gt=0, le=120)]
    bitrate_kbps: Annotated[int, Field(gt=0, le=200_000)]
    analytics_hz: Mapping[AnalyticName, float]
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
    def schedule_is_bounded(cls, value: Mapping[str, float]) -> Mapping[str, float]:
        if not value or len(value) > 32 or "person" not in value:
            raise ValueError("analytics schedule must be bounded and include person")
        if any(not math.isfinite(rate) or rate < 0 or rate > 30 for rate in value.values()):
            raise ValueError("analytics schedule rates must be finite and bounded")
        return MappingProxyType(dict(value))

    @field_serializer("analytics_hz")
    def serialize_analytics_schedule(
        self,
        value: Mapping[str, float],
    ) -> dict[str, float]:
        return dict(value)

    @field_validator("provenance_reference")
    @classmethod
    def provenance_is_scoped(cls, value: str) -> str:
        return _credential_free_reference(value, label="provenance reference")

    @model_validator(mode="after")
    def source_hash_contract(self) -> SourceManifestV2:
        if isinstance(self.source, LocalFixtureSourceV2) and self.sha256 is None:
            raise ValueError("local fixture requires sha256")
        if isinstance(self.source, TargetSecretSourceV2) and self.sha256 is not None:
            raise ValueError("target secret source must not claim a captured-file hash")
        return self


def source_profiles_sha256(
    sources: tuple[SourceManifestV2, ...],
) -> str:
    """Bind ordered source identities and profiles without resolving secrets."""
    return hashlib.sha256(
        _canonical_json(
            {
                "schema_version": "acceptance-source-profiles.v2",
                "sources": [
                    {
                        "camera_id": source.camera_id,
                        "source_index": source.source_index,
                        "source": source.source.model_dump(mode="json"),
                        "codec": source.codec,
                        "width": source.width,
                        "height": source.height,
                        "fps": source.fps,
                        "bitrate_kbps": source.bitrate_kbps,
                        "analytics_hz": dict(source.analytics_hz),
                    }
                    for source in sources
                ],
            }
        )
    ).hexdigest()


class ModuleDispositionV2(FrozenModel):
    module: AnalyticName
    mode: ModuleMode
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    evidence_reference: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    artifact_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    registry_entry_sha256: Digest | None = None
    rights_sha256: Digest | None = None
    artifact_sha256: Digest | None = None
    engine_sha256: Digest | None = None
    site_matrix_sha256: Digest | None = None
    shadow_stage_sha256: Digest | None = None
    capacity_report_sha256: Digest | None = None
    workload_sha256: Digest | None = None
    gate_decision_sha256: Digest | None = None
    gate_trust_key_spki_sha256: Digest | None = None

    @field_validator("evidence_reference")
    @classmethod
    def evidence_is_credential_free(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _credential_free_reference(value, label="evidence reference")

    @model_validator(mode="after")
    def conditional_operator_requires_signed_exact_evidence(self) -> ModuleDispositionV2:
        if self.mode == "pass/operator" and self.module in _SHADOW_ONLY:
            raise ValueError(f"{self.module} cannot become operator in the Day-20 policy")
        if self.mode == "pass/operator" and self.module not in _OPERATOR_CORE | _CONDITIONAL:
            raise ValueError("analytic is not approved by the Day-20 operator policy")
        if self.mode == "pass/operator" and self.module in _CONDITIONAL:
            if (
                self.rights_sha256 is None
                or self.artifact_id is None
                or self.registry_entry_sha256 is None
                or self.artifact_sha256 is None
                or self.engine_sha256 is None
                or self.site_matrix_sha256 is None
                or self.shadow_stage_sha256 is None
                or self.capacity_report_sha256 is None
                or self.workload_sha256 is None
                or self.evidence_reference is None
                or self.gate_decision_sha256 is None
                or self.gate_trust_key_spki_sha256 is None
            ):
                raise ValueError(
                    "conditional operator mode requires complete attested gate evidence"
                )
        return self


class LaunchAttestationV2(FrozenModel):
    schema_version: Literal["acceptance-launch-attestation.v2"]
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    site_config_file_sha256: Digest
    site_config_sha256: Digest
    runtime_manifest_file_sha256: Digest
    measured_capacity_file_sha256: Digest
    capacity_signature_sha256: Digest
    capacity_trust_key_spki_sha256: Digest
    artifact_id: Annotated[str, Field(min_length=1, max_length=128)]
    artifact_sha256: Digest
    registry_entry_sha256: Digest
    frozen_workload_sha256: Digest
    expected_workload_sha256: Digest
    engine_sha256: Digest
    image_sha256: Digest
    runtime_image_id_sha256: Digest
    runtime_image_config_sha256: Digest
    runtime_code_sha256: Digest
    mount_contract_sha256: Digest
    control_network: Annotated[
        str,
        Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$"),
    ]
    camera_network: Annotated[
        str,
        Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$"),
    ]
    expected_control_network_id: Digest
    expected_control_network_config_sha256: Digest
    expected_camera_network_id: Digest
    expected_camera_network_config_sha256: Digest
    gpu_device_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=1)]
    gpu_product_name: Annotated[str, Field(min_length=1, max_length=128)]
    gpu_pci_bus_id: Annotated[
        str,
        Field(pattern=r"^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$"),
    ]
    gpu_total_vram_bytes: Annotated[int, Field(gt=0)]
    gpu_compute_capability: Annotated[str, Field(min_length=1, max_length=32)]
    gpu_mig_mode: Literal["disabled"]
    gpu_inventory_sha256: Digest
    nvidia_driver_version: Annotated[str, Field(min_length=1, max_length=64)]
    cuda_driver_version: Annotated[str, Field(min_length=1, max_length=64)]
    cuda_runtime_version: Annotated[str, Field(min_length=1, max_length=64)]
    nvidia_container_toolkit_version: Annotated[
        str,
        Field(min_length=1, max_length=64),
    ]
    acceptance_adapter_sha256: Digest
    acceptance_adapter_policy_sha256: Digest
    acceptance_observer_sha256: Digest
    acceptance_observer_policy_sha256: Digest
    runtime_api_host: Literal["api"]
    runtime_api_port: Literal[8000]
    controller_api_host: Literal["127.0.0.1"]
    controller_api_port: Annotated[int, Field(ge=1, le=65_535)]
    run_authority_public_key_spki_sha256: Digest
    source_profiles_sha256: Digest
    required_throughput_hz: Annotated[float, Field(gt=0)]
    measured_effective_throughput_hz: Annotated[float, Field(gt=0)]
    stream_count: Literal[20]

    @field_validator(
        "required_throughput_hz",
        "measured_effective_throughput_hz",
    )
    @classmethod
    def throughput_is_finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("launch throughput must be finite")
        return value

    @model_validator(mode="after")
    def networks_are_separate(self) -> LaunchAttestationV2:
        expected_gpu_inventory_sha256 = hashlib.sha256(
            _canonical_json(
                {
                    "schema_version": "measured-gpu-inventory.v1",
                    "devices": [
                        {
                            "uuid": self.gpu_device_ids[0],
                            "product_name": self.gpu_product_name,
                            "pci_bus_id": self.gpu_pci_bus_id,
                            "total_vram_bytes": self.gpu_total_vram_bytes,
                            "compute_capability": (
                                self.gpu_compute_capability
                            ),
                            "mig_mode": self.gpu_mig_mode,
                        }
                    ],
                    "nvidia_driver_version": (
                        self.nvidia_driver_version
                    ),
                    "cuda_driver_version": self.cuda_driver_version,
                    "cuda_runtime_version": self.cuda_runtime_version,
                    "nvidia_container_toolkit_version": (
                        self.nvidia_container_toolkit_version
                    ),
                }
            )
        ).hexdigest()
        if (
            self.control_network == self.camera_network
            or len(set(self.gpu_device_ids)) != len(self.gpu_device_ids)
            or self.acceptance_adapter_sha256
            == self.acceptance_observer_sha256
            or self.acceptance_adapter_policy_sha256
            == self.acceptance_observer_policy_sha256
            or any(
                re.fullmatch(r"GPU-[A-Fa-f0-9-]{16,64}", value) is None
                for value in self.gpu_device_ids
            )
            or self.gpu_inventory_sha256
            != expected_gpu_inventory_sha256
        ):
            raise ValueError("control and camera networks must be separate")
        return self

    @property
    def attestation_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.model_dump(mode="json"))).hexdigest()


class ExecutionBindingV2(FrozenModel):
    schema_version: Literal["acceptance-execution-binding.v2"]
    launch_attestation_sha256: Digest
    launch_nonce: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    container_id: Digest
    container_config_sha256: Digest
    runtime_image_id_sha256: Digest
    acceptance_adapter_sha256: Digest
    acceptance_adapter_policy_sha256: Digest
    acceptance_observer_sha256: Digest
    acceptance_observer_policy_sha256: Digest
    control_network_id: Digest
    control_network_config_sha256: Digest
    camera_network_id: Digest
    camera_network_config_sha256: Digest
    observed_gpu_inventory_sha256: Digest

    @model_validator(mode="after")
    def executor_and_observer_are_independent(
        self,
    ) -> ExecutionBindingV2:
        if (
            self.acceptance_adapter_sha256
            == self.acceptance_observer_sha256
            or self.acceptance_adapter_policy_sha256
            == self.acceptance_observer_policy_sha256
        ):
            raise ValueError(
                "acceptance executor and observer identities must differ"
            )
        return self

    @property
    def binding_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.model_dump(mode="json"))).hexdigest()


class AcceptanceManifestV2(FrozenModel):
    schema_version: Literal["acceptance-manifest.v2"]
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    sources: Annotated[tuple[SourceManifestV2, ...], Field(min_length=20, max_length=20)]
    modules: Annotated[tuple[ModuleDispositionV2, ...], Field(min_length=1, max_length=64)]
    launch: LaunchAttestationV2
    config_sha256: Digest
    model_sha256: Digest
    engine_sha256: Digest
    image_sha256: Digest

    @model_validator(mode="after")
    def exact_identities_and_modes(self) -> AcceptanceManifestV2:
        camera_ids = tuple(source.camera_id for source in self.sources)
        indices = tuple(source.source_index for source in self.sources)
        modules = tuple(item.module for item in self.modules)
        if len(set(camera_ids)) != 20:
            raise ValueError("exactly 20 unique camera IDs are required")
        if indices != tuple(range(20)):
            raise ValueError("source indices must be the ordered exact range 0..19")
        if len(set(modules)) != len(modules):
            raise ValueError("module identities must be unique")
        scheduled_modules = {
            module
            for source in self.sources
            for module, rate in source.analytics_hz.items()
            if rate > 0
        }
        if not scheduled_modules.issubset(set(modules)):
            raise ValueError(
                "every positive scheduled analytic requires one module disposition"
            )
        if any(
            item.mode == "pass/operator"
            and item.module not in scheduled_modules
            for item in self.modules
        ):
            raise ValueError(
                "every pass/operator analytic must be positively scheduled"
            )
        if (
            self.launch.site_id != self.site_id
            or self.launch.site_config_sha256 != self.config_sha256
            or self.launch.artifact_sha256 != self.model_sha256
            or self.launch.engine_sha256 != self.engine_sha256
            or self.launch.image_sha256 != self.image_sha256
            or self.launch.source_profiles_sha256
            != source_profiles_sha256(self.sources)
        ):
            raise ValueError("manifest launch attestation identity mismatch")
        _reject_secret_like(self.model_dump(mode="json"), path="manifest")
        return self

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.model_dump(mode="json"))).hexdigest()


def _read_regular_bounded(path: Path, *, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"symlink is forbidden: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
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


def _read_regular_bounded_with_metadata(
    path: Path,
    *,
    limit: int,
) -> tuple[bytes, os.stat_result]:
    if path.is_symlink():
        raise ValueError(f"symlink is forbidden: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError(f"file is not regular and bounded: {path}")
        payload = os.read(descriptor, limit + 1)
        if len(payload) != metadata.st_size:
            raise ValueError(f"file changed while reading: {path}")
        return payload, metadata
    finally:
        os.close(descriptor)


def _write_private_snapshot(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _trusted_openssl_executable() -> str:
    candidates = (
        Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
        Path("/usr/local/opt/openssl@3/bin/openssl"),
        Path("/usr/bin/openssl"),
    )
    for candidate in candidates:
        try:
            executable = candidate.resolve(strict=True)
            metadata = executable.stat()
        except OSError:
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid in {0, os.geteuid()}
            and not metadata.st_mode & 0o022
            and os.access(executable, os.X_OK)
        ):
            return str(executable)
    raise ValueError("trusted OpenSSL executable is unavailable")


def _verify_captured_signature(
    *,
    signed_payload: bytes,
    signature_payload: bytes,
    public_key_payload: bytes,
) -> bool:
    if len(signature_payload) != 64:
        return False
    with tempfile.TemporaryDirectory(prefix="kuzet-signature-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        signed = root / "signed"
        signature = root / "signature"
        public_key = root / "public.pem"
        _write_private_snapshot(signed, signed_payload)
        _write_private_snapshot(signature, signature_payload)
        _write_private_snapshot(public_key, public_key_payload)
        key_result = subprocess.run(
            [
                _trusted_openssl_executable(),
                "pkey",
                "-pubin",
                "-in",
                str(public_key),
                "-text_pub",
                "-noout",
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if (
            key_result.returncode
            or b"ED25519 Public-Key" not in key_result.stdout
        ):
            return False
        result = subprocess.run(
            [
                _trusted_openssl_executable(),
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key),
                "-sigfile",
                str(signature),
                "-in",
                str(signed),
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0


def _sign_captured_payload(
    *,
    signed_payload: bytes,
    private_key_payload: bytes,
    public_key_payload: bytes,
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="kuzet-signing-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        signed = root / "signed"
        private_key = root / "private.pem"
        signature = root / "signature"
        _write_private_snapshot(signed, signed_payload)
        _write_private_snapshot(private_key, private_key_payload)
        key_result = subprocess.run(
            [
                _trusted_openssl_executable(),
                "pkey",
                "-in",
                str(private_key),
                "-text",
                "-noout",
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if (
            key_result.returncode
            or b"ED25519 Private-Key" not in key_result.stdout
        ):
            raise ValueError(
                "OpenSSL could not sign with an Ed25519 acceptance key"
            )
        result = subprocess.run(
            [
                _trusted_openssl_executable(),
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(signed),
                "-out",
                str(signature),
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        if result.returncode:
            raise ValueError("OpenSSL could not sign the acceptance report")
        signature_payload = _read_regular_bounded(
            signature,
            limit=64 * 1024,
        )
        if len(signature_payload) != 64:
            raise ValueError("acceptance signature must be Ed25519")
        if not _verify_captured_signature(
            signed_payload=signed_payload,
            signature_payload=signature_payload,
            public_key_payload=public_key_payload,
        ):
            raise ValueError("new acceptance signature did not verify")
        return signature_payload


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


def load_acceptance_manifest(path: Path) -> AcceptanceManifestV2:
    if path.is_symlink():
        raise ValueError("acceptance manifest symlink is forbidden")
    payload = _read_regular_bounded(path.resolve(strict=True), limit=2 * 1024 * 1024)
    manifest = AcceptanceManifestV2.model_validate(yaml.safe_load(payload))
    for item in manifest.sources:
        if not isinstance(item.source, LocalFixtureSourceV2):
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


class ConditionalGateAttestationV2(FrozenModel):
    schema_version: Literal["conditional-gate-attestation.v2"]
    decision: ConditionalModelGateResultV1
    rights_sha256: Digest
    artifact_sha256: Digest
    engine_sha256: Digest
    site_matrix_sha256: Digest
    shadow_stage_sha256: Digest
    capacity_report_sha256: Digest
    workload_sha256: Digest
    public_key_spki_sha256: Digest
    signature_file: Annotated[str, Field(min_length=1, max_length=128)]
    public_key_file: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("signature_file", "public_key_file")
    @classmethod
    def detached_files_are_safe_basenames(cls, value: str) -> str:
        validated = _credential_free_reference(value, label="attestation file")
        if PurePosixPath(validated).name != validated:
            raise ValueError("attestation file must be a sibling basename")
        return validated

    @property
    def attestation_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.model_dump(mode="json"))).hexdigest()


def load_conditional_gate_decisions(
    paths: tuple[Path, ...] | list[Path],
    *,
    trusted_public_key: Path,
) -> tuple[ConditionalGateAttestationV2, ...]:
    """Verify detached signatures on exact manifest-bound gate attestations."""
    if not trusted_public_key.is_absolute():
        raise ValueError("conditional gate trust key must be an absolute path")
    try:
        trusted_key_payload = _read_regular_bounded(
            trusted_public_key,
            limit=64_000,
        )
    except (OSError, ValueError) as exc:
        raise ValueError(
            "conditional gate attestation trust key is unavailable"
        ) from exc
    trusted_key_sha256 = ed25519_public_key_spki_sha256(
        trusted_key_payload
    )
    decisions: list[ConditionalGateAttestationV2] = []
    for path in paths:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("conditional gate attestation must be an absolute non-symlink path")
        payload = _read_regular_bounded(path, limit=1024 * 1024)
        try:
            decision = ConditionalGateAttestationV2.model_validate_json(payload)
        except ValueError as exc:
            raise ValueError("conditional gate attestation is invalid") from exc
        if _canonical_json(decision.model_dump(mode="json")) != payload:
            raise ValueError("conditional gate attestation must use canonical JSON")
        signature = path.parent / decision.signature_file
        signature_payload = _read_regular_bounded(signature, limit=64_000)
        if trusted_key_sha256 != decision.public_key_spki_sha256:
            raise ValueError("conditional gate attestation trust key hash mismatch")
        if not _verify_captured_signature(
            signed_payload=payload,
            signature_payload=signature_payload,
            public_key_payload=trusted_key_payload,
        ):
            raise ValueError("conditional gate attestation signature is invalid")
        decisions.append(
            ConditionalGateAttestationV2.model_validate_json(payload)
        )
    modules = tuple(item.decision.module for item in decisions)
    if len(set(modules)) != len(modules):
        raise ValueError("duplicate conditional gate decision module")
    return tuple(decisions)


def load_run_record(path: Path) -> AcceptanceRunRecordV2:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("run record must be an absolute non-symlink path")
    return AcceptanceRunRecordV2.model_validate_json(
        _read_regular_bounded(path, limit=64 * 1024 * 1024)
    )


class CameraRunRecordV2(FrozenModel):
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
    def accounting_is_possible(self) -> CameraRunRecordV2:
        if self.processed_samples + self.dropped_samples != self.scheduled_samples:
            raise ValueError("processed plus dropped must equal scheduled samples")
        if self.observed_records != self.processed_samples:
            raise ValueError("observed records must equal processed samples")
        return self


class CameraHealthSpanV2(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    started_at: datetime
    ended_at: datetime
    state: Literal["online", "degraded", "offline", "source_outage"]
    cadence_seconds: Annotated[float, Field(gt=0, le=60)]
    observed_samples: Annotated[int, Field(ge=2, le=10_000_000)]

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _utc(value, "health coverage timestamp")

    @model_validator(mode="after")
    def cadence_covers_exact_span(self) -> CameraHealthSpanV2:
        duration = (self.ended_at - self.started_at).total_seconds()
        intervals = duration / self.cadence_seconds
        if (
            duration <= 0
            or not math.isclose(intervals, round(intervals), abs_tol=1e-9)
            or self.observed_samples != round(intervals) + 1
        ):
            raise ValueError("health coverage cadence does not cover its exact span")
        return self


class WorkAccountingSpanV2(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    module: AnalyticName
    started_at: datetime
    ended_at: datetime
    cadence_seconds: Annotated[float, Field(gt=0, le=60)]
    observed_samples: Annotated[int, Field(ge=2, le=10_000_000)]
    scheduled_samples: Annotated[int, Field(ge=0)]
    processed_samples: Annotated[int, Field(ge=0)]
    dropped_samples: Annotated[int, Field(ge=0)]

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _utc(value, "work accounting timestamp")

    @model_validator(mode="after")
    def cadence_and_totals_are_complete(self) -> WorkAccountingSpanV2:
        duration = (self.ended_at - self.started_at).total_seconds()
        intervals = duration / self.cadence_seconds
        if (
            duration <= 0
            or not math.isclose(intervals, round(intervals), abs_tol=1e-9)
            or self.observed_samples != round(intervals) + 1
        ):
            raise ValueError("work accounting coverage cadence is incomplete")
        if self.processed_samples + self.dropped_samples != self.scheduled_samples:
            raise ValueError("work accounting outcomes differ from scheduled samples")
        return self


class QueueAgeRunV2(FrozenModel):
    age_seconds: Annotated[float, Field(ge=0, le=604_800)]
    samples: Annotated[int, Field(ge=1, le=10_000_000)]

    @field_validator("age_seconds")
    @classmethod
    def age_is_finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("queue age must be finite")
        return value


class CameraQueueCoverageV2(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    queue_name: Literal["analytics"]
    started_at: datetime
    ended_at: datetime
    cadence_seconds: Annotated[float, Field(gt=0, le=60)]
    runs: Annotated[tuple[QueueAgeRunV2, ...], Field(min_length=1, max_length=100_000)]

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _utc(value, "queue coverage timestamp")

    @model_validator(mode="after")
    def run_lengths_cover_exact_span(self) -> CameraQueueCoverageV2:
        duration = (self.ended_at - self.started_at).total_seconds()
        intervals = duration / self.cadence_seconds
        expected = round(intervals) + 1
        if (
            duration <= 0
            or not math.isclose(intervals, round(intervals), abs_tol=1e-9)
            or sum(item.samples for item in self.runs) != expected
        ):
            raise ValueError("queue coverage cadence does not cover the exact run")
        return self


class FaultRecordV2(FrozenModel):
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


class FaultStateTraceV2(FrozenModel):
    fault_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: FaultKind
    phase: Literal["degraded", "recovered"]
    observed_at: datetime
    component: Annotated[str, Field(min_length=1, max_length=64)]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    command_id: Annotated[
        str,
        Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$"),
    ]
    commanded_monotonic_offset_seconds: Annotated[float, Field(ge=0, le=604_800)]

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "fault trace timestamp")


class QueueStateTraceV2(FrozenModel):
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
    def depth_is_bounded(self) -> QueueStateTraceV2:
        if self.depth > self.capacity:
            raise ValueError("queue depth exceeds its finite capacity")
        if self.state == "full" and self.depth != self.capacity:
            raise ValueError("full queue trace must be at capacity")
        return self


class CapacityTraceV2(FrozenModel):
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


class ExceptionRecordV2(FrozenModel):
    exception_id: Annotated[str, Field(min_length=1, max_length=128)]
    occurred_at: datetime
    component: Annotated[str, Field(min_length=1, max_length=64)]
    category: Literal["handled", "crash", "oom"]
    code: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "exception timestamp")


class BoundaryTraceV2(FrozenModel):
    component: Literal["event_engine", "repository", "evidence", "metrics"]
    observed_at: datetime
    consumed_records: Annotated[int, Field(ge=0)]
    succeeded: bool
    detail_code: Literal[
        "observed",
        "event-engine-ingested",
        "injected-observation-repository",
        "no-candidate-evidence-not-exercised",
        "prometheus-registry-updated",
        "acceptance-authority-observed",
    ]

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "boundary timestamp")


class LifecycleTraceV2(FrozenModel):
    trace_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: Literal["event", "evidence", "review", "audit", "notification"]
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    event_id: Annotated[str, Field(min_length=1, max_length=128)]
    occurred_at: datetime
    state: Literal["candidate", "persisted", "ready", "confirmed", "rejected", "delivered"]
    actor_type: Literal["system", "human"]

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "lifecycle timestamp")

    @model_validator(mode="after")
    def state_and_actor_match_kind(self) -> LifecycleTraceV2:
        allowed = {
            "event": {"candidate", "persisted"},
            "evidence": {"ready"},
            "review": {"confirmed", "rejected"},
            "audit": {"confirmed", "rejected"},
            "notification": {"delivered"},
        }
        if self.state not in allowed[self.kind]:
            raise ValueError("lifecycle state is invalid for its kind")
        expected_actor = "human" if self.kind == "review" else "system"
        if self.actor_type != expected_actor:
            raise ValueError("lifecycle actor type is invalid for its kind")
        return self


class ResourceSampleV2(FrozenModel):
    sampled_at: datetime
    interval_started_at: datetime | None
    observation_cadence_seconds: Annotated[float, Field(gt=0, le=5)]
    observation_count: Annotated[int, Field(ge=1, le=10_000_000)]
    gpu_percent: Annotated[float, Field(ge=0, le=100)]
    gpu_percent_high_water: Annotated[float, Field(ge=0, le=100)]
    vram_percent: Annotated[float, Field(ge=0, le=100)]
    vram_percent_high_water: Annotated[float, Field(ge=0, le=100)]
    disk_bytes: Annotated[int, Field(ge=0)]
    disk_bytes_high_water: Annotated[int, Field(ge=0)]
    disk_limit_bytes: Annotated[int, Field(gt=0)]

    @field_validator("sampled_at", "interval_started_at")
    @classmethod
    def sampled_at_is_utc(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        return None if value is None else _utc(value, "resource timestamp")

    @model_validator(mode="after")
    def interval_high_water_is_complete(self) -> ResourceSampleV2:
        if (
            self.gpu_percent_high_water < self.gpu_percent
            or self.vram_percent_high_water < self.vram_percent
            or self.disk_bytes_high_water < self.disk_bytes
        ):
            raise ValueError("resource interval high-water cannot be below endpoint")
        if self.interval_started_at is None:
            if (
                self.observation_count != 1
                or self.gpu_percent_high_water != self.gpu_percent
                or self.vram_percent_high_water != self.vram_percent
                or self.disk_bytes_high_water != self.disk_bytes
            ):
                raise ValueError("resource baseline must contain exactly one endpoint")
            return self
        duration = (self.sampled_at - self.interval_started_at).total_seconds()
        intervals = duration / self.observation_cadence_seconds
        if (
            duration <= 0
            or not math.isclose(intervals, round(intervals), abs_tol=1e-9)
            or self.observation_count != round(intervals)
        ):
            raise ValueError(
                "resource interval observations do not exactly cover the window"
            )
        return self


class AcceptanceRunRecordV2(FrozenModel):
    schema_version: Literal["acceptance-run-record.v2"]
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    environment: Literal["test_only", "target"]
    gate: Literal["contract", "8h", "72h"]
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    manifest_sha256: Digest
    launch: LaunchAttestationV2
    execution: ExecutionBindingV2 | None = None
    started_at: datetime
    ended_at: datetime
    cameras: Annotated[tuple[CameraRunRecordV2, ...], Field(min_length=20, max_length=20)]
    health_spans: Annotated[
        tuple[CameraHealthSpanV2, ...],
        Field(min_length=20, max_length=256),
    ]
    work_spans: Annotated[
        tuple[WorkAccountingSpanV2, ...],
        Field(min_length=20, max_length=640),
    ]
    queue_coverage: Annotated[
        tuple[CameraQueueCoverageV2, ...],
        Field(min_length=20, max_length=20),
    ]
    candidate_to_event_seconds: tuple[Annotated[float, Field(ge=0)], ...]
    first_preview_seconds: tuple[Annotated[float, Field(ge=0)], ...]
    gpu_percent: tuple[Annotated[float, Field(ge=0, le=100)], ...]
    vram_percent: tuple[Annotated[float, Field(ge=0, le=100)], ...]
    disk_bytes: tuple[Annotated[int, Field(ge=0)], ...]
    disk_limit_bytes: Annotated[int, Field(gt=0)]
    disk_bounded: bool
    faults: tuple[FaultRecordV2, ...]
    fault_traces: tuple[FaultStateTraceV2, ...] = ()
    exceptions: tuple[ExceptionRecordV2, ...]
    boundaries: tuple[BoundaryTraceV2, ...]
    lifecycle: tuple[LifecycleTraceV2, ...]
    resources: tuple[ResourceSampleV2, ...]
    queue_traces: tuple[QueueStateTraceV2, ...] = ()
    capacity: CapacityTraceV2 | None = None
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
    authority_journal_root_sha256: Digest | None = None
    authority_journal_entry_count: Annotated[int, Field(ge=1)] | None = None
    authority_public_key_spki_sha256: Digest | None = None

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
    def run_is_consistent(self) -> AcceptanceRunRecordV2:
        if self.ended_at <= self.started_at:
            raise ValueError("ended_at must be after started_at")
        if (
            self.launch.site_id != self.site_id
            or self.launch.site_config_sha256 != self.config_sha256
            or self.launch.artifact_sha256 != self.model_sha256
            or self.launch.engine_sha256 != self.engine_sha256
            or self.launch.image_sha256 != self.image_sha256
            or self.launch.required_throughput_hz != self.required_throughput_hz
            or (
                self.environment == "target"
                and self.launch.measured_effective_throughput_hz
                != self.measured_effective_throughput_hz
            )
        ):
            raise ValueError("run launch attestation identity mismatch")
        if self.environment == "target":
            if (
                self.execution is None
                or self.execution.launch_attestation_sha256
                != self.launch.attestation_sha256
                or self.execution.runtime_image_id_sha256
                != self.launch.runtime_image_id_sha256
                or self.execution.acceptance_adapter_sha256
                != self.launch.acceptance_adapter_sha256
                or self.execution.acceptance_adapter_policy_sha256
                != self.launch.acceptance_adapter_policy_sha256
                or self.execution.acceptance_observer_sha256
                != self.launch.acceptance_observer_sha256
                or self.execution.acceptance_observer_policy_sha256
                != self.launch.acceptance_observer_policy_sha256
                or any(
                    not boot_id.startswith(f"{self.execution.launch_nonce}.")
                    for boot_id in self.runtime_boot_ids
                )
                or (
                    self.authority_public_key_spki_sha256 is not None
                    and self.authority_public_key_spki_sha256
                    != self.launch.run_authority_public_key_spki_sha256
                )
                or (
                    (
                        self.authority_journal_root_sha256,
                        self.authority_journal_entry_count,
                        self.authority_public_key_spki_sha256,
                    ).count(None)
                    not in {0, 3}
                )
            ):
                raise ValueError("target execution binding differs from launch authority")
        elif self.execution is not None:
            raise ValueError("test-only run cannot claim a target execution binding")
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
        fault_trace_by_phase = {
            (item.fault_id, item.phase): item for item in self.fault_traces
        }
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
        health_by_camera: dict[str, list[CameraHealthSpanV2]] = {
            camera_id: [] for camera_id in camera_ids
        }
        for span in self.health_spans:
            if span.camera_id not in health_by_camera:
                raise ValueError("health coverage references an unknown camera")
            health_by_camera[span.camera_id].append(span)
        work_by_camera: dict[str, list[WorkAccountingSpanV2]] = {
            camera_id: [] for camera_id in camera_ids
        }
        work_keys: set[tuple[str, str]] = set()
        for span in self.work_spans:
            key = (span.camera_id, span.module)
            if span.camera_id not in work_by_camera or key in work_keys:
                raise ValueError("work accounting coverage identity is invalid or duplicated")
            if span.started_at != self.started_at or span.ended_at != self.ended_at:
                raise ValueError("work accounting coverage must span the exact run")
            work_keys.add(key)
            work_by_camera[span.camera_id].append(span)
        queue_by_camera = {item.camera_id: item for item in self.queue_coverage}
        if (
            len(queue_by_camera) != len(self.queue_coverage)
            or set(queue_by_camera) != set(camera_ids)
        ):
            raise ValueError("queue coverage must contain each exact camera once")
        for camera in self.cameras:
            spans = sorted(
                health_by_camera[camera.camera_id],
                key=lambda item: item.started_at,
            )
            if (
                not spans
                or spans[0].started_at != self.started_at
                or spans[-1].ended_at != self.ended_at
                or any(
                    current.started_at != previous.ended_at
                    for previous, current in zip(spans, spans[1:])
                )
            ):
                raise ValueError("health coverage must be contiguous over the exact run")
            work = work_by_camera[camera.camera_id]
            if not work:
                raise ValueError("work accounting coverage is missing")
            scheduled = sum(item.scheduled_samples for item in work)
            processed = sum(item.processed_samples for item in work)
            dropped = sum(item.dropped_samples for item in work)
            available = sum(
                (item.ended_at - item.started_at).total_seconds()
                for item in spans
                if item.state == "online"
            )
            source_outage = sum(
                (item.ended_at - item.started_at).total_seconds()
                for item in spans
                if item.state == "source_outage"
            )
            queue_span = queue_by_camera[camera.camera_id]
            if (
                queue_span.started_at != self.started_at
                or queue_span.ended_at != self.ended_at
            ):
                raise ValueError("queue coverage must span the exact run")
            queue_values = tuple(item.age_seconds for item in queue_span.runs)
            if (
                camera.scheduled_samples != scheduled
                or camera.processed_samples != processed
                or camera.dropped_samples != dropped
                or camera.observed_records != processed
                or not math.isclose(camera.availability_seconds, available, abs_tol=1e-9)
                or not math.isclose(
                    camera.source_outage_seconds,
                    source_outage,
                    abs_tol=1e-9,
                )
                or camera.queue_age_seconds != queue_values
                or camera.last_health_at != self.ended_at
            ):
                raise ValueError(
                    "camera summary differs from health/work accounting coverage"
                )
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
        expected_source_outages: set[tuple[str, datetime, datetime]] = set()
        for fault in self.faults:
            if fault.kind not in {"camera_loss", "network_pause"}:
                continue
            source_return_at = fault.injected_at + timedelta(
                seconds=fault.duration_seconds
            )
            degraded = fault_trace_by_phase.get((fault.fault_id, "degraded"))
            if degraded is None:
                continue
            if not degraded.observed_at < source_return_at:
                raise ValueError(
                    "source fault degraded acknowledgement is late"
                )
            expected_source_outages.add(
                (fault.target, degraded.observed_at, source_return_at)
            )
        observed_source_outages = {
            (span.camera_id, span.started_at, span.ended_at)
            for span in self.health_spans
            if span.state == "source_outage"
        }
        if observed_source_outages != expected_source_outages:
            raise ValueError("health coverage source-outage intervals differ from fault authority")
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
                fault.injected_at <= trace.observed_at < source_return_at
            ):
                raise ValueError("degraded fault trace is outside the fault interval")
            if trace.phase == "recovered" and trace.observed_at < source_return_at:
                raise ValueError("recovery trace precedes source return")
            expected_command_offset = (
                fault.monotonic_offset_seconds
                if trace.phase == "degraded"
                else fault.monotonic_offset_seconds + fault.duration_seconds
            )
            if trace.commanded_monotonic_offset_seconds != expected_command_offset:
                raise ValueError("fault trace command boundary differs from canonical schedule")
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
        for index, sample in enumerate(self.resources):
            if not self.started_at <= sample.sampled_at <= self.ended_at:
                raise ValueError("resource timestamp is outside run")
            if (
                index == 0
                and (
                    sample.sampled_at != self.started_at
                    or sample.interval_started_at is not None
                )
            ) or (
                index > 0
                and sample.interval_started_at
                != self.resources[index - 1].sampled_at
            ):
                raise ValueError(
                    "resource append order and intervals must exactly cover "
                    "the run without gaps"
                )
        if (
            not self.resources
            or self.resources[-1].sampled_at != self.ended_at
        ):
            raise ValueError("resource intervals do not reach the run endpoint")
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
        latest_queue: dict[str, QueueStateTraceV2] = {}
        for trace in self.queue_traces:
            latest_queue[trace.queue] = trace
        if any(
            trace.runtime_boot_id != self.runtime_boot_ids[-1]
            or trace.api_boot_id != self.api_boot_ids[-1]
            for trace in latest_queue.values()
        ):
            raise ValueError("latest queue traces must bind the latest runtime and API boot IDs")
        ordered = sorted(self.lifecycle, key=lambda item: item.occurred_at)
        event_cameras: dict[str, str] = {}
        event_stages: dict[str, set[tuple[str, str]]] = {}
        reviews_by_event: dict[str, str] = {}
        confirmed_at: dict[str, datetime] = {}
        audited: set[tuple[str, str]] = set()
        for item in ordered:
            transition = (item.kind, item.state)
            if item.kind == "event" and item.state == "candidate":
                if item.event_id in event_cameras:
                    raise ValueError("duplicate lifecycle candidate identity")
                event_cameras[item.event_id] = item.camera_id
                event_stages[item.event_id] = {transition}
                continue
            if item.event_id not in event_cameras:
                raise ValueError("orphan lifecycle continuation")
            if item.camera_id != event_cameras[item.event_id]:
                raise ValueError("cross-camera lifecycle continuation")
            stages = event_stages[item.event_id]
            if transition in stages:
                raise ValueError("duplicate lifecycle transition")
            if item.kind == "event":
                if item.state != "persisted" or ("event", "candidate") not in stages:
                    raise ValueError("illegal event lifecycle transition")
            elif item.kind == "evidence":
                if ("event", "persisted") not in stages:
                    raise ValueError("evidence precedes persisted event")
            elif item.kind == "review":
                if ("evidence", "ready") not in stages or item.event_id in reviews_by_event:
                    raise ValueError("illegal review lifecycle transition")
                reviews_by_event[item.event_id] = item.state
                if item.state == "confirmed":
                    confirmed_at[item.event_id] = item.occurred_at
            elif item.kind == "audit":
                if reviews_by_event.get(item.event_id) != item.state:
                    raise ValueError("audit does not match its review transition")
                audited.add((item.event_id, item.state))
            elif item.kind == "notification":
                if (
                    item.event_id not in confirmed_at
                    or confirmed_at[item.event_id] > item.occurred_at
                    or (item.event_id, "confirmed") not in audited
                ):
                    raise ValueError("notification precedes confirmed audited review")
            stages.add(transition)
        for item in ordered:
            if item.kind == "review" and (item.event_id, item.state) not in audited:
                raise ValueError("review transition lacks audit trace")
        if self.cross_camera_leakage:
            raise ValueError("cross-camera leakage summary differs from lifecycle authority")
        _reject_secret_like(self.model_dump(mode="json"), path="run record")
        return self


class AcceptanceReportV2(FrozenModel):
    schema_version: Literal["acceptance-report.v2"] = "acceptance-report.v2"
    run_id: str
    site_id: str
    manifest_sha256: Digest
    manifest_signature_sha256: Digest | None = None
    manifest_trust_key_spki_sha256: Digest | None = None
    run_signature_sha256: Digest | None = None
    run_trust_key_spki_sha256: Digest | None = None
    launch: LaunchAttestationV2
    execution: ExecutionBindingV2 | None = None
    generated_at: datetime
    gate: Literal["contract", "8h", "72h"]
    environment: Literal["test_only", "target"]
    passed: bool
    reasons: tuple[str, ...]
    metrics: dict[str, float]
    worst_camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    worst_camera_availability_percent: Annotated[float, Field(ge=0, le=100)]
    worst_drop_camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    worst_drop_module: AnalyticName
    worst_drop_percent: Annotated[float, Field(ge=0, le=100)]
    worst_queue_p95_camera_id: Annotated[
        str,
        Field(min_length=1, max_length=128),
    ]
    worst_queue_p95_seconds: Annotated[float, Field(ge=0)]
    worst_queue_p99_camera_id: Annotated[
        str,
        Field(min_length=1, max_length=128),
    ]
    worst_queue_p99_seconds: Annotated[float, Field(ge=0)]
    modules: tuple[ModuleDispositionV2, ...]
    exceptions: tuple[ExceptionRecordV2, ...]

    @model_validator(mode="after")
    def report_contains_no_serialized_secrets(self) -> AcceptanceReportV2:
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


def _weighted_percentile(
    runs: tuple[QueueAgeRunV2, ...],
    quantile: float,
) -> float:
    if not runs:
        return 0.0
    rank = math.ceil(quantile * sum(item.samples for item in runs))
    consumed = 0
    for item in sorted(runs, key=lambda value: value.age_seconds):
        consumed += item.samples
        if consumed >= rank:
            return item.age_seconds
    raise RuntimeError("weighted queue percentile rank is unreachable")


def evaluate_acceptance(
    manifest: AcceptanceManifestV2,
    run: AcceptanceRunRecordV2,
    *,
    verified_gate_decisions: tuple[ConditionalGateAttestationV2, ...] = (),
) -> AcceptanceReportV2:
    reasons: list[str] = []
    if run.site_id != manifest.site_id or run.manifest_sha256 != manifest.manifest_sha256:
        reasons.append("run is not bound to the exact manifest/site")
    if run.launch != manifest.launch:
        reasons.append("run launch attestation differs from the frozen manifest")
    if (
        run.environment == "target"
        and (
            run.execution is None
            or run.execution.launch_attestation_sha256
            != run.launch.attestation_sha256
            or run.execution.runtime_image_id_sha256
            != run.launch.runtime_image_id_sha256
        )
    ):
        reasons.append("target run lacks runner-created container launch identity")
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

    source_outage_by_camera = {
        camera.camera_id: sum(
            (span.ended_at - span.started_at).total_seconds()
            for span in run.health_spans
            if span.camera_id == camera.camera_id and span.state == "source_outage"
        )
        for camera in run.cameras
    }
    scheduled = sum(item.scheduled_samples for item in run.work_spans)
    dropped = sum(item.dropped_samples for item in run.work_spans)
    camera_availability = {
        camera.camera_id: (
            100.0
            if duration - source_outage_by_camera[camera.camera_id] == 0
            else 100
            * sum(
                (span.ended_at - span.started_at).total_seconds()
                for span in run.health_spans
                if span.camera_id == camera.camera_id and span.state == "online"
            )
            / (duration - source_outage_by_camera[camera.camera_id])
        )
        for camera in run.cameras
    }
    work_drop_percent = {
        (span.camera_id, span.module): (
            0.0
            if span.scheduled_samples == 0
            else 100 * span.dropped_samples / span.scheduled_samples
        )
        for span in run.work_spans
    }
    worst_camera_id, worst_camera_availability = min(
        camera_availability.items(),
        key=lambda item: (item[1], item[0]),
    )
    (worst_drop_camera_id, worst_drop_module), worst_drop_percent = max(
        work_drop_percent.items(),
        key=lambda item: (item[1], item[0][0], item[0][1]),
    )
    eligible_seconds = sum(
        max(0.0, duration - source_outage_by_camera[camera.camera_id])
        for camera in run.cameras
    )
    available_seconds = sum(
        (span.ended_at - span.started_at).total_seconds()
        for span in run.health_spans
        if span.state == "online"
    )
    availability = 100.0 if eligible_seconds == 0 else 100 * available_seconds / eligible_seconds
    drop_percent = 0.0 if scheduled == 0 else 100 * dropped / scheduled
    queue_runs = tuple(
        run_length
        for coverage in run.queue_coverage
        for run_length in coverage.runs
    )
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
    queue_p95 = _weighted_percentile(queue_runs, 0.95)
    queue_p99 = _weighted_percentile(queue_runs, 0.99)
    queue_percentiles_by_camera = {
        coverage.camera_id: (
            _weighted_percentile(coverage.runs, 0.95),
            _weighted_percentile(coverage.runs, 0.99),
        )
        for coverage in run.queue_coverage
    }
    worst_queue_p95_camera_id, worst_queue_p95_seconds = max(
        (
            (camera_id, values[0])
            for camera_id, values in queue_percentiles_by_camera.items()
        ),
        key=lambda item: (item[1], item[0]),
    )
    worst_queue_p99_camera_id, worst_queue_p99_seconds = max(
        (
            (camera_id, values[1])
            for camera_id, values in queue_percentiles_by_camera.items()
        ),
        key=lambda item: (item[1], item[0]),
    )
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
    event_cameras: dict[str, str] = {}
    derived_cross_camera_leakage = False
    for item in ordered_lifecycle:
        if item.kind == "event" and item.state == "candidate":
            candidates.setdefault(item.event_id, item.occurred_at)
            previous_camera = event_cameras.setdefault(item.event_id, item.camera_id)
            derived_cross_camera_leakage = (
                derived_cross_camera_leakage or previous_camera != item.camera_id
            )
        elif (
            item.event_id not in event_cameras
            or event_cameras[item.event_id] != item.camera_id
        ):
            derived_cross_camera_leakage = True
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
    typed_gpu = tuple(
        sample.gpu_percent_high_water for sample in run.resources
    )
    typed_vram = tuple(
        sample.vram_percent_high_water for sample in run.resources
    )
    typed_disk = tuple(
        sample.disk_bytes_high_water for sample in run.resources
    )
    gpu_max = max(typed_gpu, default=0.0)
    vram_max = max(typed_vram, default=0.0)
    disk_growth = 0.0 if len(typed_disk) < 2 else float(typed_disk[-1] - typed_disk[0])
    boundary_map: dict[str, list[BoundaryTraceV2]] = {}
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
    latest_queues: dict[str, QueueStateTraceV2] = {}
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
            and item.disk_bytes_high_water <= item.disk_limit_bytes
            for item in run.resources
        )
    )
    resource_cadence_complete = (
        bool(run.resources)
        and run.resources[0].sampled_at == run.started_at
        and run.resources[-1].sampled_at == run.ended_at
        and run.resources[0].interval_started_at is None
        and all(
            current.interval_started_at == previous.sampled_at
            for previous, current in zip(
                run.resources,
                run.resources[1:],
            )
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
    source_by_camera = {source.camera_id: source for source in manifest.sources}
    work_by_key = {
        (span.camera_id, span.module): span for span in run.work_spans
    }
    expected_work_keys = {
        (source.camera_id, module)
        for source in manifest.sources
        for module, rate in source.analytics_hz.items()
        if rate > 0
    }
    work_coverage_complete = set(work_by_key) == expected_work_keys
    if work_coverage_complete:
        for (camera_id, module), span in work_by_key.items():
            eligible = duration - source_outage_by_camera[camera_id]
            expected_scheduled = math.floor(
                float(source_by_camera[camera_id].analytics_hz[module]) * eligible
                + 1e-9
            )
            if span.scheduled_samples != expected_scheduled:
                work_coverage_complete = False
                break
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
        and run.cross_camera_leakage == derived_cross_camera_leakage
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
        "worst_camera_availability_percent": worst_camera_availability,
        "worst_camera_module_drop_percent": worst_drop_percent,
        "queue_age_p95_seconds": queue_p95,
        "queue_age_p99_seconds": queue_p99,
        "worst_camera_queue_p95_seconds": worst_queue_p95_seconds,
        "worst_camera_queue_p99_seconds": worst_queue_p99_seconds,
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
        (
            any(value < 99.5 for value in camera_availability.values()),
            "one or more cameras have analytic availability below 99.5%",
        ),
        (
            any(value >= 1.0 for value in work_drop_percent.values()),
            "one or more scheduled camera/module workloads have drops not below 1%",
        ),
        (
            worst_queue_p95_seconds >= 1.0,
            "one or more camera queue p95 values are not below 1 second",
        ),
        (
            worst_queue_p99_seconds >= 2.0,
            "one or more camera queue p99 values are not below 2 seconds",
        ),
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
        (
            derived_cross_camera_leakage,
            "cross-camera identity leakage was observed",
        ),
        (
            run.cross_camera_leakage != derived_cross_camera_leakage,
            "cross-camera leakage summary differs from typed lifecycle traces",
        ),
        (not queue_traces_complete, "bounded queue traces are missing or not drained"),
        (not disk_traces_bounded, "disk growth was not proven bounded by resource traces"),
        (
            not typed_disk or max(typed_disk, default=0) > run.disk_limit_bytes,
            "disk samples are missing or exceed the reviewed bound",
        ),
        (not queue_runs, "queue-age samples are missing"),
        (
            not work_coverage_complete,
            "work accounting coverage does not match the frozen analytic schedule",
        ),
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
    traces_by_fault: dict[str, list[FaultStateTraceV2]] = {}
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
    decision_modules = tuple(item.decision.module for item in verified_gate_decisions)
    decisions = {item.decision.module: item for item in verified_gate_decisions}
    duplicate_decisions = {
        module for module in decision_modules if decision_modules.count(module) > 1
    }
    observed_work_modules = {item.module for item in run.work_spans}
    report_modules: list[ModuleDispositionV2] = []
    for disposition in manifest.modules:
        if disposition.mode != "pass/operator":
            report_modules.append(disposition)
            continue
        demotion_reason: str | None = None
        if disposition.module not in observed_work_modules:
            demotion_reason = "matching observed work accounting is missing"
        elif not core_passed:
            demotion_reason = "target core/capacity acceptance is missing or failed"
        elif disposition.module in {"fire_smoke", "weapon"}:
            attestation = decisions.get(disposition.module)
            decision = None if attestation is None else attestation.decision
            if (
                decision is None
                or disposition.module in duplicate_decisions
                or decision.mode != "operator"
                or decision.site_id != manifest.site_id
                or disposition.gate_decision_sha256 is None
                or attestation is None
                or attestation.attestation_sha256
                != disposition.gate_decision_sha256
                or attestation.public_key_spki_sha256
                != disposition.gate_trust_key_spki_sha256
            ):
                demotion_reason = "verified conditional gate attestation is missing or unbound"
            elif (
                decision.artifact_id != disposition.artifact_id
                or decision.registry_entry_sha256
                != disposition.registry_entry_sha256
                or attestation.rights_sha256 != disposition.rights_sha256
                or attestation.artifact_sha256 != disposition.artifact_sha256
                or attestation.engine_sha256 != disposition.engine_sha256
                or attestation.site_matrix_sha256
                != disposition.site_matrix_sha256
                or attestation.shadow_stage_sha256
                != disposition.shadow_stage_sha256
                or attestation.capacity_report_sha256
                != disposition.capacity_report_sha256
                or attestation.workload_sha256 != disposition.workload_sha256
            ):
                demotion_reason = "verified conditional gate evidence identity mismatch"
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
    return AcceptanceReportV2(
        run_id=run.run_id,
        site_id=run.site_id,
        manifest_sha256=run.manifest_sha256,
        launch=run.launch,
        execution=run.execution,
        generated_at=run.ended_at,
        gate=run.gate,
        environment=run.environment,
        passed=not reasons,
        reasons=tuple(reasons),
        metrics=metrics,
        worst_camera_id=worst_camera_id,
        worst_camera_availability_percent=worst_camera_availability,
        worst_drop_camera_id=worst_drop_camera_id,
        worst_drop_module=worst_drop_module,
        worst_drop_percent=worst_drop_percent,
        worst_queue_p95_camera_id=worst_queue_p95_camera_id,
        worst_queue_p95_seconds=worst_queue_p95_seconds,
        worst_queue_p99_camera_id=worst_queue_p99_camera_id,
        worst_queue_p99_seconds=worst_queue_p99_seconds,
        modules=tuple(report_modules),
        exceptions=run.exceptions,
    )


def render_acceptance_html(report: AcceptanceReportV2, *, title: str = "Kuzet AI acceptance") -> str:
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


class _StrictFrozenAcceptanceModel(FrozenModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SignedAcceptanceEnvelopeV2(_StrictFrozenAcceptanceModel):
    """Exact canonical bytes covered by a V2 acceptance report signature."""

    schema_version: Literal["signed-acceptance-envelope.v2"] = (
        "signed-acceptance-envelope.v2"
    )
    report: AcceptanceReportV2
    html_sha256: Digest


class AcceptanceVerificationV2(_StrictFrozenAcceptanceModel):
    """Strict metadata that locates and binds one signed V2 report bundle."""

    schema_version: Literal["acceptance-verification.v2"] = (
        "acceptance-verification.v2"
    )
    algorithm: Literal["Ed25519"]
    signed_file: Annotated[str, Field(min_length=1, max_length=128)]
    signature_file: Annotated[str, Field(min_length=1, max_length=128)]
    html_file: Annotated[str, Field(min_length=1, max_length=128)]
    signed_sha256: Digest
    html_sha256: Digest
    public_key_spki_sha256: Digest
    manifest_signature_sha256: Digest | None = None
    manifest_trust_key_spki_sha256: Digest | None = None
    run_signature_sha256: Digest | None = None
    run_trust_key_spki_sha256: Digest | None = None
    capacity_signature_sha256: Digest
    capacity_trust_key_spki_sha256: Digest

    @field_validator("signed_file", "signature_file", "html_file")
    @classmethod
    def artifact_names_are_safe_basenames(cls, value: str) -> str:
        if (
            Path(value).name != value
            or "/" in value
            or "\\" in value
            or value in {".", ".."}
        ):
            raise ValueError("acceptance verification artifact must be a safe basename")
        return value

    @model_validator(mode="after")
    def optional_trust_bindings_are_paired(self) -> AcceptanceVerificationV2:
        if (self.manifest_signature_sha256 is None) != (
            self.manifest_trust_key_spki_sha256 is None
        ) or (self.run_signature_sha256 is None) != (
            self.run_trust_key_spki_sha256 is None
        ):
            raise ValueError("acceptance signature and SPKI trust identities must be paired")
        return self


class SignedReportPathsV2(FrozenModel):
    report_json: Path
    report_html: Path
    signature: Path
    metadata: Path


@dataclass(frozen=True)
class VerifiedSignedReportV2:
    """One immutable, signature-verified capture of a complete V2 report bundle."""

    report: AcceptanceReportV2
    public_key_payload: bytes
    metadata: AcceptanceVerificationV2
    envelope: SignedAcceptanceEnvelopeV2
    metadata_artifact: CapturedRegularArtifact
    signed_artifact: CapturedRegularArtifact
    signature_artifact: CapturedRegularArtifact
    html_artifact: CapturedRegularArtifact
    public_key_artifact: CapturedRegularArtifact


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
    report: AcceptanceReportV2,
    *,
    output_dir: Path,
    private_key: Path,
    public_key: Path,
) -> SignedReportPathsV2:
    if (
        type(report) is not AcceptanceReportV2
        or report.schema_version != "acceptance-report.v2"
    ):
        raise ValueError("report signing requires one exact V2 acceptance report")
    if (
        not private_key.is_absolute()
        or not public_key.is_absolute()
        or private_key.is_symlink()
        or public_key.is_symlink()
    ):
        raise ValueError("signing key paths must be absolute non-symlinks")
    private_key_payload, private_key_metadata = (
        _read_regular_bounded_with_metadata(private_key, limit=64_000)
    )
    public_key_payload = _read_regular_bounded(public_key, limit=64_000)
    if (
        private_key_metadata.st_uid not in {0, os.geteuid()}
        or private_key_metadata.st_mode & 0o077
    ):
        raise ValueError("signing private key ownership or mode is unsafe")
    if output_dir.is_symlink():
        raise ValueError("report output directory must not be a symlink")
    html_payload = render_acceptance_html(report).encode("utf-8")
    html_digest = hashlib.sha256(html_payload).hexdigest()
    envelope = SignedAcceptanceEnvelopeV2(
        report=report,
        html_sha256=html_digest,
    )
    signed_payload = _canonical_json(envelope.model_dump(mode="json"))
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

    signature_payload = _sign_captured_payload(
        signed_payload=signed_payload,
        private_key_payload=private_key_payload,
        public_key_payload=public_key_payload,
    )
    created: list[Path] = []
    try:
        _exclusive_write(report_json, signed_payload)
        created.append(report_json)
        _exclusive_write(report_html, html_payload)
        created.append(report_html)
        _exclusive_write(signature, signature_payload)
        created.append(signature)
        verification = AcceptanceVerificationV2(
            algorithm="Ed25519",
            signed_file=report_json.name,
            signature_file=signature.name,
            html_file=report_html.name,
            signed_sha256=hashlib.sha256(signed_payload).hexdigest(),
            html_sha256=html_digest,
            public_key_spki_sha256=ed25519_public_key_spki_sha256(
                public_key_payload
            ),
            manifest_signature_sha256=report.manifest_signature_sha256,
            manifest_trust_key_spki_sha256=(
                report.manifest_trust_key_spki_sha256
            ),
            run_signature_sha256=report.run_signature_sha256,
            run_trust_key_spki_sha256=report.run_trust_key_spki_sha256,
            capacity_signature_sha256=report.launch.capacity_signature_sha256,
            capacity_trust_key_spki_sha256=(
                report.launch.capacity_trust_key_spki_sha256
            ),
        )
        _exclusive_write(
            metadata,
            _canonical_json(verification.model_dump(mode="json")),
        )
        created.append(metadata)
        paths = SignedReportPathsV2(
            report_json=report_json,
            report_html=report_html,
            signature=signature,
            metadata=metadata,
        )
        if not verify_signed_report_v2(metadata, public_key=public_key):
            raise ValueError("new acceptance signature did not verify")
        return paths
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise


def capture_verified_signed_report_v2(
    metadata_path: Path,
    *,
    public_key: Path,
    captured_metadata: CapturedRegularArtifact | None = None,
) -> VerifiedSignedReportV2:
    """Capture and verify one exact V2 bundle without reopening any artifact."""
    try:
        metadata_artifact = captured_metadata or capture_regular_bounded(
            metadata_path,
            max_bytes=64 * 1024,
            label="acceptance report verification metadata",
        )
        if not isinstance(metadata_artifact, CapturedRegularArtifact):
            raise ValueError("captured acceptance metadata is invalid")
        metadata_payload = metadata_artifact.payload
        metadata = AcceptanceVerificationV2.model_validate_json(metadata_payload)
        if (
            metadata.schema_version != "acceptance-verification.v2"
            or _canonical_json(metadata.model_dump(mode="json"))
            != metadata_payload
        ):
            raise ValueError("acceptance report verification metadata is invalid")

        base = metadata_path.parent
        signed_path = base / metadata.signed_file
        signature_path = base / metadata.signature_file
        html_path = base / metadata.html_file
        artifact_paths = (
            metadata_path,
            signed_path,
            signature_path,
            html_path,
            public_key,
        )
        if len(set(artifact_paths)) != len(artifact_paths):
            raise ValueError("acceptance report bundle artifact paths must be distinct")

        signed_artifact = capture_regular_bounded(
            signed_path,
            max_bytes=MAX_ACCEPTANCE_ENVELOPE_BYTES,
            label="signed acceptance report",
        )
        signature_artifact = capture_regular_bounded(
            signature_path,
            max_bytes=64 * 1024,
            label="acceptance report signature",
        )
        html_artifact = capture_regular_bounded(
            html_path,
            max_bytes=MAX_ACCEPTANCE_RECORD_BYTES,
            label="acceptance report HTML",
        )
        public_key_artifact = capture_regular_bounded(
            public_key,
            max_bytes=64 * 1024,
            label="acceptance report public key",
        )
        signed_payload = signed_artifact.payload
        signature_payload = signature_artifact.payload
        html_payload = html_artifact.payload
        public_key_payload = public_key_artifact.payload
        if len(signature_payload) != 64:
            raise ValueError("acceptance report signature must be Ed25519")
        if (
            ed25519_public_key_spki_sha256(public_key_payload)
            != metadata.public_key_spki_sha256
        ):
            raise ValueError("acceptance report public key differs from metadata")
        if hashlib.sha256(signed_payload).hexdigest() != metadata.signed_sha256:
            raise ValueError("signed acceptance report digest differs from metadata")
        if hashlib.sha256(html_payload).hexdigest() != metadata.html_sha256:
            raise ValueError("acceptance report HTML digest differs from metadata")
        envelope = SignedAcceptanceEnvelopeV2.model_validate_json(signed_payload)
        if (
            envelope.schema_version != "signed-acceptance-envelope.v2"
            or _canonical_json(envelope.model_dump(mode="json"))
            != signed_payload
        ):
            raise ValueError("signed acceptance report envelope is invalid")
        if envelope.html_sha256 != metadata.html_sha256:
            raise ValueError("signed acceptance report HTML binding is invalid")
        report = envelope.report
        if any(
            getattr(metadata, field) != value
            for field, value in {
                "manifest_signature_sha256": (
                    report.manifest_signature_sha256
                ),
                "manifest_trust_key_spki_sha256": (
                    report.manifest_trust_key_spki_sha256
                ),
                "run_signature_sha256": report.run_signature_sha256,
                "run_trust_key_spki_sha256": report.run_trust_key_spki_sha256,
                "capacity_signature_sha256": (
                    report.launch.capacity_signature_sha256
                ),
                "capacity_trust_key_spki_sha256": (
                    report.launch.capacity_trust_key_spki_sha256
                ),
            }.items()
        ):
            raise ValueError("signed acceptance report trust bindings are invalid")
        if not _verify_captured_signature(
            signed_payload=signed_payload,
            signature_payload=signature_payload,
            public_key_payload=public_key_payload,
        ):
            raise ValueError("acceptance report signature is invalid")
        return VerifiedSignedReportV2(
            report=report,
            public_key_payload=public_key_payload,
            metadata=metadata,
            envelope=envelope,
            metadata_artifact=metadata_artifact,
            signed_artifact=signed_artifact,
            signature_artifact=signature_artifact,
            html_artifact=html_artifact,
            public_key_artifact=public_key_artifact,
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        raise ValueError("V2 signed acceptance report verification failed") from exc


def verify_signed_report_v2(
    metadata_path: Path,
    *,
    public_key: Path,
    captured_metadata: CapturedRegularArtifact | None = None,
) -> bool:
    """Verify only an exact V2 report; this function never routes to legacy."""
    try:
        capture_verified_signed_report_v2(
            metadata_path,
            public_key=public_key,
            captured_metadata=captured_metadata,
        )
    except ValueError:
        return False
    return True


def verify_signed_report(metadata_path: Path, *, public_key: Path) -> bool:
    """Dispatch exactly once from the outer metadata schema version."""
    try:
        captured_metadata = capture_regular_bounded(
            metadata_path,
            max_bytes=64 * 1024,
            label="acceptance report verification metadata",
        )
        metadata = json.loads(captured_metadata.payload)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False
    if not isinstance(metadata, dict):
        return False
    schema_version = metadata.get("schema_version")
    if schema_version == "acceptance-verification.v2":
        return verify_signed_report_v2(
            metadata_path,
            public_key=public_key,
            captured_metadata=captured_metadata,
        )
    if schema_version == "acceptance-verification.v1":
        return verify_signed_report_v1(metadata_path, public_key=public_key)
    return False
