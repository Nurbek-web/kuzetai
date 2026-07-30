"""Fail-closed, evidence-based promotion decisions for conditional analytics."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from protector.pilot.config import FrozenModel, NonEmptyString, SiteConfig
from protector.pilot.domain import GateMode

_OPERATOR_NOTIFICATION_CATEGORIES = {
    "person": frozenset(
        {"person", "restricted_zone", "intrusion", "loitering", "line_crossing"}
    ),
    "zone": frozenset({"restricted_zone", "intrusion"}),
    "loitering": frozenset({"loitering"}),
    "line_crossing": frozenset({"line_crossing"}),
    "weapon": frozenset({"weapon"}),
    "fire_smoke": frozenset({"fire_smoke"}),
}
_OPERATOR_ELIGIBLE_ANALYTICS = frozenset(_OPERATOR_NOTIFICATION_CATEGORIES)
_SHADOW_ONLY_ANALYTICS = frozenset({"violence", "xclip", "vit", "fight", "fall"})
PILOT_TARGET_GPU_ARCHITECTURE = "NVIDIA L4 (Ada)"
PILOT_TARGET_COMPUTE_CAPABILITY = "8.9"
PILOT_TENSORRT_VERSION = "10.16.0.72"
_HEX = frozenset("0123456789abcdef")


def is_operator_notification_eligible(
    *,
    artifact_analytic: str,
    event_module: str,
) -> bool:
    """Bind a persisted model analytic to an approved pilot event category."""

    if not isinstance(artifact_analytic, str) or not isinstance(event_module, str):
        return False
    return event_module in _OPERATOR_NOTIFICATION_CATEGORIES.get(
        artifact_analytic,
        frozenset(),
    )


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("signed_at must be UTC-aware")
    return value.astimezone(timezone.utc)


def _digest(value: str, *, field_name: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(character not in _HEX for character in normalized):
        raise ValueError(f"{field_name} must be a 64-character hexadecimal digest")
    return normalized


def validate_credential_free_reference(value: str) -> str:
    """Accept only canonical HTTPS, S3, registry, or scoped relative references."""

    message = "reference must be canonical and credential-free"
    if (
        value != value.strip()
        or any(character.isspace() for character in value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "\\" in value
        or "%" in value
        or "?" in value
        or "#" in value
        or ";" in value
    ):
        raise ValueError(message)
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValueError(message) from exc
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(message)
    if parsed.query or parsed.fragment:
        raise ValueError(message)
    if parsed.scheme not in {"", "https", "s3", "registry"}:
        raise ValueError(message)

    def canonical_path(path: str, *, absolute: bool) -> bool:
        if not path or path.endswith("/") or "//" in path:
            return False
        if absolute != path.startswith("/"):
            return False
        parts = path[1:].split("/") if absolute else path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return False
        return PurePosixPath(path).as_posix() == path

    if not parsed.scheme:
        if parsed.netloc or not canonical_path(parsed.path, absolute=False):
            raise ValueError(message)
        return value

    if parsed.scheme != value.split(":", maxsplit=1)[0]:
        raise ValueError(message)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(message) from exc
    hostname = parsed.hostname
    if hostname is None or hostname != hostname.lower():
        raise ValueError(message)
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            is None
            for label in labels
        )
    ):
        raise ValueError(message)
    if parsed.scheme in {"s3", "registry"}:
        if port is not None or parsed.netloc != hostname:
            raise ValueError(message)
    else:
        expected_authority = hostname if port is None else f"{hostname}:{port}"
        if parsed.netloc != expected_authority or port == 443:
            raise ValueError(message)
    if not canonical_path(parsed.path, absolute=True):
        raise ValueError(message)
    return value


class CommercialRightsRecordV1(FrozenModel):
    """An explicit commercial-use decision, not an inferred licence label."""

    schema_version: Literal["commercial-rights.v1"]
    record_id: NonEmptyString
    terms_reference: NonEmptyString
    commercial_use_approved: bool


class ModelArtifactV1(FrozenModel):
    """The exact artifact and metadata required before operational promotion."""

    schema_version: Literal["model-artifact.v1"]
    artifact_id: NonEmptyString
    sha256: str | None = None
    source: NonEmptyString | None = None
    commercial_rights: CommercialRightsRecordV1 | None = None
    class_list: tuple[NonEmptyString, ...] = ()
    preprocessing: NonEmptyString | None = None
    analytic: NonEmptyString

    @field_validator("sha256")
    @classmethod
    def sha256_is_a_digest_when_present(cls, value: str | None) -> str | None:
        if value is not None and len(value) != 64:
            raise ValueError("sha256 must be a 64-character digest")
        if value is not None and any(character not in "0123456789abcdef" for character in value.lower()):
            raise ValueError("sha256 must be hexadecimal")
        return value


class AuditedReportV1(FrozenModel):
    """Immutable report provenance; a pass/fail boolean is never sufficient evidence alone."""

    artifact_id: NonEmptyString
    passed: bool
    report_reference: NonEmptyString
    report_sha256: str
    signed_by: NonEmptyString
    signed_at: datetime

    @field_validator("report_sha256")
    @classmethod
    def report_hash_is_a_digest(cls, value: str) -> str:
        if len(value) != 64:
            raise ValueError("report_sha256 must be a 64-character digest")
        if any(character not in "0123456789abcdef" for character in value.lower()):
            raise ValueError("report_sha256 must be hexadecimal")
        return value

    @field_validator("signed_at")
    @classmethod
    def signed_at_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @field_validator("report_reference")
    @classmethod
    def report_reference_is_credential_free(cls, value: str) -> str:
        return validate_credential_free_reference(value)


class TargetSiteReportV1(AuditedReportV1):
    """Signed target-site validation for one exact model artifact."""

    schema_version: Literal["target-site-report.v1"]
    site_id: NonEmptyString


class CapacityReportV1(AuditedReportV1):
    """Signed capacity result for the pilot's exact stream count."""

    schema_version: Literal["capacity-report.v1"]
    artifact_id: NonEmptyString
    stream_count: Annotated[int, Field(ge=1)]
    passed: bool
    report_reference: NonEmptyString


class ShadowStageReportV1(AuditedReportV1):
    """Recorded successful shadow evaluation required before operator promotion."""

    schema_version: Literal["shadow-stage-report.v1"]


class SiteMatrixSceneV1(FrozenModel):
    """One immutable positive or hard-negative scene in the signed site corpus."""

    scene_id: NonEmptyString
    source_sha256: str
    expected_event: bool
    result: Literal["pass", "fail"]

    @field_validator("source_sha256")
    @classmethod
    def source_hash_is_a_digest(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value.lower()):
            raise ValueError("source_sha256 must be a 64-character hexadecimal digest")
        return value.lower()


class SignedSiteMatrixV1(AuditedReportV1):
    """Signed event-level positives and hard negatives for one site and artifact."""

    schema_version: Literal["signed-site-matrix.v1"]
    site_id: NonEmptyString
    module: NonEmptyString
    artifact_sha256: str
    registry_entry_sha256: str
    positives: Annotated[tuple[SiteMatrixSceneV1, ...], Field(min_length=1)]
    hard_negatives: Annotated[tuple[SiteMatrixSceneV1, ...], Field(min_length=1)]

    @field_validator("artifact_sha256", "registry_entry_sha256")
    @classmethod
    def artifact_hash_is_a_digest(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value.lower()):
            raise ValueError("artifact_sha256 must be a 64-character hexadecimal digest")
        return value.lower()

    @model_validator(mode="after")
    def scene_groups_match_their_contract(self) -> SignedSiteMatrixV1:
        if any(not scene.expected_event for scene in self.positives):
            raise ValueError("positives must contain expected events")
        if any(scene.expected_event for scene in self.hard_negatives):
            raise ValueError("hard_negatives must contain expected non-events")
        scene_ids = [scene.scene_id for scene in (*self.positives, *self.hard_negatives)]
        if len(scene_ids) != len(set(scene_ids)):
            raise ValueError("site matrix scene IDs must be unique")
        return self


class ShadowStageEvidenceV1(AuditedReportV1):
    """Signed completion of the exact artifact's target-site shadow stage."""

    schema_version: Literal["shadow-stage-evidence.v1"]
    site_id: NonEmptyString
    artifact_sha256: str
    registry_entry_sha256: str

    @field_validator("artifact_sha256", "registry_entry_sha256")
    @classmethod
    def artifact_hash_is_a_digest(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value.lower()):
            raise ValueError("artifact_sha256 must be a 64-character hexadecimal digest")
        return value.lower()


class MeasuredGpuDeviceV1(FrozenModel):
    """One exact physical GPU identity used by a capacity measurement."""

    uuid: Annotated[
        str,
        Field(pattern=r"^GPU-[A-Fa-f0-9-]{16,64}$"),
    ]
    product_name: NonEmptyString
    pci_bus_id: Annotated[
        str,
        Field(pattern=r"^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$"),
    ]
    total_vram_bytes: Annotated[int, Field(gt=0, le=1_000_000_000_000)]
    compute_capability: NonEmptyString
    mig_mode: Literal["disabled"]


class MeasuredCapacityReportV1(AuditedReportV1):
    """Signed measurements for the frozen 20-stream target workload."""

    schema_version: Literal["measured-capacity-report.v1"]
    site_id: NonEmptyString
    artifact_sha256: str
    registry_entry_sha256: str
    engine_sha256: str
    precision: Literal["fp16", "int8"]
    target_gpu_architecture: NonEmptyString
    target_compute_capability: NonEmptyString
    tensorrt_version: NonEmptyString
    nvidia_driver_version: NonEmptyString
    cuda_driver_version: NonEmptyString
    cuda_runtime_version: NonEmptyString
    nvidia_container_toolkit_version: NonEmptyString
    gpu_devices: Annotated[
        tuple[MeasuredGpuDeviceV1, ...],
        Field(min_length=1, max_length=1),
    ]
    site_config_sha256: str
    runtime_manifest_file_sha256: str
    frozen_workload_sha256: str
    expected_workload_sha256: str
    runtime_image_id_sha256: str
    runtime_image_config_sha256: str
    runtime_code_sha256: str
    mount_contract_sha256: str
    stream_count: Annotated[int, Field(ge=1)]
    effective_throughput_hz: Annotated[float, Field(gt=0)]
    required_throughput_hz: Annotated[float, Field(gt=0)]
    scheduled_drop_fraction: Annotated[float, Field(ge=0, le=1)]
    queue_age_p95_seconds: Annotated[float, Field(ge=0)]
    queue_age_p99_seconds: Annotated[float, Field(ge=0)]
    gpu_utilization_max: Annotated[float, Field(ge=0, le=1)]
    vram_utilization_max: Annotated[float, Field(ge=0, le=1)]

    @field_validator(
        "artifact_sha256",
        "registry_entry_sha256",
        "engine_sha256",
        "site_config_sha256",
        "runtime_manifest_file_sha256",
        "frozen_workload_sha256",
        "expected_workload_sha256",
        "runtime_image_id_sha256",
        "runtime_image_config_sha256",
        "runtime_code_sha256",
        "mount_contract_sha256",
    )
    @classmethod
    def hashes_are_digests(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value.lower()):
            raise ValueError("capacity hashes must be 64-character hexadecimal digests")
        return value.lower()

    @model_validator(mode="after")
    def gpu_set_is_exact_and_consistent(self) -> MeasuredCapacityReportV1:
        if (
            len({item.uuid for item in self.gpu_devices})
            != len(self.gpu_devices)
            or len({item.pci_bus_id for item in self.gpu_devices})
            != len(self.gpu_devices)
            or any(
                item.compute_capability != self.target_compute_capability
                for item in self.gpu_devices
            )
        ):
            raise ValueError("capacity report GPU set is not exact or consistent")
        return self

    @property
    def gpu_inventory_sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "schema_version": "measured-gpu-inventory.v1",
                    "devices": [
                        item.model_dump(mode="json")
                        for item in self.gpu_devices
                    ],
                    "nvidia_driver_version": self.nvidia_driver_version,
                    "cuda_driver_version": self.cuda_driver_version,
                    "cuda_runtime_version": self.cuda_runtime_version,
                    "nvidia_container_toolkit_version": (
                        self.nvidia_container_toolkit_version
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()


class CameraAnalyticScheduleV1(FrozenModel):
    """One named camera's approved schedule for a single conditional module."""

    camera_id: NonEmptyString
    analytics_hz: Annotated[float, Field(gt=0, le=2)]
    inferences_per_sample: Annotated[int, Field(ge=1, le=256)]


class FrozenReplayCameraFanoutV1(FrozenModel):
    """Measured per-sample inference fanout for one exact replay camera."""

    camera_id: NonEmptyString
    inferences_per_sample: Annotated[int, Field(ge=1, le=256)]


class FrozenReplayFanoutManifestV1(FrozenModel):
    """Exact replay/fanout evidence; it never contains stream credentials."""

    schema_version: Literal["frozen-replay-fanout-manifest.v1"]
    site_id: NonEmptyString
    module: Literal["fire_smoke", "weapon"]
    corpus_id: NonEmptyString
    corpus_sha256: str
    cameras: Annotated[
        tuple[FrozenReplayCameraFanoutV1, ...],
        Field(min_length=20, max_length=20),
    ]

    @model_validator(mode="after")
    def camera_identities_and_fanout_are_exact(self) -> FrozenReplayFanoutManifestV1:
        camera_ids = tuple(camera.camera_id for camera in self.cameras)
        if len(camera_ids) != len(set(camera_ids)):
            raise ValueError("frozen replay camera IDs must be unique")
        if self.module == "fire_smoke" and any(
            camera.inferences_per_sample != 1 for camera in self.cameras
        ):
            raise ValueError("fire replay must use one full-frame inference per sample")
        return self

    @field_validator("corpus_sha256")
    @classmethod
    def corpus_hash_is_a_digest(cls, value: str) -> str:
        return _digest(value, field_name="frozen replay corpus sha256")

    @property
    def manifest_sha256(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class AttestedFrozenReplayFanoutV1(FrozenModel):
    """Canonical manifest plus the digest signed by the capacity-test authority."""

    schema_version: Literal["attested-frozen-replay-fanout.v1"]
    manifest: FrozenReplayFanoutManifestV1
    manifest_sha256: str
    passed: bool
    report_reference: NonEmptyString
    report_sha256: str
    signed_by: NonEmptyString
    signed_at: datetime

    @field_validator("manifest_sha256", "report_sha256")
    @classmethod
    def manifest_hash_is_a_digest(cls, value: str) -> str:
        return _digest(value, field_name="frozen replay manifest sha256")

    @field_validator("report_reference")
    @classmethod
    def report_reference_is_credential_free(cls, value: str) -> str:
        return validate_credential_free_reference(value)

    @field_validator("signed_at")
    @classmethod
    def signing_time_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @model_validator(mode="after")
    def digest_matches_exact_manifest(self) -> AttestedFrozenReplayFanoutV1:
        if self.manifest_sha256 != self.manifest.manifest_sha256:
            raise ValueError("frozen replay manifest sha256 mismatch")
        if not self.passed:
            raise ValueError("frozen replay fanout attestation did not pass")
        return self


class ExpectedConditionalWorkloadV1(FrozenModel):
    """Canonical site-owned workload used independently of measured capacity."""

    schema_version: Literal["expected-conditional-workload.v1"]
    site_id: NonEmptyString
    module: Literal["fire_smoke", "weapon"]
    site_config_sha256: str
    frozen_workload_sha256: str
    cameras: Annotated[
        tuple[CameraAnalyticScheduleV1, ...],
        Field(min_length=20, max_length=20),
    ]

    @field_validator("site_config_sha256", "frozen_workload_sha256")
    @classmethod
    def hashes_are_digests(cls, value: str) -> str:
        return _digest(value, field_name="expected workload hash")

    @model_validator(mode="after")
    def camera_identities_are_unique(self) -> ExpectedConditionalWorkloadV1:
        camera_ids = tuple(camera.camera_id for camera in self.cameras)
        if len(camera_ids) != len(set(camera_ids)):
            raise ValueError("expected workload camera IDs must be unique")
        if self.module == "fire_smoke" and any(
            camera.inferences_per_sample != 1 for camera in self.cameras
        ):
            raise ValueError("fire workload must use one full-frame inference per sample")
        return self

    @property
    def required_throughput_hz(self) -> float:
        return sum(
            camera.analytics_hz * camera.inferences_per_sample
            for camera in self.cameras
        )

    @property
    def expected_workload_sha256(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def site_config_sha256(site_config: SiteConfig) -> str:
    """Hash the immutable non-secret configuration without resolving stream secrets."""

    encoded = json.dumps(
        site_config.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def derive_expected_conditional_workload(
    *,
    site_id: str,
    module: Literal["fire_smoke", "weapon"],
    site_config: SiteConfig,
    frozen_replay: AttestedFrozenReplayFanoutV1,
) -> ExpectedConditionalWorkloadV1:
    """Derive capacity demand from the exact site schedule and attested replay."""

    manifest = frozen_replay.manifest
    if manifest.site_id != site_id or manifest.module != module:
        raise ValueError("frozen replay site or module binding mismatch")
    feeds = site_config.ready_to_start.feeds
    configured_camera_ids = tuple(feed.camera_id for feed in feeds)
    fanout_by_camera = {
        camera.camera_id: camera.inferences_per_sample
        for camera in manifest.cameras
    }
    if set(fanout_by_camera) != set(configured_camera_ids):
        raise ValueError("frozen replay cameras do not match the site configuration")
    schedules: list[CameraAnalyticScheduleV1] = []
    for feed in feeds:
        analytics_hz = feed.analytics_hz.get(module)
        if analytics_hz is None or analytics_hz <= 0:
            raise ValueError(f"{module} schedule must be explicitly positive for every camera")
        schedules.append(
            CameraAnalyticScheduleV1(
                camera_id=feed.camera_id,
                analytics_hz=analytics_hz,
                inferences_per_sample=fanout_by_camera[feed.camera_id],
            )
        )
    return ExpectedConditionalWorkloadV1(
        schema_version="expected-conditional-workload.v1",
        site_id=site_id,
        module=module,
        site_config_sha256=site_config_sha256(site_config),
        frozen_workload_sha256=frozen_replay.manifest_sha256,
        cameras=tuple(schedules),
    )


class ConditionalArtifactEvidence(Protocol):
    """Structural registry input consumed by the single promotion-policy authority."""

    site_id: str
    module: str
    artifact_id: str
    source_uri: str | None
    artifact_sha256: str | None
    commercial_rights: Any
    classes: tuple[str, ...]
    preprocessing: str | None
    training_provenance: str | None
    evaluation_provenance: str | None
    thresholds: Any
    engine: Any
    registry_entry_sha256: str


class ModelGateResultV1(FrozenModel):
    """A pure, auditable promotion decision with human-readable evidence gaps."""

    schema_version: Literal["model-gate-result.v1"] = "model-gate-result.v1"
    mode: GateMode
    reasons: tuple[str, ...]
    promotion_path: tuple[GateMode, GateMode, GateMode] = ("disabled", "shadow", "operator")


class ConditionalModelGateResultV1(ModelGateResultV1):
    """Artifact-bound conditional decision consumed by the runtime scheduler."""

    schema_version: Literal["conditional-model-gate-result.v1"] = (
        "conditional-model-gate-result.v1"
    )
    site_id: NonEmptyString
    module: NonEmptyString
    artifact_id: NonEmptyString
    registry_entry_sha256: str

    @field_validator("registry_entry_sha256")
    @classmethod
    def registry_hash_is_a_digest(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value.lower()):
            raise ValueError("registry_entry_sha256 must be a 64-character hexadecimal digest")
        return value.lower()

    @property
    def decision_sha256(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class ModelGate:
    """Evaluate one model without mutating artifacts, reports, or runtime state."""

    @staticmethod
    def evaluate(
        artifact: ModelArtifactV1 | None,
        target_site_report: TargetSiteReportV1 | None,
        capacity_report: CapacityReportV1 | None,
        *,
        current_mode: GateMode = "disabled",
        shadow_stage_report: ShadowStageReportV1 | None = None,
    ) -> ModelGateResultV1:
        reasons: list[str] = []
        if current_mode not in {"disabled", "shadow", "operator"}:
            return ModelGateResultV1(mode="disabled", reasons=("invalid current gate mode",))
        if artifact is None:
            reasons.append("missing model artifact")
        else:
            if artifact.sha256 is None:
                reasons.append("missing sha256")
            if artifact.source is None:
                reasons.append("missing source")
            if artifact.commercial_rights is None:
                reasons.append("missing commercial rights")
            elif not artifact.commercial_rights.commercial_use_approved:
                reasons.append("commercial rights are not approved")
            if not artifact.class_list:
                reasons.append("missing class list")
            if artifact.preprocessing is None:
                reasons.append("missing preprocessing")

        artifact_id = artifact.artifact_id if artifact is not None else None
        if target_site_report is None:
            reasons.append("missing target-site report")
        elif artifact_id is not None and target_site_report.artifact_id != artifact_id:
            reasons.append("target-site report artifact does not match")
        elif not target_site_report.passed:
            reasons.append("target-site report did not pass")

        if capacity_report is None:
            reasons.append("missing 20-stream capacity report")
        elif artifact_id is not None and capacity_report.artifact_id != artifact_id:
            reasons.append("capacity report artifact does not match")
        else:
            if capacity_report.stream_count != 20:
                reasons.append("capacity report must cover exactly 20 streams")
            if not capacity_report.passed:
                reasons.append("capacity report did not pass")

        if reasons:
            return ModelGateResultV1(mode="disabled", reasons=tuple(reasons))
        assert artifact is not None
        if artifact.analytic in _SHADOW_ONLY_ANALYTICS:
            return ModelGateResultV1(
                mode="shadow",
                reasons=(f"{artifact.analytic} remains shadow-only for this pilot",),
            )
        if artifact.analytic not in _OPERATOR_ELIGIBLE_ANALYTICS:
            return ModelGateResultV1(
                mode="disabled",
                reasons=("analytic is not approved for operator promotion",),
            )
        if current_mode == "disabled":
            return ModelGateResultV1(
                mode="shadow",
                reasons=("successful shadow-stage report is required before operator promotion",),
            )
        if shadow_stage_report is None:
            return ModelGateResultV1(
                mode="shadow",
                reasons=("successful shadow-stage report is required before operator promotion",),
            )
        if shadow_stage_report.artifact_id != artifact.artifact_id:
            return ModelGateResultV1(
                mode="disabled",
                reasons=("shadow-stage report artifact does not match",),
            )
        if not shadow_stage_report.passed:
            return ModelGateResultV1(
                mode="disabled",
                reasons=("shadow-stage report did not pass",),
            )
        return ModelGateResultV1(mode="operator", reasons=())

    @staticmethod
    def conditional_artifact_reasons(
        artifact: ConditionalArtifactEvidence,
        *,
        actual_artifact_sha256: str | None = None,
        require_engine: bool = True,
    ) -> tuple[str, ...]:
        """Return every fail-closed registry gap used by audit, export, and promotion."""

        reasons: list[str] = []
        if not artifact.source_uri:
            reasons.append("missing source URI")
        if not artifact.artifact_sha256:
            reasons.append("missing artifact sha256")
        elif (
            actual_artifact_sha256 is not None
            and artifact.artifact_sha256.lower() != actual_artifact_sha256.lower()
        ):
            reasons.append("artifact sha256 mismatch")
        rights = artifact.commercial_rights
        if rights is None:
            reasons.append("missing commercial rights evidence")
        elif rights.status != "approved":
            reasons.append(f"commercial rights status is {rights.status}")
        elif not all(
            (
                rights.evidence_reference,
                rights.evidence_sha256,
                rights.approved_by,
                rights.approved_at,
            )
        ):
            reasons.append("approved commercial rights evidence is incomplete")
        if not artifact.classes:
            reasons.append("missing class list")
        if not artifact.preprocessing:
            reasons.append("missing preprocessing")
        if not artifact.training_provenance:
            reasons.append("missing training provenance")
        if not artifact.evaluation_provenance:
            reasons.append("missing evaluation provenance")
        if not artifact.thresholds:
            reasons.append("missing thresholds")
        if require_engine:
            engine = artifact.engine
            if engine is None or not engine.engine_sha256:
                reasons.append("missing engine sha256")
            elif not all(
                (
                    engine.tensorrt_version,
                    engine.target_gpu_architecture,
                    engine.target_compute_capability,
                    engine.precision,
                )
            ):
                reasons.append("engine target identity is incomplete")
            elif engine.precision == "int8" and not all(
                (
                    engine.calibration_corpus_sha256,
                    engine.no_regression_report_sha256,
                    engine.no_regression_candidate_engine_sha256
                    == engine.engine_sha256,
                )
            ):
                reasons.append("INT8 engine evidence is incomplete")
        return tuple(reasons)

    @staticmethod
    def evaluate_conditional(
        artifact: ConditionalArtifactEvidence,
        *,
        site_matrix: SignedSiteMatrixV1 | None,
        shadow_stage: ShadowStageEvidenceV1 | None,
        capacity_report: MeasuredCapacityReportV1 | None,
        site_config: SiteConfig | None,
        frozen_replay: AttestedFrozenReplayFanoutV1 | None,
    ) -> ConditionalModelGateResultV1:
        """Evaluate conditional analytics through one staged, evidence-bound policy."""

        def decision(
            mode: GateMode,
            reasons: tuple[str, ...],
        ) -> ConditionalModelGateResultV1:
            return ConditionalModelGateResultV1(
                site_id=artifact.site_id,
                module=artifact.module,
                artifact_id=artifact.artifact_id,
                registry_entry_sha256=artifact.registry_entry_sha256,
                mode=mode,
                reasons=reasons,
            )

        artifact_reasons = ModelGate.conditional_artifact_reasons(artifact)
        if artifact_reasons:
            return decision("disabled", artifact_reasons)
        assert artifact.artifact_sha256 is not None

        if artifact.module in {"fight", "fall"}:
            return decision(
                "shadow", (f"{artifact.module} is shadow-only for this pilot",)
            )
        if artifact.module not in {"fire_smoke", "weapon"}:
            return decision(
                "disabled", ("analytic is not approved for conditional promotion",)
            )
        expected_workload: ExpectedConditionalWorkloadV1 | None = None
        if site_config is not None and frozen_replay is not None:
            try:
                expected_workload = derive_expected_conditional_workload(
                    site_id=artifact.site_id,
                    module=artifact.module,
                    site_config=site_config,
                    frozen_replay=frozen_replay,
                )
            except ValueError as exc:
                return decision(
                    "disabled",
                    (f"configured site workload is invalid: {exc}",),
                )
        engine = artifact.engine
        if (
            engine is None
            or engine.target_gpu_architecture != PILOT_TARGET_GPU_ARCHITECTURE
            or engine.target_compute_capability != PILOT_TARGET_COMPUTE_CAPABILITY
            or engine.tensorrt_version != PILOT_TENSORRT_VERSION
        ):
            return decision(
                "disabled",
                ("engine does not match the exact NVIDIA L4 pilot target",),
            )

        if site_matrix is not None and (
            site_matrix.site_id != artifact.site_id
            or site_matrix.module != artifact.module
            or site_matrix.artifact_id != artifact.artifact_id
            or site_matrix.artifact_sha256 != artifact.artifact_sha256
            or site_matrix.registry_entry_sha256 != artifact.registry_entry_sha256
        ):
            return decision("disabled", ("site matrix binding mismatch",))
        if shadow_stage is not None and (
            shadow_stage.site_id != artifact.site_id
            or shadow_stage.artifact_id != artifact.artifact_id
            or shadow_stage.artifact_sha256 != artifact.artifact_sha256
            or shadow_stage.registry_entry_sha256 != artifact.registry_entry_sha256
        ):
            return decision("disabled", ("shadow-stage evidence binding mismatch",))
        if capacity_report is not None and (
            capacity_report.site_id != artifact.site_id
            or capacity_report.artifact_id != artifact.artifact_id
            or capacity_report.artifact_sha256 != artifact.artifact_sha256
            or capacity_report.registry_entry_sha256 != artifact.registry_entry_sha256
            or artifact.engine is None
            or capacity_report.engine_sha256 != artifact.engine.engine_sha256
            or capacity_report.precision != artifact.engine.precision
            or capacity_report.target_gpu_architecture
            != artifact.engine.target_gpu_architecture
            or capacity_report.target_compute_capability
            != artifact.engine.target_compute_capability
            or capacity_report.tensorrt_version != artifact.engine.tensorrt_version
        ):
            return decision("disabled", ("capacity report binding mismatch",))
        if (
            capacity_report is not None
            and expected_workload is not None
            and (
                capacity_report.site_config_sha256
                != expected_workload.site_config_sha256
                or capacity_report.frozen_workload_sha256
                != expected_workload.frozen_workload_sha256
                or capacity_report.expected_workload_sha256
                != expected_workload.expected_workload_sha256
            )
        ):
            return decision("disabled", ("capacity report workload binding mismatch",))

        reasons: list[str] = []
        if site_matrix is None:
            reasons.append("missing signed site matrix")
        else:
            scenes = (*site_matrix.positives, *site_matrix.hard_negatives)
            if not site_matrix.passed:
                reasons.append("signed site matrix did not pass")
            if any(scene.result != "pass" for scene in scenes):
                reasons.append("site matrix contains failing scenes")

        if shadow_stage is None:
            reasons.append("missing successful shadow-stage evidence")
        elif not shadow_stage.passed:
            reasons.append("shadow-stage evidence did not pass")

        if capacity_report is None:
            reasons.append("missing measured capacity report")
        elif site_config is None:
            reasons.append("missing immutable site configuration")
        elif frozen_replay is None:
            reasons.append("missing signed frozen replay fanout evidence")
        elif expected_workload is None:
            reasons.append("missing configured site workload")
        else:
            reasons.extend(
                ModelGate._capacity_reasons(
                    capacity_report,
                    expected_workload=expected_workload,
                )
            )

        if reasons:
            return decision("shadow", tuple(reasons))
        return decision("operator", ())

    @staticmethod
    def _capacity_reasons(
        report: MeasuredCapacityReportV1,
        *,
        expected_workload: ExpectedConditionalWorkloadV1,
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if not report.passed:
            reasons.append("measured capacity report did not pass")
        if report.stream_count != 20:
            reasons.append("capacity report must cover exactly 20 streams")
        if (
            abs(
                report.required_throughput_hz
                - expected_workload.required_throughput_hz
            )
            > 1e-9
        ):
            reasons.append(
                "capacity required throughput does not match configured site workload"
            )
        if report.effective_throughput_hz < report.required_throughput_hz * 1.25:
            reasons.append("measured throughput headroom is below 25%")
        if report.scheduled_drop_fraction >= 0.01:
            reasons.append("scheduled analysis drops must be below 1%")
        if report.queue_age_p95_seconds >= 1.0:
            reasons.append("queue age p95 must be below 1 second")
        if report.queue_age_p99_seconds >= 2.0:
            reasons.append("queue age p99 must be below 2 seconds")
        if report.gpu_utilization_max > 0.75:
            reasons.append("GPU utilization exceeds 75%")
        if report.vram_utilization_max > 0.80:
            reasons.append("VRAM utilization exceeds 80%")
        return tuple(reasons)
