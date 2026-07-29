"""Audited conditional-model registry and target-safe TensorRT build contracts."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Callable, Literal

import yaml
from pydantic import Field, ValidationError, field_serializer, field_validator

from protector.pilot.config import FrozenModel, NonEmptyString, SiteConfig
from protector.pilot.gates import (
    PILOT_TARGET_COMPUTE_CAPABILITY,
    PILOT_TARGET_GPU_ARCHITECTURE,
    PILOT_TENSORRT_VERSION,
    AttestedFrozenReplayFanoutV1,
    ConditionalModelGateResultV1,
    MeasuredCapacityReportV1,
    ModelGate,
    ShadowStageEvidenceV1,
    SignedSiteMatrixV1,
    SiteMatrixSceneV1,
    validate_credential_free_reference,
)

_HEX = frozenset("0123456789abcdef")
_L4_ARCHITECTURE = PILOT_TARGET_GPU_ARCHITECTURE
_L4_COMPUTE_CAPABILITY = PILOT_TARGET_COMPUTE_CAPABILITY
_DEEPSTREAM_91_TENSORRT = PILOT_TENSORRT_VERSION


def _digest(value: str, *, field_name: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(character not in _HEX for character in normalized):
        raise ValueError(f"{field_name} must be a 64-character hexadecimal digest")
    return normalized


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be UTC-aware")
    return value.astimezone(timezone.utc)


class CommercialRightsEvidenceV1(FrozenModel):
    """Explicit legal decision and its immutable evidence, never an inferred licence label."""

    schema_version: Literal["commercial-rights-evidence.v1"]
    status: Literal["approved", "rejected", "unknown", "ambiguous"]
    evidence_reference: NonEmptyString | None = None
    evidence_sha256: str | None = None
    approved_by: NonEmptyString | None = None
    approved_at: datetime | None = None

    @field_validator("evidence_sha256")
    @classmethod
    def evidence_hash_is_a_digest(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value, field_name="evidence_sha256")

    @field_validator("approved_at")
    @classmethod
    def approval_time_is_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value, field_name="approved_at")

    @field_validator("evidence_reference")
    @classmethod
    def evidence_reference_is_credential_free(cls, value: str | None) -> str | None:
        return None if value is None else validate_credential_free_reference(value)


class EngineRecordV1(FrozenModel):
    """Configured target identity and exact built bytes; it is not host/capacity attestation."""

    schema_version: Literal["engine-record.v1"]
    engine_sha256: str | None = None
    tensorrt_version: NonEmptyString | None = None
    target_gpu_architecture: NonEmptyString | None = None
    target_compute_capability: NonEmptyString | None = None
    precision: Literal["fp16", "int8"] | None = None
    calibration_corpus_sha256: str | None = None
    no_regression_report_sha256: str | None = None
    no_regression_candidate_engine_sha256: str | None = None

    @field_validator(
        "engine_sha256",
        "calibration_corpus_sha256",
        "no_regression_report_sha256",
        "no_regression_candidate_engine_sha256",
    )
    @classmethod
    def engine_hash_is_a_digest(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value, field_name="engine_sha256")


class ModelRegistryEntryV1(FrozenModel):
    """One exact conditional artifact and all evidence needed to audit its identity."""

    schema_version: Literal["model-registry-entry.v1"]
    site_id: NonEmptyString
    module: Literal["fire_smoke", "weapon", "fight", "fall"]
    artifact_id: NonEmptyString
    source_uri: NonEmptyString | None = None
    artifact_sha256: str | None = None
    commercial_rights: CommercialRightsEvidenceV1 | None = None
    classes: tuple[NonEmptyString, ...] = ()
    preprocessing: NonEmptyString | None = None
    training_provenance: NonEmptyString | None = None
    evaluation_provenance: NonEmptyString | None = None
    thresholds: Mapping[NonEmptyString, Annotated[float, Field(ge=0, le=1)]] = Field(
        default_factory=dict
    )
    engine: EngineRecordV1 | None = None

    @field_validator("artifact_sha256")
    @classmethod
    def artifact_hash_is_a_digest(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value, field_name="artifact_sha256")

    @field_validator(
        "source_uri",
        "training_provenance",
        "evaluation_provenance",
    )
    @classmethod
    def references_are_credential_free(cls, value: str | None) -> str | None:
        return None if value is None else validate_credential_free_reference(value)

    @field_validator("classes")
    @classmethod
    def classes_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("classes must be unique")
        return values

    @field_validator("thresholds")
    @classmethod
    def freeze_thresholds(cls, values: Mapping[str, float]) -> Mapping[str, float]:
        return MappingProxyType(dict(values))

    @field_serializer("thresholds")
    def serialize_thresholds(self, values: Mapping[str, float]) -> dict[str, float]:
        return dict(values)

    @property
    def registry_entry_sha256(self) -> str:
        """Canonical identity binding thresholds, preprocessing, artifact, and engine."""

        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class ModelAuditResultV1(FrozenModel):
    schema_version: Literal["model-audit-result.v1"] = "model-audit-result.v1"
    approved_for_export: bool
    approved_for_deployment: bool
    reasons: tuple[str, ...]
    export_reasons: tuple[str, ...]
    deployment_reasons: tuple[str, ...]
    record: Mapping[str, Any]

    @field_validator("record")
    @classmethod
    def freeze_record(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return MappingProxyType(dict(value))

    @field_serializer("record")
    def serialize_record(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return dict(value)


class CalibrationCorpusV1(FrozenModel):
    schema_version: Literal["calibration-corpus.v1"]
    corpus_id: NonEmptyString
    version: NonEmptyString
    sha256: str
    reference: NonEmptyString

    @field_validator("sha256")
    @classmethod
    def corpus_hash_is_a_digest(cls, value: str) -> str:
        return _digest(value, field_name="calibration corpus sha256")

    @field_validator("reference")
    @classmethod
    def reference_is_credential_free(cls, value: str) -> str:
        return validate_credential_free_reference(value)


class NoRegressionEventReportV1(FrozenModel):
    schema_version: Literal["no-regression-event-report.v1"]
    artifact_id: NonEmptyString
    artifact_sha256: str
    registry_entry_sha256: str
    candidate_engine_sha256: str
    precision: Literal["int8"]
    target_gpu_architecture: NonEmptyString
    target_compute_capability: NonEmptyString
    tensorrt_version: NonEmptyString
    calibration_corpus_id: NonEmptyString
    calibration_corpus_version: NonEmptyString
    calibration_corpus_sha256: str
    passed: bool
    report_reference: NonEmptyString
    report_sha256: str
    signed_by: NonEmptyString
    signed_at: datetime

    @field_validator(
        "artifact_sha256",
        "registry_entry_sha256",
        "candidate_engine_sha256",
        "calibration_corpus_sha256",
        "report_sha256",
    )
    @classmethod
    def hashes_are_digests(cls, value: str) -> str:
        return _digest(value, field_name="INT8 evidence hash")

    @field_validator("signed_at")
    @classmethod
    def signature_time_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, field_name="signed_at")

    @field_validator("report_reference")
    @classmethod
    def report_reference_is_credential_free(cls, value: str) -> str:
        return validate_credential_free_reference(value)


class EngineBuildSpecV1(FrozenModel):
    """Configured target request. A later signed capacity report attests the real host."""

    schema_version: Literal["engine-build-spec.v1"] = "engine-build-spec.v1"
    precision: Literal["fp16", "int8"] = "fp16"
    target_gpu_architecture: Literal["NVIDIA L4 (Ada)"] = _L4_ARCHITECTURE
    target_compute_capability: Literal["8.9"] = _L4_COMPUTE_CAPABILITY
    tensorrt_version: Literal["10.16.0.72"] = _DEEPSTREAM_91_TENSORRT
    calibration_corpus: CalibrationCorpusV1 | None = None
    no_regression_report: NoRegressionEventReportV1 | None = None


class TargetRuntimeIdentityV1(FrozenModel):
    """Measured compatibility identity; it is not signed capacity attestation."""

    target_gpu_architecture: NonEmptyString
    target_compute_capability: NonEmptyString
    tensorrt_version: NonEmptyString
    tensorrt_runtime_version: NonEmptyString
    raw_tensorrt_banner: NonEmptyString


class EngineBuildResultV1(FrozenModel):
    schema_version: Literal["engine-build-result.v1"] = "engine-build-result.v1"
    artifact_id: NonEmptyString
    artifact_sha256: str
    registry_entry_sha256: str
    engine_sha256: str
    precision: Literal["fp16", "int8"]
    target_gpu_architecture: Literal["NVIDIA L4 (Ada)"]
    target_compute_capability: Literal["8.9"]
    tensorrt_version: Literal["10.16.0.72"]
    observed_tensorrt_runtime_version: NonEmptyString
    raw_tensorrt_banner: NonEmptyString
    target_host_attested: Literal[False] = False
    capacity_attested: Literal[False] = False
    argv: tuple[str, ...]
    exporter_output: str
    registry_record: Mapping[str, Any]
    calibration_corpus_sha256: str | None = None
    no_regression_report_sha256: str | None = None

    @field_validator("artifact_sha256", "registry_entry_sha256", "engine_sha256")
    @classmethod
    def hashes_are_digests(cls, value: str) -> str:
        return _digest(value, field_name="build result hash")

    @field_validator("registry_record")
    @classmethod
    def freeze_registry_record(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return MappingProxyType(dict(value))

    @field_serializer("registry_record")
    def serialize_registry_record(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return dict(value)


class EngineBuildIntentV1(FrozenModel):
    """Durable non-deployable ownership record for one interrupted build."""

    schema_version: Literal["engine-build-intent.v1"] = "engine-build-intent.v1"
    artifact_id: NonEmptyString
    artifact_sha256: str
    registry_entry_sha256: str
    precision: Literal["fp16", "int8"]
    target_gpu_architecture: Literal["NVIDIA L4 (Ada)"]
    target_compute_capability: Literal["8.9"]
    tensorrt_version: Literal["10.16.0.72"]
    observed_tensorrt_runtime_version: NonEmptyString
    engine_path: NonEmptyString
    receipt_path: NonEmptyString
    commit_path: NonEmptyString
    intent_path: NonEmptyString

    @field_validator("artifact_sha256", "registry_entry_sha256")
    @classmethod
    def hashes_are_digests(cls, value: str) -> str:
        return _digest(value, field_name="build intent hash")


class EngineBuildCommitV1(FrozenModel):
    """Final marker published only after exact engine and receipt are durable."""

    schema_version: Literal["engine-build-commit.v1"] = "engine-build-commit.v1"
    artifact_id: NonEmptyString
    artifact_sha256: str
    registry_entry_sha256: str
    engine_sha256: str
    receipt_sha256: str
    precision: Literal["fp16", "int8"]
    target_gpu_architecture: Literal["NVIDIA L4 (Ada)"]
    target_compute_capability: Literal["8.9"]
    tensorrt_version: Literal["10.16.0.72"]
    observed_tensorrt_runtime_version: NonEmptyString
    engine_path: NonEmptyString
    receipt_path: NonEmptyString
    commit_path: NonEmptyString
    intent_path: NonEmptyString

    @field_validator(
        "artifact_sha256",
        "registry_entry_sha256",
        "engine_sha256",
        "receipt_sha256",
    )
    @classmethod
    def hashes_are_digests(cls, value: str) -> str:
        return _digest(value, field_name="build commit hash")


class EngineBuildError(RuntimeError):
    """A preflight or target-export failure that never publishes partial engine bytes."""


def load_model_entry(path: Path) -> ModelRegistryEntryV1:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"unable to read model registry entry: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("model registry entry must be a YAML mapping")
    return ModelRegistryEntryV1.model_validate(payload)


def _audit_record(entry: ModelRegistryEntryV1) -> dict[str, Any]:
    rights = entry.commercial_rights
    rights_record: dict[str, Any] | None = None
    if rights is not None:
        rights_record = {
            "status": rights.status,
            "evidence_reference": rights.evidence_reference,
            "evidence_sha256": rights.evidence_sha256,
            "approved_by": rights.approved_by,
            "approved_at": (
                rights.approved_at.isoformat().replace("+00:00", "Z")
                if rights.approved_at is not None
                else None
            ),
        }
        rights_record = {key: value for key, value in rights_record.items() if value is not None}
    return {
        "artifact_id": entry.artifact_id,
        "artifact_sha256": entry.artifact_sha256,
        "classes": list(entry.classes),
        "commercial_rights_evidence": rights_record,
        "evaluation_provenance": entry.evaluation_provenance,
        "engine": (
            entry.engine.model_dump(mode="json", exclude_none=True)
            if entry.engine is not None
            else None
        ),
        "module": entry.module,
        "preprocessing": entry.preprocessing,
        "registry_entry_sha256": entry.registry_entry_sha256,
        "site_id": entry.site_id,
        "source_uri": entry.source_uri,
        "thresholds": dict(entry.thresholds),
        "training_provenance": entry.training_provenance,
    }


def audit_model_entry(
    entry: ModelRegistryEntryV1,
    artifact_path: Path | None,
    *,
    engine_path: Path | None = None,
    receipt_path: Path | None = None,
) -> ModelAuditResultV1:
    actual_digest: str | None = None
    path_reason: str | None = None
    if artifact_path is None:
        path_reason = "artifact file is required for hash audit"
    else:
        if not os.path.lexists(artifact_path):
            path_reason = "artifact file is missing"
        else:
            try:
                actual_digest = _sha256_file(artifact_path)
            except (OSError, ValueError):
                path_reason = "artifact file must be an available regular file"
    export_reasons = list(
        ModelGate.conditional_artifact_reasons(
            entry,
            actual_artifact_sha256=actual_digest,
            require_engine=False,
        )
    )
    deployment_reasons = list(
        ModelGate.conditional_artifact_reasons(
            entry,
            actual_artifact_sha256=actual_digest,
            require_engine=True,
        )
    )
    if entry.engine is not None and (
        entry.engine.target_gpu_architecture != PILOT_TARGET_GPU_ARCHITECTURE
        or entry.engine.target_compute_capability
        != PILOT_TARGET_COMPUTE_CAPABILITY
        or entry.engine.tensorrt_version != PILOT_TENSORRT_VERSION
    ):
        deployment_reasons.append(
            "engine does not match the exact NVIDIA L4 pilot target"
        )
    if path_reason is not None:
        export_reasons.append(path_reason)
        deployment_reasons.append(path_reason)
    if entry.engine is not None and entry.engine.engine_sha256 is not None:
        if engine_path is None:
            deployment_reasons.append("engine file is required for deployment audit")
        elif not os.path.lexists(engine_path):
            deployment_reasons.append("engine file is missing")
        else:
            try:
                engine_sha256 = _sha256_file(engine_path)
            except (OSError, ValueError):
                deployment_reasons.append(
                    "engine file must be an available regular file"
                )
            else:
                if engine_sha256 != entry.engine.engine_sha256:
                    deployment_reasons.append("engine sha256 mismatch")
                else:
                    deployment_reasons.extend(
                        _engine_publication_audit_reasons(
                            entry,
                            engine_path=engine_path,
                            receipt_path=receipt_path,
                        )
                    )
    return ModelAuditResultV1(
        approved_for_export=not export_reasons,
        approved_for_deployment=not deployment_reasons,
        reasons=tuple(deployment_reasons),
        export_reasons=tuple(export_reasons),
        deployment_reasons=tuple(deployment_reasons),
        record=_audit_record(entry),
    )


def _publication_paths(
    engine_path: Path,
    receipt_path: Path | None = None,
) -> tuple[Path, Path, Path, Path]:
    receipt = receipt_path or engine_path.with_suffix(
        engine_path.suffix + ".build.json"
    )
    commit = engine_path.with_suffix(engine_path.suffix + ".commit.json")
    intent = engine_path.with_suffix(engine_path.suffix + ".intent.json")
    lock = engine_path.with_suffix(engine_path.suffix + ".lock")
    return receipt, commit, intent, lock


def _publication_destination(path: Path) -> Path:
    """Resolve the parent but never follow an untrusted final directory entry."""

    return path.parent.resolve() / path.name


def _engine_publication_audit_reasons(
    entry: ModelRegistryEntryV1,
    *,
    engine_path: Path,
    receipt_path: Path | None,
) -> tuple[str, ...]:
    receipt, commit, intent, _ = _publication_paths(engine_path, receipt_path)
    if os.path.lexists(intent):
        return ("unfinished build intent",)
    reasons: list[str] = []
    if not receipt.is_file():
        reasons.append("exact engine build receipt is missing")
    if not commit.is_file():
        reasons.append("final engine build commit marker is missing")
    if reasons:
        return tuple(reasons)
    try:
        receipt_bytes, receipt_payload = _read_bounded_json(
            receipt,
            max_bytes=2_000_000,
        )
        receipt_record = EngineBuildResultV1.model_validate(receipt_payload)
    except (OSError, ValueError, ValidationError):
        return ("exact engine build receipt is invalid",)
    try:
        _, commit_payload = _read_bounded_json(commit, max_bytes=65_536)
        commit_record = EngineBuildCommitV1.model_validate(commit_payload)
    except (OSError, ValueError, ValidationError):
        return ("final engine build commit marker is invalid",)

    engine = entry.engine
    assert engine is not None and engine.engine_sha256 is not None
    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    expected = {
        "artifact_id": entry.artifact_id,
        "artifact_sha256": entry.artifact_sha256,
        "registry_entry_sha256": entry.registry_entry_sha256,
        "engine_sha256": engine.engine_sha256,
        "precision": engine.precision,
        "target_gpu_architecture": engine.target_gpu_architecture,
        "target_compute_capability": engine.target_compute_capability,
        "tensorrt_version": engine.tensorrt_version,
    }
    receipt_values = {
        key: getattr(receipt_record, key)
        for key in expected
    }
    commit_values = {
        key: getattr(commit_record, key)
        for key in expected
    }
    if receipt_values != expected or commit_values != expected:
        reasons.append("engine receipt or commit binding mismatch")
    if commit_record.receipt_sha256 != receipt_sha256:
        reasons.append("engine receipt sha256 does not match commit marker")
    if (
        commit_record.observed_tensorrt_runtime_version
        != receipt_record.observed_tensorrt_runtime_version
    ):
        reasons.append("engine target runtime identity does not match receipt")
    if commit_record.engine_path != str(_publication_destination(engine_path)):
        reasons.append("engine path does not match commit marker")
    if commit_record.receipt_path != str(_publication_destination(receipt)):
        reasons.append("receipt path does not match commit marker")
    if commit_record.commit_path != str(_publication_destination(commit)):
        reasons.append("commit path does not match commit marker")
    if commit_record.intent_path != str(_publication_destination(intent)):
        reasons.append("intent path does not match commit marker")
    return tuple(reasons)


def evaluate_conditional_promotion(
    entry: ModelRegistryEntryV1,
    *,
    site_matrix: SignedSiteMatrixV1 | None,
    shadow_stage: ShadowStageEvidenceV1 | None,
    capacity_report: MeasuredCapacityReportV1 | None,
    site_config: SiteConfig | None,
    frozen_replay: AttestedFrozenReplayFanoutV1 | None,
) -> ConditionalModelGateResultV1:
    """Thin registry wrapper around the single policy authority in ``gates.py``."""

    return ModelGate.evaluate_conditional(
        entry,
        site_matrix=site_matrix,
        shadow_stage=shadow_stage,
        capacity_report=capacity_report,
        site_config=site_config,
        frozen_replay=frozen_replay,
    )


def _validate_build_binding(
    entry: ModelRegistryEntryV1,
    spec: EngineBuildSpecV1,
) -> None:
    engine = entry.engine
    if engine is None:
        raise EngineBuildError("registry engine target is required before export")
    if engine.precision != spec.precision:
        raise EngineBuildError("registry precision does not match build specification")
    if (
        engine.target_gpu_architecture != spec.target_gpu_architecture
        or engine.target_compute_capability != spec.target_compute_capability
        or engine.tensorrt_version != spec.tensorrt_version
    ):
        raise EngineBuildError("registry target identity does not match build specification")


def _validate_int8_evidence(
    entry: ModelRegistryEntryV1,
    spec: EngineBuildSpecV1,
) -> None:
    if spec.precision != "int8":
        return
    corpus = spec.calibration_corpus
    report = spec.no_regression_report
    if corpus is None:
        raise EngineBuildError("INT8 requires a versioned calibration corpus")
    if report is None:
        raise EngineBuildError("INT8 requires an exact no-regression event report")
    if not report.passed:
        raise EngineBuildError("INT8 no-regression event report did not pass")
    if (
        report.artifact_id != entry.artifact_id
        or report.artifact_sha256 != entry.artifact_sha256
        or report.registry_entry_sha256 != entry.registry_entry_sha256
        or report.precision != spec.precision
        or report.target_gpu_architecture != spec.target_gpu_architecture
        or report.target_compute_capability != spec.target_compute_capability
        or report.tensorrt_version != spec.tensorrt_version
        or report.calibration_corpus_id != corpus.corpus_id
        or report.calibration_corpus_version != corpus.version
        or report.calibration_corpus_sha256 != corpus.sha256
        or entry.engine is None
        or entry.engine.calibration_corpus_sha256 != corpus.sha256
        or entry.engine.no_regression_report_sha256 != report.report_sha256
        or entry.engine.no_regression_candidate_engine_sha256
        != report.candidate_engine_sha256
        or entry.engine.engine_sha256 != report.candidate_engine_sha256
    ):
        raise EngineBuildError(
            "INT8 evidence does not match artifact, registry identity, and calibration corpus"
        )


def build_engine(
    entry: ModelRegistryEntryV1,
    *,
    artifact_path: Path,
    output_path: Path,
    receipt_path: Path | None = None,
    build_spec: EngineBuildSpecV1,
    trtexec_path: Path,
    calibration_path: Path | None = None,
    runtime_probe: Callable[[Path], TargetRuntimeIdentityV1] | None = None,
    timeout_seconds: float = 1_800,
    max_output_bytes: int = 1_000_000,
    max_engine_bytes: int = 2_000_000_000,
) -> EngineBuildResultV1:
    """Build an atomic candidate engine after rights/hash preflight.

    The returned target fields describe the configured build target only. They
    deliberately remain unattested until a signed frozen-workload report passes
    the central promotion gate.
    """

    preflight_reasons = ModelGate.conditional_artifact_reasons(
        entry,
        require_engine=False,
    )
    if preflight_reasons:
        raise EngineBuildError("; ".join(preflight_reasons))
    _validate_build_binding(entry, build_spec)
    _validate_int8_evidence(entry, build_spec)
    if timeout_seconds <= 0:
        raise EngineBuildError("export timeout must be positive")
    if max_output_bytes <= 0:
        raise EngineBuildError("export output limit must be positive")
    if max_engine_bytes <= 0:
        raise EngineBuildError("engine byte limit must be positive")
    with tempfile.TemporaryDirectory(prefix=".model-inputs-") as input_staging:
        staged_artifact = Path(input_staging) / "attested-model.onnx"
        actual_artifact_sha256, _ = _stage_attested_file(
            artifact_path,
            staged_artifact,
            label="model artifact",
        )
        if actual_artifact_sha256 != entry.artifact_sha256:
            raise EngineBuildError("artifact sha256 mismatch")

        staged_calibration: Path | None = None
        if build_spec.precision == "int8":
            if calibration_path is None:
                raise EngineBuildError(
                    "INT8 requires exact local calibration cache bytes"
                )
            assert build_spec.calibration_corpus is not None
            staged_calibration = Path(input_staging) / "attested-calibration.cache"
            calibration_sha256, _ = _stage_attested_file(
                calibration_path,
                staged_calibration,
                label="calibration cache",
            )
            if calibration_sha256 != build_spec.calibration_corpus.sha256:
                raise EngineBuildError("calibration cache sha256 mismatch")

        if not trtexec_path.is_file() or not os.access(trtexec_path, os.X_OK):
            raise EngineBuildError("TensorRT trtexec executable is unavailable")
        measured_runtime = (
            probe_target_runtime(trtexec_path)
            if runtime_probe is None
            else runtime_probe(trtexec_path)
        )
        _require_target_compatibility(build_spec, measured_runtime)
        receipt, commit, intent, lock = _publication_paths(output_path, receipt_path)
        resolved_publication_paths = {
            _publication_destination(output_path),
            _publication_destination(receipt),
            _publication_destination(commit),
            _publication_destination(intent),
            _publication_destination(lock),
        }
        if len(resolved_publication_paths) != 5:
            raise EngineBuildError("engine publication paths must be distinct")
        if receipt.parent.resolve() != output_path.parent.resolve():
            raise EngineBuildError("engine receipt must share the engine directory")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        assert entry.artifact_sha256 is not None
        intent_record = EngineBuildIntentV1(
            artifact_id=entry.artifact_id,
            artifact_sha256=entry.artifact_sha256,
            registry_entry_sha256=entry.registry_entry_sha256,
            precision=build_spec.precision,
            target_gpu_architecture=build_spec.target_gpu_architecture,
            target_compute_capability=build_spec.target_compute_capability,
            tensorrt_version=build_spec.tensorrt_version,
            observed_tensorrt_runtime_version=(
                measured_runtime.tensorrt_runtime_version
            ),
            engine_path=str(_publication_destination(output_path)),
            receipt_path=str(_publication_destination(receipt)),
            commit_path=str(_publication_destination(commit)),
            intent_path=str(_publication_destination(intent)),
        )
        lock_descriptor = _acquire_publication_lock(lock)
        try:
            recovered = _prepare_build_intent(
                intent_record,
                engine_path=output_path,
                receipt_path=receipt,
                commit_path=commit,
                intent_path=intent,
            )
        except BaseException:
            _release_publication_lock(lock_descriptor)
            raise
        if recovered is not None:
            _release_publication_lock(lock_descriptor)
            return recovered
        published: list[Path] = []
        try:
            with tempfile.TemporaryDirectory(
                prefix=".engine-build-",
                dir=output_path.parent,
            ) as temporary:
                temporary_directory = Path(temporary)
                temporary_engine = temporary_directory / "exporter-output.engine"
                private_publication = temporary_directory / "publication.engine"
                argv = [
                    str(trtexec_path),
                    f"--onnx={staged_artifact}",
                    f"--saveEngine={temporary_engine}",
                    "--skipInference",
                    "--fp16" if build_spec.precision == "fp16" else "--int8",
                ]
                if staged_calibration is not None:
                    argv.append(f"--calib={staged_calibration}")
                launch_argv = [
                    sys.executable,
                    "-m",
                    "protector.pilot.runtime._limit_exec",
                    str(max_engine_bytes + 1),
                    "--",
                    *argv,
                ]
                return_code, exporter_output = _run_bounded(
                    launch_argv,
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                )
                try:
                    exporter_output_stat = os.lstat(temporary_engine)
                except FileNotFoundError:
                    exporter_output_stat = None
                if (
                    exporter_output_stat is not None
                    and stat.S_ISREG(exporter_output_stat.st_mode)
                    and exporter_output_stat.st_size > max_engine_bytes
                ):
                    raise EngineBuildError(
                        "TensorRT exporter exceeded engine byte limit"
                    )
                if return_code != 0:
                    raise EngineBuildError(
                        f"TensorRT exporter exited with status {return_code}"
                    )
                if not os.path.lexists(temporary_engine):
                    raise EngineBuildError(
                        "TensorRT exporter did not produce an engine"
                    )
                engine_sha256, engine_size = _stage_attested_file(
                    temporary_engine,
                    private_publication,
                    label="TensorRT exporter output",
                    max_bytes=max_engine_bytes,
                )
                if engine_size <= 0:
                    raise EngineBuildError(
                        "TensorRT exporter did not produce an engine"
                    )
                if (
                    entry.engine is None
                    or entry.engine.engine_sha256 != engine_sha256
                ):
                    raise EngineBuildError(
                        "candidate engine sha256 does not match the registry entry"
                    )
                if (
                    build_spec.precision == "int8"
                    and build_spec.no_regression_report is not None
                    and build_spec.no_regression_report.candidate_engine_sha256
                    != engine_sha256
                ):
                    raise EngineBuildError(
                        "INT8 candidate engine does not match the no-regression event report"
                    )
                os.chmod(private_publication, 0o444)

                result = EngineBuildResultV1(
                    artifact_id=entry.artifact_id,
                    artifact_sha256=entry.artifact_sha256,
                    registry_entry_sha256=entry.registry_entry_sha256,
                    engine_sha256=engine_sha256,
                    precision=build_spec.precision,
                    target_gpu_architecture=build_spec.target_gpu_architecture,
                    target_compute_capability=build_spec.target_compute_capability,
                    tensorrt_version=build_spec.tensorrt_version,
                    observed_tensorrt_runtime_version=(
                        measured_runtime.tensorrt_runtime_version
                    ),
                    raw_tensorrt_banner=measured_runtime.raw_tensorrt_banner,
                    argv=tuple(argv),
                    exporter_output=exporter_output,
                    registry_record=_audit_record(entry),
                    calibration_corpus_sha256=(
                        build_spec.calibration_corpus.sha256
                        if build_spec.calibration_corpus is not None
                        else None
                    ),
                    no_regression_report_sha256=(
                        build_spec.no_regression_report.report_sha256
                        if build_spec.no_regression_report is not None
                        else None
                    ),
                )
                private_receipt = temporary_directory / "publication-receipt.json"
                try:
                    receipt_sha256 = _stage_json_file(
                        private_receipt,
                        result.model_dump(mode="json"),
                        max_bytes=2_000_000,
                    )
                except OSError as exc:
                    raise EngineBuildError("engine build receipt staging failed") from exc
                commit_record = EngineBuildCommitV1(
                    artifact_id=entry.artifact_id,
                    artifact_sha256=entry.artifact_sha256,
                    registry_entry_sha256=entry.registry_entry_sha256,
                    engine_sha256=engine_sha256,
                    receipt_sha256=receipt_sha256,
                    precision=build_spec.precision,
                    target_gpu_architecture=build_spec.target_gpu_architecture,
                    target_compute_capability=build_spec.target_compute_capability,
                    tensorrt_version=build_spec.tensorrt_version,
                    observed_tensorrt_runtime_version=(
                        measured_runtime.tensorrt_runtime_version
                    ),
                    engine_path=str(_publication_destination(output_path)),
                    receipt_path=str(_publication_destination(receipt)),
                    commit_path=str(_publication_destination(commit)),
                    intent_path=str(_publication_destination(intent)),
                )
                private_commit = temporary_directory / "publication-commit.json"
                _stage_json_file(
                    private_commit,
                    commit_record.model_dump(mode="json"),
                    max_bytes=65_536,
                )
                os.chmod(private_receipt, 0o444)
                os.chmod(private_commit, 0o444)

                for source, destination in (
                    (private_publication, output_path),
                    (private_receipt, receipt),
                ):
                    _publish_build_product(source, destination)
                    published.append(destination)
                _fsync_directory(output_path.parent)
                _publish_build_product(private_commit, commit)
                published.append(commit)
                _fsync_directory(output_path.parent)
                intent.unlink()
                _fsync_directory(output_path.parent)
                return result
        except Exception as exc:
            try:
                _cleanup_failed_build(
                    published=published,
                    intent_path=intent,
                    directory=output_path.parent,
                )
            except OSError as cleanup_exc:
                raise EngineBuildError(
                    "engine build failed; durable non-deployable intent retained"
                ) from cleanup_exc
            if isinstance(exc, EngineBuildError):
                raise
            raise EngineBuildError("engine build publication failed") from exc
        finally:
            _release_publication_lock(lock_descriptor)


def _stage_attested_file(
    source: Path,
    destination: Path,
    *,
    label: str,
    max_bytes: int | None = None,
) -> tuple[str, int]:
    """Copy one opened regular inode into a private file while hashing its bytes."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source, flags)
    except OSError as exc:
        raise EngineBuildError(f"{label} must be an available regular file") from exc
    try:
        source_stat = os.fstat(source_descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            raise EngineBuildError(f"{label} must be an available regular file")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        digest = hashlib.sha256()
        copied = 0
        try:
            while chunk := os.read(source_descriptor, 1_048_576):
                copied += len(chunk)
                if max_bytes is not None and copied > max_bytes:
                    raise EngineBuildError(
                        "TensorRT exporter exceeded engine byte limit"
                    )
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    view = view[written:]
            os.fsync(destination_descriptor)
        except BaseException:
            os.close(destination_descriptor)
            destination.unlink(missing_ok=True)
            raise
        else:
            os.close(destination_descriptor)
        return digest.hexdigest(), copied
    finally:
        os.close(source_descriptor)


def _stage_json_file(path: Path, payload: Any, *, max_bytes: int) -> str:
    """Create and fsync one bounded private JSON file, returning exact digest."""

    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise EngineBuildError("machine-readable build record exceeded byte limit")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    return hashlib.sha256(encoded).hexdigest()


def _read_bounded_json(path: Path, *, max_bytes: int) -> tuple[bytes, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > max_bytes:
            raise ValueError("build record is not a bounded regular file")
        chunks: list[bytes] = []
        read = 0
        while chunk := os.read(descriptor, 65_536):
            read += len(chunk)
            if read > max_bytes:
                raise ValueError("build record exceeds byte limit")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    encoded = b"".join(chunks)
    payload = json.loads(encoded)
    if not isinstance(payload, dict):
        raise ValueError("build record must be a JSON mapping")
    return encoded, payload


def _acquire_publication_lock(path: Path) -> int:
    """Own one crash-released publication lock without following path aliases."""

    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise EngineBuildError(
            "engine publication lock must be an available regular file"
        ) from exc
    try:
        lock_stat = os.fstat(descriptor)
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_size > 4_096:
            raise EngineBuildError(
                "engine publication lock must be a bounded regular file"
            )
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise EngineBuildError(
                    "engine publication already in progress"
                ) from exc
            raise EngineBuildError("engine publication lock is unavailable") from exc
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _release_publication_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _publish_build_product(source: Path, destination: Path) -> None:
    """No-clobber hard-link publication; callers own durability and cleanup."""

    try:
        os.link(source, destination)
    except FileExistsError as exc:
        raise EngineBuildError("concurrent engine publication refused") from exc


def _prepare_build_intent(
    record: EngineBuildIntentV1,
    *,
    engine_path: Path,
    receipt_path: Path,
    commit_path: Path,
    intent_path: Path,
) -> EngineBuildResultV1 | None:
    """Recover an exact interrupted state, then durably claim destinations."""

    if os.path.lexists(intent_path):
        try:
            _, payload = _read_bounded_json(intent_path, max_bytes=65_536)
            existing = EngineBuildIntentV1.model_validate(payload)
        except (OSError, ValueError, ValidationError) as exc:
            raise EngineBuildError(
                "existing build intent is invalid and requires quarantine"
            ) from exc
        if existing != record:
            raise EngineBuildError("existing build intent belongs to another build")
        if os.path.lexists(commit_path):
            recovered = _recover_committed_build(
                intent=record,
                engine_path=engine_path,
                receipt_path=receipt_path,
                commit_path=commit_path,
            )
            try:
                intent_path.unlink()
                _fsync_directory(engine_path.parent)
            except OSError as exc:
                raise EngineBuildError(
                    "committed build recovery could not clear durable intent"
                ) from exc
            return recovered
        try:
            engine_path.unlink(missing_ok=True)
            receipt_path.unlink(missing_ok=True)
            _fsync_directory(engine_path.parent)
            intent_path.unlink()
            _fsync_directory(engine_path.parent)
        except OSError as exc:
            raise EngineBuildError(
                "interrupted build recovery failed; non-deployable intent retained"
            ) from exc
    elif (
        os.path.lexists(engine_path)
        or os.path.lexists(receipt_path)
        or os.path.lexists(commit_path)
    ):
        raise EngineBuildError("refusing to overwrite an existing engine publication")

    with tempfile.TemporaryDirectory(
        prefix=".engine-intent-",
        dir=engine_path.parent,
    ) as temporary:
        staged = Path(temporary) / "build.intent.json"
        _stage_json_file(
            staged,
            record.model_dump(mode="json"),
            max_bytes=65_536,
        )
        try:
            _publish_build_product(staged, intent_path)
            _fsync_directory(engine_path.parent)
        except OSError as exc:
            raise EngineBuildError(
                "build intent publication durability failed; "
                "non-deployable intent retained"
            ) from exc
    return None


def _recover_committed_build(
    *,
    intent: EngineBuildIntentV1,
    engine_path: Path,
    receipt_path: Path,
    commit_path: Path,
) -> EngineBuildResultV1:
    """Validate every committed byte/binding before clearing a stale intent."""

    try:
        receipt_bytes, receipt_payload = _read_bounded_json(
            receipt_path,
            max_bytes=2_000_000,
        )
        result = EngineBuildResultV1.model_validate(receipt_payload)
        _, commit_payload = _read_bounded_json(commit_path, max_bytes=65_536)
        commit = EngineBuildCommitV1.model_validate(commit_payload)
        engine_sha256 = _sha256_file(engine_path)
    except (OSError, ValueError, ValidationError) as exc:
        raise EngineBuildError(
            "committed build recovery failed exact product validation"
        ) from exc
    expected_common = {
        "artifact_id": intent.artifact_id,
        "artifact_sha256": intent.artifact_sha256,
        "registry_entry_sha256": intent.registry_entry_sha256,
        "precision": intent.precision,
        "target_gpu_architecture": intent.target_gpu_architecture,
        "target_compute_capability": intent.target_compute_capability,
        "tensorrt_version": intent.tensorrt_version,
        "observed_tensorrt_runtime_version": (
            intent.observed_tensorrt_runtime_version
        ),
    }
    if (
        any(getattr(result, key) != value for key, value in expected_common.items())
        or any(getattr(commit, key) != value for key, value in expected_common.items())
        or result.engine_sha256 != engine_sha256
        or commit.engine_sha256 != engine_sha256
        or commit.receipt_sha256
        != hashlib.sha256(receipt_bytes).hexdigest()
        or commit.engine_path != intent.engine_path
        or commit.receipt_path != intent.receipt_path
        or commit.commit_path != intent.commit_path
        or commit.intent_path != intent.intent_path
        or str(_publication_destination(engine_path)) != intent.engine_path
        or str(_publication_destination(receipt_path)) != intent.receipt_path
    ):
        raise EngineBuildError(
            "committed build recovery found a product binding mismatch"
        )
    return result


def _cleanup_failed_build(
    *,
    published: list[Path],
    intent_path: Path,
    directory: Path,
) -> None:
    """Remove only products published by this attempt; keep intent on failure."""

    for path in reversed(published):
        path.unlink(missing_ok=True)
    _fsync_directory(directory)
    intent_path.unlink(missing_ok=True)
    _fsync_directory(directory)


def _require_target_compatibility(
    spec: EngineBuildSpecV1,
    runtime: TargetRuntimeIdentityV1,
) -> None:
    if runtime.target_gpu_architecture != spec.target_gpu_architecture:
        raise EngineBuildError("target GPU architecture does not match build specification")
    if runtime.target_compute_capability != spec.target_compute_capability:
        raise EngineBuildError("target compute capability does not match build specification")
    if runtime.tensorrt_version != spec.tensorrt_version:
        raise EngineBuildError("target TensorRT version does not match build specification")
    expected_semantic_base = ".".join(spec.tensorrt_version.split(".")[:3])
    if runtime.tensorrt_runtime_version != expected_semantic_base:
        raise EngineBuildError(
            "target TensorRT runtime semantic version does not match build specification"
        )


def parse_tensorrt_runtime_banner(output: str) -> str:
    """Normalize dotted or NVIDIA compact TensorRT banners to major.minor.patch."""

    match = re.search(
        r"TensorRT(?:\s+version)?\s+v?([0-9]+(?:\.[0-9]+){0,3})",
        output,
        flags=re.IGNORECASE,
    )
    if match is None:
        raise EngineBuildError("target TensorRT probe returned an invalid version")
    raw_version = match.group(1)
    if "." in raw_version:
        parts = raw_version.split(".")
        if len(parts) < 3:
            raise EngineBuildError("target TensorRT probe returned an invalid version")
        return ".".join(str(int(part)) for part in parts[:3])
    if len(raw_version) >= 5:
        encoded = int(raw_version)
        major = encoded // 10_000
        minor = (encoded % 10_000) // 100
        patch = encoded % 100
    elif len(raw_version) == 4:
        encoded = int(raw_version)
        major = encoded // 1_000
        minor = (encoded % 1_000) // 100
        patch = encoded % 100
    else:
        raise EngineBuildError("target TensorRT probe returned an invalid version")
    return f"{major}.{minor}.{patch}"


def probe_target_runtime(trtexec_path: Path) -> TargetRuntimeIdentityV1:
    """Probe target compatibility with bounded argv-only subprocesses."""

    gpu_argv = [
        "nvidia-smi",
        "--query-gpu=name,compute_cap",
        "--format=csv,noheader,nounits",
    ]
    try:
        gpu_status, gpu_output = _run_bounded(
            gpu_argv,
            timeout_seconds=10,
            max_output_bytes=16_384,
        )
        trt_status, trt_output = _run_bounded(
            [str(trtexec_path), "--version"],
            timeout_seconds=10,
            max_output_bytes=16_384,
        )
        package_status, package_output = _run_bounded(
            ["dpkg-query", "-W", "-f=${Version}", "libnvinfer10"],
            timeout_seconds=10,
            max_output_bytes=16_384,
        )
    except OSError as exc:
        raise EngineBuildError("target NVIDIA/TensorRT runtime probe is unavailable") from exc
    if gpu_status != 0 or trt_status != 0 or package_status != 0:
        raise EngineBuildError("target NVIDIA/TensorRT runtime probe failed")
    first_gpu = gpu_output.strip().splitlines()[0] if gpu_output.strip() else ""
    gpu_fields = [field.strip() for field in first_gpu.rsplit(",", maxsplit=1)]
    if len(gpu_fields) != 2:
        raise EngineBuildError("target GPU probe returned an invalid identity")
    gpu_name, compute_capability = gpu_fields
    runtime_version = parse_tensorrt_runtime_banner(trt_output)
    package_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", package_output)
    if package_match is None:
        raise EngineBuildError("target TensorRT package probe returned an invalid version")
    exact_package_version = package_match.group(1)
    if ".".join(exact_package_version.split(".")[:3]) != runtime_version:
        raise EngineBuildError("target TensorRT banner and package versions do not match")
    architecture = _L4_ARCHITECTURE if gpu_name in {"L4", "NVIDIA L4"} else gpu_name
    return TargetRuntimeIdentityV1(
        target_gpu_architecture=architecture,
        target_compute_capability=compute_capability,
        tensorrt_version=exact_package_version,
        tensorrt_runtime_version=runtime_version,
        raw_tensorrt_banner=trt_output.strip(),
    )


def _run_bounded(
    argv: list[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> tuple[int, str]:
    process = subprocess.Popen(  # noqa: S603 - argv is explicit and shell is never used.
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    captured = bytearray()
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise EngineBuildError("TensorRT exporter timed out")
            for key, _ in selector.select(timeout=min(remaining, 0.1)):
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(captured) + len(chunk) > max_output_bytes:
                    _kill_process_group(process)
                    raise EngineBuildError("TensorRT exporter exceeded output limit")
                captured.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_process_group(process)
            raise EngineBuildError("TensorRT exporter timed out")
        return_code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(process)
        raise EngineBuildError("TensorRT exporter timed out") from exc
    finally:
        selector.close()
        process.stdout.close()
        _kill_process_group(process)
    return return_code, captured.decode("utf-8", errors="replace")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _sha256_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("path must be a regular file")
        while chunk := os.read(descriptor, 1_048_576):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Publish one bounded machine-readable audit/build receipt atomically."""

    encoded = (json.dumps(dict(payload), indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


__all__ = [
    "CalibrationCorpusV1",
    "CommercialRightsEvidenceV1",
    "EngineBuildCommitV1",
    "EngineBuildError",
    "EngineBuildIntentV1",
    "EngineBuildResultV1",
    "EngineBuildSpecV1",
    "EngineRecordV1",
    "MeasuredCapacityReportV1",
    "ModelAuditResultV1",
    "ModelRegistryEntryV1",
    "NoRegressionEventReportV1",
    "ShadowStageEvidenceV1",
    "SignedSiteMatrixV1",
    "SiteMatrixSceneV1",
    "TargetRuntimeIdentityV1",
    "atomic_write_json",
    "audit_model_entry",
    "build_engine",
    "evaluate_conditional_promotion",
    "load_model_entry",
    "parse_tensorrt_runtime_banner",
    "probe_target_runtime",
]
