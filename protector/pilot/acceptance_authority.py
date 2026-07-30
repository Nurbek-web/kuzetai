"""Durable machine-only authority for target acceptance evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import tempfile
import threading
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, ClassVar, Literal, Protocol

from pydantic import Field, field_serializer, field_validator, model_validator

from protector.pilot.acceptance import (
    MAX_ACCEPTANCE_ENVELOPE_BYTES,
    MAX_ACCEPTANCE_RECORD_BYTES,
    AcceptanceRunRecordV2,
    AnalyticName,
    CameraHealthSpanV2,
    CameraQueueCoverageV2,
    CameraRunRecordV2,
    Digest,
    ExecutionBindingV2,
    FaultRecordV2,
    FaultStateTraceV2,
    LaunchAttestationV2,
    QueueAgeRunV2,
    ResourceSampleV2,
    ScheduledFaultV2,
    WorkAccountingSpanV2,
    build_canonical_fault_schedule,
    canonical_fault_schedule_sha256,
)
from protector.pilot.acceptance_proof import (
    AcceptanceFinalEnvelopeV2,
    AcceptanceJournalProofEntryV2,
    AcceptanceJournalProofHeaderV2,
    AcceptanceJournalProofTrailerV2,
    AcceptanceProofStore,
    ExportedAcceptanceJournalProofV2,
    JournalKindCountsV2,
    TargetRunAttestationV2,
    canonical_proof_line,
    journal_entry_sha256,
)
from protector.pilot.acceptance_trust import (
    AcceptanceGate,
    VerifiedAcceptanceTrustV2,
    _acceptance_trust_provenance_receipt,
    _named_length_framed_bytes,
    authorize_acceptance_execution,
    canonical_json_bytes,
)
from protector.pilot.config import FrozenModel

_MAX_ENTRY_BYTES = 2 * 1024 * 1024
_MAX_SAMPLE_ENTRY_BYTES = 64 * 1024
_MAX_FINAL_ENTRY_BYTES = MAX_ACCEPTANCE_RECORD_BYTES
_MAX_ENTRIES = 10_000
_MAX_TOTAL_ENTRIES = 40_000
_MAX_SESSIONS = 4
_MAX_DATABASE_BYTES = 1024 * 1024 * 1024
_MAX_VERIFIED_PAYLOAD_CACHE_BYTES = 2 * 1024 * 1024
_MAX_SESSION_SAMPLE_BYTES = 128 * 1024 * 1024
_MAX_ADAPTER_EXECUTABLE_BYTES = 64 * 1024 * 1024
_MAX_ADAPTER_POLICY_BYTES = 1024 * 1024
_QUEUE_AGE_BUCKET_SECONDS = 0.001
_QUEUE_AGE_FAILED_GATE_BUCKET_SECONDS = 2.001
_SAMPLE_ARRIVAL_TOLERANCE_SECONDS = 5.0
_COMMAND_ARRIVAL_TOLERANCE_SECONDS = 5.0
_DURABLE_ENTRY_SCHEMAS = {
    "start": "acceptance-collector-start.v2",
    "sample": "acceptance-sample-observation.v2",
    "fault_intent": "acceptance-fault-intent.v2",
    "fault_claim": "acceptance-fault-claim.v2",
    "fault_ack": "acceptance-fault-acknowledgement.v2",
    "finalize": "acceptance-run-record.v2",
}
_SECRET_LIKE = re.compile(
    r"(?i)(?:rtsp|rtsps|data):|authorization|bearer\s+|"
    r"password|api[_-]?key|access[_-]?token|refresh[_-]?token|machine[_-]?token"
)


class _ClosingSQLiteConnection(sqlite3.Connection):
    def __exit__(self, *args: object) -> bool | None:
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def read_host_boot_id() -> str:
    """Return a stable per-boot host identity or fail closed."""
    proc_path = Path("/proc/sys/kernel/random/boot_id")
    try:
        value = proc_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        try:
            result = subprocess.run(
                ("sysctl", "-n", "kern.boottime"),
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("host boot identity is unavailable") from exc
        value = result.stdout.strip()
    if not 1 <= len(value) <= 256:
        raise RuntimeError("host boot identity is invalid")
    return value


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be UTC")
    return value.astimezone(timezone.utc)


def _canonical_json(payload: object) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _decode_durable_entry(kind: str, payload_json: str) -> dict[str, object]:
    try:
        payload = json.loads(payload_json)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("acceptance journal payload is invalid") from exc
    expected_schema = _DURABLE_ENTRY_SCHEMAS.get(kind)
    if (
        expected_schema is None
        or not isinstance(payload, dict)
        or payload.get("schema_version") != expected_schema
    ):
        raise RuntimeError("acceptance journal payload schema is invalid")
    return payload


def _aggregate_queue_age_runs(
    runs: Iterable[QueueAgeRunV2],
) -> tuple[QueueAgeRunV2, ...]:
    """Bound queue evidence while conservatively preserving the 1s/2s gates."""
    counts: Counter[float] = Counter()
    for run in runs:
        if run.age_seconds > 2.0:
            bucket = _QUEUE_AGE_FAILED_GATE_BUCKET_SECONDS
        else:
            bucket = round(
                math.ceil(run.age_seconds / _QUEUE_AGE_BUCKET_SECONDS - 1e-12)
                * _QUEUE_AGE_BUCKET_SECONDS,
                3,
            )
        counts[bucket] += run.samples
    return tuple(
        QueueAgeRunV2(age_seconds=age_seconds, samples=samples)
        for age_seconds, samples in sorted(counts.items())
    )


def _reject_secret_like(payload: object) -> None:
    """Keep credentials and opaque secret-bearing URIs out of the durable journal."""
    encoded = _canonical_json(payload)
    if _SECRET_LIKE.search(encoded):
        raise ValueError("acceptance journal payload contains secret-like material")


def _read_bounded_regular(path: Path, *, limit: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
            raise ValueError("adapter response is not a bounded regular file")
        payload = os.read(descriptor, limit + 1)
        if len(payload) != metadata.st_size:
            raise ValueError("adapter response changed while reading")
        return payload
    finally:
        os.close(descriptor)


def _sha256_bounded_regular(path: Path, *, limit: int) -> tuple[os.stat_result, str]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
            raise ValueError("adapter executable is not a bounded regular file")
        consumed = 0
        while chunk := os.read(
            descriptor,
            min(1024 * 1024, limit + 1 - consumed),
        ):
            digest.update(chunk)
            consumed += len(chunk)
            if consumed > limit:
                raise ValueError("adapter executable exceeds its finite bound")
        if consumed != metadata.st_size:
            raise ValueError("adapter executable changed while hashing")
        return metadata, digest.hexdigest()
    finally:
        os.close(descriptor)


def _capture_bounded_regular(
    path: Path,
    *,
    limit: int,
    executable: bool,
) -> tuple[os.stat_result, bytes, str]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= limit
            or before.st_uid not in {0, os.geteuid()}
            or before.st_mode & 0o022
            or (executable and not before.st_mode & 0o111)
        ):
            raise ValueError("adapter artifact is not a trusted bounded file")
        chunks: list[bytes] = []
        consumed = 0
        while chunk := os.read(
            descriptor,
            min(1024 * 1024, limit + 1 - consumed),
        ):
            consumed += len(chunk)
            if consumed > limit:
                raise ValueError("adapter artifact exceeds its finite bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if consumed != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("adapter artifact changed while capturing")
        payload = b"".join(chunks)
        return before, payload, hashlib.sha256(payload).hexdigest()
    finally:
        os.close(descriptor)


class AcceptanceTrustBindingV2(FrozenModel):
    schema_version: Literal["acceptance-trust-binding.v2"]
    offline_root_spki_sha256: Digest
    policy_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    policy_sha256: Digest
    campaign_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    manifest_payload_sha256: Digest


class CollectorBindingV2(FrozenModel):
    collector_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
        ),
    ]
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    manifest_sha256: Digest
    gate: Literal["8h", "72h"]
    launch_attestation_sha256: Digest
    execution_binding_sha256: Digest
    fault_schedule_sha256: Digest
    trust_binding: AcceptanceTrustBindingV2 | None = None

    def response_fields(self) -> dict[str, object]:
        encoded = self.model_dump(mode="json")
        return {
            field: encoded[field] for field in CollectorBindingV2.model_fields
        }


class CameraAcceptanceWorkloadV2(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    source_index: Annotated[int, Field(ge=0, lt=20)]
    source_kind: Literal["local_fixture", "target_secret"]
    source_reference: Annotated[str, Field(min_length=1, max_length=4096)]
    codec: Literal["h264", "h265"]
    width: Annotated[int, Field(ge=320, le=7680)]
    height: Annotated[int, Field(ge=240, le=4320)]
    fps: Annotated[float, Field(gt=0, le=120)]
    bitrate_kbps: Annotated[int, Field(gt=0, le=200_000)]
    analytics_hz: Annotated[
        Mapping[AnalyticName, float],
        Field(min_length=1, max_length=32),
    ]

    @field_validator("analytics_hz")
    @classmethod
    def rates_are_finite_positive(
        cls,
        value: Mapping[AnalyticName, float],
    ) -> Mapping[AnalyticName, float]:
        if value.get("person", 0) <= 0 or any(
            not math.isfinite(rate) or not 0 <= rate <= 30 for rate in value.values()
        ):
            raise ValueError("acceptance analytic rates must match manifest bounds")
        return MappingProxyType(dict(value))

    @field_serializer("analytics_hz")
    def serialize_analytic_rates(
        self,
        value: Mapping[AnalyticName, float],
    ) -> dict[AnalyticName, float]:
        return dict(value)


@dataclass(frozen=True, init=False)
class AcceptanceAuthorityTrustContextV2:
    trust: VerifiedAcceptanceTrustV2
    binding: AcceptanceTrustBindingV2
    configured_site_id: str
    configured_campaign_id: str
    configured_gate: AcceptanceGate
    launch: LaunchAttestationV2
    camera_ids: tuple[str, ...]
    workloads: tuple[CameraAcceptanceWorkloadV2, ...]
    fault_schedule: tuple[ScheduledFaultV2, ...]
    _context_receipt: ClassVar[bytes] = b""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("acceptance authority trust context requires the verified builder")


_AUTHORITY_CONTEXT_PROVENANCE_KEY = secrets.token_bytes(32)


def _authority_context_mac(
    *,
    trust: VerifiedAcceptanceTrustV2,
    binding: AcceptanceTrustBindingV2,
    configured_site_id: str,
    configured_campaign_id: str,
    configured_gate: AcceptanceGate,
    launch: LaunchAttestationV2,
    camera_ids: tuple[str, ...],
    workloads: tuple[CameraAcceptanceWorkloadV2, ...],
    fault_schedule: tuple[ScheduledFaultV2, ...],
) -> bytes:
    trust_receipt = _acceptance_trust_provenance_receipt(trust)
    framed = _named_length_framed_bytes(
        domain=b"kuzet.acceptance.authority-trust-context.v2",
        fields=(
            ("verified_trust_receipt", trust_receipt),
            ("binding", canonical_json_bytes(binding)),
            ("configured_site_id", configured_site_id.encode("utf-8")),
            (
                "configured_campaign_id",
                configured_campaign_id.encode("utf-8"),
            ),
            ("configured_gate", configured_gate.encode("ascii")),
            ("launch", canonical_json_bytes(launch)),
            ("camera_ids", canonical_json_bytes(camera_ids)),
            (
                "workloads",
                canonical_json_bytes([workload.model_dump(mode="json") for workload in workloads]),
            ),
            (
                "fault_schedule",
                canonical_json_bytes([fault.model_dump(mode="json") for fault in fault_schedule]),
            ),
        ),
    )
    return hmac.digest(_AUTHORITY_CONTEXT_PROVENANCE_KEY, framed, "sha256")


def _mint_authority_trust_context(
    *,
    trust: VerifiedAcceptanceTrustV2,
    binding: AcceptanceTrustBindingV2,
    configured_site_id: str,
    configured_campaign_id: str,
    configured_gate: AcceptanceGate,
    launch: LaunchAttestationV2,
    camera_ids: tuple[str, ...],
    workloads: tuple[CameraAcceptanceWorkloadV2, ...],
    fault_schedule: tuple[ScheduledFaultV2, ...],
) -> AcceptanceAuthorityTrustContextV2:
    values: dict[str, object] = {
        "trust": trust,
        "binding": binding,
        "configured_site_id": configured_site_id,
        "configured_campaign_id": configured_campaign_id,
        "configured_gate": configured_gate,
        "launch": launch,
        "camera_ids": camera_ids,
        "workloads": workloads,
        "fault_schedule": fault_schedule,
    }
    receipt = _authority_context_mac(
        trust=trust,
        binding=binding,
        configured_site_id=configured_site_id,
        configured_campaign_id=configured_campaign_id,
        configured_gate=configured_gate,
        launch=launch,
        camera_ids=camera_ids,
        workloads=workloads,
        fault_schedule=fault_schedule,
    )
    context = object.__new__(AcceptanceAuthorityTrustContextV2)
    for name, value in values.items():
        object.__setattr__(context, name, value)
    object.__setattr__(context, "_context_receipt", receipt)
    return context


def _require_authority_trust_context(
    context: AcceptanceAuthorityTrustContextV2,
) -> AcceptanceAuthorityTrustContextV2:
    if type(context) is not AcceptanceAuthorityTrustContextV2:
        raise ValueError("acceptance authority trust context provenance is invalid")
    try:
        receipt = context._context_receipt
        expected = _authority_context_mac(
            trust=context.trust,
            binding=context.binding,
            configured_site_id=context.configured_site_id,
            configured_campaign_id=context.configured_campaign_id,
            configured_gate=context.configured_gate,
            launch=context.launch,
            camera_ids=context.camera_ids,
            workloads=context.workloads,
            fault_schedule=context.fault_schedule,
        )
    except (AttributeError, TypeError, UnicodeError, ValueError):
        raise ValueError("acceptance authority trust context provenance is invalid") from None
    if (
        not isinstance(receipt, bytes)
        or len(receipt) != hashlib.sha256().digest_size
        or not hmac.compare_digest(receipt, expected)
    ):
        raise ValueError("acceptance authority trust context provenance is invalid")
    return context


def build_acceptance_trust_binding(
    trust: VerifiedAcceptanceTrustV2,
) -> AcceptanceTrustBindingV2:
    """Project the immutable offline-root chain into every collector request."""
    _acceptance_trust_provenance_receipt(trust)
    return AcceptanceTrustBindingV2(
        schema_version="acceptance-trust-binding.v2",
        offline_root_spki_sha256=trust.root_spki_sha256,
        policy_id=trust.policy.policy_id,
        policy_sha256=trust.policy_sha256,
        campaign_id=trust.policy.campaign_id,
        manifest_payload_sha256=trust.manifest_payload_sha256,
    )


def build_authority_trust_context(
    *,
    trust: VerifiedAcceptanceTrustV2,
    configured_site_id: str,
    configured_campaign_id: str,
    configured_gate: AcceptanceGate,
) -> AcceptanceAuthorityTrustContextV2:
    """Freeze the signed manifest projection used by the target authority."""
    _acceptance_trust_provenance_receipt(trust)
    if (
        trust.policy.site_id != configured_site_id
        or trust.manifest.site_id != configured_site_id
        or trust.policy.campaign_id != configured_campaign_id
        or configured_gate not in trust.policy.allowed_gates
    ):
        raise ValueError("configured acceptance context differs from trust policy")
    camera_ids = tuple(source.camera_id for source in trust.manifest.sources)
    workloads = tuple(
        CameraAcceptanceWorkloadV2(
            camera_id=source.camera_id,
            source_index=source.source_index,
            source_kind=source.source.kind,
            source_reference=(
                source.source.path
                if source.source.kind == "local_fixture"
                else source.source.secret_reference
            ),
            codec=source.codec,
            width=source.width,
            height=source.height,
            fps=source.fps,
            bitrate_kbps=source.bitrate_kbps,
            analytics_hz=source.analytics_hz,
        )
        for source in trust.manifest.sources
    )
    return _mint_authority_trust_context(
        trust=trust,
        binding=build_acceptance_trust_binding(trust),
        configured_site_id=configured_site_id,
        configured_campaign_id=configured_campaign_id,
        configured_gate=configured_gate,
        launch=trust.manifest.launch,
        camera_ids=camera_ids,
        workloads=workloads,
        fault_schedule=build_canonical_fault_schedule(camera_ids),
    )


class AcceptanceStartRequestV2(CollectorBindingV2):
    schema_version: Literal["acceptance-collector-start.v2"]
    sample_interval_seconds: Literal[60]
    camera_ids: Annotated[tuple[str, ...], Field(min_length=20, max_length=20)]
    workloads: Annotated[
        tuple[CameraAcceptanceWorkloadV2, ...],
        Field(min_length=20, max_length=20),
    ]
    launch: LaunchAttestationV2
    execution: ExecutionBindingV2
    fault_schedule: Annotated[
        tuple[ScheduledFaultV2, ...],
        Field(min_length=8, max_length=8),
    ]

    @model_validator(mode="after")
    def exact_bindings_are_frozen(self) -> AcceptanceStartRequestV2:
        duration = 8 * 3600 if self.gate == "8h" else 72 * 3600
        if len(set(self.camera_ids)) != 20:
            raise ValueError("acceptance start requires exact unique camera identities")
        if (
            tuple(item.camera_id for item in self.workloads) != self.camera_ids
            or self.launch.site_id != self.site_id
            or self.launch.attestation_sha256 != self.launch_attestation_sha256
            or self.execution.binding_sha256 != self.execution_binding_sha256
            or self.execution.launch_attestation_sha256 != self.launch_attestation_sha256
            or self.execution.runtime_image_id_sha256 != self.launch.runtime_image_id_sha256
            or self.execution.acceptance_adapter_sha256 != self.launch.acceptance_adapter_sha256
            or self.execution.acceptance_adapter_policy_sha256
            != self.launch.acceptance_adapter_policy_sha256
            or self.execution.acceptance_observer_sha256 != self.launch.acceptance_observer_sha256
            or self.execution.acceptance_observer_policy_sha256
            != self.launch.acceptance_observer_policy_sha256
            or self.execution.control_network_id != self.launch.expected_control_network_id
            or self.execution.control_network_config_sha256
            != self.launch.expected_control_network_config_sha256
            or self.execution.camera_network_id != self.launch.expected_camera_network_id
            or self.execution.camera_network_config_sha256
            != self.launch.expected_camera_network_config_sha256
            or self.execution.observed_gpu_inventory_sha256 != self.launch.gpu_inventory_sha256
            or hashlib.sha256(
                _canonical_json(
                    {
                        "schema_version": "acceptance-source-profiles.v2",
                        "sources": [
                            {
                                "camera_id": item.camera_id,
                                "source_index": item.source_index,
                                "source": {
                                    "kind": item.source_kind,
                                    (
                                        "path"
                                        if item.source_kind == "local_fixture"
                                        else "secret_reference"
                                    ): item.source_reference,
                                },
                                "codec": item.codec,
                                "width": item.width,
                                "height": item.height,
                                "fps": item.fps,
                                "bitrate_kbps": item.bitrate_kbps,
                                "analytics_hz": dict(item.analytics_hz),
                            }
                            for item in self.workloads
                        ],
                    }
                ).encode()
            ).hexdigest()
            != self.launch.source_profiles_sha256
            or canonical_fault_schedule_sha256(self.fault_schedule) != self.fault_schedule_sha256
            or self.fault_schedule != build_canonical_fault_schedule(self.camera_ids)
            or duration % self.sample_interval_seconds != 0
        ):
            raise ValueError("acceptance start launch or fault schedule binding mismatch")
        return self


class AcceptanceSampleRequestV2(CollectorBindingV2):
    schema_version: Literal["acceptance-collector-sample.v2"]
    process_healthy: Literal[True]
    scheduled_monotonic_offset_seconds: Annotated[
        float,
        Field(ge=0, le=259_200),
    ]
    observation: AcceptanceSampleObservationV2 | None = None


class AcceptanceFaultPrepareRequestV2(CollectorBindingV2):
    schema_version: Literal["acceptance-fault-prepare.v2"]
    fault: ScheduledFaultV2
    phase: Literal["inject", "recover"]
    commanded_monotonic_offset_seconds: Annotated[
        float,
        Field(ge=0, le=604_800),
    ]

    @model_validator(mode="after")
    def command_matches_fault_boundary(self) -> AcceptanceFaultPrepareRequestV2:
        expected = (
            self.fault.offset_seconds
            if self.phase == "inject"
            else self.fault.offset_seconds + self.fault.duration_seconds
        )
        if self.commanded_monotonic_offset_seconds != expected:
            raise ValueError("fault command is not on its canonical boundary")
        return self


class AcceptanceFaultAckRequestV2(CollectorBindingV2):
    schema_version: Literal["acceptance-fault-ack.v2"]
    fault_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
        ),
    ]
    phase: Literal["inject", "recover"]
    command_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=160,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$",
        ),
    ]
    receipt: FaultEffectReceiptV2
    observation: FaultCommandObservationV2 | None = None


class AcceptanceFinalizeRequestV2(CollectorBindingV2):
    schema_version: Literal["acceptance-collector-finalize.v2"]
    candidate: Annotated[dict[str, object], Field(max_length=128)] | None = None


class AcceptanceProofRequestV2(CollectorBindingV2):
    schema_version: Literal["acceptance-proof-request.v2"]


class AcceptanceStartResponseV2(CollectorBindingV2):
    schema_version: Literal["acceptance-collector-start-response.v2"]


class AcceptanceSampleResponseV2(CollectorBindingV2):
    schema_version: Literal["acceptance-collector-sample-response.v2"]
    observed_records: Annotated[int, Field(ge=0, le=10_000_000_000)]


class AcceptanceFaultPrepareResponseV2(CollectorBindingV2):
    schema_version: Literal["acceptance-fault-prepare-response.v2"]
    fault_id: Annotated[str, Field(min_length=1, max_length=128)]
    phase: Literal["inject", "recover"]
    commanded_monotonic_offset_seconds: Annotated[
        float,
        Field(ge=0, le=604_800),
    ]
    command_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=160,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$",
        ),
    ]
    state: Literal["CLAIMED", "COMMITTED"]
    runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    api_boot_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    observed_at: datetime | None = None

    @field_validator("observed_at")
    @classmethod
    def observed_timestamp_is_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value, "fault preparation timestamp")

    @model_validator(mode="after")
    def committed_response_has_observation(self) -> AcceptanceFaultPrepareResponseV2:
        values = (self.runtime_boot_id, self.api_boot_id, self.observed_at)
        if self.state == "COMMITTED" and any(value is None for value in values):
            raise ValueError("committed fault preparation requires observed boot identities")
        if self.state == "CLAIMED" and any(value is not None for value in values):
            raise ValueError("claimed fault preparation cannot claim an observation")
        return self


class AcceptanceFaultAckResponseV2(CollectorBindingV2):
    schema_version: Literal["acceptance-fault-ack-response.v2"]
    fault_id: Annotated[str, Field(min_length=1, max_length=128)]
    phase: Literal["inject", "recover"]
    commanded_monotonic_offset_seconds: Annotated[
        float,
        Field(ge=0, le=604_800),
    ]
    command_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=160,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$",
        ),
    ]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    execution_binding_sha256: Digest
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def acknowledged_timestamp_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "fault acknowledgement timestamp")


class AnalyticCounterObservationV2(FrozenModel):
    module: AnalyticName
    scheduled_samples: Annotated[int, Field(ge=0, le=10_000_000_000)]
    processed_samples: Annotated[int, Field(ge=0, le=10_000_000_000)]
    dropped_samples: Annotated[int, Field(ge=0, le=10_000_000_000)]

    @model_validator(mode="after")
    def outcomes_match_schedule(self) -> AnalyticCounterObservationV2:
        if self.processed_samples + self.dropped_samples != self.scheduled_samples:
            raise ValueError("acceptance sample outcomes differ from schedule")
        return self


class CameraAcceptanceObservationV2(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    source_index: Annotated[int, Field(ge=0, lt=20)]
    negotiated_codec: Literal["h264", "h265"]
    negotiated_width: Annotated[int, Field(ge=320, le=7680)]
    negotiated_height: Annotated[int, Field(ge=240, le=4320)]
    negotiated_fps: Annotated[float, Field(gt=0, le=120)]
    negotiated_bitrate_kbps: Annotated[int, Field(gt=0, le=200_000)]
    queue_name: Literal["analytics"]
    state: Literal["online", "degraded", "offline"]
    counters: Annotated[
        tuple[AnalyticCounterObservationV2, ...],
        Field(min_length=1, max_length=32),
    ]
    queue_observation_cadence_seconds: Annotated[
        float,
        Field(gt=0, le=5),
    ]
    queue_age_runs: Annotated[
        tuple[QueueAgeRunV2, ...],
        Field(min_length=1, max_length=10_000),
    ]
    runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def counter_modules_are_unique(self) -> CameraAcceptanceObservationV2:
        modules = tuple(item.module for item in self.counters)
        if (
            len(set(modules)) != len(modules)
            or sum(item.samples for item in self.queue_age_runs) > 1_000_000
        ):
            raise ValueError("acceptance sample counter modules must be unique")
        return self


class CameraHealthIntervalObservationV2(FrozenModel):
    camera_id: Annotated[str, Field(min_length=1, max_length=128)]
    started_monotonic_offset_seconds: Annotated[
        float,
        Field(ge=0, le=259_200),
    ]
    ended_monotonic_offset_seconds: Annotated[
        float,
        Field(gt=0, le=259_200),
    ]
    state: Literal["online", "degraded", "offline"]

    @model_validator(mode="after")
    def interval_is_finite_and_nonempty(
        self,
    ) -> CameraHealthIntervalObservationV2:
        if (
            not math.isfinite(self.started_monotonic_offset_seconds)
            or not math.isfinite(self.ended_monotonic_offset_seconds)
            or self.ended_monotonic_offset_seconds <= self.started_monotonic_offset_seconds
        ):
            raise ValueError("camera health interval must be finite and nonempty")
        return self


class AcceptanceSampleObservationV2(FrozenModel):
    schema_version: Literal["acceptance-sample-observation.v2"]
    observed_at: datetime
    observed_records: Annotated[int, Field(ge=0, le=10_000_000_000)]
    collector_id: Annotated[str, Field(min_length=1, max_length=128)]
    launch_attestation_sha256: Digest
    execution_binding_sha256: Digest
    observer_sha256: Digest
    observer_policy_sha256: Digest
    cameras: Annotated[
        tuple[CameraAcceptanceObservationV2, ...],
        Field(min_length=20, max_length=20),
    ]
    health_intervals: Annotated[
        tuple[CameraHealthIntervalObservationV2, ...],
        Field(max_length=2_048),
    ]
    resource: ResourceSampleV2

    @field_validator("observed_at")
    @classmethod
    def timestamp_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "acceptance sample timestamp")

    @model_validator(mode="after")
    def sample_is_self_consistent(self) -> AcceptanceSampleObservationV2:
        camera_ids = tuple(item.camera_id for item in self.cameras)
        if len(set(camera_ids)) != 20:
            raise ValueError("acceptance sample requires exact camera identities")
        processed = sum(
            counter.processed_samples for camera in self.cameras for counter in camera.counters
        )
        if (
            processed != self.observed_records
            or self.resource.sampled_at != self.observed_at
            or len({item.runtime_boot_id for item in self.cameras}) != 1
            or len({item.api_boot_id for item in self.cameras}) != 1
        ):
            raise ValueError("acceptance sample count, resource, or shared boot identity differs")
        return self


AcceptanceSampleRequestV2.model_rebuild()


class FaultCommandObservationV2(FrozenModel):
    schema_version: Literal["acceptance-fault-command-observation.v2"]
    command_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=160,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$",
        ),
    ]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    execution_binding_sha256: Digest
    observer_sha256: Digest
    observer_policy_sha256: Digest


class FaultEffectExecutionRequestV2(FrozenModel):
    schema_version: Literal["acceptance-fault-effect-execution.v2"]
    collector_id: Annotated[str, Field(min_length=1, max_length=128)]
    launch_attestation_sha256: Digest
    execution_binding_sha256: Digest
    fault: ScheduledFaultV2
    phase: Literal["inject", "recover"]
    command_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=160,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$",
        ),
    ]
    commanded_monotonic_offset_seconds: Annotated[
        float,
        Field(ge=0, le=604_800),
    ]

    @model_validator(mode="after")
    def exact_fault_boundary(self) -> FaultEffectExecutionRequestV2:
        expected = (
            self.fault.offset_seconds
            if self.phase == "inject"
            else self.fault.offset_seconds + self.fault.duration_seconds
        )
        if self.commanded_monotonic_offset_seconds != expected:
            raise ValueError("fault execution is not on its canonical boundary")
        return self


class FaultEffectReceiptV2(FrozenModel):
    schema_version: Literal["acceptance-fault-effect-receipt.v2"]
    command_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=160,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$",
        ),
    ]
    fault_id: Annotated[str, Field(min_length=1, max_length=128)]
    phase: Literal["inject", "recover"]
    target: Annotated[str, Field(min_length=1, max_length=128)]
    execution_binding_sha256: Digest
    executor_sha256: Digest
    executor_policy_sha256: Digest
    pre_state: Annotated[str, Field(min_length=1, max_length=64)]
    post_state: Annotated[str, Field(min_length=1, max_length=64)]
    pre_runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    post_runtime_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    pre_api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    post_api_boot_id: Annotated[str, Field(min_length=1, max_length=128)]
    effect_started_at: datetime
    effect_completed_at: datetime
    effect_proof_sha256: Digest
    outcome: Literal["ensured"]

    @field_validator("effect_started_at", "effect_completed_at")
    @classmethod
    def receipt_timestamps_are_utc(cls, value: datetime) -> datetime:
        return _utc(value, "fault effect receipt timestamp")

    @model_validator(mode="after")
    def receipt_interval_is_ordered(self) -> FaultEffectReceiptV2:
        if self.effect_completed_at < self.effect_started_at:
            raise ValueError("fault effect receipt interval is reversed")
        return self


AcceptanceFaultAckRequestV2.model_rebuild()


class AcceptanceAdapterIdentityV2(FrozenModel):
    schema_version: Literal["acceptance-adapter-identity.v2"]
    executable_sha256: Digest
    policy_sha256: Digest
    scope: Literal["target-acceptance-v2"] = "target-acceptance-v2"


class TargetAcceptanceAdapter(Protocol):
    """Explicitly injected target observer/fault controller; no unsafe default exists."""

    @property
    def identity(self) -> AcceptanceAdapterIdentityV2: ...

    def sample(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        previous_monotonic_offset_seconds: float,
        scheduled_monotonic_offset_seconds: float,
    ) -> AcceptanceSampleObservationV2: ...

    def observe_fault(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        fault: ScheduledFaultV2,
        phase: str,
        command_id: str,
        commanded_monotonic_offset_seconds: float,
    ) -> FaultCommandObservationV2: ...

    def finalize(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
    ) -> AcceptanceRunRecordV2: ...


class AcceptanceRunSigner(Protocol):
    """Controller-isolated signer for one authority-derived final record."""

    @property
    def public_key_spki_sha256(self) -> Digest: ...

    def sign(self, payload: bytes) -> bytes: ...


class ExecutableTargetAcceptanceAdapter:
    """Bounded shell-free bridge to a site-owned observer/fault controller."""

    def __init__(
        self,
        executable: Path,
        *,
        expected_sha256: Digest,
        policy_path: Path,
        policy_sha256: Digest,
        work_root: Path,
        timeout_seconds: float = 30.0,
    ) -> None:
        if (
            not executable.is_absolute()
            or executable.is_symlink()
            or not policy_path.is_absolute()
            or policy_path.is_symlink()
            or not work_root.is_absolute()
            or work_root.is_symlink()
            or not 0 < timeout_seconds <= 60
        ):
            raise ValueError("target acceptance executable configuration is unsafe")
        _, executable_payload, executable_sha256 = _capture_bounded_regular(
            executable,
            limit=_MAX_ADAPTER_EXECUTABLE_BYTES,
            executable=True,
        )
        _, policy_payload, captured_policy_sha256 = _capture_bounded_regular(
            policy_path,
            limit=_MAX_ADAPTER_POLICY_BYTES,
            executable=False,
        )
        if executable_sha256 != expected_sha256 or captured_policy_sha256 != policy_sha256:
            raise ValueError("target acceptance adapter artifacts are not trusted")
        self.work_root = work_root
        self.timeout_seconds = timeout_seconds
        self._expected_sha256 = expected_sha256
        self._identity = AcceptanceAdapterIdentityV2(
            schema_version="acceptance-adapter-identity.v2",
            executable_sha256=expected_sha256,
            policy_sha256=policy_sha256,
        )
        self.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        work_metadata = self.work_root.stat()
        if (
            self.work_root.is_symlink()
            or not stat.S_ISDIR(work_metadata.st_mode)
            or work_metadata.st_mode & 0o077
            or work_metadata.st_uid not in {0, os.geteuid()}
            or not os.access(self.work_root, os.W_OK | os.X_OK)
        ):
            raise ValueError("target acceptance work root is not private")
        snapshot_root = Path(
            tempfile.mkdtemp(
                prefix="acceptance-adapter-snapshot-",
                dir=self.work_root,
            )
        )
        snapshot_root.chmod(0o700)

        def write_snapshot(name: str, payload: bytes, mode: int) -> Path:
            target = snapshot_root / name
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                mode,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            return target

        self.executable = write_snapshot(
            "adapter",
            executable_payload,
            0o500,
        )
        self.policy_path = write_snapshot(
            "policy.json",
            policy_payload,
            0o400,
        )
        snapshot_metadata = self.executable.stat()
        self._executable_identity = (
            snapshot_metadata.st_dev,
            snapshot_metadata.st_ino,
        )

    @property
    def identity(self) -> AcceptanceAdapterIdentityV2:
        return self._identity

    def _invoke(
        self,
        operation: Literal["sample", "fault", "finalize"],
        payload: dict[str, object],
        *,
        limit: int,
    ) -> dict[str, object]:
        current, executable_sha256 = _sha256_bounded_regular(
            self.executable,
            limit=_MAX_ADAPTER_EXECUTABLE_BYTES,
        )
        if (
            self.executable.is_symlink()
            or (current.st_dev, current.st_ino) != self._executable_identity
            or current.st_mode & 0o022
            or executable_sha256 != self._expected_sha256
        ):
            raise RuntimeError("target acceptance executable changed")
        with tempfile.TemporaryDirectory(
            prefix="acceptance-adapter-",
            dir=self.work_root,
        ) as temporary:
            temporary_path = Path(temporary)
            request_path = temporary_path / "request.json"
            response_path = temporary_path / "response.json"
            request_path.write_text(
                _canonical_json(
                    {
                        **payload,
                        "adapter_policy": {
                            "path": str(self.policy_path),
                            "sha256": self.identity.policy_sha256,
                        },
                    }
                ),
                encoding="utf-8",
            )
            request_path.chmod(0o600)
            try:
                result = subprocess.run(
                    (
                        str(self.executable),
                        operation,
                        str(request_path),
                        str(response_path),
                    ),
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd="/",
                    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C"},
                    close_fds=True,
                    timeout=self.timeout_seconds,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise RuntimeError("target acceptance adapter command failed") from exc
            if result.returncode:
                raise RuntimeError("target acceptance adapter command was rejected")
            try:
                decoded = json.loads(_read_bounded_regular(response_path, limit=limit))
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise RuntimeError("target acceptance adapter returned invalid evidence") from exc
            if not isinstance(decoded, dict):
                raise RuntimeError("target acceptance adapter returned an invalid envelope")
            return decoded

    def sample(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        previous_monotonic_offset_seconds: float,
        scheduled_monotonic_offset_seconds: float,
    ) -> AcceptanceSampleObservationV2:
        return AcceptanceSampleObservationV2.model_validate(
            self._invoke(
                "sample",
                {
                    "collector_id": collector_id,
                    "launch": launch.model_dump(mode="json"),
                    "execution": execution.model_dump(mode="json"),
                    "previous_monotonic_offset_seconds": (previous_monotonic_offset_seconds),
                    "scheduled_monotonic_offset_seconds": (scheduled_monotonic_offset_seconds),
                },
                limit=_MAX_ENTRY_BYTES,
            )
        )

    def observe_fault(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        fault: ScheduledFaultV2,
        phase: str,
        command_id: str,
        commanded_monotonic_offset_seconds: float,
    ) -> FaultCommandObservationV2:
        return FaultCommandObservationV2.model_validate(
            self._invoke(
                "observe",
                {
                    "collector_id": collector_id,
                    "launch": launch.model_dump(mode="json"),
                    "execution": execution.model_dump(mode="json"),
                    "fault": fault.model_dump(mode="json"),
                    "phase": phase,
                    "command_id": command_id,
                    "commanded_monotonic_offset_seconds": (commanded_monotonic_offset_seconds),
                },
                limit=_MAX_ENTRY_BYTES,
            )
        )

    def ensure_fault(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        fault: ScheduledFaultV2,
        phase: str,
        command_id: str,
        commanded_monotonic_offset_seconds: float,
        prior_observation: FaultCommandObservationV2 | None = None,
    ) -> FaultEffectReceiptV2:
        """Execute one idempotent host effect from the external runner only."""
        return FaultEffectReceiptV2.model_validate(
            self._invoke(
                "ensure",
                {
                    "collector_id": collector_id,
                    "launch": launch.model_dump(mode="json"),
                    "execution": execution.model_dump(mode="json"),
                    "fault": fault.model_dump(mode="json"),
                    "phase": phase,
                    "command_id": command_id,
                    "commanded_monotonic_offset_seconds": (commanded_monotonic_offset_seconds),
                    "prior_observation": (
                        None
                        if prior_observation is None
                        else prior_observation.model_dump(mode="json")
                    ),
                },
                limit=_MAX_ENTRY_BYTES,
            )
        )

    def finalize(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
    ) -> AcceptanceRunRecordV2:
        return AcceptanceRunRecordV2.model_validate(
            self._invoke(
                "finalize",
                {
                    "collector_id": collector_id,
                    "launch": launch.model_dump(mode="json"),
                    "execution": execution.model_dump(mode="json"),
                },
                limit=MAX_ACCEPTANCE_RECORD_BYTES,
            )
        )


class SQLiteAcceptanceAuthorityJournal:
    """Finite SQLite WAL ledger whose session evidence is append-only."""

    def __init__(
        self,
        path: Path,
        *,
        max_entries: int = _MAX_ENTRIES,
        max_entry_bytes: int = _MAX_ENTRY_BYTES,
        max_total_entries: int = _MAX_TOTAL_ENTRIES,
        max_sessions: int = _MAX_SESSIONS,
        max_database_bytes: int = _MAX_DATABASE_BYTES,
        protected_namespace_owner_uid: int | None = None,
    ) -> None:
        if (
            not path.is_absolute()
            or path.is_symlink()
            or max_entries < 1
            or not 1 <= max_entry_bytes <= _MAX_ENTRY_BYTES
            or max_total_entries < 1
            or max_sessions < 1
            or not 1_048_576 <= max_database_bytes <= _MAX_DATABASE_BYTES
            or (protected_namespace_owner_uid is not None and protected_namespace_owner_uid < 0)
        ):
            raise ValueError("acceptance journal requires a safe absolute bounded path")
        self.path = path
        self.max_entries = max_entries
        self.max_entry_bytes = max_entry_bytes
        self.max_total_entries = max_total_entries
        self.max_sessions = max_sessions
        self.max_database_bytes = max_database_bytes
        self.protected_namespace_owner_uid = protected_namespace_owner_uid
        self._verification_lock = threading.RLock()
        self._verified_heads: dict[str, tuple[int, str]] = {}
        self._verified_entry_sha256: dict[str, dict[int, str]] = {}
        self._verified_kind_counts: dict[str, Counter[str]] = {}
        self._verified_latest_entry_ids: dict[str, dict[str, int]] = {}
        self._verified_payloads: OrderedDict[tuple[str, int], str] = OrderedDict()
        self._verified_payload_bytes = 0
        self._pinned_file_identities: dict[Path, tuple[int, int]] = {}
        self._protected_namespace_device: int | None = None
        if self.protected_namespace:
            self._validate_protected_namespace(pin=True)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._secure_path(self.path.parent, directory=True)
            creation_flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                created_fd = os.open(self.path, creation_flags, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(created_fd)
            self._secure_path(self.path, directory=False)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS acceptance_entries (
                    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collector_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (
                        kind IN (
                            'start',
                            'sample',
                            'fault_intent',
                            'fault_claim',
                            'fault_ack',
                            'finalize'
                        )
                    ),
                    identity TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_entry_sha256 TEXT NOT NULL,
                    entry_sha256 TEXT NOT NULL,
                    UNIQUE (collector_id, kind, identity)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS acceptance_attestations (
                    collector_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    signature_hex TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS acceptance_finalize_requests (
                    collector_id TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL,
                    request_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS acceptance_reservations (
                    collector_id TEXT PRIMARY KEY,
                    reserved_entries INTEGER NOT NULL,
                    reserved_bytes INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS acceptance_session_usage (
                    collector_id TEXT PRIMARY KEY,
                    sample_bytes INTEGER NOT NULL
                        CHECK (sample_bytes >= 0)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS acceptance_journal_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            expected_namespace_mode = "protected" if self.protected_namespace else "portable"
            namespace_row = connection.execute(
                "SELECT value FROM acceptance_journal_metadata WHERE key = 'namespace_mode'"
            ).fetchone()
            if namespace_row is None:
                if (
                    self.protected_namespace
                    and connection.execute("SELECT COUNT(*) FROM acceptance_entries").fetchone()[0]
                ):
                    raise RuntimeError("acceptance journal namespace mode is unbound")
                connection.execute(
                    "INSERT INTO acceptance_journal_metadata (key, value) "
                    "VALUES ('namespace_mode', ?)",
                    (expected_namespace_mode,),
                )
            elif str(namespace_row["value"]) != expected_namespace_mode:
                raise RuntimeError("acceptance journal namespace mode changed")
            stored_usage = {
                str(row["collector_id"]): int(row["sample_bytes"])
                for row in connection.execute(
                    "SELECT collector_id, sample_bytes FROM acceptance_session_usage"
                ).fetchall()
            }
            actual_usage = {
                str(row["collector_id"]): int(row["sample_bytes"])
                for row in connection.execute(
                    "SELECT collector_id, "
                    "COALESCE(SUM(LENGTH(CAST(payload_json AS BLOB))), 0) "
                    "AS sample_bytes FROM acceptance_entries "
                    "WHERE kind = 'sample' GROUP BY collector_id"
                ).fetchall()
            }
            if any(
                stored_usage.get(collector_id) != sample_bytes
                for collector_id, sample_bytes in actual_usage.items()
                if collector_id in stored_usage
            ) or any(
                collector_id not in actual_usage and sample_bytes != 0
                for collector_id, sample_bytes in stored_usage.items()
            ):
                raise RuntimeError("acceptance journal sample byte accounting changed")
            for collector_id, sample_bytes in actual_usage.items():
                if collector_id not in stored_usage:
                    connection.execute(
                        "INSERT INTO acceptance_session_usage "
                        "(collector_id, sample_bytes) VALUES (?, ?)",
                        (collector_id, sample_bytes),
                    )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(acceptance_entries)").fetchall()
            }
            if {
                "previous_entry_sha256",
                "entry_sha256",
            } - columns:
                if connection.execute("SELECT COUNT(*) FROM acceptance_entries").fetchone()[0]:
                    raise RuntimeError("legacy acceptance journal lacks its hash chain")
                connection.execute(
                    "ALTER TABLE acceptance_entries "
                    "ADD COLUMN previous_entry_sha256 TEXT NOT NULL DEFAULT ''"
                )
                connection.execute(
                    "ALTER TABLE acceptance_entries "
                    "ADD COLUMN entry_sha256 TEXT NOT NULL DEFAULT ''"
                )
        if not self.protected_namespace:
            self.path.chmod(0o600)
        self._secure_auxiliary_files()

    @property
    def protected_namespace(self) -> bool:
        """Whether pathname immutability is supplied by a trusted provisioner."""
        return self.protected_namespace_owner_uid is not None

    def readiness_probe(self) -> None:
        """Recheck the pinned protected namespace without opening SQLite."""
        if not self.protected_namespace:
            raise RuntimeError("acceptance readiness requires a protected journal namespace")
        self._validate_protected_namespace()

    @staticmethod
    def _secure_path(path: Path, *, directory: bool) -> None:
        if path.is_symlink():
            raise ValueError("acceptance journal path cannot contain symlinks")
        metadata = path.stat()
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            not expected(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or (stat.S_IMODE(metadata.st_mode) != 0o700 if directory else metadata.st_mode & 0o077)
        ):
            raise ValueError("acceptance journal ownership or mode is unsafe")
        for ancestor in path.parents:
            ancestor_metadata = ancestor.lstat()
            if (
                stat.S_ISLNK(ancestor_metadata.st_mode)
                or not stat.S_ISDIR(ancestor_metadata.st_mode)
                or ancestor_metadata.st_uid not in {0, os.geteuid()}
                or (
                    ancestor_metadata.st_mode & 0o022
                    and not (
                        ancestor_metadata.st_uid == 0 and ancestor_metadata.st_mode & stat.S_ISVTX
                    )
                )
            ):
                raise ValueError("acceptance journal ancestor ownership or mode is unsafe")

    def _secure_auxiliary_files(self) -> None:
        if self.protected_namespace:
            self._validate_protected_namespace()
            return
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            if not candidate.exists():
                continue
            if candidate.is_symlink():
                raise RuntimeError("acceptance journal auxiliary path is a symlink")
            metadata = candidate.stat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise RuntimeError("acceptance journal auxiliary ownership or mode is unsafe")

    @staticmethod
    def _effective_mode_bits(metadata: os.stat_result) -> int:
        effective_uid = os.geteuid()
        effective_groups = {os.getegid(), *os.getgroups()}
        if effective_uid == metadata.st_uid:
            return (metadata.st_mode >> 6) & 0o7
        if metadata.st_gid in effective_groups:
            return (metadata.st_mode >> 3) & 0o7
        return metadata.st_mode & 0o7

    def _validate_protected_namespace(self, *, pin: bool = False) -> None:
        """Validate the provisioner-owned namespace that prevents path swaps.

        This boundary protects against the non-root runtime process. The
        trusted namespace owner, root, same-UID code where the directory is
        runtime-owned, and injected native code remain outside the claim.
        """
        owner_uid = self.protected_namespace_owner_uid
        if owner_uid is None:
            raise RuntimeError("acceptance journal protected namespace is unavailable")
        try:
            directory = self.path.parent.lstat()
        except OSError as exc:
            raise RuntimeError("acceptance journal protected namespace is unavailable") from exc
        directory_permissions = self._effective_mode_bits(directory)
        if (
            stat.S_ISLNK(directory.st_mode)
            or not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != owner_uid
            or directory_permissions & 0o2
            or not directory_permissions & 0o1
        ):
            raise RuntimeError("acceptance journal protected namespace is unsafe")
        if os.geteuid() != 0:
            try:
                runtime_can_write = os.access(
                    self.path.parent,
                    os.W_OK,
                    effective_ids=True,
                )
            except TypeError:
                runtime_can_write = os.access(self.path.parent, os.W_OK)
            if runtime_can_write:
                raise RuntimeError("acceptance journal protected namespace is writable")
        for ancestor in self.path.parent.parents:
            metadata = ancestor.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid(), owner_uid}
                or (
                    metadata.st_mode & 0o022
                    and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)
                )
            ):
                raise RuntimeError("acceptance journal protected namespace ancestor is unsafe")
        devices: set[int] = set()
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise RuntimeError("acceptance journal protected namespace is incomplete") from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise RuntimeError("acceptance journal protected namespace file is unsafe")
            identity = (metadata.st_dev, metadata.st_ino)
            devices.add(metadata.st_dev)
            if pin:
                self._pinned_file_identities[candidate] = identity
            elif self._pinned_file_identities.get(candidate) != identity:
                raise RuntimeError("acceptance journal protected namespace identity changed")
        if len(devices) != 1:
            raise RuntimeError("acceptance journal triplet must use the same local filesystem")
        device = next(iter(devices))
        if pin:
            self._protected_namespace_device = device
        elif self._protected_namespace_device != device:
            raise RuntimeError("acceptance journal protected namespace device changed")

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        if self.protected_namespace:
            self._validate_protected_namespace()
        try:
            expected_metadata = self.path.lstat()
        except OSError as exc:
            raise RuntimeError("acceptance journal connected inode is unavailable") from exc
        expected_main = (
            expected_metadata.st_dev,
            expected_metadata.st_ino,
        )
        pinned_main = self._pinned_file_identities.setdefault(
            self.path,
            expected_main,
        )
        if (
            pinned_main != expected_main
            or not stat.S_ISREG(expected_metadata.st_mode)
            or expected_metadata.st_uid != os.geteuid()
            or expected_metadata.st_mode & 0o077
        ):
            raise RuntimeError("acceptance journal connected inode changed")
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=5,
                factory=_ClosingSQLiteConnection,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA cache_spill=OFF")
            connection.execute("PRAGMA journal_mode=WAL").fetchone()
            current = self.path.lstat()
            if (
                not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino) != expected_main
            ):
                raise RuntimeError("acceptance journal connected inode changed")
            if self.protected_namespace:
                self._validate_protected_namespace()
        except OSError as exc:
            if connection is not None:
                connection.close()
            if self.protected_namespace:
                raise RuntimeError("acceptance journal protected namespace changed") from exc
            raise
        except BaseException:
            if connection is not None:
                connection.close()
            raise
        if not self.protected_namespace:
            self.path.chmod(0o600)
        self._secure_auxiliary_files()
        return connection

    @staticmethod
    def _entry_sha256(
        *,
        collector_id: str,
        kind: str,
        identity: str,
        payload_json: str,
        created_at: str,
        previous_entry_sha256: str,
    ) -> str:
        return journal_entry_sha256(
            collector_id=collector_id,
            kind=kind,
            identity=identity,
            payload_json=payload_json,
            created_at=created_at,
            previous_entry_sha256=previous_entry_sha256,
        )

    def _insert_entry(
        self,
        connection: sqlite3.Connection,
        *,
        collector_id: str,
        kind: str,
        identity: str,
        encoded: str,
        created_at: str,
    ) -> None:
        prior = connection.execute(
            """
            SELECT entry_sha256 FROM acceptance_entries
            WHERE collector_id = ? ORDER BY entry_id DESC LIMIT 1
            """,
            (collector_id,),
        ).fetchone()
        previous = "" if prior is None else str(prior["entry_sha256"])
        entry_sha256 = self._entry_sha256(
            collector_id=collector_id,
            kind=kind,
            identity=identity,
            payload_json=encoded,
            created_at=created_at,
            previous_entry_sha256=previous,
        )
        connection.execute(
            """
            INSERT INTO acceptance_entries
                (
                    collector_id, kind, identity, payload_json, created_at,
                    previous_entry_sha256, entry_sha256
                )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                collector_id,
                kind,
                identity,
                encoded,
                created_at,
                previous,
                entry_sha256,
            ),
        )

    @property
    def database_bytes(self) -> int:
        self._secure_auxiliary_files()
        return sum(
            candidate.stat().st_size
            for candidate in (
                self.path,
                Path(f"{self.path}-wal"),
                Path(f"{self.path}-shm"),
            )
            if candidate.exists()
        )

    def _enforce_database_bound(self, connection: sqlite3.Connection) -> None:
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        wal_path = Path(f"{self.path}-wal")
        wal_bytes = wal_path.stat().st_size if wal_path.exists() else 0
        shm_path = Path(f"{self.path}-shm")
        shm_bytes = shm_path.stat().st_size if shm_path.exists() else 0
        projected_wal_bytes = 0 if page_count == 0 else 32 + page_count * (page_size + 24)
        if (
            page_count * page_size + wal_bytes + projected_wal_bytes + shm_bytes
            > self.max_database_bytes
        ):
            raise RuntimeError("acceptance journal byte bound reached")

    def _commit_bounded(self, connection: sqlite3.Connection) -> None:
        """Commit, truncate the WAL, and verify the physical byte ceiling."""
        self._enforce_database_bound(connection)
        connection.commit()
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None:
            raise RuntimeError("acceptance journal checkpoint is unavailable")
        self._secure_auxiliary_files()
        if self.database_bytes > self.max_database_bytes:
            raise RuntimeError("acceptance journal physical byte bound reached")

    def append(
        self,
        *,
        collector_id: str,
        kind: Literal[
            "start",
            "sample",
            "fault_intent",
            "fault_claim",
            "fault_ack",
            "finalize",
        ],
        identity: str,
        payload: dict[str, object],
        created_at: datetime,
    ) -> None:
        expected_schema = _DURABLE_ENTRY_SCHEMAS.get(kind)
        if (
            expected_schema is None
            or not isinstance(payload, dict)
            or payload.get("schema_version") != expected_schema
        ):
            raise ValueError("acceptance journal entry schema is invalid")
        _reject_secret_like(payload)
        encoded = _canonical_json(payload)
        entry_limit = (
            _MAX_FINAL_ENTRY_BYTES
            if kind == "finalize"
            else min(self.max_entry_bytes, _MAX_SAMPLE_ENTRY_BYTES)
            if kind == "sample"
            else self.max_entry_bytes
        )
        if len(encoded.encode("utf-8")) > entry_limit:
            raise ValueError("acceptance journal entry exceeds its finite bound")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if (
                    kind != "finalize"
                    and connection.execute(
                        "SELECT 1 FROM acceptance_entries "
                        "WHERE collector_id = ? AND kind = 'finalize' "
                        "LIMIT 1",
                        (collector_id,),
                    ).fetchone()
                ):
                    raise RuntimeError("acceptance journal session is sealed")
                count = connection.execute(
                    "SELECT COUNT(*) FROM acceptance_entries WHERE collector_id = ?",
                    (collector_id,),
                ).fetchone()[0]
                if count >= self.max_entries:
                    raise RuntimeError("acceptance journal session is full")
                total_count = connection.execute(
                    "SELECT COUNT(*) FROM acceptance_entries"
                ).fetchone()[0]
                if total_count >= self.max_total_entries:
                    raise RuntimeError("acceptance journal global entry bound reached")
                if kind == "start" and count == 0:
                    sessions = connection.execute(
                        "SELECT COUNT(DISTINCT collector_id) FROM acceptance_entries"
                    ).fetchone()[0]
                    if sessions >= self.max_sessions:
                        raise RuntimeError("acceptance journal session bound reached")
                if kind == "sample":
                    connection.execute(
                        "INSERT OR IGNORE INTO acceptance_session_usage "
                        "(collector_id, sample_bytes) VALUES (?, 0)",
                        (collector_id,),
                    )
                    updated = connection.execute(
                        "UPDATE acceptance_session_usage "
                        "SET sample_bytes = sample_bytes + ? "
                        "WHERE collector_id = ? "
                        "AND sample_bytes + ? <= ?",
                        (
                            len(encoded.encode()),
                            collector_id,
                            len(encoded.encode()),
                            _MAX_SESSION_SAMPLE_BYTES,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise RuntimeError("acceptance journal sample byte bound reached")
                self._insert_entry(
                    connection,
                    collector_id=collector_id,
                    kind=kind,
                    identity=identity,
                    encoded=encoded,
                    created_at=_utc(
                        created_at,
                        "journal timestamp",
                    ).isoformat(),
                )
                self._commit_bounded(connection)
        except sqlite3.IntegrityError as exc:
            raise RuntimeError("acceptance journal identity already exists") from exc

    def begin_session(
        self,
        *,
        collector_id: str,
        start_payload: dict[str, object],
        fault_intents: tuple[dict[str, object], ...],
        reserved_entries: int,
        reserved_bytes: int,
        created_at: datetime,
    ) -> None:
        """Atomically persist the session and all 16 deterministic fault intents."""
        payloads = (("start", "start", start_payload),) + tuple(
            ("fault_intent", str(item["command_id"]), item) for item in fault_intents
        )
        if (
            len(fault_intents) != 16
            or len({str(item["command_id"]) for item in fault_intents}) != 16
        ):
            raise ValueError("acceptance session requires 16 unique fault intents")
        encoded_payloads: list[tuple[str, str, str]] = []
        for kind, identity, payload in payloads:
            _reject_secret_like(payload)
            encoded = _canonical_json(payload)
            if len(encoded.encode("utf-8")) > self.max_entry_bytes:
                raise ValueError("acceptance journal entry exceeds its finite bound")
            encoded_payloads.append((kind, identity, encoded))
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM acceptance_entries WHERE collector_id = ? LIMIT 1",
                    (collector_id,),
                ).fetchone():
                    raise RuntimeError("acceptance collector session already exists")
                total_count = int(
                    connection.execute("SELECT COUNT(*) FROM acceptance_entries").fetchone()[0]
                )
                session_count = int(
                    connection.execute(
                        "SELECT COUNT(DISTINCT collector_id) FROM acceptance_entries"
                    ).fetchone()[0]
                )
                reserved = connection.execute(
                    "SELECT COALESCE(SUM(reserved_entries), 0), "
                    "COALESCE(SUM(reserved_bytes), 0), COUNT(*) "
                    "FROM acceptance_reservations"
                ).fetchone()
                if (
                    len(encoded_payloads) > self.max_entries
                    or total_count + len(encoded_payloads) > self.max_total_entries
                    or session_count >= self.max_sessions
                    or int(reserved[0]) + reserved_entries > self.max_total_entries
                    or int(reserved[1]) + reserved_bytes + self.database_bytes
                    > self.max_database_bytes
                    or int(reserved[2]) >= self.max_sessions
                ):
                    raise RuntimeError("acceptance journal session or global bound reached")
                connection.execute(
                    "INSERT INTO acceptance_reservations "
                    "(collector_id, reserved_entries, reserved_bytes) "
                    "VALUES (?, ?, ?)",
                    (collector_id, reserved_entries, reserved_bytes),
                )
                timestamp = _utc(
                    created_at,
                    "journal timestamp",
                ).isoformat()
                for kind, identity, encoded in encoded_payloads:
                    self._insert_entry(
                        connection,
                        collector_id=collector_id,
                        kind=kind,
                        identity=identity,
                        encoded=encoded,
                        created_at=timestamp,
                    )
                self._commit_bounded(connection)
        except sqlite3.IntegrityError as exc:
            raise RuntimeError("acceptance journal session identity already exists") from exc

    def claim_fault(
        self,
        *,
        collector_id: str,
        command_id: str,
        payload: dict[str, object],
        created_at: datetime,
    ) -> tuple[Literal["CLAIMED", "COMMITTED"], dict[str, object]]:
        """CAS one PREPARED intent to CLAIMED, returning durable retry state."""
        _reject_secret_like(payload)
        encoded = _canonical_json(payload)
        if len(encoded.encode("utf-8")) > self.max_entry_bytes:
            raise ValueError("acceptance journal entry exceeds its finite bound")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            committed = connection.execute(
                """
                SELECT payload_json FROM acceptance_entries
                WHERE collector_id = ? AND kind = 'fault_ack' AND identity = ?
                """,
                (collector_id, command_id),
            ).fetchone()
            if committed is not None:
                return "COMMITTED", _decode_durable_entry(
                    "fault_ack",
                    committed["payload_json"],
                )
            if connection.execute(
                "SELECT 1 FROM acceptance_entries "
                "WHERE collector_id = ? AND kind = 'finalize' LIMIT 1",
                (collector_id,),
            ).fetchone():
                raise RuntimeError("acceptance journal session is sealed")
            claimed = connection.execute(
                """
                SELECT payload_json FROM acceptance_entries
                WHERE collector_id = ? AND kind = 'fault_claim' AND identity = ?
                """,
                (collector_id, command_id),
            ).fetchone()
            if claimed is not None:
                if claimed["payload_json"] != encoded:
                    raise RuntimeError("acceptance fault claim retry payload changed")
                return "CLAIMED", _decode_durable_entry(
                    "fault_claim",
                    claimed["payload_json"],
                )
            intent = connection.execute(
                """
                SELECT payload_json FROM acceptance_entries
                WHERE collector_id = ? AND kind = 'fault_intent' AND identity = ?
                """,
                (collector_id, command_id),
            ).fetchone()
            if intent is None:
                raise RuntimeError("acceptance fault intent is unavailable")
            intent_payload = _decode_durable_entry(
                "fault_intent",
                intent["payload_json"],
            )
            if (
                intent_payload.get("command_id") != command_id
                or payload.get("command_id") != command_id
            ):
                raise RuntimeError("acceptance fault claim differs from intent")
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM acceptance_entries WHERE collector_id = ?",
                    (collector_id,),
                ).fetchone()[0]
            )
            total_count = int(
                connection.execute("SELECT COUNT(*) FROM acceptance_entries").fetchone()[0]
            )
            if count >= self.max_entries or total_count >= self.max_total_entries:
                raise RuntimeError("acceptance journal entry bound reached")
            self._insert_entry(
                connection,
                collector_id=collector_id,
                kind="fault_claim",
                identity=command_id,
                encoded=encoded,
                created_at=_utc(
                    created_at,
                    "journal timestamp",
                ).isoformat(),
            )
            self._commit_bounded(connection)
            return "CLAIMED", payload

    def entries(
        self,
        collector_id: str,
        *,
        kind: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        with self._verification_lock, self._connect() as connection:
            connection.execute("BEGIN")
            self._verify_incremental(connection, collector_id)
            query = (
                "SELECT entry_id, kind, identity, payload_json, created_at, "
                "previous_entry_sha256, entry_sha256 "
                "FROM acceptance_entries WHERE collector_id = ?"
            )
            parameters: tuple[object, ...] = (collector_id,)
            if kind is not None:
                query += " AND kind = ?"
                parameters = (collector_id, kind)
            rows = connection.execute(
                query + " ORDER BY entry_id",
                parameters,
            ).fetchall()
            expected_count = (
                sum(
                    self._verified_kind_counts.get(
                        collector_id,
                        Counter(),
                    ).values()
                )
                if kind is None
                else self._verified_kind_counts.get(
                    collector_id,
                    Counter(),
                )[kind]
            )
            if len(rows) != expected_count:
                raise RuntimeError("acceptance journal verified rows changed")
            verified = tuple(
                (
                    str(row["kind"]),
                    self._trusted_payload_json(collector_id, row),
                )
                for row in rows
            )
        return tuple(
            _decode_durable_entry(row_kind, payload_json)
            for row_kind, payload_json in verified
        )

    def iter_entries(
        self,
        collector_id: str,
        *,
        kind: str | None = None,
    ) -> Iterable[dict[str, object]]:
        """Yield verified payloads without retaining decoded history."""
        with self._verification_lock, self._connect() as connection:
            connection.execute("BEGIN")
            self._verify_incremental(connection, collector_id)
            query = (
                "SELECT entry_id, kind, identity, payload_json, created_at, "
                "previous_entry_sha256, entry_sha256 "
                "FROM acceptance_entries WHERE collector_id = ?"
            )
            parameters: tuple[object, ...] = (collector_id,)
            if kind is not None:
                query += " AND kind = ?"
                parameters = (collector_id, kind)
            rows = connection.execute(
                query + " ORDER BY entry_id",
                parameters,
            )
            expected_count = (
                sum(
                    self._verified_kind_counts.get(
                        collector_id,
                        Counter(),
                    ).values()
                )
                if kind is None
                else self._verified_kind_counts.get(
                    collector_id,
                    Counter(),
                )[kind]
            )
            yielded = 0
            for row in rows:
                yielded += 1
                yield _decode_durable_entry(
                    str(row["kind"]),
                    self._trusted_payload_json(collector_id, row),
                )
            if yielded != expected_count:
                raise RuntimeError("acceptance journal verified rows changed")

    @property
    def verification_cache_bytes(self) -> int:
        with self._verification_lock:
            return self._verified_payload_bytes

    def _cache_verified_payload(
        self,
        *,
        collector_id: str,
        entry_id: int,
        payload_json: str,
    ) -> None:
        encoded_bytes = len(payload_json.encode())
        if encoded_bytes > _MAX_VERIFIED_PAYLOAD_CACHE_BYTES:
            return
        key = (collector_id, entry_id)
        existing = self._verified_payloads.pop(key, None)
        if existing is not None:
            self._verified_payload_bytes -= len(existing.encode())
        self._verified_payloads[key] = payload_json
        self._verified_payload_bytes += encoded_bytes
        while self._verified_payload_bytes > _MAX_VERIFIED_PAYLOAD_CACHE_BYTES:
            _old_key, old_payload = self._verified_payloads.popitem(last=False)
            self._verified_payload_bytes -= len(old_payload.encode())

    def _trusted_payload_json(
        self,
        collector_id: str,
        row: sqlite3.Row,
    ) -> str:
        entry_id = int(row["entry_id"])
        trusted_sha256 = self._verified_entry_sha256.get(
            collector_id,
            {},
        ).get(entry_id)
        if trusted_sha256 is None or str(row["entry_sha256"]) != trusted_sha256:
            raise RuntimeError("acceptance journal verified entry changed")

        def digest(payload_json: str) -> str:
            return self._entry_sha256(
                collector_id=collector_id,
                kind=str(row["kind"]),
                identity=str(row["identity"]),
                payload_json=payload_json,
                created_at=str(row["created_at"]),
                previous_entry_sha256=str(row["previous_entry_sha256"]),
            )

        payload_json = str(row["payload_json"])
        if digest(payload_json) == trusted_sha256:
            self._cache_verified_payload(
                collector_id=collector_id,
                entry_id=entry_id,
                payload_json=payload_json,
            )
            return payload_json
        cached = self._verified_payloads.get((collector_id, entry_id))
        if cached is None or digest(cached) != trusted_sha256:
            raise RuntimeError("acceptance journal hash chain is invalid")
        self._verified_payloads.move_to_end((collector_id, entry_id))
        return cached

    def _verify_incremental(
        self,
        connection: sqlite3.Connection,
        collector_id: str,
    ) -> None:
        last_entry_id, previous = self._verified_heads.get(
            collector_id,
            (0, ""),
        )
        if last_entry_id:
            cached = connection.execute(
                "SELECT entry_sha256 FROM acceptance_entries "
                "WHERE collector_id = ? AND entry_id = ?",
                (collector_id, last_entry_id),
            ).fetchone()
            if cached is None or cached["entry_sha256"] != previous:
                raise RuntimeError("acceptance journal verified head changed")
        rows = connection.execute(
            "SELECT entry_id, kind, identity, payload_json, created_at, "
            "previous_entry_sha256, entry_sha256 "
            "FROM acceptance_entries WHERE collector_id = ? "
            "AND entry_id > ? ORDER BY entry_id",
            (collector_id, last_entry_id),
        )
        verified = self._verified_entry_sha256.setdefault(collector_id, {})
        kind_counts = self._verified_kind_counts.setdefault(
            collector_id,
            Counter(),
        )
        latest_entry_ids = self._verified_latest_entry_ids.setdefault(
            collector_id,
            {},
        )
        for row in rows:
            expected = self._entry_sha256(
                collector_id=collector_id,
                kind=str(row["kind"]),
                identity=str(row["identity"]),
                payload_json=str(row["payload_json"]),
                created_at=str(row["created_at"]),
                previous_entry_sha256=previous,
            )
            if row["previous_entry_sha256"] != previous or row["entry_sha256"] != expected:
                raise RuntimeError("acceptance journal hash chain is invalid")
            previous = expected
            last_entry_id = int(row["entry_id"])
            kind = str(row["kind"])
            verified[last_entry_id] = expected
            kind_counts[kind] += 1
            latest_entry_ids[kind] = last_entry_id
            self._cache_verified_payload(
                collector_id=collector_id,
                entry_id=last_entry_id,
                payload_json=str(row["payload_json"]),
            )
        self._verified_heads[collector_id] = (last_entry_id, previous)

    def kind_count(self, collector_id: str, *, kind: str) -> int:
        with self._verification_lock, self._connect() as connection:
            connection.execute("BEGIN")
            self._verify_incremental(connection, collector_id)
            trusted_count = self._verified_kind_counts.get(
                collector_id,
                Counter(),
            )[kind]
            stored_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM acceptance_entries WHERE collector_id = ? AND kind = ?",
                    (collector_id, kind),
                ).fetchone()[0]
            )
            if stored_count != trusted_count:
                raise RuntimeError("acceptance journal verified rows changed")
            return trusted_count

    def entry(
        self,
        collector_id: str,
        *,
        kind: str,
        identity: str,
    ) -> dict[str, object] | None:
        with self._verification_lock, self._connect() as connection:
            connection.execute("BEGIN")
            self._verify_incremental(connection, collector_id)
            row = connection.execute(
                "SELECT entry_id, kind, identity, payload_json, created_at, "
                "previous_entry_sha256, entry_sha256 "
                "FROM acceptance_entries WHERE collector_id = ? "
                "AND kind = ? AND identity = ?",
                (collector_id, kind, identity),
            ).fetchone()
            payload_json = None if row is None else self._trusted_payload_json(collector_id, row)
        return (
            None
            if payload_json is None
            else _decode_durable_entry(kind, payload_json)
        )

    def latest_entry(
        self,
        collector_id: str,
        *,
        kind: str,
    ) -> dict[str, object] | None:
        with self._verification_lock, self._connect() as connection:
            connection.execute("BEGIN")
            self._verify_incremental(connection, collector_id)
            row = connection.execute(
                "SELECT entry_id, kind, identity, payload_json, created_at, "
                "previous_entry_sha256, entry_sha256 "
                "FROM acceptance_entries WHERE collector_id = ? "
                "AND kind = ? ORDER BY entry_id DESC LIMIT 1",
                (collector_id, kind),
            ).fetchone()
            expected_entry_id = self._verified_latest_entry_ids.get(
                collector_id,
                {},
            ).get(kind)
            if (row is None) != (expected_entry_id is None) or (
                row is not None and int(row["entry_id"]) != expected_entry_id
            ):
                raise RuntimeError("acceptance journal verified rows changed")
            payload_json = None if row is None else self._trusted_payload_json(collector_id, row)
        return (
            None
            if payload_json is None
            else _decode_durable_entry(kind, payload_json)
        )

    def has_kind(self, collector_id: str, *, kind: str) -> bool:
        return self.kind_count(collector_id, kind=kind) > 0

    def entry_count(self, collector_id: str) -> int:
        with self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM acceptance_entries WHERE collector_id = ?",
                    (collector_id,),
                ).fetchone()[0]
            )

    def total_entry_count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM acceptance_entries").fetchone()[0])

    def session_count(self) -> int:
        with self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(DISTINCT collector_id) FROM acceptance_entries"
                ).fetchone()[0]
            )

    def finalized(self, collector_id: str) -> bool:
        return self.has_kind(collector_id, kind="finalize")

    def chain_head(self, collector_id: str) -> tuple[str, int]:
        """Stream and return the verified journal head and exact entry count."""
        with self._connect() as connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                """
                SELECT kind, identity, payload_json, created_at,
                       previous_entry_sha256, entry_sha256
                FROM acceptance_entries
                WHERE collector_id = ? ORDER BY entry_id
                """,
                (collector_id,),
            )
            previous = ""
            count = 0
            for row in rows:
                expected = self._entry_sha256(
                    collector_id=collector_id,
                    kind=str(row["kind"]),
                    identity=str(row["identity"]),
                    payload_json=str(row["payload_json"]),
                    created_at=str(row["created_at"]),
                    previous_entry_sha256=previous,
                )
                if row["previous_entry_sha256"] != previous or row["entry_sha256"] != expected:
                    raise RuntimeError("acceptance journal hash chain is invalid")
                previous = expected
                count += 1
        if not count:
            raise RuntimeError("acceptance journal chain head is unavailable")
        return previous, count

    def attestation(
        self,
        collector_id: str,
    ) -> tuple[dict[str, object], bytes] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json, signature_hex "
                "FROM acceptance_attestations WHERE collector_id = ?",
                (collector_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row["payload_json"])
            signature = bytes.fromhex(str(row["signature_hex"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("acceptance run attestation storage is invalid") from exc
        if not isinstance(payload, dict) or len(signature) != 64:
            raise RuntimeError("acceptance run attestation storage is invalid")
        return payload, signature

    def bind_finalize_request(
        self,
        *,
        collector_id: str,
        payload: dict[str, object],
    ) -> None:
        _reject_secret_like(payload)
        encoded = _canonical_json(payload)
        if len(encoded.encode()) > MAX_ACCEPTANCE_ENVELOPE_BYTES:
            raise ValueError("acceptance finalize request is unbounded")
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO acceptance_finalize_requests "
                    "(collector_id, request_sha256, request_json) "
                    "VALUES (?, ?, ?)",
                    (collector_id, digest, encoded),
                )
                self._commit_bounded(connection)
        except sqlite3.IntegrityError:
            with self._connect() as connection:
                existing = connection.execute(
                    "SELECT request_sha256, request_json "
                    "FROM acceptance_finalize_requests "
                    "WHERE collector_id = ?",
                    (collector_id,),
                ).fetchone()
            if (
                existing is None
                or existing["request_sha256"] != digest
                or existing["request_json"] != encoded
            ):
                raise RuntimeError("acceptance finalize retry request changed")

    def store_attestation(
        self,
        *,
        collector_id: str,
        payload: dict[str, object],
        signature: bytes,
    ) -> None:
        encoded = _canonical_json(payload)
        if len(encoded.encode()) > _MAX_ENTRY_BYTES or len(signature) != 64:
            raise ValueError("acceptance run attestation is invalid")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT kind, identity, payload_json, created_at, "
                    "previous_entry_sha256, entry_sha256 "
                    "FROM acceptance_entries WHERE collector_id = ? "
                    "ORDER BY entry_id",
                    (collector_id,),
                )
                previous = ""
                count = 0
                final_kind = ""
                for row in rows:
                    expected = self._entry_sha256(
                        collector_id=collector_id,
                        kind=str(row["kind"]),
                        identity=str(row["identity"]),
                        payload_json=str(row["payload_json"]),
                        created_at=str(row["created_at"]),
                        previous_entry_sha256=previous,
                    )
                    if row["previous_entry_sha256"] != previous or row["entry_sha256"] != expected:
                        raise RuntimeError("acceptance journal hash chain is invalid")
                    previous = expected
                    count += 1
                    final_kind = str(row["kind"])
                if (
                    not count
                    or payload.get("journal_root_sha256") != previous
                    or payload.get("journal_entry_count") != count
                    or final_kind != "finalize"
                ):
                    raise RuntimeError("run attestation does not bind the final journal root")
                connection.execute(
                    """
                    INSERT INTO acceptance_attestations
                        (collector_id, payload_json, signature_hex)
                    VALUES (?, ?, ?)
                    """,
                    (collector_id, encoded, signature.hex()),
                )
                self._commit_bounded(connection)
        except sqlite3.IntegrityError:
            existing = self.attestation(collector_id)
            if existing != (payload, signature):
                raise RuntimeError("acceptance run attestation retry changed")

    def export_proof(
        self,
        *,
        collector_id: str,
        header: AcceptanceJournalProofHeaderV2,
        run_record_sha256: str,
        proof_store: AcceptanceProofStore,
    ) -> ExportedAcceptanceJournalProofV2:
        """Stream the sealed verified chain into one atomic canonical JSONL proof."""
        if (
            type(header) is not AcceptanceJournalProofHeaderV2
            or header.schema_version != "acceptance-journal-proof-header.v2"
        ):
            raise ValueError("acceptance proof publication requires one exact V2 header")
        if (
            len(run_record_sha256) != 64
            or any(character not in "0123456789abcdef" for character in run_record_sha256)
        ):
            raise ValueError("acceptance proof run record digest is invalid")
        if header.collector_id != collector_id:
            raise ValueError("acceptance proof header collector differs")
        state: dict[str, object] = {}

        def chunks() -> Iterable[bytes]:
            yield canonical_proof_line(header)
            with self._verification_lock, self._connect() as connection:
                connection.execute("BEGIN")
                self._verify_incremental(connection, collector_id)
                expected_count = sum(
                    self._verified_kind_counts.get(
                        collector_id,
                        Counter(),
                    ).values()
                )
                cursor = connection.execute(
                    "SELECT entry_id, kind, identity, payload_json, created_at, "
                    "previous_entry_sha256, entry_sha256 "
                    "FROM acceptance_entries WHERE collector_id = ? "
                    "ORDER BY entry_id",
                    (collector_id,),
                )
                previous = ""
                counts: Counter[str] = Counter()
                ordinal = 0
                for row in cursor:
                    ordinal += 1
                    payload_json = self._trusted_payload_json(collector_id, row)
                    payload = _decode_durable_entry(
                        str(row["kind"]),
                        payload_json,
                    )
                    if canonical_json_bytes(payload).decode() != payload_json:
                        raise RuntimeError("acceptance journal payload is not canonical JSON")
                    entry = AcceptanceJournalProofEntryV2(
                        schema_version="acceptance-journal-proof-entry.v2",
                        ordinal=ordinal,
                        collector_id=collector_id,
                        kind=str(row["kind"]),
                        identity=str(row["identity"]),
                        payload=payload,
                        created_at=str(row["created_at"]),
                        previous_entry_sha256=str(row["previous_entry_sha256"]),
                        entry_sha256=str(row["entry_sha256"]),
                    )
                    expected = journal_entry_sha256(
                        collector_id=collector_id,
                        kind=entry.kind,
                        identity=entry.identity,
                        payload_json=payload_json,
                        created_at=entry.created_at,
                        previous_entry_sha256=previous,
                    )
                    if entry.previous_entry_sha256 != previous or entry.entry_sha256 != expected:
                        raise RuntimeError("acceptance journal hash chain is invalid")
                    previous = entry.entry_sha256
                    counts[entry.kind] += 1
                    yield canonical_proof_line(entry)
                if ordinal != expected_count or counts["finalize"] != 1:
                    raise RuntimeError("acceptance proof requires one sealed exact chain")
                kind_counts = JournalKindCountsV2.model_validate(
                    {kind: counts[kind] for kind in JournalKindCountsV2.model_fields}
                )
                trailer = AcceptanceJournalProofTrailerV2(
                    schema_version="acceptance-journal-proof-trailer.v2",
                    collector_id=collector_id,
                    entry_count=ordinal,
                    kind_counts=kind_counts,
                    journal_final_root_sha256=previous,
                    run_record_sha256=run_record_sha256,
                )
                state["trailer"] = trailer
                state["line_count"] = ordinal + 2
                yield canonical_proof_line(trailer)

        published = proof_store.publish_chunks(collector_id, chunks())
        trailer = state.get("trailer")
        line_count = state.get("line_count")
        if not isinstance(trailer, AcceptanceJournalProofTrailerV2) or not isinstance(
            line_count,
            int,
        ):
            raise RuntimeError("acceptance proof export did not reach its trailer")
        return ExportedAcceptanceJournalProofV2(
            published=published,
            header=header,
            trailer=trailer,
            line_count=line_count,
        )


def _coverage_cadence(duration_seconds: float) -> float:
    if duration_seconds <= 0:
        raise ValueError("acceptance coverage span is empty")
    intervals = max(1, math.ceil(duration_seconds / 60))
    return duration_seconds / intervals


def _append_identity(identities: list[str], value: str) -> None:
    if not identities or identities[-1] != value:
        if value in identities:
            raise ValueError("acceptance boot identity regressed")
        identities.append(value)


def _fault_command_id(
    binding: CollectorBindingV2,
    fault: ScheduledFaultV2,
    phase: str,
) -> str:
    if phase not in {"inject", "recover"}:
        raise ValueError("fault command phase is invalid")
    payload = {
        **binding.response_fields(),
        "fault_id": fault.fault_id,
        "phase": phase,
        "commanded_monotonic_offset_seconds": (
            fault.offset_seconds
            if phase == "inject"
            else fault.offset_seconds + fault.duration_seconds
        ),
    }
    return f"command-{hashlib.sha256(_canonical_json(payload).encode()).hexdigest()}"


class AcceptanceAuthority:
    """Validate commands, persist observations, and publish one bound final record."""

    def __init__(
        self,
        *,
        journal: SQLiteAcceptanceAuthorityJournal,
        adapter: TargetAcceptanceAdapter | None = None,
        signer: AcceptanceRunSigner | None = None,
        proof_store: AcceptanceProofStore | None = None,
        trust_context: AcceptanceAuthorityTrustContextV2 | None = None,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic_clock: Callable[[], float],
        host_boot_id_provider: Callable[[], str] = read_host_boot_id,
    ) -> None:
        if (
            not callable(wall_clock)
            or not callable(monotonic_clock)
            or not callable(host_boot_id_provider)
        ):
            raise ValueError("acceptance authority dependencies are unavailable")
        if trust_context is not None:
            _require_authority_trust_context(trust_context)
        self.journal = journal
        self.adapter = adapter
        self.signer = signer
        self.proof_store = proof_store
        self.trust_context = trust_context
        if signer is not None and not journal.protected_namespace:
            raise ValueError("acceptance signing requires a protected journal namespace")
        if (signer is None) != (proof_store is None):
            raise ValueError("acceptance signer and proof store must be configured together")
        if (
            trust_context is not None
            and signer is not None
            and signer.public_key_spki_sha256 != trust_context.trust.policy.roles.run_spki_sha256
        ):
            raise ValueError("acceptance signer differs from the verified run role")
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock
        self.host_boot_id_provider = host_boot_id_provider

    def _require_trust_binding(self, binding: CollectorBindingV2) -> None:
        if self.trust_context is not None:
            _require_authority_trust_context(self.trust_context)
        if self.trust_context is not None and binding.trust_binding != self.trust_context.binding:
            raise RuntimeError("acceptance collector trust binding differs from boot trust")

    def _validate_target_start(
        self,
        request: AcceptanceStartRequestV2,
    ) -> None:
        context = self.trust_context
        if context is None:
            return
        _require_authority_trust_context(context)
        self._require_trust_binding(request)
        if (
            request.site_id != context.configured_site_id
            or request.gate != context.configured_gate
            or request.manifest_sha256 != context.trust.manifest.manifest_sha256
            or request.launch != context.launch
            or request.camera_ids != context.camera_ids
            or request.workloads != context.workloads
            or request.fault_schedule != context.fault_schedule
            or request.fault_schedule_sha256
            != canonical_fault_schedule_sha256(context.fault_schedule)
        ):
            raise RuntimeError("acceptance start differs from the signed manifest context")

    def readiness_probe(self) -> None:
        """Recheck boot trust, signer identity, and the protected journal."""
        context = self.trust_context
        if context is None or self.signer is None:
            raise RuntimeError("acceptance target trust is unavailable")
        _require_authority_trust_context(context)
        if (
            context.binding != build_acceptance_trust_binding(context.trust)
            or context.configured_site_id != context.trust.policy.site_id
            or context.configured_campaign_id != context.trust.policy.campaign_id
            or context.configured_gate not in context.trust.policy.allowed_gates
            or self.signer.public_key_spki_sha256 != context.trust.policy.roles.run_spki_sha256
        ):
            raise RuntimeError("acceptance target trust changed")
        self.journal.readiness_probe()

    @staticmethod
    def _validate_sample_health_intervals(
        *,
        start: AcceptanceStartRequestV2,
        previous: AcceptanceSampleObservationV2 | None,
        observation: AcceptanceSampleObservationV2,
        previous_offset: float,
        current_offset: float,
    ) -> None:
        if current_offset == 0:
            if observation.health_intervals:
                raise ValueError("initial acceptance sample cannot contain intervals")
            return
        if previous is None:
            raise ValueError("acceptance health interval has no initial state")
        ordered: list[CameraHealthIntervalObservationV2] = []
        previous_by_camera = {item.camera_id: item for item in previous.cameras}
        current_by_camera = {item.camera_id: item for item in observation.cameras}
        for camera_id in start.camera_ids:
            intervals = tuple(
                item for item in observation.health_intervals if item.camera_id == camera_id
            )
            if (
                not intervals
                or intervals[0].started_monotonic_offset_seconds != previous_offset
                or intervals[-1].ended_monotonic_offset_seconds != current_offset
                or intervals[0].state != previous_by_camera[camera_id].state
                or intervals[-1].state != current_by_camera[camera_id].state
                or any(
                    current.started_monotonic_offset_seconds != prior.ended_monotonic_offset_seconds
                    for prior, current in zip(intervals, intervals[1:])
                )
            ):
                raise ValueError("camera health intervals do not exactly partition sample window")
            ordered.extend(intervals)
        if tuple(ordered) != observation.health_intervals:
            raise ValueError(
                "camera health intervals have duplicate, unknown, or unordered identity"
            )

    @staticmethod
    def _derive_sample_evidence(
        *,
        start: AcceptanceStartRequestV2,
        started_at: datetime,
        samples: Iterable[AcceptanceSampleObservationV2],
        traces: tuple[FaultStateTraceV2, ...],
    ) -> dict[str, object]:
        health_intervals_by_camera: dict[
            str,
            list[CameraHealthIntervalObservationV2],
        ] = {camera_id: [] for camera_id in start.camera_ids}
        counter_totals: dict[str, dict[str, list[int]]] = {
            workload.camera_id: {
                module: [0, 0, 0] for module, rate in workload.analytics_hz.items() if rate > 0
            }
            for workload in start.workloads
        }
        queue_counts: dict[str, Counter[float]] = {
            camera_id: Counter() for camera_id in start.camera_ids
        }
        queue_cadences: dict[str, set[float]] = {camera_id: set() for camera_id in start.camera_ids}
        final_cameras: dict[str, CameraAcceptanceObservationV2] = {}
        resource_samples: list[ResourceSampleV2] = []
        sample_boot_evidence: list[tuple[datetime, str, str]] = []
        prior_boot_pair: tuple[str, str] | None = None
        previous_observed_at: datetime | None = None
        first_observed_at: datetime | None = None
        ended_at: datetime | None = None
        cadence: float | None = None
        sample_count = 0
        for sample in samples:
            observed_at = sample.observed_at
            if first_observed_at is None:
                first_observed_at = observed_at
            elif previous_observed_at is not None:
                gap = (observed_at - previous_observed_at).total_seconds()
                if cadence is None:
                    cadence = gap
                if not 0 < gap <= 60 or not math.isclose(gap, cadence, abs_tol=1e-9):
                    raise ValueError("acceptance sample cadence is not exact and continuous")
            camera_by_id = {camera.camera_id: camera for camera in sample.cameras}
            if tuple(camera_by_id) != start.camera_ids:
                raise ValueError("acceptance sample camera identity differs from start")
            for interval in sample.health_intervals:
                if interval.camera_id not in health_intervals_by_camera:
                    raise ValueError("acceptance sample health identity differs from start")
                health_intervals_by_camera[interval.camera_id].append(interval)
            for camera_id, camera in camera_by_id.items():
                expected_counters = counter_totals[camera_id]
                if set(item.module for item in camera.counters) != set(expected_counters):
                    raise ValueError("acceptance sample analytic identity differs from start")
                for counter in camera.counters:
                    totals = expected_counters[counter.module]
                    totals[0] += counter.scheduled_samples
                    totals[1] += counter.processed_samples
                    totals[2] += counter.dropped_samples
                for run in _aggregate_queue_age_runs(camera.queue_age_runs):
                    queue_counts[camera_id][run.age_seconds] += run.samples
                queue_cadences[camera_id].add(camera.queue_observation_cadence_seconds)
                final_cameras[camera_id] = camera
            boot_pair = (
                sample.cameras[0].runtime_boot_id,
                sample.cameras[0].api_boot_id,
            )
            if boot_pair != prior_boot_pair:
                sample_boot_evidence.append((observed_at, boot_pair[0], boot_pair[1]))
                prior_boot_pair = boot_pair
            resource_samples.append(sample.resource)
            previous_observed_at = observed_at
            ended_at = observed_at
            sample_count += 1
        if (
            sample_count < 2
            or cadence is None
            or ended_at is None
            or first_observed_at != started_at
        ):
            raise ValueError("acceptance sample coverage is incomplete")

        health_spans: list[CameraHealthSpanV2] = []
        work_spans: list[WorkAccountingSpanV2] = []
        queue_coverage: list[CameraQueueCoverageV2] = []
        cameras: list[CameraRunRecordV2] = []
        source_faults = tuple(
            fault
            for fault in start.fault_schedule
            if fault.kind in {"camera_loss", "network_pause"}
        )
        degraded_trace_by_fault = {
            trace.fault_id: trace for trace in traces if trace.phase == "degraded"
        }
        recovered_trace_by_fault = {
            trace.fault_id: trace for trace in traces if trace.phase == "recovered"
        }

        for workload in start.workloads:
            camera_id = workload.camera_id
            camera_observed_intervals = tuple(health_intervals_by_camera[camera_id])
            if not camera_observed_intervals:
                raise ValueError("camera health interval coverage is missing")
            boundaries = {
                started_at + timedelta(seconds=interval.started_monotonic_offset_seconds)
                for interval in camera_observed_intervals
            }
            boundaries.update(
                started_at + timedelta(seconds=interval.ended_monotonic_offset_seconds)
                for interval in camera_observed_intervals
            )
            camera_faults = tuple(fault for fault in source_faults if fault.target == camera_id)
            for fault in camera_faults:
                degraded_trace = degraded_trace_by_fault.get(fault.fault_id)
                recovered_trace = recovered_trace_by_fault.get(fault.fault_id)
                if degraded_trace is None or recovered_trace is None:
                    raise ValueError("source fault transition evidence is missing")
                boundaries.add(degraded_trace.observed_at)
                boundaries.add(
                    started_at + timedelta(seconds=fault.offset_seconds + fault.duration_seconds)
                )
                boundaries.add(recovered_trace.observed_at)
            ordered_boundaries = sorted(boundaries)
            raw_segments: list[tuple[datetime, datetime, str]] = []
            for segment_start, segment_end in zip(
                ordered_boundaries,
                ordered_boundaries[1:],
            ):
                midpoint = (
                    (segment_start - started_at).total_seconds()
                    + (segment_end - started_at).total_seconds()
                ) / 2
                observed_state = next(
                    interval.state
                    for interval in camera_observed_intervals
                    if (
                        interval.started_monotonic_offset_seconds
                        <= midpoint
                        < interval.ended_monotonic_offset_seconds
                    )
                )
                active_fault = next(
                    (
                        fault
                        for fault in camera_faults
                        if (
                            degraded_trace_by_fault[fault.fault_id].observed_at - started_at
                        ).total_seconds()
                        <= midpoint
                        < (
                            recovered_trace_by_fault[fault.fault_id].observed_at - started_at
                        ).total_seconds()
                    ),
                    None,
                )
                if active_fault is not None:
                    if (
                        active_fault.expected_degraded not in {"degraded", "offline"}
                        or observed_state != active_fault.expected_degraded
                    ):
                        raise ValueError("camera health intervals contradict source fault state")
                    state = (
                        "source_outage"
                        if midpoint < active_fault.offset_seconds + active_fault.duration_seconds
                        else active_fault.expected_degraded
                    )
                else:
                    state = observed_state
                if (
                    raw_segments
                    and raw_segments[-1][2] == state
                    and raw_segments[-1][1] == segment_start
                ):
                    previous_start, _, previous_state = raw_segments[-1]
                    raw_segments[-1] = (
                        previous_start,
                        segment_end,
                        previous_state,
                    )
                else:
                    raw_segments.append((segment_start, segment_end, state))
            camera_health = tuple(
                CameraHealthSpanV2(
                    camera_id=camera_id,
                    started_at=segment_start,
                    ended_at=segment_end,
                    state=state,
                    cadence_seconds=_coverage_cadence(
                        (segment_end - segment_start).total_seconds()
                    ),
                    observed_samples=round(
                        (segment_end - segment_start).total_seconds()
                        / _coverage_cadence((segment_end - segment_start).total_seconds())
                    )
                    + 1,
                )
                for segment_start, segment_end, state in raw_segments
            )
            health_spans.extend(camera_health)

            final_counters = counter_totals[camera_id]
            camera_work = tuple(
                WorkAccountingSpanV2(
                    camera_id=camera_id,
                    module=module,
                    started_at=started_at,
                    ended_at=ended_at,
                    cadence_seconds=cadence,
                    observed_samples=sample_count,
                    scheduled_samples=totals[0],
                    processed_samples=totals[1],
                    dropped_samples=totals[2],
                )
                for module, totals in final_counters.items()
            )
            work_spans.extend(camera_work)

            queue_runs = tuple(
                QueueAgeRunV2(age_seconds=age_seconds, samples=count)
                for age_seconds, count in sorted(queue_counts[camera_id].items())
            )
            camera_queue_cadences = queue_cadences[camera_id]
            if len(camera_queue_cadences) != 1:
                raise ValueError("camera queue observation cadence changed during run")
            queue_cadence = next(iter(camera_queue_cadences))
            queue_coverage.append(
                CameraQueueCoverageV2(
                    camera_id=camera_id,
                    queue_name="analytics",
                    started_at=started_at,
                    ended_at=ended_at,
                    cadence_seconds=queue_cadence,
                    runs=queue_runs,
                )
            )

            scheduled_total = sum(item.scheduled_samples for item in camera_work)
            processed_total = sum(item.processed_samples for item in camera_work)
            dropped_total = sum(item.dropped_samples for item in camera_work)
            availability_seconds = sum(
                (item.ended_at - item.started_at).total_seconds()
                for item in camera_health
                if item.state == "online"
            )
            source_outage_seconds = sum(
                (item.ended_at - item.started_at).total_seconds()
                for item in camera_health
                if item.state == "source_outage"
            )
            final_camera = final_cameras[camera_id]
            reconnect_seconds = tuple(
                max(
                    0.0,
                    (
                        trace.observed_at
                        - (
                            started_at
                            + timedelta(seconds=(fault.offset_seconds + fault.duration_seconds))
                        )
                    ).total_seconds(),
                )
                for fault in camera_faults
                for trace in traces
                if trace.fault_id == fault.fault_id and trace.phase == "recovered"
            )
            cameras.append(
                CameraRunRecordV2(
                    camera_id=camera_id,
                    scheduled_samples=scheduled_total,
                    processed_samples=processed_total,
                    dropped_samples=dropped_total,
                    availability_seconds=availability_seconds,
                    source_outage_seconds=source_outage_seconds,
                    queue_age_seconds=tuple(item.age_seconds for item in queue_runs),
                    reconnect_seconds=reconnect_seconds,
                    observed_records=processed_total,
                    last_health_at=ended_at,
                    runtime_boot_id=final_camera.runtime_boot_id,
                    api_boot_id=final_camera.api_boot_id,
                )
            )

        boot_evidence = sorted(
            (
                *sample_boot_evidence,
                *(
                    (
                        trace.observed_at,
                        trace.runtime_boot_id,
                        trace.api_boot_id,
                    )
                    for trace in traces
                ),
            ),
            key=lambda item: item[0],
        )
        runtime_boot_ids: list[str] = []
        api_boot_ids: list[str] = []
        for _, runtime_boot_id, api_boot_id in boot_evidence:
            _append_identity(runtime_boot_ids, runtime_boot_id)
            _append_identity(api_boot_ids, api_boot_id)

        resources = tuple(resource_samples)
        disk_limits = {item.disk_limit_bytes for item in resources}
        if len(disk_limits) != 1:
            raise ValueError("acceptance resource disk limit changed during run")
        return {
            "cameras": tuple(cameras),
            "health_spans": tuple(health_spans),
            "work_spans": tuple(work_spans),
            "queue_coverage": tuple(queue_coverage),
            "resources": resources,
            "gpu_percent": tuple(item.gpu_percent_high_water for item in resources),
            "vram_percent": tuple(item.vram_percent_high_water for item in resources),
            "disk_bytes": tuple(item.disk_bytes_high_water for item in resources),
            "disk_limit_bytes": resources[0].disk_limit_bytes,
            "disk_bounded": all(
                item.disk_bytes_high_water <= item.disk_limit_bytes for item in resources
            ),
            "runtime_boot_ids": tuple(runtime_boot_ids),
            "api_boot_ids": tuple(api_boot_ids),
            "measured_effective_throughput_hz": (start.launch.measured_effective_throughput_hz),
            "required_throughput_hz": start.launch.required_throughput_hz,
        }

    def start(self, payload: dict[str, object]) -> dict[str, object]:
        request = AcceptanceStartRequestV2.model_validate(payload)
        self._validate_target_start(request)
        if self.adapter is not None and (
            self.adapter.identity.executable_sha256 != request.launch.acceptance_observer_sha256
            or self.adapter.identity.policy_sha256
            != request.launch.acceptance_observer_policy_sha256
        ):
            raise RuntimeError("configured acceptance observer identity differs from launch")
        if (
            self.signer is not None
            and self.signer.public_key_spki_sha256 != request.launch.run_authority_public_key_spki_sha256
        ):
            raise RuntimeError("configured run authority key differs from signed launch")
        existing_start = self.journal.entries(
            request.collector_id,
            kind="start",
        )
        if existing_start:
            stored_request, _, _, _ = self._stored_session(request)
            if stored_request != request:
                raise RuntimeError("acceptance collector start retry binding changed")
            return AcceptanceStartResponseV2(
                schema_version="acceptance-collector-start-response.v2",
                **request.response_fields(),
            ).model_dump(mode="json")
        duration = 8 * 3600 if request.gate == "8h" else 72 * 3600
        sample_entries = duration // request.sample_interval_seconds + 1
        required_entries = sample_entries + 16 * 3 + 2
        reserved_bytes = (
            min(
                sample_entries * _MAX_SAMPLE_ENTRY_BYTES,
                _MAX_SESSION_SAMPLE_BYTES,
            )
            + _MAX_FINAL_ENTRY_BYTES
            + 8 * 1024 * 1024
        )
        if (
            required_entries > self.journal.max_entries
            or self.journal.total_entry_count() + required_entries > self.journal.max_total_entries
            or self.journal.session_count() >= self.journal.max_sessions
            or self.journal.database_bytes + reserved_bytes > self.journal.max_database_bytes
        ):
            raise RuntimeError("acceptance gate exceeds the durable journal budget")
        execution_ends_at: datetime | None = None
        if self.trust_context is not None:
            grant = authorize_acceptance_execution(
                self.trust_context.trust,
                expected_site_id=self.trust_context.configured_site_id,
                expected_campaign_id=(self.trust_context.configured_campaign_id),
                expected_gate=self.trust_context.configured_gate,
                execution_started_at=self.wall_clock(),
            )
            started_at = grant.execution_started_at
            execution_ends_at = grant.execution_ends_at
        else:
            started_at = _utc(self.wall_clock(), "acceptance start")
        stored = {
            **request.model_dump(mode="json"),
            "started_at": started_at.isoformat(),
            "started_monotonic": self.monotonic_clock(),
            "host_boot_id": self.host_boot_id_provider(),
        }
        if execution_ends_at is not None:
            stored["execution_ends_at"] = execution_ends_at.isoformat()
        intents = tuple(
            {
                "schema_version": "acceptance-fault-intent.v2",
                **request.response_fields(),
                "fault": fault.model_dump(mode="json"),
                "phase": phase,
                "commanded_monotonic_offset_seconds": (
                    fault.offset_seconds
                    if phase == "inject"
                    else fault.offset_seconds + fault.duration_seconds
                ),
                "command_id": _fault_command_id(request, fault, phase),
                "state": "PREPARED",
            }
            for fault in request.fault_schedule
            for phase in ("inject", "recover")
        )
        try:
            self.journal.begin_session(
                collector_id=request.collector_id,
                start_payload=stored,
                fault_intents=intents,
                reserved_entries=required_entries,
                reserved_bytes=reserved_bytes,
                created_at=started_at,
            )
        except RuntimeError:
            try:
                stored_request, _, _, _ = self._stored_session(request)
            except RuntimeError:
                raise
            if stored_request != request:
                raise RuntimeError("acceptance collector start retry binding changed") from None
        return AcceptanceStartResponseV2(
            schema_version="acceptance-collector-start-response.v2",
            **request.response_fields(),
        ).model_dump(mode="json")

    def _stored_session(
        self,
        binding: CollectorBindingV2,
    ) -> tuple[AcceptanceStartRequestV2, datetime, float, str]:
        self._require_trust_binding(binding)
        rows = self.journal.entries(binding.collector_id, kind="start")
        if len(rows) != 1:
            raise RuntimeError("acceptance collector session is unavailable")
        row = dict(rows[0])
        started_at = _utc(
            datetime.fromisoformat(str(row.pop("started_at"))),
            "stored acceptance start",
        )
        stored_execution_ends_at = row.pop("execution_ends_at", None)
        started_monotonic = float(row.pop("started_monotonic"))
        host_boot_id = str(row.pop("host_boot_id"))
        start = AcceptanceStartRequestV2.model_validate(row)
        self._validate_target_start(start)
        if any(
            getattr(start, field) != getattr(binding, field)
            for field in CollectorBindingV2.model_fields
        ):
            raise RuntimeError("acceptance collector session binding mismatch")
        if self.trust_context is not None:
            if stored_execution_ends_at is None:
                raise RuntimeError("trusted acceptance session lacks its original interval")
            grant = authorize_acceptance_execution(
                self.trust_context.trust,
                expected_site_id=self.trust_context.configured_site_id,
                expected_campaign_id=(self.trust_context.configured_campaign_id),
                expected_gate=self.trust_context.configured_gate,
                execution_started_at=started_at,
            )
            execution_ends_at = _utc(
                datetime.fromisoformat(str(stored_execution_ends_at)),
                "stored acceptance end",
            )
            if execution_ends_at != grant.execution_ends_at:
                raise RuntimeError("trusted acceptance session interval changed")
        return start, started_at, started_monotonic, host_boot_id

    def _session(
        self,
        binding: CollectorBindingV2,
        *,
        allow_finalized_replay: bool = False,
    ) -> tuple[AcceptanceStartRequestV2, datetime, float]:
        (
            start,
            started_at,
            started_monotonic,
            host_boot_id,
        ) = self._stored_session(binding)
        if host_boot_id != self.host_boot_id_provider():
            raise RuntimeError("acceptance session cannot resume after a host reboot")
        if self.adapter is not None and (
            self.adapter.identity.executable_sha256 != start.launch.acceptance_observer_sha256
            or self.adapter.identity.policy_sha256 != start.launch.acceptance_observer_policy_sha256
        ):
            raise RuntimeError("configured acceptance observer identity changed")
        if (
            self.signer is not None
            and self.signer.public_key_spki_sha256 != start.launch.run_authority_public_key_spki_sha256
        ):
            raise RuntimeError("configured run authority key changed")
        if not allow_finalized_replay and self.journal.finalized(binding.collector_id):
            raise RuntimeError("acceptance collector session is already finalized")
        return start, started_at, started_monotonic

    def sample(self, payload: dict[str, object]) -> dict[str, object]:
        request = AcceptanceSampleRequestV2.model_validate(payload)
        self._require_trust_binding(request)
        if request.observation is None and self.adapter is None:
            raise ValueError("acceptance sample observation is required")
        start, started_at, started_monotonic = self._session(
            request,
            allow_finalized_replay=True,
        )
        gate_duration = 8 * 3600 if start.gate == "8h" else 72 * 3600
        if request.scheduled_monotonic_offset_seconds > gate_duration:
            raise ValueError("acceptance sample exceeds its exact endurance gate")
        sample_count = self.journal.kind_count(
            request.collector_id,
            kind="sample",
        )
        requested_index, remainder = divmod(
            request.scheduled_monotonic_offset_seconds,
            start.sample_interval_seconds,
        )
        if remainder or not float(requested_index).is_integer() or requested_index < 0:
            raise ValueError("acceptance sample missed its scheduled boundary")
        requested_index = int(requested_index)
        if requested_index < sample_count:
            existing_payload = self.journal.entry(
                request.collector_id,
                kind="sample",
                identity=f"sample-{requested_index:05}",
            )
            if existing_payload is None:
                raise RuntimeError("acceptance sample sequence is incomplete")
            existing = AcceptanceSampleObservationV2.model_validate(existing_payload)
            if request.observation is not None:
                retry = request.observation.model_copy(
                    update={
                        "observed_at": existing.observed_at,
                        "resource": request.observation.resource.model_copy(
                            update={"sampled_at": existing.observed_at}
                        ),
                    }
                )
                if retry != existing:
                    raise RuntimeError("acceptance sample retry evidence changed")
            return AcceptanceSampleResponseV2(
                schema_version="acceptance-collector-sample-response.v2",
                **request.response_fields(),
                observed_records=existing.observed_records,
            ).model_dump(mode="json")
        if self.journal.finalized(request.collector_id):
            raise RuntimeError("acceptance journal session is sealed")
        expected_offset = sample_count * start.sample_interval_seconds
        arrival_offset = self.monotonic_clock() - started_monotonic
        if (
            request.scheduled_monotonic_offset_seconds != expected_offset
            or abs(arrival_offset - expected_offset) > _SAMPLE_ARRIVAL_TOLERANCE_SECONDS
        ):
            raise ValueError("acceptance sample missed its scheduled boundary")
        if request.observation is not None:
            observation = request.observation
        elif self.adapter is not None:
            observation = self.adapter.sample(
                collector_id=request.collector_id,
                launch=start.launch,
                execution=start.execution,
                previous_monotonic_offset_seconds=(
                    0.0 if sample_count == 0 else expected_offset - start.sample_interval_seconds
                ),
                scheduled_monotonic_offset_seconds=float(expected_offset),
            )
        else:
            raise ValueError("acceptance sample observation is required")
        completion_offset = self.monotonic_clock() - started_monotonic
        if abs(completion_offset - expected_offset) > _SAMPLE_ARRIVAL_TOLERANCE_SECONDS:
            raise ValueError("acceptance sample exceeded its scheduled boundary")
        if (
            observation.collector_id != request.collector_id
            or observation.launch_attestation_sha256 != request.launch_attestation_sha256
            or observation.execution_binding_sha256 != request.execution_binding_sha256
            or observation.observer_sha256 != start.launch.acceptance_observer_sha256
            or observation.observer_policy_sha256 != start.launch.acceptance_observer_policy_sha256
            or any(
                not camera.runtime_boot_id.startswith(f"{start.execution.launch_nonce}.")
                for camera in observation.cameras
            )
        ):
            raise ValueError("acceptance sample observation binding mismatch")
        canonical_observed_at = started_at + timedelta(seconds=expected_offset)
        observation = AcceptanceSampleObservationV2.model_validate(
            {
                **observation.model_dump(mode="json"),
                "observed_at": canonical_observed_at,
                "resource": {
                    **observation.resource.model_dump(mode="json"),
                    "sampled_at": canonical_observed_at,
                },
            }
        )
        previous_sample_payload = self.journal.latest_entry(
            request.collector_id,
            kind="sample",
        )
        previous_sample = (
            None
            if previous_sample_payload is None
            else AcceptanceSampleObservationV2.model_validate(previous_sample_payload)
        )
        if (previous_sample is None) != (sample_count == 0):
            raise RuntimeError("acceptance sample cursor is inconsistent")
        previous_at = started_at if previous_sample is None else previous_sample.observed_at
        if tuple(item.camera_id for item in observation.cameras) != start.camera_ids:
            raise ValueError("acceptance sample camera identity differs from start")
        workload_by_camera = {item.camera_id: item for item in start.workloads}
        previous_offset = (previous_at - started_at).total_seconds()
        current_offset = (observation.observed_at - started_at).total_seconds()
        if observation.resource.interval_started_at != (
            None if current_offset == 0 else previous_at
        ):
            raise ValueError("resource interval does not exactly match sample window")
        self._validate_sample_health_intervals(
            start=start,
            previous=previous_sample,
            observation=observation,
            previous_offset=previous_offset,
            current_offset=current_offset,
        )
        source_degraded_offsets: dict[str, float] = {}
        for row in self.journal.entries(
            request.collector_id,
            kind="fault_ack",
        ):
            fault = ScheduledFaultV2.model_validate(row["fault"])
            if fault.kind not in {"camera_loss", "network_pause"} or row["phase"] != "inject":
                continue
            observed_at = _utc(
                datetime.fromisoformat(str(row["observed_at"])),
                "source degraded acknowledgement",
            )
            source_degraded_offsets[fault.fault_id] = (observed_at - started_at).total_seconds()
        expected_observed = 0
        for camera in observation.cameras:
            queue_window = current_offset - previous_offset
            queue_intervals = queue_window / camera.queue_observation_cadence_seconds
            expected_queue_observations = 1 if current_offset == 0 else round(queue_intervals)
            if (
                current_offset > 0
                and not math.isclose(
                    queue_intervals,
                    round(queue_intervals),
                    abs_tol=1e-9,
                )
            ) or sum(item.samples for item in camera.queue_age_runs) != expected_queue_observations:
                raise ValueError("camera queue observations do not exactly cover sample window")
            workload = workload_by_camera[camera.camera_id]
            if (
                camera.source_index != workload.source_index
                or camera.negotiated_codec != workload.codec
                or camera.negotiated_width != workload.width
                or camera.negotiated_height != workload.height
                or camera.negotiated_fps != workload.fps
                or camera.negotiated_bitrate_kbps != workload.bitrate_kbps
            ):
                raise ValueError("negotiated source profile differs from frozen workload")
            expected_modules = {
                module: rate for module, rate in workload.analytics_hz.items() if rate > 0
            }
            if set(item.module for item in camera.counters) != set(expected_modules):
                raise ValueError("acceptance sample analytic identity differs from start")
            camera_source_faults = tuple(
                fault
                for fault in start.fault_schedule
                if fault.kind in {"camera_loss", "network_pause"}
                and fault.target == camera.camera_id
            )
            if any(
                current_offset > fault.offset_seconds
                and fault.fault_id not in source_degraded_offsets
                for fault in camera_source_faults
            ):
                raise ValueError("source work accounting lacks degraded acknowledgement")

            def outage_through(boundary: float) -> float:
                return sum(
                    max(
                        0.0,
                        min(
                            boundary,
                            fault.offset_seconds + fault.duration_seconds,
                        )
                        - source_degraded_offsets.get(
                            fault.fault_id,
                            fault.offset_seconds,
                        ),
                    )
                    for fault in camera_source_faults
                )

            outage_through_previous = outage_through(previous_offset)
            outage_through_current = outage_through(current_offset)
            for counter in camera.counters:
                rate = expected_modules[counter.module]
                expected_scheduled = math.floor(
                    rate * (current_offset - outage_through_current) + 1e-9
                ) - math.floor(rate * (previous_offset - outage_through_previous) + 1e-9)
                if counter.scheduled_samples != expected_scheduled:
                    raise ValueError(
                        "acceptance sample scheduled delta differs from frozen workload"
                    )
                expected_observed += counter.processed_samples
        if observation.observed_records != expected_observed:
            raise ValueError("acceptance sample processed delta is inconsistent")
        identity = f"sample-{sample_count:05}"
        serialized_observation = observation.model_dump(mode="json")
        try:
            self.journal.append(
                collector_id=request.collector_id,
                kind="sample",
                identity=identity,
                payload=serialized_observation,
                created_at=observation.observed_at,
            )
        except RuntimeError:
            concurrent = self.journal.entry(
                request.collector_id,
                kind="sample",
                identity=identity,
            )
            if concurrent != serialized_observation:
                raise
        return AcceptanceSampleResponseV2(
            schema_version="acceptance-collector-sample-response.v2",
            **request.response_fields(),
            observed_records=observation.observed_records,
        ).model_dump(mode="json")

    def prepare_fault(self, payload: dict[str, object]) -> dict[str, object]:
        request = AcceptanceFaultPrepareRequestV2.model_validate(payload)
        self._require_trust_binding(request)
        start, started_at, started_monotonic = self._session(
            request,
            allow_finalized_replay=True,
        )
        schedule = {item.fault_id: item for item in start.fault_schedule}
        if schedule.get(request.fault.fault_id) != request.fault:
            raise ValueError("fault command does not match the frozen schedule")
        command_id = _fault_command_id(request, request.fault, request.phase)
        existing_claim_or_ack = any(
            item.get("command_id") == command_id
            for kind in ("fault_claim", "fault_ack")
            for item in self.journal.entries(request.collector_id, kind=kind)
        )
        elapsed = self.monotonic_clock() - started_monotonic
        if (
            not existing_claim_or_ack
            and abs(elapsed - request.commanded_monotonic_offset_seconds)
            > _COMMAND_ARRIVAL_TOLERANCE_SECONDS
        ):
            raise ValueError("fault command missed its monotonic boundary")
        committed = {
            (str(item["fault"]["fault_id"]), str(item["phase"]))
            for item in self.journal.entries(
                request.collector_id,
                kind="fault_ack",
            )
        }
        if (
            request.phase == "recover"
            and (
                request.fault.fault_id,
                "inject",
            )
            not in committed
        ):
            raise ValueError("fault recovery precedes injection")
        intents = tuple(
            item
            for item in self.journal.entries(
                request.collector_id,
                kind="fault_intent",
            )
            if item.get("command_id") == command_id
        )
        if len(intents) != 1:
            raise RuntimeError("acceptance fault intent is unavailable")
        intent = intents[0]
        expected_intent = {
            "schema_version": "acceptance-fault-intent.v2",
            **request.response_fields(),
            "fault": request.fault.model_dump(mode="json"),
            "phase": request.phase,
            "commanded_monotonic_offset_seconds": (request.commanded_monotonic_offset_seconds),
            "command_id": command_id,
            "state": "PREPARED",
        }
        if intent != expected_intent:
            raise RuntimeError("acceptance fault intent binding changed")
        claimed_at = _utc(self.wall_clock(), "fault claim timestamp")
        state, durable = self.journal.claim_fault(
            collector_id=request.collector_id,
            command_id=command_id,
            payload={
                **expected_intent,
                "schema_version": "acceptance-fault-claim.v2",
                "state": "CLAIMED",
            },
            created_at=claimed_at,
        )
        return AcceptanceFaultPrepareResponseV2.model_validate(
            {
                "schema_version": "acceptance-fault-prepare-response.v2",
                **request.response_fields(),
                "fault_id": request.fault.fault_id,
                "phase": request.phase,
                "commanded_monotonic_offset_seconds": (
                    request.commanded_monotonic_offset_seconds
                ),
                "command_id": command_id,
                "state": state,
                **(
                    {
                        key: durable[key]
                        for key in (
                            "runtime_boot_id",
                            "api_boot_id",
                            "observed_at",
                        )
                        if key in durable
                    }
                    if state == "COMMITTED"
                    else {}
                ),
            }
        ).model_dump(mode="json")

    def acknowledge_fault(self, payload: dict[str, object]) -> dict[str, object]:
        request = AcceptanceFaultAckRequestV2.model_validate(payload)
        self._require_trust_binding(request)
        if request.observation is None and self.adapter is None:
            raise ValueError("independent post-effect fault observation is required")
        start, started_at, started_monotonic = self._session(
            request,
            allow_finalized_replay=True,
        )
        intents = tuple(
            item
            for item in self.journal.entries(
                request.collector_id,
                kind="fault_intent",
            )
            if item.get("command_id") == request.command_id
        )
        claims = tuple(
            item
            for item in self.journal.entries(
                request.collector_id,
                kind="fault_claim",
            )
            if item.get("command_id") == request.command_id
        )
        acknowledgements = tuple(
            item
            for item in self.journal.entries(
                request.collector_id,
                kind="fault_ack",
            )
            if item.get("command_id") == request.command_id
        )
        if len(acknowledgements) == 1:
            recorded = acknowledgements[0]
            if (
                recorded.get("fault", {}).get("fault_id") != request.fault_id
                or recorded.get("phase") != request.phase
                or recorded.get("receipt") != request.receipt.model_dump(mode="json")
                or (
                    request.observation is not None
                    and FaultCommandObservationV2.model_validate(
                        {
                            **{
                                field: recorded.get(field)
                                for field in FaultCommandObservationV2.model_fields
                                if field != "schema_version"
                            },
                            "schema_version": (
                                "acceptance-fault-command-observation.v2"
                            ),
                        }
                    ).model_dump(mode="json")
                    != request.observation.model_dump(mode="json")
                )
            ):
                raise RuntimeError("acceptance fault acknowledgement retry evidence changed")
            return AcceptanceFaultAckResponseV2.model_validate(
                {
                    "schema_version": "acceptance-fault-ack-response.v2",
                    **request.response_fields(),
                    "fault_id": request.fault_id,
                    "phase": request.phase,
                    "commanded_monotonic_offset_seconds": recorded[
                        "commanded_monotonic_offset_seconds"
                    ],
                    "command_id": request.command_id,
                    "state": recorded["state"],
                    "runtime_boot_id": recorded["runtime_boot_id"],
                    "api_boot_id": recorded["api_boot_id"],
                    "execution_binding_sha256": recorded[
                        "execution_binding_sha256"
                    ],
                    "observed_at": recorded["observed_at"],
                }
            ).model_dump(mode="json")
        if self.journal.finalized(request.collector_id):
            raise RuntimeError("acceptance journal session is sealed")
        if len(intents) != 1 or len(claims) != 1:
            raise RuntimeError("acceptance fault must be durably claimed before acknowledgement")
        intent = intents[0]
        if (
            intent.get("fault", {}).get("fault_id") != request.fault_id
            or intent.get("phase") != request.phase
        ):
            raise RuntimeError("acceptance fault acknowledgement binding mismatch")
        fault = ScheduledFaultV2.model_validate(intent["fault"])
        commanded_offset = float(intent["commanded_monotonic_offset_seconds"])
        receipt = request.receipt
        if (
            receipt.command_id != request.command_id
            or receipt.fault_id != request.fault_id
            or receipt.phase != request.phase
            or receipt.target != fault.target
            or receipt.execution_binding_sha256 != request.execution_binding_sha256
            or receipt.executor_sha256 != start.launch.acceptance_adapter_sha256
            or receipt.executor_policy_sha256 != start.launch.acceptance_adapter_policy_sha256
            or receipt.effect_started_at < started_at + timedelta(seconds=commanded_offset)
            or receipt.effect_completed_at
            > _utc(
                self.wall_clock(),
                "fault receipt verification timestamp",
            )
            or (
                fault.kind == "runtime_restart"
                and request.phase == "recover"
                and receipt.pre_runtime_boot_id == receipt.post_runtime_boot_id
            )
            or (
                fault.kind == "api_restart"
                and request.phase == "recover"
                and receipt.pre_api_boot_id == receipt.post_api_boot_id
            )
        ):
            raise ValueError("fault effect receipt is invalid or unbound")
        if request.observation is not None:
            observation = request.observation
        elif self.adapter is not None:
            observation = self.adapter.observe_fault(
                collector_id=request.collector_id,
                launch=start.launch,
                execution=start.execution,
                fault=fault,
                phase=request.phase,
                command_id=request.command_id,
                commanded_monotonic_offset_seconds=commanded_offset,
            )
        else:
            raise ValueError("independent post-effect fault observation is required")
        acknowledged_offset = self.monotonic_clock() - started_monotonic
        if acknowledged_offset < commanded_offset:
            raise ValueError("fault acknowledgement precedes its command")
        if (
            request.phase == "inject"
            and fault.kind in {"camera_loss", "network_pause"}
            and acknowledged_offset >= fault.offset_seconds + fault.duration_seconds
        ):
            raise ValueError("source degraded acknowledgement missed source return")
        expected_state = (
            fault.expected_degraded if request.phase == "inject" else fault.expected_recovery
        )
        if (
            observation.command_id != request.command_id
            or observation.state != expected_state
            or observation.state != receipt.post_state
            or observation.runtime_boot_id != receipt.post_runtime_boot_id
            or observation.api_boot_id != receipt.post_api_boot_id
            or observation.execution_binding_sha256 != request.execution_binding_sha256
            or observation.observer_sha256 != start.launch.acceptance_observer_sha256
            or observation.observer_policy_sha256 != start.launch.acceptance_observer_policy_sha256
            or not observation.runtime_boot_id.startswith(f"{start.execution.launch_nonce}.")
        ):
            raise ValueError("fault adapter did not observe the required state")
        observed_at = started_at + timedelta(seconds=acknowledged_offset)
        recorded = {
            **request.response_fields(),
            "fault": fault.model_dump(mode="json"),
            "phase": request.phase,
            "commanded_monotonic_offset_seconds": commanded_offset,
            **observation.model_dump(mode="json"),
            "receipt": receipt.model_dump(mode="json"),
            "observed_at": observed_at.isoformat(),
            "journal_state": "COMMITTED",
            "schema_version": "acceptance-fault-acknowledgement.v2",
        }
        try:
            self.journal.append(
                collector_id=request.collector_id,
                kind="fault_ack",
                identity=request.command_id,
                payload=recorded,
                created_at=observed_at,
            )
        except RuntimeError:
            concurrent = tuple(
                item
                for item in self.journal.entries(
                    request.collector_id,
                    kind="fault_ack",
                )
                if item.get("command_id") == request.command_id
            )
            if len(concurrent) != 1:
                raise
            winner = dict(concurrent[0])
            loser = dict(recorded)
            winner.pop("observed_at", None)
            loser.pop("observed_at", None)
            if winner != loser:
                raise RuntimeError("concurrent fault acknowledgement evidence changed")
            recorded = concurrent[0]
        return AcceptanceFaultAckResponseV2.model_validate(
            {
                "schema_version": "acceptance-fault-ack-response.v2",
                **request.response_fields(),
                "fault_id": request.fault_id,
                "phase": request.phase,
                "commanded_monotonic_offset_seconds": commanded_offset,
                "command_id": request.command_id,
                "state": recorded["state"],
                "runtime_boot_id": recorded["runtime_boot_id"],
                "api_boot_id": recorded["api_boot_id"],
                "execution_binding_sha256": recorded[
                    "execution_binding_sha256"
                ],
                "observed_at": recorded["observed_at"],
            }
        ).model_dump(mode="json")

    def command_fault(self, payload: dict[str, object]) -> dict[str, object]:
        del payload
        raise RuntimeError("legacy in-authority fault execution is disabled; use prepare/ack")

    def _attested_final_response(
        self,
        *,
        request: AcceptanceFinalizeRequestV2,
        record: AcceptanceRunRecordV2,
    ) -> dict[str, object]:
        if self.signer is None:
            raise RuntimeError("target run authority signer is unavailable")
        if self.proof_store is None or self.trust_context is None:
            raise RuntimeError("target journal proof authority is unavailable")
        _require_authority_trust_context(self.trust_context)
        start, _started_at, _started_monotonic, _host_boot_id = self._stored_session(request)
        record_payload = canonical_json_bytes(record)
        run_record_sha256 = hashlib.sha256(record_payload).hexdigest()
        trust_binding = self.trust_context.binding
        header = AcceptanceJournalProofHeaderV2(
            schema_version="acceptance-journal-proof-header.v2",
            collector_id=request.collector_id,
            site_id=request.site_id,
            manifest_sha256=request.manifest_sha256,
            gate=request.gate,
            journal_namespace_mode="protected",
            offline_root_spki_sha256=trust_binding.offline_root_spki_sha256,
            policy_id=trust_binding.policy_id,
            policy_sha256=trust_binding.policy_sha256,
            campaign_id=trust_binding.campaign_id,
            manifest_payload_sha256=trust_binding.manifest_payload_sha256,
            launch_attestation_sha256=request.launch_attestation_sha256,
            execution_binding_sha256=request.execution_binding_sha256,
            fault_schedule_sha256=request.fault_schedule_sha256,
            public_run_authority_spki_sha256=self.signer.public_key_spki_sha256,
            sample_interval_seconds=start.sample_interval_seconds,
            camera_ids=start.camera_ids,
            launch=start.launch.model_dump(mode="json"),
            execution=start.execution.model_dump(mode="json"),
            fault_schedule=tuple(item.model_dump(mode="json") for item in start.fault_schedule),
        )
        proof = self.journal.export_proof(
            collector_id=request.collector_id,
            header=header,
            run_record_sha256=run_record_sha256,
            proof_store=self.proof_store,
        )
        existing = self.journal.attestation(request.collector_id)
        if existing is not None:
            attestation_payload, signature = existing
            attestation = TargetRunAttestationV2.model_validate(attestation_payload)
            current_root, current_count = self.journal.chain_head(request.collector_id)
            if (
                attestation.journal_root_sha256 != current_root
                or attestation.journal_entry_count != current_count
                or attestation.journal_proof_sha256 != proof.published.sha256
                or attestation.journal_proof_bytes != proof.published.byte_size
                or attestation.journal_proof_lines != proof.line_count
                or attestation.journal_kind_counts != proof.trailer.kind_counts
            ):
                raise RuntimeError("stored run attestation journal binding changed")
        else:
            attestation = TargetRunAttestationV2(
                schema_version="target-run-attestation.v2",
                journal_namespace_mode="protected",
                collector_id=request.collector_id,
                site_id=request.site_id,
                manifest_sha256=request.manifest_sha256,
                gate=request.gate,
                offline_root_spki_sha256=trust_binding.offline_root_spki_sha256,
                policy_id=trust_binding.policy_id,
                policy_sha256=trust_binding.policy_sha256,
                campaign_id=trust_binding.campaign_id,
                manifest_payload_sha256=trust_binding.manifest_payload_sha256,
                launch_attestation_sha256=(request.launch_attestation_sha256),
                execution_binding_sha256=(request.execution_binding_sha256),
                fault_schedule_sha256=request.fault_schedule_sha256,
                run_record_sha256=run_record_sha256,
                journal_root_sha256=proof.trailer.journal_final_root_sha256,
                journal_entry_count=proof.trailer.entry_count,
                public_key_spki_sha256=self.signer.public_key_spki_sha256,
                journal_proof_sha256=proof.published.sha256,
                journal_proof_bytes=proof.published.byte_size,
                journal_proof_lines=proof.line_count,
                journal_kind_counts=proof.trailer.kind_counts,
            )
            signature = self.signer.sign(canonical_json_bytes(attestation))
            if len(signature) != 64:
                raise RuntimeError("run authority returned an invalid Ed25519 signature")
            self.journal.store_attestation(
                collector_id=request.collector_id,
                payload=attestation.model_dump(mode="json"),
                signature=signature,
            )
        if (
            attestation.collector_id != record.run_id
            or attestation.site_id != record.site_id
            or attestation.manifest_sha256 != record.manifest_sha256
            or attestation.gate != record.gate
            or attestation.launch_attestation_sha256 != record.launch.attestation_sha256
            or record.execution is None
            or attestation.execution_binding_sha256 != record.execution.binding_sha256
            or attestation.fault_schedule_sha256 != request.fault_schedule_sha256
            or attestation.run_record_sha256 != run_record_sha256
            or attestation.public_key_spki_sha256 != record.launch.run_authority_public_key_spki_sha256
            or attestation.offline_root_spki_sha256 != trust_binding.offline_root_spki_sha256
            or attestation.policy_id != trust_binding.policy_id
            or attestation.policy_sha256 != trust_binding.policy_sha256
            or attestation.campaign_id != trust_binding.campaign_id
            or attestation.manifest_payload_sha256 != trust_binding.manifest_payload_sha256
        ):
            raise RuntimeError("stored run attestation differs from final evidence")
        return AcceptanceFinalEnvelopeV2(
            schema_version="acceptance-final-envelope.v2",
            record=record,
            attestation=attestation,
            signature_hex=signature.hex(),
        ).model_dump(mode="json")

    def proof_metadata(
        self,
        payload: dict[str, object],
    ) -> tuple[TargetRunAttestationV2, object]:
        """Authorize one sealed, exact-bound proof stream without accepting a path."""
        binding = AcceptanceProofRequestV2.model_validate(payload)
        self._require_trust_binding(binding)
        self._stored_session(binding)
        stored = self.journal.attestation(binding.collector_id)
        if stored is None or self.proof_store is None:
            raise RuntimeError("sealed acceptance journal proof is unavailable")
        attestation_payload, _signature = stored
        attestation = TargetRunAttestationV2.model_validate(attestation_payload)
        if (
            attestation.collector_id != binding.collector_id
            or attestation.site_id != binding.site_id
            or attestation.manifest_sha256 != binding.manifest_sha256
            or attestation.gate != binding.gate
            or attestation.launch_attestation_sha256 != binding.launch_attestation_sha256
            or attestation.execution_binding_sha256 != binding.execution_binding_sha256
            or attestation.fault_schedule_sha256 != binding.fault_schedule_sha256
            or not self.journal.finalized(binding.collector_id)
        ):
            raise RuntimeError("sealed acceptance journal proof binding differs")
        published = self.proof_store.open_verified(binding.collector_id)
        if (
            published.sha256 != attestation.journal_proof_sha256
            or published.byte_size != attestation.journal_proof_bytes
        ):
            raise RuntimeError("sealed acceptance journal proof artifact changed")
        return attestation, self.proof_store.iter_bytes(binding.collector_id)

    def finalize(self, payload: dict[str, object]) -> dict[str, object]:
        request = AcceptanceFinalizeRequestV2.model_validate(payload)
        self._require_trust_binding(request)
        if request.candidate is None and self.adapter is None:
            raise ValueError("acceptance final candidate is required")
        finalized = self.journal.entries(
            request.collector_id,
            kind="finalize",
        )
        if finalized:
            self._stored_session(request)
            if len(finalized) != 1:
                raise RuntimeError("acceptance final record is ambiguous")
            stored_final = finalized[0]
            record = AcceptanceRunRecordV2.model_validate(stored_final)
            if (
                record.site_id != request.site_id
                or record.manifest_sha256 != request.manifest_sha256
                or record.gate != request.gate
                or record.run_id != request.collector_id
                or record.launch is None
                or record.launch.attestation_sha256 != request.launch_attestation_sha256
                or record.execution is None
                or record.execution.binding_sha256 != request.execution_binding_sha256
            ):
                raise RuntimeError("acceptance finalize retry binding changed")
            if (
                self.signer is None
                or self.proof_store is None
                or self.trust_context is None
            ):
                raise RuntimeError("target run attestation authority is unavailable")
            self.journal.bind_finalize_request(
                collector_id=request.collector_id,
                payload=request.model_dump(mode="json"),
            )
            return self._attested_final_response(
                request=request,
                record=record,
            )
        start, started_at, _ = self._session(request)
        minimum = 8 * 3600 if request.gate == "8h" else 72 * 3600
        sample_count = self.journal.kind_count(
            request.collector_id,
            kind="sample",
        )
        latest_sample_payload = self.journal.latest_entry(
            request.collector_id,
            kind="sample",
        )
        latest_sample = (
            None
            if latest_sample_payload is None
            else AcceptanceSampleObservationV2.model_validate(latest_sample_payload)
        )
        if (
            sample_count != minimum // start.sample_interval_seconds + 1
            or latest_sample is None
            or (latest_sample.observed_at - started_at).total_seconds() != minimum
        ):
            raise ValueError("acceptance samples do not cover the exact endurance gate")
        fault_rows = self.journal.entries(
            request.collector_id,
            kind="fault_ack",
        )
        if len(fault_rows) != 16:
            raise ValueError("acceptance session lacks all commanded fault phases")
        by_fault_phase = {
            (str(item["fault"]["fault_id"]), str(item["phase"])): item for item in fault_rows
        }
        faults: list[FaultRecordV2] = []
        traces: list[FaultStateTraceV2] = []
        for fault in start.fault_schedule:
            injected = by_fault_phase.get((fault.fault_id, "inject"))
            recovered = by_fault_phase.get((fault.fault_id, "recover"))
            if injected is None or recovered is None:
                raise ValueError("acceptance fault command evidence is incomplete")
            injected_at = started_at + timedelta(seconds=fault.offset_seconds)
            faults.append(
                FaultRecordV2(
                    fault_id=fault.fault_id,
                    kind=fault.kind,
                    target=fault.target,
                    injected_at=injected_at,
                    monotonic_offset_seconds=fault.offset_seconds,
                    duration_seconds=fault.duration_seconds,
                    expected_degraded=fault.expected_degraded,
                    expected_recovery=fault.expected_recovery,
                    observed_degraded=str(injected["state"]),
                    observed_recovery=str(recovered["state"]),
                    recovered_at=datetime.fromisoformat(str(recovered["observed_at"])),
                )
            )
            for phase, row in (("degraded", injected), ("recovered", recovered)):
                traces.append(
                    FaultStateTraceV2(
                        fault_id=fault.fault_id,
                        kind=fault.kind,
                        phase=phase,
                        observed_at=datetime.fromisoformat(str(row["observed_at"])),
                        component=fault.target,
                        state=str(row["state"]),
                        runtime_boot_id=str(row["runtime_boot_id"]),
                        api_boot_id=str(row["api_boot_id"]),
                        command_id=str(row["command_id"]),
                        commanded_monotonic_offset_seconds=float(
                            row["commanded_monotonic_offset_seconds"]
                        ),
                    )
                )
        typed_traces = tuple(sorted(traces, key=lambda item: item.observed_at))
        derived = self._derive_sample_evidence(
            start=start,
            started_at=started_at,
            samples=(
                AcceptanceSampleObservationV2.model_validate(item)
                for item in self.journal.iter_entries(
                    request.collector_id,
                    kind="sample",
                )
            ),
            traces=typed_traces,
        )
        if request.candidate is not None:
            candidate_payload = request.candidate
        elif self.adapter is not None:
            candidate_payload = self.adapter.finalize(
                collector_id=request.collector_id,
                launch=start.launch,
                execution=start.execution,
            ).model_dump(mode="json")
        else:
            raise ValueError("acceptance final candidate is required")
        _reject_secret_like(candidate_payload)
        record = AcceptanceRunRecordV2.model_validate(
            {
                **candidate_payload,
                "run_id": request.collector_id,
                "environment": "target",
                "gate": request.gate,
                "site_id": request.site_id,
                "manifest_sha256": request.manifest_sha256,
                "launch": start.launch.model_dump(mode="json"),
                "execution": start.execution.model_dump(mode="json"),
                "started_at": started_at,
                "ended_at": latest_sample.observed_at,
                "faults": [item.model_dump(mode="json") for item in faults],
                "fault_traces": [item.model_dump(mode="json") for item in typed_traces],
                **{
                    key: (
                        [item.model_dump(mode="json") for item in value]
                        if isinstance(value, tuple) and value and hasattr(value[0], "model_dump")
                        else value
                    )
                    for key, value in derived.items()
                },
            }
        )
        if (
            self.signer is None
            or self.proof_store is None
            or self.trust_context is None
        ):
            raise RuntimeError("target run attestation authority is unavailable")
        serialized_record = record.model_dump(mode="json")
        self.journal.bind_finalize_request(
            collector_id=request.collector_id,
            payload=request.model_dump(mode="json"),
        )
        try:
            self.journal.append(
                collector_id=request.collector_id,
                kind="finalize",
                identity="final",
                payload=serialized_record,
                created_at=latest_sample.observed_at,
            )
        except RuntimeError:
            concurrent = self.journal.entries(
                request.collector_id,
                kind="finalize",
            )
            if concurrent != (serialized_record,):
                raise
        return self._attested_final_response(
            request=request,
            record=record,
        )
