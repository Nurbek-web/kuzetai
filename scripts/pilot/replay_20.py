#!/usr/bin/env python3
"""Run one bounded shared portable replay and emit observed acceptance evidence."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable
from uuid import uuid4

from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from protector.pilot.acceptance import (  # noqa: E402
    MAX_ACCEPTANCE_ENVELOPE_BYTES,
    MAX_ACCEPTANCE_RECORD_BYTES,
    AcceptanceRunRecordV2,
    BoundaryTraceV2,
    CameraHealthSpanV2,
    CameraQueueCoverageV2,
    CameraRunRecordV2,
    ExecutionBindingV2,
    FaultRecordV2,
    FaultStateTraceV2,
    LaunchAttestationV2,
    LocalFixtureSourceV2,
    QueueStateTraceV2,
    ResourceSampleV2,
    ScheduledFaultV2,
    TargetSecretSourceV2,
    WorkAccountingSpanV2,
    build_canonical_fault_schedule,
    canonical_fault_schedule_sha256,
    load_acceptance_manifest,
    source_profiles_sha256,
)
from protector.pilot.acceptance_authority import (  # noqa: E402
    AcceptanceRunSigner,
    AcceptanceAuthorityTrustContextV2,
    AcceptanceFaultAckRequestV2,
    AcceptanceFaultAckResponseV2,
    AcceptanceFaultPrepareRequestV2,
    AcceptanceFaultPrepareResponseV2,
    AcceptanceFinalizeRequestV2,
    AcceptanceProofRequestV2,
    AcceptanceSampleRequestV2,
    AcceptanceSampleResponseV2,
    AcceptanceStartRequestV2,
    AcceptanceStartResponseV2,
    CameraAcceptanceWorkloadV2,
    ExecutableTargetAcceptanceAdapter,
    FaultCommandObservationV2,
    FaultEffectExecutionRequestV2,
    FaultEffectReceiptV2,
    TargetAcceptanceAdapter,
    _require_authority_trust_context,
    build_acceptance_trust_binding,
    build_authority_trust_context,
)
from protector.pilot.acceptance_c2 import (  # noqa: E402
    SQLiteTargetExecutionTransitionJournalV3,
    SignedTargetAuthorityBindingV3,
    bind_target_authority_v3,
)
from protector.pilot.acceptance_campaign import (  # noqa: E402
    TargetCampaignCompletionV3,
    TargetCampaignCoordinatorV3,
    TargetRuntimeContinuationCoordinatorV3,
    _advance_target_runtime_restart_v3,
    _register_authenticated_fault_acknowledgement_source,
    _require_distinct_authority_files,
)
from protector.pilot.acceptance_source_profile import (  # noqa: E402
    TargetSourceProfileAttestationV2,
    capture_verified_target_source_profile_attestation,
)
from protector.pilot.acceptance_target import (  # noqa: E402
    TargetRuntimeLaunchRequestV2,
    TargetSourceBindingV2,
)
from protector.pilot.acceptance_target_controller import (  # noqa: E402
    TargetRuntimeControllerEnvironmentV2,
)
from protector.pilot.acceptance_controller_v3 import (  # noqa: E402
    AcceptanceControllerResultV3,
)
from protector.pilot.acceptance_proof import (  # noqa: E402
    MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES,
    AcceptanceFinalEnvelopeV2,
    TargetRunAttestationV2,
    VerifiedAcceptanceJournalProofV2,
    verify_acceptance_journal_proof,
)
from protector.pilot.acceptance_trust import (  # noqa: E402
    AcceptanceGate,
    AcceptanceRolePublicKeyPathsV2,
    VerifiedAcceptanceTrustV2,
    canonical_json_bytes,
    load_canonical_json_bytes,
    verify_acceptance_trust_chain,
)
from protector.pilot.config import (  # noqa: E402
    CameraFeed,
    EvidenceRetention,
    KazakhstanStorage,
    QueueLimits,
    ReadyToStart,
    Resolution,
    SecretReference,
    SiteConfig,
)

# V2 replay remains a verification/evidence transport only.  Production
# authorization is exclusively the private V3 C2 -> snapshot authority path.
LEGACY_TARGET_REPLAY_AUTHORIZING = False
RETAINED_V3_RUNTIME_RESTART_AUTHORIZING = False
_TARGET_RUNTIME_UID = 10_001
_TARGET_RUNTIME_GID = 10_001


from protector.pilot.domain import ObservationV1  # noqa: E402
from protector.pilot.metrics import PilotMetrics  # noqa: E402
from protector.pilot.provisioning import (  # noqa: E402
    ProvisioningError,
    ReviewedInputSnapshots,
    load_reviewed_inputs,
)
from protector.pilot.runtime.container_runner import (  # noqa: E402
    DockerRuntimeProcess,
    launch_docker_runtime,
)
from protector.pilot.runtime.deepstream import (  # noqa: E402
    DEEPSTREAM_IMAGE,
    DeepStreamGraphSpec,
    RuntimeModelManifestV1,
)
from protector.pilot.runtime.event_engine import EventEngine  # noqa: E402
from protector.pilot.runtime.fake import FakeDataPlane, ReplayFixture  # noqa: E402
from protector.pilot.runtime.mount_contract import (  # noqa: E402
    RuntimeMountContractV1,
    stage_runtime_mount_contract,
    validate_runtime_mount_contract,
)
from protector.pilot.runtime.supervisor import CameraHealth  # noqa: E402
from protector.pilot.telemetry import read_machine_token  # noqa: E402
from protector.pilot.trusted_artifacts import (  # noqa: E402
    read_regular_bounded,  # noqa: E402
    verify_ed25519_payload,
)
from protector.pilot.trusted_yaml import (  # noqa: E402
    StrictYAMLError,
    load_strict_yaml,
)

_MAX_RUNTIME_MOUNT_CONTRACT_YAML_BYTES = 8 * 1024 * 1024
_MAX_RUNTIME_MOUNT_CONTRACT_YAML_NODES = 100_000
_MAX_RUNTIME_MOUNT_CONTRACT_YAML_DEPTH = 96
_MAX_ACCEPTANCE_CONTROLLER_V3_RESULT_BYTES = 1024 * 1024


class ObservationConsumer(Protocol):
    def consume(self, observation: ObservationV1) -> None: ...


class HealthConsumer(Protocol):
    def consume(self, health: CameraHealth, *, observed_at: datetime) -> None: ...


class FaultAdapter(Protocol):
    failure_plan: "FaultFailurePlan"


@dataclass(frozen=True, slots=True)
class FaultFailurePlan:
    """Test-only omissions used to prove fail-closed fault evidence."""

    missing_degraded: frozenset[str] = frozenset()
    missing_recovery: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        allowed = {
            "camera_loss",
            "malformed_timestamp",
            "network_pause",
            "runtime_restart",
            "api_restart",
            "object_store_outage",
            "model_timeout",
            "verifier_full",
        }
        if (self.missing_degraded | self.missing_recovery) - allowed:
            raise ValueError("failure plan contains an unknown fault kind")


def canonical_fault_schedule(camera_ids: tuple[str, ...]) -> tuple[ScheduledFaultV2, ...]:
    """Compatibility export for the acceptance-owned canonical schedule."""
    return build_canonical_fault_schedule(camera_ids)


class CollectingBoundary:
    """Observed in-memory adapters around real event-engine and metrics contracts."""

    def __init__(
        self, *, site_id: str = "school-01", camera_ids: tuple[str, ...] | None = None
    ) -> None:
        self.observations: list[ObservationV1] = []
        self.health: list[tuple[CameraHealth, datetime]] = []
        self.persisted_ids: set[str] = set()
        self.event_engine = EventEngine()
        ids = camera_ids or tuple(f"camera-{index:02}" for index in range(20))
        self.metrics = PilotMetrics(
            site_id=site_id,
            camera_ids=ids,
            model_artifact_ids=("fake-person-v1",),
        )
        self._last_observed_at: datetime | None = None
        self.api_boot_ids = [f"portable-api-{uuid4()}"]
        self.runtime_boot_id = f"portable-runtime-{uuid4()}"
        self.api_state = "ready"
        self.evidence_state = "ready"
        self.model_state = "ready"
        self.verifier_state = "ready"
        self.verifier_depth = 0
        self.verifier_capacity = 4
        self._accepted_observations = 0

    @property
    def api_boot_id(self) -> str:
        return self.api_boot_ids[-1]

    @property
    def verifier_health(self) -> str:
        return "degraded" if self.verifier_state in {"full", "timeout", "unavailable"} else "ready"

    def set_runtime_boot_id(self, boot_id: str) -> None:
        self.runtime_boot_id = boot_id

    def stop_api(self) -> str:
        self.api_state = "degraded"
        return self.api_state

    def restart_api(self) -> str:
        """Reconstruct the API-owned event/metrics authority with a new boot ID."""
        self.event_engine = EventEngine()
        self.metrics = PilotMetrics(
            site_id=self.metrics.site_id,
            camera_ids=tuple(sorted(self.metrics.camera_ids)),
            model_artifact_ids=tuple(sorted(self.metrics.model_artifact_ids)),
        )
        self.api_boot_ids.append(f"portable-api-{uuid4()}")
        self.api_state = "ready"
        return self.api_state

    def consume(
        self, item: ObservationV1 | CameraHealth, *, observed_at: datetime | None = None
    ) -> None:
        if isinstance(item, ObservationV1):
            result = self.event_engine.ingest(item)
            if not result.accepted:
                raise RuntimeError(
                    f"event engine refused observed sample: {result.rejection_reason}"
                )
            self.observations.append(item)
            self.persisted_ids.add(str(item.observation_id))
            self._accepted_observations += 1
        else:
            if observed_at is None:
                raise ValueError("health consumption requires observation time")
            self.health.append((item, observed_at))
            self._last_observed_at = observed_at
            self.metrics.update_camera(
                item.camera_id,
                available=item.state == "online",
                last_frame_age_seconds=item.last_frame_age_seconds or 0.0,
                reconnects_total=item.reconnect_count,
                runtime_session_id=item.stream_epoch.hex,
            )

    def boundary_traces(self) -> tuple[BoundaryTraceV2, ...]:
        if self._last_observed_at is None:
            raise RuntimeError("no observed health boundary timestamp")
        observed_at = self._last_observed_at
        return (
            BoundaryTraceV2(
                component="event_engine",
                observed_at=observed_at,
                consumed_records=self._accepted_observations,
                succeeded=True,
                detail_code="event-engine-ingested",
            ),
            BoundaryTraceV2(
                component="repository",
                observed_at=observed_at,
                consumed_records=len(self.persisted_ids),
                succeeded=len(self.persisted_ids) == len(self.observations),
                detail_code="injected-observation-repository",
            ),
            BoundaryTraceV2(
                component="evidence",
                observed_at=observed_at,
                consumed_records=0,
                succeeded=False,
                detail_code="no-candidate-evidence-not-exercised",
            ),
            BoundaryTraceV2(
                component="metrics",
                observed_at=observed_at,
                consumed_records=len(self.health),
                succeeded=bool(self.metrics.render()),
                detail_code="prometheus-registry-updated",
            ),
        )


class PortableFaultAdapter:
    """Finite in-process fault controls; never mutates host networking or services."""

    def __init__(self, *, failure_plan: FaultFailurePlan | None = None) -> None:
        self.failure_plan = failure_plan or FaultFailurePlan()


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.seconds = 0.0
        self.now = now

    def monotonic(self) -> float:
        return self.seconds

    def wall(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.seconds += seconds
        self.now += timedelta(seconds=seconds)


def _site(manifest: object) -> SiteConfig:
    sources = manifest.sources
    feeds = tuple(
        CameraFeed(
            camera_id=item.camera_id,
            source_index=item.source_index,
            rtsp_url=SecretReference(environment=f"PILOT_REPLAY_SOURCE_{item.source_index:02}"),
            codec=item.codec,
            resolution=Resolution(width=item.width, height=item.height),
            fps=item.fps,
            bitrate_kbps=item.bitrate_kbps,
            analytics_hz=item.analytics_hz,
        )
        for item in sources
    )
    return SiteConfig(
        ready_to_start=ReadyToStart(
            feeds=feeds,
            ntp_source="portable-injected-clock",
            camera_map="acceptance-manifest",
            site_access="test-only",
            compute="single-shared-fake-runtime",
            notification_channel="disabled",
            model_rights_decisions="manifest-dispositions",
        ),
        storage=KazakhstanStorage(
            country_code="KZ",
            endpoint="https://objects.invalid",
            bucket="test-only",
            retention=EvidenceRetention(
                continuous_video_owner="customer_nvr",
                continuous_video_storage_enabled=False,
                encoded_ring_buffer_seconds=15,
                evidence_retention_days=1,
                metadata_retention_days=1,
            ),
        ),
        queues=QueueLimits(decode=4, analytics=64, verifier=4, events=64),
    )


def _portable_fixtures(
    camera_ids: tuple[str, ...],
    *,
    run_started_at: datetime,
    runtime_started_offset: int,
    runtime_seconds: int,
    include_source_faults: bool,
) -> tuple[ReplayFixture, ...]:
    fixtures: list[ReplayFixture] = []
    if include_source_faults:
        fixtures.extend(
            (
                ReplayFixture.disconnect(camera_ids[0], at_seconds=10),
                ReplayFixture.recover(camera_ids[0], at_seconds=15),
                ReplayFixture.malformed_timestamp(camera_ids[1], at_seconds=20),
                ReplayFixture.disconnect(camera_ids[1], at_seconds=21),
                ReplayFixture.recover(camera_ids[1], at_seconds=21),
                ReplayFixture.disconnect(camera_ids[2], at_seconds=30),
                ReplayFixture.recover(camera_ids[2], at_seconds=35),
            )
        )
    for second in range(runtime_seconds):
        absolute = runtime_started_offset + second
        for index, camera_id in enumerate(camera_ids):
            if include_source_faults and (
                (index == 0 and 10 <= second < 15)
                or (index == 1 and second == 20)
                or (index == 2 and 30 <= second < 35)
            ):
                continue
            fixtures.append(
                ReplayFixture.sample(
                    camera_id,
                    at_seconds=float(second),
                    source_time=run_started_at + timedelta(seconds=absolute),
                    seq=absolute,
                )
            )
    return tuple(fixtures)


def _camera_state(runtime: FakeDataPlane, camera_id: str) -> str:
    return next(item.state for item in runtime.health() if item.camera_id == camera_id)


def _fault_record(
    scheduled: ScheduledFaultV2,
    *,
    started_at: datetime,
    degraded: FaultStateTraceV2 | None,
    recovered: FaultStateTraceV2 | None,
) -> FaultRecordV2:
    return FaultRecordV2(
        fault_id=scheduled.fault_id,
        kind=scheduled.kind,
        target=scheduled.target,
        injected_at=started_at + timedelta(seconds=scheduled.offset_seconds),
        monotonic_offset_seconds=scheduled.offset_seconds,
        duration_seconds=scheduled.duration_seconds,
        expected_degraded=scheduled.expected_degraded,
        expected_recovery=scheduled.expected_recovery,
        observed_degraded=None if degraded is None else degraded.state,
        observed_recovery=None if recovered is None else recovered.state,
        recovered_at=None if recovered is None else recovered.observed_at,
    )


def run_portable(
    manifest_path: Path,
    *,
    observation_consumer: ObservationConsumer,
    health_consumer: HealthConsumer,
    fault_adapter: FaultAdapter,
    boundary_probe: CollectingBoundary | None = None,
    started_at: datetime | None = None,
) -> AcceptanceRunRecordV2:
    """Drive sequential shared fake runtimes and observe every portable fault."""
    manifest = load_acceptance_manifest(manifest_path)
    if any(not isinstance(source.source, LocalFixtureSourceV2) for source in manifest.sources):
        raise ValueError("portable replay requires lawful local fixture sources")
    started_at = started_at or datetime.now(timezone.utc)
    if started_at.tzinfo is None:
        raise ValueError("started_at must be UTC-aware")
    started_at = started_at.astimezone(timezone.utc)
    clock = _Clock(started_at)
    camera_ids = tuple(item.camera_id for item in manifest.sources)
    schedule = canonical_fault_schedule(camera_ids)
    scheduled_by_kind = {item.kind: item for item in schedule}
    failure_plan = fault_adapter.failure_plan
    if boundary_probe is None:
        raise ValueError("portable faults require a typed boundary probe")
    runtime_boot_ids: list[str] = []
    fault_traces: list[FaultStateTraceV2] = []
    queue_traces: list[QueueStateTraceV2] = []
    drained: list[ObservationV1] = []
    health_samples: list[CameraHealth] = []
    last_health_by_runtime: list[list[CameraHealth]] = []

    def new_runtime(*, offset: int, seconds: int, source_faults: bool) -> FakeDataPlane:
        boot_id = f"portable-runtime-{uuid4()}"
        runtime_boot_ids.append(boot_id)
        boundary_probe.set_runtime_boot_id(boot_id)
        instance = FakeDataPlane(
            fixtures=_portable_fixtures(
                camera_ids,
                run_started_at=started_at,
                runtime_started_offset=offset,
                runtime_seconds=seconds,
                include_source_faults=source_faults,
            ),
            monotonic_clock=clock.monotonic,
            wall_clock=clock.wall,
            stale_after_seconds=30.0,
        )
        instance.start(_site(manifest))
        return instance

    def trace(
        scheduled: ScheduledFaultV2,
        *,
        phase: str,
        state: str,
        component: str | None = None,
    ) -> FaultStateTraceV2:
        item = FaultStateTraceV2(
            fault_id=scheduled.fault_id,
            kind=scheduled.kind,
            phase=phase,
            observed_at=clock.wall(),
            component=component or scheduled.target,
            state=state,
            runtime_boot_id=runtime_boot_ids[-1],
            api_boot_id=boundary_probe.api_boot_id,
            command_id=f"portable-{scheduled.fault_id}-{phase}",
            commanded_monotonic_offset_seconds=(
                scheduled.offset_seconds
                if phase == "degraded"
                else scheduled.offset_seconds + scheduled.duration_seconds
            ),
        )
        fault_traces.append(item)
        return item

    def drain_and_publish(runtime: FakeDataPlane) -> list[CameraHealth]:
        batch = runtime.drain_observations()
        for observation in batch:
            observation_consumer.consume(observation)
        drained.extend(batch)
        samples = runtime.health()
        for health in samples:
            health_consumer.consume(health, observed_at=clock.wall())
        return samples

    runtime = new_runtime(offset=0, seconds=40, source_faults=True)
    try:
        for second in range(40):
            runtime.run_ready()
            health_samples = drain_and_publish(runtime)
            for kind, degraded_at, recovered_at in (
                ("camera_loss", 10, 15),
                ("malformed_timestamp", 20, 21),
                ("network_pause", 30, 35),
            ):
                scheduled = scheduled_by_kind[kind]
                if second == degraded_at and kind not in failure_plan.missing_degraded:
                    trace(
                        scheduled, phase="degraded", state=_camera_state(runtime, scheduled.target)
                    )
                if second == recovered_at and kind not in failure_plan.missing_recovery:
                    trace(
                        scheduled, phase="recovered", state=_camera_state(runtime, scheduled.target)
                    )
            clock.advance(1.0)
    finally:
        last_health_by_runtime.append(runtime.health())
        runtime.stop()
    runtime_running = False
    restart = scheduled_by_kind["runtime_restart"]
    if restart.kind not in failure_plan.missing_degraded:
        trace(restart, phase="degraded", state="online" if runtime_running else "offline")
    clock.advance(restart.duration_seconds)
    runtime = new_runtime(offset=43, seconds=40, source_faults=False)
    runtime_running = True
    runtime.run_ready()
    health_samples = drain_and_publish(runtime)
    if restart.kind not in failure_plan.missing_recovery:
        trace(
            restart,
            phase="recovered",
            state=(
                "online"
                if runtime_running and all(item.state == "online" for item in health_samples)
                else "degraded"
            ),
        )
    clock.advance(1.0)
    try:
        while clock.seconds <= 82:
            absolute = int(clock.seconds)
            runtime.run_ready()
            health_samples = drain_and_publish(runtime)
            if absolute == 50:
                fault = scheduled_by_kind["api_restart"]
                if fault.kind not in failure_plan.missing_degraded:
                    trace(fault, phase="degraded", state=boundary_probe.stop_api())
            elif absolute == 53:
                fault = scheduled_by_kind["api_restart"]
                if fault.kind not in failure_plan.missing_recovery:
                    trace(fault, phase="recovered", state=boundary_probe.restart_api())
            elif absolute == 60:
                fault = scheduled_by_kind["object_store_outage"]
                if fault.kind not in failure_plan.missing_degraded:
                    boundary_probe.evidence_state = "degraded"
                    trace(fault, phase="degraded", state=boundary_probe.evidence_state)
            elif absolute == 65:
                fault = scheduled_by_kind["object_store_outage"]
                if fault.kind not in failure_plan.missing_recovery:
                    boundary_probe.evidence_state = "ready"
                    trace(fault, phase="recovered", state=boundary_probe.evidence_state)
            elif absolute == 70:
                fault = scheduled_by_kind["model_timeout"]
                if fault.kind not in failure_plan.missing_degraded:
                    boundary_probe.model_state = "degraded"
                    trace(fault, phase="degraded", state=boundary_probe.model_state)
            elif absolute == 72:
                fault = scheduled_by_kind["model_timeout"]
                if fault.kind not in failure_plan.missing_recovery:
                    boundary_probe.model_state = "ready"
                    trace(fault, phase="recovered", state=boundary_probe.model_state)
            elif absolute == 80:
                fault = scheduled_by_kind["verifier_full"]
                if fault.kind not in failure_plan.missing_degraded:
                    boundary_probe.verifier_depth = boundary_probe.verifier_capacity
                    boundary_probe.verifier_state = "full"
                    queue_traces.append(
                        QueueStateTraceV2(
                            queue="verifier",
                            observed_at=clock.wall(),
                            depth=boundary_probe.verifier_depth,
                            capacity=boundary_probe.verifier_capacity,
                            state=boundary_probe.verifier_state,
                            runtime_boot_id=runtime_boot_ids[-1],
                            api_boot_id=boundary_probe.api_boot_id,
                        )
                    )
                    trace(fault, phase="degraded", state=boundary_probe.verifier_health)
            elif absolute == 82:
                fault = scheduled_by_kind["verifier_full"]
                if fault.kind not in failure_plan.missing_recovery:
                    boundary_probe.verifier_depth = 0
                    boundary_probe.verifier_state = "ready"
                    queue_traces.append(
                        QueueStateTraceV2(
                            queue="verifier",
                            observed_at=clock.wall(),
                            depth=0,
                            capacity=boundary_probe.verifier_capacity,
                            state="ready",
                            runtime_boot_id=runtime_boot_ids[-1],
                            api_boot_id=boundary_probe.api_boot_id,
                        )
                    )
                    trace(fault, phase="recovered", state=boundary_probe.verifier_health)
            clock.advance(1.0)
    finally:
        last_health_by_runtime.append(runtime.health())
        runtime.stop()
    if len({item.camera_id for item in drained}) != 20:
        raise RuntimeError("shared runtime did not emit observed records for all 20 cameras")
    if not health_samples or len(health_samples) != 20:
        raise RuntimeError("shared runtime did not publish exact 20-camera health")
    counts = {camera_id: 0 for camera_id in camera_ids}
    for observation in drained:
        counts[observation.camera_id] += 1
    ended_at = clock.wall()
    trace_by_fault_phase = {(item.fault_id, item.phase): item for item in fault_traces}
    faults = tuple(
        _fault_record(
            item,
            started_at=started_at,
            degraded=trace_by_fault_phase.get((item.fault_id, "degraded")),
            recovered=trace_by_fault_phase.get((item.fault_id, "recovered")),
        )
        for item in schedule
    )
    actual_health_at = boundary_probe._last_observed_at or (ended_at - timedelta(seconds=1))
    ended_at = actual_health_at
    health_by_camera = {item.camera_id: item for item in health_samples}
    scheduled_totals = {
        camera_id: sum(
            next(item.scheduled_samples for item in session if item.camera_id == camera_id)
            for session in last_health_by_runtime
        )
        for camera_id in camera_ids
    }
    dropped_totals = {
        camera_id: sum(
            next(item.dropped_samples for item in session if item.camera_id == camera_id)
            for session in last_health_by_runtime
        )
        for camera_id in camera_ids
    }
    duration_seconds = int((ended_at - started_at).total_seconds())
    source_outages: dict[str, tuple[datetime, datetime]] = {}
    for fault in faults:
        if fault.kind not in {"camera_loss", "network_pause"}:
            continue
        degraded = trace_by_fault_phase.get((fault.fault_id, "degraded"))
        source_return_at = fault.injected_at + timedelta(seconds=fault.duration_seconds)
        if degraded is not None and degraded.observed_at < source_return_at:
            source_outages[fault.target] = (
                degraded.observed_at,
                source_return_at,
            )
    health_spans: list[CameraHealthSpanV2] = []
    work_spans: list[WorkAccountingSpanV2] = []
    queue_coverage: list[CameraQueueCoverageV2] = []
    for camera_id in camera_ids:
        outage = source_outages.get(camera_id)
        intervals = (
            ((started_at, ended_at, "online"),)
            if outage is None
            else (
                (started_at, outage[0], "online"),
                (outage[0], outage[1], "source_outage"),
                (outage[1], ended_at, "online"),
            )
        )
        for span_start, span_end, state in intervals:
            seconds = int((span_end - span_start).total_seconds())
            cadence = next(value for value in range(60, 0, -1) if seconds % value == 0)
            health_spans.append(
                CameraHealthSpanV2(
                    camera_id=camera_id,
                    started_at=span_start,
                    ended_at=span_end,
                    state=state,
                    cadence_seconds=cadence,
                    observed_samples=seconds // cadence + 1,
                )
            )
        work_spans.append(
            WorkAccountingSpanV2(
                camera_id=camera_id,
                module="person",
                started_at=started_at,
                ended_at=ended_at,
                cadence_seconds=1,
                observed_samples=duration_seconds + 1,
                scheduled_samples=scheduled_totals[camera_id],
                processed_samples=counts[camera_id],
                dropped_samples=dropped_totals[camera_id],
            )
        )
        queue_age = health_by_camera[camera_id].queue_age_seconds or 0.0
        queue_coverage.append(
            CameraQueueCoverageV2(
                camera_id=camera_id,
                queue_name="analytics",
                started_at=started_at,
                ended_at=ended_at,
                cadence_seconds=1,
                runs=({"age_seconds": queue_age, "samples": duration_seconds + 1},),
            )
        )
    cameras = tuple(
        CameraRunRecordV2(
            camera_id=camera_id,
            scheduled_samples=scheduled_totals[camera_id],
            processed_samples=counts[camera_id],
            dropped_samples=dropped_totals[camera_id],
            availability_seconds=float(
                duration_seconds
                - (
                    0
                    if camera_id not in source_outages
                    else (
                        source_outages[camera_id][1] - source_outages[camera_id][0]
                    ).total_seconds()
                )
            ),
            source_outage_seconds=(
                0.0
                if camera_id not in source_outages
                else (source_outages[camera_id][1] - source_outages[camera_id][0]).total_seconds()
            ),
            queue_age_seconds=(health_by_camera[camera_id].queue_age_seconds or 0.0,),
            reconnect_seconds=()
            if sum(
                next(item.reconnect_count for item in session if item.camera_id == camera_id)
                for session in last_health_by_runtime
            )
            == 0
            else tuple(
                item.duration_seconds
                for item in faults
                if item.target == camera_id and item.kind in {"camera_loss", "network_pause"}
            ),
            observed_records=counts[camera_id],
            last_health_at=ended_at,
            runtime_boot_id=runtime_boot_ids[-1],
            api_boot_id=boundary_probe.api_boot_id,
        )
        for camera_id in camera_ids
    )
    boundaries = boundary_probe.boundary_traces()
    queue_traces.append(
        QueueStateTraceV2(
            queue="analytics",
            observed_at=actual_health_at,
            depth=0,
            capacity=64,
            state="ready",
            runtime_boot_id=runtime_boot_ids[-1],
            api_boot_id=boundary_probe.api_boot_id,
        )
    )
    return AcceptanceRunRecordV2(
        schema_version="acceptance-run-record.v2",
        run_id=f"portable-{uuid4()}",
        environment="test_only",
        gate="contract",
        site_id=manifest.site_id,
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        started_at=started_at,
        ended_at=ended_at,
        cameras=cameras,
        health_spans=tuple(health_spans),
        work_spans=tuple(work_spans),
        queue_coverage=tuple(queue_coverage),
        candidate_to_event_seconds=(),
        first_preview_seconds=(),
        gpu_percent=(),
        vram_percent=(),
        disk_bytes=(),
        disk_limit_bytes=1,
        disk_bounded=True,
        faults=faults,
        fault_traces=tuple(fault_traces),
        exceptions=(),
        boundaries=boundaries,
        lifecycle=(),
        resources=(
            ResourceSampleV2(
                sampled_at=started_at,
                interval_started_at=None,
                observation_cadence_seconds=1,
                observation_count=1,
                gpu_percent=0,
                gpu_percent_high_water=0,
                vram_percent=0,
                vram_percent_high_water=0,
                disk_bytes=0,
                disk_bytes_high_water=0,
                disk_limit_bytes=1,
            ),
            ResourceSampleV2(
                sampled_at=actual_health_at,
                interval_started_at=started_at,
                observation_cadence_seconds=1,
                observation_count=round((actual_health_at - started_at).total_seconds()),
                gpu_percent=0,
                gpu_percent_high_water=0,
                vram_percent=0,
                vram_percent_high_water=0,
                disk_bytes=0,
                disk_bytes_high_water=0,
                disk_limit_bytes=1,
            ),
        ),
        queue_traces=tuple(queue_traces),
        capacity=None,
        runtime_boot_ids=tuple(runtime_boot_ids),
        api_boot_ids=tuple(boundary_probe.api_boot_ids),
        events_evidence_complete=bool(
            boundaries
            and next(item for item in boundaries if item.component == "evidence").succeeded
        ),
        reviews_audited=False,
        notifications_after_confirmation=False,
        cross_camera_leakage=len(counts) != 20,
        queues_drained=all(item.queue_age_seconds is None for item in health_samples),
        consumers_connected=bool(boundaries),
        measured_effective_throughput_hz=1.0,
        required_throughput_hz=sum(float(item.analytics_hz["person"]) for item in manifest.sources),
        config_sha256=manifest.config_sha256,
        model_sha256=manifest.model_sha256,
        engine_sha256=manifest.engine_sha256,
        image_sha256=manifest.image_sha256,
    )


@runtime_checkable
class TargetCollector(Protocol):
    """CLI-owned bounded authority for target telemetry and final run evidence."""

    @property
    def collector_id(self) -> str: ...

    def start(
        self,
        *,
        site_id: str,
        manifest_sha256: str,
        gate: str,
        camera_ids: tuple[str, ...],
        workloads: tuple[CameraAcceptanceWorkloadV2, ...],
        sample_interval_seconds: int,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        schedule: tuple[ScheduledFaultV2, ...],
    ) -> None: ...

    def collect(
        self,
        *,
        process_healthy: bool,
        scheduled_monotonic_offset_seconds: float,
    ) -> None: ...

    def command_fault(
        self,
        *,
        fault_id: str,
        phase: str,
        at_offset: float,
    ) -> object: ...

    def finish(self) -> AcceptanceRunRecordV2: ...


@dataclass(frozen=True)
class TargetV3CollectedEvidence:
    """The V2 envelope/proof observed only after V3 C2 authorization."""

    final_envelope: AcceptanceFinalEnvelopeV2
    journal_proof_path: Path
    continuation_capability: object

    def __post_init__(self) -> None:
        if (
            type(self.final_envelope) is not AcceptanceFinalEnvelopeV2
            or not isinstance(self.journal_proof_path, Path)
            or not self.journal_proof_path.is_absolute()
            or self.continuation_capability is None
        ):
            raise ValueError("V3 collector evidence must use exact durable V2 artifacts")


class TargetV3CollectorRunner(Protocol):
    def __call__(
        self,
        arguments: argparse.Namespace,
        campaign: TargetCampaignCompletionV3,
    ) -> TargetV3CollectedEvidence: ...


class FaultEffectExecutor(Protocol):
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
        prior_observation: FaultCommandObservationV2 | None,
    ) -> FaultEffectReceiptV2: ...


class SQLiteTargetCollectorJournal:
    """Host-runner durable requests, responses, and effect receipts."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("target collector journal path is unsafe")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.stat()
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError("target collector journal root must be private and runner-owned")
        for ancestor in path.parent.parents:
            metadata = ancestor.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid()}
                or (
                    metadata.st_mode & 0o022
                    and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)
                )
            ):
                raise ValueError("target collector journal ancestor is unsafe")
        self.path = path
        self._root_identity = (parent.st_dev, parent.st_ino)
        self._lock = threading.RLock()
        previous_umask = os.umask(0o077)
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """
                CREATE TABLE IF NOT EXISTS collector_operations (
                    operation_key TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    response_json TEXT
                )
                """
                )
                connection.execute(
                    """
                CREATE TABLE IF NOT EXISTS executor_receipts (
                    command_id TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('PREPARED', 'COMMITTED')),
                    receipt_json TEXT,
                    observation_json TEXT
                )
                """
                )
        finally:
            os.umask(previous_umask)
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        parent = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
            or (parent.st_dev, parent.st_ino) != self._root_identity
        ):
            raise RuntimeError("target collector journal root identity changed")
        for ancestor in self.path.parent.parents:
            metadata = ancestor.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid()}
                or (
                    metadata.st_mode & 0o022
                    and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)
                )
            ):
                raise RuntimeError("target collector journal ancestor changed")
        if self.path.exists():
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise RuntimeError("target collector journal ownership or mode is unsafe")
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        if self.path.exists():
            self.path.chmod(0o600)
        for suffix in ("-wal", "-shm"):
            auxiliary = Path(f"{self.path}{suffix}")
            if auxiliary.exists():
                metadata = auxiliary.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_mode & 0o077
                ):
                    connection.close()
                    raise RuntimeError("target collector journal auxiliary file is unsafe")
                auxiliary.chmod(0o600)
        return connection

    def _enforce_bound(self, connection: sqlite3.Connection) -> None:
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        wal = Path(f"{self.path}-wal")
        wal_bytes = wal.stat().st_size if wal.exists() else 0
        shm = Path(f"{self.path}-shm")
        shm_bytes = shm.stat().st_size if shm.exists() else 0
        if page_count * page_size + wal_bytes + shm_bytes > 1024 * 1024 * 1024:
            raise RuntimeError("target collector journal byte bound reached")

    @staticmethod
    def _encoded(
        payload: dict[str, object],
        *,
        max_bytes: int = 64 * 1024,
    ) -> tuple[str, str]:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(encoded.encode()) > max_bytes:
            raise ValueError("target collector operation is unbounded")
        return encoded, hashlib.sha256(encoded.encode()).hexdigest()

    def request(self, key: str) -> dict[str, object] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT request_json FROM collector_operations WHERE operation_key = ?",
                (key,),
            ).fetchone()
        return None if row is None else json.loads(row["request_json"])

    def response(self, key: str) -> dict[str, object] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT response_json FROM collector_operations WHERE operation_key = ?",
                (key,),
            ).fetchone()
        if row is None or row["response_json"] is None:
            return None
        return json.loads(row["response_json"])

    def completed(
        self,
        prefix: str,
    ) -> tuple[tuple[str, dict[str, object]], ...]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT operation_key, response_json "
                "FROM collector_operations "
                "WHERE operation_key LIKE ? AND response_json IS NOT NULL "
                "ORDER BY operation_key",
                (f"{prefix}%",),
            ).fetchall()
        return tuple((str(row["operation_key"]), json.loads(row["response_json"])) for row in rows)

    def stage(
        self,
        key: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        encoded, digest = self._encoded(
            payload,
            max_bytes=(MAX_ACCEPTANCE_ENVELOPE_BYTES if key == "finalize" else 64 * 1024),
        )
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_sha256, request_json "
                "FROM collector_operations WHERE operation_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO collector_operations "
                    "(operation_key, request_sha256, request_json) "
                    "VALUES (?, ?, ?)",
                    (key, digest, encoded),
                )
                self._enforce_bound(connection)
                return payload
            if row["request_sha256"] != digest or row["request_json"] != encoded:
                raise RuntimeError("target collector operation retry payload changed")
            return json.loads(row["request_json"])

    def complete(
        self,
        key: str,
        *,
        request: dict[str, object],
        response: dict[str, object],
    ) -> dict[str, object]:
        operation_limit = MAX_ACCEPTANCE_ENVELOPE_BYTES if key == "finalize" else 64 * 1024
        request_json, digest = self._encoded(
            request,
            max_bytes=operation_limit,
        )
        response_json, _ = self._encoded(
            response,
            max_bytes=operation_limit,
        )
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_sha256, request_json, response_json "
                "FROM collector_operations WHERE operation_key = ?",
                (key,),
            ).fetchone()
            if (
                row is None
                or row["request_sha256"] != digest
                or row["request_json"] != request_json
            ):
                raise RuntimeError("target collector completion is not bound to staged request")
            if row["response_json"] is None:
                connection.execute(
                    "UPDATE collector_operations SET response_json = ? "
                    "WHERE operation_key = ? AND response_json IS NULL",
                    (response_json, key),
                )
                self._enforce_bound(connection)
                return response
            if row["response_json"] != response_json:
                raise RuntimeError("target collector retry response changed")
            return json.loads(row["response_json"])

    def effect(
        self,
        command_id: str,
    ) -> (
        tuple[str, dict[str, object], FaultEffectReceiptV2 | None, dict[str, object] | None] | None
    ):
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT state, request_json, receipt_json, observation_json "
                "FROM executor_receipts WHERE command_id = ?",
                (command_id,),
            ).fetchone()
        if row is None:
            return None
        request = FaultEffectExecutionRequestV2.model_validate_json(
            row["request_json"]
        )
        if request.command_id != command_id:
            raise RuntimeError("durable target fault effect command binding changed")
        return (
            str(row["state"]),
            request.model_dump(mode="json"),
            (
                None
                if row["receipt_json"] is None
                else FaultEffectReceiptV2.model_validate_json(row["receipt_json"])
            ),
            (
                None
                if row["observation_json"] is None
                else FaultCommandObservationV2.model_validate_json(
                    row["observation_json"]
                ).model_dump(mode="json")
            ),
        )

    def prepare_effect(
        self,
        command_id: str,
        *,
        request: dict[str, object],
    ) -> None:
        typed_request = FaultEffectExecutionRequestV2.model_validate(request)
        if typed_request.command_id != command_id:
            raise ValueError("target fault effect command binding differs")
        request_json, request_sha256 = self._encoded(
            typed_request.model_dump(mode="json")
        )
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_sha256, request_json FROM executor_receipts WHERE command_id = ?",
                (command_id,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO executor_receipts "
                    "(command_id, request_sha256, request_json, state) "
                    "VALUES (?, ?, ?, 'PREPARED')",
                    (command_id, request_sha256, request_json),
                )
                self._enforce_bound(connection)
            elif row["request_sha256"] != request_sha256 or row["request_json"] != request_json:
                raise RuntimeError("target fault effect retry request changed")

    def store_effect(
        self,
        command_id: str,
        *,
        request: dict[str, object],
        receipt: FaultEffectReceiptV2,
        observation: dict[str, object],
    ) -> None:
        typed_request = FaultEffectExecutionRequestV2.model_validate(request)
        typed_receipt = FaultEffectReceiptV2.model_validate(receipt)
        typed_observation = FaultCommandObservationV2.model_validate(observation)
        if (
            typed_request.command_id != command_id
            or typed_receipt.command_id != command_id
            or typed_observation.command_id != command_id
        ):
            raise ValueError("target fault effect command binding differs")
        request_json, request_sha256 = self._encoded(
            typed_request.model_dump(mode="json")
        )
        receipt_json = typed_receipt.model_dump_json()
        observation_json = json.dumps(
            typed_observation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_sha256, request_json, state, "
                "receipt_json, observation_json "
                "FROM executor_receipts WHERE command_id = ?",
                (command_id,),
            ).fetchone()
            if (
                row is None
                or row["request_sha256"] != request_sha256
                or row["request_json"] != request_json
            ):
                raise RuntimeError("target fault effect was not durably prepared")
            if row["state"] == "PREPARED":
                connection.execute(
                    "UPDATE executor_receipts SET state = 'COMMITTED', "
                    "receipt_json = ?, observation_json = ? "
                    "WHERE command_id = ? AND state = 'PREPARED'",
                    (receipt_json, observation_json, command_id),
                )
                self._enforce_bound(connection)
            elif row["receipt_json"] != receipt_json or row["observation_json"] != observation_json:
                raise RuntimeError("target fault effect retry evidence changed")


class TargetCampaignLock:
    """Hold one exclusive host-runner lease for the entire target campaign."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("target campaign lock path is unsafe")
        self.path = path
        self._descriptor: int | None = None

    def __enter__(self) -> TargetCampaignLock:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077
        ):
            raise ValueError("target campaign lock parent is not private")
        descriptor = os.open(
            self.path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise ValueError("target campaign lock file is unsafe")
            try:
                fcntl.flock(
                    descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except BlockingIOError as exc:
                raise RuntimeError("another target acceptance runner owns this campaign") from exc
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        return self

    def __exit__(self, *_args: object) -> None:
        if self._descriptor is None:
            return
        descriptor = self._descriptor
        self._descriptor = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _verify_final_envelope(
    response: dict[str, object],
    *,
    run_authority_public_key: bytes,
) -> tuple[AcceptanceRunRecordV2, TargetRunAttestationV2, bytes]:
    try:
        envelope = AcceptanceFinalEnvelopeV2.model_validate(response)
        if envelope.schema_version != "acceptance-final-envelope.v2":
            raise ValueError("signed target V2 envelope is required")
        record = envelope.record
        attestation = envelope.attestation
        signature = bytes.fromhex(envelope.signature_hex)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("target final attestation envelope is invalid") from exc
    attestation_payload = json.dumps(
        attestation.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    fingerprint = verify_ed25519_payload(
        payload=attestation_payload,
        signature=signature,
        trusted_public_key=run_authority_public_key,
        label="target run attestation",
    )
    record_payload = json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if (
        fingerprint != record.launch.run_authority_public_key_spki_sha256
        or attestation.public_key_spki_sha256 != fingerprint
        or attestation.run_record_sha256 != hashlib.sha256(record_payload).hexdigest()
        or attestation.collector_id != record.run_id
        or attestation.site_id != record.site_id
        or attestation.manifest_sha256 != record.manifest_sha256
        or attestation.gate != record.gate
        or attestation.launch_attestation_sha256 != record.launch.attestation_sha256
        or record.execution is None
        or attestation.execution_binding_sha256 != record.execution.binding_sha256
    ):
        raise RuntimeError("target final attestation trust binding is invalid")
    return record, attestation, signature


def _recover_root_authenticated_v2_final(
    *,
    journal: SQLiteTargetCollectorJournal,
    response: dict[str, object],
    trust_context: AcceptanceAuthorityTrustContextV2,
) -> tuple[AcceptanceRunRecordV2, TargetRunAttestationV2, bytes]:
    """Recover only a policy-rooted, proof-bound V2 final envelope."""
    _require_authority_trust_context(trust_context)
    stored_start = journal.request("start")
    try:
        if stored_start is None:
            raise ValueError("missing start")
        start = AcceptanceStartRequestV2.model_validate(stored_start)
    except ValueError:
        raise RuntimeError(
            "root-authenticated V2 recovery requires a valid durable start"
        ) from None
    expected_binding = build_acceptance_trust_binding(trust_context.trust)
    if start.trust_binding != expected_binding:
        raise RuntimeError("root-authenticated V2 recovery trust binding differs")
    record, attestation, signature = _verify_final_envelope(
        response,
        run_authority_public_key=(trust_context.trust.role_public_keys.run),
    )
    if (
        start.collector_id != record.run_id
        or start.site_id != trust_context.configured_site_id
        or start.manifest_sha256 != trust_context.trust.manifest.manifest_sha256
        or start.gate != trust_context.configured_gate
        or start.launch != trust_context.launch
        or start.camera_ids != trust_context.camera_ids
        or start.workloads != trust_context.workloads
        or start.fault_schedule != trust_context.fault_schedule
        or start.execution != record.execution
        or record.environment != "target"
        or record.site_id != trust_context.configured_site_id
        or record.manifest_sha256 != trust_context.trust.manifest.manifest_sha256
        or record.gate != trust_context.configured_gate
        or record.launch != trust_context.launch
        or attestation.fault_schedule_sha256
        != canonical_fault_schedule_sha256(trust_context.fault_schedule)
        or attestation.offline_root_spki_sha256 != trust_context.binding.offline_root_spki_sha256
        or attestation.policy_id != trust_context.binding.policy_id
        or attestation.policy_sha256 != trust_context.binding.policy_sha256
        or attestation.campaign_id != trust_context.binding.campaign_id
        or attestation.manifest_payload_sha256 != trust_context.binding.manifest_payload_sha256
    ):
        raise RuntimeError("root-authenticated V2 recovery differs from verified trust")
    return record, attestation, signature


class AuthenticatedTargetCollector:
    """Collect acceptance evidence from the machine-authenticated control plane."""

    _MAX_SAMPLE_BYTES = 64 * 1024
    _MAX_RECORD_BYTES = MAX_ACCEPTANCE_ENVELOPE_BYTES

    def __init__(
        self,
        *,
        base_url: str,
        acceptance_controller_token_file: Path,
        verified_trust: VerifiedAcceptanceTrustV2,
        configured_site_id: str,
        configured_campaign_id: str,
        configured_gate: AcceptanceGate,
        fault_executor: FaultEffectExecutor | None = None,
        observer: TargetAcceptanceAdapter | None = None,
        journal_path: Path | None = None,
        collector_id: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.hostname != "127.0.0.1"
        ):
            raise ValueError("collector URL must be the reviewed loopback API origin")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("collector timeout must be finite and at most 30 seconds")
        if collector_id is not None and (
            type(collector_id) is not str
            or not 1 <= len(collector_id) <= 160
            or any(
                character
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-"
                for character in collector_id
            )
        ):
            raise ValueError("target collector identity is invalid")
        trust_context = build_authority_trust_context(
            trust=verified_trust,
            configured_site_id=configured_site_id,
            configured_campaign_id=configured_campaign_id,
            configured_gate=configured_gate,
        )
        self._base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self._token = read_machine_token(acceptance_controller_token_file)
        self._timeout_seconds = timeout_seconds
        self._trust_context = trust_context
        self._fault_executor = fault_executor
        self._observer = observer
        self._temporary_journal_root: tempfile.TemporaryDirectory[str] | None = None
        if journal_path is None:
            self._temporary_journal_root = tempfile.TemporaryDirectory(
                prefix=".kuzet-target-collector-",
                dir=Path.cwd(),
            )
            temporary_root = Path(self._temporary_journal_root.name)
            temporary_root.chmod(0o700)
            journal_path = temporary_root / "collector.sqlite3"
        self._journal = SQLiteTargetCollectorJournal(journal_path)
        self._operation_lock = threading.RLock()
        self._run_authority_public_key = trust_context.trust.role_public_keys.run
        self.final_attestation: TargetRunAttestationV2 | None = None
        self.final_signature: bytes | None = None

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args: object, **_kwargs: object) -> None:
                return None

        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
        )
        self._binding: dict[str, object] | None = None
        self._observations = 0
        self._counted_samples: set[str] = set()
        self._schedule: dict[str, ScheduledFaultV2] = {}
        self._fault_acknowledgements: dict[tuple[str, str], dict[str, object]] = {}
        self._launch: LaunchAttestationV2 | None = None
        self._execution: ExecutionBindingV2 | None = None
        self._requested_collector_id = collector_id

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self._base_url!r})"

    @property
    def collector_id(self) -> str:
        if self._binding is None:
            raise RuntimeError("target collector has not started")
        collector_id = self._binding["collector_id"]
        if not isinstance(collector_id, str):
            raise RuntimeError("target collector identity is invalid")
        return collector_id

    @property
    def campaign_collector_id(self) -> str:
        if self._binding is not None:
            return self.collector_id
        stored = self._journal.request("start")
        stored_id = (
            None
            if stored is None
            else AcceptanceStartRequestV2.model_validate(stored).collector_id
        )
        if (
            stored_id is not None
            and self._requested_collector_id is not None
            and stored_id != self._requested_collector_id
        ):
            raise RuntimeError("durable target collector identity differs")
        if stored_id is not None:
            return stored_id
        if self._requested_collector_id is None:
            self._requested_collector_id = f"collector-{uuid4()}"
        return self._requested_collector_id

    def _post(self, path: str, payload: dict[str, object], *, limit: int) -> dict[str, object]:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        request = urllib.request.Request(
            f"{self._base_url}{path}",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        )
        last_error: Exception | None = None
        encoded = b""
        for _attempt in range(3):
            try:
                with self._opener.open(
                    request,
                    timeout=self._timeout_seconds,
                ) as response:
                    final = urllib.parse.urlsplit(response.geturl())
                    expected = urllib.parse.urlsplit(request.full_url)
                    final_url = (
                        final.scheme,
                        final.hostname,
                        final.port or (443 if final.scheme == "https" else 80),
                        final.path,
                        final.query,
                        final.fragment,
                        final.username,
                        final.password,
                    )
                    expected_url = (
                        expected.scheme,
                        expected.hostname,
                        expected.port or (443 if expected.scheme == "https" else 80),
                        expected.path,
                        expected.query,
                        expected.fragment,
                        expected.username,
                        expected.password,
                    )
                    if not 200 <= response.status < 300 or final_url != expected_url:
                        raise RuntimeError(
                            f"target collector response was rejected (status={response.status})"
                        )
                    encoded = response.read(limit + 1)
                    if len(encoded) > limit:
                        raise RuntimeError(
                            "target collector response was rejected or unbounded "
                            f"(status={response.status}, bytes={len(encoded)})"
                        )
                break
            except (
                OSError,
                RuntimeError,
                ValueError,
                urllib.error.URLError,
                urllib.error.HTTPError,
            ) as exc:
                last_error = exc
        else:
            raise RuntimeError("target collector request failed") from last_error
        def reject_duplicate_keys(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            decoded_object: dict[str, object] = {}
            for key, value in pairs:
                if key in decoded_object:
                    raise ValueError(
                        "target collector returned duplicate JSON keys"
                    )
                decoded_object[key] = value
            return decoded_object

        def reject_nonfinite(value: str) -> None:
            raise ValueError(
                f"target collector returned non-finite JSON: {value}"
            )

        try:
            decoded = json.loads(
                encoded,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonfinite,
            )
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("target collector returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("target collector returned an invalid envelope")
        return decoded

    def _durable_post(
        self,
        *,
        operation_key: str,
        path: str,
        payload: dict[str, object],
        limit: int,
        response_model: type[BaseModel],
    ) -> dict[str, object]:
        with self._operation_lock:
            staged = self._journal.stage(operation_key, payload)
            completed = self._journal.response(operation_key)
            if completed is not None:
                return response_model.model_validate(completed).model_dump(mode="json")
            response = self._post(path, staged, limit=limit)
            verified = response_model.model_validate(response).model_dump(mode="json")
            completed = self._journal.complete(
                operation_key,
                request=staged,
                response=verified,
            )
            return response_model.model_validate(completed).model_dump(mode="json")

    def start(
        self,
        *,
        site_id: str,
        manifest_sha256: str,
        gate: str,
        camera_ids: tuple[str, ...],
        workloads: tuple[CameraAcceptanceWorkloadV2, ...],
        sample_interval_seconds: int,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        schedule: tuple[ScheduledFaultV2, ...],
    ) -> None:
        if self._binding is not None:
            raise RuntimeError("target collector is already started")
        trust_context = self._trust_context
        _require_authority_trust_context(trust_context)
        if (
            len(schedule) != 8
            or len({item.kind for item in schedule}) != 8
            or len({item.fault_id for item in schedule}) != 8
        ):
            raise RuntimeError("target collector requires the canonical fault schedule")
        if (
            site_id != trust_context.configured_site_id
            or manifest_sha256 != trust_context.trust.manifest.manifest_sha256
            or gate != trust_context.configured_gate
            or camera_ids != trust_context.camera_ids
            or workloads != trust_context.workloads
            or launch != trust_context.launch
            or schedule != trust_context.fault_schedule
        ):
            raise RuntimeError("target collector inputs differ from verified offline-root trust")
        schedule_sha256 = canonical_fault_schedule_sha256(schedule)
        stored_start = self._journal.request("start")
        stored_collector_id = (
            None
            if stored_start is None
            else AcceptanceStartRequestV2.model_validate(stored_start).collector_id
        )
        if stored_collector_id is not None and not isinstance(stored_collector_id, str):
            raise RuntimeError("durable target collector identity is invalid")
        self._binding = {
            "site_id": site_id,
            "manifest_sha256": manifest_sha256,
            "gate": gate,
            "collector_id": (
                stored_collector_id
                or self._requested_collector_id
                or f"collector-{uuid4()}"
            ),
            "launch_attestation_sha256": launch.attestation_sha256,
            "execution_binding_sha256": execution.binding_sha256,
            "fault_schedule_sha256": schedule_sha256,
            "trust_binding": trust_context.binding.model_dump(mode="json"),
        }
        self._schedule = {item.fault_id: item for item in schedule}
        self._requested_collector_id = str(self._binding["collector_id"])
        self._launch = launch
        self._execution = execution
        start_request = AcceptanceStartRequestV2.model_validate(
            {
                "schema_version": "acceptance-collector-start.v2",
                **self._binding,
                "sample_interval_seconds": sample_interval_seconds,
                "camera_ids": list(camera_ids),
                "workloads": [item.model_dump(mode="json") for item in workloads],
                "launch": launch.model_dump(mode="json"),
                "execution": execution.model_dump(mode="json"),
                "fault_schedule": [item.model_dump(mode="json") for item in schedule],
            }
        )
        response = self._durable_post(
            operation_key="start",
            path="/api/internal/acceptance/start",
            payload=start_request.model_dump(mode="json"),
            limit=self._MAX_SAMPLE_BYTES,
            response_model=AcceptanceStartResponseV2,
        )
        if any(response.get(key) != value for key, value in self._binding.items()):
            raise RuntimeError("target collector start binding mismatch")
        completed_samples = self._journal.completed("sample:")
        self._counted_samples = {key for key, _item in completed_samples}
        self._observations = sum(
            int(item.get("observed_records", 0)) for _key, item in completed_samples
        )
        self._fault_acknowledgements = {}
        for _key, item in self._journal.completed("fault-ack:"):
            fault_id = item.get("fault_id")
            phase = item.get("phase")
            if isinstance(fault_id, str) and phase in {"inject", "recover"}:
                self._fault_acknowledgements[(fault_id, phase)] = item

    def collect(
        self,
        *,
        process_healthy: bool,
        scheduled_monotonic_offset_seconds: float,
    ) -> None:
        if self._binding is None or not process_healthy:
            raise RuntimeError("target collector requires one healthy shared runtime")
        operation_key = f"sample:{scheduled_monotonic_offset_seconds:.9f}"
        staged_sample = self._journal.request(operation_key)
        if staged_sample is None:
            observation = None
            if (
                self._observer is not None
                and self._launch is not None
                and self._execution is not None
            ):
                observation = self._observer.sample(
                    collector_id=self.collector_id,
                    launch=self._launch,
                    execution=self._execution,
                    previous_monotonic_offset_seconds=max(
                        0.0,
                        scheduled_monotonic_offset_seconds - 60.0,
                    ),
                    scheduled_monotonic_offset_seconds=(scheduled_monotonic_offset_seconds),
                )
            sample_payload = {
                "schema_version": "acceptance-collector-sample.v2",
                **self._binding,
                "process_healthy": True,
                "scheduled_monotonic_offset_seconds": (scheduled_monotonic_offset_seconds),
                **(
                    {}
                    if observation is None
                    else {"observation": observation.model_dump(mode="json")}
                ),
            }
        else:
            sample_payload = AcceptanceSampleRequestV2.model_validate(
                staged_sample
            ).model_dump(mode="json")
        sample_request = AcceptanceSampleRequestV2.model_validate(sample_payload)
        response = self._durable_post(
            operation_key=operation_key,
            path="/api/internal/acceptance/sample",
            payload=sample_request.model_dump(mode="json"),
            limit=self._MAX_SAMPLE_BYTES,
            response_model=AcceptanceSampleResponseV2,
        )
        if any(response.get(key) != value for key, value in self._binding.items()):
            raise RuntimeError("target collector sample binding mismatch")
        observations = response.get("observed_records")
        if not isinstance(observations, int) or isinstance(observations, bool) or observations < 0:
            raise RuntimeError("target collector sample count is invalid")
        if operation_key not in self._counted_samples:
            self._observations += observations
            self._counted_samples.add(operation_key)

    def command_fault(
        self,
        *,
        fault_id: str,
        phase: str,
        at_offset: float,
    ) -> object:
        if self._binding is None or phase not in {"inject", "recover"}:
            raise RuntimeError("target fault command requires an active collector session")
        fault = self._schedule.get(fault_id)
        expected_offset = (
            None
            if fault is None
            else fault.offset_seconds
            if phase == "inject"
            else fault.offset_seconds + fault.duration_seconds
        )
        if fault is None or at_offset != expected_offset:
            raise RuntimeError("target fault command differs from canonical schedule")
        prepare_request = AcceptanceFaultPrepareRequestV2.model_validate(
            {
                "schema_version": "acceptance-fault-prepare.v2",
                **self._binding,
                "fault": fault.model_dump(mode="json"),
                "phase": phase,
                "commanded_monotonic_offset_seconds": at_offset,
            }
        )
        prepared = self._durable_post(
            operation_key=f"fault-prepare:{fault_id}:{phase}",
            path="/api/internal/acceptance/fault/prepare",
            payload=prepare_request.model_dump(mode="json"),
            limit=self._MAX_SAMPLE_BYTES,
            response_model=AcceptanceFaultPrepareResponseV2,
        )
        if any(prepared.get(key) != value for key, value in self._binding.items()):
            raise RuntimeError("target fault command binding mismatch")
        if (
            prepared.get("fault_id") != fault_id
            or prepared.get("phase") != phase
            or prepared.get("commanded_monotonic_offset_seconds") != at_offset
            or not isinstance(prepared.get("command_id"), str)
            or prepared.get("state") not in {"CLAIMED", "COMMITTED"}
        ):
            raise RuntimeError("target fault preparation is invalid")
        if prepared["state"] == "COMMITTED":
            response = {
                **prepared,
                "schema_version": "acceptance-fault-ack-response.v2",
                "state": (
                    fault.expected_degraded
                    if phase == "inject"
                    else fault.expected_recovery
                ),
            }
        else:
            if self._fault_executor is None or self._launch is None or self._execution is None:
                raise RuntimeError("target fault executor is unavailable")
            command_id = str(prepared["command_id"])
            effect_request = FaultEffectExecutionRequestV2(
                schema_version="acceptance-fault-effect-execution.v2",
                collector_id=self.collector_id,
                launch_attestation_sha256=self._launch.attestation_sha256,
                execution_binding_sha256=self._execution.binding_sha256,
                fault=fault,
                phase=phase,
                command_id=command_id,
                commanded_monotonic_offset_seconds=at_offset,
            ).model_dump(mode="json")
            durable_effect = self._journal.effect(command_id)
            self._journal.prepare_effect(
                command_id,
                request=effect_request,
            )
            if durable_effect is None or durable_effect[0] == "PREPARED":
                prior_observation = None
                if durable_effect is not None and self._observer is not None:
                    # A prior runner may have crashed after the effect. Observe
                    # first, then ask the idempotent executor to reconcile and
                    # return its durable typed receipt.
                    try:
                        prior_observation = self._observer.observe_fault(
                            collector_id=self.collector_id,
                            launch=self._launch,
                            execution=self._execution,
                            fault=fault,
                            phase=phase,
                            command_id=command_id,
                            commanded_monotonic_offset_seconds=at_offset,
                        )
                    except (RuntimeError, ValueError):
                        pass
                receipt = self._fault_executor.ensure_fault(
                    collector_id=self.collector_id,
                    launch=self._launch,
                    execution=self._execution,
                    fault=fault,
                    phase=phase,
                    command_id=command_id,
                    commanded_monotonic_offset_seconds=at_offset,
                    prior_observation=prior_observation,
                )
                if self._observer is None:
                    raise RuntimeError("independent target fault observer is unavailable")
                observation = self._observer.observe_fault(
                    collector_id=self.collector_id,
                    launch=self._launch,
                    execution=self._execution,
                    fault=fault,
                    phase=phase,
                    command_id=command_id,
                    commanded_monotonic_offset_seconds=at_offset,
                )
                observation_payload = observation.model_dump(mode="json")
                self._journal.store_effect(
                    command_id,
                    request=effect_request,
                    receipt=receipt,
                    observation=observation_payload,
                )
            else:
                (
                    _state,
                    stored_effect_request,
                    receipt,
                    observation_payload,
                ) = durable_effect
                if (
                    stored_effect_request != effect_request
                    or receipt is None
                    or observation_payload is None
                ):
                    raise RuntimeError("durable target fault effect is incomplete")
            ack_request = AcceptanceFaultAckRequestV2.model_validate(
                {
                    "schema_version": "acceptance-fault-ack.v2",
                    **self._binding,
                    "fault_id": fault_id,
                    "phase": phase,
                    "command_id": prepared["command_id"],
                    "receipt": receipt.model_dump(mode="json"),
                    "observation": observation_payload,
                }
            )
            response = self._durable_post(
                operation_key=f"fault-ack:{command_id}",
                path="/api/internal/acceptance/fault/ack",
                payload=ack_request.model_dump(mode="json"),
                limit=self._MAX_SAMPLE_BYTES,
                response_model=AcceptanceFaultAckResponseV2,
            )
        if (
            any(response.get(key) != value for key, value in self._binding.items())
            or response.get("fault_id") != fault_id
            or response.get("phase") != phase
            or response.get("commanded_monotonic_offset_seconds") != at_offset
            or response.get("command_id") != prepared["command_id"]
            or not isinstance(response.get("runtime_boot_id"), str)
            or not isinstance(response.get("api_boot_id"), str)
        ):
            raise RuntimeError("target fault acknowledgement is invalid")
        acknowledgement = AcceptanceFaultAckResponseV2.model_validate_json(
            canonical_json_bytes(response),
            strict=True,
        )
        self._fault_acknowledgements[(fault_id, phase)] = (
            acknowledgement.model_dump(mode="json")
        )
        return _issue_authenticated_fault_acknowledgement(
            acknowledgement=acknowledgement,
            collector=self,
        )

    def finish(self) -> AcceptanceRunRecordV2:
        if (
            self._binding is None
            or self._observations <= 0
            or len(self._fault_acknowledgements) != 16
        ):
            raise RuntimeError("collector observed no bounded samples")
        staged_finalize = self._journal.request("finalize")
        if staged_finalize is None:
            candidate = None
            if (
                self._observer is not None
                and self._launch is not None
                and self._execution is not None
            ):
                candidate = self._observer.finalize(
                    collector_id=self.collector_id,
                    launch=self._launch,
                    execution=self._execution,
                )
            finalize_payload = {
                "schema_version": "acceptance-collector-finalize.v2",
                **self._binding,
                **({} if candidate is None else {"candidate": candidate.model_dump(mode="json")}),
            }
        else:
            finalize_payload = AcceptanceFinalizeRequestV2.model_validate(
                staged_finalize
            ).model_dump(mode="json")
        finalize_request = AcceptanceFinalizeRequestV2.model_validate(
            finalize_payload
        )
        response = self._durable_post(
            operation_key="finalize",
            path="/api/internal/acceptance/finalize",
            payload=finalize_request.model_dump(mode="json"),
            limit=self._MAX_RECORD_BYTES,
            response_model=AcceptanceFinalEnvelopeV2,
        )
        record, attestation, signature = _verify_final_envelope(
            response,
            run_authority_public_key=self._run_authority_public_key,
        )
        self.final_attestation = attestation
        self.final_signature = signature
        if (
            record.site_id != self._binding["site_id"]
            or record.manifest_sha256 != self._binding["manifest_sha256"]
            or record.gate != self._binding["gate"]
        ):
            raise RuntimeError("target collector final binding mismatch")
        traces = {(item.fault_id, item.phase): item for item in record.fault_traces}
        for (fault_id, phase), acknowledgement in self._fault_acknowledgements.items():
            trace_phase = "degraded" if phase == "inject" else "recovered"
            trace = traces.get((fault_id, trace_phase))
            if (
                trace is None
                or trace.command_id != acknowledgement["command_id"]
                or trace.commanded_monotonic_offset_seconds
                != acknowledgement["commanded_monotonic_offset_seconds"]
            ):
                raise RuntimeError("target fault evidence is not bound to commanded effects")
        return record

    def finalize_v3(
        self,
        collector_id: str,
    ) -> AcceptanceControllerResultV3:
        """Ask the packaged controller to own V3 evaluation and signing."""

        with self._operation_lock:
            if (
                self._binding is None
                or collector_id != self.collector_id
                or collector_id != self.campaign_collector_id
            ):
                raise RuntimeError(
                    "V3 finalization requires the active exact collector"
                )
            encoded_collector = urllib.parse.quote(
                collector_id,
                safe="",
            )
            response = self._post(
                (
                    "/api/internal/acceptance/v3/collectors/"
                    f"{encoded_collector}/finalize"
                ),
                {},
                limit=_MAX_ACCEPTANCE_CONTROLLER_V3_RESULT_BYTES,
            )
            try:
                result = AcceptanceControllerResultV3.model_validate_json(
                    canonical_json_bytes(response),
                    strict=True,
                )
            except ValueError as exc:
                raise RuntimeError(
                    "packaged V3 controller returned an invalid result"
                ) from exc
            if (
                result.collector_id != collector_id
                or result.accepted is not True
                or result.pass_attestation is None
            ):
                raise RuntimeError(
                    "packaged V3 controller returned no signed pass"
                )
            return result


_issue_authenticated_fault_acknowledgement = (
    _register_authenticated_fault_acknowledgement_source(
        AuthenticatedTargetCollector
    )
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-signature", type=Path)
    parser.add_argument("--acceptance-site-id")
    parser.add_argument("--acceptance-campaign-id")
    parser.add_argument("--acceptance-gate", choices=("8h", "72h"))
    parser.add_argument("--acceptance-offline-root-spki-sha256")
    parser.add_argument("--acceptance-offline-root-public-key", type=Path)
    parser.add_argument("--acceptance-trust-policy", type=Path)
    parser.add_argument("--acceptance-trust-policy-signature", type=Path)
    parser.add_argument("--acceptance-manifest-role-public-key", type=Path)
    parser.add_argument("--acceptance-capacity-role-public-key", type=Path)
    parser.add_argument("--acceptance-run-role-public-key", type=Path)
    parser.add_argument("--acceptance-report-role-public-key", type=Path)
    parser.add_argument("--acceptance-conditional-role-public-key", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", choices=("portable", "target"), default="portable")
    parser.add_argument("--site-config", type=Path)
    parser.add_argument("--site-config-sha256")
    parser.add_argument("--runtime-manifest", type=Path)
    parser.add_argument("--runtime-manifest-sha256")
    parser.add_argument("--measured-capacity-report", type=Path)
    parser.add_argument("--measured-capacity-sha256")
    parser.add_argument("--measured-capacity-signature", type=Path)
    parser.add_argument("--runtime-image-id-sha256")
    parser.add_argument("--runtime-image-config-sha256")
    parser.add_argument("--runtime-code-sha256")
    parser.add_argument("--mount-contract-sha256")
    parser.add_argument("--mount-contract", type=Path)
    parser.add_argument("--container-engine", type=Path)
    parser.add_argument("--nvidia-ctk", type=Path)
    parser.add_argument("--control-network")
    parser.add_argument("--camera-network")
    parser.add_argument("--control-network-id")
    parser.add_argument("--control-network-config-sha256")
    parser.add_argument("--camera-network-id")
    parser.add_argument("--camera-network-config-sha256")
    parser.add_argument("--acceptance-adapter-sha256")
    parser.add_argument("--acceptance-adapter-executable", type=Path)
    parser.add_argument("--acceptance-adapter-policy", type=Path)
    parser.add_argument("--acceptance-adapter-policy-sha256")
    parser.add_argument("--acceptance-adapter-work-root", type=Path)
    parser.add_argument("--acceptance-observer-sha256")
    parser.add_argument("--acceptance-observer-executable", type=Path)
    parser.add_argument("--acceptance-observer-policy", type=Path)
    parser.add_argument("--acceptance-observer-policy-sha256")
    parser.add_argument("--acceptance-observer-work-root", type=Path)
    parser.add_argument("--collector-state", type=Path)
    parser.add_argument("--acceptance-transition-journal", type=Path)
    parser.add_argument("--control-plane-url")
    parser.add_argument("--machine-token-file", type=Path)
    parser.add_argument("--acceptance-controller-token-file", type=Path)
    parser.add_argument("--acceptance-channel-dir", type=Path)
    parser.add_argument("--acceptance-source-secrets-root", type=Path)
    parser.add_argument("--acceptance-native-projection-dir", type=Path)
    parser.add_argument("--acceptance-work-projection-dir", type=Path)
    parser.add_argument(
        "--acceptance-source-profile-attestation",
        type=Path,
        action="append",
        dest="acceptance_source_profile_attestations",
    )
    parser.add_argument(
        "--acceptance-source-profile-signature",
        type=Path,
        action="append",
        dest="acceptance_source_profile_signatures",
    )
    parser.add_argument(
        "--acceptance-launch-nonce",
        action="append",
        dest="acceptance_launch_nonces",
    )
    parser.add_argument("--acceptance-first-runtime-epoch", type=int, default=1)
    parser.add_argument("--acceptance-module-gates-sha256")
    parser.add_argument("--controller-image-id-sha256")
    parser.add_argument("--controller-image-config-sha256")
    parser.add_argument("--controller-code-sha256")
    parser.add_argument("--acceptance-run-signing-key", type=Path)
    parser.add_argument("--acceptance-capture-dir", type=Path)
    parser.add_argument("--acceptance-snapshot-dir", type=Path)
    parser.add_argument("--acceptance-v3-proof-dir", type=Path)
    parser.add_argument("--acceptance-v3-state", type=Path)
    parser.add_argument("--acceptance-operational-limits", type=Path)
    parser.add_argument("--acceptance-operational-evidence", type=Path)
    parser.add_argument("--acceptance-repository-boundary", type=Path)
    parser.add_argument(
        "--acceptance-conditional-gate-decision",
        type=Path,
        action="append",
        default=[],
        dest="acceptance_conditional_gate_decisions",
    )
    parser.add_argument("--out-v3-result", type=Path)
    parser.add_argument("--out-attestation", type=Path)
    parser.add_argument("--out-signature", type=Path)
    parser.add_argument("--out-journal-proof", type=Path)
    parser.add_argument("--duration-seconds", type=int, default=28_800)
    parser.add_argument("--stop-grace-seconds", type=int, default=30)
    parser.add_argument("--collector-interval-seconds", type=int, default=60)
    return parser


def target_command(
    arguments: argparse.Namespace,
    *,
    launch_nonce: str,
    acceptance_channel: str | None = None,
    acceptance_source_secrets: str | None = None,
    acceptance_native_projection: str | None = None,
    acceptance_work_projection: str | None = None,
) -> tuple[str, ...]:
    required = (
        "site_config",
        "site_config_sha256",
        "runtime_manifest",
        "runtime_manifest_sha256",
        "measured_capacity_report",
        "measured_capacity_sha256",
        "measured_capacity_signature",
        "runtime_image_id_sha256",
        "runtime_image_config_sha256",
        "runtime_code_sha256",
        "mount_contract_sha256",
        "mount_contract",
        "container_engine",
        "nvidia_ctk",
        "control_network",
        "camera_network",
        "control_network_id",
        "control_network_config_sha256",
        "camera_network_id",
        "camera_network_config_sha256",
        "acceptance_adapter_sha256",
        "acceptance_adapter_executable",
        "acceptance_adapter_policy",
        "acceptance_adapter_policy_sha256",
        "acceptance_adapter_work_root",
        "acceptance_observer_sha256",
        "acceptance_observer_executable",
        "acceptance_observer_policy",
        "acceptance_observer_policy_sha256",
        "acceptance_observer_work_root",
        "collector_state",
        "control_plane_url",
        "machine_token_file",
        "acceptance_controller_token_file",
        "out_attestation",
        "out_signature",
        "out_journal_proof",
    )
    if any(getattr(arguments, name, None) is None for name in required):
        raise ValueError("target mode requires every reviewed DeepStream input")
    if len(launch_nonce) != 32:
        raise ValueError("target runtime launch nonce is invalid")
    command = (
        "--site-config",
        "/run/config/site.yaml",
        "--site-config-sha256",
        arguments.site_config_sha256,
        "--runtime-manifest",
        "/run/config/runtime-manifest.yaml",
        "--runtime-manifest-sha256",
        arguments.runtime_manifest_sha256,
        "--measured-capacity-report",
        "/run/config/measured-capacity.yaml",
        "--measured-capacity-sha256",
        arguments.measured_capacity_sha256,
        "--measured-capacity-signature",
        "/run/config/measured-capacity.sig",
        "--capacity-authority-public-key",
        "/run/config/capacity-authority.pem",
        "--runtime-image-id-sha256",
        arguments.runtime_image_id_sha256,
        "--runtime-image-config-sha256",
        arguments.runtime_image_config_sha256,
        "--runtime-code-sha256",
        arguments.runtime_code_sha256,
        "--mount-contract-sha256",
        arguments.mount_contract_sha256,
        "--runtime-launch-nonce",
        launch_nonce,
        "--control-plane-url",
        "http://api:8000",
        "--machine-token-file",
        "/run/secrets/machine_token",
    )
    acceptance_values = (
        acceptance_channel,
        acceptance_source_secrets,
        acceptance_native_projection,
        acceptance_work_projection,
    )
    if all(value is None for value in acceptance_values):
        return command
    if any(
        type(value) is not str
        or not value
        or not value.startswith("/")
        or "\x00" in value
        for value in acceptance_values
    ):
        raise ValueError("target acceptance child paths are incomplete")
    return (
        *command,
        "--acceptance-channel",
        acceptance_channel,
        "--acceptance-source-secrets-root",
        acceptance_source_secrets,
        "--acceptance-native-projection",
        acceptance_native_projection,
        "--acceptance-work-projection",
        acceptance_work_projection,
    )


@dataclass(frozen=True)
class ReviewedTargetLaunch:
    launch: LaunchAttestationV2
    site: SiteConfig
    runtime: RuntimeModelManifestV1
    snapshots: ReviewedInputSnapshots


def reviewed_launch_attestation(
    arguments: argparse.Namespace,
    *,
    manifest: object,
    capacity_authority_public_key: bytes,
) -> ReviewedTargetLaunch:
    """Parse, gate, and bind every file that the target process will receive."""
    try:
        with tempfile.TemporaryDirectory(
            prefix=".kuzet-verified-capacity-role-",
            dir=arguments.measured_capacity_report.parent,
        ) as temporary:
            key_root = Path(temporary)
            key_root.chmod(0o700)
            capacity_key_path = key_root / "capacity-role-public.pem"
            capacity_key_path.write_bytes(capacity_authority_public_key)
            capacity_key_path.chmod(0o600)
            site, runtime, capacity, reviewed_snapshots = load_reviewed_inputs(
                site_id=manifest.site_id,
                site_config_path=arguments.site_config,
                site_config_sha256=arguments.site_config_sha256,
                runtime_manifest_path=arguments.runtime_manifest,
                runtime_manifest_sha256=arguments.runtime_manifest_sha256,
                measured_capacity_path=arguments.measured_capacity_report,
                measured_capacity_sha256=arguments.measured_capacity_sha256,
                measured_capacity_signature_path=(arguments.measured_capacity_signature),
                capacity_authority_public_key_path=capacity_key_path,
                runtime_image_id_sha256=arguments.runtime_image_id_sha256,
                runtime_image_config_sha256=(arguments.runtime_image_config_sha256),
                runtime_code_sha256=arguments.runtime_code_sha256,
                mount_contract_sha256=arguments.mount_contract_sha256,
            )
    except (OSError, ValueError, ProvisioningError) as exc:
        raise ValueError("reviewed target launch inputs are invalid") from exc
    feeds = site.ready_to_start.feeds
    if tuple(feed.camera_id for feed in feeds) != tuple(
        source.camera_id for source in manifest.sources
    ) or any(
        feed.analytics_hz != source.analytics_hz for feed, source in zip(feeds, manifest.sources)
    ):
        raise ValueError("reviewed target launch workload differs from acceptance manifest")
    artifact_sha256 = runtime.artifact.sha256
    engine_sha256 = runtime.engine_sha256
    if artifact_sha256 is None or engine_sha256 is None:
        raise ValueError("reviewed target launch artifact identity is incomplete")
    image_sha256 = DEEPSTREAM_IMAGE.rsplit("@sha256:", maxsplit=1)[1]
    controller_origin = urllib.parse.urlsplit(arguments.control_plane_url)
    if (
        controller_origin.scheme != "http"
        or controller_origin.hostname != "127.0.0.1"
        or controller_origin.port is None
        or controller_origin.path not in {"", "/"}
        or controller_origin.query
        or controller_origin.fragment
    ):
        raise ValueError("target controller origin differs from reviewed loopback")
    try:
        adapter_payload = read_regular_bounded(
            arguments.acceptance_adapter_executable,
            max_bytes=64 * 1024 * 1024,
            label="acceptance adapter executable",
        )
        adapter_policy_payload = read_regular_bounded(
            arguments.acceptance_adapter_policy,
            max_bytes=1024 * 1024,
            label="acceptance adapter policy",
        )
        observer_payload = read_regular_bounded(
            arguments.acceptance_observer_executable,
            max_bytes=64 * 1024 * 1024,
            label="acceptance observer executable",
        )
        observer_policy_payload = read_regular_bounded(
            arguments.acceptance_observer_policy,
            max_bytes=1024 * 1024,
            label="acceptance observer policy",
        )
    except (OSError, ValueError) as exc:
        raise ValueError("acceptance adapter artifacts are unavailable") from exc
    if (
        hashlib.sha256(adapter_payload).hexdigest() != arguments.acceptance_adapter_sha256
        or hashlib.sha256(adapter_policy_payload).hexdigest()
        != arguments.acceptance_adapter_policy_sha256
        or hashlib.sha256(observer_payload).hexdigest() != arguments.acceptance_observer_sha256
        or hashlib.sha256(observer_policy_payload).hexdigest()
        != arguments.acceptance_observer_policy_sha256
    ):
        raise ValueError("acceptance executor or observer artifact identity differs from launch")
    if (
        arguments.acceptance_adapter_sha256,
        arguments.acceptance_adapter_policy_sha256,
    ) == (
        arguments.acceptance_observer_sha256,
        arguments.acceptance_observer_policy_sha256,
    ):
        raise ValueError("acceptance observer must be independently identified from executor")
    launch = LaunchAttestationV2(
        schema_version="acceptance-launch-attestation.v2",
        site_id=manifest.site_id,
        site_config_file_sha256=arguments.site_config_sha256,
        site_config_sha256=capacity.site_config_sha256,
        runtime_manifest_file_sha256=arguments.runtime_manifest_sha256,
        measured_capacity_file_sha256=arguments.measured_capacity_sha256,
        capacity_signature_sha256=(reviewed_snapshots.capacity.signature_sha256),
        capacity_trust_key_spki_sha256=(
            reviewed_snapshots.capacity.trust_key_spki_sha256
        ),
        artifact_id=runtime.artifact.artifact_id,
        artifact_sha256=artifact_sha256,
        registry_entry_sha256=runtime.registry_entry_sha256,
        frozen_workload_sha256=runtime.frozen_workload_sha256,
        expected_workload_sha256=runtime.expected_workload_sha256,
        engine_sha256=engine_sha256,
        image_sha256=image_sha256,
        runtime_image_id_sha256=arguments.runtime_image_id_sha256,
        runtime_image_config_sha256=arguments.runtime_image_config_sha256,
        runtime_code_sha256=arguments.runtime_code_sha256,
        mount_contract_sha256=arguments.mount_contract_sha256,
        control_network=arguments.control_network,
        camera_network=arguments.camera_network,
        expected_control_network_id=arguments.control_network_id,
        expected_control_network_config_sha256=(arguments.control_network_config_sha256),
        expected_camera_network_id=arguments.camera_network_id,
        expected_camera_network_config_sha256=(arguments.camera_network_config_sha256),
        gpu_device_ids=tuple(device.uuid for device in capacity.gpu_devices),
        gpu_product_name=capacity.gpu_devices[0].product_name,
        gpu_pci_bus_id=capacity.gpu_devices[0].pci_bus_id,
        gpu_total_vram_bytes=capacity.gpu_devices[0].total_vram_bytes,
        gpu_compute_capability=(capacity.gpu_devices[0].compute_capability),
        gpu_mig_mode=capacity.gpu_devices[0].mig_mode,
        gpu_inventory_sha256=capacity.gpu_inventory_sha256,
        nvidia_driver_version=capacity.nvidia_driver_version,
        cuda_driver_version=capacity.cuda_driver_version,
        cuda_runtime_version=capacity.cuda_runtime_version,
        nvidia_container_toolkit_version=(capacity.nvidia_container_toolkit_version),
        acceptance_adapter_sha256=arguments.acceptance_adapter_sha256,
        acceptance_adapter_policy_sha256=(arguments.acceptance_adapter_policy_sha256),
        acceptance_observer_sha256=arguments.acceptance_observer_sha256,
        acceptance_observer_policy_sha256=(arguments.acceptance_observer_policy_sha256),
        runtime_api_host="api",
        runtime_api_port=8000,
        controller_api_host="127.0.0.1",
        controller_api_port=controller_origin.port,
        run_authority_public_key_spki_sha256=(manifest.launch.run_authority_public_key_spki_sha256),
        source_profiles_sha256=source_profiles_sha256(manifest.sources),
        required_throughput_hz=capacity.required_throughput_hz,
        measured_effective_throughput_hz=capacity.effective_throughput_hz,
        stream_count=capacity.stream_count,
    )
    if launch != manifest.launch:
        raise ValueError("reviewed target launch attestation differs from manifest")
    return ReviewedTargetLaunch(
        launch=launch,
        site=site,
        runtime=runtime,
        snapshots=reviewed_snapshots,
    )


def _write_new_run_record(path: Path, record: AcceptanceRunRecordV2) -> None:
    payload = json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if len(payload) > MAX_ACCEPTANCE_RECORD_BYTES:
        raise ValueError("run record exceeds the finite output bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o640,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _download_journal_proof(
    *,
    base_url: str,
    acceptance_controller_token_file: Path,
    binding: dict[str, object],
    attestation: TargetRunAttestationV2,
    record: AcceptanceRunRecordV2,
    destination: Path,
    timeout_seconds: float = 30.0,
) -> None:
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not 0 < timeout_seconds <= 30
        or destination.exists()
        or destination.is_symlink()
    ):
        raise ValueError("target journal proof download configuration is invalid")
    token = read_machine_token(acceptance_controller_token_file)
    request = urllib.request.Request(
        urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/api/internal/acceptance/proof",
                "",
                "",
            )
        ),
        data=json.dumps(
            AcceptanceProofRequestV2.model_validate(
                {
                    "schema_version": "acceptance-proof-request.v2",
                    **binding,
                }
            ).model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args: object, **_kwargs: object) -> None:
            return None

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
    )
    descriptor = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    consumed = 0
    digest = hashlib.sha256()
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            final = urllib.parse.urlsplit(response.geturl())
            expected = urllib.parse.urlsplit(request.full_url)
            if not 200 <= response.status < 300 or (
                final.scheme,
                final.hostname,
                final.port or 80,
                final.path,
                final.query,
                final.fragment,
                final.username,
                final.password,
            ) != (
                expected.scheme,
                expected.hostname,
                expected.port or 80,
                expected.path,
                expected.query,
                expected.fragment,
                expected.username,
                expected.password,
            ):
                raise RuntimeError("acceptance journal proof download was refused")
            content_length = response.headers.get("Content-Length")
            response_digest = response.headers.get("Digest")
            response_lines = response.headers.get("X-Kuzet-Proof-Lines")
            if (
                content_length != str(attestation.journal_proof_bytes)
                or response_digest != f"sha-256={attestation.journal_proof_sha256}"
                or response_lines != str(attestation.journal_proof_lines)
            ):
                raise RuntimeError("acceptance journal proof response binding differs")
            while chunk := response.read(1024 * 1024):
                consumed += len(chunk)
                if consumed > MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES:
                    raise RuntimeError("acceptance journal proof response is unbounded")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short journal proof output write")
                    view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        destination.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    if (
        consumed != attestation.journal_proof_bytes
        or digest.hexdigest() != attestation.journal_proof_sha256
    ):
        destination.unlink(missing_ok=True)
        raise RuntimeError("acceptance journal proof response digest differs")
    verify_acceptance_journal_proof(
        destination,
        expected_attestation=attestation,
        expected_run_record=record,
    )


@dataclass(frozen=True)
class _PinnedOutputTarget:
    path: Path
    parent_descriptor: int
    parent_metadata: os.stat_result
    expected_bytes: int
    expected_sha256: str


@dataclass(frozen=True)
class _StagedOutput:
    target: _PinnedOutputTarget
    temporary_name: str
    descriptor: int


def _unsafe_output_directory(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or (
            metadata.st_mode & 0o022
            and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)
        )
    )


def _validate_output_ancestors(path: Path) -> None:
    for ancestor in (path.parent, *path.parent.parents):
        try:
            metadata = ancestor.lstat()
        except OSError:
            raise ValueError("target acceptance output ancestor is unavailable") from None
        if _unsafe_output_directory(metadata):
            raise ValueError("target acceptance output ancestor is unsafe")


def _open_safe_output_parent(path: Path) -> tuple[int, os.stat_result]:
    if (
        not path.is_absolute()
        or path != Path(os.path.abspath(path))
        or path.name in {"", ".", ".."}
    ):
        raise ValueError("target acceptance output path is unsafe")
    for ancestor in reversed((path.parent, *path.parent.parents)):
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise ValueError("target acceptance output ancestor is unavailable") from None
        if _unsafe_output_directory(metadata):
            raise ValueError("target acceptance output ancestor is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _validate_output_ancestors(path)
    descriptor = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        current = path.parent.lstat()
        if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            current.st_dev,
            current.st_ino,
        ):
            raise ValueError("target acceptance output parent changed")
    except BaseException as primary:
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "target acceptance parent validation and cleanup both failed",
                [primary, cleanup],
            ) from primary
        raise
    return descriptor, opened


def _revalidate_output_parent(
    path: Path,
    descriptor: int,
    expected: os.stat_result,
) -> None:
    _validate_output_ancestors(path)
    current = path.parent.lstat()
    opened = os.fstat(descriptor)
    identity = (expected.st_dev, expected.st_ino)
    if (
        _unsafe_output_directory(current)
        or _unsafe_output_directory(opened)
        or (current.st_dev, current.st_ino) != identity
        or (opened.st_dev, opened.st_ino) != identity
    ):
        raise ValueError("target acceptance output parent changed")


def _output_inode_binding(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_output_leaf_binding(
    target: _PinnedOutputTarget,
    descriptor: int,
    expected: os.stat_result,
) -> None:
    opened = os.fstat(descriptor)
    try:
        current = os.stat(
            target.path.name,
            dir_fd=target.parent_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        raise RuntimeError("target acceptance output leaf binding changed") from None
    if _output_inode_binding(opened) != _output_inode_binding(expected) or _output_inode_binding(
        current
    ) != _output_inode_binding(expected):
        raise RuntimeError("target acceptance output leaf binding changed")
    # POSIX has no operation that pins a directory leaf after this comparison.
    # The validated owner/mode ancestry is therefore the trusted private-parent
    # boundary for the remaining return/close instructions.


def _open_validated_existing_output(
    target: _PinnedOutputTarget,
) -> tuple[int, os.stat_result] | None:
    _revalidate_output_parent(
        target.path,
        target.parent_descriptor,
        target.parent_metadata,
    )
    try:
        descriptor = os.open(
            target.path.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=target.parent_descriptor,
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise ValueError("preexisting target acceptance output is unsafe") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_dev != target.parent_metadata.st_dev
            or before.st_size != target.expected_bytes
        ):
            raise ValueError("preexisting target acceptance output is unsafe")
        digest = hashlib.sha256()
        consumed = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            consumed += len(chunk)
            if consumed > target.expected_bytes:
                raise RuntimeError("preexisting target acceptance output differs")
        after = os.fstat(descriptor)
        if consumed != target.expected_bytes or digest.hexdigest() != target.expected_sha256:
            raise RuntimeError("preexisting target acceptance output differs")
        os.fsync(descriptor)
        synced = os.fstat(descriptor)
        _revalidate_output_parent(
            target.path,
            target.parent_descriptor,
            target.parent_metadata,
        )
        _require_output_leaf_binding(target, descriptor, synced)
        if _output_inode_binding(before) != _output_inode_binding(after) or _output_inode_binding(
            after
        ) != _output_inode_binding(synced):
            raise RuntimeError("preexisting target acceptance output differs")
    except BaseException as primary:
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "target acceptance output validation and cleanup both failed",
                [primary, cleanup],
            ) from primary
        raise
    return descriptor, synced


def _validate_existing_output(target: _PinnedOutputTarget) -> bool:
    opened = _open_validated_existing_output(target)
    if opened is None:
        return False
    descriptor, _validated_metadata = opened
    os.close(descriptor)
    return True


def _preflight_output_targets(
    bindings: tuple[tuple[Path, int, str], ...],
) -> tuple[_PinnedOutputTarget, ...]:
    targets: list[_PinnedOutputTarget] = []
    try:
        for path, expected_bytes, expected_sha256 in bindings:
            if (
                expected_bytes < 1
                or len(expected_sha256) != 64
                or any(character not in "0123456789abcdef" for character in expected_sha256)
            ):
                raise ValueError("target acceptance output binding is invalid")
            descriptor, metadata = _open_safe_output_parent(path)
            targets.append(
                _PinnedOutputTarget(
                    path=path,
                    parent_descriptor=descriptor,
                    parent_metadata=metadata,
                    expected_bytes=expected_bytes,
                    expected_sha256=expected_sha256,
                )
            )
        identities = {
            (
                target.parent_metadata.st_dev,
                target.parent_metadata.st_ino,
                target.path.name,
            )
            for target in targets
        }
        if len(identities) != len(targets):
            raise ValueError("target acceptance outputs must be distinct")
        for target in targets:
            _validate_existing_output(target)
        return tuple(targets)
    except BaseException as primary:
        cleanup_errors = _close_output_targets(tuple(targets))
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance preflight and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise


def _close_output_targets(
    targets: tuple[_PinnedOutputTarget, ...],
) -> list[BaseException]:
    errors: list[BaseException] = []
    for target in targets:
        try:
            os.close(target.parent_descriptor)
        except BaseException as exc:
            errors.append(exc)
    return errors


def _close_publication_handles(
    targets: tuple[_PinnedOutputTarget, ...],
    descriptors: tuple[int, ...] = (),
) -> list[BaseException]:
    errors = _close_output_targets(targets)
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except BaseException as exc:
            errors.append(exc)
    return errors


def _finish_output_quarantine(
    target: _PinnedOutputTarget,
    quarantine_name: str,
    quarantine_descriptor: int,
    *,
    remove_directory: bool,
) -> list[BaseException]:
    errors: list[BaseException] = []
    try:
        os.fsync(quarantine_descriptor)
    except BaseException as exc:
        errors.append(exc)
    try:
        os.close(quarantine_descriptor)
    except BaseException as exc:
        errors.append(exc)
    if remove_directory:
        try:
            os.rmdir(
                quarantine_name,
                dir_fd=target.parent_descriptor,
            )
        except BaseException as exc:
            errors.append(exc)
    try:
        os.fsync(target.parent_descriptor)
    except BaseException as exc:
        errors.append(exc)
    return errors


def _restore_quarantined_directory(
    target: _PinnedOutputTarget,
    quarantine_descriptor: int,
    name: str,
    candidate: os.stat_result,
) -> None:
    reservation: os.stat_result | None = None
    try:
        # mkdir is the portable no-replace reservation for a directory leaf.
        # The validated parent is the trusted boundary between reservation,
        # replacement, and the descriptor-relative identity check below.
        os.mkdir(
            name,
            0o700,
            dir_fd=target.parent_descriptor,
        )
        reservation = os.stat(
            name,
            dir_fd=target.parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(reservation.st_mode)
            or reservation.st_uid != os.geteuid()
            or stat.S_IMODE(reservation.st_mode) != 0o700
            or reservation.st_dev != target.parent_metadata.st_dev
        ):
            raise RuntimeError("target acceptance directory reservation changed")
        os.rename(
            "candidate",
            name,
            src_dir_fd=quarantine_descriptor,
            dst_dir_fd=target.parent_descriptor,
        )
        current = os.stat(
            name,
            dir_fd=target.parent_descriptor,
            follow_symlinks=False,
        )
        if (current.st_dev, current.st_ino) != (candidate.st_dev, candidate.st_ino):
            raise RuntimeError("target acceptance directory restoration changed")
    except BaseException as primary:
        try:
            current = os.stat(
                name,
                dir_fd=target.parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            current = None
        except BaseException as probe:
            raise BaseExceptionGroup(
                "target acceptance directory restoration and probe both failed",
                [primary, probe],
            ) from primary
        if current is not None and (current.st_dev, current.st_ino) == (
            candidate.st_dev,
            candidate.st_ino,
        ):
            return
        cleanup_errors: list[BaseException] = []
        if reservation is not None:
            if current is None:
                pass
            elif (current.st_dev, current.st_ino) == (
                reservation.st_dev,
                reservation.st_ino,
            ):
                try:
                    os.rmdir(
                        name,
                        dir_fd=target.parent_descriptor,
                    )
                except BaseException as cleanup:
                    cleanup_errors.append(cleanup)
            else:
                cleanup_errors.append(
                    RuntimeError("target acceptance directory reservation changed")
                )
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance directory restoration and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise


def _remove_owned_output_name(
    target: _PinnedOutputTarget,
    name: str,
    descriptor: int,
) -> bool:
    try:
        os.stat(
            name,
            dir_fd=target.parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    quarantine_name = f".kuzet-output-quarantine-{uuid4().hex}"
    os.mkdir(
        quarantine_name,
        0o700,
        dir_fd=target.parent_descriptor,
    )
    try:
        quarantine_descriptor = os.open(
            quarantine_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=target.parent_descriptor,
        )
    except BaseException as primary:
        cleanup_errors: list[BaseException] = []
        # The random 0700 name was created by this runner in the already-pinned
        # trusted parent. Remove that still-empty name before surfacing an open
        # failure, then durably record the removal.
        try:
            os.rmdir(
                quarantine_name,
                dir_fd=target.parent_descriptor,
            )
        except BaseException as cleanup:
            cleanup_errors.append(cleanup)
        try:
            os.fsync(target.parent_descriptor)
        except BaseException as cleanup:
            cleanup_errors.append(cleanup)
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance quarantine open and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise
    quarantine_owned = False
    candidate_present = False
    try:
        opened_quarantine = os.fstat(quarantine_descriptor)
        named_quarantine = os.stat(
            quarantine_name,
            dir_fd=target.parent_descriptor,
            follow_symlinks=False,
        )
        quarantine_owned = (
            stat.S_ISDIR(opened_quarantine.st_mode)
            and opened_quarantine.st_uid == os.geteuid()
            and stat.S_IMODE(opened_quarantine.st_mode) == 0o700
            and opened_quarantine.st_dev == target.parent_metadata.st_dev
            and (opened_quarantine.st_dev, opened_quarantine.st_ino)
            == (named_quarantine.st_dev, named_quarantine.st_ino)
        )
        if not quarantine_owned:
            raise RuntimeError("target acceptance output quarantine changed")
        os.rename(
            name,
            "candidate",
            src_dir_fd=target.parent_descriptor,
            dst_dir_fd=quarantine_descriptor,
        )
        candidate_present = True
        candidate = os.stat(
            "candidate",
            dir_fd=quarantine_descriptor,
            follow_symlinks=False,
        )
        opened_output = os.fstat(descriptor)
        if (candidate.st_dev, candidate.st_ino) == (
            opened_output.st_dev,
            opened_output.st_ino,
        ):
            # The public leaf has already moved atomically. The remaining
            # stat/unlink pair is confined to this private 0700 quarantine.
            os.unlink("candidate", dir_fd=quarantine_descriptor)
            candidate_present = False
            removed = True
        else:
            try:
                if stat.S_ISDIR(candidate.st_mode):
                    _restore_quarantined_directory(
                        target,
                        quarantine_descriptor,
                        name,
                        candidate,
                    )
                    candidate_present = False
                else:
                    os.link(
                        "candidate",
                        name,
                        src_dir_fd=quarantine_descriptor,
                        dst_dir_fd=target.parent_descriptor,
                        follow_symlinks=False,
                    )
            except BaseException as exc:
                raise RuntimeError(
                    "target acceptance output replacement could not be restored without overwrite"
                ) from exc
            if candidate_present:
                os.unlink("candidate", dir_fd=quarantine_descriptor)
                candidate_present = False
            removed = False
    except FileNotFoundError as primary:
        cleanup_errors = _finish_output_quarantine(
            target,
            quarantine_name,
            quarantine_descriptor,
            remove_directory=quarantine_owned and not candidate_present,
        )
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance output removal and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        if candidate_present:
            raise
        return False
    except BaseException as primary:
        cleanup_errors = _finish_output_quarantine(
            target,
            quarantine_name,
            quarantine_descriptor,
            remove_directory=quarantine_owned and not candidate_present,
        )
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance output removal and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise
    cleanup_errors = _finish_output_quarantine(
        target,
        quarantine_name,
        quarantine_descriptor,
        remove_directory=True,
    )
    if cleanup_errors:
        if len(cleanup_errors) == 1:
            raise cleanup_errors[0]
        raise BaseExceptionGroup("target acceptance output removal cleanup failed", cleanup_errors)
    return removed


def _publish_chunks_to_target(
    target: _PinnedOutputTarget,
    chunks: object,
) -> None:
    if _validate_existing_output(target):
        return
    temporary_name = f".{target.path.name}.tmp-{uuid4().hex}"
    output = os.open(
        temporary_name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=target.parent_descriptor,
    )
    temporary_owned = True
    linked = False
    try:
        digest = hashlib.sha256()
        consumed = 0
        for chunk in chunks:  # type: ignore[union-attr]
            if not isinstance(chunk, bytes) or not chunk:
                raise ValueError("target acceptance output chunk is invalid")
            consumed += len(chunk)
            if consumed > target.expected_bytes:
                raise RuntimeError("target acceptance output differs from its binding")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise OSError("short target acceptance output write")
                view = view[written:]
        before_link = os.fstat(output)
        if (
            consumed != target.expected_bytes
            or digest.hexdigest() != target.expected_sha256
            or not stat.S_ISREG(before_link.st_mode)
            or before_link.st_uid != os.geteuid()
            or stat.S_IMODE(before_link.st_mode) != 0o600
            or before_link.st_nlink != 1
            or before_link.st_dev != target.parent_metadata.st_dev
            or before_link.st_size != target.expected_bytes
        ):
            raise RuntimeError("target acceptance output differs from its binding")
        os.fsync(output)
        _revalidate_output_parent(
            target.path,
            target.parent_descriptor,
            target.parent_metadata,
        )
        try:
            os.link(
                temporary_name,
                target.path.name,
                src_dir_fd=target.parent_descriptor,
                dst_dir_fd=target.parent_descriptor,
                follow_symlinks=False,
            )
            linked = True
        except FileExistsError:
            if not _validate_existing_output(target):
                raise RuntimeError("target acceptance output publication raced")
        if not _remove_owned_output_name(target, temporary_name, output):
            raise RuntimeError("target acceptance output temporary changed")
        temporary_owned = False
        published = os.fstat(output)
        if linked and (
            not stat.S_ISREG(published.st_mode)
            or published.st_nlink != 1
            or published.st_uid != os.geteuid()
            or stat.S_IMODE(published.st_mode) != 0o600
            or published.st_dev != target.parent_metadata.st_dev
            or published.st_size != target.expected_bytes
        ):
            raise RuntimeError("published target acceptance output metadata changed")
        os.fsync(target.parent_descriptor)
        _revalidate_output_parent(
            target.path,
            target.parent_descriptor,
            target.parent_metadata,
        )
    finally:
        if temporary_owned:
            try:
                _remove_owned_output_name(target, temporary_name, output)
            except BaseException:
                pass
        os.close(output)
    if not _validate_existing_output(target):
        raise RuntimeError("published target acceptance output is unavailable")


def _stage_chunks_for_batch(
    target: _PinnedOutputTarget,
    chunks: object,
) -> _StagedOutput | None:
    if _validate_existing_output(target):
        return None
    temporary_name = f".{target.path.name}.tmp-{uuid4().hex}"
    descriptor = os.open(
        temporary_name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=target.parent_descriptor,
    )
    try:
        digest = hashlib.sha256()
        consumed = 0
        for chunk in chunks:  # type: ignore[union-attr]
            if not isinstance(chunk, bytes) or not chunk:
                raise ValueError("target acceptance output chunk is invalid")
            consumed += len(chunk)
            if consumed > target.expected_bytes:
                raise RuntimeError("target acceptance output differs from its binding")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short target acceptance output write")
                view = view[written:]
        metadata = os.fstat(descriptor)
        if (
            consumed != target.expected_bytes
            or digest.hexdigest() != target.expected_sha256
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_dev != target.parent_metadata.st_dev
            or metadata.st_size != target.expected_bytes
        ):
            raise RuntimeError("target acceptance output differs from its binding")
        os.fsync(descriptor)
        return _StagedOutput(
            target=target,
            temporary_name=temporary_name,
            descriptor=descriptor,
        )
    except BaseException as primary:
        cleanup_errors: list[BaseException] = []
        try:
            _remove_owned_output_name(
                target,
                temporary_name,
                descriptor,
            )
        except BaseException as exc:
            cleanup_errors.append(exc)
        try:
            os.close(descriptor)
        except BaseException as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance staging and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise


def _name_is_owned_output(
    staged: _StagedOutput,
    name: str,
) -> bool:
    opened = os.fstat(staged.descriptor)
    try:
        current = os.stat(
            name,
            dir_fd=staged.target.parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    return (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino)


def _require_staged_output_metadata(staged: _StagedOutput) -> None:
    metadata = os.fstat(staged.descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_dev != staged.target.parent_metadata.st_dev
        or metadata.st_size != staged.target.expected_bytes
    ):
        raise RuntimeError("published target acceptance output metadata changed")


def _publish_staged_output(
    staged: _StagedOutput,
    newly_linked: list[_StagedOutput],
) -> None:
    target = staged.target
    _revalidate_output_parent(
        target.path,
        target.parent_descriptor,
        target.parent_metadata,
    )
    # A link syscall can complete and still surface an error to Python. Register
    # the runner-owned inode first so outer rollback always probes the
    # potentially exposed final name.
    newly_linked.append(staged)
    linked = False
    try:
        os.link(
            staged.temporary_name,
            target.path.name,
            src_dir_fd=target.parent_descriptor,
            dst_dir_fd=target.parent_descriptor,
            follow_symlinks=False,
        )
        linked = True
    except FileExistsError as primary:
        try:
            linked = _name_is_owned_output(staged, target.path.name)
        except BaseException as probe:
            raise BaseExceptionGroup(
                "target acceptance link and ownership probe both failed",
                [primary, probe],
            ) from primary
        if not linked:
            opened_winner = _open_validated_existing_output(target)
            if opened_winner is None:
                raise RuntimeError("target acceptance output publication raced")
            winner_descriptor, winner_metadata = opened_winner
            try:
                if _output_inode_binding(os.fstat(winner_descriptor)) != _output_inode_binding(
                    winner_metadata
                ):
                    raise RuntimeError("target acceptance output leaf binding changed")
                if not _remove_owned_output_name(
                    target,
                    staged.temporary_name,
                    staged.descriptor,
                ):
                    raise RuntimeError("target acceptance output temporary changed")
                _revalidate_output_parent(
                    target.path,
                    target.parent_descriptor,
                    target.parent_metadata,
                )
                _require_output_leaf_binding(
                    target,
                    winner_descriptor,
                    winner_metadata,
                )
            except BaseException as winner_primary:
                try:
                    os.close(winner_descriptor)
                except BaseException as cleanup:
                    raise BaseExceptionGroup(
                        "target acceptance winner handling and cleanup both failed",
                        [winner_primary, cleanup],
                    ) from winner_primary
                raise
            os.close(winner_descriptor)
            return
    except BaseException as primary:
        try:
            _name_is_owned_output(staged, target.path.name)
        except BaseException as probe:
            raise BaseExceptionGroup(
                "target acceptance link and ownership probe both failed",
                [primary, probe],
            ) from primary
        raise
    if not linked:
        raise RuntimeError("target acceptance output publication failed")
    if not _remove_owned_output_name(
        target,
        staged.temporary_name,
        staged.descriptor,
    ):
        raise RuntimeError("target acceptance output temporary changed")
    _require_staged_output_metadata(staged)
    _revalidate_output_parent(
        target.path,
        target.parent_descriptor,
        target.parent_metadata,
    )
    if not _validate_existing_output(target):
        raise RuntimeError("published target acceptance output is unavailable")


def _rollback_new_outputs(
    newly_linked: list[_StagedOutput],
) -> list[BaseException]:
    errors: list[BaseException] = []
    for staged in reversed(newly_linked):
        try:
            _remove_owned_output_name(
                staged.target,
                staged.target.path.name,
                staged.descriptor,
            )
        except BaseException as exc:
            errors.append(exc)
    return errors


def _close_staged_outputs(
    staged_outputs: list[_StagedOutput],
) -> list[BaseException]:
    errors: list[BaseException] = []
    for staged in reversed(staged_outputs):
        try:
            _remove_owned_output_name(
                staged.target,
                staged.temporary_name,
                staged.descriptor,
            )
        except BaseException as exc:
            errors.append(exc)
        try:
            os.close(staged.descriptor)
        except BaseException as exc:
            errors.append(exc)
    return errors


def _publish_exact_bytes(path: Path, payload: bytes) -> None:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ACCEPTANCE_ENVELOPE_BYTES:
        raise ValueError("target acceptance output payload is invalid")
    target = _preflight_output_targets(((path, len(payload), hashlib.sha256(payload).hexdigest()),))
    try:
        _publish_chunks_to_target(target[0], (payload,))
    except BaseException as primary:
        cleanup_errors = _close_publication_handles(target)
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance byte publication and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise
    else:
        cleanup_errors = _close_publication_handles(target)
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance byte publication cleanup failed",
                cleanup_errors,
            )


def _open_exact_source(
    source: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> tuple[int, tuple[int, int, int, int, int, int]]:
    if (
        expected_bytes < 1
        or expected_bytes > MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise ValueError("target journal proof publication binding is invalid")
    descriptor = os.open(
        source,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected_bytes
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise ValueError("target journal proof source is unsafe")
        digest = hashlib.sha256()
        consumed = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            consumed += len(chunk)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
        )
        if (
            consumed != expected_bytes
            or digest.hexdigest() != expected_sha256
            or identity
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_nlink,
            )
        ):
            raise ValueError("target journal proof source digest differs")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, identity
    except BaseException as primary:
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "target journal proof source validation and cleanup both failed",
                [primary, cleanup],
            ) from primary
        raise


def _require_source_unchanged(
    descriptor: int,
    expected: tuple[int, int, int, int, int, int],
) -> None:
    current = os.fstat(descriptor)
    if expected != (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
        current.st_nlink,
    ):
        raise RuntimeError("target journal proof source changed during publication")


def _publish_exact_file(
    path: Path,
    source: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> None:
    source_descriptor, source_identity = _open_exact_source(
        source,
        expected_bytes=expected_bytes,
        expected_sha256=expected_sha256,
    )
    targets: tuple[_PinnedOutputTarget, ...] = ()
    try:
        targets = _preflight_output_targets(((path, expected_bytes, expected_sha256),))
        os.lseek(source_descriptor, 0, os.SEEK_SET)

        def chunks() -> object:
            while chunk := os.read(source_descriptor, 1024 * 1024):
                yield chunk

        _publish_chunks_to_target(targets[0], chunks())
        _require_source_unchanged(source_descriptor, source_identity)
    except BaseException as primary:
        cleanup_errors = _close_publication_handles(
            targets,
            (source_descriptor,),
        )
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target proof publication and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise
    else:
        cleanup_errors = _close_publication_handles(
            targets,
            (source_descriptor,),
        )
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target proof publication cleanup failed",
                cleanup_errors,
            )


def _write_new_target_artifacts(
    *,
    record_path: Path,
    attestation_path: Path,
    signature_path: Path,
    proof_path: Path,
    proof_source: Path,
    record: AcceptanceRunRecordV2,
    attestation: TargetRunAttestationV2,
    signature: bytes,
) -> None:
    payloads = (
        (
            record_path,
            json.dumps(
                record.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode(),
        ),
        (
            attestation_path,
            json.dumps(
                attestation.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode(),
        ),
        (signature_path, signature),
    )
    paths = tuple(path for path, _payload in payloads)
    if len(set((*paths, proof_path))) != 4 or len(signature) != 64:
        raise ValueError("target acceptance outputs must be four distinct paths")
    source_descriptor, source_identity = _open_exact_source(
        proof_source,
        expected_bytes=attestation.journal_proof_bytes,
        expected_sha256=attestation.journal_proof_sha256,
    )
    targets: tuple[_PinnedOutputTarget, ...] = ()
    staged_outputs: list[_StagedOutput] = []
    newly_linked: list[_StagedOutput] = []
    try:
        targets = _preflight_output_targets(
            (
                *(
                    (path, len(payload), hashlib.sha256(payload).hexdigest())
                    for path, payload in payloads
                ),
                (
                    proof_path,
                    attestation.journal_proof_bytes,
                    attestation.journal_proof_sha256,
                ),
            )
        )
        staged_by_target: list[_StagedOutput | None] = []
        for target, (_path, payload) in zip(targets[:3], payloads, strict=True):
            staged = _stage_chunks_for_batch(target, (payload,))
            staged_by_target.append(staged)
            if staged is not None:
                staged_outputs.append(staged)
        os.lseek(source_descriptor, 0, os.SEEK_SET)

        def proof_chunks() -> object:
            while chunk := os.read(source_descriptor, 1024 * 1024):
                yield chunk

        staged_proof = _stage_chunks_for_batch(targets[-1], proof_chunks())
        staged_by_target.append(staged_proof)
        if staged_proof is not None:
            staged_outputs.append(staged_proof)
        _require_source_unchanged(source_descriptor, source_identity)
        for staged in staged_by_target:
            if staged is not None:
                _publish_staged_output(staged, newly_linked)
        _require_source_unchanged(source_descriptor, source_identity)
        for target in targets:
            if not _validate_existing_output(target):
                raise RuntimeError("published target acceptance output is unavailable")
    except BaseException as primary:
        cleanup_errors = [
            *_rollback_new_outputs(newly_linked),
            *_close_staged_outputs(staged_outputs),
            *_close_publication_handles(
                targets,
                (source_descriptor,),
            ),
        ]
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance publication and rollback both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise
    else:
        cleanup_errors = [
            *_close_staged_outputs(staged_outputs),
            *_close_publication_handles(
                targets,
                (source_descriptor,),
            ),
        ]
        if cleanup_errors:
            raise BaseExceptionGroup(
                "target acceptance publication cleanup failed",
                cleanup_errors,
            )


def _launch_staged_container(
    arguments: argparse.Namespace,
    *,
    reviewed: ReviewedTargetLaunch,
    launch_nonce: str,
    work_root: Path,
) -> DockerRuntimeProcess:
    mount_payload = read_regular_bounded(
        arguments.mount_contract,
        max_bytes=8 * 1024 * 1024,
        label="runtime mount contract",
    )
    if hashlib.sha256(mount_payload).hexdigest() != arguments.mount_contract_sha256:
        raise ValueError("runtime mount contract digest differs from reviewed input")
    contract = _load_runtime_mount_contract(mount_payload)
    expected_image_id = f"sha256:{arguments.runtime_image_id_sha256}"
    if contract.image_id != expected_image_id:
        raise ValueError("runtime mount contract image differs from launch")
    original_by_target = {mount.target: mount for mount in contract.mounts}
    reviewed_sources = {
        Path("/run/config/site.yaml"): arguments.site_config,
        Path("/run/config/runtime-manifest.yaml"): arguments.runtime_manifest,
        Path("/run/config/measured-capacity.yaml"): (arguments.measured_capacity_report),
        Path("/run/config/measured-capacity.sig"): (arguments.measured_capacity_signature),
    }
    if (
        any(
            target not in original_by_target or original_by_target[target].source != source
            for target, source in reviewed_sources.items()
        )
        or Path("/run/config/capacity-authority.pem") not in original_by_target
    ):
        raise ValueError("runtime mount contract substitutes a reviewed input source")
    staged = stage_runtime_mount_contract(
        contract=contract,
        work_root=work_root,
        captured_by_target={
            Path("/run/config/site.yaml"): reviewed.snapshots.site_config,
            Path("/run/config/runtime-manifest.yaml"): (reviewed.snapshots.runtime_manifest),
            Path("/run/config/measured-capacity.yaml"): (reviewed.snapshots.capacity.payload),
            Path("/run/config/measured-capacity.sig"): (reviewed.snapshots.capacity.signature),
            Path("/run/config/capacity-authority.pem"): (reviewed.snapshots.capacity.trust_key),
        },
    )
    staged_by_target = {mount.target: mount.source for mount in staged.mounts}
    mount_argv = validate_runtime_mount_contract(
        site_config=reviewed.site,
        runtime_manifest=reviewed.runtime,
        contract=staged,
        expected_image_id=expected_image_id,
        site_config_source=staged_by_target[Path("/run/config/site.yaml")],
        runtime_manifest_source=staged_by_target[Path("/run/config/runtime-manifest.yaml")],
        measured_capacity_source=staged_by_target[Path("/run/config/measured-capacity.yaml")],
        measured_capacity_signature_source=staged_by_target[
            Path("/run/config/measured-capacity.sig")
        ],
        capacity_authority_public_key_source=staged_by_target[
            Path("/run/config/capacity-authority.pem")
        ],
    )
    return launch_docker_runtime(
        engine_path=arguments.container_engine,
        nvidia_ctk_path=arguments.nvidia_ctk,
        image_id=expected_image_id,
        image_config_sha256=arguments.runtime_image_config_sha256,
        runtime_code_sha256=arguments.runtime_code_sha256,
        mount_contract_sha256=arguments.mount_contract_sha256,
        launch_nonce=launch_nonce,
        command=target_command(arguments, launch_nonce=launch_nonce),
        mount_argv=mount_argv,
        control_network=arguments.control_network,
        camera_network=arguments.camera_network,
        expected_control_network_id=(reviewed.launch.expected_control_network_id),
        expected_control_network_config_sha256=(
            reviewed.launch.expected_control_network_config_sha256
        ),
        expected_camera_network_id=(reviewed.launch.expected_camera_network_id),
        expected_camera_network_config_sha256=(
            reviewed.launch.expected_camera_network_config_sha256
        ),
        expected_gpu_device_ids=reviewed.launch.gpu_device_ids,
        expected_gpu_product_name=reviewed.launch.gpu_product_name,
        expected_gpu_pci_bus_id=reviewed.launch.gpu_pci_bus_id,
        expected_gpu_total_vram_bytes=(reviewed.launch.gpu_total_vram_bytes),
        expected_gpu_compute_capability=(reviewed.launch.gpu_compute_capability),
        expected_gpu_mig_mode=reviewed.launch.gpu_mig_mode,
        expected_gpu_inventory_sha256=(reviewed.launch.gpu_inventory_sha256),
        expected_nvidia_driver_version=(reviewed.launch.nvidia_driver_version),
        expected_cuda_driver_version=(reviewed.launch.cuda_driver_version),
        expected_cuda_runtime_version=(reviewed.launch.cuda_runtime_version),
        expected_nvidia_container_toolkit_version=(
            reviewed.launch.nvidia_container_toolkit_version
        ),
    )


def _stage_reviewed_runtime_mounts(
    arguments: argparse.Namespace,
    *,
    reviewed: ReviewedTargetLaunch,
    work_root: Path,
) -> tuple[tuple[str, ...], frozenset[Path]]:
    """Stage one epoch's immutable base mounts without launching a process."""

    work_root.mkdir(mode=0o700)
    mount_payload = read_regular_bounded(
        arguments.mount_contract,
        max_bytes=8 * 1024 * 1024,
        label="runtime mount contract",
    )
    if hashlib.sha256(mount_payload).hexdigest() != arguments.mount_contract_sha256:
        raise ValueError("runtime mount contract digest differs from reviewed input")
    contract = _load_runtime_mount_contract(mount_payload)
    expected_image_id = f"sha256:{arguments.runtime_image_id_sha256}"
    if contract.image_id != expected_image_id:
        raise ValueError("runtime mount contract image differs from launch")
    original_by_target = {mount.target: mount for mount in contract.mounts}
    reviewed_sources = {
        Path("/run/config/site.yaml"): arguments.site_config,
        Path("/run/config/runtime-manifest.yaml"): arguments.runtime_manifest,
        Path("/run/config/measured-capacity.yaml"): (
            arguments.measured_capacity_report
        ),
        Path("/run/config/measured-capacity.sig"): (
            arguments.measured_capacity_signature
        ),
    }
    if (
        any(
            target not in original_by_target
            or original_by_target[target].source != source
            for target, source in reviewed_sources.items()
        )
        or Path("/run/config/capacity-authority.pem")
        not in original_by_target
    ):
        raise ValueError("runtime mount contract substitutes a reviewed input source")
    staged = stage_runtime_mount_contract(
        contract=contract,
        work_root=work_root,
        captured_by_target={
            Path("/run/config/site.yaml"): reviewed.snapshots.site_config,
            Path("/run/config/runtime-manifest.yaml"): (
                reviewed.snapshots.runtime_manifest
            ),
            Path("/run/config/measured-capacity.yaml"): (
                reviewed.snapshots.capacity.payload
            ),
            Path("/run/config/measured-capacity.sig"): (
                reviewed.snapshots.capacity.signature
            ),
            Path("/run/config/capacity-authority.pem"): (
                reviewed.snapshots.capacity.trust_key
            ),
        },
    )
    staged_by_target = {mount.target: mount.source for mount in staged.mounts}
    mount_argv = validate_runtime_mount_contract(
        site_config=reviewed.site,
        runtime_manifest=reviewed.runtime,
        contract=staged,
        expected_image_id=expected_image_id,
        site_config_source=staged_by_target[Path("/run/config/site.yaml")],
        runtime_manifest_source=staged_by_target[
            Path("/run/config/runtime-manifest.yaml")
        ],
        measured_capacity_source=staged_by_target[
            Path("/run/config/measured-capacity.yaml")
        ],
        measured_capacity_signature_source=staged_by_target[
            Path("/run/config/measured-capacity.sig")
        ],
        capacity_authority_public_key_source=staged_by_target[
            Path("/run/config/capacity-authority.pem")
        ],
    )
    original_sources = frozenset(
        mount.source for mount in contract.mounts
    )
    return (
        mount_argv,
        original_sources | frozenset(staged_by_target.values()),
    )


def _load_runtime_mount_contract(payload: bytes) -> RuntimeMountContractV1:
    """Parse a digest-bound runtime mount contract without YAML ambiguity."""
    try:
        parsed = load_strict_yaml(
            payload,
            max_bytes=_MAX_RUNTIME_MOUNT_CONTRACT_YAML_BYTES,
            max_nodes=_MAX_RUNTIME_MOUNT_CONTRACT_YAML_NODES,
            max_depth=_MAX_RUNTIME_MOUNT_CONTRACT_YAML_DEPTH,
            require_mapping=True,
        )
    except StrictYAMLError as exc:
        raise ValueError("runtime mount contract is invalid") from exc
    try:
        return RuntimeMountContractV1.model_validate(parsed)
    except ValueError as exc:
        raise ValueError("runtime mount contract is invalid") from exc


_GATE_BY_DURATION: dict[int, AcceptanceGate] = {
    28_800: "8h",
    259_200: "72h",
}


def _verify_target_acceptance_context(
    arguments: argparse.Namespace,
) -> AcceptanceAuthorityTrustContextV2:
    """Verify target trust before any campaign-owned state can be opened."""
    duration = getattr(arguments, "duration_seconds", None)
    if duration not in _GATE_BY_DURATION:
        raise ValueError("target duration must be exactly the 8h or 72h gate")
    gate = _GATE_BY_DURATION[duration]
    if getattr(arguments, "acceptance_gate", None) != gate:
        raise ValueError("configured acceptance gate differs from target duration")
    if not 1 <= getattr(arguments, "stop_grace_seconds", 0) <= 60:
        raise ValueError("target stop grace must be finite and at most 60 seconds")
    if getattr(arguments, "collector_interval_seconds", None) != 60:
        raise ValueError("target collector interval must be exactly 60 seconds")
    required_paths = (
        "acceptance_offline_root_public_key",
        "acceptance_trust_policy",
        "acceptance_trust_policy_signature",
        "acceptance_manifest_role_public_key",
        "acceptance_capacity_role_public_key",
        "acceptance_run_role_public_key",
        "acceptance_report_role_public_key",
        "acceptance_conditional_role_public_key",
        "manifest",
        "manifest_signature",
    )
    if any(not isinstance(getattr(arguments, name, None), Path) for name in required_paths):
        raise ValueError("target mode requires the complete offline-root trust chain")
    configured_site_id = getattr(arguments, "acceptance_site_id", None)
    configured_campaign_id = getattr(
        arguments,
        "acceptance_campaign_id",
        None,
    )
    expected_root = getattr(
        arguments,
        "acceptance_offline_root_spki_sha256",
        None,
    )
    if (
        not isinstance(configured_site_id, str)
        or not configured_site_id
        or not isinstance(configured_campaign_id, str)
        or not configured_campaign_id
        or not isinstance(expected_root, str)
    ):
        raise ValueError("target mode requires exact site, campaign, and offline root")
    trust = verify_acceptance_trust_chain(
        expected_offline_root_spki_sha256=expected_root,
        root_public_key_path=arguments.acceptance_offline_root_public_key,
        policy_path=arguments.acceptance_trust_policy,
        policy_signature_path=arguments.acceptance_trust_policy_signature,
        role_public_key_paths=AcceptanceRolePublicKeyPathsV2(
            manifest=arguments.acceptance_manifest_role_public_key,
            capacity=arguments.acceptance_capacity_role_public_key,
            run=arguments.acceptance_run_role_public_key,
            report=arguments.acceptance_report_role_public_key,
            conditional=arguments.acceptance_conditional_role_public_key,
        ),
        manifest_path=arguments.manifest,
        manifest_signature_path=arguments.manifest_signature,
    )
    return build_authority_trust_context(
        trust=trust,
        configured_site_id=configured_site_id,
        configured_campaign_id=configured_campaign_id,
        configured_gate=gate,
    )


class RetainedRuntimeTargetV3Collector:
    """Collect the V2 compatibility graph on the C2-authorized retained epoch."""

    def __init__(
        self,
        *,
        collector: AuthenticatedTargetCollector,
        trust_context: AcceptanceAuthorityTrustContextV2,
        continuation: TargetRuntimeContinuationCoordinatorV3,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            type(collector) is not AuthenticatedTargetCollector
            or type(continuation)
            is not TargetRuntimeContinuationCoordinatorV3
        ):
            raise TypeError("retained V3 collection requires the exact collector")
        self._collector = collector
        self._continuation = continuation
        self._trust_context = _require_authority_trust_context(trust_context)
        if not callable(monotonic) or not callable(sleep):
            raise TypeError("retained V3 collector clocks are invalid")
        self._monotonic = monotonic
        self._sleep = sleep
        self.collected: TargetV3CollectedEvidence | None = None

    def __call__(
        self,
        arguments: argparse.Namespace,
        campaign: TargetCampaignCompletionV3,
    ) -> TargetV3CollectedEvidence:
        try:
            collected = self._collect(arguments, campaign)
        except BaseException as primary:
            try:
                self._continuation.cleanup(campaign)
            except BaseException as cleanup:
                raise BaseExceptionGroup(
                    "retained V3 collection and continuation cleanup failed",
                    [primary, cleanup],
                ) from primary
            raise
        self._continuation.cleanup(campaign)
        self.collected = collected
        return collected

    def _collect(
        self,
        arguments: argparse.Namespace,
        campaign: TargetCampaignCompletionV3,
    ) -> TargetV3CollectedEvidence:
        if type(campaign) is not TargetCampaignCompletionV3:
            raise TypeError("retained V3 collector requires exact campaign evidence")
        if campaign.c2_evidence.collector_id != self._collector.campaign_collector_id:
            raise ValueError("retained V3 collector identity differs from C2")
        context = self._trust_context
        manifest = context.trust.manifest
        runtime = campaign.final_runtime
        identity = runtime.reverify_identity()
        request = identity.launch_request
        if (
            identity.identity_sha256
            != campaign.c2_evidence.epochs[-1].runtime_identity_sha256
            or request.launch != context.launch
        ):
            raise ValueError("retained runtime identity differs from final C2 epoch")
        execution = ExecutionBindingV2(
            schema_version="acceptance-execution-binding.v2",
            launch_attestation_sha256=request.launch.attestation_sha256,
            launch_nonce=request.launch_nonce,
            container_id=identity.container_id,
            container_config_sha256=identity.container_config_sha256,
            runtime_image_id_sha256=identity.runtime_image_id_sha256,
            acceptance_adapter_sha256=request.launch.acceptance_adapter_sha256,
            acceptance_adapter_policy_sha256=(
                request.launch.acceptance_adapter_policy_sha256
            ),
            acceptance_observer_sha256=(
                request.launch.acceptance_observer_sha256
            ),
            acceptance_observer_policy_sha256=(
                request.launch.acceptance_observer_policy_sha256
            ),
            control_network_id=identity.control_network_id,
            control_network_config_sha256=(
                identity.control_network_config_sha256
            ),
            camera_network_id=identity.camera_network_id,
            camera_network_config_sha256=(
                identity.camera_network_config_sha256
            ),
            observed_gpu_inventory_sha256=(
                identity.observed_gpu_inventory.launch_compatibility_sha256
            ),
        )
        workloads = tuple(
            CameraAcceptanceWorkloadV2(
                camera_id=source.camera_id,
                source_index=source.source_index,
                source_kind=source.source.kind,
                source_reference=(
                    source.source.path
                    if isinstance(source.source, LocalFixtureSourceV2)
                    else source.source.secret_reference
                ),
                codec=source.codec,
                width=source.width,
                height=source.height,
                fps=source.fps,
                bitrate_kbps=source.bitrate_kbps,
                analytics_hz=source.analytics_hz,
            )
            for source in manifest.sources
        )
        schedule = context.fault_schedule
        restart_faults = tuple(
            fault for fault in schedule if fault.kind == "runtime_restart"
        )
        if len(restart_faults) != 1:
            raise RuntimeError(
                "retained V3 collector requires one canonical runtime restart"
            )
        restart_fault = restart_faults[0]
        self._collector.start(
            site_id=context.configured_site_id,
            manifest_sha256=manifest.manifest_sha256,
            gate=context.configured_gate,
            camera_ids=context.camera_ids,
            workloads=workloads,
            sample_interval_seconds=arguments.collector_interval_seconds,
            launch=request.launch,
            execution=execution,
            schedule=schedule,
        )
        pending = sorted(
            command
            for fault in schedule
            for command in (
                (fault.offset_seconds, fault.fault_id, "inject"),
                (
                    fault.offset_seconds + fault.duration_seconds,
                    fault.fault_id,
                    "recover",
                ),
            )
        )
        started = self._monotonic()
        deadline = started + arguments.duration_seconds
        next_sample = 0.0
        continuation_completion = None
        replacement_launched = False
        while True:
            now = self._monotonic()
            elapsed = now - started
            while pending and pending[0][0] <= elapsed:
                boundary, fault_id, phase = pending.pop(0)
                fault = next(
                    item for item in schedule if item.fault_id == fault_id
                )
                if fault is restart_fault and phase == "inject":
                    runtime = _advance_target_runtime_restart_v3(
                        continuation=self._continuation,
                        collector=self._collector,
                        campaign=campaign,
                        previous_execution=execution,
                        fault=fault,
                        phase=phase,
                        at_offset=boundary,
                    )
                elif fault is restart_fault and phase == "recover":
                    runtime = _advance_target_runtime_restart_v3(
                        continuation=self._continuation,
                        collector=self._collector,
                        campaign=campaign,
                        previous_execution=execution,
                        fault=fault,
                        phase=phase,
                        at_offset=boundary,
                    )
                    replacement_launched = True
                else:
                    self._collector.command_fault(
                        fault_id=fault_id,
                        phase=phase,
                        at_offset=boundary,
                    )
            if runtime is not None:
                runtime.reverify_identity()
                if runtime.poll() is not None:
                    raise RuntimeError(
                        "retained V3 runtime exited before the selected gate"
                    )
            if replacement_launched and continuation_completion is None:
                continuation_completion = (
                    self._continuation.poll_authorization()
                )
            if elapsed >= next_sample and runtime is not None:
                self._collector.collect(
                    process_healthy=True,
                    scheduled_monotonic_offset_seconds=next_sample,
                )
                next_sample += arguments.collector_interval_seconds
            if now >= deadline:
                break
            next_boundary = min(
                arguments.duration_seconds,
                next_sample,
                pending[0][0] if pending else arguments.duration_seconds,
                (
                    elapsed + 0.25
                    if replacement_launched
                    and runtime is not None
                    and continuation_completion is None
                    else arguments.duration_seconds
                ),
            )
            self._sleep(max(0.0, next_boundary - elapsed))
        if (
            runtime is None
            or continuation_completion is None
            or runtime is not continuation_completion.final_runtime
        ):
            raise RuntimeError(
                "retained V3 gate ended before epoch-three authorization"
            )
        runtime.reverify_identity()
        runtime.terminate(timeout_seconds=arguments.stop_grace_seconds)
        exit_code = runtime.wait(
            timeout_seconds=float(arguments.stop_grace_seconds)
        )
        if exit_code != 0:
            raise RuntimeError("retained V3 runtime did not stop cleanly")
        record = self._collector.finish()
        attestation = self._collector.final_attestation
        signature = self._collector.final_signature
        if (
            record.run_id != campaign.c2_evidence.collector_id
            or record.environment != "target"
            or record.site_id != campaign.c2_evidence.site_id
            or record.gate != campaign.c2_evidence.gate
            or record.launch != request.launch
            or record.execution != execution
            or attestation is None
            or signature is None
        ):
            raise RuntimeError("retained V3 collector final graph differs")
        envelope = AcceptanceFinalEnvelopeV2(
            schema_version="acceptance-final-envelope.v2",
            record=record,
            attestation=attestation,
            signature_hex=signature.hex(),
        )
        proof_binding = {
            "collector_id": record.run_id,
            "site_id": record.site_id,
            "manifest_sha256": record.manifest_sha256,
            "gate": record.gate,
            "launch_attestation_sha256": record.launch.attestation_sha256,
            "execution_binding_sha256": record.execution.binding_sha256,
            "fault_schedule_sha256": canonical_fault_schedule_sha256(schedule),
            "trust_binding": context.binding.model_dump(mode="json"),
        }
        with tempfile.TemporaryDirectory(
            prefix=".kuzet-v3-proof-download-"
        ) as temporary:
            proof_source = Path(temporary) / "journal-proof.jsonl"
            _download_journal_proof(
                base_url=arguments.control_plane_url,
                acceptance_controller_token_file=(
                    arguments.acceptance_controller_token_file
                ),
                binding=proof_binding,
                attestation=attestation,
                record=record,
                destination=proof_source,
            )
            _write_new_target_artifacts(
                record_path=arguments.out,
                attestation_path=arguments.out_attestation,
                signature_path=arguments.out_signature,
                proof_path=arguments.out_journal_proof,
                proof_source=proof_source,
                record=record,
                attestation=attestation,
                signature=signature,
            )
        collected = TargetV3CollectedEvidence(
            final_envelope=envelope,
            journal_proof_path=arguments.out_journal_proof,
            continuation_capability=continuation_completion.capability,
        )
        return collected


def run_target_v3(
    arguments: argparse.Namespace,
    *,
    coordinator: TargetCampaignCoordinatorV3,
    collector_runner: TargetV3CollectorRunner,
    trust_context: AcceptanceAuthorityTrustContextV2,
    signer: AcceptanceRunSigner,
) -> tuple[
    SignedTargetAuthorityBindingV3,
    VerifiedAcceptanceJournalProofV2,
]:
    """Run C2 first, collect on its retained epoch, then sign the exact V2 graph."""

    if type(coordinator) is not TargetCampaignCoordinatorV3:
        raise TypeError("target replay requires the exact V3 campaign coordinator")
    if type(collector_runner) is not RetainedRuntimeTargetV3Collector:
        raise TypeError(
            "target replay requires the exact retained V3 collector runner"
        )
    context = _require_authority_trust_context(trust_context)
    campaign = coordinator.run()
    if type(campaign) is not TargetCampaignCompletionV3:
        raise TypeError("target campaign returned an invalid completion")
    collected = collector_runner(arguments, campaign)
    if type(collected) is not TargetV3CollectedEvidence:
        raise TypeError("V3 collector returned an invalid evidence capture")
    if (
        collected.final_envelope.record.run_id
        != campaign.c2_evidence.collector_id
        or collected.final_envelope.record.site_id
        != campaign.c2_evidence.site_id
        or collected.final_envelope.record.gate != campaign.c2_evidence.gate
        or collected.final_envelope.record.environment != "target"
    ):
        raise ValueError("V3 collector evidence differs from the C2 campaign")
    # The exact retained collector returns only after ordered epoch-two and
    # epoch-three cleanup.  No caller-owned cleanup seam is accepted here.
    return bind_target_authority_v3(
        c2_capability=campaign.c2_capability,
        continuation_capability=collected.continuation_capability,
        trust_context=context,
        signer=signer,
        final_envelope=collected.final_envelope,
        journal_proof_path=collected.journal_proof_path,
    )


def _require_private_v3_directory(path: object, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError(f"{label} must be one absolute directory")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or os.geteuid() != _TARGET_RUNTIME_UID
        or os.getegid() != _TARGET_RUNTIME_GID
        or metadata.st_uid != _TARGET_RUNTIME_UID
        or metadata.st_gid != _TARGET_RUNTIME_GID
    ):
        raise ValueError(
            f"{label} must be canonical, mode 0700, and owned by "
            "fixed child UID/GID 10001"
        )
    return path


def _require_distinct_directory_identities(
    paths: tuple[Path, ...],
    *,
    label: str,
) -> None:
    """Reject lexical, symlink, and bind-mount aliases of protected roots."""

    if (
        type(paths) is not tuple
        or len(paths) != len(set(paths))
        or any(not isinstance(path, Path) for path in paths)
    ):
        raise ValueError(f"{label} must be distinct")
    resolved_paths: list[Path] = []
    identities: list[tuple[int, int]] = []
    ancestor_identities: list[set[tuple[int, int]]] = []
    for path in paths:
        try:
            resolved = path.resolve(strict=True)
            metadata = path.stat()
            ancestors = {
                (ancestor.stat().st_dev, ancestor.stat().st_ino)
                for ancestor in resolved.parents
            }
        except OSError as exc:
            raise ValueError(f"{label} is unavailable") from exc
        identity = (metadata.st_dev, metadata.st_ino)
        if resolved != path:
            raise ValueError(
                f"{label} contains a path or mounted inode alias"
            )
        resolved_paths.append(resolved)
        identities.append(identity)
        ancestor_identities.append(ancestors)
    for index, path in enumerate(resolved_paths):
        for other_index in range(index + 1, len(resolved_paths)):
            other = resolved_paths[other_index]
            if (
                path in other.parents
                or other in path.parents
                or identities[index] == identities[other_index]
                or identities[index] in ancestor_identities[other_index]
                or identities[other_index] in ancestor_identities[index]
            ):
                raise ValueError(
                    f"{label} contains nested paths or mounted inode aliases"
                )


def _require_unmounted_signer_path(
    path: object,
    *,
    forbidden_roots: tuple[Path, ...],
) -> Path:
    """Keep the run signing key outside every child-visible mount tree."""

    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or type(forbidden_roots) is not tuple
        or any(not isinstance(root, Path) for root in forbidden_roots)
    ):
        raise ValueError("acceptance run signing key path is invalid")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError("acceptance run signing key is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError(
            "acceptance run signing key must remain outside child mounts"
        )
    return _require_host_authority_path_outside_child_mounts(
        path,
        label="acceptance run signing key",
        forbidden_roots=forbidden_roots,
        require_existing=True,
    )


def _require_host_authority_path_outside_child_mounts(
    path: object,
    *,
    label: str,
    forbidden_roots: tuple[Path, ...],
    require_existing: bool,
) -> Path:
    """Reject containment, symlink, hardlink, and mount aliases."""

    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or type(forbidden_roots) is not tuple
        or not forbidden_roots
        or any(
            not isinstance(source, Path) or not source.is_absolute()
            for source in forbidden_roots
        )
    ):
        raise ValueError(f"{label} path is invalid")
    try:
        parent = path.parent.resolve(strict=True)
        if parent != path.parent:
            raise ValueError(f"{label} parent must be canonical")
        for ancestor in (path.parent, *path.parent.parents):
            if stat.S_ISLNK(ancestor.lstat().st_mode):
                raise ValueError(f"{label} has a symlink ancestor")
        sources: list[
            tuple[Path, os.stat_result, tuple[int, int]]
        ] = []
        for source in forbidden_roots:
            resolved_source = source.resolve(strict=True)
            source_metadata = source.lstat()
            for ancestor in (source, *source.parents):
                if stat.S_ISLNK(ancestor.lstat().st_mode):
                    raise ValueError(
                        "child-visible mount source is not canonical"
                    )
            if (
                resolved_source != source
                or not (
                    stat.S_ISREG(source_metadata.st_mode)
                    or stat.S_ISDIR(source_metadata.st_mode)
                )
            ):
                raise ValueError(
                    "child-visible mount source is not canonical"
                )
            sources.append(
                (
                    resolved_source,
                    source_metadata,
                    (source_metadata.st_dev, source_metadata.st_ino),
                )
            )
        authority_ancestor_identities = {
            (ancestor.stat().st_dev, ancestor.stat().st_ino)
            for ancestor in (parent, *parent.parents)
        }
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            resolved = path.resolve(strict=True)
        else:
            if require_existing:
                raise ValueError(f"{label} is unavailable")
            resolved = parent / path.name
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    authority_identity = (
        None
        if metadata is None
        else (metadata.st_dev, metadata.st_ino)
    )
    if (
        resolved != path
        or path.name in {"", ".", ".."}
        or (
            metadata is not None
            and (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
            )
        )
        or any(
            source == resolved
            or source in resolved.parents
            or resolved in source.parents
            or (
                authority_identity is not None
                and authority_identity == source_identity
            )
            or (
                stat.S_ISDIR(source_metadata.st_mode)
                and source_identity in authority_ancestor_identities
            )
            for source, source_metadata, source_identity in sources
        )
    ):
        raise ValueError(
            f"{label} must remain outside every child-visible mount"
        )
    return path


def _required_digest_argument(
    arguments: argparse.Namespace,
    name: str,
) -> str:
    value = getattr(arguments, name, None)
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be one exact SHA-256 digest")
    return value


def _load_reviewed_v3_model(
    path: object,
    model: type[BaseModel],
    *,
    label: str,
) -> BaseModel:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    payload = read_regular_bounded(
        path,
        max_bytes=64 * 1024 * 1024,
        label=label,
    )
    return load_canonical_json_bytes(
        payload,
        model,
        max_bytes=64 * 1024 * 1024,
        label=label,
    )


def run_production_target_v3(
    arguments: argparse.Namespace,
) -> dict[str, object]:
    """Hold one host-wide lease for the complete production V3 campaign."""

    collector_state = getattr(arguments, "collector_state", None)
    if (
        not isinstance(collector_state, Path)
        or not collector_state.is_absolute()
    ):
        raise ValueError(
            "production V3 requires an absolute durable collector state path"
        )
    lock_path = collector_state.with_name(
        f"{collector_state.name}.campaign.lock"
    )
    with TargetCampaignLock(lock_path):
        return _run_production_target_v3_locked(arguments)


def _run_production_target_v3_locked(
    arguments: argparse.Namespace,
) -> dict[str, object]:
    """Compose C2, retained collection, capture publication, and V3 finalization."""

    from protector.pilot.acceptance import load_conditional_gate_decisions
    from protector.pilot.acceptance_capture_v3 import (
        ProtectedAcceptanceCaptureRepositoryV3,
        ReviewedAcceptanceCaptureProducerV3,
    )
    from protector.pilot.acceptance_operational import (
        AcceptanceLimitsV1,
        AuthoritativeRepositoryBoundaryV1,
        OperationalAcceptanceEvidenceV1,
    )
    from protector.pilot.api.acceptance_controller import (
        OpenSSLAcceptanceRunSigner,
    )

    context = _verify_target_acceptance_context(arguments)
    manifest = context.trust.manifest
    reviewed = reviewed_launch_attestation(
        arguments,
        manifest=manifest,
        capacity_authority_public_key=(
            context.trust.role_public_keys.capacity
        ),
    )
    channel_root = _require_private_v3_directory(
        getattr(arguments, "acceptance_channel_dir", None),
        label="acceptance channel root",
    )
    source_secrets = _require_private_v3_directory(
        getattr(arguments, "acceptance_source_secrets_root", None),
        label="acceptance source secret root",
    )
    native_projection_root = _require_private_v3_directory(
        getattr(arguments, "acceptance_native_projection_dir", None),
        label="acceptance native projection root",
    )
    work_projection_root = _require_private_v3_directory(
        getattr(arguments, "acceptance_work_projection_dir", None),
        label="acceptance work projection root",
    )
    capture_root = _require_private_v3_directory(
        getattr(arguments, "acceptance_capture_dir", None),
        label="acceptance capture root",
    )
    snapshot_root = _require_private_v3_directory(
        getattr(arguments, "acceptance_snapshot_dir", None),
        label="acceptance snapshot root",
    )
    v3_proof_root = _require_private_v3_directory(
        getattr(arguments, "acceptance_v3_proof_dir", None),
        label="acceptance V3 proof root",
    )
    transition_journal_candidate = getattr(
        arguments,
        "acceptance_transition_journal",
        None,
    )
    if (
        not isinstance(transition_journal_candidate, Path)
        or not transition_journal_candidate.is_absolute()
        or transition_journal_candidate.name in {"", ".", ".."}
    ):
        raise ValueError(
            "acceptance transition journal must be one absolute file path"
        )
    transition_journal_root = _require_private_v3_directory(
        transition_journal_candidate.parent,
        label="acceptance transition journal root",
    )
    protected_roots = (
        channel_root,
        source_secrets,
        native_projection_root,
        work_projection_root,
        capture_root,
        snapshot_root,
        v3_proof_root,
        transition_journal_root,
    )
    _require_distinct_directory_identities(
        protected_roots,
        label="acceptance V3 protected roots",
    )
    child_visible_roots = (
        channel_root,
        source_secrets,
        native_projection_root,
        work_projection_root,
    )
    _require_host_authority_path_outside_child_mounts(
        getattr(arguments, "acceptance_controller_token_file", None),
        label="acceptance controller token",
        forbidden_roots=child_visible_roots,
        require_existing=True,
    )
    collector_state_candidate = (
        _require_host_authority_path_outside_child_mounts(
            getattr(arguments, "collector_state", None),
            label="acceptance collector state",
            forbidden_roots=child_visible_roots,
            require_existing=False,
        )
    )
    transition_journal_path = (
        _require_host_authority_path_outside_child_mounts(
            transition_journal_candidate,
            label="acceptance transition journal",
            forbidden_roots=child_visible_roots,
            require_existing=False,
        )
    )
    v3_state_candidate = _require_host_authority_path_outside_child_mounts(
        getattr(arguments, "acceptance_v3_state", None),
        label="acceptance V3 state",
        forbidden_roots=child_visible_roots,
        require_existing=True,
    )
    _require_distinct_authority_files(
        (
            ("collector state", collector_state_candidate),
            ("transition journal", transition_journal_path),
            ("V3 state", v3_state_candidate),
        )
    )

    profile_paths = tuple(
        getattr(arguments, "acceptance_source_profile_attestations", ()) or ()
    )
    signature_paths = tuple(
        getattr(arguments, "acceptance_source_profile_signatures", ()) or ()
    )
    launch_nonces = tuple(
        getattr(arguments, "acceptance_launch_nonces", ()) or ()
    )
    if (
        len(profile_paths) != 3
        or len(signature_paths) != 3
        or len(launch_nonces) != 3
        or len(set(launch_nonces)) != 3
        or any(
            type(nonce) is not str
            or len(nonce) != 32
            or any(character not in "0123456789abcdef" for character in nonce)
            for nonce in launch_nonces
        )
    ):
        raise ValueError(
            "production V3 requires exactly three fresh launch profiles"
        )
    first_epoch = getattr(arguments, "acceptance_first_runtime_epoch", None)
    if (
        type(first_epoch) is not int
        or isinstance(first_epoch, bool)
        or not 1 <= first_epoch < 2**63 - 2
    ):
        raise ValueError("acceptance first runtime epoch is invalid")
    attestations = tuple(
        _load_reviewed_v3_model(
            path,
            TargetSourceProfileAttestationV2,
            label=f"acceptance source profile epoch {index + 1}",
        )
        for index, path in enumerate(profile_paths)
    )
    assert all(
        type(attestation) is TargetSourceProfileAttestationV2
        for attestation in attestations
    )
    first_attestation = attestations[0]
    assert isinstance(first_attestation, TargetSourceProfileAttestationV2)
    if any(
        attestation.source_identity_commitments
        != first_attestation.source_identity_commitments
        or attestation.expectations != first_attestation.expectations
        for attestation in attestations[1:]
    ):
        raise ValueError("three-epoch source profile identities differ")
    source_bindings = tuple(
        TargetSourceBindingV2(
            camera_id=expectation.camera_id,
            source_index=expectation.source_index,
            source_identity_commitment=(
                expectation.source_identity_commitment
            ),
        )
        for expectation in first_attestation.expectations
    )
    trust_binding_sha256 = hashlib.sha256(
        canonical_json_bytes(build_acceptance_trust_binding(context.trust))
    ).hexdigest()
    module_gates_sha256 = _required_digest_argument(
        arguments,
        "acceptance_module_gates_sha256",
    )
    controller_image_id_sha256 = _required_digest_argument(
        arguments,
        "controller_image_id_sha256",
    )
    controller_image_config_sha256 = _required_digest_argument(
        arguments,
        "controller_image_config_sha256",
    )
    controller_code_sha256 = _required_digest_argument(
        arguments,
        "controller_code_sha256",
    )
    requests = tuple(
        TargetRuntimeLaunchRequestV2(
            schema_version="target-runtime-launch-request.v2",
            campaign_id=context.configured_campaign_id,
            gate=context.configured_gate,
            launch_nonce=nonce,
            manifest_sha256=context.binding.manifest_payload_sha256,
            acceptance_trust_binding_sha256=trust_binding_sha256,
            module_gate_bindings_sha256=module_gates_sha256,
            controller_image_id_sha256=controller_image_id_sha256,
            controller_image_config_sha256=(
                controller_image_config_sha256
            ),
            controller_code_sha256=controller_code_sha256,
            runtime_epoch=first_epoch + index,
            runtime_epoch_started_generation=first_epoch + index,
            launch=reviewed.launch,
            source_bindings=source_bindings,
        )
        for index, nonce in enumerate(launch_nonces)
    )
    verified_profiles = tuple(
        capture_verified_target_source_profile_attestation(
            context=context,
            launch_request=request,
            attestation_path=profile_path,
            signature_path=signature_path,
        )
        for request, profile_path, signature_path in zip(
            requests,
            profile_paths,
            signature_paths,
            strict=True,
        )
    )
    profile_by_request = {
        request.request_sha256: profile
        for request, profile in zip(requests, verified_profiles, strict=True)
    }
    graph = DeepStreamGraphSpec.from_site(reviewed.site)
    collector_id = f"collector-{uuid4()}"
    fault_executor = ExecutableTargetAcceptanceAdapter(
        arguments.acceptance_adapter_executable,
        expected_sha256=reviewed.launch.acceptance_adapter_sha256,
        policy_path=arguments.acceptance_adapter_policy,
        policy_sha256=reviewed.launch.acceptance_adapter_policy_sha256,
        work_root=arguments.acceptance_adapter_work_root,
    )
    observer = ExecutableTargetAcceptanceAdapter(
        arguments.acceptance_observer_executable,
        expected_sha256=reviewed.launch.acceptance_observer_sha256,
        policy_path=arguments.acceptance_observer_policy,
        policy_sha256=reviewed.launch.acceptance_observer_policy_sha256,
        work_root=arguments.acceptance_observer_work_root,
    )
    with (
        tempfile.TemporaryDirectory(prefix=".kuzet-v3-runtime-stage-")
        as staging_name,
        tempfile.TemporaryDirectory(
            prefix=".epoch-native-",
            dir=native_projection_root,
        ) as native_name,
        tempfile.TemporaryDirectory(
            prefix=".epoch-work-",
            dir=work_projection_root,
        ) as work_name,
    ):
        staging_root = Path(staging_name)
        staging_root.chmod(0o700)
        native_root = Path(native_name)
        native_root.chmod(0o700)
        work_root = Path(work_name)
        work_root.chmod(0o700)
        environments: dict[
            str,
            tuple[tuple[str, ...], Path, Path, frozenset[Path]],
        ] = {}
        reviewed_mount_sources: set[Path] = {
            channel_root,
            source_secrets,
            native_root,
            work_root,
        }
        for request in requests:
            epoch_stage = staging_root / f"epoch-{request.runtime_epoch}"
            mount_argv, sources = _stage_reviewed_runtime_mounts(
                arguments,
                reviewed=reviewed,
                work_root=epoch_stage,
            )
            reviewed_mount_sources.update(sources)
            native_path = native_root / f"native-{request.launch_nonce}.json"
            work_path = work_root / f"work-{request.launch_nonce}.json"
            environments[request.request_sha256] = (
                mount_argv,
                native_path,
                work_path,
                sources,
            )

        child_visible_sources = tuple(
            sorted(reviewed_mount_sources, key=os.fspath)
        )
        controller_token_path = (
            _require_host_authority_path_outside_child_mounts(
                getattr(
                    arguments,
                    "acceptance_controller_token_file",
                    None,
                ),
                label="acceptance controller token",
                forbidden_roots=child_visible_sources,
                require_existing=True,
            )
        )
        collector_state_path = (
            _require_host_authority_path_outside_child_mounts(
                collector_state_candidate,
                label="acceptance collector state",
                forbidden_roots=child_visible_sources,
                require_existing=False,
            )
        )
        transition_journal_path = (
            _require_host_authority_path_outside_child_mounts(
                transition_journal_path,
                label="acceptance transition journal",
                forbidden_roots=child_visible_sources,
                require_existing=False,
            )
        )
        v3_state_path = _require_host_authority_path_outside_child_mounts(
            v3_state_candidate,
            label="acceptance V3 state",
            forbidden_roots=child_visible_sources,
            require_existing=True,
        )
        _require_distinct_authority_files(
            (
                ("collector state", collector_state_path),
                ("transition journal", transition_journal_path),
                ("V3 state", v3_state_path),
            )
        )
        signer_path = _require_unmounted_signer_path(
            getattr(arguments, "acceptance_run_signing_key", None),
            forbidden_roots=child_visible_sources,
        )
        collector = AuthenticatedTargetCollector(
            base_url=arguments.control_plane_url,
            acceptance_controller_token_file=controller_token_path,
            verified_trust=context.trust,
            configured_site_id=context.configured_site_id,
            configured_campaign_id=context.configured_campaign_id,
            configured_gate=context.configured_gate,
            fault_executor=fault_executor,
            observer=observer,
            journal_path=collector_state_path,
            collector_id=collector_id,
        )
        signer = OpenSSLAcceptanceRunSigner(
            signer_path,
            expected_public_key_spki_sha256=(
                context.trust.policy.roles.run_spki_sha256
            ),
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )

        def environment_factory(
            request: TargetRuntimeLaunchRequestV2,
            channel_path: Path,
        ) -> TargetRuntimeControllerEnvironmentV2:
            mount_argv, native_path, work_path, _sources = environments[
                request.request_sha256
            ]
            child_channel = "/run/acceptance/channel"
            child_sources = "/run/acceptance/source-secrets"
            child_native = f"/run/acceptance/native/{native_path.name}"
            child_work = f"/run/acceptance/work/{work_path.name}"
            return TargetRuntimeControllerEnvironmentV2(
                engine_path=arguments.container_engine,
                nvidia_ctk_path=arguments.nvidia_ctk,
                command=target_command(
                    arguments,
                    launch_nonce=request.launch_nonce,
                    acceptance_channel=child_channel,
                    acceptance_source_secrets=child_sources,
                    acceptance_native_projection=child_native,
                    acceptance_work_projection=child_work,
                ),
                reviewed_mount_argv=(
                    *mount_argv,
                    "--mount",
                    (
                        f"type=bind,src={channel_path},"
                        f"dst={child_channel}"
                    ),
                    "--mount",
                    (
                        f"type=bind,src={source_secrets},"
                        f"dst={child_sources},readonly"
                    ),
                    "--mount",
                    (
                        f"type=bind,src={native_root},"
                        "dst=/run/acceptance/native"
                    ),
                    "--mount",
                    (
                        f"type=bind,src={work_root},"
                        "dst=/run/acceptance/work"
                    ),
                ),
            )

        coordinator = TargetCampaignCoordinatorV3(
            collector_id=collector.campaign_collector_id,
            trust_context=context,
            launch_requests=(requests[0], requests[1]),
            graph=graph,
            channel_root=channel_root,
            environment_factory=environment_factory,
            source_profile_provider=lambda request: profile_by_request[
                request.request_sha256
            ],
            reviewed_mount_sources=tuple(reviewed_mount_sources),
        )
        continuation = TargetRuntimeContinuationCoordinatorV3(
            collector_id=collector.campaign_collector_id,
            trust_context=context,
            launch_request=requests[2],
            graph=graph,
            channel_root=channel_root,
            environment_factory=environment_factory,
            source_profile_provider=lambda request: profile_by_request[
                request.request_sha256
            ],
            transition_journal=(
                SQLiteTargetExecutionTransitionJournalV3(
                    transition_journal_path
                )
            ),
            authenticated_collector=collector,
            reviewed_mount_sources=tuple(reviewed_mount_sources),
            stop_grace_seconds=arguments.stop_grace_seconds,
        )
        collector_runner = RetainedRuntimeTargetV3Collector(
            collector=collector,
            trust_context=context,
            continuation=continuation,
        )
        signed_target, _proof = run_target_v3(
            arguments,
            coordinator=coordinator,
            collector_runner=collector_runner,
            trust_context=context,
            signer=signer,
        )
        collected = collector_runner.collected
        if collected is None:
            raise RuntimeError("retained V3 collector produced no durable evidence")

    limits = _load_reviewed_v3_model(
        getattr(arguments, "acceptance_operational_limits", None),
        AcceptanceLimitsV1,
        label="acceptance operational limits",
    )
    operational = _load_reviewed_v3_model(
        getattr(arguments, "acceptance_operational_evidence", None),
        OperationalAcceptanceEvidenceV1,
        label="acceptance operational evidence",
    )
    boundary = _load_reviewed_v3_model(
        getattr(arguments, "acceptance_repository_boundary", None),
        AuthoritativeRepositoryBoundaryV1,
        label="acceptance repository boundary",
    )
    assert type(limits) is AcceptanceLimitsV1
    assert type(operational) is OperationalAcceptanceEvidenceV1
    assert type(boundary) is AuthoritativeRepositoryBoundaryV1
    conditional_paths = tuple(
        getattr(arguments, "acceptance_conditional_gate_decisions", ()) or ()
    )
    decisions = load_conditional_gate_decisions(
        conditional_paths,
        trusted_public_key=arguments.acceptance_conditional_role_public_key,
    )
    producer = ReviewedAcceptanceCaptureProducerV3(
        trust_context=context,
        controller_image_sha256=controller_image_id_sha256,
        controller_code_sha256=controller_code_sha256,
        operational_limits=limits,
        operational_evidence=operational,
        repository_boundary=boundary,
        conditional_gate_decisions=decisions,
    )
    provider = ProtectedAcceptanceCaptureRepositoryV3(
        capture_root,
        trust_context=context,
    )
    capture = producer.capture(
        signed_target_authority=signed_target,
        final_envelope_v2=collected.final_envelope,
        journal_proof_v2_path=collected.journal_proof_path,
    )
    provider.publish(capture)
    result_model = collector.finalize_v3(
        collector.campaign_collector_id
    )
    result = result_model.model_dump(mode="json")
    result_payload = canonical_json_bytes(result)
    out_v3_result = getattr(arguments, "out_v3_result", None)
    if not isinstance(out_v3_result, Path) or not out_v3_result.is_absolute():
        raise ValueError("acceptance V3 result path must be absolute")
    _publish_exact_bytes(out_v3_result, result_payload)
    return result


def run_target(
    arguments: argparse.Namespace,
    *,
    process_factory: Callable[..., object] | None = None,
    collector: TargetCollector | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> AcceptanceRunRecordV2:
    """Collect legacy V2 target evidence; never grant production authority."""

    collector_state = getattr(arguments, "collector_state", None)
    if not isinstance(collector_state, Path) or not collector_state.is_absolute():
        raise ValueError("target mode requires an absolute durable collector state path")
    trust_context = _verify_target_acceptance_context(arguments)
    lock_path = collector_state.with_name(f"{collector_state.name}.campaign.lock")
    with TargetCampaignLock(lock_path):
        return _run_target_locked(
            arguments,
            trust_context=trust_context,
            process_factory=process_factory,
            collector=collector,
            monotonic=monotonic,
            sleep=sleep,
        )


def _run_target_locked(
    arguments: argparse.Namespace,
    *,
    trust_context: AcceptanceAuthorityTrustContextV2,
    process_factory: Callable[..., object] | None = None,
    collector: TargetCollector | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> AcceptanceRunRecordV2:
    _require_authority_trust_context(trust_context)
    if arguments.duration_seconds not in _GATE_BY_DURATION:
        raise ValueError("target duration must be exactly the 8h or 72h gate")
    gate = _GATE_BY_DURATION[arguments.duration_seconds]
    if gate != trust_context.configured_gate:
        raise ValueError("verified acceptance gate differs from target duration")
    if not 1 <= arguments.stop_grace_seconds <= 60:
        raise ValueError("target stop grace must be finite and at most 60 seconds")
    if arguments.collector_interval_seconds != 60:
        raise ValueError("target collector interval must be exactly 60 seconds")
    manifest = trust_context.trust.manifest
    reviewed = reviewed_launch_attestation(
        arguments,
        manifest=manifest,
        capacity_authority_public_key=(trust_context.trust.role_public_keys.capacity),
    )
    if collector is not None and any(
        path.exists() or path.is_symlink()
        for path in (
            arguments.out,
            arguments.out_attestation,
            arguments.out_signature,
            arguments.out_journal_proof,
        )
    ):
        raise ValueError("target mode requires new CLI-owned output paths")
    if process_factory is None:
        feeds = reviewed.site.ready_to_start.feeds
        if any(
            not isinstance(source.source, TargetSecretSourceV2)
            or feed.rtsp_url.environment is not None
            or feed.rtsp_url.docker_secret is None
            or source.source.secret_reference != str(feed.rtsp_url.docker_secret)
            or source.source_index != source_index
            or source.camera_id != feed.camera_id
            or source.source_index != feed.source_index
            or source.codec != feed.codec
            or source.width != feed.resolution.width
            or source.height != feed.resolution.height
            or source.fps != feed.fps
            or source.bitrate_kbps != feed.bitrate_kbps
            or dict(source.analytics_hz) != dict(feed.analytics_hz)
            for source_index, (source, feed) in enumerate(zip(manifest.sources, feeds, strict=True))
        ):
            raise ValueError(
                "target acceptance sources differ from the exact reviewed "
                "Docker-secret feed contract"
            )
    launch = reviewed.launch
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    if collector is None:
        durable_journal = SQLiteTargetCollectorJournal(arguments.collector_state)
        completed_final = durable_journal.response("finalize")
        if completed_final is not None:
            record, attestation, signature = _recover_root_authenticated_v2_final(
                journal=durable_journal,
                response=completed_final,
                trust_context=trust_context,
            )
            start_payload = durable_journal.request("start")
            if start_payload is None:
                raise RuntimeError("durable target start is unavailable")
            proof_binding = {
                field: start_payload[field]
                for field in (
                    "collector_id",
                    "site_id",
                    "manifest_sha256",
                    "gate",
                    "launch_attestation_sha256",
                    "execution_binding_sha256",
                    "fault_schedule_sha256",
                    "trust_binding",
                )
            }
            with tempfile.TemporaryDirectory(prefix=".kuzet-proof-recovery-") as temporary:
                proof_source = Path(temporary) / "journal-proof.jsonl"
                _download_journal_proof(
                    base_url=arguments.control_plane_url,
                    acceptance_controller_token_file=(arguments.acceptance_controller_token_file),
                    binding=proof_binding,
                    attestation=attestation,
                    record=record,
                    destination=proof_source,
                )
                _write_new_target_artifacts(
                    record_path=arguments.out,
                    attestation_path=arguments.out_attestation,
                    signature_path=arguments.out_signature,
                    proof_path=arguments.out_journal_proof,
                    proof_source=proof_source,
                    record=record,
                    attestation=attestation,
                    signature=signature,
                )
            return record
        if durable_journal.request("start") is not None:
            raise RuntimeError(
                "incomplete target campaign cannot be relaunched with a new "
                "runtime identity; operator invalidation is required"
            )
        if any(
            path.exists() or path.is_symlink()
            for path in (
                arguments.out,
                arguments.out_attestation,
                arguments.out_signature,
                arguments.out_journal_proof,
            )
        ):
            raise ValueError("target outputs require an exact completed durable campaign")
    launch_nonce = uuid4().hex
    command = target_command(arguments, launch_nonce=launch_nonce)
    workloads = tuple(
        CameraAcceptanceWorkloadV2(
            camera_id=source.camera_id,
            source_index=source.source_index,
            source_kind=source.source.kind,
            source_reference=(
                source.source.path
                if isinstance(source.source, LocalFixtureSourceV2)
                else source.source.secret_reference
            ),
            codec=source.codec,
            width=source.width,
            height=source.height,
            fps=source.fps,
            bitrate_kbps=source.bitrate_kbps,
            analytics_hz=source.analytics_hz,
        )
        for source in manifest.sources
    )
    staging = tempfile.TemporaryDirectory(prefix="kuzet-runtime-stage-")
    staging_root = Path(staging.name)
    staging_root.chmod(0o700)
    process: object | None = None
    try:
        if process_factory is None:
            process = _launch_staged_container(
                arguments,
                reviewed=reviewed,
                launch_nonce=launch_nonce,
                work_root=staging_root,
            )
        else:
            process = process_factory(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
        container_id = getattr(process, "container_id", None)
        container_config_sha256 = getattr(
            process,
            "container_config_sha256",
            None,
        )
        control_network_id = getattr(process, "control_network_id", None)
        control_network_config_sha256 = getattr(
            process,
            "control_network_config_sha256",
            None,
        )
        camera_network_id = getattr(process, "camera_network_id", None)
        camera_network_config_sha256 = getattr(
            process,
            "camera_network_config_sha256",
            None,
        )
        if (
            not isinstance(container_id, str)
            or not isinstance(container_config_sha256, str)
            or not isinstance(control_network_id, str)
            or not isinstance(control_network_config_sha256, str)
            or not isinstance(camera_network_id, str)
            or not isinstance(camera_network_config_sha256, str)
        ):
            raise RuntimeError("target container runner omitted execution identity")
        observed_gpu_inventory_sha256 = getattr(
            process,
            "observed_gpu_inventory_sha256",
            None,
        )
        if observed_gpu_inventory_sha256 is None and process_factory is not None:
            observed_gpu_inventory_sha256 = launch.gpu_inventory_sha256
        execution = ExecutionBindingV2(
            schema_version="acceptance-execution-binding.v2",
            launch_attestation_sha256=launch.attestation_sha256,
            launch_nonce=launch_nonce,
            container_id=container_id,
            container_config_sha256=container_config_sha256,
            runtime_image_id_sha256=launch.runtime_image_id_sha256,
            acceptance_adapter_sha256=launch.acceptance_adapter_sha256,
            acceptance_adapter_policy_sha256=(launch.acceptance_adapter_policy_sha256),
            acceptance_observer_sha256=(launch.acceptance_observer_sha256),
            acceptance_observer_policy_sha256=(launch.acceptance_observer_policy_sha256),
            control_network_id=control_network_id,
            control_network_config_sha256=control_network_config_sha256,
            camera_network_id=camera_network_id,
            camera_network_config_sha256=camera_network_config_sha256,
            observed_gpu_inventory_sha256=(observed_gpu_inventory_sha256),
        )
        if collector is None:
            fault_executor = ExecutableTargetAcceptanceAdapter(
                arguments.acceptance_adapter_executable,
                expected_sha256=launch.acceptance_adapter_sha256,
                policy_path=arguments.acceptance_adapter_policy,
                policy_sha256=(launch.acceptance_adapter_policy_sha256),
                work_root=arguments.acceptance_adapter_work_root,
            )
            observer = ExecutableTargetAcceptanceAdapter(
                arguments.acceptance_observer_executable,
                expected_sha256=launch.acceptance_observer_sha256,
                policy_path=arguments.acceptance_observer_policy,
                policy_sha256=(launch.acceptance_observer_policy_sha256),
                work_root=arguments.acceptance_observer_work_root,
            )
            collector = AuthenticatedTargetCollector(
                base_url=arguments.control_plane_url,
                acceptance_controller_token_file=(arguments.acceptance_controller_token_file),
                verified_trust=trust_context.trust,
                configured_site_id=trust_context.configured_site_id,
                configured_campaign_id=(trust_context.configured_campaign_id),
                configured_gate=trust_context.configured_gate,
                fault_executor=fault_executor,
                observer=observer,
                journal_path=arguments.collector_state,
            )
    except BaseException as primary:
        cleanup_errors: list[Exception] = []
        if process is not None and hasattr(process, "remove"):
            try:
                process.remove()
            except Exception as cleanup:
                cleanup_errors.append(cleanup)
        try:
            staging.cleanup()
        except Exception as cleanup:
            cleanup_errors.append(cleanup)
        if cleanup_errors and isinstance(primary, Exception):
            raise ExceptionGroup(
                "target launch binding and cleanup both failed",
                [primary, *cleanup_errors],
            ) from primary
        raise
    if process is None:
        staging.cleanup()
        raise RuntimeError("target runtime process was not created")
    fault_commands = sorted(
        (
            (fault.offset_seconds, fault.fault_id, "inject"),
            (
                fault.offset_seconds + fault.duration_seconds,
                fault.fault_id,
                "recover",
            ),
        )
        for fault in schedule
    )
    pending_fault_commands = sorted(command for commands in fault_commands for command in commands)

    def cleanup_execution(*, preserve: Exception | None = None) -> None:
        cleanup_errors: list[Exception] = []
        if hasattr(process, "remove"):
            try:
                process.remove()
            except Exception as exc:
                cleanup_errors.append(exc)
        try:
            staging.cleanup()
        except Exception as exc:
            cleanup_errors.append(exc)
        if cleanup_errors and preserve is not None:
            raise ExceptionGroup(
                "target execution and cleanup both failed",
                [preserve, *cleanup_errors],
            ) from preserve
        if cleanup_errors:
            raise RuntimeError("runner-owned target execution cleanup failed") from cleanup_errors[
                0
            ]

    failure: Exception | None = None
    forced_kill = False
    try:
        if collector is None:
            raise RuntimeError("target collector is unavailable")
        collector.start(
            site_id=manifest.site_id,
            manifest_sha256=manifest.manifest_sha256,
            gate=gate,
            camera_ids=tuple(source.camera_id for source in manifest.sources),
            workloads=workloads,
            sample_interval_seconds=arguments.collector_interval_seconds,
            launch=launch,
            execution=execution,
            schedule=schedule,
        )
        started_monotonic = monotonic()
        deadline = started_monotonic + arguments.duration_seconds
        next_sample_offset = 0.0
        while True:
            now = monotonic()
            elapsed = now - started_monotonic
            if hasattr(process, "verify_identity"):
                process.verify_identity()
            if process.poll() is not None:
                raise RuntimeError(
                    "target shared DeepStream process exited before selected duration"
                )
            while pending_fault_commands and pending_fault_commands[0][0] <= elapsed:
                boundary, fault_id, phase = pending_fault_commands.pop(0)
                collector.command_fault(
                    fault_id=fault_id,
                    phase=phase,
                    at_offset=boundary,
                )
            if elapsed >= next_sample_offset:
                if hasattr(process, "verify_identity"):
                    process.verify_identity()
                collector.collect(
                    process_healthy=True,
                    scheduled_monotonic_offset_seconds=next_sample_offset,
                )
                next_sample_offset += arguments.collector_interval_seconds
            if now >= deadline:
                break
            next_boundary = min(
                arguments.duration_seconds,
                next_sample_offset,
                (
                    pending_fault_commands[0][0]
                    if pending_fault_commands
                    else arguments.duration_seconds
                ),
            )
            sleep(max(0.0, next_boundary - elapsed))
        if hasattr(process, "verify_identity"):
            process.verify_identity()
    except Exception as exc:
        failure = exc
    finally:
        try:
            process.terminate(
                timeout_seconds=arguments.stop_grace_seconds,
            )
        except Exception as exc:
            failure = failure or exc
        else:
            try:
                process.wait(timeout=arguments.stop_grace_seconds)
            except subprocess.TimeoutExpired:
                forced_kill = True
                try:
                    process.kill()
                    process.wait(timeout=10)
                except Exception as exc:
                    failure = failure or exc
            except Exception as exc:
                failure = failure or exc
    if failure is not None:
        cleanup_execution(preserve=failure)
        raise failure
    if forced_kill:
        failure = RuntimeError("target shared DeepStream process did not stop gracefully")
        cleanup_execution(preserve=failure)
        raise failure
    if process.returncode != 0:
        failure = RuntimeError(
            "target shared DeepStream process did not complete a clean graceful shutdown"
        )
        cleanup_execution(preserve=failure)
        raise failure
    try:
        record = collector.finish()
    except Exception as exc:
        cleanup_execution(preserve=exc)
        raise
    if record.run_id != collector.collector_id:
        failure = RuntimeError("target observed record is not bound to the exact collector session")
        cleanup_execution(preserve=failure)
        raise failure
    if (
        record.environment != "target"
        or record.gate != gate
        or record.site_id != manifest.site_id
        or record.manifest_sha256 != manifest.manifest_sha256
        or record.launch != launch
        or record.execution != execution
    ):
        failure = RuntimeError(
            "target observed record is not bound to the exact manifest/site/gate/launch"
        )
        cleanup_execution(preserve=failure)
        raise failure
    cleanup_execution()
    if isinstance(collector, AuthenticatedTargetCollector):
        if collector.final_attestation is None or collector.final_signature is None:
            raise RuntimeError("controller did not return a signed target run attestation")
        proof_binding = {
            "collector_id": record.run_id,
            "site_id": record.site_id,
            "manifest_sha256": record.manifest_sha256,
            "gate": record.gate,
            "launch_attestation_sha256": record.launch.attestation_sha256,
            "execution_binding_sha256": record.execution.binding_sha256,
            "fault_schedule_sha256": canonical_fault_schedule_sha256(schedule),
            "trust_binding": trust_context.binding.model_dump(mode="json"),
        }
        with tempfile.TemporaryDirectory(prefix=".kuzet-proof-download-") as temporary:
            proof_source = Path(temporary) / "journal-proof.jsonl"
            _download_journal_proof(
                base_url=arguments.control_plane_url,
                acceptance_controller_token_file=(arguments.acceptance_controller_token_file),
                binding=proof_binding,
                attestation=collector.final_attestation,
                record=record,
                destination=proof_source,
            )
            _write_new_target_artifacts(
                record_path=arguments.out,
                attestation_path=arguments.out_attestation,
                signature_path=arguments.out_signature,
                proof_path=arguments.out_journal_proof,
                proof_source=proof_source,
                record=record,
                attestation=collector.final_attestation,
                signature=collector.final_signature,
            )
    return record


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.mode == "target":
        try:
            run_production_target_v3(arguments)
            return 0
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f"target replay refused: {exc}", file=sys.stderr)
            return 2
    boundary = CollectingBoundary()
    try:
        record = run_portable(
            arguments.manifest,
            observation_consumer=boundary,
            health_consumer=boundary,
            fault_adapter=PortableFaultAdapter(),
            boundary_probe=boundary,
        )
        _write_new_run_record(arguments.out, record)
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        digest = hashlib.sha256(str(exc).encode()).hexdigest()
        print(f"portable replay refused ({digest[:12]})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
