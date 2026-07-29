#!/usr/bin/env python3
"""Run one bounded shared portable replay and emit observed acceptance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from protector.pilot.acceptance import (  # noqa: E402
    AcceptanceRunRecordV1,
    BoundaryTraceV1,
    CameraRunRecordV1,
    FaultRecordV1,
    FaultStateTraceV1,
    QueueStateTraceV1,
    ResourceSampleV1,
    canonical_fault_policy,
    load_acceptance_manifest,
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
from protector.pilot.domain import ObservationV1  # noqa: E402
from protector.pilot.metrics import PilotMetrics  # noqa: E402
from protector.pilot.runtime.event_engine import EventEngine  # noqa: E402
from protector.pilot.runtime.fake import FakeDataPlane, ReplayFixture  # noqa: E402
from protector.pilot.runtime.supervisor import CameraHealth  # noqa: E402
from protector.pilot.telemetry import read_machine_token  # noqa: E402


class ObservationConsumer(Protocol):
    def consume(self, observation: ObservationV1) -> None: ...


class HealthConsumer(Protocol):
    def consume(self, health: CameraHealth, *, observed_at: datetime) -> None: ...


class FaultAdapter(Protocol):
    failure_plan: "FaultFailurePlan"


@dataclass(frozen=True, slots=True)
class ScheduledFault:
    fault_id: str
    kind: str
    target: str
    offset_seconds: float
    duration_seconds: float
    expected_degraded: str
    expected_recovery: str


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


def canonical_fault_schedule(camera_ids: tuple[str, ...]) -> tuple[ScheduledFault, ...]:
    """Finite deterministic schedule; adapters own effects and observed results."""
    if len(camera_ids) != 20 or len(set(camera_ids)) != 20:
        raise ValueError("fault schedule requires exact 20 unique cameras")
    specs = (
        ("camera-loss", "camera_loss", camera_ids[0], 10.0, 5.0),
        ("malformed-timestamp", "malformed_timestamp", camera_ids[1], 20.0, 1.0),
        ("network-pause", "network_pause", camera_ids[2], 30.0, 5.0),
        ("runtime-restart", "runtime_restart", "shared-runtime", 40.0, 3.0),
        ("api-restart", "api_restart", "control-api", 50.0, 3.0),
        ("object-outage", "object_store_outage", "evidence-store", 60.0, 5.0),
        ("model-timeout", "model_timeout", "person-primary", 70.0, 2.0),
        ("verifier-full", "verifier_full", "weapon-verifier", 80.0, 2.0),
    )
    schedule: list[ScheduledFault] = []
    for index, (name, kind, target, offset, duration) in enumerate(specs):
        (
            canonical_target,
            degraded,
            recovery,
            canonical_offset,
            canonical_duration,
        ) = canonical_fault_policy(kind)
        expected_target = (
            camera_ids[int(canonical_target.rsplit(":", maxsplit=1)[1])]
            if canonical_target.startswith("source_index:")
            else canonical_target
        )
        if (
            target != expected_target
            or offset != canonical_offset
            or duration != canonical_duration
        ):
            raise RuntimeError("portable fault schedule diverged from canonical policy")
        schedule.append(
            ScheduledFault(
            fault_id=f"fault-{index:02}-{name}",
            kind=kind,
            target=target,
            offset_seconds=offset,
            duration_seconds=duration,
            expected_degraded=degraded,
            expected_recovery=recovery,
        )
        )
    return tuple(schedule)


class CollectingBoundary:
    """Observed in-memory adapters around real event-engine and metrics contracts."""

    def __init__(self, *, site_id: str = "school-01", camera_ids: tuple[str, ...] | None = None) -> None:
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

    def consume(self, item: ObservationV1 | CameraHealth, *, observed_at: datetime | None = None) -> None:
        if isinstance(item, ObservationV1):
            result = self.event_engine.ingest(item)
            if not result.accepted:
                raise RuntimeError(f"event engine refused observed sample: {result.rejection_reason}")
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

    def boundary_traces(self) -> tuple[BoundaryTraceV1, ...]:
        if self._last_observed_at is None:
            raise RuntimeError("no observed health boundary timestamp")
        observed_at = self._last_observed_at
        return (
            BoundaryTraceV1(
                component="event_engine",
                observed_at=observed_at,
                consumed_records=self._accepted_observations,
                succeeded=True,
                detail_code="event-engine-ingested",
            ),
            BoundaryTraceV1(
                component="repository",
                observed_at=observed_at,
                consumed_records=len(self.persisted_ids),
                succeeded=len(self.persisted_ids) == len(self.observations),
                detail_code="injected-observation-repository",
            ),
            BoundaryTraceV1(
                component="evidence",
                observed_at=observed_at,
                consumed_records=0,
                succeeded=False,
                detail_code="no-candidate-evidence-not-exercised",
            ),
            BoundaryTraceV1(
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
            rtsp_url=SecretReference(environment=f"PILOT_REPLAY_SOURCE_{item.source_index:02}"),
            codec=item.codec,
            resolution=Resolution(width=item.width, height=item.height),
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
    scheduled: ScheduledFault,
    *,
    started_at: datetime,
    degraded: FaultStateTraceV1 | None,
    recovered: FaultStateTraceV1 | None,
) -> FaultRecordV1:
    return FaultRecordV1(
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
) -> AcceptanceRunRecordV1:
    """Drive sequential shared fake runtimes and observe every portable fault."""
    manifest = load_acceptance_manifest(manifest_path)
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
    fault_traces: list[FaultStateTraceV1] = []
    queue_traces: list[QueueStateTraceV1] = []
    drained: list[ObservationV1] = []
    health_samples: list[CameraHealth] = []
    last_health_by_runtime: list[list[CameraHealth]] = []
    availability_ticks = {camera_id: 0 for camera_id in camera_ids}

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
        scheduled: ScheduledFault,
        *,
        phase: str,
        state: str,
        component: str | None = None,
    ) -> FaultStateTraceV1:
        item = FaultStateTraceV1(
            fault_id=scheduled.fault_id,
            kind=scheduled.kind,
            phase=phase,
            observed_at=clock.wall(),
            component=component or scheduled.target,
            state=state,
            runtime_boot_id=runtime_boot_ids[-1],
            api_boot_id=boundary_probe.api_boot_id,
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
            if health.state == "online":
                availability_ticks[health.camera_id] += 1
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
                    trace(scheduled, phase="degraded", state=_camera_state(runtime, scheduled.target))
                if second == recovered_at and kind not in failure_plan.missing_recovery:
                    trace(scheduled, phase="recovered", state=_camera_state(runtime, scheduled.target))
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
                        QueueStateTraceV1(
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
                        QueueStateTraceV1(
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
    trace_by_fault_phase = {
        (item.fault_id, item.phase): item for item in fault_traces
    }
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
    health_by_camera = {
        item.camera_id: item for item in health_samples
    }
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
    cameras = tuple(
        CameraRunRecordV1(
            camera_id=camera_id,
            scheduled_samples=scheduled_totals[camera_id],
            processed_samples=counts[camera_id],
            dropped_samples=dropped_totals[camera_id],
            availability_seconds=float(availability_ticks[camera_id]),
            source_outage_seconds=sum(
                item.duration_seconds
                for item in faults
                if item.target == camera_id
                and item.kind in {"camera_loss", "network_pause"}
                and item.observed_degraded == item.expected_degraded
                and item.observed_recovery == item.expected_recovery
            ),
            queue_age_seconds=()
            if health_by_camera[camera_id].queue_age_seconds is None
            else (health_by_camera[camera_id].queue_age_seconds,),
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
            last_health_at=actual_health_at,
            runtime_boot_id=runtime_boot_ids[-1],
            api_boot_id=boundary_probe.api_boot_id,
        )
        for camera_id in camera_ids
    )
    boundaries = boundary_probe.boundary_traces()
    queue_traces.append(
        QueueStateTraceV1(
            queue="analytics",
            observed_at=actual_health_at,
            depth=0,
            capacity=64,
            state="ready",
            runtime_boot_id=runtime_boot_ids[-1],
            api_boot_id=boundary_probe.api_boot_id,
        )
    )
    return AcceptanceRunRecordV1(
        schema_version="acceptance-run-record.v1",
        run_id=f"portable-{uuid4()}",
        environment="test_only",
        gate="contract",
        site_id=manifest.site_id,
        manifest_sha256=manifest.manifest_sha256,
        started_at=started_at,
        ended_at=ended_at,
        cameras=cameras,
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
            ResourceSampleV1(
                sampled_at=started_at,
                gpu_percent=0,
                vram_percent=0,
                disk_bytes=0,
                disk_limit_bytes=1,
            ),
            ResourceSampleV1(
                sampled_at=actual_health_at,
                gpu_percent=0,
                vram_percent=0,
                disk_bytes=0,
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
        required_throughput_hz=sum(
            float(item.analytics_hz["person"]) for item in manifest.sources
        ),
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

    def start(self, *, site_id: str, manifest_sha256: str, gate: str) -> None: ...

    def collect(self, *, process_healthy: bool) -> None: ...

    def finish(self) -> AcceptanceRunRecordV1: ...


class AuthenticatedTargetCollector:
    """Collect acceptance evidence from the machine-authenticated control plane."""

    _MAX_SAMPLE_BYTES = 64 * 1024
    _MAX_RECORD_BYTES = 64 * 1024 * 1024

    def __init__(
        self,
        *,
        base_url: str,
        machine_token_file: Path,
        timeout_seconds: float = 5.0,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("collector URL must be an absolute HTTP(S) origin")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("collector timeout must be finite and at most 30 seconds")
        self._base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self._token = read_machine_token(machine_token_file)
        self._timeout_seconds = timeout_seconds
        self._binding: dict[str, str] | None = None
        self._observations = 0

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self._base_url!r})"

    @property
    def collector_id(self) -> str:
        if self._binding is None:
            raise RuntimeError("target collector has not started")
        return self._binding["collector_id"]

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
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                encoded = response.read(limit + 1)
                if not 200 <= response.status < 300 or len(encoded) > limit:
                    raise RuntimeError("target collector response was rejected or unbounded")
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise RuntimeError("target collector request failed") from exc
        try:
            decoded = json.loads(encoded)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("target collector returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("target collector returned an invalid envelope")
        return decoded

    def start(self, *, site_id: str, manifest_sha256: str, gate: str) -> None:
        if self._binding is not None:
            raise RuntimeError("target collector is already started")
        self._binding = {
            "site_id": site_id,
            "manifest_sha256": manifest_sha256,
            "gate": gate,
            "collector_id": f"collector-{uuid4()}",
        }
        response = self._post(
            "/api/internal/acceptance/start",
            {"schema_version": "acceptance-collector-start.v1", **self._binding},
            limit=self._MAX_SAMPLE_BYTES,
        )
        if any(response.get(key) != value for key, value in self._binding.items()):
            raise RuntimeError("target collector start binding mismatch")

    def collect(self, *, process_healthy: bool) -> None:
        if self._binding is None or not process_healthy:
            raise RuntimeError("target collector requires one healthy shared runtime")
        response = self._post(
            "/api/internal/acceptance/sample",
            {
                "schema_version": "acceptance-collector-sample.v1",
                **self._binding,
                "process_healthy": True,
            },
            limit=self._MAX_SAMPLE_BYTES,
        )
        if any(response.get(key) != value for key, value in self._binding.items()):
            raise RuntimeError("target collector sample binding mismatch")
        observations = response.get("observed_records")
        if not isinstance(observations, int) or isinstance(observations, bool) or observations < 0:
            raise RuntimeError("target collector sample count is invalid")
        self._observations += observations

    def finish(self) -> AcceptanceRunRecordV1:
        if self._binding is None or self._observations <= 0:
            raise RuntimeError("collector observed no bounded samples")
        response = self._post(
            "/api/internal/acceptance/finalize",
            {"schema_version": "acceptance-collector-finalize.v1", **self._binding},
            limit=self._MAX_RECORD_BYTES,
        )
        record = AcceptanceRunRecordV1.model_validate(response)
        if (
            record.site_id != self._binding["site_id"]
            or record.manifest_sha256 != self._binding["manifest_sha256"]
            or record.gate != self._binding["gate"]
        ):
            raise RuntimeError("target collector final binding mismatch")
        return record


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", choices=("portable", "target"), default="portable")
    parser.add_argument("--site-config", type=Path)
    parser.add_argument("--site-config-sha256")
    parser.add_argument("--runtime-manifest", type=Path)
    parser.add_argument("--runtime-manifest-sha256")
    parser.add_argument("--measured-capacity-report", type=Path)
    parser.add_argument("--measured-capacity-sha256")
    parser.add_argument("--control-plane-url")
    parser.add_argument("--machine-token-file", type=Path)
    parser.add_argument("--duration-seconds", type=int, default=28_800)
    parser.add_argument("--stop-grace-seconds", type=int, default=30)
    parser.add_argument("--collector-interval-seconds", type=int, default=30)
    return parser


def target_command(arguments: argparse.Namespace) -> tuple[str, ...]:
    required = (
        "site_config",
        "site_config_sha256",
        "runtime_manifest",
        "runtime_manifest_sha256",
        "measured_capacity_report",
        "measured_capacity_sha256",
        "control_plane_url",
        "machine_token_file",
    )
    if any(getattr(arguments, name, None) is None for name in required):
        raise ValueError("target mode requires every reviewed DeepStream input")
    return (
        sys.executable,
        "-m",
        "protector.pilot.runtime.deepstream",
        "--site-config",
        str(arguments.site_config),
        "--site-config-sha256",
        arguments.site_config_sha256,
        "--runtime-manifest",
        str(arguments.runtime_manifest),
        "--runtime-manifest-sha256",
        arguments.runtime_manifest_sha256,
        "--measured-capacity-report",
        str(arguments.measured_capacity_report),
        "--measured-capacity-sha256",
        arguments.measured_capacity_sha256,
        "--control-plane-url",
        arguments.control_plane_url,
        "--machine-token-file",
        str(arguments.machine_token_file),
    )


def _write_new_run_record(path: Path, record: AcceptanceRunRecordV1) -> None:
    payload = json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if len(payload) > 64 * 1024 * 1024:
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


def run_target(
    arguments: argparse.Namespace,
    *,
    process_factory: Callable[..., object] = subprocess.Popen,
    collector: TargetCollector | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> AcceptanceRunRecordV1:
    gate_by_duration = {28_800: "8h", 259_200: "72h"}
    if arguments.duration_seconds not in gate_by_duration:
        raise ValueError("target duration must be exactly the 8h or 72h gate")
    gate = gate_by_duration[arguments.duration_seconds]
    if not 1 <= arguments.stop_grace_seconds <= 60:
        raise ValueError("target stop grace must be finite and at most 60 seconds")
    if not 1 <= arguments.collector_interval_seconds <= 60:
        raise ValueError("collector interval must be finite and at most 60 seconds")
    if arguments.out.exists():
        raise ValueError("target output must be a new CLI-owned path")
    manifest = load_acceptance_manifest(arguments.manifest)
    command = target_command(arguments)
    collector = collector or AuthenticatedTargetCollector(
        base_url=arguments.control_plane_url,
        machine_token_file=arguments.machine_token_file,
    )
    collector.start(
        site_id=manifest.site_id,
        manifest_sha256=manifest.manifest_sha256,
        gate=gate,
    )
    process = process_factory(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    deadline = monotonic() + arguments.duration_seconds
    failure: Exception | None = None
    forced_kill = False
    try:
        while monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("target shared DeepStream process exited before selected duration")
            collector.collect(process_healthy=True)
            sleep(min(arguments.collector_interval_seconds, deadline - monotonic()))
    except Exception as exc:
        failure = exc
    finally:
        process.terminate()
        try:
            process.wait(timeout=arguments.stop_grace_seconds)
        except subprocess.TimeoutExpired:
            forced_kill = True
            process.kill()
            process.wait(timeout=10)
    if failure is not None:
        raise failure
    if forced_kill:
        raise RuntimeError("target shared DeepStream process did not stop gracefully")
    if process.returncode not in {0, -9, -15}:
        raise RuntimeError("target shared DeepStream process failed")
    record = collector.finish()
    if record.run_id != collector.collector_id:
        raise RuntimeError("target observed record is not bound to the exact collector session")
    if (
        record.environment != "target"
        or record.gate != gate
        or record.site_id != manifest.site_id
        or record.manifest_sha256 != manifest.manifest_sha256
    ):
        raise RuntimeError("target observed record is not bound to the exact manifest/site/gate")
    return record


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.mode == "target":
        try:
            record = run_target(arguments)
            _write_new_run_record(arguments.out, record)
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
