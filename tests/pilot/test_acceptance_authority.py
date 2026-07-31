from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import pytest
import yaml
from fastapi.testclient import TestClient

import protector.pilot.acceptance_authority as authority_module
import protector.pilot.api.acceptance_controller as controller_module
from protector.pilot.acceptance import (
    AcceptanceManifestV2,
    AcceptanceRunRecordV2,
    ExecutionBindingV2,
    LaunchAttestationV2,
    QueueAgeRunV2,
    ResourceSampleV2,
    ScheduledFaultV2,
    canonical_fault_schedule_sha256,
    source_profiles_sha256,
)
from protector.pilot.acceptance_authority import (
    AcceptanceAdapterIdentityV2,
    AcceptanceAuthority,
    AcceptanceSampleObservationV2,
    AcceptanceStartRequestV2,
    AnalyticCounterObservationV2,
    CameraAcceptanceObservationV2,
    CameraAcceptanceWorkloadV2,
    CameraHealthIntervalObservationV2,
    FaultCommandObservationV2,
    FaultEffectReceiptV2,
    SQLiteAcceptanceAuthorityJournal,
)
from protector.pilot.acceptance_proof import (
    AcceptanceFinalEnvelopeV2,
    AcceptanceProofStore,
)
from protector.pilot.api.acceptance_controller import (
    OpenSSLAcceptanceRunSigner,
    build_production_acceptance_authority,
    create_acceptance_controller_app,
)
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import Base
from protector.pilot.storage.repositories import PilotRepository
from scripts.pilot.replay_20 import (
    AuthenticatedTargetCollector,
    canonical_fault_schedule,
)
from tests.pilot.acceptance_trust_helpers import authority_trust_context
from tests.pilot.test_acceptance_report import _manifest, _run

UTC = timezone.utc
START = datetime(2026, 7, 30, tzinfo=UTC)
TOKEN = "acceptance-machine-token-never-returned"
GENERAL_MACHINE_TOKEN = "general-machine-token-never-returned"
REPO_ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def _protected_journal_namespace(path: Path) -> Iterator[None]:
    """Create a real WAL triplet, then remove runtime namespace mutation."""
    path.parent.mkdir(mode=0o700)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        connection.execute("PRAGMA user_version=1")
    finally:
        connection.close()
    Path(f"{path}-wal").touch(mode=0o600)
    Path(f"{path}-shm").touch(mode=0o600)
    path.chmod(0o600)
    path.parent.chmod(0o500)
    try:
        yield
    finally:
        path.parent.chmod(0o700)


class ControlledClock:
    def __init__(self) -> None:
        self.offset = 0.0

    def wall(self) -> datetime:
        return START + timedelta(seconds=self.offset)

    def monotonic(self) -> float:
        return self.offset


class NonDestructiveObservedAdapter:
    """Test adapter with no host, process, network, or storage mutations."""

    def __init__(self, template: AcceptanceRunRecordV2, clock: ControlledClock) -> None:
        self.template = template
        self.clock = clock
        self.commands: list[tuple[str, str, float]] = []
        assert template.execution is not None
        self.runtime_boot_id = f"{template.execution.launch_nonce}.runtime-boot-1"
        self.api_boot_id = "api-boot-1"
        self.last_sample_offset = 0.0

    @property
    def identity(self) -> AcceptanceAdapterIdentityV2:
        return AcceptanceAdapterIdentityV2(
            schema_version="acceptance-adapter-identity.v2",
            executable_sha256=self.template.launch.acceptance_observer_sha256,
            policy_sha256=(self.template.launch.acceptance_observer_policy_sha256),
        )

    def sample(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        previous_monotonic_offset_seconds: float,
        scheduled_monotonic_offset_seconds: float,
    ) -> AcceptanceSampleObservationV2:
        current_offset = (self.clock.wall() - self.template.started_at).total_seconds()
        if (
            previous_monotonic_offset_seconds != self.last_sample_offset
            or scheduled_monotonic_offset_seconds != current_offset
        ):
            raise AssertionError("test adapter sample schedule differs")
        previous_offset = previous_monotonic_offset_seconds
        camera_observations: list[CameraAcceptanceObservationV2] = []
        observed_records = 0
        for source_index, camera in enumerate(self.template.cameras):
            counters: list[AnalyticCounterObservationV2] = []
            for work in self.template.work_spans:
                if work.camera_id != camera.camera_id:
                    continue
                rate = work.scheduled_samples / (
                    (work.ended_at - work.started_at).total_seconds() - camera.source_outage_seconds
                )
                outage_through_previous = sum(
                    max(
                        0.0,
                        min(
                            previous_offset,
                            (span.ended_at - self.template.started_at).total_seconds(),
                        )
                        - (span.started_at - self.template.started_at).total_seconds(),
                    )
                    for span in self.template.health_spans
                    if span.camera_id == camera.camera_id and span.state == "source_outage"
                )
                outage_through_current = sum(
                    max(
                        0.0,
                        min(
                            current_offset,
                            (span.ended_at - self.template.started_at).total_seconds(),
                        )
                        - (span.started_at - self.template.started_at).total_seconds(),
                    )
                    for span in self.template.health_spans
                    if span.camera_id == camera.camera_id and span.state == "source_outage"
                )
                scheduled = math.floor(
                    rate * (current_offset - outage_through_current) + 1e-9
                ) - math.floor(rate * (previous_offset - outage_through_previous) + 1e-9)
                dropped = (
                    work.dropped_samples
                    if current_offset
                    == (self.template.ended_at - self.template.started_at).total_seconds()
                    else 0
                )
                counters.append(
                    AnalyticCounterObservationV2(
                        module=work.module,
                        scheduled_samples=scheduled,
                        processed_samples=scheduled - dropped,
                        dropped_samples=dropped,
                    )
                )
                observed_records += scheduled - dropped
            camera_observations.append(
                CameraAcceptanceObservationV2(
                    camera_id=camera.camera_id,
                    source_index=source_index,
                    negotiated_codec="h264",
                    negotiated_width=1920,
                    negotiated_height=1080,
                    negotiated_fps=25.0,
                    negotiated_bitrate_kbps=4096,
                    queue_name="analytics",
                    state="online",
                    counters=tuple(counters),
                    queue_observation_cadence_seconds=1,
                    queue_age_runs=(
                        QueueAgeRunV2(
                            age_seconds=camera.queue_age_seconds[0],
                            samples=(
                                1
                                if current_offset == 0
                                else round(current_offset - previous_offset)
                            ),
                        ),
                    ),
                    runtime_boot_id=self.runtime_boot_id,
                    api_boot_id=self.api_boot_id,
                )
            )
        resource = next(
            item for item in self.template.resources if item.sampled_at == self.clock.wall()
        )
        self.last_sample_offset = current_offset
        health_intervals = tuple(
            CameraHealthIntervalObservationV2(
                camera_id=camera.camera_id,
                started_monotonic_offset_seconds=max(
                    previous_offset,
                    (span.started_at - self.template.started_at).total_seconds(),
                ),
                ended_monotonic_offset_seconds=min(
                    current_offset,
                    (span.ended_at - self.template.started_at).total_seconds(),
                ),
                state=("offline" if span.state == "source_outage" else span.state),
            )
            for camera in self.template.cameras
            for span in self.template.health_spans
            if (
                span.camera_id == camera.camera_id
                and current_offset > previous_offset
                and (span.ended_at - self.template.started_at).total_seconds() > previous_offset
                and (span.started_at - self.template.started_at).total_seconds() < current_offset
            )
        )
        return AcceptanceSampleObservationV2(
            schema_version="acceptance-sample-observation.v2",
            observed_at=self.clock.wall(),
            observed_records=observed_records,
            collector_id=collector_id,
            launch_attestation_sha256=launch.attestation_sha256,
            execution_binding_sha256=execution.binding_sha256,
            observer_sha256=execution.acceptance_observer_sha256,
            observer_policy_sha256=(execution.acceptance_observer_policy_sha256),
            cameras=tuple(camera_observations),
            health_intervals=health_intervals,
            resource=resource,
        )

    def apply_fault(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
        fault: ScheduledFaultV2,
        phase: str,
        command_id: str,
        commanded_monotonic_offset_seconds: float,
    ) -> FaultEffectReceiptV2:
        del collector_id, launch
        pre_runtime_boot_id = self.runtime_boot_id
        pre_api_boot_id = self.api_boot_id
        if fault.kind == "runtime_restart" and phase == "recover":
            self.runtime_boot_id = f"{execution.launch_nonce}.runtime-boot-2"
        if fault.kind == "api_restart" and phase == "recover":
            self.api_boot_id = "api-boot-2"
        self.commands.append((fault.fault_id, phase, commanded_monotonic_offset_seconds))
        return FaultEffectReceiptV2(
            schema_version="acceptance-fault-effect-receipt.v2",
            command_id=command_id,
            fault_id=fault.fault_id,
            phase=phase,
            target=fault.target,
            execution_binding_sha256=execution.binding_sha256,
            executor_sha256=execution.acceptance_adapter_sha256,
            executor_policy_sha256=(execution.acceptance_adapter_policy_sha256),
            pre_state="ready",
            post_state=(fault.expected_degraded if phase == "inject" else fault.expected_recovery),
            pre_runtime_boot_id=pre_runtime_boot_id,
            post_runtime_boot_id=self.runtime_boot_id,
            pre_api_boot_id=pre_api_boot_id,
            post_api_boot_id=self.api_boot_id,
            effect_started_at=self.clock.wall(),
            effect_completed_at=self.clock.wall(),
            effect_proof_sha256=hashlib.sha256(command_id.encode()).hexdigest(),
            outcome="ensured",
        )

    def observe_fault(
        self,
        *,
        fault: ScheduledFaultV2,
        phase: str,
        execution: ExecutionBindingV2,
        command_id: str,
        **_kwargs,
    ) -> FaultCommandObservationV2:
        return FaultCommandObservationV2(
            schema_version="acceptance-fault-command-observation.v2",
            command_id=command_id,
            state=(fault.expected_degraded if phase == "inject" else fault.expected_recovery),
            runtime_boot_id=self.runtime_boot_id,
            api_boot_id=self.api_boot_id,
            execution_binding_sha256=execution.binding_sha256,
            observer_sha256=execution.acceptance_observer_sha256,
            observer_policy_sha256=(execution.acceptance_observer_policy_sha256),
        )

    def finalize(
        self,
        *,
        collector_id: str,
        launch: LaunchAttestationV2,
        execution: ExecutionBindingV2,
    ) -> AcceptanceRunRecordV2:
        # Deliberately corrupt every collector-owned final field. The authority
        # must replace these with evidence derived from the durable sample journal.
        return self.template.model_copy(
            update={
                "run_id": collector_id,
                "launch": launch,
                "execution": execution,
                "cameras": (),
                "health_spans": (),
                "work_spans": (),
                "queue_coverage": (),
                "resources": (),
                "gpu_percent": (),
                "vram_percent": (),
                "disk_bytes": (),
                "runtime_boot_ids": (),
                "api_boot_ids": (),
            }
        )


class AdapterBackedEffectExecutor:
    def __init__(self, adapter: NonDestructiveObservedAdapter) -> None:
        self.adapter = adapter

    def ensure_fault(self, **kwargs) -> FaultEffectReceiptV2:
        kwargs.pop("prior_observation", None)
        return self.adapter.apply_fault(**kwargs)


def _execute_fault(
    *,
    authority: AcceptanceAuthority,
    payload: dict[str, object],
    executor: object,
    launch: LaunchAttestationV2,
    execution: ExecutionBindingV2,
) -> dict[str, object]:
    prepared = authority.prepare_fault(
        {
            **payload,
            "schema_version": "acceptance-fault-prepare.v2",
        }
    )
    fault = ScheduledFaultV2.model_validate(payload["fault"])
    receipt = executor.ensure_fault(
        collector_id=str(payload["collector_id"]),
        launch=launch,
        execution=execution,
        fault=fault,
        phase=str(payload["phase"]),
        command_id=str(prepared["command_id"]),
        commanded_monotonic_offset_seconds=float(payload["commanded_monotonic_offset_seconds"]),
    )
    binding_keys = (
        "collector_id",
        "site_id",
        "manifest_sha256",
        "gate",
        "launch_attestation_sha256",
        "execution_binding_sha256",
        "fault_schedule_sha256",
        "trust_binding",
    )
    return authority.acknowledge_fault(
        {
            "schema_version": "acceptance-fault-ack.v2",
            **{key: payload[key] for key in binding_keys if key in payload},
            "fault_id": fault.fault_id,
            "phase": payload["phase"],
            "command_id": prepared["command_id"],
            "receipt": receipt.model_dump(mode="json"),
        }
    )


def _client(
    tmp_path: Path,
    repository: PilotRepository,
    authority: AcceptanceAuthority,
    *,
    restart: int,
) -> TestClient:
    del repository
    app = create_acceptance_controller_app(
        authority=authority,
        controller_token=TOKEN,
        runtime_lock_path=tmp_path / f"api-{restart}.lock",
    )
    return TestClient(app, base_url="https://testserver")


def _binding(
    *,
    collector_id: str,
    manifest_sha256: str,
    launch: LaunchAttestationV2,
    schedule: tuple[ScheduledFaultV2, ...],
    gate: str = "8h",
) -> dict[str, object]:
    execution = _execution(launch)
    return {
        "collector_id": collector_id,
        "site_id": launch.site_id,
        "manifest_sha256": manifest_sha256,
        "gate": gate,
        "launch_attestation_sha256": launch.attestation_sha256,
        "execution_binding_sha256": execution.binding_sha256,
        "fault_schedule_sha256": canonical_fault_schedule_sha256(schedule),
    }


def _execution(launch: LaunchAttestationV2) -> ExecutionBindingV2:
    return ExecutionBindingV2(
        schema_version="acceptance-execution-binding.v2",
        launch_attestation_sha256=launch.attestation_sha256,
        launch_nonce="1" * 32,
        container_id="2" * 64,
        container_config_sha256="3" * 64,
        runtime_image_id_sha256=launch.runtime_image_id_sha256,
        acceptance_adapter_sha256=launch.acceptance_adapter_sha256,
        acceptance_adapter_policy_sha256=(launch.acceptance_adapter_policy_sha256),
        acceptance_observer_sha256=launch.acceptance_observer_sha256,
        acceptance_observer_policy_sha256=(launch.acceptance_observer_policy_sha256),
        control_network_id="4" * 64,
        control_network_config_sha256="5" * 64,
        camera_network_id="6" * 64,
        camera_network_config_sha256="7" * 64,
        observed_gpu_inventory_sha256=launch.gpu_inventory_sha256,
    )


def _workloads(
    manifest: AcceptanceManifestV2,
) -> tuple[CameraAcceptanceWorkloadV2, ...]:
    return tuple(
        CameraAcceptanceWorkloadV2(
            camera_id=source.camera_id,
            source_index=source.source_index,
            source_kind=source.source.kind,
            source_reference=source.source.path,
            codec=source.codec,
            width=source.width,
            height=source.height,
            fps=source.fps,
            bitrate_kbps=source.bitrate_kbps,
            analytics_hz=source.analytics_hz,
        )
        for source in manifest.sources
    )


def test_real_acceptance_routes_are_durable_command_bound_and_machine_authenticated(
    tmp_path: Path,
    monkeypatch,
    request: pytest.FixtureRequest,
) -> None:
    manifest = _manifest(tmp_path)
    template = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    clock = ControlledClock()
    adapter = NonDestructiveObservedAdapter(template, clock)
    journal_path = tmp_path / "protected-authority" / "acceptance-authority.sqlite3"
    trust_context = authority_trust_context(tmp_path, manifest)
    namespace = _protected_journal_namespace(journal_path)
    namespace.__enter__()
    request.addfinalizer(lambda: namespace.__exit__(None, None, None))
    private_key_path = tmp_path / "target-run-private.pem"
    private_key_path.chmod(0o600)
    signer = OpenSSLAcceptanceRunSigner(
        private_key_path,
        expected_public_key_spki_sha256=(
            manifest.launch.run_authority_public_key_spki_sha256
        ),
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
    )
    proof_root = tmp_path / "acceptance-proofs"
    proof_root.mkdir(mode=0o700)
    proof_store = AcceptanceProofStore(proof_root)

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'api.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    authority = AcceptanceAuthority(
        journal=SQLiteAcceptanceAuthorityJournal(
            journal_path,
            protected_namespace_owner_uid=os.geteuid(),
        ),
        adapter=adapter,
        signer=signer,
        proof_store=proof_store,
        trust_context=trust_context,
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-controller-test",
    )
    client = _client(tmp_path, repository, authority, restart=1)
    binding = _binding(
        collector_id="unauthorized-probe",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    start_payload = {
        "schema_version": "acceptance-collector-start.v2",
        **binding,
        "sample_interval_seconds": 60,
        "camera_ids": [source.camera_id for source in manifest.sources],
        "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
        "launch": manifest.launch.model_dump(mode="json"),
        "execution": _execution(manifest.launch).model_dump(mode="json"),
        "fault_schedule": [item.model_dump(mode="json") for item in schedule],
    }
    assert (
        client.post(
            "/api/internal/acceptance/start",
            json=start_payload,
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/internal/acceptance/start",
            headers={"Authorization": f"Bearer {GENERAL_MACHINE_TOKEN}"},
            json=start_payload,
        ).status_code
        == 401
    )
    token_path = tmp_path / "acceptance-machine-token"
    token_path.write_text(TOKEN, encoding="utf-8")

    class UrlOpenResponse:
        def __init__(self, response, *, final_url: str) -> None:
            self.status = response.status_code
            self._content = response.content
            self._final_url = final_url

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return self._content[:limit]

        def geturl(self) -> str:
            return self._final_url

    def urlopen(request, *, timeout: float):
        assert timeout == 5.0
        path = urllib.parse.urlsplit(request.full_url).path
        if path == "/api/internal/acceptance/sample":
            request_payload = json.loads(request.data)
            if request_payload["scheduled_monotonic_offset_seconds"] == 0:
                baseline_resource = request_payload["observation"]["resource"]
                assert "interval_started_at" in baseline_resource
                assert baseline_resource["interval_started_at"] is None
        response = client.post(
            path,
            headers=dict(request.header_items()),
            content=request.data,
        )
        return UrlOpenResponse(response, final_url=request.full_url)

    collector = AuthenticatedTargetCollector(
        base_url="http://127.0.0.1:8765",
        acceptance_controller_token_file=token_path,
        fault_executor=AdapterBackedEffectExecutor(adapter),
        observer=adapter,
        verified_trust=trust_context.trust,
        configured_site_id=trust_context.configured_site_id,
        configured_campaign_id=trust_context.configured_campaign_id,
        configured_gate=trust_context.configured_gate,
    )
    monkeypatch.setattr(collector._opener, "open", urlopen)
    collector.start(
        site_id=manifest.site_id,
        manifest_sha256=manifest.manifest_sha256,
        gate="8h",
        camera_ids=tuple(source.camera_id for source in manifest.sources),
        workloads=_workloads(manifest),
        sample_interval_seconds=60,
        launch=manifest.launch,
        execution=_execution(manifest.launch),
        schedule=schedule,
    )
    collector_id = collector.collector_id

    commands = sorted(
        (
            boundary,
            fault,
            phase,
        )
        for fault in schedule
        for phase, boundary in (
            ("inject", fault.offset_seconds),
            ("recover", fault.offset_seconds + fault.duration_seconds),
        )
    )
    command_index = 0
    for sample_offset in range(0, 28_801, 60):
        while command_index < len(commands) and commands[command_index][0] <= sample_offset:
            boundary, fault, phase = commands[command_index]
            clock.offset = boundary
            collector.command_fault(
                fault_id=fault.fault_id,
                phase=phase,
                at_offset=boundary,
            )
            command_index += 1
            if fault.kind == "api_restart" and phase == "inject":
                authority = AcceptanceAuthority(
                    journal=SQLiteAcceptanceAuthorityJournal(
                        journal_path,
                        protected_namespace_owner_uid=os.geteuid(),
                    ),
                    adapter=adapter,
                    signer=signer,
                    proof_store=proof_store,
                    trust_context=trust_context,
                    wall_clock=clock.wall,
                    monotonic_clock=clock.monotonic,
                    host_boot_id_provider=lambda: "host-controller-test",
                )
                client = _client(
                    tmp_path,
                    repository,
                    authority,
                    restart=2,
                )
        clock.offset = float(sample_offset)
        collector.collect(
            process_healthy=True,
            scheduled_monotonic_offset_seconds=float(sample_offset),
        )

    record = collector.finish()
    assert record.run_id == collector_id
    assert record.launch == manifest.launch
    assert len(record.fault_traces) == 16
    assert len({trace.command_id for trace in record.fault_traces}) == 16
    assert all(
        trace.command_id.startswith("command-") and len(trace.command_id) == len("command-") + 64
        for trace in record.fault_traces
    )
    assert len(adapter.commands) == 16
    camera_loss = next(fault for fault in schedule if fault.kind == "camera_loss")
    between_sample_outage = next(
        span
        for span in record.health_spans
        if span.camera_id == camera_loss.target and span.state == "source_outage"
    )
    assert between_sample_outage.started_at == START + timedelta(seconds=camera_loss.offset_seconds)
    assert between_sample_outage.ended_at == START + timedelta(
        seconds=camera_loss.offset_seconds + camera_loss.duration_seconds
    )

    replay = SQLiteAcceptanceAuthorityJournal(
        journal_path,
        protected_namespace_owner_uid=os.geteuid(),
    )
    assert replay.entry_count(collector_id) == 531
    assert replay.finalized(collector_id) is True
    sample_rows = tuple(
        AcceptanceSampleObservationV2.model_validate(item)
        for item in replay.entries(collector_id, kind="sample")
    )
    contradictory_intervals = tuple(
        interval.model_copy(update={"state": "online"})
        if interval.camera_id == camera_loss.target and interval.state == "offline"
        else interval
        for interval in sample_rows[1].health_intervals
    )
    contradictory_samples = (
        sample_rows[0],
        sample_rows[1].model_copy(update={"health_intervals": contradictory_intervals}),
        *sample_rows[2:],
    )
    with pytest.raises(ValueError, match="contradict source fault"):
        AcceptanceAuthority._derive_sample_evidence(
            start=AcceptanceStartRequestV2.model_validate(start_payload),
            started_at=START,
            samples=contradictory_samples,
            traces=record.fault_traces,
        )
    assert sum(item.observed_records for item in sample_rows) == sum(
        camera.observed_records for camera in record.cameras
    )
    assert record.resources == tuple(item.resource for item in sample_rows)


def test_delayed_source_acknowledgements_partition_outage_and_availability(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    manifest = _manifest(tmp_path)
    template = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    camera_ids = tuple(source.camera_id for source in manifest.sources)
    schedule = canonical_fault_schedule(camera_ids)
    delayed_fault = next(fault for fault in schedule if fault.kind == "camera_loss")
    clock = ControlledClock()

    class DelayedSourceAdapter(NonDestructiveObservedAdapter):
        def sample(
            self,
            *,
            collector_id: str,
            launch: LaunchAttestationV2,
            execution: ExecutionBindingV2,
            previous_monotonic_offset_seconds: float,
            scheduled_monotonic_offset_seconds: float,
        ) -> AcceptanceSampleObservationV2:
            previous_offset = self.last_sample_offset
            observation = super().sample(
                collector_id=collector_id,
                launch=launch,
                execution=execution,
                previous_monotonic_offset_seconds=(previous_monotonic_offset_seconds),
                scheduled_monotonic_offset_seconds=(scheduled_monotonic_offset_seconds),
            )
            current_offset = clock.offset

            def outage_through(boundary: float) -> float:
                return max(
                    0.0,
                    min(
                        boundary,
                        delayed_fault.offset_seconds + delayed_fault.duration_seconds,
                    )
                    - (delayed_fault.offset_seconds + 1.5),
                )

            cameras: list[CameraAcceptanceObservationV2] = []
            for camera in observation.cameras:
                if camera.camera_id != delayed_fault.target:
                    cameras.append(camera)
                    continue
                counters: list[AnalyticCounterObservationV2] = []
                source = next(
                    item for item in manifest.sources if item.camera_id == camera.camera_id
                )
                for counter in camera.counters:
                    rate = source.analytics_hz[counter.module]
                    scheduled = math.floor(
                        rate * (current_offset - outage_through(current_offset)) + 1e-9
                    ) - math.floor(
                        rate * (previous_offset - outage_through(previous_offset)) + 1e-9
                    )
                    counters.append(
                        counter.model_copy(
                            update={
                                "scheduled_samples": scheduled,
                                "processed_samples": (scheduled - counter.dropped_samples),
                            }
                        )
                    )
                cameras.append(camera.model_copy(update={"counters": tuple(counters)}))
            health_intervals: list[CameraHealthIntervalObservationV2] = []
            for camera_id in camera_ids:
                if camera_id != delayed_fault.target:
                    health_intervals.extend(
                        item for item in observation.health_intervals if item.camera_id == camera_id
                    )
                    continue
                boundaries = sorted(
                    {
                        previous_offset,
                        current_offset,
                        *(
                            boundary
                            for boundary in (
                                delayed_fault.offset_seconds + 1.5,
                                delayed_fault.offset_seconds + delayed_fault.duration_seconds,
                                delayed_fault.offset_seconds + delayed_fault.duration_seconds + 2.5,
                            )
                            if previous_offset < boundary < current_offset
                        ),
                    }
                )
                health_intervals.extend(
                    CameraHealthIntervalObservationV2(
                        camera_id=camera_id,
                        started_monotonic_offset_seconds=interval_start,
                        ended_monotonic_offset_seconds=interval_end,
                        state=(
                            "offline"
                            if delayed_fault.offset_seconds + 1.5
                            <= (interval_start + interval_end) / 2
                            < (delayed_fault.offset_seconds + delayed_fault.duration_seconds + 2.5)
                            else "online"
                        ),
                    )
                    for interval_start, interval_end in zip(
                        boundaries,
                        boundaries[1:],
                    )
                )
            return observation.model_copy(
                update={
                    "cameras": tuple(cameras),
                    "health_intervals": tuple(health_intervals),
                    "observed_records": sum(
                        counter.processed_samples
                        for camera in cameras
                        for counter in camera.counters
                    ),
                }
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
            observation = super().observe_fault(
                collector_id=collector_id,
                launch=launch,
                execution=execution,
                fault=fault,
                phase=phase,
                command_id=command_id,
                commanded_monotonic_offset_seconds=(commanded_monotonic_offset_seconds),
            )
            if fault.fault_id == delayed_fault.fault_id:
                clock.offset += 1.5 if phase == "inject" else 2.5
            return observation

    adapter = DelayedSourceAdapter(template, clock)
    trust_context = authority_trust_context(tmp_path, manifest)
    journal_path = tmp_path / "protected-delayed" / "authority.sqlite3"
    namespace = _protected_journal_namespace(journal_path)
    namespace.__enter__()
    request.addfinalizer(lambda: namespace.__exit__(None, None, None))
    private_key_path = tmp_path / "target-run-private.pem"
    private_key_path.chmod(0o600)
    signer = OpenSSLAcceptanceRunSigner(
        private_key_path,
        expected_public_key_spki_sha256=(
            manifest.launch.run_authority_public_key_spki_sha256
        ),
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
    )
    proof_root = tmp_path / "delayed-proofs"
    proof_root.mkdir(mode=0o700)
    authority = AcceptanceAuthority(
        journal=SQLiteAcceptanceAuthorityJournal(
            journal_path,
            protected_namespace_owner_uid=os.geteuid(),
        ),
        adapter=adapter,
        signer=signer,
        proof_store=AcceptanceProofStore(proof_root),
        trust_context=trust_context,
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-delayed-recovery",
    )
    binding = _binding(
        collector_id="collector-delayed-recovery",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    binding["trust_binding"] = trust_context.binding.model_dump(mode="json")
    execution = _execution(manifest.launch)
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": camera_ids,
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": execution.model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    commands = sorted(
        (boundary, fault, phase)
        for fault in schedule
        for phase, boundary in (
            ("inject", fault.offset_seconds),
            ("recover", fault.offset_seconds + fault.duration_seconds),
        )
    )
    command_index = 0
    for sample_offset in range(0, 28_801, 60):
        while command_index < len(commands) and commands[command_index][0] <= sample_offset:
            boundary, fault, phase = commands[command_index]
            clock.offset = boundary
            _execute_fault(
                authority=authority,
                payload={
                    "schema_version": "acceptance-fault-command.v2",
                    **binding,
                    "fault": fault.model_dump(mode="json"),
                    "phase": phase,
                    "commanded_monotonic_offset_seconds": boundary,
                },
                executor=AdapterBackedEffectExecutor(adapter),
                launch=manifest.launch,
                execution=execution,
            )
            command_index += 1
        clock.offset = float(sample_offset)
        authority.sample(
            {
                "schema_version": "acceptance-collector-sample.v2",
                **binding,
                "process_healthy": True,
                "scheduled_monotonic_offset_seconds": float(sample_offset),
            }
        )
    record = AcceptanceFinalEnvelopeV2.model_validate(
        authority.finalize(
            {
                "schema_version": "acceptance-collector-finalize.v2",
                **binding,
            }
        )
    ).record

    camera = next(item for item in record.cameras if item.camera_id == delayed_fault.target)
    assert camera.source_outage_seconds == 3.5
    assert camera.availability_seconds == pytest.approx(28_800 - 3.5 - 2.5)
    relevant_spans = tuple(
        span for span in record.health_spans if span.camera_id == delayed_fault.target
    )
    assert tuple(
        (
            span.state,
            (span.started_at - START).total_seconds(),
            (span.ended_at - START).total_seconds(),
        )
        for span in relevant_spans
    ) == (
        ("online", 0.0, 11.5),
        ("source_outage", 11.5, 15.0),
        ("offline", 15.0, 17.5),
        ("online", 17.5, 28_800.0),
    )


def test_production_authority_rejects_wrong_uid_before_journal_construction(
    tmp_path: Path,
    monkeypatch,
) -> None:
    journal_path = tmp_path / "production-namespace" / "production-acceptance.sqlite3"
    monkeypatch.setenv("PILOT_ACCEPTANCE_JOURNAL_PATH", str(journal_path))
    monkeypatch.setattr(
        controller_module,
        "_PROTECTED_NAMESPACE_RUNTIME_UID",
        os.geteuid() + 1,
        raising=False,
    )
    with pytest.raises(RuntimeError, match=r"runtime UID"):
        build_production_acceptance_authority()
    assert not journal_path.exists()


def test_production_controller_rejects_legacy_acceptance_overrides(
    tmp_path: Path,
    monkeypatch,
) -> None:
    journal_path = tmp_path / "configured-authority.sqlite3"
    monkeypatch.setenv("PILOT_ACCEPTANCE_JOURNAL_PATH", str(journal_path))
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_ADAPTER_EXECUTABLE",
        "/opt/kuzet/forbidden-adapter",
    )
    monkeypatch.setattr(
        controller_module,
        "_PROTECTED_NAMESPACE_RUNTIME_UID",
        os.geteuid(),
        raising=False,
    )
    with pytest.raises(RuntimeError, match="unsupported override"):
        build_production_acceptance_authority()
    assert not journal_path.exists()


def test_deployment_wires_durable_reviewed_acceptance_authority() -> None:
    compose = yaml.safe_load(
        (REPO_ROOT / "deploy/pilot/docker-compose.acceptance.yml").read_text()
    )
    base = yaml.safe_load((REPO_ROOT / "deploy/pilot/docker-compose.yml").read_text())
    controller = compose["services"]["acceptance-controller"]
    environment = controller["environment"]
    assert environment["PILOT_ACCEPTANCE_JOURNAL_PATH"] == (
        "/var/lib/kuzet/acceptance/authority.sqlite3"
    )
    assert "PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256" in environment
    assert "PILOT_ACCEPTANCE_RUN_PUBLIC_KEY_SHA256" not in environment
    assert not any("ADAPTER" in key for key in environment)
    assert "acceptance_controller_token" in controller["secrets"]
    assert "acceptance_run_signing_private_key" not in controller["secrets"]
    assert {volume["target"] for volume in controller["volumes"] if volume["read_only"]} >= {
        "/run/config/acceptance/offline-root-public.pem",
        "/run/config/acceptance/trust-policy.json",
        "/run/config/acceptance/acceptance-manifest.json",
        "/run/config/acceptance/run-role-public.pem",
        "/run/keys/acceptance/run-private.pem",
    }
    assert all(volume["bind"]["create_host_path"] is False for volume in controller["volumes"])
    assert "docker.sock" not in str(controller["volumes"])
    assert "ports" not in base["services"]["api"]
    dockerfile = (REPO_ROOT / "deploy/pilot/Dockerfile.api").read_text()
    assert "install -d -o root -g root -m 0755 /var/lib/kuzet/acceptance" in dockerfile
    ready = (REPO_ROOT / "docs/pilot/ready_to_start.md").read_text()
    assert "PENDING external NVIDIA/20-source execution" in ready


def test_journal_global_bounds_and_72h_budget_fail_before_session_start(
    tmp_path: Path,
) -> None:
    bounded = SQLiteAcceptanceAuthorityJournal(
        tmp_path / "global-bound.sqlite3",
        max_total_entries=1,
        max_sessions=1,
    )
    bounded.append(
        collector_id="collector-one",
        kind="start",
        identity="start",
        payload={
            "schema_version": "acceptance-collector-start.v2",
            "bounded": True,
        },
        created_at=START,
    )
    with pytest.raises(RuntimeError, match="global entry"):
        bounded.append(
            collector_id="collector-two",
            kind="start",
            identity="start",
            payload={
                "schema_version": "acceptance-collector-start.v2",
                "bounded": True,
            },
            created_at=START,
        )

    manifest = _manifest(tmp_path)
    clock = ControlledClock()
    camera_ids = tuple(source.camera_id for source in manifest.sources)
    schedule = canonical_fault_schedule(camera_ids)
    journal = SQLiteAcceptanceAuthorityJournal(
        tmp_path / "72h-budget.sqlite3",
        max_entries=4_350,
    )
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=NonDestructiveObservedAdapter(_run(manifest), clock),
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-budget",
    )
    binding = _binding(
        collector_id="collector-72h-budget",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
        gate="72h",
    )
    with pytest.raises(RuntimeError, match="journal budget"):
        authority.start(
            {
                "schema_version": "acceptance-collector-start.v2",
                **binding,
                "sample_interval_seconds": 60,
                "camera_ids": camera_ids,
                "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
                "launch": manifest.launch.model_dump(mode="json"),
                "execution": _execution(manifest.launch).model_dump(mode="json"),
                "fault_schedule": [item.model_dump(mode="json") for item in schedule],
            }
        )
    assert journal.entry_count("collector-72h-budget") == 0


def test_adapter_fifo_response_is_rejected_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "response.fifo"
    os.mkfifo(fifo)
    outcomes: list[BaseException] = []

    def read_fifo() -> None:
        try:
            authority_module._read_bounded_regular(fifo, limit=1024)
        except BaseException as exc:
            outcomes.append(exc)

    reader = threading.Thread(target=read_fifo, daemon=True)
    reader.start()
    reader.join(timeout=1)
    if reader.is_alive():
        writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(writer)
        reader.join(timeout=1)
    assert not reader.is_alive()
    assert len(outcomes) == 1
    assert isinstance(outcomes[0], ValueError)
    assert "bounded regular file" in str(outcomes[0])


def test_acceptance_session_fails_closed_after_host_reboot(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    template = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    clock = ControlledClock()
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "reboot.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=NonDestructiveObservedAdapter(template, clock),
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-boot-before",
    )
    binding = _binding(
        collector_id="collector-reboot",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": [source.camera_id for source in manifest.sources],
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": _execution(manifest.launch).model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )

    restarted = AcceptanceAuthority(
        journal=journal,
        adapter=NonDestructiveObservedAdapter(template, clock),
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-boot-after",
    )
    with pytest.raises(RuntimeError, match="host reboot"):
        restarted.sample(
            {
                "schema_version": "acceptance-collector-sample.v2",
                **binding,
                "process_healthy": True,
                "scheduled_monotonic_offset_seconds": 0,
            }
        )


@pytest.mark.parametrize(
    ("adapter_latency", "accepted"),
    ((0.25, True), (5.01, False)),
)
def test_authority_canonicalizes_bounded_sample_latency_and_rejects_stale_data(
    tmp_path: Path,
    adapter_latency: float,
    accepted: bool,
) -> None:
    manifest = _manifest(tmp_path)
    clock = ControlledClock()
    camera_ids = tuple(source.camera_id for source in manifest.sources)
    schedule = canonical_fault_schedule(camera_ids)

    class DelayedAdapter:
        identity = AcceptanceAdapterIdentityV2(
            schema_version="acceptance-adapter-identity.v2",
            executable_sha256=manifest.launch.acceptance_observer_sha256,
            policy_sha256=manifest.launch.acceptance_observer_policy_sha256,
        )

        def sample(
            self,
            *,
            collector_id: str,
            launch: LaunchAttestationV2,
            execution: ExecutionBindingV2,
            previous_monotonic_offset_seconds: float,
            scheduled_monotonic_offset_seconds: float,
        ) -> AcceptanceSampleObservationV2:
            assert previous_monotonic_offset_seconds == 0
            assert scheduled_monotonic_offset_seconds == 0
            clock.offset = adapter_latency
            return AcceptanceSampleObservationV2(
                schema_version="acceptance-sample-observation.v2",
                observed_at=clock.wall(),
                observed_records=0,
                collector_id=collector_id,
                launch_attestation_sha256=launch.attestation_sha256,
                execution_binding_sha256=execution.binding_sha256,
                observer_sha256=execution.acceptance_observer_sha256,
                observer_policy_sha256=(execution.acceptance_observer_policy_sha256),
                cameras=tuple(
                    CameraAcceptanceObservationV2(
                        camera_id=source.camera_id,
                        source_index=source.source_index,
                        negotiated_codec=source.codec,
                        negotiated_width=source.width,
                        negotiated_height=source.height,
                        negotiated_fps=source.fps,
                        negotiated_bitrate_kbps=source.bitrate_kbps,
                        queue_name="analytics",
                        state="online",
                        counters=tuple(
                            AnalyticCounterObservationV2(
                                module=module,
                                scheduled_samples=0,
                                processed_samples=0,
                                dropped_samples=0,
                            )
                            for module, rate in source.analytics_hz.items()
                            if rate > 0
                        ),
                        queue_observation_cadence_seconds=1,
                        queue_age_runs=(
                            QueueAgeRunV2(
                                age_seconds=0.1,
                                samples=1,
                            ),
                        ),
                        runtime_boot_id=f"{execution.launch_nonce}.runtime-latency",
                        api_boot_id="api-latency",
                    )
                    for source in manifest.sources
                ),
                health_intervals=(),
                resource=ResourceSampleV2(
                    sampled_at=clock.wall(),
                    interval_started_at=None,
                    observation_cadence_seconds=1,
                    observation_count=1,
                    gpu_percent=10,
                    gpu_percent_high_water=10,
                    vram_percent=20,
                    vram_percent_high_water=20,
                    disk_bytes=100,
                    disk_bytes_high_water=100,
                    disk_limit_bytes=1000,
                ),
            )

        def observe_fault(self, **_kwargs):
            raise AssertionError("fault command is not used")

        def finalize(self, **_kwargs):
            raise AssertionError("finalize is not used")

    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / f"latency-{adapter_latency}.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=DelayedAdapter(),
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-latency",
    )
    binding = _binding(
        collector_id=f"collector-latency-{adapter_latency}",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": camera_ids,
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": _execution(manifest.launch).model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    sample_payload = {
        "schema_version": "acceptance-collector-sample.v2",
        **binding,
        "process_healthy": True,
        "scheduled_monotonic_offset_seconds": 0,
    }
    if not accepted:
        with pytest.raises(ValueError, match="exceeded its scheduled boundary"):
            authority.sample(sample_payload)
        assert journal.entries(binding["collector_id"], kind="sample") == ()
        return
    response = authority.sample(sample_payload)
    assert response["observed_records"] == 0
    persisted = AcceptanceSampleObservationV2.model_validate(
        journal.entries(binding["collector_id"], kind="sample")[0]
    )
    assert persisted.observed_at == START
    assert persisted.resource.sampled_at == START


def test_authority_rejects_samples_beyond_gate_without_journal_growth(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    clock = ControlledClock()
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "gate-bound.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=NonDestructiveObservedAdapter(
            _run(manifest, hours=8).model_copy(update={"gate": "8h"}),
            clock,
        ),
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-gate-bound",
    )
    binding = _binding(
        collector_id="collector-gate-bound",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": [source.camera_id for source in manifest.sources],
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": _execution(manifest.launch).model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    before = journal.entry_count("collector-gate-bound")
    clock.offset = 28_860
    with pytest.raises(ValueError, match="exceeds its exact endurance gate"):
        authority.sample(
            {
                "schema_version": "acceptance-collector-sample.v2",
                **binding,
                "process_healthy": True,
                "scheduled_monotonic_offset_seconds": 28_860,
            }
        )
    assert journal.entry_count("collector-gate-bound") == before


def test_queue_age_aggregation_is_bounded_and_conservative_for_72h() -> None:
    runs = (
        QueueAgeRunV2(
            age_seconds=(index % 2_002) / 1000 + 0.000_000_1,
            samples=1,
        )
        for index in range(259_201)
    )
    aggregated = authority_module._aggregate_queue_age_runs(runs)

    assert len(aggregated) <= 2_002
    assert sum(item.samples for item in aggregated) == 259_201
    assert authority_module._aggregate_queue_age_runs(
        (
            QueueAgeRunV2(age_seconds=0.9991, samples=1),
            QueueAgeRunV2(age_seconds=1.9991, samples=1),
            QueueAgeRunV2(age_seconds=2.0001, samples=1),
        )
    ) == (
        QueueAgeRunV2(age_seconds=1.0, samples=1),
        QueueAgeRunV2(age_seconds=2.0, samples=1),
        QueueAgeRunV2(age_seconds=2.001, samples=1),
    )


def test_warm_journal_cache_never_returns_tampered_historical_payload(
    tmp_path: Path,
) -> None:
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "cache-chain.sqlite3")
    journal.append(
        collector_id="collector-cache-chain",
        kind="start",
        identity="start",
        payload={
            "schema_version": "acceptance-collector-start.v2",
            "value": "trusted",
        },
        created_at=START,
    )
    assert journal.entries("collector-cache-chain") == (
        {
            "schema_version": "acceptance-collector-start.v2",
            "value": "trusted",
        },
    )
    connection = authority_module.sqlite3.connect(journal.path)
    try:
        connection.execute(
            "UPDATE acceptance_entries SET payload_json = ? "
            "WHERE collector_id = ? AND identity = ?",
            (
                '{"schema_version":"acceptance-collector-start.v2","value":"tampered"}',
                "collector-cache-chain",
                "start",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    assert journal.entries("collector-cache-chain") == (
        {
            "schema_version": "acceptance-collector-start.v2",
            "value": "trusted",
        },
    )
    with pytest.raises(RuntimeError, match="hash chain"):
        journal.chain_head("collector-cache-chain")


def test_journal_rejects_commit_without_conservative_physical_headroom(
    tmp_path: Path,
) -> None:
    path = tmp_path / "physical.sqlite3"
    journal = SQLiteAcceptanceAuthorityJournal(
        path,
        max_database_bytes=1024 * 1024 * 1024,
    )
    for index in range(80):
        journal.append(
            collector_id="collector-physical",
            kind="fault_intent",
            identity=str(index),
            payload={
                "schema_version": "acceptance-fault-intent.v2",
                "index": index,
                "value": "y" * 20_000,
            },
            created_at=START,
        )
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    finally:
        connection.close()
    exact_cap = journal.database_bytes
    reopened = SQLiteAcceptanceAuthorityJournal(
        path,
        max_database_bytes=exact_cap,
    )

    with pytest.raises(RuntimeError, match="byte bound"):
        reopened.append(
            collector_id="collector-physical",
            kind="fault_intent",
            identity="armed",
            payload={
                "schema_version": "acceptance-fault-intent.v2",
                "value": "tiny",
            },
            created_at=START,
        )

    assert reopened.database_bytes <= exact_cap
    assert (
        reopened.entry(
            "collector-physical",
            kind="fault_intent",
            identity="armed",
        )
        is None
    )


def test_journal_concurrent_reader_cannot_force_commit_past_physical_cap(
    tmp_path: Path,
) -> None:
    path = tmp_path / "physical-reader.sqlite3"
    journal = SQLiteAcceptanceAuthorityJournal(
        path,
        max_database_bytes=1024 * 1024 * 1024,
    )
    for index in range(80):
        journal.append(
            collector_id="collector-physical-reader",
            kind="fault_intent",
            identity=str(index),
            payload={
                "schema_version": "acceptance-fault-intent.v2",
                "index": index,
                "value": "y" * 20_000,
            },
            created_at=START,
        )
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    finally:
        connection.close()
    reader = sqlite3.connect(path)
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM acceptance_entries").fetchone()
    exact_cap = journal.database_bytes
    reopened = SQLiteAcceptanceAuthorityJournal(
        path,
        max_database_bytes=exact_cap,
    )
    try:
        with pytest.raises(
            RuntimeError,
            match=r"byte bound|connected.*inode",
        ):
            reopened.append(
                collector_id="collector-physical-reader",
                kind="fault_intent",
                identity="armed",
                payload={
                    "schema_version": "acceptance-fault-intent.v2",
                    "value": "tiny",
                },
                created_at=START,
            )
        assert reopened.database_bytes <= exact_cap
        assert (
            reader.execute(
                "SELECT COUNT(*) FROM acceptance_entries WHERE collector_id = ? AND identity = ?",
                ("collector-physical-reader", "armed"),
            ).fetchone()[0]
            == 0
        )
    finally:
        reader.close()


def test_journal_rejects_main_inode_swap_restored_during_sqlite_connect(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "protected-main" / "authority.sqlite3"
    replacement = tmp_path / "main-connect-replacement.sqlite3"
    displaced = tmp_path / "main-connect-displaced.sqlite3"
    real_connect = authority_module.sqlite3.connect

    def swapped_connect(database, *args, **kwargs):
        assert Path(database) == path
        os.replace(path, displaced)
        os.replace(replacement, path)
        try:
            connection = real_connect(database, *args, **kwargs)
        finally:
            os.replace(path, replacement)
            os.replace(displaced, path)
        return connection

    with _protected_journal_namespace(path):
        journal = SQLiteAcceptanceAuthorityJournal(
            path,
            protected_namespace_owner_uid=os.geteuid(),
        )
        journal.append(
            collector_id="collector-main-connect-swap",
            kind="start",
            identity="start",
            payload={
                "schema_version": "acceptance-collector-start.v2",
                "value": "trusted",
            },
            created_at=START,
        )
        shutil.copy2(path, replacement)
        monkeypatch.setattr(
            authority_module.sqlite3,
            "connect",
            swapped_connect,
        )
        with pytest.raises(RuntimeError, match=r"protected namespace"):
            journal.entry_count("collector-main-connect-swap")


def test_journal_rejects_wal_inode_swap_restored_during_sqlite_connect(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "protected-wal" / "authority.sqlite3"
    real_connect = authority_module.sqlite3.connect
    with _protected_journal_namespace(path):
        journal = SQLiteAcceptanceAuthorityJournal(
            path,
            protected_namespace_owner_uid=os.geteuid(),
        )
        journal.append(
            collector_id="collector-wal-connect-swap",
            kind="start",
            identity="start",
            payload={
                "schema_version": "acceptance-collector-start.v2",
                "value": "trusted",
            },
            created_at=START,
        )
        reader = real_connect(path)
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM acceptance_entries").fetchone()
        writer = real_connect(path)
        try:
            writer.execute(
                "INSERT INTO acceptance_session_usage (collector_id, sample_bytes) VALUES (?, 0)",
                ("reader-retained-wal",),
            )
            writer.commit()
        finally:
            writer.close()
        wal = Path(f"{path}-wal")
        assert wal.exists()
        replacement = tmp_path / "wal-connect-replacement"
        displaced = tmp_path / "wal-connect-displaced"
        shutil.copy2(wal, replacement)

        def swapped_connect(database, *args, **kwargs):
            assert Path(database) == path
            os.replace(wal, displaced)
            os.replace(replacement, wal)
            try:
                connection = real_connect(database, *args, **kwargs)
                connection.execute("PRAGMA journal_mode=WAL").fetchone()
            finally:
                os.replace(wal, replacement)
                os.replace(displaced, wal)
            return connection

        monkeypatch.setattr(
            authority_module.sqlite3,
            "connect",
            swapped_connect,
        )

        try:
            with pytest.raises(RuntimeError, match=r"protected namespace"):
                journal.entry_count("collector-wal-connect-swap")
        finally:
            reader.close()


def test_journal_rejects_shm_inode_swap_during_sqlite_connect(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "protected-shm" / "authority.sqlite3"
    real_connect = authority_module.sqlite3.connect
    with _protected_journal_namespace(path):
        journal = SQLiteAcceptanceAuthorityJournal(
            path,
            protected_namespace_owner_uid=os.geteuid(),
        )
        shm = Path(f"{path}-shm")
        replacement = tmp_path / "shm-connect-replacement"
        displaced = tmp_path / "shm-connect-displaced"
        shutil.copy2(shm, replacement)

        def swapped_connect(database, *args, **kwargs):
            assert Path(database) == path
            os.replace(shm, displaced)
            os.replace(replacement, shm)
            try:
                return real_connect(database, *args, **kwargs)
            finally:
                os.replace(shm, replacement)
                os.replace(displaced, shm)

        monkeypatch.setattr(
            authority_module.sqlite3,
            "connect",
            swapped_connect,
        )

        with pytest.raises(RuntimeError, match=r"protected namespace"):
            journal.entry_count("collector-shm-connect-swap")


def test_protected_journal_never_raw_opens_sqlite_main(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "protected-no-witness" / "authority.sqlite3"
    with _protected_journal_namespace(path):
        journal = SQLiteAcceptanceAuthorityJournal(
            path,
            protected_namespace_owner_uid=os.geteuid(),
        )
        real_open = authority_module.os.open

        def reject_main_open(candidate, *args, **kwargs):
            if Path(candidate) == path:
                raise AssertionError("protected SQLite main file was raw-opened")
            return real_open(candidate, *args, **kwargs)

        monkeypatch.setattr(authority_module.os, "open", reject_main_open)
        journal.append(
            collector_id="collector-no-witness",
            kind="start",
            identity="start",
            payload={
                "schema_version": "acceptance-collector-start.v2",
                "value": "trusted",
            },
            created_at=START,
        )
        reopened = SQLiteAcceptanceAuthorityJournal(
            path,
            protected_namespace_owner_uid=os.geteuid(),
        )
        assert reopened.entry_count("collector-no-witness") == 1


def test_protected_journal_requires_one_triplet_device(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "protected-device" / "authority.sqlite3"
    shm = Path(f"{path}-shm")
    with _protected_journal_namespace(path):
        real_lstat = Path.lstat

        def cross_device_lstat(candidate: Path):
            metadata = real_lstat(candidate)
            if candidate == shm:
                values = list(metadata)
                values[2] += 1
                return os.stat_result(values)
            return metadata

        monkeypatch.setattr(Path, "lstat", cross_device_lstat)
        with pytest.raises(RuntimeError, match=r"same.*filesystem"):
            SQLiteAcceptanceAuthorityJournal(
                path,
                protected_namespace_owner_uid=os.geteuid(),
            )


def test_protected_journal_requires_nonwritable_complete_namespace(
    tmp_path: Path,
) -> None:
    path = tmp_path / "writable-namespace" / "authority.sqlite3"
    path.parent.mkdir(mode=0o700)
    SQLiteAcceptanceAuthorityJournal(path)

    with pytest.raises(RuntimeError, match=r"protected namespace"):
        SQLiteAcceptanceAuthorityJournal(
            path,
            protected_namespace_owner_uid=os.geteuid(),
        )

    missing_path = tmp_path / "missing-aux" / "authority.sqlite3"
    with _protected_journal_namespace(missing_path):
        missing_path.parent.chmod(0o700)
        Path(f"{missing_path}-shm").unlink()
        missing_path.parent.chmod(0o500)
        with pytest.raises(RuntimeError, match=r"protected namespace"):
            SQLiteAcceptanceAuthorityJournal(
                missing_path,
                protected_namespace_owner_uid=os.geteuid(),
            )


def test_portable_journal_cannot_be_reclassified_as_protected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "portable-reclassification" / "authority.sqlite3"
    path.parent.mkdir(mode=0o700)
    SQLiteAcceptanceAuthorityJournal(path)
    Path(f"{path}-wal").touch(mode=0o600)
    Path(f"{path}-shm").touch(mode=0o600)
    path.parent.chmod(0o500)
    try:
        with pytest.raises(RuntimeError, match=r"namespace mode"):
            SQLiteAcceptanceAuthorityJournal(
                path,
                protected_namespace_owner_uid=os.geteuid(),
            )
    finally:
        path.parent.chmod(0o700)


def test_signing_authority_requires_protected_journal_namespace(
    tmp_path: Path,
) -> None:
    class Signer:
        public_key_spki_sha256 = "8" * 64

        def sign(self, _payload: bytes) -> bytes:
            return b"x" * 64

    with pytest.raises(ValueError, match=r"protected.*namespace"):
        AcceptanceAuthority(
            journal=SQLiteAcceptanceAuthorityJournal(tmp_path / "portable-signing.sqlite3"),
            signer=Signer(),
            monotonic_clock=lambda: 0.0,
        )


def test_protected_journal_reopens_writes_checkpoints_and_reads_concurrently(
    tmp_path: Path,
) -> None:
    path = tmp_path / "protected-lifecycle" / "authority.sqlite3"
    with _protected_journal_namespace(path):
        journal = SQLiteAcceptanceAuthorityJournal(
            path,
            protected_namespace_owner_uid=os.geteuid(),
        )
        journal.append(
            collector_id="collector-protected-lifecycle",
            kind="start",
            identity="start",
            payload={
                "schema_version": "acceptance-collector-start.v2",
                "value": "trusted",
            },
            created_at=START,
        )
        with sqlite3.connect(path) as connection:
            connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        reopened = SQLiteAcceptanceAuthorityJournal(
            path,
            protected_namespace_owner_uid=os.geteuid(),
        )
        errors: list[BaseException] = []
        lock = threading.Lock()

        def read_repeatedly() -> None:
            try:
                for _ in range(50):
                    assert reopened.entry_count("collector-protected-lifecycle") == 1
            except BaseException as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=read_repeatedly) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert not any(thread.is_alive() for thread in threads)
        assert errors == []


def test_protected_journal_enforces_physical_cap(
    tmp_path: Path,
) -> None:
    path = tmp_path / "protected-cap" / "authority.sqlite3"
    byte_cap = 1024 * 1024
    with _protected_journal_namespace(path):
        journal = SQLiteAcceptanceAuthorityJournal(
            path,
            max_database_bytes=byte_cap,
            protected_namespace_owner_uid=os.geteuid(),
        )
        rejected_identity = ""
        for index in range(100):
            rejected_identity = str(index)
            try:
                journal.append(
                    collector_id="collector-protected-cap",
                    kind="fault_intent",
                    identity=rejected_identity,
                    payload={
                        "schema_version": "acceptance-fault-intent.v2",
                        "index": index,
                        "value": "y" * 20_000,
                    },
                    created_at=START,
                )
            except RuntimeError as exc:
                assert "byte bound" in str(exc)
                break
        else:
            pytest.fail("protected journal never reached its physical cap")

        assert journal.database_bytes <= byte_cap
        assert (
            journal.entry(
                "collector-protected-cap",
                kind="fault_intent",
                identity=rejected_identity,
            )
            is None
        )


def test_journal_reconnects_after_clean_auxiliary_inode_recreation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "clean-aux-recreation.sqlite3"
    journal = SQLiteAcceptanceAuthorityJournal(path)
    journal.append(
        collector_id="collector-clean-aux",
        kind="start",
        identity="start",
        payload={
            "schema_version": "acceptance-collector-start.v2",
            "value": "trusted",
        },
        created_at=START,
    )
    for auxiliary in (Path(f"{path}-wal"), Path(f"{path}-shm")):
        if auxiliary.exists():
            auxiliary.unlink()

    assert journal.entry_count("collector-clean-aux") == 1
    journal.append(
        collector_id="collector-clean-aux",
        kind="fault_intent",
        identity="after-clean-recreation",
        payload={
            "schema_version": "acceptance-fault-intent.v2",
            "value": "still-trusted",
        },
        created_at=START,
    )
    assert journal.entry_count("collector-clean-aux") == 2


def test_protected_journal_preserves_write_lock_during_fd_churn(
    tmp_path: Path,
) -> None:
    journal_directory = tmp_path / "journal-state"
    journal_path = journal_directory / "concurrent-fd-attestation.sqlite3"
    noise_directory = tmp_path / "unrelated-fd-noise"
    noise_directory.mkdir()
    noise_paths = []
    for index in range(4):
        noise_path = noise_directory / f"noise-{index}.bin"
        noise_path.write_bytes(b"unrelated")
        noise_paths.append(noise_path)
    with _protected_journal_namespace(journal_path):
        journal = SQLiteAcceptanceAuthorityJournal(
            journal_path,
            protected_namespace_owner_uid=os.geteuid(),
        )
        journal.append(
            collector_id="collector-concurrent-fd",
            kind="start",
            identity="start",
            payload={
                "schema_version": "acceptance-collector-start.v2",
                "value": "trusted",
            },
            created_at=START,
        )
        holder = sqlite3.connect(journal_path, timeout=5)
        holder.execute("BEGIN IMMEDIATE")
        child_script = """
import sqlite3
import sys

path = sys.argv[1]
connection = sqlite3.connect(path, timeout=10)
print("READY", flush=True)
try:
    connection.execute(
        "INSERT INTO acceptance_session_usage "
        "(collector_id, sample_bytes) VALUES (?, 0)",
        ("subprocess-lock-probe",),
    )
    connection.commit()
    print("COMMITTED", flush=True)
finally:
    connection.close()
"""
        process = subprocess.Popen(
            (sys.executable, "-c", child_script, str(journal_path)),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdout is not None
            assert process.stdout.readline() == "READY\n"
            barrier = threading.Barrier(8)
            errors: list[BaseException] = []
            errors_lock = threading.Lock()

            def read_repeatedly() -> None:
                try:
                    barrier.wait(timeout=5)
                    for _ in range(250):
                        assert journal.entry_count("collector-concurrent-fd") == 1
                except BaseException as exc:
                    with errors_lock:
                        errors.append(exc)

            def churn_unrelated_file(path: Path) -> None:
                try:
                    barrier.wait(timeout=5)
                    for _ in range(250):
                        descriptor = os.open(
                            path,
                            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                        )
                        try:
                            os.fstat(descriptor)
                        finally:
                            os.close(descriptor)
                except BaseException as exc:
                    with errors_lock:
                        errors.append(exc)

            threads = [
                *(threading.Thread(target=read_repeatedly) for _ in range(4)),
                *(
                    threading.Thread(
                        target=churn_unrelated_file,
                        args=(path,),
                    )
                    for path in noise_paths
                ),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=15)

            assert not any(thread.is_alive() for thread in threads)
            assert errors == []
            with pytest.raises(subprocess.TimeoutExpired):
                process.communicate(timeout=0.5)
            holder.commit()
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr
            assert stdout == "COMMITTED\n"
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            holder.close()

        verifier = sqlite3.connect(journal_path)
        try:
            assert verifier.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        finally:
            verifier.close()
        root, count = journal.chain_head("collector-concurrent-fd")
        assert root != ""
        assert count == 1


def test_journal_counts_retained_wal_plus_next_commit_projection(
    tmp_path: Path,
) -> None:
    path = tmp_path / "physical-retained-wal.sqlite3"
    journal = SQLiteAcceptanceAuthorityJournal(
        path,
        max_database_bytes=1024 * 1024 * 1024,
    )
    for index in range(80):
        journal.append(
            collector_id="collector-retained-wal",
            kind="fault_intent",
            identity=str(index),
            payload={
                "schema_version": "acceptance-fault-intent.v2",
                "index": index,
                "value": "y" * 20_000,
            },
            created_at=START,
        )
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    finally:
        connection.close()
    projected_wal = 32 + page_count * (page_size + 24)
    cap = page_count * page_size + 32_768 + projected_wal + 10_000
    reopened = SQLiteAcceptanceAuthorityJournal(
        path,
        max_database_bytes=cap,
    )
    reader = sqlite3.connect(path)
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM acceptance_entries").fetchone()
    try:
        reopened.append(
            collector_id="collector-retained-wal",
            kind="fault_intent",
            identity="first",
            payload={
                "schema_version": "acceptance-fault-intent.v2",
                "value": "tiny",
            },
            created_at=START,
        )
        with pytest.raises(
            RuntimeError,
            match=r"byte bound|connected.*inode",
        ):
            reopened.append(
                collector_id="collector-retained-wal",
                kind="fault_intent",
                identity="second",
                payload={
                    "schema_version": "acceptance-fault-intent.v2",
                    "value": "tiny",
                },
                created_at=START,
            )
        assert reopened.database_bytes <= cap
    finally:
        reader.close()
    assert reopened.entry(
        "collector-retained-wal",
        kind="fault_intent",
        identity="first",
    ) == {
        "schema_version": "acceptance-fault-intent.v2",
        "value": "tiny",
    }
    assert (
        reopened.entry(
            "collector-retained-wal",
            kind="fault_intent",
            identity="second",
        )
        is None
    )


def test_journal_over_cap_append_rolls_back_without_physical_growth(
    tmp_path: Path,
) -> None:
    path = tmp_path / "physical-rollback.sqlite3"
    journal = SQLiteAcceptanceAuthorityJournal(
        path,
        max_database_bytes=1024 * 1024 * 1024,
    )
    for index in range(80):
        journal.append(
            collector_id="collector-physical-rollback",
            kind="fault_intent",
            identity=str(index),
            payload={
                "schema_version": "acceptance-fault-intent.v2",
                "index": index,
                "value": "y" * 20_000,
            },
            created_at=START,
        )
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    finally:
        connection.close()
    exact_cap = journal.database_bytes
    reopened = SQLiteAcceptanceAuthorityJournal(
        path,
        max_database_bytes=exact_cap,
    )

    with pytest.raises(RuntimeError, match="byte bound"):
        reopened.append(
            collector_id="collector-physical-rollback",
            kind="fault_intent",
            identity="too-large",
            payload={
                "schema_version": "acceptance-fault-intent.v2",
                "value": "y" * 20_000,
            },
            created_at=START,
        )

    assert reopened.database_bytes <= exact_cap
    assert (
        reopened.entry(
            "collector-physical-rollback",
            kind="fault_intent",
            identity="too-large",
        )
        is None
    )


def test_journal_verification_cache_does_not_retain_full_payload_history(
    tmp_path: Path,
) -> None:
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "bounded-cache.sqlite3")
    for index in range(400):
        journal.append(
            collector_id="collector-bounded-cache",
            kind="sample",
            identity=f"sample-{index:05}",
            payload={
                "schema_version": "acceptance-sample-observation.v2",
                "index": index,
                "value": "y" * 60_000,
            },
            created_at=START,
        )

    assert len(journal.entries("collector-bounded-cache", kind="sample")) == 400
    assert journal.verification_cache_bytes <= 2 * 1024 * 1024


def test_journal_streams_verified_entries_without_retaining_decoded_history(
    tmp_path: Path,
) -> None:
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "streamed-cache.sqlite3")
    expected = tuple(
        {
            "schema_version": "acceptance-sample-observation.v2",
            "index": index,
            "value": "y" * 60_000,
        }
        for index in range(40)
    )
    for index, payload in enumerate(expected):
        journal.append(
            collector_id="collector-streamed-cache",
            kind="sample",
            identity=f"sample-{index:05}",
            payload=payload,
            created_at=START,
        )

    streamed = journal.iter_entries(
        "collector-streamed-cache",
        kind="sample",
    )

    assert iter(streamed) is streamed
    assert tuple(streamed) == expected
    assert journal.verification_cache_bytes <= 2 * 1024 * 1024


def test_journal_enforces_aggregate_sample_payload_budget_atomically(
    tmp_path: Path,
    monkeypatch,
) -> None:
    payload = {
        "schema_version": "acceptance-sample-observation.v2",
        "value": "y" * 60_000,
    }
    encoded_bytes = len(authority_module._canonical_json(payload).encode())
    monkeypatch.setattr(
        authority_module,
        "_MAX_SESSION_SAMPLE_BYTES",
        encoded_bytes * 2,
    )
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "sample-payload-budget.sqlite3")
    for index in range(2):
        journal.append(
            collector_id="collector-sample-budget",
            kind="sample",
            identity=f"sample-{index:05}",
            payload=payload,
            created_at=START,
        )

    with pytest.raises(RuntimeError, match="sample byte bound"):
        journal.append(
            collector_id="collector-sample-budget",
            kind="sample",
            identity="sample-00002",
            payload=payload,
            created_at=START,
        )

    assert (
        journal.kind_count(
            "collector-sample-budget",
            kind="sample",
        )
        == 2
    )


def test_72h_sample_budget_covers_realistic_20_camera_observations() -> None:
    realistic_sample_bytes = 13_354 + 4_320 * 16_401

    assert realistic_sample_bytes <= authority_module._MAX_SESSION_SAMPLE_BYTES <= 128 * 1024 * 1024


def test_invalid_finalize_never_persists_a_finalize_request(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "invalid-finalize.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=None,
        monotonic_clock=lambda: 0.0,
    )
    binding = _binding(
        collector_id="collector-never-started",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    candidate = _run(manifest, hours=8).model_copy(
        update={
            "run_id": "collector-never-started",
            "gate": "8h",
            "execution": _execution(manifest.launch),
        }
    )

    with pytest.raises(RuntimeError, match="session is unavailable"):
        authority.finalize(
            {
                "schema_version": "acceptance-collector-finalize.v2",
                **binding,
                "candidate": candidate.model_dump(mode="json"),
            }
        )

    with sqlite3.connect(journal.path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM acceptance_finalize_requests").fetchone()[0]
            == 0
        )


def test_premature_finalize_never_binds_a_candidate_request(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    clock = ControlledClock()
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "premature-finalize.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=None,
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-premature-finalize",
    )
    binding = _binding(
        collector_id="collector-premature-finalize",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": [source.camera_id for source in manifest.sources],
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": _execution(manifest.launch).model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    candidate = _run(manifest, hours=8).model_copy(
        update={
            "run_id": "collector-premature-finalize",
            "gate": "8h",
            "execution": _execution(manifest.launch),
        }
    )

    with pytest.raises(ValueError, match="exact endurance gate"):
        authority.finalize(
            {
                "schema_version": "acceptance-collector-finalize.v2",
                **binding,
                "candidate": candidate.model_dump(mode="json"),
            }
        )

    with sqlite3.connect(journal.path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM acceptance_finalize_requests").fetchone()[0]
            == 0
        )


def test_unsigned_committed_finalize_fails_closed_after_host_reboot_without_mutation(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "finalize-reboot-replay.sqlite3")
    binding = _binding(
        collector_id="collector-finalize-reboot",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    old_authority = AcceptanceAuthority(
        journal=journal,
        adapter=None,
        wall_clock=lambda: START,
        monotonic_clock=lambda: 0.0,
        host_boot_id_provider=lambda: "host-before-reboot",
    )
    old_authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": [source.camera_id for source in manifest.sources],
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": _execution(manifest.launch).model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    record = _run(manifest, hours=8).model_copy(
        update={
            "run_id": "collector-finalize-reboot",
            "gate": "8h",
            "execution": _execution(manifest.launch),
        }
    )
    finalize_request = {
        "schema_version": "acceptance-collector-finalize.v2",
        **binding,
        "candidate": record.model_dump(mode="json"),
    }
    journal.bind_finalize_request(
        collector_id="collector-finalize-reboot",
        payload=finalize_request,
    )
    journal.append(
        collector_id="collector-finalize-reboot",
        kind="finalize",
        identity="final",
        payload=record.model_dump(mode="json"),
        created_at=record.ended_at,
    )
    count = journal.entry_count("collector-finalize-reboot")
    restarted = AcceptanceAuthority(
        journal=SQLiteAcceptanceAuthorityJournal(journal.path),
        adapter=None,
        monotonic_clock=lambda: 0.0,
        host_boot_id_provider=lambda: "host-after-reboot",
    )

    with pytest.raises(RuntimeError, match="attestation authority"):
        restarted.finalize(finalize_request)
    assert journal.entry_count("collector-finalize-reboot") == count


def test_exact_sample_retry_after_seal_is_read_only(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    clock = ControlledClock()
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    adapter = NonDestructiveObservedAdapter(
        _run(manifest, hours=8).model_copy(update={"gate": "8h"}),
        clock,
    )
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "sealed-sample-retry.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=adapter,
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-sealed-sample",
    )
    binding = _binding(
        collector_id="collector-sealed-sample",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": [source.camera_id for source in manifest.sources],
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": _execution(manifest.launch).model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    sample = {
        "schema_version": "acceptance-collector-sample.v2",
        **binding,
        "process_healthy": True,
        "scheduled_monotonic_offset_seconds": 0,
    }
    first = authority.sample(sample)
    journal.append(
        collector_id="collector-sealed-sample",
        kind="finalize",
        identity="final",
        payload={
            "schema_version": "acceptance-run-record.v2",
            "sealed": True,
        },
        created_at=START,
    )
    count = journal.entry_count("collector-sealed-sample")

    assert authority.sample(sample) == first
    assert journal.entry_count("collector-sealed-sample") == count
    clock.offset = 60
    with pytest.raises(RuntimeError, match="sealed"):
        authority.sample(
            {
                **sample,
                "scheduled_monotonic_offset_seconds": 60,
            }
        )
    assert journal.entry_count("collector-sealed-sample") == count


def test_exact_fault_retries_after_seal_are_read_only(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    clock = ControlledClock()
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    adapter = NonDestructiveObservedAdapter(
        _run(manifest, hours=8).model_copy(update={"gate": "8h"}),
        clock,
    )
    execution = _execution(manifest.launch)
    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "sealed-fault-retry.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=adapter,
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-sealed-fault",
    )
    binding = _binding(
        collector_id="collector-sealed-fault",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": [source.camera_id for source in manifest.sources],
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": execution.model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    fault = schedule[0]
    clock.offset = fault.offset_seconds
    prepare_payload = {
        "schema_version": "acceptance-fault-prepare.v2",
        **binding,
        "fault": fault.model_dump(mode="json"),
        "phase": "inject",
        "commanded_monotonic_offset_seconds": fault.offset_seconds,
    }
    prepared = authority.prepare_fault(prepare_payload)
    receipt = AdapterBackedEffectExecutor(adapter).ensure_fault(
        collector_id="collector-sealed-fault",
        launch=manifest.launch,
        execution=execution,
        fault=fault,
        phase="inject",
        command_id=str(prepared["command_id"]),
        commanded_monotonic_offset_seconds=fault.offset_seconds,
    )
    ack_payload = {
        "schema_version": "acceptance-fault-ack.v2",
        **binding,
        "fault_id": fault.fault_id,
        "phase": "inject",
        "command_id": prepared["command_id"],
        "receipt": receipt.model_dump(mode="json"),
    }
    acknowledged = authority.acknowledge_fault(ack_payload)
    journal.append(
        collector_id="collector-sealed-fault",
        kind="finalize",
        identity="final",
        payload={
            "schema_version": "acceptance-run-record.v2",
            "sealed": True,
        },
        created_at=clock.wall(),
    )
    count = journal.entry_count("collector-sealed-fault")

    assert authority.prepare_fault(prepare_payload)["state"] == "COMMITTED"
    assert authority.acknowledge_fault(ack_payload) == acknowledged
    assert journal.entry_count("collector-sealed-fault") == count


def test_authority_timestamps_fault_state_after_adapter_acknowledgement(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    clock = ControlledClock()
    camera_ids = tuple(source.camera_id for source in manifest.sources)
    schedule = canonical_fault_schedule(camera_ids)
    fault = schedule[0]

    class DelayedFaultAdapter:
        identity = AcceptanceAdapterIdentityV2(
            schema_version="acceptance-adapter-identity.v2",
            executable_sha256=manifest.launch.acceptance_observer_sha256,
            policy_sha256=manifest.launch.acceptance_observer_policy_sha256,
        )

        def sample(self, **_kwargs):
            raise AssertionError("sample is not used")

        def observe_fault(self, **kwargs) -> FaultCommandObservationV2:
            clock.offset += 2.5
            execution = kwargs["execution"]
            return FaultCommandObservationV2(
                schema_version="acceptance-fault-command-observation.v2",
                command_id=kwargs["command_id"],
                state=fault.expected_degraded,
                runtime_boot_id=f"{execution.launch_nonce}.runtime-fault",
                api_boot_id="api-fault",
                execution_binding_sha256=execution.binding_sha256,
                observer_sha256=execution.acceptance_observer_sha256,
                observer_policy_sha256=(execution.acceptance_observer_policy_sha256),
            )

        def finalize(self, **_kwargs):
            raise AssertionError("finalize is not used")

    class DelayedFaultExecutor:
        def ensure_fault(self, **kwargs) -> FaultEffectReceiptV2:
            execution = kwargs["execution"]
            command_id = kwargs["command_id"]
            return FaultEffectReceiptV2(
                schema_version="acceptance-fault-effect-receipt.v2",
                command_id=command_id,
                fault_id=fault.fault_id,
                phase="inject",
                target=fault.target,
                execution_binding_sha256=execution.binding_sha256,
                executor_sha256=execution.acceptance_adapter_sha256,
                executor_policy_sha256=(execution.acceptance_adapter_policy_sha256),
                pre_state="online",
                post_state=fault.expected_degraded,
                pre_runtime_boot_id=f"{execution.launch_nonce}.runtime-fault",
                post_runtime_boot_id=f"{execution.launch_nonce}.runtime-fault",
                pre_api_boot_id="api-fault",
                post_api_boot_id="api-fault",
                effect_started_at=clock.wall(),
                effect_completed_at=clock.wall(),
                effect_proof_sha256=hashlib.sha256(command_id.encode()).hexdigest(),
                outcome="ensured",
            )

    journal = SQLiteAcceptanceAuthorityJournal(tmp_path / "fault-latency.sqlite3")
    authority = AcceptanceAuthority(
        journal=journal,
        adapter=DelayedFaultAdapter(),
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-fault",
    )
    binding = _binding(
        collector_id="collector-fault-latency",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    execution = _execution(manifest.launch)
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": camera_ids,
            "workloads": [item.model_dump(mode="json") for item in _workloads(manifest)],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": execution.model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    clock.offset = fault.offset_seconds
    response = _execute_fault(
        authority=authority,
        payload={
            "schema_version": "acceptance-fault-command.v2",
            **binding,
            "fault": fault.model_dump(mode="json"),
            "phase": "inject",
            "commanded_monotonic_offset_seconds": fault.offset_seconds,
        },
        executor=DelayedFaultExecutor(),
        launch=manifest.launch,
        execution=execution,
    )

    expected = START + timedelta(seconds=fault.offset_seconds + 2.5)
    assert datetime.fromisoformat(str(response["observed_at"])) == expected
    row = journal.entries(
        "collector-fault-latency",
        kind="fault_ack",
    )[0]
    assert datetime.fromisoformat(str(row["observed_at"])) == expected
    assert row["commanded_monotonic_offset_seconds"] == fault.offset_seconds


def test_sample_deltas_use_cumulative_floor_and_omit_zero_rate_modules(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    sources = tuple(
        source.model_copy(update={"analytics_hz": {"person": 2.55, "weapon": 0.0}})
        for source in manifest.sources
    )
    manifest = manifest.model_copy(
        update={
            "sources": sources,
            "launch": manifest.launch.model_copy(
                update={"source_profiles_sha256": source_profiles_sha256(sources)}
            ),
        }
    )
    clock = ControlledClock()
    camera_ids = tuple(source.camera_id for source in manifest.sources)
    workloads = tuple(
        CameraAcceptanceWorkloadV2(
            camera_id=source.camera_id,
            source_index=source.source_index,
            source_kind=source.source.kind,
            source_reference=source.source.path,
            codec=source.codec,
            width=source.width,
            height=source.height,
            fps=source.fps,
            bitrate_kbps=source.bitrate_kbps,
            analytics_hz={"person": 2.55, "weapon": 0.0},
        )
        for source in manifest.sources
    )
    schedule = canonical_fault_schedule(camera_ids)
    source_fault_targets = {
        fault.target for fault in schedule if fault.kind in {"camera_loss", "network_pause"}
    }

    class FractionalAdapter:
        identity = AcceptanceAdapterIdentityV2(
            schema_version="acceptance-adapter-identity.v2",
            executable_sha256=manifest.launch.acceptance_observer_sha256,
            policy_sha256=manifest.launch.acceptance_observer_policy_sha256,
        )

        def sample(
            self,
            *,
            collector_id: str,
            launch: LaunchAttestationV2,
            execution: ExecutionBindingV2,
            previous_monotonic_offset_seconds: float,
            scheduled_monotonic_offset_seconds: float,
        ) -> AcceptanceSampleObservationV2:
            default_delta = 0 if clock.offset == 0 else 153
            return AcceptanceSampleObservationV2(
                schema_version="acceptance-sample-observation.v2",
                observed_at=clock.wall(),
                observed_records=(0 if clock.offset == 0 else default_delta * 18 + 280),
                collector_id=collector_id,
                launch_attestation_sha256=launch.attestation_sha256,
                execution_binding_sha256=execution.binding_sha256,
                observer_sha256=execution.acceptance_observer_sha256,
                observer_policy_sha256=(execution.acceptance_observer_policy_sha256),
                cameras=tuple(
                    CameraAcceptanceObservationV2(
                        camera_id=source.camera_id,
                        source_index=source.source_index,
                        negotiated_codec=source.codec,
                        negotiated_width=source.width,
                        negotiated_height=source.height,
                        negotiated_fps=source.fps,
                        negotiated_bitrate_kbps=source.bitrate_kbps,
                        queue_name="analytics",
                        state="online",
                        counters=(
                            AnalyticCounterObservationV2(
                                module="person",
                                scheduled_samples=(
                                    140
                                    if clock.offset and source.camera_id in source_fault_targets
                                    else default_delta
                                ),
                                processed_samples=(
                                    140
                                    if clock.offset and source.camera_id in source_fault_targets
                                    else default_delta
                                ),
                                dropped_samples=0,
                            ),
                        ),
                        queue_observation_cadence_seconds=1,
                        queue_age_runs=(
                            QueueAgeRunV2(
                                age_seconds=0.1,
                                samples=(
                                    1
                                    if scheduled_monotonic_offset_seconds == 0
                                    else round(
                                        scheduled_monotonic_offset_seconds
                                        - previous_monotonic_offset_seconds
                                    )
                                ),
                            ),
                        ),
                        runtime_boot_id=f"{execution.launch_nonce}.runtime-one",
                        api_boot_id="api-one",
                    )
                    for source in manifest.sources
                ),
                health_intervals=tuple(
                    CameraHealthIntervalObservationV2(
                        camera_id=camera_id,
                        started_monotonic_offset_seconds=(previous_monotonic_offset_seconds),
                        ended_monotonic_offset_seconds=(scheduled_monotonic_offset_seconds),
                        state="online",
                    )
                    for camera_id in camera_ids
                    if scheduled_monotonic_offset_seconds > 0
                ),
                resource=ResourceSampleV2(
                    sampled_at=clock.wall(),
                    interval_started_at=(
                        None
                        if scheduled_monotonic_offset_seconds == 0
                        else START + timedelta(seconds=previous_monotonic_offset_seconds)
                    ),
                    observation_cadence_seconds=1,
                    observation_count=(
                        1
                        if scheduled_monotonic_offset_seconds == 0
                        else round(
                            scheduled_monotonic_offset_seconds - previous_monotonic_offset_seconds
                        )
                    ),
                    gpu_percent=10,
                    gpu_percent_high_water=10,
                    vram_percent=20,
                    vram_percent_high_water=20,
                    disk_bytes=100,
                    disk_bytes_high_water=100,
                    disk_limit_bytes=1000,
                ),
            )

        def observe_fault(
            self,
            *,
            fault: ScheduledFaultV2,
            phase: str,
            execution: ExecutionBindingV2,
            command_id: str,
            **_kwargs,
        ) -> FaultCommandObservationV2:
            return FaultCommandObservationV2(
                schema_version="acceptance-fault-command-observation.v2",
                command_id=command_id,
                state=(fault.expected_degraded if phase == "inject" else fault.expected_recovery),
                runtime_boot_id=f"{execution.launch_nonce}.runtime-one",
                api_boot_id="api-one",
                execution_binding_sha256=execution.binding_sha256,
                observer_sha256=execution.acceptance_observer_sha256,
                observer_policy_sha256=(execution.acceptance_observer_policy_sha256),
            )

        def finalize(self, **_kwargs):
            raise AssertionError("finalize is not used")

    class FractionalExecutor:
        def ensure_fault(self, **kwargs) -> FaultEffectReceiptV2:
            execution = kwargs["execution"]
            fault = kwargs["fault"]
            phase = kwargs["phase"]
            command_id = kwargs["command_id"]
            return FaultEffectReceiptV2(
                schema_version="acceptance-fault-effect-receipt.v2",
                command_id=command_id,
                fault_id=fault.fault_id,
                phase=phase,
                target=fault.target,
                execution_binding_sha256=execution.binding_sha256,
                executor_sha256=execution.acceptance_adapter_sha256,
                executor_policy_sha256=(execution.acceptance_adapter_policy_sha256),
                pre_state="online",
                post_state=(
                    fault.expected_degraded if phase == "inject" else fault.expected_recovery
                ),
                pre_runtime_boot_id=f"{execution.launch_nonce}.runtime-one",
                post_runtime_boot_id=f"{execution.launch_nonce}.runtime-one",
                pre_api_boot_id="api-one",
                post_api_boot_id="api-one",
                effect_started_at=clock.wall(),
                effect_completed_at=clock.wall(),
                effect_proof_sha256=hashlib.sha256(command_id.encode()).hexdigest(),
                outcome="ensured",
            )

    authority = AcceptanceAuthority(
        journal=SQLiteAcceptanceAuthorityJournal(tmp_path / "fractional.sqlite3"),
        adapter=FractionalAdapter(),
        wall_clock=clock.wall,
        monotonic_clock=clock.monotonic,
        host_boot_id_provider=lambda: "host-boot",
    )
    binding = _binding(
        collector_id="collector-fractional",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    execution = _execution(manifest.launch)
    authority.start(
        {
            "schema_version": "acceptance-collector-start.v2",
            **binding,
            "sample_interval_seconds": 60,
            "camera_ids": camera_ids,
            "workloads": [item.model_dump(mode="json") for item in workloads],
            "launch": manifest.launch.model_dump(mode="json"),
            "execution": execution.model_dump(mode="json"),
            "fault_schedule": [item.model_dump(mode="json") for item in schedule],
        }
    )
    sample_payload = {
        "schema_version": "acceptance-collector-sample.v2",
        **binding,
        "process_healthy": True,
        "scheduled_monotonic_offset_seconds": 0,
    }
    assert authority.sample(sample_payload)["observed_records"] == 0
    divergent = authority.journal.entries(
        "collector-fractional",
        kind="sample",
    )[0]
    divergent["cameras"][1]["runtime_boot_id"] = "runtime-other"
    with pytest.raises(ValueError, match="shared boot identity"):
        AcceptanceSampleObservationV2.model_validate(divergent)
    for fault in schedule:
        if fault.kind not in {"camera_loss", "network_pause"}:
            continue
        for phase, boundary in (
            ("inject", fault.offset_seconds),
            ("recover", fault.offset_seconds + fault.duration_seconds),
        ):
            clock.offset = boundary
            _execute_fault(
                authority=authority,
                payload={
                    "schema_version": "acceptance-fault-command.v2",
                    **binding,
                    "fault": fault.model_dump(mode="json"),
                    "phase": phase,
                    "commanded_monotonic_offset_seconds": boundary,
                },
                executor=FractionalExecutor(),
                launch=manifest.launch,
                execution=execution,
            )
    clock.offset = 60
    sample_payload["scheduled_monotonic_offset_seconds"] = 60
    assert authority.sample(sample_payload)["observed_records"] == 3_034
