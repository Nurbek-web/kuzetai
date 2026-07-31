from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import sys
import threading
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import scripts.pilot.acceptance_report as acceptance_report_module
import scripts.pilot.replay_20 as replay_module
from protector.pilot.acceptance import (
    AcceptanceManifestV2,
    AcceptanceReportV2,
    AcceptanceRunRecordV2,
    BoundaryTraceV2,
    CapacityTraceV2,
    ConditionalGateAttestationV2,
    ExceptionRecordV2,
    ExecutionBindingV2,
    FaultRecordV2,
    FaultStateTraceV2,
    LifecycleTraceV2,
    LocalFixtureSourceV2,
    ModuleDispositionV2,
    QueueStateTraceV2,
    ResourceSampleV2,
    SourceManifestV2,
    TargetSecretSourceV2,
    canonical_fault_schedule_sha256,
    evaluate_acceptance,
    load_acceptance_manifest,
    load_conditional_gate_decisions,
    percentile_nearest_rank,
    render_acceptance_html,
    source_profiles_sha256,
    verify_signed_report,
)
from protector.pilot.acceptance_authority import (
    AcceptanceSampleResponseV2,
    CameraAcceptanceWorkloadV2,
    FaultCommandObservationV2,
    FaultEffectReceiptV2,
    build_authority_trust_context,
)
from protector.pilot.acceptance_proof import (
    AcceptanceJournalProofEntryV2,
    AcceptanceJournalProofHeaderV2,
    AcceptanceJournalProofTrailerV2,
    JournalKindCountsV2,
    TargetRunAttestationV2,
    canonical_proof_line,
    journal_entry_sha256,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.config import (
    CameraFeed,
    EvidenceRetention,
    KazakhstanStorage,
    QueueLimits,
    ReadyToStart,
    Resolution,
    SecretReference,
    SiteConfig,
)
from protector.pilot.gates import (
    CapacityReportV1,
    CommercialRightsRecordV1,
    ConditionalModelGateResultV1,
    MeasuredCapacityReportV1,
    ModelArtifactV1,
    ShadowStageReportV1,
    TargetSiteReportV1,
    site_config_sha256,
)
from protector.pilot.runtime.deepstream import DEEPSTREAM_IMAGE, RuntimeModelManifestV1
from protector.pilot.trusted_artifacts import (
    ed25519_public_key_spki_sha256,
)
from scripts.pilot.acceptance_report import main as acceptance_report_main
from scripts.pilot.replay_20 import (
    AuthenticatedTargetCollector,
    CollectingBoundary,
    FaultFailurePlan,
    PortableFaultAdapter,
    SQLiteTargetCollectorJournal,
    TargetCampaignLock,
    TargetCollector,
    canonical_fault_schedule,
    run_portable,
    run_target,
)
from tests.pilot.acceptance_trust_helpers import (
    authority_trust_context,
    verified_trust_bundle,
)

UTC = timezone.utc
START = datetime(2026, 7, 30, tzinfo=UTC)
HEX = "a" * 64
ADAPTER_PAYLOAD = b"fixture-acceptance-adapter"
ADAPTER_POLICY_PAYLOAD = b'{"schema_version":"acceptance-adapter-policy.v1"}'
ADAPTER_SHA256 = hashlib.sha256(ADAPTER_PAYLOAD).hexdigest()
ADAPTER_POLICY_SHA256 = hashlib.sha256(ADAPTER_POLICY_PAYLOAD).hexdigest()
OBSERVER_PAYLOAD = b"fixture-independent-acceptance-observer"
OBSERVER_POLICY_PAYLOAD = b'{"schema_version":"acceptance-observer-policy.v1"}'
OBSERVER_SHA256 = hashlib.sha256(OBSERVER_PAYLOAD).hexdigest()
OBSERVER_POLICY_SHA256 = hashlib.sha256(OBSERVER_POLICY_PAYLOAD).hexdigest()


def _fixture(tmp_path: Path, index: int) -> SourceManifestV2:
    path = tmp_path / f"camera-{index:02}.bin"
    path.write_bytes(f"lawful fixture {index}".encode())
    return SourceManifestV2(
        camera_id=f"camera-{index:02}",
        source_index=index,
        source={"kind": "local_fixture", "path": str(path)},
        codec="h264",
        width=1920,
        height=1080,
        fps=25.0,
        bitrate_kbps=4096,
        analytics_hz={"person": 5.0, "weapon": 1.0},
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        provenance_reference=f"lawful/camera-{index:02}.json",
    )


def _manifest(tmp_path: Path) -> AcceptanceManifestV2:
    sources = tuple(_fixture(tmp_path, index) for index in range(20))
    site = SiteConfig(
        ready_to_start=ReadyToStart(
            feeds=tuple(
                CameraFeed(
                    camera_id=source.camera_id,
                    source_index=source.source_index,
                    rtsp_url=SecretReference(
                        environment=f"PILOT_CAMERA_{source.source_index:02}_RTSP"
                    ),
                    codec=source.codec,
                    resolution=Resolution(width=source.width, height=source.height),
                    fps=source.fps,
                    bitrate_kbps=source.bitrate_kbps,
                    analytics_hz=source.analytics_hz,
                )
                for source in sources
            ),
            ntp_source="reviewed-ntp",
            camera_map="reviewed-camera-map",
            site_access="approved",
            compute="nvidia-l4",
            notification_channel="disabled",
            model_rights_decisions="reviewed-rights",
        ),
        storage=KazakhstanStorage(
            country_code="KZ",
            endpoint="https://objects.example.test",
            bucket="pilot-evidence",
            evidence_prefix="pilot-evidence/school-01",
            retention=EvidenceRetention(
                continuous_video_owner="customer_nvr",
                continuous_video_storage_enabled=False,
                encoded_ring_buffer_seconds=15,
                evidence_retention_days=30,
                metadata_retention_days=90,
            ),
        ),
        queues=QueueLimits(decode=8, analytics=64, verifier=4, events=64),
    )
    artifact = ModelArtifactV1(
        schema_version="model-artifact.v1",
        artifact_id="person-primary-v1",
        sha256=HEX,
        source="s3://reviewed-model-registry/person-primary-v1.onnx",
        commercial_rights=CommercialRightsRecordV1(
            schema_version="commercial-rights.v1",
            record_id="rights-person-v1",
            terms_reference="contracts/person-primary-v1.pdf",
            commercial_use_approved=True,
        ),
        class_list=("person",),
        preprocessing="letterbox-rgb-640x640",
        analytic="person",
    )
    shared_report = {
        "artifact_id": artifact.artifact_id,
        "passed": True,
        "report_reference": "reports/person-primary-v1.json",
        "report_sha256": "b" * 64,
        "signed_by": "pilot-qa",
        "signed_at": START,
    }
    runtime = RuntimeModelManifestV1(
        schema_version="deepstream-runtime-manifest.v1",
        site_id="school-01",
        artifact=artifact,
        registry_entry_sha256=HEX,
        frozen_workload_sha256=HEX,
        expected_workload_sha256=HEX,
        engine_sha256=HEX,
        precision="fp16",
        target_compute_capability="8.9",
        tensorrt_version="10.16.0.72",
        target_site_report=TargetSiteReportV1(
            schema_version="target-site-report.v1",
            site_id="school-01",
            **shared_report,
        ),
        capacity_report=CapacityReportV1(
            schema_version="capacity-report.v1",
            stream_count=20,
            **shared_report,
        ),
        shadow_stage_report=ShadowStageReportV1(
            schema_version="shadow-stage-report.v1",
            **shared_report,
        ),
    )
    capacity = MeasuredCapacityReportV1(
        schema_version="measured-capacity-report.v1",
        site_id="school-01",
        artifact_id=artifact.artifact_id,
        artifact_sha256=HEX,
        registry_entry_sha256=HEX,
        engine_sha256=HEX,
        precision="fp16",
        target_gpu_architecture="NVIDIA L4 (Ada)",
        target_compute_capability="8.9",
        tensorrt_version="10.16.0.72",
        nvidia_driver_version="575.57.08",
        cuda_driver_version="13.0",
        cuda_runtime_version="13.0",
        nvidia_container_toolkit_version="1.17.8",
        gpu_devices=(
            {
                "uuid": "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "product_name": "NVIDIA L4",
                "pci_bus_id": "0000:01:00.0",
                "total_vram_bytes": 24_000_000_000,
                "compute_capability": "8.9",
                "mig_mode": "disabled",
            },
        ),
        site_config_sha256=site_config_sha256(site),
        runtime_manifest_file_sha256=hashlib.sha256(
            yaml.safe_dump(
                runtime.model_dump(mode="json"),
                sort_keys=True,
            ).encode()
        ).hexdigest(),
        frozen_workload_sha256=HEX,
        expected_workload_sha256=HEX,
        runtime_image_id_sha256=HEX,
        runtime_image_config_sha256=HEX,
        runtime_code_sha256=HEX,
        mount_contract_sha256=HEX,
        stream_count=20,
        effective_throughput_hz=125.0,
        required_throughput_hz=100.0,
        scheduled_drop_fraction=0.005,
        queue_age_p95_seconds=0.5,
        queue_age_p99_seconds=1.0,
        gpu_utilization_max=0.70,
        vram_utilization_max=0.75,
        passed=True,
        report_reference="reports/capacity/person-primary-v1.json",
        report_sha256="c" * 64,
        signed_by="capacity-qa",
        signed_at=START,
    )
    reviewed = (
        (tmp_path / "site.yaml", site),
        (tmp_path / "runtime.yaml", runtime),
        (tmp_path / "capacity.yaml", capacity),
    )
    for path, model in reviewed:
        path.write_text(yaml.safe_dump(model.model_dump(mode="json"), sort_keys=True))
    site_path, runtime_path, capacity_path = (item[0] for item in reviewed)
    capacity_private_key = tmp_path / "capacity-authority-private.pem"
    capacity_public_key = tmp_path / "capacity-authority-public.pem"
    capacity_signature = tmp_path / "capacity.sig"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(capacity_private_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(capacity_private_key),
            "-pubout",
            "-out",
            str(capacity_public_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(capacity_private_key),
            "-in",
            str(capacity_path),
            "-out",
            str(capacity_signature),
        ],
        check=True,
        capture_output=True,
    )
    image_sha256 = DEEPSTREAM_IMAGE.rsplit("@sha256:", maxsplit=1)[1]
    run_private_key = tmp_path / "target-run-private.pem"
    run_public_key = tmp_path / "target-run-authority.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(run_private_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(run_private_key),
            "-pubout",
            "-out",
            str(run_public_key),
        ],
        check=True,
        capture_output=True,
    )
    return AcceptanceManifestV2(
        schema_version="acceptance-manifest.v2",
        site_id="school-01",
        sources=sources,
        modules=(
            ModuleDispositionV2(module="person", mode="pass/operator", reason="core"),
            ModuleDispositionV2(module="weapon", mode="shadow", reason="site matrix pending"),
            ModuleDispositionV2(module="fire_smoke", mode="disabled", reason="rights pending"),
            ModuleDispositionV2(module="fight", mode="shadow", reason="shadow only"),
        ),
        launch={
            "schema_version": "acceptance-launch-attestation.v2",
            "site_id": "school-01",
            "site_config_file_sha256": hashlib.sha256(site_path.read_bytes()).hexdigest(),
            "site_config_sha256": site_config_sha256(site),
            "runtime_manifest_file_sha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
            "measured_capacity_file_sha256": hashlib.sha256(capacity_path.read_bytes()).hexdigest(),
            "capacity_signature_sha256": hashlib.sha256(
                capacity_signature.read_bytes()
            ).hexdigest(),
            "capacity_trust_key_spki_sha256": ed25519_public_key_spki_sha256(
                capacity_public_key.read_bytes()
            ),
            "artifact_id": "person-primary-v1",
            "artifact_sha256": HEX,
            "registry_entry_sha256": HEX,
            "frozen_workload_sha256": HEX,
            "expected_workload_sha256": HEX,
            "engine_sha256": HEX,
            "image_sha256": image_sha256,
            "runtime_image_id_sha256": HEX,
            "runtime_image_config_sha256": HEX,
            "runtime_code_sha256": HEX,
            "mount_contract_sha256": HEX,
            "control_network": "kuzet-control",
            "camera_network": "kuzet-camera",
            "expected_control_network_id": "4" * 64,
            "expected_control_network_config_sha256": "5" * 64,
            "expected_camera_network_id": "6" * 64,
            "expected_camera_network_config_sha256": "7" * 64,
            "gpu_device_ids": ("GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",),
            "gpu_product_name": "NVIDIA L4",
            "gpu_pci_bus_id": "0000:01:00.0",
            "gpu_total_vram_bytes": 24_000_000_000,
            "gpu_compute_capability": "8.9",
            "gpu_mig_mode": "disabled",
            "gpu_inventory_sha256": capacity.gpu_inventory_sha256,
            "nvidia_driver_version": capacity.nvidia_driver_version,
            "cuda_driver_version": capacity.cuda_driver_version,
            "cuda_runtime_version": capacity.cuda_runtime_version,
            "nvidia_container_toolkit_version": (capacity.nvidia_container_toolkit_version),
            "acceptance_adapter_sha256": ADAPTER_SHA256,
            "acceptance_adapter_policy_sha256": ADAPTER_POLICY_SHA256,
            "acceptance_observer_sha256": OBSERVER_SHA256,
            "acceptance_observer_policy_sha256": OBSERVER_POLICY_SHA256,
            "runtime_api_host": "api",
            "runtime_api_port": 8000,
            "controller_api_host": "127.0.0.1",
            "controller_api_port": 8765,
            "run_authority_public_key_spki_sha256": (
                ed25519_public_key_spki_sha256(run_public_key.read_bytes())
            ),
            "source_profiles_sha256": source_profiles_sha256(sources),
            "required_throughput_hz": 100.0,
            "measured_effective_throughput_hz": 125.0,
            "stream_count": 20,
        },
        config_sha256=site_config_sha256(site),
        model_sha256=HEX,
        engine_sha256=HEX,
        image_sha256=image_sha256,
    )


def _run(manifest: AcceptanceManifestV2, *, hours: int = 72) -> AcceptanceRunRecordV2:
    end = START + timedelta(hours=hours)
    launch_nonce = "1" * 32
    duration_seconds = hours * 3600
    resources = tuple(
        ResourceSampleV2(
            sampled_at=START + timedelta(seconds=offset),
            interval_started_at=(None if offset == 0 else START + timedelta(seconds=offset - 60)),
            observation_cadence_seconds=1,
            observation_count=1 if offset == 0 else 60,
            gpu_percent=70 if offset == hours * 3600 else 60,
            gpu_percent_high_water=(70 if offset == hours * 3600 else 60),
            vram_percent=75 if offset == hours * 3600 else 70,
            vram_percent_high_water=(75 if offset == hours * 3600 else 70),
            disk_bytes=1000 + min(offset // 60, 200),
            disk_bytes_high_water=1000 + min(offset // 60, 200),
            disk_limit_bytes=1_000_000,
        )
        for offset in range(0, hours * 3600 + 1, 60)
    )
    cameras = []
    health_spans: list[dict[str, object]] = []
    work_spans: list[dict[str, object]] = []
    queue_coverage: list[dict[str, object]] = []

    def cadence_for(seconds: float) -> int:
        return next(
            cadence for cadence in range(60, 0, -1) if seconds / cadence == round(seconds / cadence)
        )

    for index in range(20):
        camera_id = f"camera-{index:02}"
        outage = (10.0, 15.0) if index == 0 else (30.0, 35.0) if index == 2 else None
        intervals = (
            ((0.0, float(duration_seconds), "online"),)
            if outage is None
            else (
                (0.0, outage[0], "online"),
                (outage[0], outage[1], "source_outage"),
                (outage[1], float(duration_seconds), "online"),
            )
        )
        for span_start, span_end, state in intervals:
            cadence = cadence_for(span_end - span_start)
            health_spans.append(
                {
                    "camera_id": camera_id,
                    "started_at": START + timedelta(seconds=span_start),
                    "ended_at": START + timedelta(seconds=span_end),
                    "state": state,
                    "cadence_seconds": cadence,
                    "observed_samples": round((span_end - span_start) / cadence) + 1,
                }
            )
        outage_seconds = 0 if outage is None else outage[1] - outage[0]
        eligible_seconds = duration_seconds - outage_seconds
        scheduled_by_module = {
            module: int(rate * eligible_seconds)
            for module, rate in manifest.sources[index].analytics_hz.items()
            if rate > 0
        }
        for module, scheduled in scheduled_by_module.items():
            dropped = 1 if module == "person" else 0
            work_spans.append(
                {
                    "camera_id": camera_id,
                    "module": module,
                    "started_at": START,
                    "ended_at": end,
                    "cadence_seconds": 60,
                    "observed_samples": duration_seconds // 60 + 1,
                    "scheduled_samples": scheduled,
                    "processed_samples": scheduled - dropped,
                    "dropped_samples": dropped,
                }
            )
        scheduled_total = sum(scheduled_by_module.values())
        dropped_total = 1
        queue_coverage.append(
            {
                "camera_id": camera_id,
                "queue_name": "analytics",
                "started_at": START,
                "ended_at": end,
                "cadence_seconds": 60,
                "runs": (
                    {
                        "age_seconds": 0.2,
                        "samples": duration_seconds // 60 + 1,
                    },
                ),
            }
        )
        cameras.append(
            {
                "camera_id": camera_id,
                "scheduled_samples": scheduled_total,
                "processed_samples": scheduled_total - dropped_total,
                "dropped_samples": dropped_total,
                "availability_seconds": eligible_seconds,
                "source_outage_seconds": outage_seconds,
                "queue_age_seconds": [0.2],
                "reconnect_seconds": [10.0],
                "observed_records": scheduled_total - dropped_total,
                "last_health_at": end.isoformat(),
                "runtime_boot_id": f"{launch_nonce}.runtime-boot-2",
                "api_boot_id": "api-boot-2",
            }
        )
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    faults = tuple(
        FaultRecordV2(
            fault_id=fault.fault_id,
            kind=fault.kind,
            target=fault.target,
            injected_at=START + timedelta(seconds=fault.offset_seconds),
            monotonic_offset_seconds=fault.offset_seconds,
            duration_seconds=fault.duration_seconds,
            expected_degraded=fault.expected_degraded,
            expected_recovery=fault.expected_recovery,
            observed_degraded=fault.expected_degraded,
            observed_recovery=fault.expected_recovery,
            recovered_at=START + timedelta(seconds=fault.offset_seconds + fault.duration_seconds),
        )
        for fault in schedule
    )
    fault_traces: tuple[FaultStateTraceV2, ...] = ()
    for index, fault in enumerate(faults):
        degraded_runtime = (
            f"{launch_nonce}.runtime-boot-1" if index <= 3 else f"{launch_nonce}.runtime-boot-2"
        )
        recovered_runtime = f"{launch_nonce}.runtime-boot-2" if index == 3 else degraded_runtime
        degraded_api = "api-boot-1" if index <= 4 else "api-boot-2"
        recovered_api = "api-boot-2" if index == 4 else degraded_api
        fault_traces = (
            *fault_traces,
            FaultStateTraceV2(
                fault_id=fault.fault_id,
                kind=fault.kind,
                phase="degraded",
                observed_at=fault.injected_at,
                component=fault.target,
                state=fault.observed_degraded or "missing",
                runtime_boot_id=degraded_runtime,
                api_boot_id=degraded_api,
                command_id=f"command-{fault.fault_id}-inject",
                commanded_monotonic_offset_seconds=fault.monotonic_offset_seconds,
            ),
            FaultStateTraceV2(
                fault_id=fault.fault_id,
                kind=fault.kind,
                phase="recovered",
                observed_at=fault.recovered_at or fault.injected_at,
                component=fault.target,
                state=fault.observed_recovery or "missing",
                runtime_boot_id=recovered_runtime,
                api_boot_id=recovered_api,
                command_id=f"command-{fault.fault_id}-recover",
                commanded_monotonic_offset_seconds=(
                    fault.monotonic_offset_seconds + fault.duration_seconds
                ),
            ),
        )
    lifecycle = (
        LifecycleTraceV2(
            trace_id="event-candidate",
            kind="event",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=1),
            state="candidate",
            actor_type="system",
        ),
        LifecycleTraceV2(
            trace_id="event-persisted",
            kind="event",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=1.2),
            state="persisted",
            actor_type="system",
        ),
        LifecycleTraceV2(
            trace_id="evidence-ready",
            kind="evidence",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=1.5),
            state="ready",
            actor_type="system",
        ),
        LifecycleTraceV2(
            trace_id="review-confirmed",
            kind="review",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=2),
            state="confirmed",
            actor_type="human",
        ),
        LifecycleTraceV2(
            trace_id="audit-confirmed",
            kind="audit",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=2.1),
            state="confirmed",
            actor_type="system",
        ),
        LifecycleTraceV2(
            trace_id="notification-delivered",
            kind="notification",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=3),
            state="delivered",
            actor_type="system",
        ),
    )
    return AcceptanceRunRecordV2(
        schema_version="acceptance-run-record.v2",
        run_id="run-001",
        environment="target",
        gate="72h",
        site_id=manifest.site_id,
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        execution=ExecutionBindingV2(
            schema_version="acceptance-execution-binding.v2",
            launch_attestation_sha256=manifest.launch.attestation_sha256,
            launch_nonce=launch_nonce,
            container_id="2" * 64,
            container_config_sha256="3" * 64,
            runtime_image_id_sha256=manifest.launch.runtime_image_id_sha256,
            acceptance_adapter_sha256=(manifest.launch.acceptance_adapter_sha256),
            acceptance_adapter_policy_sha256=(manifest.launch.acceptance_adapter_policy_sha256),
            acceptance_observer_sha256=(manifest.launch.acceptance_observer_sha256),
            acceptance_observer_policy_sha256=(manifest.launch.acceptance_observer_policy_sha256),
            control_network_id="4" * 64,
            control_network_config_sha256="5" * 64,
            camera_network_id="6" * 64,
            camera_network_config_sha256="7" * 64,
            observed_gpu_inventory_sha256=(manifest.launch.gpu_inventory_sha256),
        ),
        started_at=START,
        ended_at=end,
        cameras=tuple(cameras),
        health_spans=tuple(health_spans),
        work_spans=tuple(work_spans),
        queue_coverage=tuple(queue_coverage),
        candidate_to_event_seconds=(0.2,),
        first_preview_seconds=(0.5,),
        gpu_percent=tuple(item.gpu_percent for item in resources),
        vram_percent=tuple(item.vram_percent for item in resources),
        disk_bytes=tuple(item.disk_bytes for item in resources),
        disk_limit_bytes=1_000_000,
        disk_bounded=True,
        faults=faults,
        fault_traces=fault_traces,
        exceptions=(),
        boundaries=tuple(
            BoundaryTraceV2(
                component=component,
                observed_at=end,
                consumed_records=20,
                succeeded=True,
                detail_code="observed",
            )
            for component in ("event_engine", "repository", "evidence", "metrics")
        ),
        lifecycle=lifecycle,
        resources=resources,
        queue_traces=tuple(
            QueueStateTraceV2(
                queue=queue,
                observed_at=end,
                depth=0,
                capacity=64,
                state="ready",
                runtime_boot_id=f"{launch_nonce}.runtime-boot-2",
                api_boot_id="api-boot-2",
            )
            for queue in ("decode", "analytics", "verifier", "events", "evidence")
        ),
        capacity=CapacityTraceV2(
            observed_at=end,
            manifest_sha256=manifest.manifest_sha256,
            config_sha256=manifest.config_sha256,
            model_sha256=manifest.model_sha256,
            engine_sha256=manifest.engine_sha256,
            image_sha256=manifest.image_sha256,
            effective_throughput_hz=125.0,
            required_throughput_hz=100.0,
            stream_count=20,
        ),
        runtime_boot_ids=(
            f"{launch_nonce}.runtime-boot-1",
            f"{launch_nonce}.runtime-boot-2",
        ),
        api_boot_ids=("api-boot-1", "api-boot-2"),
        events_evidence_complete=True,
        reviews_audited=True,
        notifications_after_confirmation=True,
        cross_camera_leakage=False,
        queues_drained=True,
        consumers_connected=True,
        measured_effective_throughput_hz=125.0,
        required_throughput_hz=100.0,
        config_sha256=manifest.config_sha256,
        model_sha256=manifest.model_sha256,
        engine_sha256=manifest.engine_sha256,
        image_sha256=manifest.image_sha256,
    )


def test_manifest_requires_exact_unique_twenty_and_hashes_local_files(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=True))
    loaded = load_acceptance_manifest(path)
    assert loaded.manifest_sha256 == manifest.manifest_sha256

    (tmp_path / "camera-00.bin").write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash"):
        load_acceptance_manifest(path)
    with pytest.raises(ValueError, match="20"):
        AcceptanceManifestV2(**{**manifest.model_dump(), "sources": manifest.sources[:-1]})


def test_manifest_rejects_symlink_duplicate_indices_and_operator_heavy_modules(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    link = tmp_path / "link.bin"
    link.symlink_to(tmp_path / "camera-00.bin")
    bad_source = manifest.sources[0].model_copy(
        update={"source": LocalFixtureSourceV2(kind="local_fixture", path=str(link))}
    )
    path = tmp_path / "manifest.yaml"
    payload = manifest.model_dump(mode="json")
    payload["sources"][0] = bad_source.model_dump(mode="json")
    payload["launch"]["source_profiles_sha256"] = source_profiles_sha256(
        (bad_source, *manifest.sources[1:])
    )
    path.write_text(yaml.safe_dump(payload))
    with pytest.raises(ValueError, match="symlink"):
        load_acceptance_manifest(path)
    with pytest.raises(ValueError, match="source indices"):
        AcceptanceManifestV2(
            **{
                **manifest.model_dump(),
                "sources": (
                    manifest.sources[0],
                    manifest.sources[1].model_copy(update={"source_index": 0}),
                    *manifest.sources[2:],
                ),
            }
        )
    with pytest.raises(ValueError, match="operator"):
        AcceptanceManifestV2(
            **{
                **manifest.model_dump(),
                "modules": (
                    ModuleDispositionV2(module="xclip", mode="pass/operator", reason="invalid"),
                ),
            }
        )
    with pytest.raises(ValueError, match="operator"):
        AcceptanceManifestV2(
            **{
                **manifest.model_dump(),
                "modules": (
                    ModuleDispositionV2(module="weapon", mode="pass/operator", reason="ungated"),
                ),
            }
        )


def test_manifest_requires_disposition_for_every_positive_scheduled_analytic(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    payload = manifest.model_dump(mode="json")
    payload["modules"] = [item for item in payload["modules"] if item["module"] != "weapon"]
    with pytest.raises(ValueError, match="scheduled analytic"):
        AcceptanceManifestV2.model_validate(payload)

    payload = manifest.model_dump(mode="json")
    payload["modules"].append(
        {
            "module": "line_crossing",
            "mode": "disabled",
            "reason": "known but not scheduled",
        }
    )
    AcceptanceManifestV2.model_validate(payload)


def test_operator_disposition_requires_scheduled_and_observed_module_work(
    tmp_path: Path,
) -> None:
    payload = _manifest(tmp_path).model_dump(mode="json")
    payload["modules"].append(
        {
            "module": "line_crossing",
            "mode": "pass/operator",
            "reason": "operator candidate requires observed work",
        }
    )
    with pytest.raises(ValueError, match="positively scheduled"):
        AcceptanceManifestV2.model_validate_json(json.dumps(payload))

    payload["sources"][0]["analytics_hz"]["line_crossing"] = 1.0
    payload["launch"]["source_profiles_sha256"] = source_profiles_sha256(
        tuple(SourceManifestV2.model_validate(source) for source in payload["sources"])
    )
    manifest = AcceptanceManifestV2.model_validate_json(json.dumps(payload))
    complete = _run(manifest)
    assert evaluate_acceptance(manifest, complete).modules[-1].mode == "pass/operator"

    serialized = complete.model_dump(mode="json")
    omitted = next(
        span
        for span in serialized["work_spans"]
        if span["camera_id"] == "camera-00" and span["module"] == "line_crossing"
    )
    serialized["work_spans"].remove(omitted)
    camera = next(item for item in serialized["cameras"] if item["camera_id"] == "camera-00")
    camera["scheduled_samples"] -= omitted["scheduled_samples"]
    camera["processed_samples"] -= omitted["processed_samples"]
    camera["dropped_samples"] -= omitted["dropped_samples"]
    camera["observed_records"] -= omitted["processed_samples"]
    incomplete = AcceptanceRunRecordV2.model_validate_json(json.dumps(serialized))
    report = evaluate_acceptance(manifest, incomplete)
    assert report.passed is False
    assert any("work accounting coverage" in reason for reason in report.reasons)
    assert report.modules[-1].mode == "shadow"


def test_manifest_secret_scan_rejects_embedded_uri_scheme_bypass(
    tmp_path: Path,
) -> None:
    payload = _manifest(tmp_path).model_dump(mode="json")
    payload["modules"][0]["reason"] = "opaque-prefix(evidence:https://objects.kz/customer/item)"
    with pytest.raises(ValueError, match="secret-like|URI"):
        AcceptanceManifestV2.model_validate(payload)


@pytest.mark.parametrize(
    "opaque_reference",
    (
        "data:application/json;base64,e30=",
        "mailto:operator@example.test",
        "urn:kuzet:event:123",
        "s3:customer-bucket/evidence",
    ),
)
def test_signed_models_reject_opaque_uri_tokens_but_allow_prose_colons(
    tmp_path: Path,
    opaque_reference: str,
) -> None:
    manifest_payload = _manifest(tmp_path).model_dump(mode="json")
    manifest_payload["modules"][0]["reason"] = opaque_reference
    with pytest.raises(ValueError, match="secret-like"):
        AcceptanceManifestV2.model_validate(manifest_payload)

    run_payload = _run(_manifest(tmp_path)).model_dump(mode="json")
    run_payload["run_id"] = opaque_reference
    with pytest.raises(ValueError, match="secret-like"):
        AcceptanceRunRecordV2.model_validate(run_payload)

    report_payload = evaluate_acceptance(
        _manifest(tmp_path),
        _run(_manifest(tmp_path)),
    ).model_dump(mode="json")
    report_payload["run_id"] = opaque_reference
    with pytest.raises(ValueError, match="secret-like"):
        AcceptanceReportV2.model_validate(report_payload)

    prose = _manifest(tmp_path).model_dump(mode="json")
    prose["modules"][0]["reason"] = "demoted: reviewer evidence is pending"
    AcceptanceManifestV2.model_validate(prose)


def test_target_source_uses_reference_only_and_never_resolves_credentials(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    source = manifest.sources[0].model_copy(
        update={
            "source": TargetSecretSourceV2(
                kind="target_secret", secret_reference="/run/secrets/camera-00"
            ),
            "sha256": None,
        }
    )
    sources = (source, *manifest.sources[1:])
    validated = AcceptanceManifestV2(
        **{
            **manifest.model_dump(),
            "sources": sources,
            "launch": manifest.launch.model_copy(
                update={"source_profiles_sha256": source_profiles_sha256(sources)}
            ),
        }
    )
    serialized = validated.model_dump_json()
    assert "rtsp://" not in serialized
    assert "password" not in serialized


def test_percentile_is_nearest_rank_and_zero_is_explicit() -> None:
    assert percentile_nearest_rank([], 0.95) == 0.0
    assert percentile_nearest_rank([1, 2, 3, 4], 0.95) == 4
    assert percentile_nearest_rank([4, 1, 3, 2], 0.50) == 2


def test_exact_72h_target_record_passes_core_thresholds(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    report = evaluate_acceptance(manifest, _run(manifest))
    assert report.passed is True
    assert report.metrics["availability_percent"] == 100.0
    assert 0 < report.metrics["scheduled_drop_percent"] < 0.001
    assert report.worst_camera_availability_percent == 100.0
    assert report.worst_drop_percent < 1.0
    assert report.modules[1].mode == "shadow"


def test_one_bad_camera_and_module_cannot_hide_behind_healthy_fleet(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    payload = _run(manifest).model_dump(mode="json")
    end = START + timedelta(hours=72)
    offline_at = end - timedelta(hours=6)
    payload["health_spans"] = [
        span for span in payload["health_spans"] if span["camera_id"] != "camera-19"
    ] + [
        {
            "camera_id": "camera-19",
            "started_at": START,
            "ended_at": offline_at,
            "state": "online",
            "cadence_seconds": 60,
            "observed_samples": 3961,
        },
        {
            "camera_id": "camera-19",
            "started_at": offline_at,
            "ended_at": end,
            "state": "offline",
            "cadence_seconds": 60,
            "observed_samples": 361,
        },
    ]
    bad_work = next(
        span
        for span in payload["work_spans"]
        if span["camera_id"] == "camera-19" and span["module"] == "person"
    )
    added_drops = bad_work["scheduled_samples"] // 50
    bad_work["dropped_samples"] = added_drops
    bad_work["processed_samples"] = bad_work["scheduled_samples"] - added_drops
    bad_camera = next(camera for camera in payload["cameras"] if camera["camera_id"] == "camera-19")
    original_drops = bad_camera["dropped_samples"]
    bad_camera["dropped_samples"] += added_drops - 1
    bad_camera["processed_samples"] -= added_drops - 1
    bad_camera["observed_records"] = bad_camera["processed_samples"]
    bad_camera["availability_seconds"] = 66 * 3600
    assert original_drops == 1

    report = evaluate_acceptance(
        manifest,
        AcceptanceRunRecordV2.model_validate(payload),
    )

    assert report.metrics["availability_percent"] >= 99.5
    assert report.metrics["scheduled_drop_percent"] < 1.0
    assert report.passed is False
    assert report.worst_camera_id == "camera-19"
    assert report.worst_camera_availability_percent == pytest.approx(91.6666667)
    assert report.worst_drop_camera_id == "camera-19"
    assert report.worst_drop_module == "person"
    assert report.worst_drop_percent == pytest.approx(2.0, rel=1e-3)
    assert any("one or more cameras" in reason for reason in report.reasons)
    assert any("camera/module" in reason for reason in report.reasons)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("typed_gpu", 76.0, "GPU"),
        ("typed_vram", 81.0, "VRAM"),
        ("typed_candidate", 1.1, "candidate"),
        ("typed_preview", 2.1, "preview"),
        ("cross_camera_leakage", True, "cross-camera"),
        ("queue_traces", (), "queue"),
        ("boundaries", (), "boundary"),
        ("typed_capacity", 124.99, "headroom"),
    ],
)
def test_report_fails_closed_on_core_gate(
    tmp_path: Path, field: str, value: object, reason: str
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    if field == "typed_gpu":
        resources = tuple(
            item.model_copy(
                update={
                    "gpu_percent": value,
                    "gpu_percent_high_water": value,
                }
            )
            for item in run.resources
        )
        run = run.model_copy(update={"resources": resources})
    elif field == "typed_vram":
        resources = tuple(
            item.model_copy(
                update={
                    "vram_percent": value,
                    "vram_percent_high_water": value,
                }
            )
            for item in run.resources
        )
        run = run.model_copy(update={"resources": resources})
    elif field in {"typed_candidate", "typed_preview"}:
        changed = []
        for item in run.lifecycle:
            if field == "typed_candidate" and item.state == "persisted":
                item = item.model_copy(
                    update={"occurred_at": START + timedelta(seconds=1 + float(value))}
                )
            if field == "typed_preview" and item.kind == "evidence":
                item = item.model_copy(
                    update={"occurred_at": START + timedelta(seconds=1 + float(value))}
                )
            changed.append(item)
        run = run.model_copy(update={"lifecycle": tuple(changed)})
    elif field == "typed_capacity":
        run = run.model_copy(
            update={"capacity": run.capacity.model_copy(update={"effective_throughput_hz": value})}
        )
    else:
        run = run.model_copy(update={field: value})
    report = evaluate_acceptance(manifest, run)
    assert not report.passed
    assert any(reason.lower() in item.lower() for item in report.reasons)


def test_portable_test_only_can_never_satisfy_duration_gate(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest).model_copy(update={"environment": "test_only"})
    report = evaluate_acceptance(manifest, run)
    assert not report.passed
    assert "test_only" in " ".join(report.reasons)


def test_faults_require_complete_bounded_recovery_and_run_binding(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    fault = FaultRecordV2(
        fault_id="fault-camera-loss-1",
        kind="camera_loss",
        target="camera-00",
        injected_at=START + timedelta(seconds=10),
        monotonic_offset_seconds=10,
        duration_seconds=5,
        expected_degraded="offline",
        expected_recovery="online",
        observed_degraded="offline",
        observed_recovery=None,
        recovered_at=None,
    )
    report = evaluate_acceptance(manifest, _run(manifest).model_copy(update={"faults": (fault,)}))
    assert not report.passed
    assert any("recovery" in item for item in report.reasons)


def test_run_schema_rejects_nan_negative_regressive_and_secret_fields(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    with pytest.raises(ValueError):
        AcceptanceRunRecordV2(**{**run.model_dump(), "gpu_percent": (float("nan"),)})
    with pytest.raises(ValueError, match="after"):
        AcceptanceRunRecordV2(**{**run.model_dump(), "ended_at": START - timedelta(seconds=1)})
    payload = run.model_dump(mode="json")
    payload["rtsp_url"] = "rtsp://user:pass@example/cam"
    with pytest.raises(ValueError):
        AcceptanceRunRecordV2.model_validate(payload)


def test_html_is_escaped_and_contains_no_secrets(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    report = evaluate_acceptance(manifest, _run(manifest))
    html = render_acceptance_html(report, title="<script>alert(1)</script>")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "rtsp://" not in html


def test_external_openssl_signature_binds_json_and_html_digest(
    tmp_path: Path,
) -> None:
    import subprocess

    if subprocess.run(["openssl", "version"], capture_output=True).returncode:
        pytest.skip("OpenSSL unavailable")
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True,
        capture_output=True,
    )
    manifest = _manifest(tmp_path)
    report = evaluate_acceptance(manifest, _run(manifest))
    from protector.pilot.acceptance import write_signed_report

    paths = write_signed_report(
        report,
        output_dir=tmp_path / "out",
        private_key=private_key,
        public_key=public_key,
    )
    assert verify_signed_report(paths.metadata, public_key=public_key)
    data = json.loads(paths.report_json.read_text())
    data["passed"] = False
    paths.report_json.write_text(json.dumps(data))
    assert not verify_signed_report(paths.metadata, public_key=public_key)


def test_signed_report_targets_are_fresh_append_only_and_preserve_original(
    tmp_path: Path,
) -> None:
    if subprocess.run(["openssl", "version"], capture_output=True).returncode:
        pytest.skip("OpenSSL unavailable")
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True,
        capture_output=True,
    )
    manifest = _manifest(tmp_path)
    report = evaluate_acceptance(manifest, _run(manifest))
    from protector.pilot.acceptance import write_signed_report

    output = tmp_path / "report"
    paths = write_signed_report(
        report,
        output_dir=output,
        private_key=private_key,
        public_key=public_key,
    )
    originals = {path: path.read_bytes() for path in paths.model_dump().values()}
    with pytest.raises(ValueError, match="fresh"):
        write_signed_report(
            report,
            output_dir=output,
            private_key=private_key,
            public_key=public_key,
        )
    assert {path: path.read_bytes() for path in originals} == originals
    assert verify_signed_report(paths.metadata, public_key=public_key)

    symlink_output = tmp_path / "symlink-report"
    symlink_output.mkdir()
    outside = tmp_path / "outside.sig"
    outside.write_bytes(b"do-not-touch")
    (symlink_output / "acceptance-report.sig").symlink_to(outside)
    with pytest.raises(ValueError, match="fresh"):
        write_signed_report(
            report,
            output_dir=symlink_output,
            private_key=private_key,
            public_key=public_key,
        )
    assert outside.read_bytes() == b"do-not-touch"
    assert set(path.name for path in symlink_output.iterdir()) == {"acceptance-report.sig"}


def test_signing_failure_cleans_new_partial_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_key = (tmp_path / "private.pem").resolve()
    public_key = (tmp_path / "public.pem").resolve()
    private_key.write_text("bounded-private-fixture")
    private_key.chmod(0o600)
    public_key.write_text("bounded-public-fixture")
    output = tmp_path / "empty-report"
    output.mkdir()
    manifest = _manifest(tmp_path)
    report = evaluate_acceptance(manifest, _run(manifest))
    monkeypatch.setattr(
        "protector.pilot.acceptance.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )
    from protector.pilot.acceptance import write_signed_report

    with pytest.raises(ValueError, match="could not sign"):
        write_signed_report(
            report,
            output_dir=output,
            private_key=private_key,
            public_key=public_key,
        )
    assert list(output.iterdir()) == []


def test_fault_schedule_is_complete_unique_and_bounded() -> None:
    schedule = canonical_fault_schedule(tuple(f"camera-{index:02}" for index in range(20)))
    assert {item.kind for item in schedule} == {
        "camera_loss",
        "malformed_timestamp",
        "network_pause",
        "runtime_restart",
        "api_restart",
        "object_store_outage",
        "model_timeout",
        "verifier_full",
    }
    assert len({item.fault_id for item in schedule}) == 8
    assert all(0 < item.duration_seconds <= 3600 for item in schedule)


def test_portable_runner_uses_one_shared_runtime_and_drains_real_records(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=True))
    boundary = CollectingBoundary()
    run = run_portable(
        path,
        observation_consumer=boundary,
        health_consumer=boundary,
        fault_adapter=PortableFaultAdapter(),
        boundary_probe=boundary,
        started_at=START,
    )
    assert run.environment == "test_only"
    assert run.gate == "contract"
    assert {item.camera_id for item in boundary.observations} == {
        f"camera-{index:02}" for index in range(20)
    }
    assert {item.runtime_boot_id for item in run.cameras} == {run.runtime_boot_ids[-1]}
    assert run.queues_drained
    assert all(item.observed_records > 1 for item in run.cameras)
    assert len(boundary.health) > 400
    assert {item.component for item in run.boundaries} == {
        "event_engine",
        "repository",
        "evidence",
        "metrics",
    }
    evidence = next(item for item in run.boundaries if item.component == "evidence")
    assert evidence.succeeded is False
    assert run.events_evidence_complete is False
    assert run.reviews_audited is False
    assert run.notifications_after_confirmation is False
    assert run.cameras[0].last_health_at == run.ended_at
    assert all(item.observed_recovery is not None for item in run.faults)
    assert not evaluate_acceptance(manifest, run).passed


def test_portable_fault_harness_observes_all_faults_from_mutated_state(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=True))
    boundary = CollectingBoundary()

    run = run_portable(
        path,
        observation_consumer=boundary,
        health_consumer=boundary,
        fault_adapter=PortableFaultAdapter(),
        boundary_probe=boundary,
        started_at=START,
    )

    assert all(
        fault.observed_degraded == fault.expected_degraded
        and fault.observed_recovery == fault.expected_recovery
        and fault.recovered_at is not None
        for fault in run.faults
    )
    assert len(run.runtime_boot_ids) == 2
    assert len(set(run.runtime_boot_ids)) == 2
    assert len(run.api_boot_ids) == 2
    assert len(set(run.api_boot_ids)) == 2
    assert {(trace.kind, trace.phase, trace.state) for trace in run.fault_traces} >= {
        ("object_store_outage", "degraded", "degraded"),
        ("model_timeout", "degraded", "degraded"),
        ("verifier_full", "degraded", "degraded"),
    }
    assert any(item.queue == "verifier" and item.state == "full" for item in run.queue_traces)
    assert all(camera.last_health_at <= run.ended_at for camera in run.cameras)


@pytest.mark.parametrize(
    ("missing_degraded", "missing_recovery"),
    [
        (frozenset({"camera_loss"}), frozenset()),
        (frozenset(), frozenset({"object_store_outage"})),
    ],
)
def test_portable_fault_failure_adapter_cannot_claim_missing_transition(
    tmp_path: Path,
    missing_degraded: frozenset[str],
    missing_recovery: frozenset[str],
) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=True))
    boundary = CollectingBoundary()
    run = run_portable(
        path,
        observation_consumer=boundary,
        health_consumer=boundary,
        fault_adapter=PortableFaultAdapter(
            failure_plan=FaultFailurePlan(
                missing_degraded=missing_degraded,
                missing_recovery=missing_recovery,
            )
        ),
        boundary_probe=boundary,
        started_at=START,
    )
    assert not evaluate_acceptance(manifest, run).passed
    assert any(
        "incomplete degraded/recovery" in reason
        for reason in evaluate_acceptance(manifest, run).reasons
    )


class _FakeProcess:
    def __init__(
        self,
        *,
        ignore_terminate: bool = False,
        exit_early: bool = False,
        signaled_exit: bool = False,
    ) -> None:
        self.ignore_terminate = ignore_terminate
        self.signaled_exit = signaled_exit
        self.returncode = 3 if exit_early else None
        self.container_id = "2" * 64
        self.container_config_sha256 = "3" * 64
        self.control_network_id = "4" * 64
        self.control_network_config_sha256 = "5" * 64
        self.camera_network_id = "6" * 64
        self.camera_network_config_sha256 = "7" * 64
        self.observed_gpu_inventory_sha256: str | None = None
        self.terminate_calls = 0
        self.kill_calls = 0
        self.remove_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self, *, timeout_seconds: int) -> None:
        assert 1 <= timeout_seconds <= 60
        self.terminate_calls += 1
        if not self.ignore_terminate:
            self.returncode = -15 if self.signaled_exit else 0

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("deepstream", timeout)
        return self.returncode

    def remove(self) -> None:
        self.remove_calls += 1


class _FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class _FakeCollector(TargetCollector):
    def __init__(self, record: AcceptanceRunRecordV2, *, observations: int = 1) -> None:
        self.record = record
        self.observations = observations
        self.samples = 0
        self.started: tuple[str, str, str] | None = None
        self.fault_commands: list[tuple[str, str, float]] = []
        self.finish_calls = 0
        self._collector_id = "collector-test-session"

    @property
    def collector_id(self) -> str:
        return self._collector_id

    def start(
        self,
        *,
        site_id: str,
        manifest_sha256: str,
        gate: str,
        camera_ids: tuple[str, ...],
        workloads: object,
        sample_interval_seconds: int,
        launch: object,
        execution: ExecutionBindingV2,
        schedule: object,
    ) -> None:
        assert len(camera_ids) == 20
        assert 30 <= sample_interval_seconds <= 60
        del launch, schedule, workloads
        self.started = (site_id, manifest_sha256, gate)
        self.record = self.record.model_copy(
            update={
                "run_id": self.collector_id,
                "execution": execution,
            }
        )

    def collect(
        self,
        *,
        process_healthy: bool,
        scheduled_monotonic_offset_seconds: float,
    ) -> None:
        assert process_healthy
        assert scheduled_monotonic_offset_seconds >= 0
        self.samples += self.observations

    def command_fault(
        self,
        *,
        fault_id: str,
        phase: str,
        at_offset: float,
    ) -> None:
        self.fault_commands.append((fault_id, phase, at_offset))

    def finish(self) -> AcceptanceRunRecordV2:
        self.finish_calls += 1
        if self.samples == 0:
            raise RuntimeError("collector observed no bounded samples")
        return self.record


def _target_args(
    tmp_path: Path,
    manifest: AcceptanceManifestV2,
    *,
    duration: int,
) -> SimpleNamespace:
    trust_bundle = verified_trust_bundle(
        tmp_path,
        manifest,
        valid_until=START + timedelta(days=4),
        allowed_gates=("8h", "72h"),
    )
    gate = "72h" if duration == 259_200 else "8h"
    token = tmp_path / "machine-token"
    token.write_text("machine-token-not-printed")
    acceptance_token = tmp_path / "acceptance-controller-token"
    acceptance_token.write_text("acceptance-controller-token-not-printed")
    acceptance_adapter = tmp_path / "acceptance-adapter"
    acceptance_adapter.unlink(missing_ok=True)
    acceptance_adapter.write_bytes(ADAPTER_PAYLOAD)
    acceptance_adapter.chmod(0o500)
    acceptance_observer = tmp_path / "acceptance-observer"
    acceptance_observer.unlink(missing_ok=True)
    acceptance_observer.write_bytes(OBSERVER_PAYLOAD)
    acceptance_observer.chmod(0o500)
    acceptance_policy = tmp_path / "acceptance-policy.json"
    acceptance_policy.unlink(missing_ok=True)
    acceptance_policy.write_bytes(ADAPTER_POLICY_PAYLOAD)
    acceptance_policy.chmod(0o400)
    observer_policy = tmp_path / "observer-policy.json"
    observer_policy.unlink(missing_ok=True)
    observer_policy.write_bytes(OBSERVER_POLICY_PAYLOAD)
    observer_policy.chmod(0o400)
    return SimpleNamespace(
        _fixture_verified_trust=trust_bundle.trust,
        manifest=trust_bundle.manifest,
        manifest_signature=trust_bundle.manifest_signature,
        acceptance_site_id=manifest.site_id,
        acceptance_campaign_id=trust_bundle.trust.policy.campaign_id,
        acceptance_gate=gate,
        acceptance_offline_root_spki_sha256=(trust_bundle.expected_offline_root_spki_sha256),
        acceptance_offline_root_public_key=(trust_bundle.root_public_key),
        acceptance_trust_policy=trust_bundle.policy,
        acceptance_trust_policy_signature=(trust_bundle.policy_signature),
        acceptance_manifest_role_public_key=(trust_bundle.role_public_keys.manifest),
        acceptance_capacity_role_public_key=(trust_bundle.role_public_keys.capacity),
        acceptance_run_role_public_key=(trust_bundle.role_public_keys.run),
        acceptance_report_role_public_key=(trust_bundle.role_public_keys.report),
        acceptance_conditional_role_public_key=(trust_bundle.role_public_keys.conditional),
        out=tmp_path / "new-run.json",
        duration_seconds=duration,
        stop_grace_seconds=5,
        collector_interval_seconds=60,
        site_config=tmp_path / "site.yaml",
        site_config_sha256=manifest.launch.site_config_file_sha256,
        runtime_manifest=tmp_path / "runtime.yaml",
        runtime_manifest_sha256=manifest.launch.runtime_manifest_file_sha256,
        measured_capacity_report=tmp_path / "capacity.yaml",
        measured_capacity_sha256=manifest.launch.measured_capacity_file_sha256,
        measured_capacity_signature=tmp_path / "capacity.sig",
        runtime_image_id_sha256=manifest.launch.runtime_image_id_sha256,
        runtime_image_config_sha256=manifest.launch.runtime_image_config_sha256,
        runtime_code_sha256=manifest.launch.runtime_code_sha256,
        mount_contract_sha256=manifest.launch.mount_contract_sha256,
        mount_contract=tmp_path / "mount-contract.yaml",
        container_engine=Path("/usr/bin/true"),
        nvidia_ctk=Path("/usr/bin/true"),
        control_network=manifest.launch.control_network,
        camera_network=manifest.launch.camera_network,
        control_network_id=manifest.launch.expected_control_network_id,
        control_network_config_sha256=(manifest.launch.expected_control_network_config_sha256),
        camera_network_id=manifest.launch.expected_camera_network_id,
        camera_network_config_sha256=(manifest.launch.expected_camera_network_config_sha256),
        acceptance_adapter_sha256=manifest.launch.acceptance_adapter_sha256,
        acceptance_adapter_executable=acceptance_adapter,
        acceptance_adapter_policy=acceptance_policy,
        acceptance_adapter_policy_sha256=(manifest.launch.acceptance_adapter_policy_sha256),
        acceptance_adapter_work_root=tmp_path / "adapter-work",
        acceptance_observer_sha256=(manifest.launch.acceptance_observer_sha256),
        acceptance_observer_executable=acceptance_observer,
        acceptance_observer_policy=observer_policy,
        acceptance_observer_policy_sha256=(manifest.launch.acceptance_observer_policy_sha256),
        acceptance_observer_work_root=tmp_path / "observer-work",
        collector_state=tmp_path / "collector-state" / "runner.sqlite3",
        control_plane_url="http://127.0.0.1:8765",
        machine_token_file=token,
        acceptance_controller_token_file=acceptance_token,
        out_attestation=tmp_path / "new-run.attestation.json",
        out_signature=tmp_path / "new-run.attestation.sig",
        out_journal_proof=tmp_path / "new-run.journal-proof.jsonl",
    )


def _target_trust_context(arguments: SimpleNamespace):
    return build_authority_trust_context(
        trust=arguments._fixture_verified_trust,
        configured_site_id=arguments.acceptance_site_id,
        configured_campaign_id=arguments.acceptance_campaign_id,
        configured_gate=arguments.acceptance_gate,
    )


def _durable_recovery_start(
    arguments: SimpleNamespace,
    record: AcceptanceRunRecordV2,
) -> dict[str, object]:
    context = _target_trust_context(arguments)
    assert record.execution is not None
    schedule_sha256 = canonical_fault_schedule_sha256(context.fault_schedule)
    return {
        "schema_version": "acceptance-collector-start.v2",
        "collector_id": record.run_id,
        "site_id": context.configured_site_id,
        "manifest_sha256": context.trust.manifest.manifest_sha256,
        "gate": context.configured_gate,
        "launch_attestation_sha256": context.launch.attestation_sha256,
        "execution_binding_sha256": record.execution.binding_sha256,
        "fault_schedule_sha256": schedule_sha256,
        "trust_binding": context.binding.model_dump(mode="json"),
        "sample_interval_seconds": 60,
        "camera_ids": list(context.camera_ids),
        "workloads": [workload.model_dump(mode="json") for workload in context.workloads],
        "launch": context.launch.model_dump(mode="json"),
        "execution": record.execution.model_dump(mode="json"),
        "fault_schedule": [fault.model_dump(mode="json") for fault in context.fault_schedule],
    }


def test_target_verifies_offline_root_before_campaign_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    arguments = _target_args(tmp_path, manifest, duration=28_800)
    events: list[str] = []
    original_verify = replay_module.verify_acceptance_trust_chain

    def verify(**kwargs: object):
        events.append("verify")
        return original_verify(**kwargs)

    def stop_after_lock(_lock: TargetCampaignLock):
        events.append("lock")
        raise RuntimeError("stop-after-lock")

    monkeypatch.setattr(
        replay_module,
        "verify_acceptance_trust_chain",
        verify,
    )
    monkeypatch.setattr(
        replay_module.TargetCampaignLock,
        "__enter__",
        stop_after_lock,
    )
    with pytest.raises(RuntimeError, match="stop-after-lock"):
        run_target(
            arguments,
            process_factory=lambda *_args, **_kwargs: pytest.fail("process must not start"),
            collector=_FakeCollector(_run(manifest, hours=8)),
        )
    assert events == ["verify", "lock"]


def test_bad_offline_root_fails_before_state_token_process_or_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    arguments = _target_args(tmp_path, manifest, duration=28_800)
    arguments.acceptance_offline_root_spki_sha256 = "0" * 64
    token_reads = 0
    opener_builds = 0
    process_starts = 0

    def token_read(_path: Path) -> str:
        nonlocal token_reads
        token_reads += 1
        raise AssertionError("bad root reached token read")

    def opener(*_args: object, **_kwargs: object):
        nonlocal opener_builds
        opener_builds += 1
        raise AssertionError("bad root reached network setup")

    def process(*_args: object, **_kwargs: object) -> _FakeProcess:
        nonlocal process_starts
        process_starts += 1
        raise AssertionError("bad root reached process launch")

    monkeypatch.setattr(replay_module, "read_machine_token", token_read)
    monkeypatch.setattr(
        replay_module.urllib.request,
        "build_opener",
        opener,
    )
    with pytest.raises(ValueError, match="offline root"):
        run_target(arguments, process_factory=process)
    lock_path = arguments.collector_state.with_name(
        f"{arguments.collector_state.name}.campaign.lock"
    )
    assert token_reads == opener_builds == process_starts == 0
    assert not lock_path.exists()
    assert not arguments.collector_state.exists()
    assert not arguments.out.exists()
    assert not arguments.out_attestation.exists()
    assert not arguments.out_signature.exists()


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("acceptance_site_id", "attacker-site", "context"),
        ("acceptance_campaign_id", "attacker-campaign", "context"),
        ("acceptance_gate", "72h", "duration"),
    ),
)
def test_target_rejects_configured_trust_context_mismatch_before_lock(
    tmp_path: Path,
    field: str,
    value: str,
    match: str,
) -> None:
    manifest = _manifest(tmp_path)
    arguments = _target_args(tmp_path, manifest, duration=28_800)
    setattr(arguments, field, value)

    with pytest.raises(ValueError, match=match):
        run_target(
            arguments,
            process_factory=lambda *_args, **_kwargs: pytest.fail("trust mismatch must not launch"),
            collector=_FakeCollector(_run(manifest, hours=8)),
        )
    lock_path = arguments.collector_state.with_name(
        f"{arguments.collector_state.name}.campaign.lock"
    )
    assert not lock_path.exists()


def test_default_target_collector_receives_only_verified_chain_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    arguments = _target_args(tmp_path, manifest, duration=28_800)
    captured: dict[str, object] = {}
    process = _FakeProcess()

    def capture_collector(**kwargs: object) -> None:
        captured.update(kwargs)
        raise RuntimeError("collector-captured")

    monkeypatch.setattr(
        replay_module,
        "AuthenticatedTargetCollector",
        capture_collector,
    )
    with pytest.raises(RuntimeError, match="collector-captured"):
        run_target(
            arguments,
            process_factory=lambda *_args, **_kwargs: process,
        )

    trust = captured["verified_trust"]
    assert trust.manifest == manifest
    assert captured["configured_site_id"] == manifest.site_id
    assert captured["configured_campaign_id"] == "campaign-2026-001"
    assert captured["configured_gate"] == "8h"
    assert "run_authority_public_key_path" not in captured
    assert process.remove_calls == 1


@pytest.mark.parametrize(("duration", "gate"), [(28_800, "8h"), (259_200, "72h")])
def test_target_cli_owns_duration_process_and_authenticated_collector(
    tmp_path: Path, duration: int, gate: str
) -> None:
    manifest = _manifest(tmp_path)
    record = _run(manifest, hours=duration // 3600).model_copy(update={"gate": gate})
    process = _FakeProcess()
    clock = _FakeClock()
    collector = _FakeCollector(record)
    popen_calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def popen(command: tuple[str, ...], **kwargs: object) -> _FakeProcess:
        popen_calls.append((command, kwargs))
        return process

    result = run_target(
        _target_args(tmp_path, manifest, duration=duration),
        process_factory=popen,
        collector=collector,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    assert result.gate == gate
    assert len(popen_calls) == 1
    command, kwargs = popen_calls[0]
    assert kwargs["shell"] is False
    assert "machine-token-not-printed" not in " ".join(command)
    assert collector.started == (manifest.site_id, manifest.manifest_sha256, gate)
    assert process.terminate_calls == 1
    assert process.kill_calls == 0
    assert process.remove_calls == 1


def test_target_kills_unresponsive_process_and_marks_run_failed(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    process = _FakeProcess(ignore_terminate=True)
    clock = _FakeClock()
    with pytest.raises(RuntimeError, match="graceful"):
        run_target(
            _target_args(tmp_path, manifest, duration=28_800),
            process_factory=lambda *_args, **_kwargs: process,
            collector=_FakeCollector(record),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert process.remove_calls == 1


def test_target_rejects_signaled_exit_and_does_not_finalize(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    process = _FakeProcess(signaled_exit=True)
    collector = _FakeCollector(record)
    clock = _FakeClock()
    with pytest.raises(RuntimeError, match="clean graceful shutdown"):
        run_target(
            _target_args(tmp_path, manifest, duration=28_800),
            process_factory=lambda *_args, **_kwargs: process,
            collector=collector,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
    assert process.returncode == -15
    assert collector.finish_calls == 0


def test_target_rejects_cadence_that_cannot_fit_the_72h_journal(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    arguments = _target_args(tmp_path, manifest, duration=259_200)
    arguments.collector_interval_seconds = 29
    with pytest.raises(ValueError, match="exactly 60"):
        run_target(
            arguments,
            process_factory=lambda *_args, **_kwargs: pytest.fail("process must not start"),
            collector=_FakeCollector(_run(manifest)),
        )


def test_target_starts_gate_clock_only_after_process_and_authority_start(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    clock = _FakeClock()

    class DelayedStartCollector(_FakeCollector):
        def start(self, **kwargs: object) -> None:
            clock.value += 20
            super().start(**kwargs)

    def slow_process_factory(
        *_args: object,
        **_kwargs: object,
    ) -> _FakeProcess:
        clock.value += 10
        return _FakeProcess()

    collector = DelayedStartCollector(record)
    run_target(
        _target_args(tmp_path, manifest, duration=28_800),
        process_factory=slow_process_factory,
        collector=collector,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    assert clock.value == 28_830
    assert collector.fault_commands[0][2] == 10
    assert collector.fault_commands[-1][2] == 82


def test_target_refuses_missing_observations_and_preexisting_output(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    args = _target_args(tmp_path, manifest, duration=28_800)
    clock = _FakeClock()
    with pytest.raises(RuntimeError, match="no bounded samples"):
        run_target(
            args,
            process_factory=lambda *_args, **_kwargs: _FakeProcess(),
            collector=_FakeCollector(record, observations=0),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
    args.out.write_text("untrusted-old-record")
    with pytest.raises(ValueError, match="new CLI-owned"):
        run_target(args, collector=_FakeCollector(record))


def test_target_discards_process_output_without_global_file_limit(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    args = _target_args(tmp_path, manifest, duration=28_800)
    clock = _FakeClock()

    def isolated_process(_command: tuple[str, ...], **kwargs: object) -> _FakeProcess:
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert "preexec_fn" not in kwargs
        return _FakeProcess()

    assert (
        run_target(
            args,
            process_factory=isolated_process,
            collector=_FakeCollector(record),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        ).run_id
        == "collector-test-session"
    )


def test_target_rejects_stale_same_binding_record_without_collector_nonce(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})

    class StaleCollector(_FakeCollector):
        def finish(self) -> AcceptanceRunRecordV2:
            return super().finish().model_copy(update={"run_id": "stale-prior-session"})

    clock = _FakeClock()
    process = _FakeProcess()
    with pytest.raises(RuntimeError, match="collector session"):
        run_target(
            _target_args(tmp_path, manifest, duration=28_800),
            process_factory=lambda *_args, **_kwargs: process,
            collector=StaleCollector(record),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
    assert process.remove_calls == 1


def test_authenticated_collector_rejects_response_binding_without_leaking_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = tmp_path / "machine-token"
    token.write_text("machine-token-never-in-repr")

    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "schema_version": "acceptance-collector-start-response.v2",
                    "site_id": "wrong-site",
                    "manifest_sha256": HEX,
                    "gate": "8h",
                    "collector_id": "wrong",
                    "launch_attestation_sha256": "1" * 64,
                    "execution_binding_sha256": "2" * 64,
                    "fault_schedule_sha256": "3" * 64,
                }
            ).encode()

        def geturl(self) -> str:
            return "http://127.0.0.1:8765/api/internal/acceptance/start"

    manifest = _manifest(tmp_path)
    trust_context = authority_trust_context(tmp_path, manifest)
    collector = AuthenticatedTargetCollector(
        base_url="http://127.0.0.1:8765",
        acceptance_controller_token_file=token,
        verified_trust=trust_context.trust,
        configured_site_id=trust_context.configured_site_id,
        configured_campaign_id=trust_context.configured_campaign_id,
        configured_gate=trust_context.configured_gate,
    )
    monkeypatch.setattr(
        collector._opener,
        "open",
        lambda *_args, **_kwargs: Response(),
    )
    assert "machine-token-never-in-repr" not in repr(collector)
    execution = ExecutionBindingV2(
        schema_version="acceptance-execution-binding.v2",
        launch_attestation_sha256=manifest.launch.attestation_sha256,
        launch_nonce="1" * 32,
        container_id="2" * 64,
        container_config_sha256="3" * 64,
        runtime_image_id_sha256=manifest.launch.runtime_image_id_sha256,
        acceptance_adapter_sha256=manifest.launch.acceptance_adapter_sha256,
        acceptance_adapter_policy_sha256=(manifest.launch.acceptance_adapter_policy_sha256),
        acceptance_observer_sha256=(manifest.launch.acceptance_observer_sha256),
        acceptance_observer_policy_sha256=(manifest.launch.acceptance_observer_policy_sha256),
        control_network_id="4" * 64,
        control_network_config_sha256="5" * 64,
        camera_network_id="6" * 64,
        camera_network_config_sha256="7" * 64,
        observed_gpu_inventory_sha256=(manifest.launch.gpu_inventory_sha256),
    )
    with pytest.raises(RuntimeError, match="binding mismatch"):
        collector.start(
            site_id=manifest.site_id,
            manifest_sha256=manifest.manifest_sha256,
            gate="8h",
            camera_ids=trust_context.camera_ids,
            workloads=tuple(
                CameraAcceptanceWorkloadV2(**item.model_dump(mode="python"))
                for item in trust_context.workloads
            ),
            launch=manifest.launch,
            execution=execution,
            schedule=trust_context.fault_schedule,
            sample_interval_seconds=60,
        )


@pytest.mark.parametrize(
    ("status", "final_url"),
    (
        (503, "http://127.0.0.1:8765/api/internal/acceptance/sample"),
        (200, "http://attacker.invalid/api/internal/acceptance/sample"),
        (200, "http://127.0.0.1:8765/api/internal/acceptance/other"),
        (200, "http://127.0.0.1:8765/api/internal/acceptance/sample?changed=1"),
        (200, "http://127.0.0.1:8765/api/internal/acceptance/sample#changed"),
        (200, "http://operator@127.0.0.1:8765/api/internal/acceptance/sample"),
    ),
)
def test_authenticated_collector_rejects_response_before_reading_hostile_body(
    status: int,
    final_url: str,
) -> None:
    reads = 0
    attempts = 0

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            nonlocal reads
            reads += 1
            return b'{"accepted":true}'

        def geturl(self) -> str:
            return final_url

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> Response:
            nonlocal attempts
            attempts += 1
            response = Response()
            response.status = status
            return response

    collector = object.__new__(AuthenticatedTargetCollector)
    collector._base_url = "http://127.0.0.1:8765"
    collector._token = "controller-token-not-secret-in-test"
    collector._timeout_seconds = 1.0
    collector._opener = Opener()

    with pytest.raises(RuntimeError, match="target collector request failed"):
        collector._post(
            "/api/internal/acceptance/sample",
            {"schema_version": "probe.v1"},
            limit=1024,
        )

    assert attempts == 3
    assert reads == 0


def test_target_collector_journal_replays_exact_response_across_reconstruction(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runner-state"
    root.mkdir(mode=0o700)
    path = root / "collector.sqlite3"
    first = SQLiteTargetCollectorJournal(path)
    request = {"schema_version": "probe.v1", "sequence": 7}
    response = {"accepted": True, "sequence": 7}
    assert first.stage("sample:7", request) == request
    assert (
        first.complete(
            "sample:7",
            request=request,
            response=response,
        )
        == response
    )

    reconstructed = SQLiteTargetCollectorJournal(path)
    assert reconstructed.request("sample:7") == request
    assert reconstructed.response("sample:7") == response
    assert reconstructed.completed("sample:") == (("sample:7", response),)
    with pytest.raises(RuntimeError, match="payload changed"):
        reconstructed.stage(
            "sample:7",
            {"schema_version": "probe.v1", "sequence": 8},
        )


def test_target_campaign_lock_refuses_a_second_host_runner(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "campaign-state" / "runner.lock"
    with TargetCampaignLock(lock_path):
        with pytest.raises(
            RuntimeError,
            match="another target acceptance runner",
        ):
            with TargetCampaignLock(lock_path):
                raise AssertionError("second campaign lock must not enter")


def test_target_campaign_lock_is_exclusive_across_processes(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "cross-process-state" / "runner.lock"
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from scripts.pilot.replay_20 import TargetCampaignLock\n"
        "with TargetCampaignLock(Path(sys.argv[1])):\n"
        " print('READY', flush=True)\n"
        " sys.stdin.readline()\n"
    )
    child = subprocess.Popen(
        (sys.executable, "-c", code, str(lock_path)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "READY"
        with pytest.raises(
            RuntimeError,
            match="another target acceptance runner",
        ):
            with TargetCampaignLock(lock_path):
                raise AssertionError("second process must not acquire")
    finally:
        child.communicate(input="\n", timeout=10)
    assert child.returncode == 0


def test_target_refuses_incomplete_durable_campaign_before_runtime_launch(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    args = _target_args(tmp_path, manifest, duration=28_800)
    SQLiteTargetCollectorJournal(args.collector_state).stage(
        "start",
        {"collector_id": "incomplete-campaign"},
    )
    launches: list[tuple[str, ...]] = []

    def launch(command: tuple[str, ...], **_kwargs: object):
        launches.append(command)
        raise AssertionError("incomplete campaign must not relaunch")

    with pytest.raises(
        RuntimeError,
        match="incomplete target campaign cannot be relaunched",
    ):
        run_target(args, process_factory=launch)
    assert launches == []


def _signed_completed_final_envelope(
    tmp_path: Path,
    manifest: AcceptanceManifestV2,
    record: AcceptanceRunRecordV2,
    *,
    private_key: Path | None = None,
    stem: str = "completed",
) -> dict[str, object]:
    del tmp_path, manifest, record, private_key, stem
    return {"schema_version": "acceptance-final-envelope.v1"}


def _signed_completed_final_envelope_v2(
    tmp_path: Path,
    arguments: SimpleNamespace,
    manifest: AcceptanceManifestV2,
    record: AcceptanceRunRecordV2,
    *,
    proof_payload: bytes,
) -> dict[str, object]:
    assert record.execution is not None
    context = _target_trust_context(arguments)
    record_payload = json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    inventory = JournalKindCountsV2.exact_for_gate(record.gate)
    attestation = TargetRunAttestationV2(
        schema_version="target-run-attestation.v2",
        journal_namespace_mode="protected",
        collector_id=record.run_id,
        site_id=record.site_id,
        manifest_sha256=record.manifest_sha256,
        gate=record.gate,
        offline_root_spki_sha256=context.binding.offline_root_spki_sha256,
        policy_id=context.binding.policy_id,
        policy_sha256=context.binding.policy_sha256,
        campaign_id=context.binding.campaign_id,
        manifest_payload_sha256=context.binding.manifest_payload_sha256,
        launch_attestation_sha256=record.launch.attestation_sha256,
        execution_binding_sha256=record.execution.binding_sha256,
        fault_schedule_sha256=canonical_fault_schedule_sha256(
            canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
        ),
        run_record_sha256=hashlib.sha256(record_payload).hexdigest(),
        journal_root_sha256="b" * 64,
        journal_entry_count=inventory.total,
        public_key_spki_sha256=record.launch.run_authority_public_key_spki_sha256,
        journal_proof_sha256=hashlib.sha256(proof_payload).hexdigest(),
        journal_proof_bytes=len(proof_payload),
        journal_proof_lines=inventory.total + 2,
        journal_kind_counts=inventory,
    )
    attestation_path = tmp_path / "completed-v2-attestation.json"
    attestation_path.write_text(
        json.dumps(
            attestation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    signature_path = tmp_path / "completed-v2-attestation.sig"
    subprocess.run(
        (
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(tmp_path / "target-run-private.pem"),
            "-in",
            str(attestation_path),
            "-out",
            str(signature_path),
        ),
        check=True,
    )
    return {
        "schema_version": "acceptance-final-envelope.v2",
        "record": record.model_dump(mode="json"),
        "attestation": attestation.model_dump(mode="json"),
        "signature_hex": signature_path.read_bytes().hex(),
    }


def _write_bound_journal_proof(
    path: Path,
    *,
    run: AcceptanceRunRecordV2,
    trust: object,
) -> TargetRunAttestationV2:
    payload_schemas = {
        "start": "acceptance-collector-start.v2",
        "sample": "acceptance-sample-observation.v2",
        "fault_intent": "acceptance-fault-intent.v2",
        "fault_claim": "acceptance-fault-claim.v2",
        "fault_ack": "acceptance-fault-acknowledgement.v2",
        "finalize": "acceptance-run-record.v2",
    }
    assert run.execution is not None
    schedule = canonical_fault_schedule(
        tuple(source.camera_id for source in trust.manifest.sources)
    )
    counts = JournalKindCountsV2.exact_for_gate(run.gate)
    header = AcceptanceJournalProofHeaderV2(
        schema_version="acceptance-journal-proof-header.v2",
        collector_id=run.run_id,
        site_id=run.site_id,
        manifest_sha256=run.manifest_sha256,
        gate=run.gate,
        journal_namespace_mode="protected",
        offline_root_spki_sha256=trust.root_spki_sha256,
        policy_id=trust.policy.policy_id,
        policy_sha256=trust.policy_sha256,
        campaign_id=trust.policy.campaign_id,
        manifest_payload_sha256=trust.manifest_payload_sha256,
        launch_attestation_sha256=run.launch.attestation_sha256,
        execution_binding_sha256=run.execution.binding_sha256,
        fault_schedule_sha256=canonical_fault_schedule_sha256(schedule),
        public_run_authority_spki_sha256=trust.policy.roles.run_spki_sha256,
        sample_interval_seconds=60,
        camera_ids=tuple(source.camera_id for source in trust.manifest.sources),
        launch=run.launch.model_dump(mode="json"),
        execution=run.execution.model_dump(mode="json"),
        fault_schedule=tuple(item.model_dump(mode="json") for item in schedule),
    )
    kinds = (
        ("start",)
        + ("sample",) * counts.sample
        + ("fault_intent",) * counts.fault_intent
        + ("fault_claim",) * counts.fault_claim
        + ("fault_ack",) * counts.fault_ack
        + ("finalize",)
    )
    previous = ""
    lines = [canonical_proof_line(header)]
    for ordinal, kind in enumerate(kinds, start=1):
        identity = "final" if kind == "finalize" else f"{kind}-{ordinal:04}"
        payload = (
            run.model_dump(mode="json")
            if kind == "finalize"
            else {
                "schema_version": payload_schemas[kind],
                "kind": kind,
                "ordinal": ordinal,
            }
        )
        payload_json = canonical_json_bytes(payload).decode()
        created_at = run.ended_at.isoformat()
        entry_sha256 = journal_entry_sha256(
            collector_id=run.run_id,
            kind=kind,
            identity=identity,
            payload_json=payload_json,
            created_at=created_at,
            previous_entry_sha256=previous,
        )
        lines.append(
            canonical_proof_line(
                AcceptanceJournalProofEntryV2(
                    schema_version="acceptance-journal-proof-entry.v2",
                    ordinal=ordinal,
                    collector_id=run.run_id,
                    kind=kind,
                    identity=identity,
                    payload=payload,
                    created_at=created_at,
                    previous_entry_sha256=previous,
                    entry_sha256=entry_sha256,
                )
            )
        )
        previous = entry_sha256
    run_sha256 = hashlib.sha256(canonical_json_bytes(run)).hexdigest()
    trailer = AcceptanceJournalProofTrailerV2(
        schema_version="acceptance-journal-proof-trailer.v2",
        collector_id=run.run_id,
        entry_count=counts.total,
        kind_counts=counts,
        journal_final_root_sha256=previous,
        run_record_sha256=run_sha256,
    )
    lines.append(canonical_proof_line(trailer))
    proof_payload = b"".join(lines)
    path.write_bytes(proof_payload)
    return TargetRunAttestationV2(
        schema_version="target-run-attestation.v2",
        journal_namespace_mode="protected",
        collector_id=run.run_id,
        site_id=run.site_id,
        manifest_sha256=run.manifest_sha256,
        gate=run.gate,
        offline_root_spki_sha256=trust.root_spki_sha256,
        policy_id=trust.policy.policy_id,
        policy_sha256=trust.policy_sha256,
        campaign_id=trust.policy.campaign_id,
        manifest_payload_sha256=trust.manifest_payload_sha256,
        launch_attestation_sha256=run.launch.attestation_sha256,
        execution_binding_sha256=run.execution.binding_sha256,
        fault_schedule_sha256=header.fault_schedule_sha256,
        run_record_sha256=run_sha256,
        journal_root_sha256=previous,
        journal_entry_count=counts.total,
        public_key_spki_sha256=trust.policy.roles.run_spki_sha256,
        journal_proof_sha256=hashlib.sha256(proof_payload).hexdigest(),
        journal_proof_bytes=len(proof_payload),
        journal_proof_lines=len(lines),
        journal_kind_counts=counts,
    )


def _target_artifact_publication_inputs(
    tmp_path: Path,
) -> tuple[AcceptanceRunRecordV2, TargetRunAttestationV2, bytes, Path]:
    manifest = _manifest(tmp_path)
    arguments = _target_args(tmp_path, manifest, duration=28_800)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    proof_payload = b"sealed-journal-proof\n"
    envelope = _signed_completed_final_envelope_v2(
        tmp_path,
        arguments,
        manifest,
        record,
        proof_payload=proof_payload,
    )
    proof_source = tmp_path / "publication-source.jsonl"
    proof_source.write_bytes(proof_payload)
    proof_source.chmod(0o600)
    return (
        record,
        TargetRunAttestationV2.model_validate(envelope["attestation"]),
        bytes.fromhex(str(envelope["signature_hex"])),
        proof_source,
    )


def _target_artifact_paths(
    tmp_path: Path,
    *,
    mixed_parents: bool = False,
) -> tuple[Path, Path, Path, Path]:
    names = (
        "run.json",
        "run.attestation.json",
        "run.attestation.sig",
        "run.proof.jsonl",
    )
    if not mixed_parents:
        output = tmp_path / "outputs"
        output.mkdir()
        return tuple(output / name for name in names)  # type: ignore[return-value]
    parents = tuple(tmp_path / f"output-{index}" for index in range(4))
    for parent in parents:
        parent.mkdir()
    return tuple(  # type: ignore[return-value]
        parent / name for parent, name in zip(parents, names, strict=True)
    )


def _target_artifact_payloads(
    record: AcceptanceRunRecordV2,
    attestation: TargetRunAttestationV2,
    signature: bytes,
    proof_source: Path,
) -> tuple[bytes, bytes, bytes, bytes]:
    return (
        json.dumps(
            record.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode(),
        json.dumps(
            attestation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode(),
        signature,
        proof_source.read_bytes(),
    )


def _publish_target_artifacts(
    paths: tuple[Path, Path, Path, Path],
    inputs: tuple[AcceptanceRunRecordV2, TargetRunAttestationV2, bytes, Path],
) -> None:
    record, attestation, signature, proof_source = inputs
    replay_module._write_new_target_artifacts(
        record_path=paths[0],
        attestation_path=paths[1],
        signature_path=paths[2],
        proof_path=paths[3],
        proof_source=proof_source,
        record=record,
        attestation=attestation,
        signature=signature,
    )


def _exception_messages(error: BaseException) -> tuple[str, ...]:
    if isinstance(error, BaseExceptionGroup):
        return tuple(
            message for nested in error.exceptions for message in _exception_messages(nested)
        )
    return (str(error),)


def test_target_recovers_committed_final_before_runtime_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    args = _target_args(tmp_path, manifest, duration=28_800)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    proof_payload = b"sealed-journal-proof\n"
    envelope = _signed_completed_final_envelope_v2(
        tmp_path,
        args,
        manifest,
        record,
        proof_payload=proof_payload,
    )
    journal = SQLiteTargetCollectorJournal(args.collector_state)
    journal.stage("start", _durable_recovery_start(args, record))
    request = {"schema_version": "completed-final-probe.v1"}
    journal.stage("finalize", request)
    journal.complete("finalize", request=request, response=envelope)
    launches: list[tuple[str, ...]] = []

    def launch(command: tuple[str, ...], **_kwargs: object):
        launches.append(command)
        raise AssertionError("committed final recovery must not relaunch")

    def download(**kwargs: object) -> None:
        assert kwargs["record"] == record
        destination = Path(kwargs["destination"])
        destination.write_bytes(proof_payload)
        destination.chmod(0o600)

    monkeypatch.setattr(replay_module, "_download_journal_proof", download)
    recovered = run_target(args, process_factory=launch)

    assert recovered == record
    assert launches == []
    assert args.out.exists()
    assert args.out_attestation.exists()
    assert args.out_signature.exists()
    assert args.out_journal_proof.read_bytes() == proof_payload


def test_target_proof_publication_rejects_same_size_digest_substitution(
    tmp_path: Path,
) -> None:
    source = tmp_path / "downloaded-proof.jsonl"
    source.write_bytes(b"trusted-proof\n")
    source.chmod(0o600)
    destination = tmp_path / "published-proof.jsonl"

    with pytest.raises(ValueError, match="digest"):
        replay_module._publish_exact_file(
            destination,
            source,
            expected_bytes=source.stat().st_size,
            expected_sha256=hashlib.sha256(b"altered-proof\n").hexdigest(),
        )
    assert not destination.exists()


def test_target_proof_publication_rejects_multilink_existing_target(
    tmp_path: Path,
) -> None:
    source = tmp_path / "downloaded-proof.jsonl"
    source.write_bytes(b"trusted-proof\n")
    source.chmod(0o600)
    existing = tmp_path / "published-proof.jsonl"
    existing.write_bytes(source.read_bytes())
    existing.chmod(0o600)
    (tmp_path / "published-proof-alias.jsonl").hardlink_to(existing)

    with pytest.raises(ValueError, match="unsafe"):
        replay_module._publish_exact_file(
            existing,
            source,
            expected_bytes=source.stat().st_size,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )


def test_target_proof_publication_does_not_unlink_raced_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "downloaded-proof.jsonl"
    source.write_bytes(b"trusted-proof\n")
    source.chmod(0o600)
    destination = tmp_path / "published-proof.jsonl"
    replacement = b"raced-replacement\n"
    original_link = replay_module.os.link

    def replace_after_link(
        source_name: str,
        destination_name: str,
        **kwargs: object,
    ) -> None:
        original_link(source_name, destination_name, **kwargs)
        destination_parent = kwargs["dst_dir_fd"]
        assert isinstance(destination_parent, int)
        replay_module.os.unlink(
            destination_name,
            dir_fd=destination_parent,
        )
        descriptor = replay_module.os.open(
            destination_name,
            replay_module.os.O_WRONLY | replay_module.os.O_CREAT | replay_module.os.O_EXCL,
            0o600,
            dir_fd=destination_parent,
        )
        try:
            replay_module.os.write(descriptor, replacement)
        finally:
            replay_module.os.close(descriptor)

    monkeypatch.setattr(replay_module.os, "link", replace_after_link)
    with pytest.raises(RuntimeError, match="metadata changed"):
        replay_module._publish_exact_file(
            destination,
            source,
            expected_bytes=source.stat().st_size,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )
    assert destination.read_bytes() == replacement


def test_target_byte_publication_rejects_symlinked_ancestor(
    tmp_path: Path,
) -> None:
    reviewed = tmp_path / "reviewed"
    attacker = tmp_path / "attacker"
    reviewed.mkdir()
    attacker.mkdir()
    (reviewed / "redirect").symlink_to(attacker, target_is_directory=True)
    destination = reviewed / "redirect" / "nested" / "run.json"

    with pytest.raises(ValueError, match="ancestor is unsafe"):
        replay_module._publish_exact_bytes(destination, b"trusted-record")

    assert not (attacker / "nested" / "run.json").exists()


def test_target_byte_publication_cleanup_is_pinned_across_parent_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "outputs"
    parent.mkdir()
    moved_parent = tmp_path / "outputs-original"
    destination = parent / "run.json"
    attacker_payload = b"attacker-temp-winner"
    temporary_name = ""

    def swap_parent_and_win(
        source_name: str | Path,
        _destination_name: str | Path,
        **_kwargs: object,
    ) -> None:
        nonlocal temporary_name
        temporary_name = Path(source_name).name
        parent.rename(moved_parent)
        parent.mkdir()
        (parent / temporary_name).write_bytes(attacker_payload)
        raise FileExistsError("simulated parent-swap race")

    monkeypatch.setattr(replay_module.os, "link", swap_parent_and_win)
    with pytest.raises(ValueError, match="parent changed"):
        replay_module._publish_exact_bytes(destination, b"trusted-record")

    assert (parent / temporary_name).read_bytes() == attacker_payload
    assert not (moved_parent / temporary_name).exists()
    assert not destination.exists()


def test_target_byte_publication_does_not_unlink_replaced_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "run.json"
    attacker_payload = b"attacker-temp-replacement"
    temporary_name = ""
    original_link = replay_module.os.link

    def replace_temporary(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal temporary_name
        if temporary_name:
            original_link(source_name, destination_name, **kwargs)
            return
        temporary_name = Path(source_name).name
        source_parent = kwargs.get("src_dir_fd")
        if isinstance(source_parent, int):
            replay_module.os.unlink(temporary_name, dir_fd=source_parent)
            descriptor = replay_module.os.open(
                temporary_name,
                replay_module.os.O_WRONLY | replay_module.os.O_CREAT | replay_module.os.O_EXCL,
                0o600,
                dir_fd=source_parent,
            )
            try:
                replay_module.os.write(descriptor, attacker_payload)
            finally:
                replay_module.os.close(descriptor)
        else:
            Path(source_name).unlink()
            Path(source_name).write_bytes(attacker_payload)
        raise OSError("simulated temporary replacement")

    monkeypatch.setattr(replay_module.os, "link", replace_temporary)
    with pytest.raises(OSError, match="temporary replacement"):
        replay_module._publish_exact_bytes(destination, b"trusted-record")

    assert (tmp_path / temporary_name).read_bytes() == attacker_payload
    assert not destination.exists()


def test_target_byte_publication_preserves_raced_destination_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "run.json"
    attacker_payload = b"attacker-destination-winner"
    original_link = replay_module.os.link

    def replace_destination_after_link(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        original_link(source_name, destination_name, **kwargs)
        destination_parent = kwargs.get("dst_dir_fd")
        if isinstance(destination_parent, int):
            replay_module.os.unlink(Path(destination_name).name, dir_fd=destination_parent)
            descriptor = replay_module.os.open(
                Path(destination_name).name,
                replay_module.os.O_WRONLY | replay_module.os.O_CREAT | replay_module.os.O_EXCL,
                0o600,
                dir_fd=destination_parent,
            )
            try:
                replay_module.os.write(descriptor, attacker_payload)
            finally:
                replay_module.os.close(descriptor)
        else:
            Path(destination_name).unlink()
            Path(destination_name).write_bytes(attacker_payload)

    monkeypatch.setattr(replay_module.os, "link", replace_destination_after_link)
    with pytest.raises(RuntimeError, match="metadata changed"):
        replay_module._publish_exact_bytes(destination, b"trusted-record")

    assert destination.read_bytes() == attacker_payload


def test_target_artifact_publication_preflights_all_four_before_writing(
    tmp_path: Path,
) -> None:
    record, attestation, signature, proof_source = _target_artifact_publication_inputs(tmp_path)
    output = tmp_path / "outputs"
    output.mkdir()
    record_path = output / "run.json"
    attestation_path = output / "run.attestation.json"
    signature_path = output / "run.attestation.sig"
    proof_path = output / "run.proof.jsonl"
    attacker = tmp_path / "attacker-proof"
    attacker.write_bytes(b"attacker-proof")
    proof_path.symlink_to(attacker)

    with pytest.raises(ValueError, match="unsafe"):
        replay_module._write_new_target_artifacts(
            record_path=record_path,
            attestation_path=attestation_path,
            signature_path=signature_path,
            proof_path=proof_path,
            proof_source=proof_source,
            record=record,
            attestation=attestation,
            signature=signature,
        )

    assert not record_path.exists()
    assert not attestation_path.exists()
    assert not signature_path.exists()
    assert proof_path.is_symlink()
    assert attacker.read_bytes() == b"attacker-proof"


def test_target_artifact_publication_rejects_redirected_ancestor_before_writing(
    tmp_path: Path,
) -> None:
    record, attestation, signature, proof_source = _target_artifact_publication_inputs(tmp_path)
    reviewed = tmp_path / "reviewed"
    attacker = tmp_path / "attacker"
    safe = tmp_path / "safe"
    reviewed.mkdir()
    attacker.mkdir()
    safe.mkdir()
    (reviewed / "redirect").symlink_to(attacker, target_is_directory=True)
    record_path = reviewed / "redirect" / "run.json"
    attestation_path = safe / "run.attestation.json"
    signature_path = safe / "run.attestation.sig"
    proof_path = safe / "run.proof.jsonl"

    with pytest.raises(ValueError, match="ancestor is unsafe"):
        replay_module._write_new_target_artifacts(
            record_path=record_path,
            attestation_path=attestation_path,
            signature_path=signature_path,
            proof_path=proof_path,
            proof_source=proof_source,
            record=record,
            attestation=attestation,
            signature=signature,
        )

    assert not (attacker / "run.json").exists()
    assert not attestation_path.exists()
    assert not signature_path.exists()
    assert not proof_path.exists()


def test_target_artifact_publication_supports_four_pinned_mixed_parents(
    tmp_path: Path,
) -> None:
    record, attestation, signature, proof_source = _target_artifact_publication_inputs(tmp_path)
    parents = tuple(tmp_path / f"output-{index}" for index in range(4))
    for parent in parents:
        parent.mkdir()
    paths = tuple(parent / "artifact" for parent in parents)

    replay_module._write_new_target_artifacts(
        record_path=paths[0],
        attestation_path=paths[1],
        signature_path=paths[2],
        proof_path=paths[3],
        proof_source=proof_source,
        record=record,
        attestation=attestation,
        signature=signature,
    )

    published_identities = tuple((path.stat().st_dev, path.stat().st_ino) for path in paths)
    replay_module._write_new_target_artifacts(
        record_path=paths[0],
        attestation_path=paths[1],
        signature_path=paths[2],
        proof_path=paths[3],
        proof_source=proof_source,
        record=record,
        attestation=attestation,
        signature=signature,
    )

    expected = (
        json.dumps(
            record.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode(),
        json.dumps(
            attestation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode(),
        signature,
        proof_source.read_bytes(),
    )
    for path, payload in zip(paths, expected, strict=True):
        metadata = path.stat()
        assert path.read_bytes() == payload
        assert metadata.st_mode & 0o777 == 0o600
        assert metadata.st_uid == replay_module.os.geteuid()
        assert metadata.st_nlink == 1
        assert metadata.st_dev == path.parent.stat().st_dev
    assert tuple((path.stat().st_dev, path.stat().st_ino) for path in paths) == (
        published_identities
    )


@pytest.mark.parametrize("failed_write", (2, 3, 4))
def test_target_artifact_publication_stages_all_four_before_linking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_write: int,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)
    original_write = replay_module.os.write
    writes = 0

    def fail_selected_stage(descriptor: int, payload: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == failed_write:
            raise OSError(f"simulated stage {failed_write} failure")
        return original_write(descriptor, payload)

    monkeypatch.setattr(replay_module.os, "write", fail_selected_stage)
    with pytest.raises(OSError, match=f"stage {failed_write} failure"):
        _publish_target_artifacts(paths, inputs)

    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize("failed_link", (2, 3, 4))
def test_target_artifact_publication_rolls_back_after_link_failure_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_link: int,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)
    original_link = replay_module.os.link
    links = 0

    def fail_selected_link(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal links
        links += 1
        if links == failed_link:
            raise OSError(f"simulated link {failed_link} failure")
        original_link(source_name, destination_name, **kwargs)

    monkeypatch.setattr(replay_module.os, "link", fail_selected_link)
    with pytest.raises(OSError, match=f"link {failed_link} failure"):
        _publish_target_artifacts(paths, inputs)
    assert all(not path.exists() for path in paths)

    monkeypatch.setattr(replay_module.os, "link", original_link)
    _publish_target_artifacts(paths, inputs)
    published_identities = tuple((path.stat().st_dev, path.stat().st_ino) for path in paths)
    _publish_target_artifacts(paths, inputs)
    assert tuple((path.stat().st_dev, path.stat().st_ino) for path in paths) == (
        published_identities
    )


def test_target_artifact_publication_preserves_preexisting_exact_outputs_on_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    payloads = _target_artifact_payloads(*inputs)
    preexisting_indices = (0, 2)
    for index in preexisting_indices:
        paths[index].write_bytes(payloads[index])
        paths[index].chmod(0o600)
    preexisting_identities = {
        index: (paths[index].stat().st_dev, paths[index].stat().st_ino)
        for index in preexisting_indices
    }
    original_link = replay_module.os.link
    links = 0

    def fail_second_missing_link(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal links
        links += 1
        if links == 2:
            raise OSError("simulated later artifact failure")
        original_link(source_name, destination_name, **kwargs)

    monkeypatch.setattr(replay_module.os, "link", fail_second_missing_link)
    with pytest.raises(OSError, match="later artifact failure"):
        _publish_target_artifacts(paths, inputs)

    for index in preexisting_indices:
        assert paths[index].read_bytes() == payloads[index]
        assert (paths[index].stat().st_dev, paths[index].stat().st_ino) == (
            preexisting_identities[index]
        )
    assert not paths[1].exists()
    assert not paths[3].exists()


@pytest.mark.parametrize("swapped_index", range(4))
def test_target_artifact_publication_rolls_back_in_pinned_swapped_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swapped_index: int,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    original_parents = tuple(path.parent for path in paths)
    moved_parent = tmp_path / f"moved-output-{swapped_index}"
    attacker_payload = f"attacker-{swapped_index}".encode()
    original_link = replay_module.os.link
    links = 0

    def swap_parent_after_selected_link(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal links
        original_link(source_name, destination_name, **kwargs)
        links += 1
        if links != swapped_index + 1:
            return
        original_parents[swapped_index].rename(moved_parent)
        original_parents[swapped_index].mkdir(mode=0o700)
        attacker = original_parents[swapped_index] / Path(destination_name).name
        attacker.write_bytes(attacker_payload)
        attacker.chmod(0o600)

    monkeypatch.setattr(replay_module.os, "link", swap_parent_after_selected_link)
    with pytest.raises(ValueError, match="parent changed"):
        _publish_target_artifacts(paths, inputs)

    assert paths[swapped_index].read_bytes() == attacker_payload
    assert not (moved_parent / paths[swapped_index].name).exists()
    assert all(not path.exists() for index, path in enumerate(paths) if index != swapped_index)


def test_target_artifact_publication_preserves_replaced_temporary_on_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)
    attacker_payload = b"attacker-batch-temporary"
    temporary_name = ""
    original_link = replay_module.os.link
    original_unlink = replay_module.os.unlink

    def replace_first_temporary_after_link(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal temporary_name
        original_link(source_name, destination_name, **kwargs)
        if temporary_name:
            return
        temporary_name = Path(source_name).name
        parent_descriptor = kwargs["src_dir_fd"]
        assert isinstance(parent_descriptor, int)
        original_unlink(temporary_name, dir_fd=parent_descriptor)
        descriptor = replay_module.os.open(
            temporary_name,
            replay_module.os.O_WRONLY | replay_module.os.O_CREAT | replay_module.os.O_EXCL,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            replay_module.os.write(descriptor, attacker_payload)
        finally:
            replay_module.os.close(descriptor)

    monkeypatch.setattr(
        replay_module.os,
        "link",
        replace_first_temporary_after_link,
    )
    with pytest.raises(RuntimeError, match="temporary changed"):
        _publish_target_artifacts(paths, inputs)

    assert (paths[0].parent / temporary_name).read_bytes() == attacker_payload
    assert all(not path.exists() for path in paths)


def test_target_artifact_publication_preserves_raced_destination_on_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)
    attacker_payload = b"attacker-batch-destination"
    original_link = replay_module.os.link
    original_unlink = replay_module.os.unlink
    replaced = False

    def replace_first_destination_after_link(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal replaced
        original_link(source_name, destination_name, **kwargs)
        if replaced:
            return
        replaced = True
        parent_descriptor = kwargs["dst_dir_fd"]
        assert isinstance(parent_descriptor, int)
        original_unlink(Path(destination_name).name, dir_fd=parent_descriptor)
        descriptor = replay_module.os.open(
            Path(destination_name).name,
            replay_module.os.O_WRONLY | replay_module.os.O_CREAT | replay_module.os.O_EXCL,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            replay_module.os.write(descriptor, attacker_payload)
        finally:
            replay_module.os.close(descriptor)

    monkeypatch.setattr(
        replay_module.os,
        "link",
        replace_first_destination_after_link,
    )
    with pytest.raises(RuntimeError, match="metadata changed"):
        _publish_target_artifacts(paths, inputs)

    assert paths[0].read_bytes() == attacker_payload
    assert all(not path.exists() for path in paths[1:])


def test_target_artifact_publication_rolls_back_new_finals_in_reverse_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)
    final_names = tuple(path.name for path in paths)
    parent_identity = (paths[0].parent.stat().st_dev, paths[0].parent.stat().st_ino)
    original_fsync = replay_module.os.fsync
    original_rename = replay_module.os.rename
    directory_fsyncs = 0
    rollback_order: list[str] = []

    def fail_fourth_directory_fsync(descriptor: int) -> None:
        nonlocal directory_fsyncs
        metadata = replay_module.os.fstat(descriptor)
        if (
            replay_module.stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == parent_identity
        ):
            directory_fsyncs += 1
            if directory_fsyncs == 4:
                raise OSError("simulated fourth directory fsync failure")
        original_fsync(descriptor)

    def record_final_quarantine(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        leaf = Path(source_name).name
        if leaf in final_names:
            rollback_order.append(leaf)
        original_rename(source_name, destination_name, **kwargs)

    monkeypatch.setattr(replay_module.os, "fsync", fail_fourth_directory_fsync)
    monkeypatch.setattr(replay_module.os, "rename", record_final_quarantine)
    with pytest.raises(OSError, match="fourth directory fsync failure"):
        _publish_target_artifacts(paths, inputs)

    assert rollback_order == list(reversed(final_names))
    assert all(not path.exists() for path in paths)


def test_target_artifact_publication_surfaces_rollback_errors_after_all_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)
    final_names = tuple(path.name for path in paths)
    parent_identity = (paths[0].parent.stat().st_dev, paths[0].parent.stat().st_ino)
    original_fsync = replay_module.os.fsync
    original_rename = replay_module.os.rename
    directory_fsyncs = 0
    rollback_order: list[str] = []

    def fail_fourth_directory_fsync(descriptor: int) -> None:
        nonlocal directory_fsyncs
        metadata = replay_module.os.fstat(descriptor)
        if (
            replay_module.stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == parent_identity
        ):
            directory_fsyncs += 1
            if directory_fsyncs == 4:
                raise OSError("simulated publication failure")
        original_fsync(descriptor)

    def fail_one_rollback_quarantine(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        leaf = Path(source_name).name
        if leaf in final_names:
            rollback_order.append(leaf)
            if leaf == final_names[-1]:
                raise OSError("simulated rollback rename failure")
        original_rename(source_name, destination_name, **kwargs)

    monkeypatch.setattr(replay_module.os, "fsync", fail_fourth_directory_fsync)
    monkeypatch.setattr(
        replay_module.os,
        "rename",
        fail_one_rollback_quarantine,
    )
    with pytest.raises(BaseExceptionGroup) as raised:
        _publish_target_artifacts(paths, inputs)

    assert rollback_order == list(reversed(final_names))
    assert any("publication failure" in str(error) for error in raised.value.exceptions)
    assert any("rollback rename failure" in str(error) for error in raised.value.exceptions)
    assert paths[-1].exists()
    assert all(not path.exists() for path in paths[:-1])


@pytest.mark.parametrize("failed_link_index", range(4))
def test_target_artifact_ambiguous_link_and_probe_failure_rolls_back_potential_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_link_index: int,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    original_link = replay_module.os.link
    original_stat = replay_module.os.stat
    links = 0
    ambiguous_created = False
    probe_failed = False

    def create_then_raise(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal links, ambiguous_created
        links += 1
        original_link(source_name, destination_name, **kwargs)
        if links == failed_link_index + 1:
            ambiguous_created = True
            raise OSError("simulated ambiguous link completion")

    def fail_first_ownership_probe(
        name: str | Path,
        **kwargs: object,
    ) -> object:
        nonlocal probe_failed
        if (
            ambiguous_created
            and not probe_failed
            and Path(name).name == paths[failed_link_index].name
        ):
            probe_failed = True
            raise OSError("simulated ownership probe failure")
        return original_stat(name, **kwargs)

    monkeypatch.setattr(replay_module.os, "link", create_then_raise)
    monkeypatch.setattr(replay_module.os, "stat", fail_first_ownership_probe)
    with pytest.raises(BaseExceptionGroup) as raised:
        _publish_target_artifacts(paths, inputs)

    messages = _exception_messages(raised.value)
    assert any("ambiguous link completion" in item for item in messages)
    assert any("ownership probe failure" in item for item in messages)
    assert probe_failed
    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize("replaced_index", range(4))
def test_target_artifact_rollback_quarantines_before_ownership_check_and_restores_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replaced_index: int,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    selected = paths[replaced_index]
    selected_parent_identity = (
        selected.parent.stat().st_dev,
        selected.parent.stat().st_ino,
    )
    publication_parent_identities = {
        (path.parent.stat().st_dev, path.parent.stat().st_ino) for path in paths
    }
    attacker_payload = f"attacker-rollback-{replaced_index}".encode()
    original_fsync = replay_module.os.fsync
    original_rename = replay_module.os.rename
    original_unlink = replay_module.os.unlink
    directory_fsyncs = 0
    replaced = False
    restored_parent_fsynced = False

    def fail_fourth_publication_fsync(descriptor: int) -> None:
        nonlocal directory_fsyncs, restored_parent_fsynced
        metadata = replay_module.os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            replay_module.stat.S_ISDIR(metadata.st_mode)
            and identity in publication_parent_identities
        ):
            directory_fsyncs += 1
            if directory_fsyncs == 4:
                raise OSError("simulated publication durability failure")
            if replaced and identity == selected_parent_identity:
                restored_parent_fsynced = True
        original_fsync(descriptor)

    def replace_immediately_before_quarantine(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal replaced
        source_parent = kwargs.get("src_dir_fd")
        if (
            not replaced
            and isinstance(source_parent, int)
            and Path(source_name).name == selected.name
            and (
                replay_module.os.fstat(source_parent).st_dev,
                replay_module.os.fstat(source_parent).st_ino,
            )
            == selected_parent_identity
        ):
            original_unlink(source_name, dir_fd=source_parent)
            descriptor = replay_module.os.open(
                source_name,
                replay_module.os.O_WRONLY | replay_module.os.O_CREAT | replay_module.os.O_EXCL,
                0o600,
                dir_fd=source_parent,
            )
            try:
                replay_module.os.write(descriptor, attacker_payload)
            finally:
                replay_module.os.close(descriptor)
            replaced = True
        original_rename(source_name, destination_name, **kwargs)

    monkeypatch.setattr(replay_module.os, "fsync", fail_fourth_publication_fsync)
    monkeypatch.setattr(
        replay_module.os,
        "rename",
        replace_immediately_before_quarantine,
    )
    with pytest.raises(OSError, match="publication durability failure"):
        _publish_target_artifacts(paths, inputs)

    assert replaced
    assert selected.read_bytes() == attacker_payload
    assert restored_parent_fsynced
    assert all(not path.exists() for index, path in enumerate(paths) if index != replaced_index)
    assert not tuple(selected.parent.glob(".kuzet-output-quarantine-*"))


def test_target_artifact_publication_source_revalidation_failure_exposes_no_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)

    def reject_changed_source(
        _descriptor: int,
        _expected: tuple[int, int, int, int, int, int],
    ) -> None:
        raise RuntimeError("simulated source identity change")

    monkeypatch.setattr(
        replay_module,
        "_require_source_unchanged",
        reject_changed_source,
    )
    with pytest.raises(RuntimeError, match="source identity change"):
        _publish_target_artifacts(paths, inputs)

    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize("replaced_index", range(4))
def test_target_artifact_final_validation_binds_hashed_inode_to_current_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replaced_index: int,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    payloads = _target_artifact_payloads(*inputs)
    for path, payload in zip(paths, payloads, strict=True):
        path.write_bytes(payload)
        path.chmod(0o600)
    selected = paths[replaced_index]
    original_validate = replay_module._validate_existing_output
    original_read = replay_module.os.read
    validation_calls = 0
    armed = False
    replaced = False
    aside = selected.parent / f"{selected.name}.validated-aside"
    wrong_payload = bytes([payloads[replaced_index][0] ^ 0xFF]) + payloads[replaced_index][1:]

    def arm_final_validation(target: object) -> bool:
        nonlocal validation_calls, armed
        if target.path == selected:
            validation_calls += 1
            if validation_calls == 3:
                armed = True
        try:
            return original_validate(target)
        finally:
            armed = False

    def replace_leaf_after_hash(descriptor: int, limit: int) -> bytes:
        nonlocal replaced
        chunk = original_read(descriptor, limit)
        if armed and not chunk and not replaced:
            selected.rename(aside)
            selected.write_bytes(wrong_payload)
            selected.chmod(0o600)
            replaced = True
        return chunk

    monkeypatch.setattr(
        replay_module,
        "_validate_existing_output",
        arm_final_validation,
    )
    monkeypatch.setattr(replay_module.os, "read", replace_leaf_after_hash)

    with pytest.raises(RuntimeError, match="leaf binding"):
        _publish_target_artifacts(paths, inputs)

    assert replaced
    assert aside.read_bytes() == payloads[replaced_index]
    assert selected.read_bytes() == wrong_payload


@pytest.mark.parametrize("winner_index", range(4))
def test_target_artifact_exact_race_winner_fsyncs_then_revalidates_pinned_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    winner_index: int,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    winner_parent_identity = (
        paths[winner_index].parent.stat().st_dev,
        paths[winner_index].parent.stat().st_ino,
    )
    original_link = replay_module.os.link
    original_rename = replay_module.os.rename
    original_fsync = replay_module.os.fsync
    original_stat = replay_module.os.stat
    original_revalidate = replay_module._revalidate_output_parent
    links = 0
    cleanup_complete = False
    winner_file_identity: tuple[int, int] | None = None
    events: list[str] = []

    def exact_concurrent_winner(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal links, winner_file_identity
        links += 1
        if links != winner_index + 1:
            original_link(source_name, destination_name, **kwargs)
            return
        source_parent = kwargs["src_dir_fd"]
        destination_parent = kwargs["dst_dir_fd"]
        assert isinstance(source_parent, int)
        assert isinstance(destination_parent, int)
        source_descriptor = replay_module.os.open(
            source_name,
            replay_module.os.O_RDONLY,
            dir_fd=source_parent,
        )
        try:
            payload = b""
            while chunk := replay_module.os.read(source_descriptor, 1024 * 1024):
                payload += chunk
        finally:
            replay_module.os.close(source_descriptor)
        destination_descriptor = replay_module.os.open(
            destination_name,
            replay_module.os.O_WRONLY | replay_module.os.O_CREAT | replay_module.os.O_EXCL,
            0o600,
            dir_fd=destination_parent,
        )
        try:
            view = memoryview(payload)
            while view:
                written = replay_module.os.write(destination_descriptor, view)
                assert written > 0
                view = view[written:]
            winner = replay_module.os.fstat(destination_descriptor)
            winner_file_identity = (winner.st_dev, winner.st_ino)
        finally:
            replay_module.os.close(destination_descriptor)
        raise FileExistsError("simulated exact concurrent winner")

    def record_winner_quarantine(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal cleanup_complete
        descriptor = kwargs.get("src_dir_fd")
        is_winner_temporary = (
            isinstance(descriptor, int)
            and Path(source_name).name.startswith(f".{paths[winner_index].name}.tmp-")
            and (
                replay_module.os.fstat(descriptor).st_dev,
                replay_module.os.fstat(descriptor).st_ino,
            )
            == winner_parent_identity
        )
        original_rename(source_name, destination_name, **kwargs)
        if is_winner_temporary:
            cleanup_complete = True
            events.append("cleanup")

    def record_parent_fsync(descriptor: int) -> None:
        metadata = replay_module.os.fstat(descriptor)
        if (
            winner_file_identity is not None
            and replay_module.stat.S_ISREG(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == winner_file_identity
            and "file-fsync" not in events
        ):
            events.append("file-fsync")
        if (
            cleanup_complete
            and replay_module.stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == winner_parent_identity
            and "parent-fsync" not in events
        ):
            events.append("parent-fsync")
        original_fsync(descriptor)

    def record_parent_revalidation(
        path: Path,
        descriptor: int,
        expected: object,
    ) -> None:
        if cleanup_complete and path == paths[winner_index] and "parent-revalidate" not in events:
            events.append("parent-revalidate")
        original_revalidate(path, descriptor, expected)

    def record_leaf_binding(
        name: str | Path,
        **kwargs: object,
    ) -> object:
        metadata = original_stat(name, **kwargs)
        descriptor = kwargs.get("dir_fd")
        if (
            winner_file_identity is not None
            and isinstance(descriptor, int)
            and Path(name).name == paths[winner_index].name
            and (
                replay_module.os.fstat(descriptor).st_dev,
                replay_module.os.fstat(descriptor).st_ino,
            )
            == winner_parent_identity
            and (metadata.st_dev, metadata.st_ino) == winner_file_identity
            and "parent-revalidate" in events
            and "leaf-binding" not in events
        ):
            events.append("leaf-binding")
        return metadata

    monkeypatch.setattr(replay_module.os, "link", exact_concurrent_winner)
    monkeypatch.setattr(replay_module.os, "rename", record_winner_quarantine)
    monkeypatch.setattr(replay_module.os, "fsync", record_parent_fsync)
    monkeypatch.setattr(replay_module.os, "stat", record_leaf_binding)
    monkeypatch.setattr(
        replay_module,
        "_revalidate_output_parent",
        record_parent_revalidation,
    )

    _publish_target_artifacts(paths, inputs)

    assert events[:5] == [
        "file-fsync",
        "cleanup",
        "parent-fsync",
        "parent-revalidate",
        "leaf-binding",
    ]
    assert all(path.exists() for path in paths)


def test_target_artifact_exact_winner_rebinds_the_hashed_fsynced_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"exact-concurrent-winner"
    wrong_payload = b"X" * len(payload)
    destination = tmp_path / "run.json"
    targets = replay_module._preflight_output_targets(
        (
            (
                destination,
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            ),
        )
    )
    staged = replay_module._stage_chunks_for_batch(targets[0], (payload,))
    assert staged is not None
    original_link = replay_module.os.link
    original_open_validated = replay_module._open_validated_existing_output
    mutated = False
    newly_linked: list[object] = []

    def create_exact_concurrent_winner(
        _source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        destination_parent = kwargs["dst_dir_fd"]
        assert isinstance(destination_parent, int)
        descriptor = replay_module.os.open(
            destination_name,
            replay_module.os.O_WRONLY | replay_module.os.O_CREAT | replay_module.os.O_EXCL,
            0o600,
            dir_fd=destination_parent,
        )
        try:
            replay_module.os.write(descriptor, payload)
        finally:
            replay_module.os.close(descriptor)
        raise FileExistsError("simulated exact concurrent winner")

    def mutate_after_validated_open(target: object) -> object:
        nonlocal mutated
        opened = original_open_validated(target)
        if opened is None:
            return None
        descriptor = opened[0] if isinstance(opened, tuple) else opened
        assert isinstance(descriptor, int)
        writer = replay_module.os.open(
            target.path.name,
            replay_module.os.O_WRONLY,
            dir_fd=target.parent_descriptor,
        )
        try:
            replay_module.os.write(writer, wrong_payload)
        finally:
            replay_module.os.close(writer)
        mutated = True
        return opened

    monkeypatch.setattr(
        replay_module.os,
        "link",
        create_exact_concurrent_winner,
    )
    monkeypatch.setattr(
        replay_module,
        "_open_validated_existing_output",
        mutate_after_validated_open,
    )
    try:
        with pytest.raises(RuntimeError, match="leaf binding"):
            replay_module._publish_staged_output(
                staged,
                newly_linked,
            )
    finally:
        monkeypatch.setattr(replay_module.os, "link", original_link)
        replay_module._rollback_new_outputs(newly_linked)
        replay_module._close_staged_outputs([staged])
        replay_module._close_output_targets(targets)

    assert mutated
    assert destination.read_bytes() == wrong_payload


def test_target_artifact_preflight_preserves_primary_and_closes_every_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)
    attacker = tmp_path / "attacker-proof"
    attacker.write_bytes(b"attacker-proof")
    paths[-1].symlink_to(attacker)
    original_close = replay_module.os.close
    directory_close_attempts = 0

    def fail_first_directory_close(descriptor: int) -> None:
        nonlocal directory_close_attempts
        metadata = replay_module.os.fstat(descriptor)
        is_directory = replay_module.stat.S_ISDIR(metadata.st_mode)
        if is_directory:
            directory_close_attempts += 1
        original_close(descriptor)
        if is_directory and directory_close_attempts == 1:
            raise OSError("simulated preflight parent close failure")

    monkeypatch.setattr(replay_module.os, "close", fail_first_directory_close)
    with pytest.raises(BaseExceptionGroup) as raised:
        _publish_target_artifacts(paths, inputs)

    messages = _exception_messages(raised.value)
    assert any("preexisting target acceptance output is unsafe" in item for item in messages)
    assert any("preflight parent close failure" in item for item in messages)
    assert directory_close_attempts == 4


def test_target_artifact_preflight_leaf_close_preserves_validation_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path)
    paths[0].write_bytes(b"wrong-preexisting-record")
    paths[0].chmod(0o600)
    leaf_identity = (paths[0].stat().st_dev, paths[0].stat().st_ino)
    original_close = replay_module.os.close
    failed = False

    def fail_validation_leaf_close(descriptor: int) -> None:
        nonlocal failed
        metadata = replay_module.os.fstat(descriptor)
        is_leaf = (metadata.st_dev, metadata.st_ino) == leaf_identity
        original_close(descriptor)
        if is_leaf and not failed:
            failed = True
            raise OSError("simulated validation leaf close failure")

    monkeypatch.setattr(replay_module.os, "close", fail_validation_leaf_close)
    with pytest.raises(BaseExceptionGroup) as raised:
        _publish_target_artifacts(paths, inputs)

    messages = _exception_messages(raised.value)
    assert any("preexisting target acceptance output is unsafe" in item for item in messages)
    assert any("validation leaf close failure" in item for item in messages)


def test_target_artifact_parent_open_close_preserves_identity_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    target_parent = paths[0].parent
    parent_identity = (target_parent.stat().st_dev, target_parent.stat().st_ino)
    original_lstat = replay_module.Path.lstat
    original_close = replay_module.os.close
    parent_lstat_calls = 0

    def substitute_parent_identity(path: Path) -> object:
        nonlocal parent_lstat_calls
        metadata = original_lstat(path)
        if path != target_parent:
            return metadata
        parent_lstat_calls += 1
        if parent_lstat_calls != 3:
            return metadata
        fields = list(metadata)
        fields[1] += 1
        return replay_module.os.stat_result(fields)

    def fail_changed_parent_close(descriptor: int) -> None:
        metadata = replay_module.os.fstat(descriptor)
        is_target_parent = (
            replay_module.stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == parent_identity
            and parent_lstat_calls >= 3
        )
        original_close(descriptor)
        if is_target_parent:
            raise OSError("simulated changed-parent close failure")

    monkeypatch.setattr(replay_module.Path, "lstat", substitute_parent_identity)
    monkeypatch.setattr(replay_module.os, "close", fail_changed_parent_close)
    with pytest.raises(BaseExceptionGroup) as raised:
        _publish_target_artifacts(paths, inputs)

    messages = _exception_messages(raised.value)
    assert any("target acceptance output parent changed" in item for item in messages)
    assert any("changed-parent close failure" in item for item in messages)


@pytest.mark.parametrize("failure_kind", ("fstat", "lstat"))
def test_target_artifact_parent_post_open_failure_always_closes_and_groups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    target_parent = paths[0].parent
    original_open = replay_module.os.open
    original_fstat = replay_module.os.fstat
    original_lstat = replay_module.Path.lstat
    original_close = replay_module.os.close
    parent_descriptor: int | None = None
    parent_lstat_calls = 0
    close_attempted = False

    def capture_parent_descriptor(
        path: str | Path,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal parent_descriptor
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path) == target_parent and kwargs.get("dir_fd") is None:
            parent_descriptor = descriptor
        return descriptor

    def fail_parent_fstat(descriptor: int) -> object:
        if failure_kind == "fstat" and descriptor == parent_descriptor:
            raise OSError("simulated post-open parent fstat failure")
        return original_fstat(descriptor)

    def fail_parent_lstat(path: Path) -> object:
        nonlocal parent_lstat_calls
        metadata = original_lstat(path)
        if path == target_parent:
            parent_lstat_calls += 1
            if failure_kind == "lstat" and parent_lstat_calls == 3:
                raise OSError("simulated post-open parent lstat failure")
        return metadata

    def fail_parent_close(descriptor: int) -> None:
        nonlocal close_attempted
        is_parent = descriptor == parent_descriptor
        original_close(descriptor)
        if is_parent:
            close_attempted = True
            raise OSError("simulated post-open parent close failure")

    monkeypatch.setattr(replay_module.os, "open", capture_parent_descriptor)
    monkeypatch.setattr(replay_module.os, "fstat", fail_parent_fstat)
    monkeypatch.setattr(replay_module.Path, "lstat", fail_parent_lstat)
    monkeypatch.setattr(replay_module.os, "close", fail_parent_close)
    with pytest.raises(BaseExceptionGroup) as raised:
        _publish_target_artifacts(paths, inputs)

    messages = _exception_messages(raised.value)
    assert any(f"parent {failure_kind} failure" in item for item in messages)
    assert any("post-open parent close failure" in item for item in messages)
    assert close_attempted


def test_target_artifact_winner_post_open_fstat_failure_closes_and_groups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"staged-target-artifact"
    destination = tmp_path / "run.json"
    targets = replay_module._preflight_output_targets(
        (
            (
                destination,
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            ),
        )
    )
    staged = replay_module._stage_chunks_for_batch(targets[0], (payload,))
    assert staged is not None
    winner_path = tmp_path / "winner.json"
    winner_path.write_bytes(payload)
    winner_path.chmod(0o600)
    winner_descriptor = replay_module.os.open(
        winner_path,
        replay_module.os.O_RDONLY,
    )
    original_fstat = replay_module.os.fstat
    original_close = replay_module.os.close
    winner_close_attempted = False

    def fail_publication_link(*_args: object, **_kwargs: object) -> None:
        raise FileExistsError("simulated concurrent winner")

    def return_open_winner(_target: object) -> tuple[int, object]:
        return winner_descriptor, original_fstat(winner_descriptor)

    def reject_winner_fstat(descriptor: int) -> object:
        if descriptor == winner_descriptor:
            raise OSError("simulated winner fstat failure")
        return original_fstat(descriptor)

    def fail_winner_close(descriptor: int) -> None:
        nonlocal winner_close_attempted
        original_close(descriptor)
        if descriptor == winner_descriptor and not winner_close_attempted:
            winner_close_attempted = True
            raise OSError("simulated winner close failure")

    monkeypatch.setattr(replay_module.os, "link", fail_publication_link)
    monkeypatch.setattr(replay_module, "_name_is_owned_output", lambda *_args: False)
    monkeypatch.setattr(
        replay_module,
        "_open_validated_existing_output",
        return_open_winner,
    )
    monkeypatch.setattr(replay_module.os, "fstat", reject_winner_fstat)
    monkeypatch.setattr(replay_module.os, "close", fail_winner_close)
    try:
        with pytest.raises(BaseExceptionGroup) as raised:
            replay_module._publish_staged_output(staged, [])
    finally:
        monkeypatch.setattr(replay_module.os, "fstat", original_fstat)
        monkeypatch.setattr(replay_module.os, "close", original_close)
        if not winner_close_attempted:
            original_close(winner_descriptor)
        replay_module._close_staged_outputs([staged])
        replay_module._close_output_targets(targets)

    messages = _exception_messages(raised.value)
    assert any("winner fstat failure" in item for item in messages)
    assert any("winner close failure" in item for item in messages)
    assert winner_close_attempted


def test_target_artifact_rollback_restores_quarantined_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"runner-owned-target"
    destination = tmp_path / "run.json"
    targets = replay_module._preflight_output_targets(
        (
            (
                destination,
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            ),
        )
    )
    staged = replay_module._stage_chunks_for_batch(targets[0], (payload,))
    assert staged is not None
    replay_module.os.link(
        staged.temporary_name,
        destination.name,
        src_dir_fd=targets[0].parent_descriptor,
        dst_dir_fd=targets[0].parent_descriptor,
        follow_symlinks=False,
    )
    original_rename = replay_module.os.rename
    original_unlink = replay_module.os.unlink
    replaced = False
    attacker_identity: tuple[int, int] | None = None

    def replace_final_with_directory_before_quarantine(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal replaced, attacker_identity
        if (
            not replaced
            and Path(source_name).name == destination.name
            and kwargs.get("src_dir_fd") == targets[0].parent_descriptor
        ):
            original_unlink(
                destination.name,
                dir_fd=targets[0].parent_descriptor,
            )
            destination.mkdir(mode=0o700)
            (destination / "marker").write_bytes(b"attacker-directory")
            metadata = destination.stat()
            attacker_identity = (metadata.st_dev, metadata.st_ino)
            replaced = True
        original_rename(source_name, destination_name, **kwargs)

    monkeypatch.setattr(
        replay_module.os,
        "rename",
        replace_final_with_directory_before_quarantine,
    )
    try:
        assert (
            replay_module._remove_owned_output_name(
                targets[0],
                destination.name,
                staged.descriptor,
            )
            is False
        )
        restored = destination.stat()
        assert (restored.st_dev, restored.st_ino) == attacker_identity
        assert (destination / "marker").read_bytes() == b"attacker-directory"
        assert not tuple(tmp_path.glob(".kuzet-output-quarantine-*"))
    finally:
        monkeypatch.setattr(replay_module.os, "rename", original_rename)
        replay_module._close_staged_outputs([staged])
        replay_module._close_output_targets(targets)

    assert replaced


def test_target_artifact_quarantine_open_failure_removes_empty_runner_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"runner-owned-temporary"
    destination = tmp_path / "run.json"
    targets = replay_module._preflight_output_targets(
        (
            (
                destination,
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            ),
        )
    )
    staged = replay_module._stage_chunks_for_batch(targets[0], (payload,))
    assert staged is not None
    original_open = replay_module.os.open
    original_unlink = replay_module.os.unlink
    original_close = replay_module.os.close
    original_rmdir = replay_module.os.rmdir

    def fail_quarantine_open(
        path: str | Path,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        if (
            Path(path).name.startswith(".kuzet-output-quarantine-")
            and kwargs.get("dir_fd") == targets[0].parent_descriptor
        ):
            raise OSError("simulated quarantine open failure")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(replay_module.os, "open", fail_quarantine_open)
    try:
        with pytest.raises(OSError, match="quarantine open failure"):
            replay_module._remove_owned_output_name(
                targets[0],
                staged.temporary_name,
                staged.descriptor,
            )
        assert not tuple(tmp_path.glob(".kuzet-output-quarantine-*"))
    finally:
        for quarantine in tmp_path.glob(".kuzet-output-quarantine-*"):
            original_rmdir(
                quarantine.name,
                dir_fd=targets[0].parent_descriptor,
            )
        original_unlink(
            staged.temporary_name,
            dir_fd=targets[0].parent_descriptor,
        )
        original_close(staged.descriptor)
        replay_module._close_output_targets(targets)


def test_target_artifact_stage_cleanup_preserves_primary_unlink_and_close_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    original_write = replay_module.os.write
    original_unlink = replay_module.os.unlink
    original_close = replay_module.os.close
    writes = 0
    failed_descriptor: int | None = None

    def fail_second_stage_write(descriptor: int, payload: bytes) -> int:
        nonlocal writes, failed_descriptor
        writes += 1
        if writes == 2:
            failed_descriptor = descriptor
            raise OSError("simulated second stage write failure")
        return original_write(descriptor, payload)

    def fail_failed_stage_unlink(name: str | Path, **kwargs: object) -> None:
        descriptor = kwargs.get("dir_fd")
        if failed_descriptor is not None and isinstance(descriptor, int):
            current = replay_module.os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            failed = replay_module.os.fstat(failed_descriptor)
            if (current.st_dev, current.st_ino) == (failed.st_dev, failed.st_ino):
                raise OSError("simulated failed-stage unlink cleanup failure")
        original_unlink(name, **kwargs)

    def fail_failed_stage_close(descriptor: int) -> None:
        original_close(descriptor)
        if descriptor == failed_descriptor:
            raise OSError("simulated failed-stage close cleanup failure")

    monkeypatch.setattr(replay_module.os, "write", fail_second_stage_write)
    monkeypatch.setattr(replay_module.os, "unlink", fail_failed_stage_unlink)
    monkeypatch.setattr(replay_module.os, "close", fail_failed_stage_close)
    with pytest.raises(BaseExceptionGroup) as raised:
        _publish_target_artifacts(paths, inputs)

    messages = _exception_messages(raised.value)
    assert any("second stage write failure" in item for item in messages)
    assert any("failed-stage unlink cleanup failure" in item for item in messages)
    assert any("failed-stage close cleanup failure" in item for item in messages)


def test_target_artifact_final_cleanup_preserves_primary_and_closes_every_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    parent_identities = {(path.parent.stat().st_dev, path.parent.stat().st_ino) for path in paths}
    original_link = replay_module.os.link
    original_close = replay_module.os.close
    links = 0
    link_failed = False
    directory_close_attempts = 0

    def fail_second_link(
        source_name: str | Path,
        destination_name: str | Path,
        **kwargs: object,
    ) -> None:
        nonlocal links, link_failed
        links += 1
        if links == 2:
            link_failed = True
            raise OSError("simulated second artifact link failure")
        original_link(source_name, destination_name, **kwargs)

    def fail_selected_final_closes(descriptor: int) -> None:
        nonlocal directory_close_attempts
        metadata = replay_module.os.fstat(descriptor)
        is_final_parent = (
            link_failed
            and replay_module.stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) in parent_identities
        )
        if is_final_parent:
            directory_close_attempts += 1
        original_close(descriptor)
        if is_final_parent and directory_close_attempts in {1, 3}:
            raise OSError(f"simulated final parent close failure {directory_close_attempts}")

    monkeypatch.setattr(replay_module.os, "link", fail_second_link)
    monkeypatch.setattr(replay_module.os, "close", fail_selected_final_closes)
    with pytest.raises(BaseExceptionGroup) as raised:
        _publish_target_artifacts(paths, inputs)

    messages = _exception_messages(raised.value)
    assert any("second artifact link failure" in item for item in messages)
    assert any("final parent close failure 1" in item for item in messages)
    assert any("final parent close failure 3" in item for item in messages)
    assert directory_close_attempts == 4
    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize("failed_write", (2, 3, 4))
def test_target_artifact_stage_failure_fsyncs_every_removed_temporary_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_write: int,
) -> None:
    inputs = _target_artifact_publication_inputs(tmp_path)
    paths = _target_artifact_paths(tmp_path, mixed_parents=True)
    parent_identities = tuple(
        (path.parent.stat().st_dev, path.parent.stat().st_ino) for path in paths
    )
    original_write = replay_module.os.write
    original_fsync = replay_module.os.fsync
    writes = 0
    fsynced_parents: set[tuple[int, int]] = set()

    def fail_selected_stage_write(descriptor: int, payload: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == failed_write:
            raise OSError(f"simulated stage {failed_write} write failure")
        return original_write(descriptor, payload)

    def record_directory_fsync(descriptor: int) -> None:
        metadata = replay_module.os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        if replay_module.stat.S_ISDIR(metadata.st_mode) and identity in parent_identities:
            fsynced_parents.add(identity)
        original_fsync(descriptor)

    monkeypatch.setattr(replay_module.os, "write", fail_selected_stage_write)
    monkeypatch.setattr(replay_module.os, "fsync", record_directory_fsync)
    with pytest.raises(OSError, match=f"stage {failed_write} write failure"):
        _publish_target_artifacts(paths, inputs)

    assert fsynced_parents == set(parent_identities[:failed_write])
    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        ("missing", "valid durable start"),
        ("altered", "trust binding"),
    ),
)
def test_target_recovery_rejects_missing_or_altered_stored_trust_binding(
    tmp_path: Path,
    mutation: str,
    match: str,
) -> None:
    manifest = _manifest(tmp_path)
    arguments = _target_args(tmp_path, manifest, duration=28_800)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    journal = SQLiteTargetCollectorJournal(arguments.collector_state)
    if mutation == "altered":
        start = _durable_recovery_start(arguments, record)
        binding = dict(start["trust_binding"])
        binding["policy_sha256"] = "0" * 64
        start["trust_binding"] = binding
        journal.stage("start", start)
    finalize = {"schema_version": "completed-final-probe.v1"}
    journal.stage("finalize", finalize)
    journal.complete(
        "finalize",
        request=finalize,
        response=_signed_completed_final_envelope(
            tmp_path,
            manifest,
            record,
            stem=f"binding-{mutation}",
        ),
    )

    with pytest.raises(RuntimeError, match=match):
        run_target(
            arguments,
            process_factory=lambda *_args, **_kwargs: pytest.fail(
                "invalid recovery must not launch"
            ),
        )
    assert not arguments.out.exists()
    assert not arguments.out_attestation.exists()
    assert not arguments.out_signature.exists()


def test_target_recovery_rejects_self_signed_attacker_root(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    arguments = _target_args(tmp_path, manifest, duration=28_800)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    journal = SQLiteTargetCollectorJournal(arguments.collector_state)
    journal.stage("start", _durable_recovery_start(arguments, record))
    finalize = {"schema_version": "completed-final-probe.v1"}
    journal.stage("finalize", finalize)
    journal.complete(
        "finalize",
        request=finalize,
        response=_signed_completed_final_envelope(
            tmp_path,
            manifest,
            record,
            stem="attacker-root",
        ),
    )

    attacker_root = tmp_path / "attacker-root-chain"
    attacker_root.mkdir()
    for name in (
        "capacity-authority-public.pem",
        "target-run-authority.pem",
    ):
        (attacker_root / name).write_bytes((tmp_path / name).read_bytes())
    attacker = verified_trust_bundle(
        attacker_root,
        manifest,
        valid_until=START + timedelta(days=4),
        allowed_gates=("8h", "72h"),
    )
    arguments.acceptance_offline_root_public_key = attacker.root_public_key
    arguments.acceptance_trust_policy = attacker.policy
    arguments.acceptance_trust_policy_signature = attacker.policy_signature
    arguments.acceptance_manifest_role_public_key = attacker.role_public_keys.manifest
    arguments.acceptance_capacity_role_public_key = attacker.role_public_keys.capacity
    arguments.acceptance_run_role_public_key = attacker.role_public_keys.run
    arguments.acceptance_report_role_public_key = attacker.role_public_keys.report
    arguments.acceptance_conditional_role_public_key = attacker.role_public_keys.conditional
    arguments.manifest = attacker.manifest
    arguments.manifest_signature = attacker.manifest_signature

    with pytest.raises(ValueError, match="offline root"):
        run_target(arguments)
    assert not arguments.out.exists()
    assert not arguments.out_attestation.exists()
    assert not arguments.out_signature.exists()


def test_target_collector_durable_post_retries_response_loss_once(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    trust_context = authority_trust_context(tmp_path, manifest)
    token = tmp_path / "controller-token"
    token.write_text("controller-token-not-secret-in-test")
    root = tmp_path / "runner-state"
    root.mkdir(mode=0o700)
    collector = AuthenticatedTargetCollector(
        base_url="http://127.0.0.1:8765",
        acceptance_controller_token_file=token,
        verified_trust=trust_context.trust,
        configured_site_id=trust_context.configured_site_id,
        configured_campaign_id=trust_context.configured_campaign_id,
        configured_gate=trust_context.configured_gate,
        journal_path=root / "collector.sqlite3",
    )
    calls = 0
    execution = _run(manifest, hours=8).execution
    assert execution is not None
    binding = {
        "collector_id": "collector-response-loss",
        "site_id": manifest.site_id,
        "manifest_sha256": manifest.manifest_sha256,
        "gate": "8h",
        "launch_attestation_sha256": manifest.launch.attestation_sha256,
        "execution_binding_sha256": execution.binding_sha256,
        "fault_schedule_sha256": canonical_fault_schedule_sha256(
            trust_context.fault_schedule
        ),
        "trust_binding": trust_context.binding.model_dump(mode="json"),
    }
    request = {
        "schema_version": "acceptance-collector-sample.v2",
        **binding,
        "process_healthy": True,
        "scheduled_monotonic_offset_seconds": 0.0,
        "observation": None,
    }
    response_payload = {
        "schema_version": "acceptance-collector-sample-response.v2",
        **binding,
        "observed_records": 7,
    }

    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                response_payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()

        def geturl(self) -> str:
            return "http://127.0.0.1:8765/probe"

    def response_loss_then_success(
        *_args: object,
        **_kwargs: object,
    ) -> Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise urllib.error.URLError("response lost")
        return Response()

    collector._opener.open = response_loss_then_success
    assert collector._durable_post(
        operation_key="sample:0",
        path="/probe",
        payload=request,
        limit=1024,
        response_model=AcceptanceSampleResponseV2,
    ) == response_payload
    assert calls == 2

    reconstructed = AuthenticatedTargetCollector(
        base_url="http://127.0.0.1:8765",
        acceptance_controller_token_file=token,
        verified_trust=trust_context.trust,
        configured_site_id=trust_context.configured_site_id,
        configured_campaign_id=trust_context.configured_campaign_id,
        configured_gate=trust_context.configured_gate,
        journal_path=root / "collector.sqlite3",
    )
    reconstructed._opener.open = lambda *_args, **_kwargs: pytest.fail(
        "completed durable response must not hit the network"
    )
    assert reconstructed._durable_post(
        operation_key="sample:0",
        path="/probe",
        payload=request,
        limit=1024,
        response_model=AcceptanceSampleResponseV2,
    ) == response_payload


def test_target_collector_v3_finalize_uses_exact_packaged_route() -> None:
    collector = object.__new__(AuthenticatedTargetCollector)
    collector._operation_lock = threading.RLock()
    collector._binding = {"collector_id": "collector-route-01"}
    observed: list[tuple[str, dict[str, object], int]] = []
    digests = {
        "snapshot_sha256": "1" * 64,
        "evaluation_sha256": "2" * 64,
        "final_decision_sha256": "3" * 64,
        "proof_sha256": "4" * 64,
    }
    pass_payload = {
        "schema_version": "acceptance-pass-attestation.v3",
        "collector_id": "collector-route-01",
        **digests,
        "accepted": True,
    }
    response = {
        "schema_version": "acceptance-controller-result.v3",
        "collector_id": "collector-route-01",
        "state": "ATTESTED",
        **digests,
        "accepted": True,
        "pass_attestation": {
            "schema_version": "signed-acceptance-pass-attestation.v3",
            "payload": pass_payload,
            "signature_hex": "a" * 128,
        },
    }

    def post(
        path: str,
        payload: dict[str, object],
        *,
        limit: int,
    ) -> dict[str, object]:
        observed.append((path, payload, limit))
        return response

    collector._post = post
    result = collector.finalize_v3("collector-route-01")

    assert result.collector_id == "collector-route-01"
    assert result.accepted is True
    assert observed == [
        (
            (
                "/api/internal/acceptance/v3/collectors/"
                "collector-route-01/finalize"
            ),
            {},
            replay_module._MAX_ACCEPTANCE_CONTROLLER_V3_RESULT_BYTES,
        )
    ]

    with pytest.raises(RuntimeError, match="active exact collector"):
        collector.finalize_v3("collector-route-02")
    hostile = {
        **response,
        "collector_id": "collector-route-02",
        "pass_attestation": {
            **response["pass_attestation"],
            "payload": {
                **pass_payload,
                "collector_id": "collector-route-02",
            },
        },
    }
    collector._post = lambda *_args, **_kwargs: hostile
    with pytest.raises(RuntimeError, match="invalid result|signed pass"):
        collector.finalize_v3("collector-route-01")


def test_target_fault_resume_observes_before_idempotent_effect_reconciliation(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    trust_context = authority_trust_context(tmp_path, manifest)
    execution = _run(manifest).execution
    assert execution is not None
    schedule = canonical_fault_schedule(tuple(source.camera_id for source in manifest.sources))
    fault = schedule[0]
    phase = "inject"
    at_offset = fault.offset_seconds
    command_id = "command-" + "a" * 64
    binding = {
        "site_id": manifest.site_id,
        "manifest_sha256": manifest.manifest_sha256,
        "gate": "8h",
        "collector_id": "collector-crash-cut",
        "launch_attestation_sha256": manifest.launch.attestation_sha256,
        "execution_binding_sha256": execution.binding_sha256,
        "fault_schedule_sha256": canonical_fault_schedule_sha256(schedule),
        "trust_binding": trust_context.binding.model_dump(mode="json"),
    }
    effect_request = {
        "schema_version": "acceptance-fault-effect-execution.v2",
        "collector_id": binding["collector_id"],
        "launch_attestation_sha256": manifest.launch.attestation_sha256,
        "execution_binding_sha256": execution.binding_sha256,
        "fault": fault.model_dump(mode="json"),
        "phase": phase,
        "command_id": command_id,
        "commanded_monotonic_offset_seconds": at_offset,
    }
    root = tmp_path / "runner-state"
    root.mkdir(mode=0o700)
    state_path = root / "collector.sqlite3"
    crashed = SQLiteTargetCollectorJournal(state_path)
    crashed.prepare_effect(command_id, request=effect_request)
    assert crashed.effect(command_id)[:2] == (
        "PREPARED",
        effect_request,
    )

    calls: list[str] = []
    external_state = {"degraded": True, "mutations": 1}

    class Observer:
        def observe_fault(self, **_kwargs: object) -> FaultCommandObservationV2:
            calls.append("observe")
            return FaultCommandObservationV2(
                schema_version="acceptance-fault-command-observation.v2",
                command_id=command_id,
                state=fault.expected_degraded,
                runtime_boot_id=f"{execution.launch_nonce}.runtime-1",
                api_boot_id="api-1",
                execution_binding_sha256=execution.binding_sha256,
                observer_sha256=execution.acceptance_observer_sha256,
                observer_policy_sha256=(execution.acceptance_observer_policy_sha256),
            )

    class Executor:
        def ensure_fault(self, **kwargs: object) -> FaultEffectReceiptV2:
            calls.append("ensure")
            prior = kwargs["prior_observation"]
            assert isinstance(prior, FaultCommandObservationV2)
            assert prior.state == fault.expected_degraded
            if not external_state["degraded"]:
                external_state["degraded"] = True
                external_state["mutations"] += 1
            return FaultEffectReceiptV2(
                schema_version="acceptance-fault-effect-receipt.v2",
                command_id=command_id,
                fault_id=fault.fault_id,
                phase=phase,
                target=fault.target,
                execution_binding_sha256=execution.binding_sha256,
                executor_sha256=execution.acceptance_adapter_sha256,
                executor_policy_sha256=(execution.acceptance_adapter_policy_sha256),
                pre_state="unknown-after-crash",
                post_state=fault.expected_degraded,
                pre_runtime_boot_id=f"{execution.launch_nonce}.runtime-1",
                post_runtime_boot_id=f"{execution.launch_nonce}.runtime-1",
                pre_api_boot_id="api-1",
                post_api_boot_id="api-1",
                effect_started_at=START + timedelta(seconds=at_offset),
                effect_completed_at=START + timedelta(seconds=at_offset),
                effect_proof_sha256="b" * 64,
                outcome="ensured",
            )

    token = tmp_path / "controller-token"
    token.write_text("controller-token-not-secret-in-test")
    collector = AuthenticatedTargetCollector(
        base_url="http://127.0.0.1:8765",
        acceptance_controller_token_file=token,
        verified_trust=trust_context.trust,
        configured_site_id=trust_context.configured_site_id,
        configured_campaign_id=trust_context.configured_campaign_id,
        configured_gate=trust_context.configured_gate,
        journal_path=state_path,
        fault_executor=Executor(),
        observer=Observer(),
    )
    collector._binding = binding
    collector._schedule = {fault.fault_id: fault}
    collector._launch = manifest.launch
    collector._execution = execution

    def durable_response(**kwargs: object) -> dict[str, object]:
        if kwargs["path"].endswith("/prepare"):
            response = {
                "schema_version": (
                    "acceptance-fault-prepare-response.v2"
                ),
                **binding,
                "fault_id": fault.fault_id,
                "phase": phase,
                "commanded_monotonic_offset_seconds": at_offset,
                "command_id": command_id,
                "state": "CLAIMED",
            }
        else:
            response = {
                "schema_version": "acceptance-fault-ack-response.v2",
                **binding,
                "fault_id": fault.fault_id,
                "phase": phase,
                "commanded_monotonic_offset_seconds": at_offset,
                "command_id": command_id,
                "state": fault.expected_degraded,
                "runtime_boot_id": (
                    f"{execution.launch_nonce}.runtime-1"
                ),
                "api_boot_id": "api-1",
                "observed_at": START.isoformat(),
            }
        operation_key = str(kwargs["operation_key"])
        request = kwargs["payload"]
        assert isinstance(request, dict)
        collector._journal.stage(operation_key, request)
        collector._journal.complete(
            operation_key,
            request=request,
            response=response,
        )
        return response

    collector._durable_post = durable_response
    collector.command_fault(
        fault_id=fault.fault_id,
        phase=phase,
        at_offset=at_offset,
    )
    assert calls == ["observe", "ensure", "observe"]
    assert external_state["mutations"] == 1
    committed = SQLiteTargetCollectorJournal(state_path).effect(command_id)
    assert committed is not None and committed[0] == "COMMITTED"


def test_target_refuses_early_exit_wrong_binding_and_non_gate_duration(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    args = _target_args(tmp_path, manifest, duration=10)
    with pytest.raises(ValueError, match="8h or 72h"):
        run_target(args, collector=_FakeCollector(_run(manifest)))

    args = _target_args(tmp_path, manifest, duration=28_800)
    clock = _FakeClock()
    with pytest.raises(RuntimeError, match="exited before"):
        run_target(
            args,
            process_factory=lambda *_args, **_kwargs: _FakeProcess(exit_early=True),
            collector=_FakeCollector(_run(manifest, hours=8).model_copy(update={"gate": "8h"})),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

    wrong = _run(manifest, hours=8).model_copy(update={"gate": "8h", "site_id": "other-site"})
    wrong_clock = _FakeClock()
    with pytest.raises(RuntimeError, match="exact manifest/site"):
        run_target(
            args,
            process_factory=lambda *_args, **_kwargs: _FakeProcess(),
            collector=_FakeCollector(wrong),
            monotonic=wrong_clock.monotonic,
            sleep=wrong_clock.sleep,
        )


def test_report_derives_outcomes_from_typed_traces_not_claimed_booleans(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    broken = run.model_copy(
        update={
            "events_evidence_complete": True,
            "reviews_audited": True,
            "notifications_after_confirmation": True,
            "queues_drained": True,
            "consumers_connected": True,
            "lifecycle": (),
            "queue_traces": (),
            "capacity": None,
            "candidate_to_event_seconds": (),
            "first_preview_seconds": (),
        }
    )
    report = evaluate_acceptance(manifest, broken)
    assert not report.passed
    joined = " ".join(report.reasons)
    assert "latency samples" in joined
    assert "queue traces" in joined
    assert "capacity evidence" in joined


def test_report_rejects_unsupported_outage_exclusion_and_unbound_capacity(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    camera = run.cameras[0].model_copy(update={"source_outage_seconds": 30})
    unbound = run.capacity.model_copy(update={"manifest_sha256": "b" * 64})
    report = evaluate_acceptance(
        manifest,
        run.model_copy(update={"cameras": (camera, *run.cameras[1:]), "capacity": unbound}),
    )
    assert not report.passed
    joined = " ".join(report.reasons)
    assert "unsupported source-outage exclusion" in joined
    assert "capacity evidence binding" in joined


def test_canonical_fault_policy_rejects_internally_consistent_forged_expectations(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    fault = run.faults[0].model_copy(
        update={
            "expected_degraded": "degraded",
            "expected_recovery": "ready",
            "observed_degraded": "degraded",
            "observed_recovery": "ready",
        }
    )
    traces = tuple(
        trace.model_copy(update={"state": "degraded" if trace.phase == "degraded" else "ready"})
        if trace.fault_id == fault.fault_id
        else trace
        for trace in run.fault_traces
    )
    report = evaluate_acceptance(
        manifest,
        run.model_copy(update={"faults": (fault, *run.faults[1:]), "fault_traces": traces}),
    )
    assert not report.passed
    assert any("canonical fault policy" in reason for reason in report.reasons)


def test_fault_trace_kind_target_timing_and_restart_boots_are_bound(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    first = run.fault_traces[0].model_copy(
        update={"kind": "network_pause", "component": "wrong-target"}
    )
    restart = next(item for item in run.faults if item.kind == "runtime_restart")
    late_recovery = restart.model_copy(
        update={
            "recovered_at": restart.injected_at + timedelta(seconds=restart.duration_seconds + 31)
        }
    )
    faults = tuple(
        late_recovery if item.fault_id == restart.fault_id else item for item in run.faults
    )
    report = evaluate_acceptance(
        manifest,
        run.model_copy(
            update={
                "faults": faults,
                "fault_traces": (first, *run.fault_traces[1:]),
                "runtime_boot_ids": ("runtime-boot-1",),
            }
        ),
    )
    assert not report.passed
    joined = " ".join(report.reasons)
    assert "trace binding" in joined
    assert "restart boot" in joined


def test_report_derives_source_return_recovery_and_rejects_over_30_seconds(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    fault = run.faults[0]
    recovered_at = fault.injected_at + timedelta(seconds=fault.duration_seconds + 31)
    changed_fault = fault.model_copy(update={"recovered_at": recovered_at})
    changed_traces = tuple(
        trace.model_copy(update={"observed_at": recovered_at})
        if trace.fault_id == fault.fault_id and trace.phase == "recovered"
        else trace
        for trace in run.fault_traces
    )
    report = evaluate_acceptance(
        manifest,
        run.model_copy(
            update={"faults": (changed_fault, *run.faults[1:]), "fault_traces": changed_traces}
        ),
    )
    assert not report.passed
    assert any("source return" in reason for reason in report.reasons)


def test_operator_output_demotes_without_core_capacity_or_verified_gate_decision(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    no_capacity = evaluate_acceptance(
        manifest, _run(manifest).model_copy(update={"capacity": None})
    )
    assert no_capacity.modules[0].mode == "shadow"
    assert "demoted" in no_capacity.modules[0].reason

    with pytest.raises(ValueError, match="complete attested gate evidence"):
        ModuleDispositionV2(
            module="weapon",
            mode="pass/operator",
            reason="forged boolean only",
            evidence_reference="evidence/weapon-matrix.json",
            artifact_id="weapon-v1",
            registry_entry_sha256="b" * 64,
            rights_sha256=HEX,
            artifact_sha256=HEX,
            site_matrix_sha256=HEX,
        )


def test_run_rejects_non_append_order_and_duplicate_trace_or_exception_ids(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    payload = run.model_dump(mode="json")
    payload["resources"] = list(reversed(payload["resources"]))
    with pytest.raises(ValueError, match="append"):
        AcceptanceRunRecordV2.model_validate(payload)

    duplicate = ExceptionRecordV2(
        exception_id="duplicate",
        occurred_at=START + timedelta(seconds=4),
        component="runtime",
        category="handled",
        code="bounded",
    )
    payload = run.model_dump(mode="json")
    payload["exceptions"] = [
        duplicate.model_dump(mode="json"),
        duplicate.model_dump(mode="json"),
    ]
    with pytest.raises(ValueError, match="exception IDs"):
        AcceptanceRunRecordV2.model_validate(payload)


def test_run_rejects_normalized_secret_keys_and_object_store_uri_values(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    payload = _run(manifest).model_dump(mode="json")
    payload["boundaries"][0]["detail_code"] = "S3://customer-secret-bucket/evidence"
    with pytest.raises(ValueError, match="detail_code"):
        AcceptanceRunRecordV2.model_validate(payload)

    report_payload = evaluate_acceptance(manifest, _run(manifest)).model_dump(mode="json")
    report_payload["metrics"]["Object-Store_URL"] = 1.0
    with pytest.raises(ValueError, match="sensitive field"):
        AcceptanceReportV2.model_validate(report_payload)


def test_signature_verification_bounds_signature_before_openssl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if subprocess.run(["openssl", "version"], capture_output=True).returncode:
        pytest.skip("OpenSSL unavailable")
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True,
        capture_output=True,
    )
    manifest = _manifest(tmp_path)
    from protector.pilot.acceptance import write_signed_report

    paths = write_signed_report(
        evaluate_acceptance(manifest, _run(manifest)),
        output_dir=tmp_path / "out",
        private_key=private_key,
        public_key=public_key,
    )
    paths.signature.write_bytes(b"x" * 65_537)
    monkeypatch.setattr(
        "protector.pilot.acceptance.subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("OpenSSL must not see an unbounded signature")
        ),
    )
    assert verify_signed_report(paths.metadata, public_key=public_key) is False


def test_acceptance_timestamps_reject_nonzero_utc_offset() -> None:
    plus_five = timezone(timedelta(hours=5))
    with pytest.raises(ValueError, match="must be UTC"):
        ResourceSampleV2(
            sampled_at=START.astimezone(plus_five),
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
        )


def test_endurance_fault_schedule_rejects_duplicate_kind_duration_and_source_target(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    duplicate = run.faults[1].model_copy(
        update={"kind": run.faults[0].kind, "target": run.faults[0].target}
    )
    wrong_duration = run.faults[2].model_copy(update={"duration_seconds": 99})
    wrong_target = run.faults[0].model_copy(update={"target": "camera-03"})
    for faults in (
        (run.faults[0], duplicate, *run.faults[2:]),
        (*run.faults[:2], wrong_duration, *run.faults[3:]),
        (wrong_target, *run.faults[1:]),
    ):
        report = evaluate_acceptance(manifest, run.model_copy(update={"faults": faults}))
        assert not report.passed
        assert any("canonical fault schedule" in reason for reason in report.reasons)


def test_sparse_target_resource_samples_cannot_cover_endurance_gate(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    sparse = (run.resources[0], run.resources[-1])
    report = evaluate_acceptance(
        manifest,
        run.model_copy(
            update={
                "resources": sparse,
                "gpu_percent": tuple(item.gpu_percent for item in sparse),
                "vram_percent": tuple(item.vram_percent for item in sparse),
                "disk_bytes": tuple(item.disk_bytes for item in sparse),
            }
        ),
    )
    assert not report.passed
    assert any("resource sampling cadence" in reason for reason in report.reasons)


def test_conditional_gate_decision_loader_is_bounded_unique_and_evaluator_bound(
    tmp_path: Path,
) -> None:
    if subprocess.run(["openssl", "version"], capture_output=True).returncode:
        pytest.skip("OpenSSL unavailable")
    private_key = (tmp_path / "private.pem").resolve()
    public_key = (tmp_path / "public.pem").resolve()
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True,
        capture_output=True,
    )
    decision = ConditionalModelGateResultV1(
        site_id="school-01",
        module="weapon",
        artifact_id="weapon-v1",
        registry_entry_sha256="b" * 64,
        mode="operator",
        reasons=(),
    )
    decision_path = (tmp_path / "weapon-gate.json").resolve()
    signature_path = tmp_path / "weapon-gate.sig"
    attestation = ConditionalGateAttestationV2(
        schema_version="conditional-gate-attestation.v2",
        decision=decision,
        rights_sha256=HEX,
        artifact_sha256=HEX,
        engine_sha256=HEX,
        site_matrix_sha256=HEX,
        shadow_stage_sha256=HEX,
        capacity_report_sha256=HEX,
        workload_sha256=HEX,
        public_key_spki_sha256=ed25519_public_key_spki_sha256(public_key.read_bytes()),
        signature_file=signature_path.name,
        public_key_file=public_key.name,
    )
    decision_path.write_bytes(
        json.dumps(
            attestation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(decision_path),
            "-out",
            str(signature_path),
        ],
        check=True,
        capture_output=True,
    )
    assert load_conditional_gate_decisions(
        (decision_path,),
        trusted_public_key=public_key,
    ) == (attestation,)
    with pytest.raises(ValueError, match="duplicate"):
        load_conditional_gate_decisions(
            (decision_path, decision_path),
            trusted_public_key=public_key,
        )
    link = tmp_path / "gate-link.json"
    link.symlink_to(decision_path)
    with pytest.raises(ValueError, match="symlink"):
        load_conditional_gate_decisions(
            (link,),
            trusted_public_key=public_key,
        )

    promoted = ModuleDispositionV2(
        module="weapon",
        mode="pass/operator",
        reason="authoritative conditional gate",
        evidence_reference="evidence/weapon-matrix.json",
        artifact_id="weapon-v1",
        registry_entry_sha256="b" * 64,
        rights_sha256=HEX,
        artifact_sha256=HEX,
        engine_sha256=HEX,
        site_matrix_sha256=HEX,
        shadow_stage_sha256=HEX,
        capacity_report_sha256=HEX,
        workload_sha256=HEX,
        gate_decision_sha256=attestation.attestation_sha256,
        gate_trust_key_spki_sha256=attestation.public_key_spki_sha256,
    )
    base_manifest = _manifest(tmp_path)
    manifest = base_manifest.model_copy(
        update={
            "modules": (
                base_manifest.modules[0],
                promoted,
                *base_manifest.modules[2:],
            )
        }
    )

    wrong_decision = decision.model_copy(
        update={"artifact_id": "different-artifact", "registry_entry_sha256": "c" * 64}
    )
    wrong_identity = attestation.model_copy(update={"decision": wrong_decision})
    wrong_disposition = promoted.model_copy(
        update={"gate_decision_sha256": wrong_identity.attestation_sha256}
    )
    wrong_manifest = manifest.model_copy(
        update={
            "modules": (
                manifest.modules[0],
                wrong_disposition,
                *manifest.modules[2:],
            )
        }
    )
    wrong_report = evaluate_acceptance(
        wrong_manifest,
        _run(wrong_manifest),
        verified_gate_decisions=(wrong_identity,),
    )
    wrong_weapon = next(item for item in wrong_report.modules if item.module == "weapon")
    assert wrong_weapon.mode == "shadow"
    assert "evidence identity" in wrong_weapon.reason


def test_report_cli_requires_rooted_v2_proof_and_verify_reevaluates_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    trust_bundle = verified_trust_bundle(
        tmp_path,
        manifest,
        valid_until=START + timedelta(hours=9),
        allowed_gates=("8h",),
    )
    run = _run(manifest, hours=8).model_copy(update={"gate": "8h"})
    run_path = tmp_path / "report-run.json"
    run_path.write_bytes(canonical_json_bytes(run))
    proof_path = tmp_path / "report-journal-proof.jsonl"
    attestation = _write_bound_journal_proof(
        proof_path,
        run=run,
        trust=trust_bundle.trust,
    )
    attestation_path = tmp_path / "report-run.attestation.json"
    attestation_path.write_bytes(canonical_json_bytes(attestation))
    signature_path = tmp_path / "report-run.attestation.sig"
    subprocess.run(
        (
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(tmp_path / "target-run-private.pem"),
            "-in",
            str(attestation_path),
            "-out",
            str(signature_path),
        ),
        check=True,
        capture_output=True,
    )
    redirect_token = tmp_path / "proof-download-token"
    redirect_token.write_text("proof-download-token-secret")
    redirected_destination = tmp_path / "redirected-proof.jsonl"

    class RedirectResponse:
        status = 200
        headers: dict[str, str] = {}

        def __enter__(self) -> RedirectResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "http://attacker.invalid/api/internal/acceptance/proof"

        def read(self, _limit: int) -> bytes:
            raise AssertionError("redirected proof body must not be consumed")

    class RedirectOpener:
        def open(self, *_args: object, **_kwargs: object) -> RedirectResponse:
            return RedirectResponse()

    def redirected_opener(*handlers: object) -> RedirectOpener:
        assert any(
            isinstance(handler, replay_module.urllib.request.HTTPRedirectHandler)
            for handler in handlers
        )
        return RedirectOpener()

    monkeypatch.setattr(
        replay_module.urllib.request,
        "build_opener",
        redirected_opener,
    )
    with pytest.raises(RuntimeError, match="download was refused"):
        replay_module._download_journal_proof(
            base_url="http://127.0.0.1:8765",
            acceptance_controller_token_file=redirect_token,
            binding={
                "collector_id": run.run_id,
                "site_id": run.site_id,
                "manifest_sha256": run.manifest_sha256,
                "gate": run.gate,
                "launch_attestation_sha256": (
                    run.launch.attestation_sha256
                ),
                "execution_binding_sha256": (
                    run.execution.binding_sha256
                ),
                "fault_schedule_sha256": (
                    attestation.fault_schedule_sha256
                ),
            },
            attestation=attestation,
            record=run,
            destination=redirected_destination,
        )
    assert not redirected_destination.exists()

    report_private = trust_bundle.role_public_keys.report.with_name("report.private.pem")
    report_public = trust_bundle.role_public_keys.report
    common = [
        "--acceptance-site-id",
        manifest.site_id,
        "--acceptance-campaign-id",
        trust_bundle.trust.policy.campaign_id,
        "--acceptance-gate",
        "8h",
        "--acceptance-offline-root-spki-sha256",
        trust_bundle.expected_offline_root_spki_sha256,
        "--acceptance-offline-root-public-key",
        str(trust_bundle.root_public_key),
        "--acceptance-trust-policy",
        str(trust_bundle.policy),
        "--acceptance-trust-policy-signature",
        str(trust_bundle.policy_signature),
        "--acceptance-manifest-role-public-key",
        str(trust_bundle.role_public_keys.manifest),
        "--acceptance-capacity-role-public-key",
        str(trust_bundle.role_public_keys.capacity),
        "--acceptance-run-role-public-key",
        str(trust_bundle.role_public_keys.run),
        "--acceptance-report-role-public-key",
        str(trust_bundle.role_public_keys.report),
        "--acceptance-conditional-role-public-key",
        str(trust_bundle.role_public_keys.conditional),
        "--manifest",
        str(trust_bundle.manifest),
        "--manifest-signature",
        str(trust_bundle.manifest_signature),
        "--run-record",
        str(run_path),
        "--run-attestation",
        str(attestation_path),
        "--run-signature",
        str(signature_path),
        "--journal-proof",
        str(proof_path),
        "--measured-capacity-report",
        str(tmp_path / "capacity.yaml"),
        "--measured-capacity-signature",
        str(tmp_path / "capacity.sig"),
        "--public-key",
        str(report_public),
    ]
    output = tmp_path / "rooted-report"
    assert (
        acceptance_report_main(
            [
                "generate",
                *common,
                "--out-dir",
                str(output),
                "--private-key",
                str(report_private),
            ]
        )
        == 0
    )
    verify = [
        "verify",
        *common,
        "--metadata",
        str(output / "acceptance-verification.json"),
    ]
    assert acceptance_report_main(verify) == 0

    from protector.pilot.acceptance import write_signed_report

    forged = evaluate_acceptance(manifest, run).model_copy(
        update={
            "passed": False,
            "reasons": ("forged evaluator result",),
            "manifest_signature_sha256": trust_bundle.trust.manifest_signature_sha256,
            "manifest_trust_key_spki_sha256": (trust_bundle.trust.policy.roles.manifest_spki_sha256),
            "run_signature_sha256": hashlib.sha256(signature_path.read_bytes()).hexdigest(),
            "run_trust_key_spki_sha256": trust_bundle.trust.policy.roles.run_spki_sha256,
        }
    )
    forged_paths = write_signed_report(
        forged,
        output_dir=tmp_path / "forged-report",
        private_key=report_private,
        public_key=report_public,
    )
    forged_verify = [
        *verify[:-1],
        str(forged_paths.metadata),
    ]
    assert verify_signed_report(forged_paths.metadata, public_key=report_public)
    assert acceptance_report_main(forged_verify) == 2


def test_run_rejects_serialized_cross_camera_lifecycle_continuation(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    payload = json.loads(_run(manifest).model_dump_json())
    for trace in payload["lifecycle"][1:]:
        trace["camera_id"] = "camera-01"

    with pytest.raises(ValueError, match="cross-camera"):
        AcceptanceRunRecordV2.model_validate_json(json.dumps(payload))


def test_one_work_sample_per_camera_cannot_prove_72_hour_coverage(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    cameras = tuple(
        camera.model_copy(
            update={
                "scheduled_samples": 1,
                "processed_samples": 1,
                "dropped_samples": 0,
                "observed_records": 1,
            }
        )
        for camera in run.cameras
    )
    with pytest.raises(ValueError, match="work accounting coverage"):
        AcceptanceRunRecordV2.model_validate_json(
            run.model_copy(update={"cameras": cameras}).model_dump_json()
        )


@pytest.mark.parametrize(
    "module",
    (
        "criminal_face_watchlist",
        "face_recognition",
        "attendance",
        "emotion",
        "unknown_analytic",
    ),
)
def test_day20_manifest_rejects_unknown_or_excluded_analytics(
    tmp_path: Path,
    module: str,
) -> None:
    manifest = _manifest(tmp_path)
    payload = manifest.model_dump(mode="json")
    payload["modules"] = [
        {
            "module": module,
            "mode": "pass/operator",
            "reason": "must never enter the Day-20 manifest",
        }
    ]
    payload["sources"][0]["analytics_hz"][module] = 1.0

    with pytest.raises(ValueError, match="analytic|module"):
        AcceptanceManifestV2.model_validate_json(json.dumps(payload))


def test_presigned_https_references_are_rejected_from_manifest_run_and_report(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    presigned = (
        "https://objects.kz/customer/evidence"
        "?X-Amz-Credential=ACCESS/20260730/kz/s3/aws4_request"
        "&X-Amz-Signature=TOPSECRET"
    )
    manifest_payload = manifest.model_dump(mode="json")
    manifest_payload["modules"][1]["evidence_reference"] = presigned
    with pytest.raises(ValueError, match="reference|secret-like"):
        AcceptanceManifestV2.model_validate_json(json.dumps(manifest_payload))

    run_payload = _run(manifest).model_dump(mode="json")
    run_payload["boundaries"][0]["detail_code"] = presigned
    with pytest.raises(ValueError, match="detail|secret-like"):
        AcceptanceRunRecordV2.model_validate_json(json.dumps(run_payload))

    report_payload = evaluate_acceptance(manifest, _run(manifest)).model_dump(mode="json")
    report_payload["modules"][1]["evidence_reference"] = presigned
    with pytest.raises(ValueError, match="reference|secret-like"):
        AcceptanceReportV2.model_validate_json(json.dumps(report_payload))


def test_unsigned_self_hashed_conditional_decision_is_not_verified_authority(
    tmp_path: Path,
) -> None:
    decision = ConditionalModelGateResultV1(
        site_id="school-01",
        module="weapon",
        artifact_id="weapon-v1",
        registry_entry_sha256="b" * 64,
        mode="operator",
        reasons=(),
    )
    decision_path = (tmp_path / "unsigned-weapon-gate.json").resolve()
    decision_path.write_text(decision.model_dump_json())

    with pytest.raises(ValueError, match="signature|attestation"):
        load_conditional_gate_decisions(
            (decision_path,),
            trusted_public_key=(tmp_path / "missing-trust.pem").resolve(),
        )


def test_target_refuses_unreviewed_launch_inputs_before_process_start(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    args = _target_args(tmp_path, manifest, duration=28_800)
    args.runtime_manifest_sha256 = "f" * 64
    collector = _FakeCollector(_run(manifest, hours=8).model_copy(update={"gate": "8h"}))
    clock = _FakeClock()
    process_started = False

    def forbidden_process_start(*_args: object, **_kwargs: object) -> _FakeProcess:
        nonlocal process_started
        process_started = True
        return _FakeProcess()

    with pytest.raises((ValueError, RuntimeError), match="reviewed|launch"):
        run_target(
            args,
            process_factory=forbidden_process_start,
            collector=collector,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
    assert process_started is False


def _ready_to_start_commands(section_heading: str) -> tuple[tuple[str, ...], ...]:
    documentation = Path("docs/pilot/ready_to_start.md").read_text(encoding="utf-8")
    section = documentation.split(f"## {section_heading}\n", maxsplit=1)[1]
    section = section.split("\n## ", maxsplit=1)[0]
    fenced_bash = re.search(r"```bash\n(.*?)\n```", section, flags=re.DOTALL)
    assert fenced_bash is not None

    commands: list[tuple[str, ...]] = []
    command = ""
    for line in fenced_bash.group(1).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "export ")):
            continue
        if stripped.endswith("\\"):
            command += f"{stripped[:-1].rstrip()} "
            continue
        command += stripped
        commands.append(tuple(shlex.split(command)))
        command = ""
    assert not command
    return tuple(commands)


def _safe_documented_argv(command: tuple[str, ...]) -> tuple[str, ...]:
    replacements = {
        "$PILOT_SITE_ID": "school-01",
        "$PILOT_ACCEPTANCE_CAMPAIGN_ID": "campaign-2026-001",
        "$PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256": "a" * 64,
        "REPLACE_WITH_64_HEX": "b" * 64,
        "REPLACE_WITH_REVIEWED_64_HEX": "c" * 64,
    }
    argv = tuple(replacements.get(token, token) for token in command)
    assert not any(token.startswith("$") or "REPLACE_WITH_" in token for token in argv)
    return argv


def _single_documented_command(
    section_heading: str,
    *,
    script: str,
    subcommand: str | None = None,
) -> tuple[str, ...]:
    prefix = ("uv", "run", "python", script)
    matches = tuple(
        command
        for command in _ready_to_start_commands(section_heading)
        if command[:4] == prefix and (subcommand is None or command[4:5] == (subcommand,))
    )
    assert len(matches) == 1
    return _safe_documented_argv(matches[0])


def _assert_host_runner_paths(arguments: object, command: tuple[str, ...]) -> None:
    assert not any(token.startswith(("/run/", "/opt/kuzet/")) for token in command)
    paths = tuple(value for value in vars(arguments).values() if isinstance(value, Path))
    assert paths
    assert all(path.is_absolute() for path in paths)
    assert not any(str(path).startswith(("/run/", "/opt/kuzet/")) for path in paths)


@pytest.mark.parametrize(
    ("section_heading", "gate", "duration_seconds"),
    (
        ("Target-only 8-hour integration replay", "8h", 28_800),
        ("Target-only 72-hour final soak", "72h", 259_200),
    ),
)
def test_ready_to_start_target_commands_are_executable_parser_contracts(
    section_heading: str,
    gate: str,
    duration_seconds: int,
) -> None:
    command = _single_documented_command(
        section_heading,
        script="scripts/pilot/replay_20.py",
    )
    arguments = replay_module._parser().parse_args(command[4:])

    assert arguments.mode == "target"
    assert arguments.acceptance_site_id == "school-01"
    assert arguments.acceptance_campaign_id == "campaign-2026-001"
    assert arguments.acceptance_gate == gate
    assert arguments.acceptance_offline_root_spki_sha256 == "a" * 64
    assert arguments.duration_seconds == duration_seconds
    assert arguments.collector_interval_seconds == 60
    assert arguments.control_plane_url == "http://127.0.0.1:8765"
    assert all(
        getattr(arguments, field) is not None
        for field in (
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
            "acceptance_adapter_executable",
            "acceptance_adapter_sha256",
            "acceptance_adapter_policy",
            "acceptance_adapter_policy_sha256",
            "acceptance_adapter_work_root",
            "acceptance_observer_executable",
            "acceptance_observer_sha256",
            "acceptance_observer_policy",
            "acceptance_observer_policy_sha256",
            "acceptance_observer_work_root",
            "collector_state",
            "acceptance_controller_token_file",
            "out",
            "out_attestation",
            "out_signature",
            "out_journal_proof",
        )
    )
    assert arguments.collector_state.is_absolute()
    assert (
        len(
            {
                arguments.collector_state,
                arguments.out,
                arguments.out_attestation,
                arguments.out_signature,
                arguments.out_journal_proof,
            }
        )
        == 5
    )
    assert {
        "--manifest-trusted-public-key",
        "--capacity-authority-public-key",
        "--run-authority-public-key",
    }.isdisjoint(command)
    _assert_host_runner_paths(arguments, command)

    replay_module.target_command(arguments, launch_nonce="0" * 32)


@pytest.mark.parametrize(
    "section_heading",
    (
        "Target-only 8-hour integration replay",
        "Target-only 72-hour final soak",
    ),
)
def test_ready_to_start_report_commands_consume_all_signed_run_artifacts(
    section_heading: str,
) -> None:
    replay_command = _single_documented_command(
        section_heading,
        script="scripts/pilot/replay_20.py",
    )
    report_command = _single_documented_command(
        section_heading,
        script="scripts/pilot/acceptance_report.py",
        subcommand="generate",
    )
    replay_arguments = replay_module._parser().parse_args(replay_command[4:])
    report_arguments = acceptance_report_module._parser().parse_args(report_command[4:])

    assert report_arguments.command == "generate"
    assert report_arguments.run_record == replay_arguments.out
    assert report_arguments.run_attestation == replay_arguments.out_attestation
    assert report_arguments.run_signature == replay_arguments.out_signature
    assert report_arguments.manifest == replay_arguments.manifest
    assert report_arguments.manifest_signature == replay_arguments.manifest_signature
    assert report_arguments.acceptance_site_id == replay_arguments.acceptance_site_id
    assert report_arguments.acceptance_campaign_id == replay_arguments.acceptance_campaign_id
    assert report_arguments.acceptance_gate == replay_arguments.acceptance_gate
    for role in ("manifest", "capacity", "run", "report", "conditional"):
        assert getattr(
            report_arguments,
            f"acceptance_{role}_role_public_key",
        ) == getattr(
            replay_arguments,
            f"acceptance_{role}_role_public_key",
        )
    assert report_arguments.journal_proof == replay_arguments.out_journal_proof
    assert all(
        getattr(report_arguments, field) is not None
        for field in (
            "measured_capacity_report",
            "measured_capacity_signature",
            "out_dir",
            "private_key",
            "public_key",
        )
    )
    _assert_host_runner_paths(report_arguments, report_command)


@pytest.mark.parametrize(
    "section_heading",
    (
        "Target-only 8-hour integration replay",
        "Target-only 72-hour final soak",
    ),
)
def test_ready_to_start_report_verify_replays_the_same_rooted_evidence(
    section_heading: str,
) -> None:
    generate_command = _single_documented_command(
        section_heading,
        script="scripts/pilot/acceptance_report.py",
        subcommand="generate",
    )
    verify_command = _single_documented_command(
        section_heading,
        script="scripts/pilot/acceptance_report.py",
        subcommand="verify",
    )
    generate = acceptance_report_module._parser().parse_args(generate_command[4:])
    verify = acceptance_report_module._parser().parse_args(verify_command[4:])

    shared = (
        "acceptance_site_id",
        "acceptance_campaign_id",
        "acceptance_gate",
        "acceptance_offline_root_spki_sha256",
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
        "run_record",
        "run_attestation",
        "run_signature",
        "journal_proof",
        "measured_capacity_report",
        "measured_capacity_signature",
        "public_key",
    )
    assert all(getattr(verify, field) == getattr(generate, field) for field in shared)
    assert verify.metadata.is_absolute()
    _assert_host_runner_paths(verify, verify_command)


def test_ready_to_start_endurance_gates_use_distinct_state_and_output_paths() -> None:
    arguments = tuple(
        replay_module._parser().parse_args(
            _single_documented_command(
                section_heading,
                script="scripts/pilot/replay_20.py",
            )[4:]
        )
        for section_heading in (
            "Target-only 8-hour integration replay",
            "Target-only 72-hour final soak",
        )
    )
    reports = tuple(
        acceptance_report_module._parser().parse_args(
            _single_documented_command(
                section_heading,
                script="scripts/pilot/acceptance_report.py",
                subcommand="generate",
            )[4:]
        )
        for section_heading in (
            "Target-only 8-hour integration replay",
            "Target-only 72-hour final soak",
        )
    )

    for field in (
        "collector_state",
        "acceptance_adapter_work_root",
        "acceptance_observer_work_root",
        "out",
        "out_attestation",
        "out_signature",
    ):
        assert getattr(arguments[0], field) != getattr(arguments[1], field)
    assert reports[0].out_dir != reports[1].out_dir


@pytest.mark.parametrize(
    "section_heading",
    (
        "Target-only 8-hour integration replay",
        "Target-only 72-hour final soak",
    ),
)
def test_ready_to_start_host_commands_have_no_container_only_paths(
    section_heading: str,
) -> None:
    commands = _ready_to_start_commands(section_heading)

    assert commands
    assert not any(
        token.startswith(("/run/", "/opt/kuzet/")) for command in commands for token in command
    )


def test_target_commands_every_canonical_fault_phase_at_its_boundary(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    record = _run(manifest, hours=8).model_copy(update={"gate": "8h"})

    class FaultRecordingCollector(_FakeCollector):
        def __init__(self) -> None:
            super().__init__(record)

    collector = FaultRecordingCollector()
    clock = _FakeClock()
    run_target(
        _target_args(tmp_path, manifest, duration=28_800),
        process_factory=lambda *_args, **_kwargs: _FakeProcess(),
        collector=collector,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    assert collector.fault_commands == [
        (fault.fault_id, phase, boundary)
        for fault in canonical_fault_schedule(
            tuple(source.camera_id for source in manifest.sources)
        )
        for phase, boundary in (
            ("inject", fault.offset_seconds),
            ("recover", fault.offset_seconds + fault.duration_seconds),
        )
    ]
