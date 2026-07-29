from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from protector.pilot.acceptance import (
    AcceptanceManifestV1,
    AcceptanceReportV1,
    AcceptanceRunRecordV1,
    BoundaryTraceV1,
    CapacityTraceV1,
    ExceptionRecordV1,
    FaultRecordV1,
    FaultStateTraceV1,
    LifecycleTraceV1,
    LocalFixtureSourceV1,
    ModuleDispositionV1,
    QueueStateTraceV1,
    ResourceSampleV1,
    SourceManifestV1,
    TargetSecretSourceV1,
    evaluate_acceptance,
    load_acceptance_manifest,
    load_conditional_gate_decisions,
    percentile_nearest_rank,
    render_acceptance_html,
    verify_signed_report,
)
from protector.pilot.gates import ConditionalModelGateResultV1
from scripts.pilot.acceptance_report import main as acceptance_report_main
from scripts.pilot.replay_20 import (
    AuthenticatedTargetCollector,
    CollectingBoundary,
    FaultFailurePlan,
    PortableFaultAdapter,
    TargetCollector,
    canonical_fault_schedule,
    run_portable,
    run_target,
)

UTC = timezone.utc
START = datetime(2026, 7, 30, tzinfo=UTC)
HEX = "a" * 64


def _fixture(tmp_path: Path, index: int) -> SourceManifestV1:
    path = tmp_path / f"camera-{index:02}.bin"
    path.write_bytes(f"lawful fixture {index}".encode())
    return SourceManifestV1(
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


def _manifest(tmp_path: Path) -> AcceptanceManifestV1:
    return AcceptanceManifestV1(
        schema_version="acceptance-manifest.v1",
        site_id="school-01",
        sources=tuple(_fixture(tmp_path, index) for index in range(20)),
        modules=(
            ModuleDispositionV1(module="person", mode="pass/operator", reason="core"),
            ModuleDispositionV1(module="weapon", mode="shadow", reason="site matrix pending"),
            ModuleDispositionV1(module="fire_smoke", mode="disabled", reason="rights pending"),
            ModuleDispositionV1(module="fight", mode="shadow", reason="shadow only"),
        ),
        config_sha256=HEX,
        model_sha256=HEX,
        engine_sha256=HEX,
        image_sha256=HEX,
    )


def _run(manifest: AcceptanceManifestV1, *, hours: int = 72) -> AcceptanceRunRecordV1:
    end = START + timedelta(hours=hours)
    resources = tuple(
        ResourceSampleV1(
            sampled_at=START + timedelta(seconds=offset),
            gpu_percent=70 if offset == hours * 3600 else 60,
            vram_percent=75 if offset == hours * 3600 else 70,
            disk_bytes=1000 + min(offset // 60, 200),
            disk_limit_bytes=1_000_000,
        )
        for offset in range(0, hours * 3600 + 1, 60)
    )
    cameras = []
    for index in range(20):
        cameras.append(
            {
                "camera_id": f"camera-{index:02}",
                "scheduled_samples": 1000,
                "processed_samples": 999,
                "dropped_samples": 1,
                "availability_seconds": hours * 3600,
                "source_outage_seconds": 0,
                "queue_age_seconds": [0.1, 0.2, 0.3],
                "reconnect_seconds": [10.0],
                "observed_records": 999,
                "last_health_at": end.isoformat(),
                "runtime_boot_id": "runtime-boot-2",
                "api_boot_id": "api-boot-2",
            }
        )
    fault_kinds = (
        "camera_loss",
        "malformed_timestamp",
        "network_pause",
        "runtime_restart",
        "api_restart",
        "object_store_outage",
        "model_timeout",
        "verifier_full",
    )
    fault_targets = (
        "camera-00",
        "camera-01",
        "camera-02",
        "shared-runtime",
        "control-api",
        "evidence-store",
        "person-primary",
        "weapon-verifier",
    )
    fault_states = (
        ("offline", "online"),
        ("degraded", "online"),
        ("offline", "online"),
        ("offline", "online"),
        ("degraded", "ready"),
        ("degraded", "ready"),
        ("degraded", "ready"),
        ("degraded", "ready"),
    )
    fault_durations = (5, 1, 5, 3, 3, 5, 2, 2)
    faults = tuple(
        FaultRecordV1(
            fault_id=f"fault-{index:02}",
            kind=kind,
            target=fault_targets[index],
            injected_at=START + timedelta(seconds=10 + index * 10),
            monotonic_offset_seconds=10 + index * 10,
            duration_seconds=fault_durations[index],
            expected_degraded=fault_states[index][0],
            expected_recovery=fault_states[index][1],
            observed_degraded=fault_states[index][0],
            observed_recovery=fault_states[index][1],
            recovered_at=START
            + timedelta(seconds=10 + index * 10 + fault_durations[index]),
        )
        for index, kind in enumerate(fault_kinds)
    )
    fault_traces: tuple[FaultStateTraceV1, ...] = ()
    for index, fault in enumerate(faults):
        degraded_runtime = "runtime-boot-1" if index <= 3 else "runtime-boot-2"
        recovered_runtime = "runtime-boot-2" if index == 3 else degraded_runtime
        degraded_api = "api-boot-1" if index <= 4 else "api-boot-2"
        recovered_api = "api-boot-2" if index == 4 else degraded_api
        fault_traces = (
            *fault_traces,
            FaultStateTraceV1(
                fault_id=fault.fault_id,
                kind=fault.kind,
                phase="degraded",
                observed_at=fault.injected_at,
                component=fault.target,
                state=fault.observed_degraded or "missing",
                runtime_boot_id=degraded_runtime,
                api_boot_id=degraded_api,
            ),
            FaultStateTraceV1(
                fault_id=fault.fault_id,
                kind=fault.kind,
                phase="recovered",
                observed_at=fault.recovered_at or fault.injected_at,
                component=fault.target,
                state=fault.observed_recovery or "missing",
                runtime_boot_id=recovered_runtime,
                api_boot_id=recovered_api,
            ),
        )
    lifecycle = (
        LifecycleTraceV1(
            trace_id="event-candidate",
            kind="event",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=1),
            state="candidate",
            actor_type="system",
        ),
        LifecycleTraceV1(
            trace_id="event-persisted",
            kind="event",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=1.2),
            state="persisted",
            actor_type="system",
        ),
        LifecycleTraceV1(
            trace_id="evidence-ready",
            kind="evidence",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=1.5),
            state="ready",
            actor_type="system",
        ),
        LifecycleTraceV1(
            trace_id="review-confirmed",
            kind="review",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=2),
            state="confirmed",
            actor_type="human",
        ),
        LifecycleTraceV1(
            trace_id="audit-confirmed",
            kind="audit",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=2.1),
            state="confirmed",
            actor_type="system",
        ),
        LifecycleTraceV1(
            trace_id="notification-delivered",
            kind="notification",
            camera_id="camera-00",
            event_id="event-001",
            occurred_at=START + timedelta(seconds=3),
            state="delivered",
            actor_type="system",
        ),
    )
    return AcceptanceRunRecordV1(
        schema_version="acceptance-run-record.v1",
        run_id="run-001",
        environment="target",
        gate="72h",
        site_id=manifest.site_id,
        manifest_sha256=manifest.manifest_sha256,
        started_at=START,
        ended_at=end,
        cameras=tuple(cameras),
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
            BoundaryTraceV1(
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
            QueueStateTraceV1(
                queue=queue,
                observed_at=end,
                depth=0,
                capacity=64,
                state="ready",
                runtime_boot_id="runtime-boot-2",
                api_boot_id="api-boot-2",
            )
            for queue in ("decode", "analytics", "verifier", "events", "evidence")
        ),
        capacity=CapacityTraceV1(
            observed_at=end,
            manifest_sha256=manifest.manifest_sha256,
            config_sha256=HEX,
            model_sha256=HEX,
            engine_sha256=HEX,
            image_sha256=HEX,
            effective_throughput_hz=125.0,
            required_throughput_hz=100.0,
            stream_count=20,
        ),
        runtime_boot_ids=("runtime-boot-1", "runtime-boot-2"),
        api_boot_ids=("api-boot-1", "api-boot-2"),
        events_evidence_complete=True,
        reviews_audited=True,
        notifications_after_confirmation=True,
        cross_camera_leakage=False,
        queues_drained=True,
        consumers_connected=True,
        measured_effective_throughput_hz=125.0,
        required_throughput_hz=100.0,
        config_sha256=HEX,
        model_sha256=HEX,
        engine_sha256=HEX,
        image_sha256=HEX,
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
        AcceptanceManifestV1(**{**manifest.model_dump(), "sources": manifest.sources[:-1]})


def test_manifest_rejects_symlink_duplicate_indices_and_operator_heavy_modules(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    link = tmp_path / "link.bin"
    link.symlink_to(tmp_path / "camera-00.bin")
    bad_source = manifest.sources[0].model_copy(
        update={"source": LocalFixtureSourceV1(kind="local_fixture", path=str(link))}
    )
    path = tmp_path / "manifest.yaml"
    payload = manifest.model_dump(mode="json")
    payload["sources"][0] = bad_source.model_dump(mode="json")
    path.write_text(yaml.safe_dump(payload))
    with pytest.raises(ValueError, match="symlink"):
        load_acceptance_manifest(path)
    with pytest.raises(ValueError, match="source indices"):
        AcceptanceManifestV1(
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
        AcceptanceManifestV1(
            **{
                **manifest.model_dump(),
                "modules": (
                    ModuleDispositionV1(
                        module="xclip", mode="pass/operator", reason="invalid"
                    ),
                ),
            }
        )
    with pytest.raises(ValueError, match="operator"):
        AcceptanceManifestV1(
            **{
                **manifest.model_dump(),
                "modules": (
                    ModuleDispositionV1(
                        module="weapon", mode="pass/operator", reason="ungated"
                    ),
                ),
            }
        )


def test_target_source_uses_reference_only_and_never_resolves_credentials(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    source = manifest.sources[0].model_copy(
        update={
            "source": TargetSecretSourceV1(
                kind="target_secret", secret_reference="/run/secrets/camera-00"
            ),
            "sha256": None,
        }
    )
    validated = AcceptanceManifestV1(
        **{**manifest.model_dump(), "sources": (source, *manifest.sources[1:])}
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
    assert report.metrics["scheduled_drop_percent"] == pytest.approx(0.1)
    assert report.modules[1].mode == "shadow"


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
        resources = tuple(item.model_copy(update={"gpu_percent": value}) for item in run.resources)
        run = run.model_copy(update={"resources": resources})
    elif field == "typed_vram":
        resources = tuple(item.model_copy(update={"vram_percent": value}) for item in run.resources)
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
            update={
                "capacity": run.capacity.model_copy(
                    update={"effective_throughput_hz": value}
                )
            }
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
    fault = FaultRecordV1(
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
    report = evaluate_acceptance(
        manifest, _run(manifest).model_copy(update={"faults": (fault,)})
    )
    assert not report.passed
    assert any("recovery" in item for item in report.reasons)


def test_run_schema_rejects_nan_negative_regressive_and_secret_fields(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    with pytest.raises(ValueError):
        AcceptanceRunRecordV1(
            **{**run.model_dump(), "gpu_percent": (float("nan"),)}
        )
    with pytest.raises(ValueError, match="after"):
        AcceptanceRunRecordV1(**{**run.model_dump(), "ended_at": START - timedelta(seconds=1)})
    payload = run.model_dump(mode="json")
    payload["rtsp_url"] = "rtsp://user:pass@example/cam"
    with pytest.raises(ValueError):
        AcceptanceRunRecordV1.model_validate(payload)


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
    public_key.write_text("bounded-public-fixture")
    output = tmp_path / "empty-report"
    output.mkdir()
    monkeypatch.setattr(
        "protector.pilot.acceptance.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )
    manifest = _manifest(tmp_path)
    from protector.pilot.acceptance import write_signed_report

    with pytest.raises(ValueError, match="could not sign"):
        write_signed_report(
            evaluate_acceptance(manifest, _run(manifest)),
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
    assert run.cameras[0].last_health_at < run.ended_at
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
    assert {
        (trace.kind, trace.phase, trace.state) for trace in run.fault_traces
    } >= {
        ("object_store_outage", "degraded", "degraded"),
        ("model_timeout", "degraded", "degraded"),
        ("verifier_full", "degraded", "degraded"),
    }
    assert any(
        item.queue == "verifier" and item.state == "full"
        for item in run.queue_traces
    )
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
    assert any("incomplete degraded/recovery" in reason for reason in evaluate_acceptance(manifest, run).reasons)


class _FakeProcess:
    def __init__(self, *, ignore_terminate: bool = False, exit_early: bool = False) -> None:
        self.ignore_terminate = ignore_terminate
        self.returncode = 3 if exit_early else None
        self.terminate_calls = 0
        self.kill_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1
        if not self.ignore_terminate:
            self.returncode = -15

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("deepstream", timeout)
        return self.returncode


class _FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class _FakeCollector(TargetCollector):
    def __init__(self, record: AcceptanceRunRecordV1, *, observations: int = 1) -> None:
        self.record = record
        self.observations = observations
        self.samples = 0
        self.started: tuple[str, str, str] | None = None
        self._collector_id = "collector-test-session"

    @property
    def collector_id(self) -> str:
        return self._collector_id

    def start(self, *, site_id: str, manifest_sha256: str, gate: str) -> None:
        self.started = (site_id, manifest_sha256, gate)
        self.record = self.record.model_copy(update={"run_id": self.collector_id})

    def collect(self, *, process_healthy: bool) -> None:
        assert process_healthy
        self.samples += self.observations

    def finish(self) -> AcceptanceRunRecordV1:
        if self.samples == 0:
            raise RuntimeError("collector observed no bounded samples")
        return self.record


def _target_args(tmp_path: Path, manifest: AcceptanceManifestV1, *, duration: int) -> SimpleNamespace:
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=True))
    token = tmp_path / "machine-token"
    token.write_text("machine-token-not-printed")
    return SimpleNamespace(
        manifest=manifest_path,
        out=tmp_path / "new-run.json",
        duration_seconds=duration,
        stop_grace_seconds=5,
        collector_interval_seconds=60,
        site_config=tmp_path / "site.yaml",
        site_config_sha256=HEX,
        runtime_manifest=tmp_path / "runtime.yaml",
        runtime_manifest_sha256=HEX,
        measured_capacity_report=tmp_path / "capacity.yaml",
        measured_capacity_sha256=HEX,
        control_plane_url="https://control.invalid",
        machine_token_file=token,
    )


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
        def finish(self) -> AcceptanceRunRecordV1:
            return super().finish().model_copy(update={"run_id": "stale-prior-session"})

    clock = _FakeClock()
    with pytest.raises(RuntimeError, match="collector session"):
        run_target(
            _target_args(tmp_path, manifest, duration=28_800),
            process_factory=lambda *_args, **_kwargs: _FakeProcess(),
            collector=StaleCollector(record),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )


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
                    "site_id": "wrong-site",
                    "manifest_sha256": HEX,
                    "gate": "8h",
                    "collector_id": "wrong",
                }
            ).encode()

    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: Response())
    collector = AuthenticatedTargetCollector(
        base_url="https://control.invalid",
        machine_token_file=token,
    )
    assert "machine-token-never-in-repr" not in repr(collector)
    with pytest.raises(RuntimeError, match="binding mismatch"):
        collector.start(site_id="school-01", manifest_sha256=HEX, gate="8h")


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

    wrong = _run(manifest, hours=8).model_copy(
        update={"gate": "8h", "site_id": "other-site"}
    )
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
        trace.model_copy(
            update={"state": "degraded" if trace.phase == "degraded" else "ready"}
        )
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
            "recovered_at": restart.injected_at
            + timedelta(seconds=restart.duration_seconds + 31)
        }
    )
    faults = tuple(late_recovery if item.fault_id == restart.fault_id else item for item in run.faults)
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

    promoted_weapon = ModuleDispositionV1(
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
    promoted_manifest = manifest.model_copy(
        update={
            "modules": (
                manifest.modules[0],
                promoted_weapon,
                *manifest.modules[2:],
            )
        }
    )
    report = evaluate_acceptance(promoted_manifest, _run(promoted_manifest))
    weapon = next(item for item in report.modules if item.module == "weapon")
    assert weapon.mode == "shadow"
    assert "verified conditional gate decision" in weapon.reason


def test_run_rejects_non_append_order_and_duplicate_trace_or_exception_ids(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    run = _run(manifest)
    payload = run.model_dump(mode="json")
    payload["resources"] = list(reversed(payload["resources"]))
    with pytest.raises(ValueError, match="append"):
        AcceptanceRunRecordV1.model_validate(payload)

    duplicate = ExceptionRecordV1(
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
        AcceptanceRunRecordV1.model_validate(payload)


def test_run_rejects_normalized_secret_keys_and_object_store_uri_values(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    payload = _run(manifest).model_dump(mode="json")
    payload["boundaries"][0]["detail_code"] = "S3://customer-secret-bucket/evidence"
    with pytest.raises(ValueError, match="secret-like"):
        AcceptanceRunRecordV1.model_validate(payload)

    report_payload = evaluate_acceptance(manifest, _run(manifest)).model_dump(mode="json")
    report_payload["metrics"]["Object-Store_URL"] = 1.0
    with pytest.raises(ValueError, match="sensitive field"):
        AcceptanceReportV1.model_validate(report_payload)


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
        ResourceSampleV1(
            sampled_at=START.astimezone(plus_five),
            gpu_percent=0,
            vram_percent=0,
            disk_bytes=0,
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


def test_conditional_gate_decision_loader_is_bounded_unique_and_cli_bound(
    tmp_path: Path,
) -> None:
    if subprocess.run(["openssl", "version"], capture_output=True).returncode:
        pytest.skip("OpenSSL unavailable")
    decision = ConditionalModelGateResultV1(
        site_id="school-01",
        module="weapon",
        artifact_id="weapon-v1",
        registry_entry_sha256="b" * 64,
        mode="operator",
        reasons=(),
    )
    decision_path = (tmp_path / "weapon-gate.json").resolve()
    decision_path.write_text(decision.model_dump_json())
    assert load_conditional_gate_decisions((decision_path,)) == (decision,)
    with pytest.raises(ValueError, match="duplicate"):
        load_conditional_gate_decisions((decision_path, decision_path))
    link = tmp_path / "gate-link.json"
    link.symlink_to(decision_path)
    with pytest.raises(ValueError, match="symlink"):
        load_conditional_gate_decisions((link,))

    promoted = ModuleDispositionV1(
        module="weapon",
        mode="pass/operator",
        reason="authoritative conditional gate",
        evidence_reference="evidence/weapon-matrix.json",
        artifact_id="weapon-v1",
        registry_entry_sha256="b" * 64,
        rights_sha256=HEX,
        artifact_sha256=HEX,
        site_matrix_sha256=HEX,
        gate_decision_sha256=decision.decision_sha256,
    )
    manifest = _manifest(tmp_path).model_copy(
        update={
            "modules": (
                _manifest(tmp_path).modules[0],
                promoted,
                *_manifest(tmp_path).modules[2:],
            )
        }
    )
    manifest_path = (tmp_path / "acceptance.yaml").resolve()
    manifest_path.write_text(yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=True))
    run_path = (tmp_path / "run.json").resolve()
    run_path.write_text(_run(manifest).model_dump_json())
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
    output = (tmp_path / "report").resolve()
    assert (
        acceptance_report_main(
            [
                "generate",
                "--manifest",
                str(manifest_path),
                "--run-record",
                str(run_path),
                "--conditional-gate-decision",
                str(decision_path),
                "--out-dir",
                str(output),
                "--private-key",
                str(private_key),
                "--public-key",
                str(public_key),
            ]
        )
        == 0
    )
    envelope = json.loads((output / "acceptance-report.json").read_text())
    weapon = next(
        item for item in envelope["report"]["modules"] if item["module"] == "weapon"
    )
    assert weapon["mode"] == "pass/operator"

    wrong_identity = decision.model_copy(
        update={"artifact_id": "different-artifact", "registry_entry_sha256": "c" * 64}
    )
    wrong_disposition = promoted.model_copy(
        update={"gate_decision_sha256": wrong_identity.decision_sha256}
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
    assert "artifact/registry identity" in wrong_weapon.reason
