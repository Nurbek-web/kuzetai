from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

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
    ModelArtifactV1,
    ShadowStageReportV1,
    TargetSiteReportV1,
)
from protector.pilot.runtime.deepstream import (
    DEEPSTREAM_IMAGE,
    DeepStreamDataPlane,
    DeepStreamGraphSpec,
    FrameMetadataV1,
    GraphContractError,
    MetadataPublisher,
    NvidiaBindingsUnavailable,
    RuntimeModelManifestV1,
    SourceRecoveryCoordinator,
    configure_nvtracker,
    main,
    metadata_observation_sequence,
    person_config_paths_match,
    resolve_rtsp_locations,
    stop_pipeline,
)
from protector.pilot.runtime.supervisor import CameraSupervisor


def _site(*, feed_count: int = 20) -> SiteConfig:
    feeds = tuple(
        CameraFeed(
            camera_id=f"camera-{number:02d}",
            rtsp_url=SecretReference(environment=f"PILOT_CAMERA_{number:02d}_RTSP"),
            codec="h264" if number % 2 else "h265",
            resolution=Resolution(width=1920, height=1080),
            bitrate_kbps=2048,
            analytics_hz={"person": 5.0, "fire_smoke": 1.0, "weapon": 1.0},
        )
        for number in range(1, feed_count + 1)
    )
    return SiteConfig(
        ready_to_start=ReadyToStart(
            feeds=feeds,
            ntp_source="ntp.example.test",
            camera_map="camera-map-v1",
            site_access="approved",
            compute="nvidia-l4",
            notification_channel="disabled",
            model_rights_decisions="model-register-v1",
        ),
        storage=KazakhstanStorage(
            country_code="KZ",
            endpoint="https://objects.example.test",
            bucket="pilot-evidence",
            retention=EvidenceRetention(
                continuous_video_owner="customer_nvr",
                continuous_video_storage_enabled=False,
                encoded_ring_buffer_seconds=15,
                evidence_retention_days=30,
                metadata_retention_days=90,
            ),
        ),
        queues=QueueLimits(decode=8, analytics=16, verifier=4, events=16),
    )


def _manifest() -> RuntimeModelManifestV1:
    now = datetime(2026, 7, 28, 9, 0, tzinfo=UTC)
    digest = "a" * 64
    artifact = ModelArtifactV1(
        schema_version="model-artifact.v1",
        artifact_id="person-primary-v1",
        sha256=digest,
        source="s3://kz-model-registry/person-primary-v1.onnx",
        commercial_rights=CommercialRightsRecordV1(
            schema_version="commercial-rights.v1",
            record_id="rights-person-v1",
            terms_reference="contracts/model-rights/person-primary-v1.pdf",
            commercial_use_approved=True,
        ),
        class_list=("person",),
        preprocessing="letterbox-rgb-640x640",
        analytic="person",
    )
    report = dict(
        artifact_id=artifact.artifact_id,
        passed=True,
        report_reference="reports/person-primary-v1.json",
        report_sha256="b" * 64,
        signed_by="pilot-qa",
        signed_at=now,
    )
    return RuntimeModelManifestV1(
        schema_version="deepstream-runtime-manifest.v1",
        site_id="customer-site-1",
        artifact=artifact,
        engine_sha256="c" * 64,
        precision="fp16",
        target_compute_capability="8.9",
        tensorrt_version="10.16.0.72",
        target_site_report=TargetSiteReportV1(
            schema_version="target-site-report.v1", site_id="customer-site-1", **report
        ),
        capacity_report=CapacityReportV1(
            schema_version="capacity-report.v1", stream_count=20, **report
        ),
        shadow_stage_report=ShadowStageReportV1(
            schema_version="shadow-stage-report.v1", **report
        ),
    )


def _manifest_with_files(tmp_path: Path) -> RuntimeModelManifestV1:
    model = tmp_path / "person.onnx"
    engine = tmp_path / "person.engine"
    model.write_bytes(b"approved-model")
    engine.write_bytes(b"approved-engine")
    manifest = _manifest()
    return manifest.model_copy(
        update={
            "artifact_path": model,
            "engine_path": engine,
            "artifact": manifest.artifact.model_copy(
                update={"sha256": hashlib.sha256(model.read_bytes()).hexdigest()}
            ),
            "engine_sha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
        }
    )


def test_shared_graph_uses_twenty_unique_source_bins_and_one_gpu_batch() -> None:
    graph = DeepStreamGraphSpec.from_site(_site())

    assert len(graph.sources) == 20
    assert {source.source_id for source in graph.sources} == set(range(20))
    assert graph.element("streammux").properties == {
        "batch-size": 20,
        "live-source": 1,
        "nvbuf-memory-type": "nvbuf-mem-cuda-device",
    }
    assert graph.primary_inference_count == 1
    assert graph.tracker_count == 1
    assert graph.analytics_count == 1
    assert all(source.has_encoded_evidence_branch for source in graph.sources)
    assert all(source.has_nvdec_branch for source in graph.sources)
    assert graph.element("primary-queue").properties == {
        "max-size-buffers": 16,
        "max-size-bytes": 0,
        "max-size-time": 0,
        "leaky": "downstream",
    }


def test_graph_rejects_wrong_feed_count_and_duplicate_source_ids() -> None:
    graph = DeepStreamGraphSpec.from_site(_site())
    with pytest.raises(GraphContractError, match="exactly 20"):
        graph.model_copy(update={"sources": graph.sources[:19]}).validate()
    duplicate = graph.model_copy(
        update={"sources": (graph.sources[0], graph.sources[0], *graph.sources[2:])}
    )
    with pytest.raises(GraphContractError, match="unique"):
        duplicate.validate()


def test_graph_rejects_unbounded_or_nonleaky_queues_and_cpu_frame_sinks() -> None:
    graph = DeepStreamGraphSpec.from_site(_site())
    queue = graph.element("primary-queue")
    unbounded = graph.replace_element(
        queue.model_copy(update={"properties": {"max-size-buffers": 0, "leaky": "downstream"}})
    )
    with pytest.raises(GraphContractError, match="bounded"):
        unbounded.validate()

    nonleaky = graph.replace_element(
        queue.model_copy(update={"properties": {"max-size-buffers": 16, "leaky": "no"}})
    )
    with pytest.raises(GraphContractError, match="downstream-leaky"):
        nonleaky.validate()

    forbidden = graph.with_element(name="display-copy", factory="appsink", properties={})
    with pytest.raises(GraphContractError, match="forbidden"):
        forbidden.validate()


def test_graph_rejects_per_camera_inference_or_tracker_stacks() -> None:
    graph = DeepStreamGraphSpec.from_site(_site())
    duplicated_infer = graph.with_element(
        name="camera-01-infer", factory="nvinfer", properties={"role": "primary"}
    )
    with pytest.raises(GraphContractError, match="one primary"):
        duplicated_infer.validate()

    duplicated_tracker = graph.with_element(
        name="camera-01-tracker", factory="nvtracker", properties={}
    )
    with pytest.raises(GraphContractError, match="one shared"):
        duplicated_tracker.validate()


def test_optional_analytics_are_disabled_and_isolated_by_valves_and_leaky_queues() -> None:
    graph = DeepStreamGraphSpec.from_site(_site())

    for module in ("fire_smoke", "weapon"):
        branch = graph.optional_branch(module)
        assert branch.enabled is False
        assert branch.shadow_only is True
        assert branch.valve.properties == {"drop": True}
        assert branch.queue.properties["leaky"] == "downstream"
        assert branch.queue.properties["max-size-buffers"] == 4
        assert branch.queue.properties["max-size-bytes"] == 0
        assert branch.queue.properties["max-size-time"] == 0


def test_runtime_manifest_fails_closed_for_missing_rights_hashes_or_target_mismatch() -> None:
    manifest = _manifest()
    assert manifest.validate_for_host(compute_capability="8.9", tensorrt_version="10.16.0.72") is None

    with pytest.raises(GraphContractError, match="engine sha256"):
        manifest.model_copy(update={"engine_sha256": None}).validate_for_host(
            compute_capability="8.9", tensorrt_version="10.16.0.72"
        )
    with pytest.raises(GraphContractError, match="commercial rights"):
        manifest.model_copy(
            update={"artifact": manifest.artifact.model_copy(update={"commercial_rights": None})}
        ).validate_for_host(compute_capability="8.9", tensorrt_version="10.16.0.72")
    with pytest.raises(GraphContractError, match="compute capability"):
        manifest.validate_for_host(compute_capability="8.6", tensorrt_version="10.16.0.72")
    with pytest.raises(GraphContractError, match="TensorRT"):
        manifest.validate_for_host(compute_capability="8.9", tensorrt_version="10.13.2.6")
    with pytest.raises(GraphContractError, match="person analytic"):
        manifest.model_copy(
            update={"artifact": manifest.artifact.model_copy(update={"analytic": "weapon"})}
        ).validate_for_host(compute_capability="8.9", tensorrt_version="10.16.0.72")
    with pytest.raises(GraphContractError, match="person class list"):
        manifest.model_copy(
            update={"artifact": manifest.artifact.model_copy(update={"class_list": ("person", "bag")})}
        ).validate_for_host(compute_capability="8.9", tensorrt_version="10.16.0.72")


def test_nvidia_bindings_are_loaded_only_when_the_target_adapter_starts(tmp_path: Path) -> None:
    def missing_bindings() -> object:
        raise ModuleNotFoundError("No module named 'gi'")

    manifest = _manifest_with_files(tmp_path)
    assert manifest.artifact_path is not None
    assert manifest.engine_path is not None
    config = tmp_path / "person_primary.txt"
    config.write_text(
        "\n".join(
            (
                "[property]",
                f"onnx-file={manifest.artifact_path}",
                f"model-engine-file={manifest.engine_path}",
            )
        ),
        encoding="utf-8",
    )
    runtime = DeepStreamDataPlane(
        runtime_manifest=manifest,
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        binding_loader=missing_bindings,
        person_config_path=config,
    )

    with pytest.raises(NvidiaBindingsUnavailable, match="NVIDIA DeepStream bindings"):
        runtime.start(_site())


def test_rtsp_locations_are_resolved_only_at_startup_and_never_embedded_in_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_url = "rtsp://operator:secret@camera.example.test/live"
    for number in range(1, 21):
        monkeypatch.setenv(
            f"PILOT_CAMERA_{number:02d}_RTSP",
            secret_url if number == 1 else f"rtsp://camera-{number:02d}.example.test/live",
        )

    locations = resolve_rtsp_locations(_site())
    graph = DeepStreamGraphSpec.from_site(_site())

    assert locations["camera-01"] == secret_url
    assert secret_url not in graph.model_dump_json()
    assert all("@" not in source.camera_id for source in graph.sources)


class Clocks:
    def __init__(self) -> None:
        self.monotonic_seconds = 0.0
        self.wall_time = datetime(2026, 7, 28, 9, 0, tzinfo=UTC)

    def monotonic(self) -> float:
        return self.monotonic_seconds

    def wall(self) -> datetime:
        return self.wall_time

    def advance(self, seconds: float) -> None:
        self.monotonic_seconds += seconds
        self.wall_time += timedelta(seconds=seconds)


def test_inner_rtsp_error_routes_to_its_camera_and_rebuilds_only_after_backoff() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01", "camera-02"),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    rebuilt: list[str] = []
    recovery = SourceRecoveryCoordinator(
        supervisor=supervisor,
        source_ids={"camera-01": 0, "camera-02": 1},
        rebuild_source=rebuilt.append,
    )

    recovery.handle_element_error("depay-0")
    assert supervisor.health_for("camera-01").state == "offline"
    assert supervisor.health_for("camera-02").state == "starting"
    clocks.advance(1.0)
    recovery.advance()

    assert rebuilt == ["camera-01"]
    assert supervisor.health_for("camera-01").state == "reconnecting"
    supervisor.accept_sample(camera_id="camera-01", source_time=clocks.wall(), monotonic_seq=0)
    assert supervisor.health_for("camera-01").state == "online"


def test_failed_camera_local_rebuild_returns_only_that_camera_to_backoff() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01", "camera-02"),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    recovery = SourceRecoveryCoordinator(
        supervisor=supervisor,
        source_ids={"camera-01": 0, "camera-02": 1},
        rebuild_source=lambda _: (_ for _ in ()).throw(RuntimeError("RTSP still unavailable")),
    )

    recovery.handle_element_error("rtsp-0")
    clocks.advance(1.0)
    recovery.advance()

    assert supervisor.health_for("camera-01").state == "offline"
    assert supervisor.health_for("camera-01").reconnect_count == 2
    assert supervisor.health_for("camera-02").state == "starting"


def test_stale_frame_heartbeat_enters_camera_local_recovery() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01", "camera-02"),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
        stale_after_seconds=5.0,
    )
    rebuilt: list[str] = []
    recovery = SourceRecoveryCoordinator(
        supervisor=supervisor,
        source_ids={"camera-01": 0, "camera-02": 1},
        rebuild_source=rebuilt.append,
    )

    assert supervisor.record_frame(
        camera_id="camera-01", source_time=clocks.wall() - timedelta(seconds=10), monotonic_seq=0
    ) is False
    recovery.handle_camera_failure("camera-01", "invalid_frame_heartbeat")
    clocks.advance(1.0)
    recovery.advance()

    assert rebuilt == ["camera-01"]
    assert supervisor.health_for("camera-02").state == "starting"


def test_repeated_child_bus_errors_do_not_multiply_one_camera_backoff() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01",),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    recovery = SourceRecoveryCoordinator(
        supervisor=supervisor,
        source_ids={"camera-01": 0},
        rebuild_source=lambda _: None,
    )

    recovery.handle_element_error("rtsp-0")
    recovery.handle_element_error("depay-0")

    assert supervisor.health_for("camera-01").reconnect_count == 1


def test_person_nvinfer_config_must_load_the_exact_hash_verified_paths(tmp_path: Path) -> None:
    manifest = _manifest_with_files(tmp_path)
    assert manifest.artifact_path is not None
    assert manifest.engine_path is not None
    config = tmp_path / "person_primary.txt"
    config.write_text(
        "\n".join(
            (
                "[property]",
                f"onnx-file={manifest.artifact_path}",
                f"model-engine-file={manifest.engine_path}",
            )
        ),
        encoding="utf-8",
    )

    assert person_config_paths_match(manifest, config) is None
    config.write_text(
        "[property]\nonnx-file=/wrong/model.onnx\nmodel-engine-file=/wrong/model.engine\n",
        encoding="utf-8",
    )
    with pytest.raises(GraphContractError, match="does not load manifest-verified"):
        person_config_paths_match(manifest, config)


def test_nvtracker_configuration_applies_documented_gstreamer_properties(tmp_path: Path) -> None:
    config = tmp_path / "nvtracker.yml"
    config.write_text(
        """tracker:
  tracker-width: 960
  tracker-height: 544
  gpu-id: 0
  enable-batch-process: 1
  enable-past-frame: 0
  ll-lib-file: /opt/nvidia/deepstream/lib/libnvds_nvmultiobjecttracker.so
  ll-config-file: /opt/nvidia/deepstream/config_tracker_NvDCF_perf.yml
""",
        encoding="utf-8",
    )

    class Tracker:
        def __init__(self) -> None:
            self.properties: dict[str, object] = {}

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

    tracker = Tracker()
    configure_nvtracker(tracker, config)

    assert tracker.properties == {
        "tracker-width": 960,
        "tracker-height": 544,
        "gpu-id": 0,
        "enable-batch-process": 1,
        "enable-past-frame": 0,
        "ll-lib-file": "/opt/nvidia/deepstream/lib/libnvds_nvmultiobjecttracker.so",
        "ll-config-file": "/opt/nvidia/deepstream/config_tracker_NvDCF_perf.yml",
    }


def test_deployment_artifacts_pin_the_target_and_shared_person_tracker_contract() -> None:
    root = Path(__file__).parents[2]
    dockerfile = (root / "deploy/pilot/Dockerfile.runtime").read_text(encoding="utf-8")
    person_config = (root / "deploy/pilot/deepstream/person_primary.txt").read_text(
        encoding="utf-8"
    )
    tracker_config = yaml.safe_load(
        (root / "deploy/pilot/deepstream/nvtracker.yml").read_text(encoding="utf-8")
    )

    assert f"FROM --platform=linux/amd64 {DEEPSTREAM_IMAGE}" in dockerfile
    assert "pydantic==2.13.4" in dockerfile
    assert "pyyaml==6.0.3" in dockerfile
    assert "ENTRYPOINT [\"python3\", \"-m\", \"protector.pilot.runtime.deepstream\"]" in dockerfile
    assert "batch-size=20" in person_config
    assert "network-mode=2" in person_config
    assert "onnx-file=/models/approved/person_primary.onnx" in person_config
    assert "model-engine-file=/models/approved/person_primary_l4_fp16.engine" in person_config
    assert tracker_config["tracker"]["enable-batch-process"] == 1
    assert "NvDCF" in tracker_config["tracker"]["ll-config-file"]


def test_metadata_publisher_emits_versioned_observations_without_cpu_surface_access() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01",),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    publisher = MetadataPublisher(supervisor=supervisor, model_artifact_id="person-primary-v1")

    published = publisher.publish(
        FrameMetadataV1(
            camera_id="camera-01",
            source_time=clocks.wall(),
            monotonic_seq=0,
            class_name="untrusted-label-file-value",
            confidence=0.91,
            bbox=(0.1, 0.2, 0.3, 0.4),
            track_id="tracker-7",
        )
    )

    assert published is not None
    assert published.schema_version == "observation.v1"
    assert published.camera_id == "camera-01"
    assert published.class_name == "person"
    assert published.model_artifact_id == "person-primary-v1"
    assert published.sample_kind == "fresh"


def test_objects_from_one_frame_publish_distinct_deterministic_observation_sequences() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01",),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    publisher = MetadataPublisher(supervisor=supervisor, model_artifact_id="person-primary-v1")
    first = publisher.publish(
        FrameMetadataV1(
            camera_id="camera-01",
            source_time=clocks.wall(),
            monotonic_seq=metadata_observation_sequence(3, 0),
            class_name="person",
            confidence=0.8,
            bbox=(0.1, 0.1, 0.2, 0.2),
        )
    )
    second = publisher.publish(
        FrameMetadataV1(
            camera_id="camera-01",
            source_time=clocks.wall(),
            monotonic_seq=metadata_observation_sequence(3, 1),
            class_name="person",
            confidence=0.9,
            bbox=(0.3, 0.3, 0.4, 0.4),
        )
    )

    assert [first.monotonic_seq, second.monotonic_seq] == [196608, 196609]
    assert len(supervisor.drain_observations()) == 2


def test_manifest_compares_model_and_engine_file_hashes_before_starting(tmp_path: Path) -> None:
    manifest = _manifest_with_files(tmp_path)
    assert manifest.engine_path is not None

    assert manifest.validate_for_host(
        compute_capability="8.9", tensorrt_version="10.16.0.72", require_files=True
    ) is None
    manifest.engine_path.write_bytes(b"tampered-engine")
    with pytest.raises(GraphContractError, match="engine file sha256"):
        manifest.validate_for_host(
            compute_capability="8.9", tensorrt_version="10.16.0.72", require_files=True
        )


def test_stop_uses_gst_null_and_partial_start_cleanup_does_not_leave_a_pipeline() -> None:
    class State:
        NULL = object()

    Gst = type("Gst", (), {"State": State})

    class Pipeline:
        def __init__(self) -> None:
            self.states: list[object] = []

        def set_state(self, state: object) -> None:
            self.states.append(state)

    pipeline = Pipeline()
    stop_pipeline(pipeline, Gst)

    assert pipeline.states == [State.NULL]


def test_target_entrypoint_refuses_to_start_without_a_site_and_runtime_manifest() -> None:
    with pytest.raises(SystemExit) as exit_status:
        main([])

    assert exit_status.value.code == 2


def test_deepstream_adapter_exposes_the_same_bounded_observation_drain_as_replay() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01",),
        observation_queue_size=2,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    supervisor.accept_sample(camera_id="camera-01", source_time=clocks.wall(), monotonic_seq=0)
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
    )
    runtime._supervisor = supervisor

    assert [item.camera_id for item in runtime.drain_observations()] == ["camera-01"]
    assert runtime.drain_observations() == []
