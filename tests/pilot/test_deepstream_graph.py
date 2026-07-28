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
    evidence_placeholder_properties,
    main,
    metadata_observation_sequence,
    person_config_paths_match,
    resolve_rtsp_locations,
    rtsp_caps_fields,
    should_link_rtsp_video_pad,
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
    config = tmp_path / "person_primary.txt"
    config.write_text(
        (
            f"[property]\nonnx-file={model}\nmodel-engine-file={engine}\nnetwork-mode=2\n"
            "batch-size=20\ninfer-dims=3;640;640\nmodel-color-format=0\n"
            "net-scale-factor=0.003921568627\nmaintain-aspect-ratio=1\nsymmetric-padding=1\n"
        ),
        encoding="utf-8",
    )
    manifest = _manifest()
    return manifest.model_copy(
        update={
            "artifact_path": model,
            "engine_path": engine,
            "artifact": manifest.artifact.model_copy(
                update={"sha256": hashlib.sha256(model.read_bytes()).hexdigest()}
            ),
            "engine_sha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
            "nvinfer_config_path": config,
            "nvinfer_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
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
        "batched-push-timeout": 40_000,
        "attach-sys-ts": False,
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


def test_pre_evidence_source_branch_has_nonblocking_discard_placeholder() -> None:
    class Element:
        def __init__(self, factory: str, name: str) -> None:
            self.factory = factory
            self.name = name
            self.properties: dict[str, object] = {}
            self.links: list[Element] = []

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

        def connect(self, *_: object) -> None:
            return None

        def link(self, other: Element) -> bool:
            self.links.append(other)
            return True

        def get_static_pad(self, name: str) -> tuple[str, str]:
            return self.name, name

    class Bin:
        def __init__(self, name: str) -> None:
            self.name = name
            self.elements: dict[str, Element] = {}
            self.ghost_pads: list[tuple[str, tuple[str, str]]] = []

        def add(self, element: Element) -> None:
            self.elements[element.name] = element

        def add_pad(self, pad: tuple[str, tuple[str, str]]) -> None:
            self.ghost_pads.append(pad)

    class Gst:
        class Bin:
            @staticmethod
            def new(name: str) -> Bin:
                return Bin(name)

        class ElementFactory:
            @staticmethod
            def make(factory: str, name: str) -> Element:
                return Element(factory, name)

        class Element:
            @staticmethod
            def link_many(*elements: Element) -> bool:
                return all(left.link(right) for left, right in zip(elements, elements[1:]))

        class GhostPad:
            @staticmethod
            def new(name: str, pad: tuple[str, str]) -> tuple[str, tuple[str, str]]:
                return name, pad

    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(), runtime_info=lambda: ("8.9", "10.16.0.72")
    )
    source_bin = runtime._build_source_bin(
        Gst, DeepStreamGraphSpec.from_site(_site()).sources[0], "rtsp://redacted"
    )

    evidence_queue = source_bin.elements["evidence-0"]
    discard = source_bin.elements["evidence-discard-0"]
    assert evidence_placeholder_properties() == {"sync": False, "async": False}
    assert evidence_queue.links == [discard]
    assert discard.factory == "fakesink"
    assert discard.properties == {"sync": False, "async": False}
    assert [name for name, _ in source_bin.ghost_pads] == ["decoded_src"]


def test_encoded_writer_replaces_discard_only_after_factory_succeeds() -> None:
    class Element:
        def __init__(self, factory: str, name: str) -> None:
            self.factory = factory
            self.name = name
            self.properties: dict[str, object] = {}
            self.links: list[Element] = []

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

        def connect(self, *_: object) -> None:
            return None

        def link(self, other: Element) -> bool:
            self.links.append(other)
            return True

        def get_static_pad(self, name: str) -> tuple[str, str]:
            return self.name, name

    class Bin:
        def __init__(self, name: str) -> None:
            self.name = name
            self.elements: dict[str, Element] = {}

        def add(self, element: Element) -> None:
            self.elements[element.name] = element

        def add_pad(self, _: object) -> None:
            return None

    class Gst:
        class Bin:
            @staticmethod
            def new(name: str) -> Bin:
                return Bin(name)

        class ElementFactory:
            @staticmethod
            def make(factory: str, name: str) -> Element:
                return Element(factory, name)

        class Element:
            @staticmethod
            def link_many(*elements: Element) -> bool:
                return all(left.link(right) for left, right in zip(elements, elements[1:]))

        class GhostPad:
            @staticmethod
            def new(name: str, pad: object) -> tuple[str, object]:
                return name, pad

    def writer_factory(gst: object, source: object) -> Element:
        return Gst.ElementFactory.make("splitmuxsink", f"evidence-writer-{source.source_id}")

    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=writer_factory,
    )
    source = DeepStreamGraphSpec.from_site(_site()).sources[0]
    source_bin = runtime._build_source_bin(Gst, source, "rtsp://redacted")

    queue = source_bin.elements["evidence-0"]
    writer = source_bin.elements["evidence-writer-0"]
    assert queue.links == [writer]
    assert "evidence-discard-0" not in source_bin.elements
    assert source_bin.elements["parse-0"].properties["config-interval"] == -1

    def failed_factory(_: object, __: object) -> Element:
        raise RuntimeError("writer unavailable")

    fallback_runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=failed_factory,
    )
    fallback = fallback_runtime._build_source_bin(Gst, source, "rtsp://redacted")
    assert fallback.elements["evidence-0"].links == [fallback.elements["evidence-discard-0"]]
    assert fallback_runtime.evidence_attachment_failures == 1


def test_rtsp_dynamic_pad_accepts_only_matching_video_rtp_caps() -> None:
    assert should_link_rtsp_video_pad(
        {"name": "application/x-rtp", "media": "video", "encoding-name": "H264"}, "h264"
    )
    assert not should_link_rtsp_video_pad(
        {"name": "application/x-rtp", "media": "audio", "encoding-name": "H264"}, "h264"
    )
    assert not should_link_rtsp_video_pad(
        {"name": "application/x-rtp", "media": "video", "encoding-name": "H265"}, "h264"
    )


def test_rtsp_caps_reader_ignores_missing_empty_and_structureless_caps() -> None:
    class EmptyCaps:
        def get_size(self) -> int:
            return 0

    class MissingStructureCaps:
        def get_size(self) -> int:
            return 1

        def get_structure(self, _: int) -> None:
            return None

    assert rtsp_caps_fields(None) is None
    assert rtsp_caps_fields(EmptyCaps()) is None
    assert rtsp_caps_fields(MissingStructureCaps()) is None


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
    runtime = DeepStreamDataPlane(
        runtime_manifest=manifest,
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        binding_loader=missing_bindings,
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


def test_rebuild_attempt_gets_a_fresh_five_second_first_frame_grace() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01",),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    supervisor.accept_sample(camera_id="camera-01", source_time=clocks.wall(), monotonic_seq=0)
    recovery = SourceRecoveryCoordinator(
        supervisor=supervisor,
        source_ids={"camera-01": 0},
        rebuild_source=lambda _: None,
        monotonic_clock=clocks.monotonic,
    )

    clocks.advance(5.1)
    recovery.handle_camera_failure("camera-01", "source_frame_timeout")
    clocks.advance(1.0)
    recovery.advance()
    assert recovery.first_frame_grace_expired("camera-01", grace_seconds=5.0) is False

    clocks.advance(4.1)
    assert recovery.first_frame_grace_expired("camera-01", grace_seconds=5.0) is False
    clocks.advance(1.0)
    assert recovery.first_frame_grace_expired("camera-01", grace_seconds=5.0) is True


def test_startup_watchdog_treats_monotonic_zero_as_a_valid_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
        monotonic_clock=clocks.monotonic,
    )
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(), runtime_info=lambda: ("8.9", "10.16.0.72")
    )
    runtime._pipeline = object()
    runtime._supervisor = supervisor
    runtime._recovery = recovery
    runtime._started_monotonic = 0.0
    monkeypatch.setattr(
        "protector.pilot.runtime.deepstream.time.monotonic", clocks.monotonic
    )

    clocks.advance(5.1)
    runtime._advance_recovery()

    assert supervisor.health_for("camera-01").state == "offline"


def test_internal_rtsp_child_resolves_camera_from_source_bin_ancestry() -> None:
    class Element:
        def __init__(self, name: str, parent: Element | None = None) -> None:
            self._name = name
            self._parent = parent

        def get_name(self) -> str:
            return self._name

        def get_parent(self) -> Element | None:
            return self._parent

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
        monotonic_clock=clocks.monotonic,
    )
    child = Element("udpsrc-internal-17", Element("rtp-session", Element("source-0")))

    assert recovery.camera_for_element(child) == "camera-01"
    fatal_calls: list[None] = []
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        fatal_callback=lambda: fatal_calls.append(None),
    )
    runtime._recovery = recovery
    message = type(
        "Message",
        (),
        {"src": child, "type": "error", "get_structure": lambda _: None},
    )()

    runtime._on_bus_message(None, message)

    assert supervisor.health_for("camera-01").state == "offline"
    assert runtime.failed_reason is None
    assert fatal_calls == []


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


def test_source_rebuild_retries_after_replacement_link_failed_and_old_bin_was_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Pad:
        def __init__(self, *, peer: Pad | None = None, link_result: int = 0) -> None:
            self._peer = peer
            self._link_result = link_result

        def get_peer(self) -> Pad | None:
            return self._peer

        def unlink(self, _: Pad) -> bool:
            self._peer = None
            return True

        def link(self, _: Pad) -> int:
            return self._link_result

    mux_pad = Pad()

    class Bin:
        def __init__(self, name: str, pad: Pad, *, sync_result: bool = True) -> None:
            self.name = name
            self.pad = pad
            self.sync_result = sync_result

        def get_static_pad(self, _: str) -> Pad:
            return self.pad

        def set_state(self, _: object) -> None:
            return None

        def sync_state_with_parent(self) -> bool:
            return self.sync_result

    class Mux:
        def get_static_pad(self, name: str) -> Pad | None:
            return mux_pad if name == "sink_0" else None

    class Pipeline:
        def __init__(self) -> None:
            self.elements: dict[str, object] = {
                "source-0": Bin("source-0", Pad(peer=mux_pad)),
                "streammux": Mux(),
            }

        def get_by_name(self, name: str) -> object | None:
            return self.elements.get(name)

        def add(self, element: Bin) -> None:
            self.elements[element.name] = element

        def remove(self, element: Bin) -> None:
            self.elements.pop(element.name, None)

    class Gst:
        class State:
            NULL = object()

        class PadLinkReturn:
            OK = 0

    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(), runtime_info=lambda: ("8.9", "10.16.0.72")
    )
    runtime._graph = DeepStreamGraphSpec.from_site(_site())
    runtime._pipeline = Pipeline()
    runtime._bindings = type("Bindings", (), {"gst": Gst})()
    runtime._locations = {"camera-01": "rtsp://redacted"}
    replacements = iter(
        (
            Bin("source-0", Pad(link_result=1)),
            Bin("source-0", Pad(link_result=0)),
        )
    )
    monkeypatch.setattr(runtime, "_build_source_bin", lambda *_: next(replacements))

    with pytest.raises(RuntimeError, match="relink"):
        runtime._rebuild_source("camera-01")
    runtime._rebuild_source("camera-01")

    assert runtime._pipeline.get_by_name("source-0") is not None


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
                "network-mode=2",
                "batch-size=20",
                "infer-dims=3;640;640",
                "model-color-format=0",
                "net-scale-factor=0.003921568627",
                "maintain-aspect-ratio=1",
                "symmetric-padding=1",
            )
        ),
        encoding="utf-8",
    )

    manifest = manifest.model_copy(
        update={
            "nvinfer_config_path": config,
            "nvinfer_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        }
    )
    assert person_config_paths_match(manifest, config) is None
    config.write_text(
        "[property]\nonnx-file=/wrong/model.onnx\nmodel-engine-file=/wrong/model.engine\n",
        encoding="utf-8",
    )
    with pytest.raises(GraphContractError, match="configuration sha256"):
        person_config_paths_match(manifest, config)


def test_signed_person_config_requires_symmetric_letterbox_padding(tmp_path: Path) -> None:
    manifest = _manifest_with_files(tmp_path)
    assert manifest.nvinfer_config_path is not None
    config = manifest.nvinfer_config_path
    config.write_text(
        config.read_text(encoding="utf-8").replace("symmetric-padding=1\n", ""),
        encoding="utf-8",
    )
    manifest = manifest.model_copy(
        update={"nvinfer_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest()}
    )

    with pytest.raises(GraphContractError, match="approved person preprocessing"):
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
    assert "symmetric-padding=1" in person_config
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


def test_malformed_frame_and_object_do_not_suppress_later_valid_metadata() -> None:
    class Node:
        def __init__(self, data: object, next_node: Node | None = None) -> None:
            self.data = data
            self.next = next_node

    class Cast:
        @staticmethod
        def cast(value: object) -> object:
            return value

    class Pyds:
        NvDsFrameMeta = Cast
        NvDsObjectMeta = Cast

    class Rect:
        left = 10.0
        top = 10.0
        width = 20.0
        height = 30.0

    class BadObject:
        confidence = 0.7
        object_id = 1

    class GoodObject:
        rect_params = Rect()
        confidence = 0.9
        object_id = 2

    clocks = Clocks()
    ntp = int(clocks.wall().timestamp() * 1_000_000_000)
    good_frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": ntp,
            "source_frame_width": 100,
            "source_frame_height": 100,
            "frame_num": 1,
            "obj_meta_list": Node(BadObject(), Node(GoodObject())),
        },
    )()
    bad_frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": ntp,
            "source_frame_width": 0,
            "source_frame_height": 100,
            "frame_num": 0,
            "obj_meta_list": None,
        },
    )()
    supervisor = CameraSupervisor(
        camera_ids=tuple(f"camera-{number:02d}" for number in range(1, 21)),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(), runtime_info=lambda: ("8.9", "10.16.0.72")
    )
    runtime._graph = DeepStreamGraphSpec.from_site(_site())
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor, model_artifact_id="person-primary-v1"
    )
    batch = type("Batch", (), {"frame_meta_list": Node(bad_frame, Node(good_frame))})()

    runtime._publish_batch_metadata(batch, Pyds)

    observations = runtime.drain_observations()
    assert len(observations) == 1
    assert observations[0].track_id == "2"
    assert runtime.invalid_metadata_count == 2
    assert supervisor.health_for("camera-01").state == "online"


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
