from __future__ import annotations

import hashlib
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
import yaml

import protector.pilot.runtime.deepstream as deepstream_module
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
    MeasuredCapacityReportV1,
    ModelArtifactV1,
    ShadowStageReportV1,
    TargetSiteReportV1,
    site_config_sha256,
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
    build_evidence_sink_factory,
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
from protector.pilot.runtime.evidence import (
    EncodedFragmentRing,
    SourceTimeMapper,
    SourceTimeMappingError,
    SplitMuxEvidenceSinkFactory,
)
from protector.pilot.runtime.mount_contract import (
    RuntimeBindMountV1,
    RuntimeMountContractV1,
    validate_runtime_mount_contract,
)
from protector.pilot.runtime.source_probe import CorrelatedNtpV1
from protector.pilot.runtime.supervisor import CameraSupervisor


def _site(*, feed_count: int = 20) -> SiteConfig:
    feeds = tuple(
        CameraFeed(
            camera_id=f"camera-{number:02d}",
            source_index=number - 1,
            rtsp_url=SecretReference(environment=f"PILOT_CAMERA_{number:02d}_RTSP"),
            codec="h264" if number % 2 else "h265",
            resolution=Resolution(width=1920, height=1080),
            fps=25.0,
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
        registry_entry_sha256="d" * 64,
        frozen_workload_sha256="e" * 64,
        expected_workload_sha256="f" * 64,
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
        shadow_stage_report=ShadowStageReportV1(schema_version="shadow-stage-report.v1", **report),
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
        def __init__(
            self,
            factory: str,
            name: str,
            *,
            link_result: bool = True,
        ) -> None:
            self.factory = factory
            self.name = name
            self.link_result = link_result
            self.properties: dict[str, object] = {}
            self.links: list[Element] = []

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

        def connect(self, *_: object) -> None:
            return None

        def link(self, other: Element) -> bool:
            self.links.append(other)
            return self.link_result

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
    with pytest.raises(RuntimeError, match="bounded evidence writer"):
        fallback_runtime._build_source_bin(Gst, source, "rtsp://redacted")
    assert fallback_runtime.evidence_attachment_failures == 1

    development_runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=None,
    )
    discard = development_runtime._build_source_bin(Gst, source, "rtsp://redacted")
    assert discard.elements["evidence-0"].links == [discard.elements["evidence-discard-0"]]

    class FailingGst(Gst):
        class ElementFactory:
            @staticmethod
            def make(factory: str, name: str) -> Element:
                return Element(factory, name, link_result=name != "decode-0")

    class RecordingWriterFactory:
        def __init__(self) -> None:
            self.writer = Element("splitmuxsink", "evidence-writer-0")
            self.unbound: list[Element] = []
            self.disabled: list[str] = []

        def __call__(self, _: object, __: object) -> Element:
            return self.writer

        def unbind_writer(self, writer: Element) -> None:
            self.unbound.append(writer)

        def disable(self, camera_id: str) -> None:
            self.disabled.append(camera_id)

    recording_factory = RecordingWriterFactory()
    failed_generation = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=recording_factory,
    )
    with pytest.raises(RuntimeError, match="evidence/NVDEC"):
        failed_generation._build_source_bin(
            FailingGst,
            source,
            "rtsp://redacted",
        )

    assert recording_factory.unbound == [recording_factory.writer]
    assert recording_factory.disabled == []

    for retry_via in ("rebuild", "stop"):

        class RetryingWriterFactory:
            def __init__(self) -> None:
                self.writer = Element("splitmuxsink", "evidence-writer-0")
                self.unbind_attempts: list[Element] = []
                self.disabled: list[str] = []

            def __call__(self, _: object, __: object) -> Element:
                return self.writer

            def unbind_writer(self, writer: Element) -> None:
                self.unbind_attempts.append(writer)
                if len(self.unbind_attempts) == 1:
                    raise RuntimeError("transient writer cleanup failure")

            def disable(self, camera_id: str) -> None:
                self.disabled.append(camera_id)

        retrying_factory = RetryingWriterFactory()
        retrying_runtime = DeepStreamDataPlane(
            runtime_manifest=_manifest(),
            runtime_info=lambda: ("8.9", "10.16.0.72"),
            evidence_sink_factory=retrying_factory,
        )
        with pytest.raises(RuntimeError, match="evidence/NVDEC"):
            retrying_runtime._build_source_bin(
                FailingGst,
                source,
                "rtsp://redacted",
            )
        assert retrying_factory.unbind_attempts == [retrying_factory.writer]

        healthy_writer = Element("splitmuxsink", "healthy-old-writer")
        if retry_via == "rebuild":
            retrying_runtime._active_source_generations[source.camera_id] = (
                deepstream_module._SourceGeneration(
                    camera_id=source.camera_id,
                    source_id=source.source_id,
                    ordinal=1,
                    source_bin=object(),
                    writer=healthy_writer,
                    lease=object(),  # type: ignore[arg-type]
                    lifecycle="authorized",
                    _writer_bound=True,
                )
            )
            retrying_runtime._retry_pending_generation_cleanup(source.camera_id)
        else:
            retrying_runtime.stop()

        assert retrying_factory.unbind_attempts == [
            retrying_factory.writer,
            retrying_factory.writer,
        ]
        assert healthy_writer not in retrying_factory.unbind_attempts
        assert retrying_factory.disabled == []


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


def test_native_source_generation_wires_only_observed_gstreamer_primitives() -> None:
    observed_times = iter((101, 102, 103, 104, 105))

    class Lease:
        def __init__(self) -> None:
            self.calls: list[tuple[object, ...]] = []
            self.close_calls = 0
            self.last_ntp_observed_monotonic_ns: int | None = None

        def observe_rtp_caps(self, codec: str, observed_monotonic_ns: int) -> bool:
            self.calls.append(("rtp", codec, observed_monotonic_ns))
            return True

        def observe_decoder_caps(
            self,
            width: int,
            height: int,
            fps_numerator: int,
            fps_denominator: int,
            observed_monotonic_ns: int,
        ) -> bool:
            self.calls.append(
                (
                    "decoder_caps",
                    width,
                    height,
                    fps_numerator,
                    fps_denominator,
                    observed_monotonic_ns,
                )
            )
            return True

        def observe_parser_buffer(
            self,
            byte_size: int,
            source_timestamp_ns: int,
            pts_ns: int,
            observed_monotonic_ns: int,
        ) -> bool:
            self.calls.append(
                (
                    "parser",
                    byte_size,
                    source_timestamp_ns,
                    pts_ns,
                    observed_monotonic_ns,
                )
            )
            return True

        def observe_decoded_buffer(
            self,
            pts_ns: int,
            observed_monotonic_ns: int,
        ) -> bool:
            self.calls.append(("decoded", pts_ns, observed_monotonic_ns))
            return True

        def observe_nvds_ntp(
            self,
            pts_ns: int,
            source_ntp_ns: int,
            observed_monotonic_ns: int,
        ) -> bool:
            self.calls.append(("ntp", pts_ns, source_ntp_ns, observed_monotonic_ns))
            self.last_ntp_observed_monotonic_ns = observed_monotonic_ns
            return True

        def correlated_ntp(
            self,
            pts_ns: int,
            source_ntp_ns: int,
        ) -> CorrelatedNtpV1 | None:
            if self.last_ntp_observed_monotonic_ns is None:
                return None
            return CorrelatedNtpV1(
                pts_ns=pts_ns,
                source_ntp_ns=source_ntp_ns,
                parser_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
                decoded_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
                ntp_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
                completed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
            )

        def close(self) -> None:
            self.close_calls += 1

    class LeaseFactory:
        def __init__(self, lease: Lease) -> None:
            self.lease = lease
            self.acquisitions: list[tuple[str, int]] = []

        def acquire(self, camera_id: str, source_id: int) -> Lease:
            self.acquisitions.append((camera_id, source_id))
            return self.lease

    class Structure:
        def __init__(self, name: str, values: dict[str, object]) -> None:
            self._name = name
            self._values = values

        def get_name(self) -> str:
            return self._name

        def get_string(self, name: str) -> str | None:
            value = self._values.get(name)
            return value if isinstance(value, str) else None

        def get_value(self, name: str) -> object:
            return self._values[name]

    class Caps:
        def __init__(self, structure: Structure) -> None:
            self.structure = structure

        def get_size(self) -> int:
            return 1

        def get_structure(self, _: int) -> Structure:
            return self.structure

    class Pad:
        def __init__(self, name: str) -> None:
            self.name = name
            self.probes: list[tuple[object, object, tuple[object, ...]]] = []
            self.current_caps: Caps | None = None
            self.linked = False

        def add_probe(
            self,
            probe_type: object,
            callback: object,
            *arguments: object,
        ) -> None:
            self.probes.append((probe_type, callback, arguments))

        def get_current_caps(self) -> Caps | None:
            return self.current_caps

        def query_caps(self, _: object) -> Caps | None:
            return self.current_caps

        def is_linked(self) -> bool:
            return self.linked

        def link(self, _: Pad) -> int:
            self.linked = True
            return 0

    class Element:
        def __init__(self, factory: str, name: str) -> None:
            self.factory = factory
            self.name = name
            self.properties: dict[str, object] = {}
            self.links: list[Element] = []
            self.pads = {"src": Pad(f"{name}:src"), "sink": Pad(f"{name}:sink")}
            self.connections: list[tuple[str, object, tuple[object, ...]]] = []

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

        def connect(self, signal_name: str, callback: object, *arguments: object) -> None:
            self.connections.append((signal_name, callback, arguments))

        def link(self, other: Element) -> bool:
            self.links.append(other)
            return True

        def get_static_pad(self, name: str) -> Pad:
            return self.pads[name]

    class Bin:
        def __init__(self, name: str) -> None:
            self.name = name
            self.elements: dict[str, Element] = {}
            self.ghost_pads: dict[str, Pad] = {}

        def add(self, element: Element) -> None:
            self.elements[element.name] = element

        def add_pad(self, pad: tuple[str, Pad]) -> None:
            self.ghost_pads[pad[0]] = pad[1]

        def get_by_name(self, name: str) -> Element | None:
            return self.elements.get(name)

        def get_static_pad(self, name: str) -> Pad:
            return self.ghost_pads[name]

    class Gst:
        CLOCK_TIME_NONE = 2**64 - 1

        class PadProbeType:
            BUFFER = "buffer"
            EVENT_DOWNSTREAM = "event-downstream"

        class PadProbeReturn:
            OK = "ok"

        class EventType:
            CAPS = "caps"

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
            def new(name: str, pad: Pad) -> tuple[str, Pad]:
                return name, pad

    class Pyds:
        configured: list[int] = []

        @classmethod
        def configure_source_for_ntp_sync(cls, source_hash: int) -> None:
            cls.configured.append(source_hash)

    class Info:
        def __init__(self, *, buffer: object | None = None, event: object | None = None) -> None:
            self.buffer = buffer
            self.event = event

        def get_buffer(self) -> object | None:
            return self.buffer

        def get_event(self) -> object | None:
            return self.event

    class Buffer:
        def __init__(self, *, size: int, dts: int, pts: int) -> None:
            self.size = size
            self.dts = dts
            self.pts = pts

        def get_size(self) -> int:
            return self.size

    class Event:
        type = Gst.EventType.CAPS

        def __init__(self, caps: Caps) -> None:
            self.caps = caps

        def parse_caps(self) -> Caps:
            return self.caps

    lease = Lease()
    factory = LeaseFactory(lease)
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=factory,
        monotonic_ns=lambda: next(observed_times),
    )
    runtime._bindings = deepstream_module._NvidiaBindings(
        gst=Gst,
        glib=object(),
        pyds=Pyds,
    )
    graph = DeepStreamGraphSpec.from_site(_site())
    source = graph.sources[0]
    generation = runtime._build_source_generation(
        Gst,
        source,
        "rtsp://redacted",
    )
    runtime._graph = graph
    generation.lifecycle = "live_unauthorized"
    runtime._active_source_generations[source.camera_id] = generation
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=tuple(item.camera_id for item in graph.sources),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )

    source_bin = generation.source_bin
    rtspsrc = source_bin.elements["rtsp-0"]
    dynamic_pad = Pad("rtsp-video")
    dynamic_pad.current_caps = Caps(
        Structure(
            "application/x-rtp",
            {"media": "video", "encoding-name": "H264"},
        )
    )
    _, pad_added, pad_arguments = rtspsrc.connections[0]
    pad_added(rtspsrc, dynamic_pad, *pad_arguments)

    decoder_src = source_bin.elements["nvdec-0"].get_static_pad("src")
    decoder_caps_probe = next(
        probe for probe in decoder_src.probes if probe[0] == Gst.PadProbeType.EVENT_DOWNSTREAM
    )
    decoder_caps_probe[1](
        decoder_src,
        Info(
            event=Event(
                Caps(
                    Structure(
                        "video/x-raw",
                        {"width": 1280, "height": 720, "framerate": (30000, 1001)},
                    )
                )
            )
        ),
        *decoder_caps_probe[2],
    )
    decoder_buffer_probe = next(
        probe for probe in decoder_src.probes if probe[0] == Gst.PadProbeType.BUFFER
    )
    decoder_buffer_probe[1](
        decoder_src,
        Info(buffer=Buffer(size=1, dts=0, pts=7_000_000_000)),
        *decoder_buffer_probe[2],
    )
    parser_src = source_bin.elements["parse-0"].get_static_pad("src")
    parser_probe = next(probe for probe in parser_src.probes if probe[0] == Gst.PadProbeType.BUFFER)
    parser_probe[1](
        parser_src,
        Info(buffer=Buffer(size=4096, dts=6_960_000_000, pts=7_000_000_000)),
        *parser_probe[2],
    )
    ntp_timestamp = int(clocks.wall().timestamp() * 1_000_000_000)
    runtime._publish_frame_metadata(
        type(
            "Frame",
            (),
            {
                "source_id": 0,
                "ntp_timestamp": ntp_timestamp,
                "buf_pts": 7_000_000_000,
                "source_frame_width": 1280,
                "source_frame_height": 720,
                "frame_num": 1,
                "obj_meta_list": None,
            },
        )(),
        type("PydsMetadata", (), {})(),
    )

    assert factory.acquisitions == [("camera-01", 0)]
    assert Pyds.configured == [hash(rtspsrc)]
    assert lease.calls == [
        ("rtp", "h264", 101),
        ("decoder_caps", 1280, 720, 30000, 1001, 102),
        ("decoded", 7_000_000_000, 103),
        ("parser", 4096, 6_960_000_000, 7_000_000_000, 104),
        ("ntp", 7_000_000_000, ntp_timestamp, 105),
    ]
    assert supervisor.health_for(source.camera_id).state == "online"


def test_missing_native_ntp_configuration_closes_the_acquired_generation() -> None:
    class Lease:
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    class Factory:
        def __init__(self, lease: Lease) -> None:
            self.lease = lease

        def acquire(self, camera_id: str, source_id: int) -> Lease:
            assert (camera_id, source_id) == ("camera-01", 0)
            return self.lease

    class Element:
        def set_property(self, _: str, __: object) -> None:
            return None

    class Gst:
        class Bin:
            @staticmethod
            def new(_: str) -> object:
                return object()

        class ElementFactory:
            @staticmethod
            def make(_: str, __: str) -> Element:
                return Element()

    lease = Lease()
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=Factory(lease),
    )
    runtime._bindings = deepstream_module._NvidiaBindings(
        gst=Gst,
        glib=object(),
        pyds=object(),
    )

    with pytest.raises(RuntimeError, match="NTP sync"):
        runtime._build_source_generation(
            Gst,
            DeepStreamGraphSpec.from_site(_site()).sources[0],
            "rtsp://redacted",
        )

    assert lease.close_calls == 1


def test_runtime_manifest_fails_closed_for_missing_rights_hashes_or_target_mismatch() -> None:
    manifest = _manifest()
    assert (
        manifest.validate_for_host(compute_capability="8.9", tensorrt_version="10.16.0.72") is None
    )

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
            update={
                "artifact": manifest.artifact.model_copy(update={"class_list": ("person", "bag")})
            }
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


def test_every_data_plane_start_uses_a_fresh_injectable_runtime_session_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduled: list[tuple[int, object]] = []
    publications: list[tuple[object, str, str]] = []

    class Gst:
        class State:
            NULL = "NULL"
            PLAYING = "PLAYING"

        class StateChangeReturn:
            FAILURE = "FAILURE"

    class Glib:
        @staticmethod
        def timeout_add(interval: int, callback: object) -> None:
            scheduled.append((interval, callback))
            return None

    class Bus:
        def add_signal_watch(self) -> None:
            return None

        def connect(self, *_: object) -> None:
            return None

    class Pipeline:
        def get_bus(self) -> Bus:
            return Bus()

        def set_state(self, _: object) -> str:
            return "SUCCESS"

    for number in range(1, 21):
        monkeypatch.setenv(
            f"PILOT_CAMERA_{number:02d}_RTSP",
            f"rtsp://camera-{number:02d}.example.test/live",
        )
    seeds = iter(
        (
            UUID("11111111-1111-1111-1111-111111111111"),
            UUID("22222222-2222-2222-2222-222222222222"),
        )
    )

    class Publisher:
        def enqueue(
            self,
            health: object,
            *,
            analytics_state: str,
            evidence_state: str,
        ) -> None:
            publications.append((health, analytics_state, evidence_state))

        def close(self) -> None:
            return None

    class LeaseFactory:
        def acquire(self, camera_id: str, source_id: int) -> object:
            raise AssertionError(f"stubbed pipeline unexpectedly acquired {camera_id}/{source_id}")

    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest_with_files(tmp_path),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        binding_loader=lambda: deepstream_module._NvidiaBindings(
            gst=Gst,
            glib=Glib,
            pyds=object(),
        ),
        runtime_session_seed_factory=lambda: next(seeds),
        telemetry_publisher_factory=lambda _: Publisher(),
        native_probe_lease_factory=LeaseFactory(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(
        runtime,
        "_build_pipeline",
        lambda *_: Pipeline(),
    )

    runtime.start(_site())
    first_epoch = runtime.health()[0].stream_epoch
    assert [interval for interval, _ in scheduled] == [250, 1_000]
    assert scheduled[1][1]() is True  # type: ignore[operator]
    assert len(publications[0][0]) == 20  # type: ignore[arg-type]
    assert publications[0][1:] == ("degraded", "failed")
    runtime.stop()
    runtime.start(_site())
    second_epoch = runtime.health()[0].stream_epoch
    runtime.stop()

    assert first_epoch != second_epoch
    assert [interval for interval, _ in scheduled] == [250, 1_000, 250, 1_000]


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


class _CorrelatedLease:
    def __init__(self) -> None:
        self.ntp_calls: list[tuple[int, int, int]] = []
        self.close_calls = 0
        self.last_ntp_observed_monotonic_ns: int | None = None

    def observe_nvds_ntp(
        self,
        pts_ns: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        self.ntp_calls.append((pts_ns, source_ntp_ns, observed_monotonic_ns))
        self.last_ntp_observed_monotonic_ns = observed_monotonic_ns
        return True

    def correlated_ntp(
        self,
        pts_ns: int,
        source_ntp_ns: int,
    ) -> CorrelatedNtpV1 | None:
        if self.last_ntp_observed_monotonic_ns is None:
            return None
        return CorrelatedNtpV1(
            pts_ns=pts_ns,
            source_ntp_ns=source_ntp_ns,
            parser_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
            decoded_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
            ntp_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
            completed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
        )

    def close(self) -> None:
        self.close_calls += 1


def _own_metadata_frame(
    runtime: DeepStreamDataPlane,
    graph: DeepStreamGraphSpec,
    *,
    source_id: int,
    pts_ns: int,
) -> _CorrelatedLease:
    source = next(item for item in graph.sources if item.source_id == source_id)
    generation = runtime._active_source_generations.get(source.camera_id)
    if generation is None:
        lease = _CorrelatedLease()
        generation = deepstream_module._SourceGeneration(
            camera_id=source.camera_id,
            source_id=source.source_id,
            ordinal=1,
            source_bin=object(),
            writer=None,
            lease=lease,  # type: ignore[arg-type]
            lifecycle="live_unauthorized",
        )
        runtime._active_source_generations[source.camera_id] = generation
        runtime._metadata_source_generations[source.camera_id] = generation
    else:
        lease = generation.lease
        assert isinstance(lease, _CorrelatedLease)
    runtime._record_metadata_owner(  # noqa: SLF001
        source.camera_id,
        lease,  # type: ignore[arg-type]
        pts_ns,
    )
    return lease


def test_inner_rtsp_error_routes_to_its_camera_and_rebuilds_only_after_backoff() -> None:
    clocks = Clocks()
    supervisor = CameraSupervisor(
        camera_ids=("camera-01", "camera-02"),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    rebuilt: list[tuple[str, object]] = []

    def rebuild(camera_id: str) -> None:
        rebuilt.append((camera_id, supervisor.health_for(camera_id).stream_epoch))

    initial_epoch = supervisor.health_for("camera-01").stream_epoch
    recovery = SourceRecoveryCoordinator(
        supervisor=supervisor,
        source_ids={"camera-01": 0, "camera-02": 1},
        rebuild_source=rebuild,
    )

    recovery.handle_element_error("depay-0")
    assert supervisor.health_for("camera-01").state == "offline"
    assert supervisor.health_for("camera-02").state == "starting"
    clocks.advance(1.0)
    recovery.advance()

    assert rebuilt == [("camera-01", supervisor.health_for("camera-01").stream_epoch)]
    assert rebuilt[0][1] != initial_epoch
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
    monkeypatch.setattr("protector.pilot.runtime.deepstream.time.monotonic", clocks.monotonic)

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


def test_splitmux_bus_close_maps_source_time_and_adopts_through_live_runtime(
    tmp_path: Path,
) -> None:
    class Element:
        def __init__(self, name: str) -> None:
            self.name = name
            self.properties: dict[str, object] = {}
            self.states: list[object] = []

        def get_name(self) -> str:
            return self.name

        def get_parent(self) -> None:
            return None

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

        def set_state(self, state: object) -> None:
            self.states.append(state)

    class Gst:
        class State:
            NULL = "null"

        class ElementFactory:
            @staticmethod
            def make(_: str, name: str) -> Element:
                return Element(name)

    class Structure:
        def __init__(self, name: str, **values: object) -> None:
            self.name = name
            self.values = values

        def get_name(self) -> str:
            return self.name

        def get_value(self, name: str) -> object:
            return self.values[name]

    class Message:
        type = "element"

        def __init__(self, src: Element, structure: Structure) -> None:
            self.src = src
            self.structure = structure

        def get_structure(self) -> Structure:
            return self.structure

    ring = EncodedFragmentRing(
        tmp_path / "spool",
        ring_seconds=15,
        max_camera_bytes=1_000,
        max_spool_bytes=2_000,
    )
    factory = SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=2,
        max_fragment_bytes=100,
        packet_probe=lambda _: True,
    )
    graph = DeepStreamGraphSpec.from_site(_site())
    source = graph.sources[0]
    sink = factory(Gst, source)
    part = Path(str(sink.properties["location"]).replace("%05d", "00001"))
    part.write_bytes(b"runtime-closed-fragment")
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=factory,
    )
    supervisor = CameraSupervisor(
        camera_ids=tuple(item.camera_id for item in graph.sources),
        observation_queue_size=4,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: datetime(2026, 7, 28, 9, 0, tzinfo=UTC),
    )
    runtime._graph = graph
    runtime._supervisor = supervisor
    runtime._bindings = type("Bindings", (), {"gst": Gst})()
    epoch = str(supervisor.health_for(source.camera_id).stream_epoch)
    factory.bind_writer(sink, stream_epoch=epoch)
    runtime._active_source_generations[source.camera_id] = deepstream_module._SourceGeneration(
        camera_id=source.camera_id,
        source_id=source.source_id,
        ordinal=1,
        source_bin=object(),
        writer=sink,
        lease=_CorrelatedLease(),  # type: ignore[arg-type]
        lifecycle="authorized",
        authorized_running_time_ns=8_000_000_000,
        authorized_stream_epoch=epoch,
        _writer_bound=True,
    )
    runtime._source_time_mapper.anchor(
        camera_id=source.camera_id,
        stream_epoch=epoch,
        running_time_ns=10_000_000_000,
        source_time=datetime(2026, 7, 28, 9, 0, tzinfo=UTC),
    )

    runtime._on_bus_message(
        None,
        Message(
            sink,
            Structure(
                "splitmuxsink-fragment-opened",
                location=str(part),
                **{"running-time": 9_000_000_000},
            ),
        ),
    )
    runtime._on_bus_message(
        None,
        Message(
            sink,
            Structure(
                "splitmuxsink-fragment-closed",
                location=str(part),
                **{"running-time": 11_000_000_000},
            ),
        ),
    )

    fragments = ring.fragments(source.camera_id)
    assert len(fragments) == 1
    assert fragments[0].stream_epoch == epoch
    assert fragments[0].start_at == datetime(2026, 7, 28, 8, 59, 59, tzinfo=UTC)
    assert not part.exists()

    oversized = part.with_name("00002.part.mp4")
    oversized.write_bytes(b"x" * 101)
    runtime._on_bus_message(
        None,
        Message(
            sink,
            Structure(
                "splitmuxsink-fragment-opened",
                location=str(oversized),
                **{"running-time": 12_000_000_000},
            ),
        ),
    )
    runtime._on_bus_message(
        None,
        Message(
            sink,
            Structure(
                "splitmuxsink-fragment-closed",
                location=str(oversized),
                **{"running-time": 14_000_000_000},
            ),
        ),
    )
    assert runtime.evidence_attachment_failures == 1
    assert sink.states == ["null"]
    assert supervisor.health_for(source.camera_id).state == "offline"


def test_target_config_builds_the_bounded_writer_instead_of_discarding_encoded_branch(
    tmp_path: Path,
) -> None:
    site = _site()
    retention = site.storage.retention.model_copy(
        update={
            "encoded_spool_root": tmp_path / "owned-spool",
            "encoded_ring_max_camera_bytes": 1_000,
            "encoded_ring_max_spool_bytes": 20_000,
            "encoded_fragment_max_bytes": 100,
        }
    )
    configured = site.model_copy(
        update={
            "storage": site.storage.model_copy(
                update={"retention": retention},
            )
        }
    )

    factory = build_evidence_sink_factory(configured)

    assert factory.ring.root == (tmp_path / "owned-spool").resolve()
    assert factory.fragment_seconds == 2
    assert factory.max_fragment_bytes == 100


def test_runtime_stop_clears_writer_generation_and_allows_clean_restart(
    tmp_path: Path,
) -> None:
    class Element:
        def __init__(self) -> None:
            self.properties: dict[str, object] = {}

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

    class Gst:
        class State:
            NULL = "null"

        class ElementFactory:
            @staticmethod
            def make(_: str, __: str) -> Element:
                return Element()

    class Pipeline:
        def __init__(self) -> None:
            self.states: list[object] = []

        def set_state(self, state: object) -> None:
            self.states.append(state)

    class Structure:
        def get_name(self) -> str:
            return "splitmuxsink-fragment-closed"

        def get_value(self, name: str) -> object:
            return {
                "location": "/already/removed/old.part.mp4",
                "running-time": 2_000_000_000,
            }[name]

    ring = EncodedFragmentRing(
        tmp_path / "spool",
        ring_seconds=15,
        max_camera_bytes=1_000,
        max_spool_bytes=2_000,
    )
    factory = SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=2,
        max_fragment_bytes=100,
    )
    graph = DeepStreamGraphSpec.from_site(_site())
    source = graph.sources[0]
    old_writer = factory(Gst, source)
    epoch = "epoch-before-stop"
    factory.bind_writer(old_writer, stream_epoch=epoch)
    open_part = Path(str(old_writer.properties["location"]).replace("%05d", "00001"))
    open_part.write_bytes(b"unadopted")
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=factory,
    )
    pipeline = Pipeline()
    runtime._graph = graph
    runtime._pipeline = pipeline
    runtime._bindings = type("Bindings", (), {"gst": Gst})()

    runtime.stop()

    assert pipeline.states == ["null"]
    assert not open_part.exists()
    assert ring.used_bytes == 0
    assert (
        factory.handle_writer_message(
            writer=old_writer,
            structure=Structure(),
            source_time_mapper=SourceTimeMapper(),
        )
        is None
    )
    restarted_writer = factory(Gst, source)
    factory.bind_writer(restarted_writer, stream_epoch="epoch-after-stop")
    assert ring.used_bytes == 100


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


def test_source_rebuild_link_failure_restores_old_generation_before_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Pad:
        def __init__(self, *, peer: Pad | None = None, link_result: int = 0) -> None:
            self._peer = peer
            self._link_result = link_result
            self.linked_to: list[Pad] = []
            self.unlinked_from: list[Pad] = []

        def get_peer(self) -> Pad | None:
            return self._peer

        def unlink(self, other: Pad) -> bool:
            self.unlinked_from.append(other)
            self._peer = None
            return True

        def link(self, other: Pad) -> int:
            self.linked_to.append(other)
            if self._link_result == 0:
                self._peer = other
            return self._link_result

        def add_probe(self, _: object, callback: object) -> int:
            callback(self, object())  # type: ignore[operator]
            return 1

        @staticmethod
        def remove_probe(_: int) -> None:
            return None

        @staticmethod
        def send_event(_: object) -> bool:
            return True

    mux_pad = Pad()

    class Bin:
        def __init__(self, name: str, pad: Pad, *, sync_result: bool = True) -> None:
            self.name = name
            self.pad = pad
            self.sync_result = sync_result
            self.states: list[object] = []

        def get_static_pad(self, _: str) -> Pad:
            return self.pad

        def get_by_name(self, _: str) -> None:
            return None

        def set_state(self, state: object) -> None:
            self.states.append(state)

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
            self.added: list[Bin] = []
            self.removed: list[Bin] = []

        def get_by_name(self, name: str) -> object | None:
            return self.elements.get(name)

        def add(self, element: Bin) -> bool:
            self.added.append(element)
            self.elements[element.name] = element
            return True

        def remove(self, element: Bin) -> bool:
            self.removed.append(element)
            self.elements.pop(element.name, None)
            return True

    class Gst:
        class State:
            NULL = object()

        class PadLinkReturn:
            OK = 0

        class PadProbeType:
            IDLE = 1
            BLOCK_DOWNSTREAM = 2

        class PadProbeReturn:
            OK = "ok"

        class Event:
            @staticmethod
            def new_flush_start() -> str:
                return "flush-start"

            @staticmethod
            def new_flush_stop(reset_time: bool) -> tuple[str, bool]:
                return "flush-stop", reset_time

    class Lease:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    class Factory:
        def __init__(self, leases: list[Lease]) -> None:
            self.leases = iter(leases)
            self.acquisitions: list[tuple[str, int]] = []

        def acquire(self, camera_id: str, source_id: int) -> Lease:
            self.acquisitions.append((camera_id, source_id))
            return next(self.leases)

    old_lease = Lease()
    successful_lease = Lease()
    factory = Factory([old_lease, successful_lease])
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=factory,
    )
    runtime._graph = DeepStreamGraphSpec.from_site(_site())
    pipeline = Pipeline()
    runtime._pipeline = pipeline
    runtime._bindings = type("Bindings", (), {"gst": Gst})()
    runtime._locations = {"camera-01": "rtsp://redacted"}
    old_bin = pipeline.get_by_name("source-0")
    assert isinstance(old_bin, Bin)
    old_facade = deepstream_module._TransactionalSourceProbeLease(
        factory=factory,  # type: ignore[arg-type]
        camera_id="camera-01",
        source_id=0,
    )
    old_facade.activate()
    runtime._active_source_generations["camera-01"] = deepstream_module._SourceGeneration(
        camera_id="camera-01",
        source_id=0,
        ordinal=1,
        source_bin=old_bin,
        writer=None,
        lease=old_facade,
    )
    replacements = iter(
        (
            Bin("source-0-generation-2", Pad(link_result=1)),
            Bin("source-0-generation-3", Pad(link_result=0)),
        )
    )
    monkeypatch.setattr(runtime, "_build_source_bin", lambda *_: next(replacements))

    with pytest.raises(RuntimeError, match="relink"):
        runtime._rebuild_source("camera-01")
    assert runtime._active_source_generations["camera-01"].source_bin is old_bin
    assert old_lease.close_calls == 0
    assert factory.acquisitions == [("camera-01", 0)]
    assert old_bin.pad.linked_to[-1] is mux_pad

    runtime._rebuild_source("camera-01")

    current = runtime._active_source_generations["camera-01"]
    assert current.source_bin.name == "source-0-generation-3"
    assert current.lease.active
    assert old_lease.close_calls == 1
    assert successful_lease.close_calls == 0
    assert factory.acquisitions == [("camera-01", 0), ("camera-01", 0)]


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

    assert (
        supervisor.record_frame(
            camera_id="camera-01",
            source_time=clocks.wall() - timedelta(seconds=10),
            monotonic_seq=0,
        )
        is False
    )
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
    assert 'ENTRYPOINT ["python3", "-m", "protector.pilot.runtime.deepstream"]' in dockerfile
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


def test_frame_metadata_anchors_splitmux_running_time_to_camera_rtcp_utc() -> None:
    clocks = Clocks()
    graph = DeepStreamGraphSpec.from_site(_site())
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in graph.sources),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
    )
    runtime._graph = graph
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )
    ntp_timestamp = int(clocks.wall().timestamp() * 1_000_000_000)
    frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": ntp_timestamp,
            "buf_pts": 7_000_000_000,
            "source_frame_width": 1920,
            "source_frame_height": 1080,
            "frame_num": 1,
            "obj_meta_list": None,
        },
    )()
    pyds = type("Pyds", (), {})()

    _own_metadata_frame(runtime, graph, source_id=0, pts_ns=7_000_000_000)
    runtime._publish_frame_metadata(frame, pyds)

    camera_id = graph.sources[0].camera_id
    epoch = str(supervisor.health_for(camera_id).stream_epoch)
    assert runtime._source_time_mapper.map(
        camera_id=camera_id,
        stream_epoch=epoch,
        running_time_ns=8_000_000_000,
    ) == clocks.wall() + timedelta(seconds=1)


def test_missing_camera_ntp_never_marks_online_publishes_or_anchors() -> None:
    clocks = Clocks()
    graph = DeepStreamGraphSpec.from_site(_site())
    camera_id = graph.sources[0].camera_id
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in graph.sources),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    failures: list[tuple[str, str]] = []
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
    )
    runtime._graph = graph
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )
    runtime._recovery = type(
        "Recovery",
        (),
        {
            "handle_camera_failure": lambda _self, camera, reason, **_: failures.append(
                (camera, reason)
            )
        },
    )()
    frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": 0,
            "buf_pts": 7_000_000_000,
            "source_frame_width": 1920,
            "source_frame_height": 1080,
            "frame_num": 1,
            "obj_meta_list": None,
        },
    )()

    _own_metadata_frame(runtime, graph, source_id=0, pts_ns=7_000_000_000)
    runtime._publish_frame_metadata(frame, type("Pyds", (), {})())

    assert failures == [(camera_id, "camera_rtcp_time_unavailable")]
    assert supervisor.health_for(camera_id).state == "starting"
    assert supervisor.drain_observations() == []
    with pytest.raises(SourceTimeMappingError, match="not anchored"):
        runtime._source_time_mapper.map(
            camera_id=camera_id,
            stream_epoch=str(supervisor.health_for(camera_id).stream_epoch),
            running_time_ns=7_000_000_000,
        )


def test_rtcp_discontinuity_enters_recovery_and_reanchors_only_in_new_epoch() -> None:
    clocks = Clocks()
    graph = DeepStreamGraphSpec.from_site(_site())
    camera_id = graph.sources[0].camera_id
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in graph.sources),
        observation_queue_size=4,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    recovery = SourceRecoveryCoordinator(
        supervisor=supervisor,
        source_ids={camera_id: 0},
        rebuild_source=lambda _: None,
        monotonic_clock=clocks.monotonic,
    )
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
    )
    runtime._graph = graph
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )
    runtime._recovery = recovery
    runtime._source_time_mapper = SourceTimeMapper(max_anchor_error_seconds=0.050)
    initial_epoch = supervisor.health_for(camera_id).stream_epoch

    def frame(*, source_time: datetime, running_time_ns: int, number: int) -> object:
        return type(
            "Frame",
            (),
            {
                "source_id": 0,
                "ntp_timestamp": int(source_time.timestamp() * 1_000_000_000),
                "buf_pts": running_time_ns,
                "source_frame_width": 1920,
                "source_frame_height": 1080,
                "frame_num": number,
                "obj_meta_list": None,
            },
        )()

    first_frame = frame(
        source_time=clocks.wall(),
        running_time_ns=1_000_000_000,
        number=1,
    )
    _own_metadata_frame(runtime, graph, source_id=0, pts_ns=1_000_000_000)
    runtime._publish_frame_metadata(first_frame, type("Pyds", (), {})())
    discontinuous_frame = frame(
        source_time=clocks.wall() + timedelta(seconds=3),
        running_time_ns=2_000_000_000,
        number=2,
    )
    _own_metadata_frame(runtime, graph, source_id=0, pts_ns=2_000_000_000)
    runtime._publish_frame_metadata(discontinuous_frame, type("Pyds", (), {})())

    assert supervisor.health_for(camera_id).state == "offline"
    assert supervisor.health_for(camera_id).degraded_reason == (
        "evidence_source_time_mapping_failed"
    )
    clocks.advance(1)
    recovery.advance()
    assert supervisor.health_for(camera_id).stream_epoch != initial_epoch


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
            "buf_pts": 1_000_000_000,
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
            "buf_pts": 500_000_000,
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
    graph = DeepStreamGraphSpec.from_site(_site())
    runtime._graph = graph
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor, model_artifact_id="person-primary-v1"
    )
    batch = type("Batch", (), {"frame_meta_list": Node(bad_frame, Node(good_frame))})()

    _own_metadata_frame(runtime, graph, source_id=0, pts_ns=500_000_000)
    _own_metadata_frame(runtime, graph, source_id=0, pts_ns=1_000_000_000)
    runtime._publish_batch_metadata(batch, Pyds)

    observations = runtime.drain_observations()
    assert len(observations) == 1
    assert observations[0].track_id == "2"
    assert runtime.invalid_metadata_count == 2
    assert supervisor.health_for("camera-01").state == "online"


def test_manifest_compares_model_and_engine_file_hashes_before_starting(tmp_path: Path) -> None:
    manifest = _manifest_with_files(tmp_path)
    assert manifest.engine_path is not None

    assert (
        manifest.validate_for_host(
            compute_capability="8.9", tensorrt_version="10.16.0.72", require_files=True
        )
        is None
    )
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


def test_stop_cleans_gpu_pipeline_even_when_telemetry_close_fails() -> None:
    class State:
        NULL = object()

    gst = type("Gst", (), {"State": State})

    class Pipeline:
        def __init__(self) -> None:
            self.states: list[object] = []

        def set_state(self, state: object) -> None:
            self.states.append(state)

    class Telemetry:
        def close(self) -> None:
            raise RuntimeError("bounded telemetry shutdown failed")

    pipeline = Pipeline()
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
    )
    runtime._pipeline = pipeline
    runtime._bindings = deepstream_module._NvidiaBindings(
        gst=gst,
        glib=object(),
        pyds=object(),
    )
    runtime._telemetry_publisher = Telemetry()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="bounded telemetry shutdown failed"):
        runtime.stop()

    assert pipeline.states == [State.NULL]
    assert runtime._pipeline is None
    assert runtime._bindings is None
    assert runtime._telemetry_publisher is None


def test_target_reviewed_files_are_bounded_regular_and_digest_matched(
    tmp_path: Path,
) -> None:
    reviewed = tmp_path / "reviewed.yaml"
    reviewed.write_bytes(b"site: reviewed\n")
    digest = hashlib.sha256(reviewed.read_bytes()).hexdigest()
    assert (
        deepstream_module._read_reviewed_file(
            reviewed,
            expected_sha256=digest,
            label="site configuration",
        )
        == reviewed.read_bytes()
    )
    with pytest.raises(RuntimeError, match="digest mismatch"):
        deepstream_module._read_reviewed_file(
            reviewed,
            expected_sha256="0" * 64,
            label="site configuration",
        )
    linked = tmp_path / "linked.yaml"
    linked.symlink_to(reviewed)
    with pytest.raises(RuntimeError, match="unavailable"):
        deepstream_module._read_reviewed_file(
            linked,
            expected_sha256=digest,
            label="site configuration",
        )


def test_target_entrypoint_refuses_to_start_without_a_site_and_runtime_manifest() -> None:
    with pytest.raises(SystemExit) as exit_status:
        main([])

    assert exit_status.value.code == 2


def test_target_mount_contract_covers_exact_secrets_artifacts_and_reviewed_inputs(
    tmp_path: Path,
) -> None:
    feeds = tuple(
        feed.model_copy(
            update={
                "rtsp_url": SecretReference(
                    docker_secret=Path(f"/run/secrets/camera_{index:02d}_rtsp"),
                )
            }
        )
        for index, feed in enumerate(_site().ready_to_start.feeds, start=1)
    )
    site = _site().model_copy(
        update={"ready_to_start": _site().ready_to_start.model_copy(update={"feeds": feeds})}
    )
    model_source = tmp_path / "person.onnx"
    engine_source = tmp_path / "person.engine"
    config_source = tmp_path / "person_primary.txt"
    model_source.write_bytes(b"approved-model")
    engine_source.write_bytes(b"approved-engine")
    model_target = Path("/run/runtime/person.onnx")
    engine_target = Path("/run/runtime/person.engine")
    config_target = Path("/run/runtime/person_primary.txt")
    config_source.write_text(
        (f"[property]\nonnx-file={model_target}\nmodel-engine-file={engine_target}\n")
    )
    base_manifest = _manifest()
    manifest = base_manifest.model_copy(
        update={
            "artifact_path": model_target,
            "artifact": base_manifest.artifact.model_copy(
                update={"sha256": hashlib.sha256(model_source.read_bytes()).hexdigest()}
            ),
            "engine_path": engine_target,
            "engine_sha256": hashlib.sha256(engine_source.read_bytes()).hexdigest(),
            "nvinfer_config_path": config_target,
            "nvinfer_config_sha256": hashlib.sha256(config_source.read_bytes()).hexdigest(),
        }
    )
    site_source = tmp_path / "site.yaml"
    runtime_source = tmp_path / "runtime.yaml"
    capacity_source = tmp_path / "capacity.yaml"
    capacity_signature_source = tmp_path / "capacity.sig"
    capacity_public_key_source = tmp_path / "capacity-authority.pem"
    token_source = tmp_path / "machine_token"
    evidence_source = tmp_path / "evidence-spool"
    site_source.write_text(yaml.safe_dump(site.model_dump(mode="json")))
    runtime_source.write_text(yaml.safe_dump(manifest.model_dump(mode="json")))
    capacity_source.write_text("schema_version: measured-capacity-report.v1\n")
    capacity_signature_source.write_bytes(b"bounded-signature")
    capacity_public_key_source.write_bytes(b"bounded-public-key")
    token_source.write_text("machine-token-fixture")
    evidence_source.mkdir(mode=0o700)
    mounts = [
        RuntimeBindMountV1(
            source=site_source,
            target=Path("/run/config/site.yaml"),
            kind="file",
            read_only=True,
        ),
        RuntimeBindMountV1(
            source=runtime_source,
            target=Path("/run/config/runtime-manifest.yaml"),
            kind="file",
            read_only=True,
        ),
        RuntimeBindMountV1(
            source=capacity_source,
            target=Path("/run/config/measured-capacity.yaml"),
            kind="file",
            read_only=True,
        ),
        RuntimeBindMountV1(
            source=capacity_signature_source,
            target=Path("/run/config/measured-capacity.sig"),
            kind="file",
            read_only=True,
        ),
        RuntimeBindMountV1(
            source=capacity_public_key_source,
            target=Path("/run/config/capacity-authority.pem"),
            kind="file",
            read_only=True,
        ),
        RuntimeBindMountV1(
            source=token_source,
            target=Path("/run/secrets/machine_token"),
            kind="file",
            read_only=True,
        ),
        RuntimeBindMountV1(
            source=evidence_source,
            target=Path("/srv/kuzet/evidence-spool"),
            kind="directory",
            read_only=False,
        ),
        RuntimeBindMountV1(
            source=model_source,
            target=model_target,
            kind="file",
            read_only=True,
        ),
        RuntimeBindMountV1(
            source=engine_source,
            target=engine_target,
            kind="file",
            read_only=True,
        ),
        RuntimeBindMountV1(
            source=config_source,
            target=config_target,
            kind="file",
            read_only=True,
        ),
    ]
    for index in range(1, 21):
        secret = tmp_path / f"camera_{index:02d}_rtsp"
        secret.write_text(f"rtsp://fixture-camera-{index:02d}")
        mounts.append(
            RuntimeBindMountV1(
                source=secret,
                target=Path(f"/run/secrets/camera_{index:02d}_rtsp"),
                kind="file",
                read_only=True,
            )
        )
    contract = RuntimeMountContractV1(
        schema_version="runtime-mount-contract.v1",
        image_id=f"sha256:{'1' * 64}",
        mounts=tuple(mounts),
    )

    argv = validate_runtime_mount_contract(
        site_config=site,
        runtime_manifest=manifest,
        contract=contract,
        expected_image_id=contract.image_id,
        site_config_source=site_source,
        runtime_manifest_source=runtime_source,
        measured_capacity_source=capacity_source,
        measured_capacity_signature_source=capacity_signature_source,
        capacity_authority_public_key_source=capacity_public_key_source,
        runtime_uid=os.geteuid(),
        runtime_gid=os.getegid(),
    )

    assert len(contract.mounts) == 30
    assert len(argv) == 60
    assert all("rtsp://" not in argument for argument in argv)
    duplicate_secret_site = site.model_copy(
        update={
            "ready_to_start": site.ready_to_start.model_copy(
                update={
                    "feeds": (
                        feeds[0],
                        feeds[1].model_copy(update={"rtsp_url": feeds[0].rtsp_url}),
                        *feeds[2:],
                    )
                }
            )
        }
    )
    duplicate_secret_contract = contract.model_copy(
        update={
            "mounts": tuple(
                mount
                for mount in contract.mounts
                if mount.target != Path("/run/secrets/camera_02_rtsp")
            )
        }
    )
    with pytest.raises(ValueError, match="20 unique direct camera secret"):
        validate_runtime_mount_contract(
            site_config=duplicate_secret_site,
            runtime_manifest=manifest,
            contract=duplicate_secret_contract,
            expected_image_id=contract.image_id,
            site_config_source=site_source,
            runtime_manifest_source=runtime_source,
            measured_capacity_source=capacity_source,
            measured_capacity_signature_source=capacity_signature_source,
            capacity_authority_public_key_source=capacity_public_key_source,
        )
    camera_01_source = next(
        mount.source
        for mount in contract.mounts
        if mount.target == Path("/run/secrets/camera_01_rtsp")
    )
    duplicate_camera_source_contract = contract.model_copy(
        update={
            "mounts": tuple(
                mount.model_copy(update={"source": camera_01_source})
                if mount.target == Path("/run/secrets/camera_02_rtsp")
                else mount
                for mount in contract.mounts
            )
        }
    )
    with pytest.raises(ValueError, match="unique and disjoint host source"):
        validate_runtime_mount_contract(
            site_config=site,
            runtime_manifest=manifest,
            contract=duplicate_camera_source_contract,
            expected_image_id=contract.image_id,
            site_config_source=site_source,
            runtime_manifest_source=runtime_source,
            measured_capacity_source=capacity_source,
            measured_capacity_signature_source=capacity_signature_source,
            capacity_authority_public_key_source=capacity_public_key_source,
        )
    token_source_collision_contract = contract.model_copy(
        update={
            "mounts": tuple(
                mount.model_copy(update={"source": token_source})
                if mount.target == Path("/run/secrets/camera_01_rtsp")
                else mount
                for mount in contract.mounts
            )
        }
    )
    with pytest.raises(ValueError, match="unique and disjoint host source"):
        validate_runtime_mount_contract(
            site_config=site,
            runtime_manifest=manifest,
            contract=token_source_collision_contract,
            expected_image_id=contract.image_id,
            site_config_source=site_source,
            runtime_manifest_source=runtime_source,
            measured_capacity_source=capacity_source,
            measured_capacity_signature_source=capacity_signature_source,
            capacity_authority_public_key_source=capacity_public_key_source,
        )
    with pytest.raises(ValueError, match="exact required target set"):
        validate_runtime_mount_contract(
            site_config=site,
            runtime_manifest=manifest,
            contract=contract.model_copy(update={"mounts": contract.mounts[:-1]}),
            expected_image_id=contract.image_id,
            site_config_source=site_source,
            runtime_manifest_source=runtime_source,
            measured_capacity_source=capacity_source,
            measured_capacity_signature_source=capacity_signature_source,
            capacity_authority_public_key_source=capacity_public_key_source,
        )
    with pytest.raises(ValueError, match="immutable SHA-256 image ID"):
        RuntimeMountContractV1(
            schema_version="runtime-mount-contract.v1",
            image_id="kuzet-pilot-runtime:review",
            mounts=contract.mounts,
        )


@pytest.mark.parametrize(
    "binding",
    (
        "registry_entry_sha256",
        "frozen_workload_sha256",
        "expected_workload_sha256",
    ),
)
def test_target_entrypoint_rejects_rehashed_capacity_with_tampered_inner_binding(
    tmp_path: Path,
    binding: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    site = _site()
    manifest = _manifest()
    site_path = tmp_path / "site.yaml"
    manifest_path = tmp_path / "runtime.yaml"
    capacity_path = tmp_path / "capacity.yaml"
    site_path.write_text(yaml.safe_dump(site.model_dump(mode="json"), sort_keys=True))
    manifest_path.write_text(yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=True))
    capacity = MeasuredCapacityReportV1(
        schema_version="measured-capacity-report.v1",
        site_id=manifest.site_id,
        artifact_id=manifest.artifact.artifact_id,
        artifact_sha256=manifest.artifact.sha256,
        registry_entry_sha256=manifest.registry_entry_sha256,
        engine_sha256=manifest.engine_sha256,
        precision="fp16",
        target_gpu_architecture="NVIDIA L4 (Ada)",
        target_compute_capability=manifest.target_compute_capability,
        tensorrt_version=manifest.tensorrt_version,
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
                "compute_capability": manifest.target_compute_capability,
                "mig_mode": "disabled",
            },
        ),
        site_config_sha256=site_config_sha256(site),
        runtime_manifest_file_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        frozen_workload_sha256=manifest.frozen_workload_sha256,
        expected_workload_sha256=manifest.expected_workload_sha256,
        runtime_image_id_sha256="1" * 64,
        runtime_image_config_sha256="2" * 64,
        runtime_code_sha256="3" * 64,
        mount_contract_sha256="4" * 64,
        stream_count=20,
        effective_throughput_hz=125.0,
        required_throughput_hz=100.0,
        scheduled_drop_fraction=0.005,
        queue_age_p95_seconds=0.5,
        queue_age_p99_seconds=1.0,
        gpu_utilization_max=0.7,
        vram_utilization_max=0.75,
        passed=True,
        report_reference="reports/target-capacity.json",
        report_sha256="9" * 64,
        signed_by="capacity-qa",
        signed_at=datetime(2026, 7, 29, 11, 0, tzinfo=UTC),
    ).model_dump(mode="json")
    capacity[binding] = "0" * 64
    capacity_path.write_text(yaml.safe_dump(capacity, sort_keys=True))
    private_key = tmp_path / "capacity-private.pem"
    public_key = tmp_path / "capacity-public.pem"
    signature = tmp_path / "capacity.sig"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
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
            str(private_key),
            "-in",
            str(capacity_path),
            "-out",
            str(signature),
        ],
        check=True,
        capture_output=True,
    )

    with pytest.raises(SystemExit) as exit_status:
        main(
            [
                "--site-config",
                str(site_path),
                "--site-config-sha256",
                hashlib.sha256(site_path.read_bytes()).hexdigest(),
                "--runtime-manifest",
                str(manifest_path),
                "--runtime-manifest-sha256",
                hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                "--measured-capacity-report",
                str(capacity_path),
                "--measured-capacity-sha256",
                hashlib.sha256(capacity_path.read_bytes()).hexdigest(),
                "--measured-capacity-signature",
                str(signature),
                "--capacity-authority-public-key",
                str(public_key),
                "--runtime-image-id-sha256",
                "1" * 64,
                "--runtime-image-config-sha256",
                "2" * 64,
                "--runtime-code-sha256",
                "3" * 64,
                "--mount-contract-sha256",
                "4" * 64,
                "--runtime-launch-nonce",
                "1" * 32,
                "--control-plane-url",
                "http://api:8000",
                "--machine-token-file",
                str(tmp_path / "unread-token"),
            ]
        )

    assert exit_status.value.code == 2
    assert "missing exact bindings or 25% headroom" in capsys.readouterr().err


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


def test_sigterm_quits_main_loop_drains_runtime_and_exits_cleanly() -> None:
    installed: dict[int, object] = {}
    restored = {15: object(), 2: object()}

    class FakeSignal:
        SIGTERM = 15
        SIGINT = 2

        @staticmethod
        def getsignal(signum: int) -> object:
            return restored[signum]

        @staticmethod
        def signal(signum: int, handler: object) -> None:
            installed[signum] = handler

    class Runtime:
        failed_reason = None
        stop_calls = 0

        def stop(self) -> None:
            self.stop_calls += 1

    class Loop:
        quit_calls = 0

        def run(self) -> None:
            handler = installed[FakeSignal.SIGTERM]
            assert callable(handler)
            handler(FakeSignal.SIGTERM, None)

        def quit(self) -> None:
            self.quit_calls += 1

    runtime = Runtime()
    loop = Loop()
    result = deepstream_module._run_main_loop_with_graceful_signals(
        runtime,  # type: ignore[arg-type]
        loop,
        signal_module=FakeSignal,
    )

    assert result == 0
    assert loop.quit_calls == 1
    assert runtime.stop_calls == 1
    assert installed == restored
