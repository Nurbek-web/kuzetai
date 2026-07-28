"""NVIDIA-only DeepStream adapter with an import-safe graph contract.

The graph contract is deliberately pure Python so M2 CI can validate the
twenty-camera topology and refusal gates.  GI, GStreamer, and ``pyds`` are
loaded only after the target host has passed the manifest checks in ``start``.
``pyds`` is isolated here while the Service Maker metadata publication API is
evaluated (replacement issue: PILOT-DS-001); it never escapes this adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import math
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from protector.pilot.config import FrozenModel, SiteConfig, load_site_config
from protector.pilot.gates import (
    CapacityReportV1,
    ModelArtifactV1,
    ModelGate,
    ShadowStageReportV1,
    TargetSiteReportV1,
)
from protector.pilot.runtime.evidence import (
    EncodedFragmentRing,
    SourceTimeMapper,
    SourceTimeMappingError,
    SplitMuxEvidenceSinkFactory,
)
from protector.pilot.runtime.supervisor import CameraHealth, CameraSupervisor

DEEPSTREAM_IMAGE = (
    "nvcr.io/nvidia/deepstream:9.1-samples-multiarch"
    "@sha256:10eca409b3894e91c1bac915c9f1346307e56695e552487cbe8cf2f58a3f998f"
)
DEEPSTREAM_X86_TENSORRT = "10.16.0.72"
DEEPSTREAM_X86_CUDA = "13.2"
GPU_MEMORY_TYPE = "nvbuf-mem-cuda-device"
PYDS_REPLACEMENT_ISSUE = "PILOT-DS-001: replace isolated pyds probe with Service Maker API"
NVTRACKER_CONFIG_PATH = Path("/app/deploy/pilot/deepstream/nvtracker.yml")
_OBJECT_SEQUENCE_BITS = 16
_MAX_OBJECTS_PER_FRAME = 1 << _OBJECT_SEQUENCE_BITS
_NVTRACKER_PROPERTIES = (
    "tracker-width",
    "tracker-height",
    "gpu-id",
    "enable-batch-process",
    "enable-past-frame",
    "ll-lib-file",
    "ll-config-file",
)

_FORBIDDEN_CORE_FACTORIES = frozenset(
    {"appsink", "opencv", "cv2", "numpy", "numpy-frame-copy", "cpu-frame-copy"}
)


class GraphContractError(ValueError):
    """The requested graph or runtime artifact is unsafe for pilot startup."""


class NvidiaBindingsUnavailable(RuntimeError):
    """The target-only DeepStream adapter was invoked without its NVIDIA stack."""


class SourcePlan(FrozenModel):
    """Immutable per-camera source topology before all streams converge at the mux."""

    camera_id: str
    source_id: int = Field(ge=0)
    codec: Literal["h264", "h265"]
    queue_capacity: int = Field(gt=0)
    has_encoded_evidence_branch: bool = True
    has_nvdec_branch: bool = True

    @property
    def depay_factory(self) -> str:
        return "rtph264depay" if self.codec == "h264" else "rtph265depay"

    @property
    def parser_factory(self) -> str:
        return "h264parse" if self.codec == "h264" else "h265parse"


class ElementSpec(FrozenModel):
    """A graph element and the small property subset safety gates inspect."""

    name: str
    factory: str
    properties: Mapping[str, Any]


class OptionalBranchSpec(FrozenModel):
    """A conditional analytic that cannot apply backpressure to the core path."""

    module: Literal["fire_smoke", "weapon"]
    enabled: bool = False
    shadow_only: bool = True
    queue: ElementSpec
    valve: ElementSpec


class DeepStreamGraphSpec(FrozenModel):
    """A single shared 20-stream graph; it contains no CPU-frame publication path."""

    sources: tuple[SourcePlan, ...]
    elements: tuple[ElementSpec, ...]
    optional_branches: tuple[OptionalBranchSpec, ...]
    metadata_only_publication: bool = True

    @classmethod
    def from_site(cls, site: SiteConfig) -> DeepStreamGraphSpec:
        feeds = site.ready_to_start.feeds
        sources = tuple(
            SourcePlan(
                camera_id=feed.camera_id,
                source_id=index,
                codec=feed.codec,
                queue_capacity=site.queues.decode,
            )
            for index, feed in enumerate(feeds)
        )
        elements = (
            ElementSpec(
                name="streammux",
                factory="nvstreammux",
                properties={
                    "batch-size": len(feeds),
                    "live-source": 1,
                    "nvbuf-memory-type": GPU_MEMORY_TYPE,
                    "batched-push-timeout": 40_000,
                    "attach-sys-ts": False,
                },
            ),
            ElementSpec(
                name="primary-queue",
                factory="queue",
                properties={
                    "max-size-buffers": site.queues.analytics,
                    "max-size-bytes": 0,
                    "max-size-time": 0,
                    "leaky": "downstream",
                },
            ),
            ElementSpec(
                name="person-primary",
                factory="nvinfer",
                properties={"role": "primary", "batch-size": len(feeds), "precision": "fp16"},
            ),
            ElementSpec(name="tracker", factory="nvtracker", properties={"shared": True}),
            ElementSpec(name="analytics", factory="nvdsanalytics", properties={"shared": True}),
            ElementSpec(
                name="metadata-sink", factory="fakesink", properties={"sync": False, "metadata-only": True}
            ),
        )
        optional_branches = tuple(
            OptionalBranchSpec(
                module=module,
                queue=ElementSpec(
                    name=f"{module}-queue",
                    factory="queue",
                    properties={
                        "max-size-buffers": site.queues.verifier,
                        "max-size-bytes": 0,
                        "max-size-time": 0,
                        "leaky": "downstream",
                    },
                ),
                valve=ElementSpec(
                    name=f"{module}-valve", factory="valve", properties={"drop": True}
                ),
            )
            for module in ("fire_smoke", "weapon")
        )
        graph = cls(sources=sources, elements=elements, optional_branches=optional_branches)
        graph.validate()
        return graph

    @property
    def primary_inference_count(self) -> int:
        return sum(
            element.factory == "nvinfer" and element.properties.get("role") == "primary"
            for element in self.elements
        )

    @property
    def tracker_count(self) -> int:
        return sum(element.factory == "nvtracker" for element in self.elements)

    @property
    def analytics_count(self) -> int:
        return sum(element.factory == "nvdsanalytics" for element in self.elements)

    def element(self, name: str) -> ElementSpec:
        for element in self.elements:
            if element.name == name:
                return element
        raise KeyError(name)

    def optional_branch(self, module: str) -> OptionalBranchSpec:
        for branch in self.optional_branches:
            if branch.module == module:
                return branch
        raise KeyError(module)

    def replace_element(self, replacement: ElementSpec) -> DeepStreamGraphSpec:
        return self.model_copy(
            update={
                "elements": tuple(
                    replacement if element.name == replacement.name else element
                    for element in self.elements
                )
            }
        )

    def with_element(
        self, *, name: str, factory: str, properties: Mapping[str, Any]
    ) -> DeepStreamGraphSpec:
        return self.model_copy(
            update={"elements": (*self.elements, ElementSpec(name=name, factory=factory, properties=properties))}
        )

    def validate(self) -> None:
        if len(self.sources) != 20:
            raise GraphContractError("DeepStream graph requires exactly 20 source bins")
        source_ids = [source.source_id for source in self.sources]
        camera_ids = [source.camera_id for source in self.sources]
        if len(set(source_ids)) != len(source_ids) or len(set(camera_ids)) != len(camera_ids):
            raise GraphContractError("source IDs and camera IDs must be unique")
        if not all(source.has_encoded_evidence_branch and source.has_nvdec_branch for source in self.sources):
            raise GraphContractError("every source requires encoded evidence and NVDEC branches")
        if not self.metadata_only_publication:
            raise GraphContractError("core graph may publish metadata only")
        if len({element.name for element in self.elements}) != len(self.elements):
            raise GraphContractError("graph element names must be unique")
        if any(element.factory.lower() in _FORBIDDEN_CORE_FACTORIES for element in self.elements):
            raise GraphContractError("forbidden CPU frame sink/copy element in core graph")

        muxes = [element for element in self.elements if element.factory == "nvstreammux"]
        if len(muxes) != 1:
            raise GraphContractError("graph requires one shared nvstreammux")
        mux = muxes[0]
        if mux.properties.get("batch-size") != 20 or mux.properties.get("live-source") != 1:
            raise GraphContractError("streammux must use batch-size=20 and live-source=1")
        if mux.properties.get("nvbuf-memory-type") != GPU_MEMORY_TYPE:
            raise GraphContractError("streammux must keep decoded surfaces in NVIDIA GPU memory")
        if self.primary_inference_count != 1:
            raise GraphContractError("graph requires one primary shared nvinfer")
        if self.tracker_count != 1:
            raise GraphContractError("graph requires one shared nvtracker")
        if self.analytics_count != 1:
            raise GraphContractError("graph requires one shared nvdsanalytics")
        primary = next(
            element
            for element in self.elements
            if element.factory == "nvinfer" and element.properties.get("role") == "primary"
        )
        if primary.properties.get("batch-size") != 20 or primary.properties.get("precision") != "fp16":
            raise GraphContractError("primary nvinfer must be shared FP16 batch-size=20")

        for element in self.elements:
            if element.factory == "queue":
                self._validate_queue(element)
        if {branch.module for branch in self.optional_branches} != {"fire_smoke", "weapon"}:
            raise GraphContractError("fire_smoke and weapon branches must both be declared")
        for branch in self.optional_branches:
            if branch.enabled or not branch.shadow_only:
                raise GraphContractError("conditional analytics must start disabled and shadow-only")
            self._validate_queue(branch.queue)
            if branch.valve.factory != "valve" or branch.valve.properties.get("drop") is not True:
                raise GraphContractError("conditional analytics require a closed valve")

    @staticmethod
    def _validate_queue(queue: ElementSpec) -> None:
        if queue.properties.get("max-size-buffers", 0) <= 0:
            raise GraphContractError("every queue must be explicitly bounded")
        if queue.properties.get("leaky") != "downstream":
            raise GraphContractError("every queue must be downstream-leaky")


class RuntimeModelManifestV1(FrozenModel):
    """The exact promoted model and engine required for target-host graph startup."""

    schema_version: Literal["deepstream-runtime-manifest.v1"]
    site_id: str
    artifact: ModelArtifactV1
    artifact_path: Path | None = None
    engine_sha256: str | None
    engine_path: Path | None = None
    nvinfer_config_path: Path | None = None
    nvinfer_config_sha256: str | None = None
    precision: str
    target_compute_capability: str
    tensorrt_version: str
    target_site_report: TargetSiteReportV1 | None
    capacity_report: CapacityReportV1 | None
    shadow_stage_report: ShadowStageReportV1 | None

    @field_validator("engine_sha256")
    @classmethod
    def engine_hash_is_digest_when_present(cls, value: str | None) -> str | None:
        if value is not None and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value.lower())):
            raise ValueError("engine_sha256 must be a 64-character hexadecimal digest")
        return value

    @field_validator("nvinfer_config_sha256")
    @classmethod
    def config_hash_is_digest_when_present(cls, value: str | None) -> str | None:
        if value is not None and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value.lower())):
            raise ValueError("nvinfer_config_sha256 must be a 64-character hexadecimal digest")
        return value

    def validate_for_host(
        self,
        *,
        compute_capability: str,
        tensorrt_version: str,
        require_files: bool = False,
    ) -> None:
        if self.artifact.sha256 is None:
            raise GraphContractError("model artifact sha256 is required")
        if self.artifact.analytic != "person":
            raise GraphContractError("shared primary graph requires a person analytic")
        if self.artifact.class_list != ("person",):
            raise GraphContractError("shared primary graph requires exactly the person class list")
        if self.engine_sha256 is None:
            raise GraphContractError("engine sha256 is required")
        if self.precision != "fp16":
            raise GraphContractError("runtime manifest requires FP16 engine mode")
        if self.target_compute_capability != compute_capability:
            raise GraphContractError("engine compute capability does not match target host")
        if self.tensorrt_version != tensorrt_version:
            raise GraphContractError("engine TensorRT version does not match target runtime")
        if self.target_site_report is None or self.target_site_report.site_id != self.site_id:
            raise GraphContractError("target-site report does not match runtime site")
        gate = ModelGate.evaluate(
            self.artifact,
            self.target_site_report,
            self.capacity_report,
            current_mode="shadow",
            shadow_stage_report=self.shadow_stage_report,
        )
        if gate.mode != "operator":
            raise GraphContractError(f"model promotion gate failed: {', '.join(gate.reasons)}")
        if require_files:
            self._validate_artifact_file(self.artifact_path, self.artifact.sha256, "model")
            self._validate_artifact_file(self.engine_path, self.engine_sha256, "engine")
            self._validate_artifact_file(
                self.nvinfer_config_path, self.nvinfer_config_sha256, "nvinfer config"
            )

    @staticmethod
    def _validate_artifact_file(path: Path | None, expected_sha256: str, label: str) -> None:
        if path is None or not path.is_file():
            raise GraphContractError(f"{label} file is required for target startup")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected_sha256:
            raise GraphContractError(f"{label} file sha256 does not match runtime manifest")


class FrameMetadataV1(FrozenModel):
    """Scalar metadata extracted by DeepStream; it deliberately has no frame surface."""

    camera_id: str
    source_time: datetime
    timestamp_quality: Literal["camera_rtcp", "host_ntp_fallback"] = "camera_rtcp"
    monotonic_seq: int = Field(ge=0)
    class_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    bbox: tuple[float, float, float, float]
    track_id: str | None = None


class MetadataPublisher:
    """Converts scalar probe metadata into the versioned observation contract."""

    def __init__(self, *, supervisor: CameraSupervisor, model_artifact_id: str) -> None:
        self._supervisor = supervisor
        self._model_artifact_id = model_artifact_id

    def publish(self, metadata: FrameMetadataV1) -> Any:
        return self._supervisor.accept_sample(
            camera_id=metadata.camera_id,
            source_time=metadata.source_time,
            monotonic_seq=metadata.monotonic_seq,
            timestamp_quality=metadata.timestamp_quality,
            module="person",
            class_name="person",
            confidence=metadata.confidence,
            bbox=metadata.bbox,
            track_id=metadata.track_id,
            model_artifact_id=self._model_artifact_id,
        )

    def record_frame(self, *, camera_id: str, source_time: datetime, monotonic_seq: int) -> bool:
        """Refresh source health even when this decoded frame has zero detections."""
        return self._supervisor.record_frame(
            camera_id=camera_id,
            source_time=source_time,
            monotonic_seq=monotonic_seq,
        )


def resolve_rtsp_locations(site: SiteConfig) -> dict[str, str]:
    """Resolve RTSP secrets only when the target runtime is about to connect."""
    return {
        feed.camera_id: feed.rtsp_url.resolve().get_secret_value()
        for feed in site.ready_to_start.feeds
    }


def person_config_paths_match(manifest: RuntimeModelManifestV1, config_path: Path) -> None:
    """Refuse a config that would load files other than the hash-verified pair."""
    if (
        manifest.artifact_path is None
        or manifest.engine_path is None
        or manifest.nvinfer_config_path is None
        or manifest.nvinfer_config_sha256 is None
    ):
        raise GraphContractError("model and engine paths are required for nvinfer startup")
    if config_path != manifest.nvinfer_config_path:
        raise GraphContractError("nvinfer configuration path does not match runtime manifest")
    try:
        properties = dict(
            line.split("=", 1)
            for line in config_path.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        )
    except OSError as exc:
        raise GraphContractError("person nvinfer configuration is unavailable") from exc
    if hashlib.sha256(config_path.read_bytes()).hexdigest() != manifest.nvinfer_config_sha256:
        raise GraphContractError("nvinfer configuration sha256 does not match runtime manifest")
    if any("REPLACE_" in value for value in properties.values()):
        raise GraphContractError("nvinfer configuration contains an unresolved placeholder")
    required_person_properties = {
        "network-mode": "2",
        "batch-size": "20",
        "infer-dims": "3;640;640",
        "model-color-format": "0",
        "net-scale-factor": "0.003921568627",
        "maintain-aspect-ratio": "1",
        "symmetric-padding": "1",
    }
    if manifest.artifact.preprocessing != "letterbox-rgb-640x640" or any(
        properties.get(key) != value for key, value in required_person_properties.items()
    ):
        raise GraphContractError("nvinfer configuration does not match approved person preprocessing")
    if (
        properties.get("onnx-file") != str(manifest.artifact_path)
        or properties.get("model-engine-file") != str(manifest.engine_path)
    ):
        raise GraphContractError("person nvinfer configuration does not load manifest-verified paths")


def should_link_rtsp_video_pad(caps: Mapping[str, str], codec: Literal["h264", "h265"]) -> bool:
    """Keep audio/control RTP pads out of a camera's video decoder branch."""
    expected_encoding = "H264" if codec == "h264" else "H265"
    return (
        caps.get("name") == "application/x-rtp"
        and caps.get("media", "").lower() == "video"
        and caps.get("encoding-name", "").upper() == expected_encoding
    )


def rtsp_caps_fields(caps: Any | None) -> dict[str, str] | None:
    """Read one negotiated RTP structure without assuming caps are ready."""
    if caps is None or caps.get_size() < 1:
        return None
    structure = caps.get_structure(0)
    if structure is None:
        return None
    return {
        "name": structure.get_name(),
        "media": structure.get_string("media") or "",
        "encoding-name": structure.get_string("encoding-name") or "",
    }


def evidence_placeholder_properties() -> dict[str, bool]:
    """Nonblocking discard sink replaced by Task 7's bounded encoded writer."""
    return {"sync": False, "async": False}


def metadata_observation_sequence(frame_number: int, object_ordinal: int) -> int:
    """Give each object a unique sequence while preserving the source-frame order.

    The lower 16 bits reserve room for at most 65,536 objects in one decoded
    frame; that bound is far above the pilot's valid person-detection load and
    fails closed rather than colliding a dedupe identity.
    """
    if frame_number < 0 or not 0 <= object_ordinal < _MAX_OBJECTS_PER_FRAME:
        raise GraphContractError("invalid frame/object ordinal for observation sequence")
    return (frame_number << _OBJECT_SEQUENCE_BITS) | object_ordinal


def configure_nvtracker(tracker: Any, config_path: Path) -> None:
    """Apply DS 9.1 Gst-nvtracker properties from the shared NvDCF YAML."""
    try:
        import yaml

        raw_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        settings = raw_config["tracker"]
        values = {name: settings[name] for name in _NVTRACKER_PROPERTIES}
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise GraphContractError("invalid NvDCF tracker configuration") from exc
    for name, value in values.items():
        tracker.set_property(name, value)


class SourceRecoveryCoordinator:
    """Routes inner source-bin failures to one camera and rebuilds after its backoff."""

    _SOURCE_ELEMENT_PREFIXES = frozenset(
        {"source", "rtsp", "depay", "parse", "encoded-tee", "evidence", "decode", "nvdec"}
    )

    def __init__(
        self,
        *,
        supervisor: CameraSupervisor,
        source_ids: Mapping[str, int],
        rebuild_source: Callable[[str], None],
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._supervisor = supervisor
        self._source_ids = dict(source_ids)
        self._camera_by_source_id = {source_id: camera_id for camera_id, source_id in source_ids.items()}
        self._rebuild_source = rebuild_source
        self._monotonic = monotonic_clock
        self._last_rebuild_reconnect_count: dict[str, int] = {}
        self._attempt_started_at: dict[str, float] = {}

    def handle_element_error(self, element_name: str) -> None:
        camera_id = self._camera_for_element(element_name)
        if camera_id is not None:
            self.handle_camera_failure(camera_id, "rtsp_pipeline_error")

    def camera_for_element(self, element: Any) -> str | None:
        """Resolve internally-created rtspsrc children through source-bin ancestry."""
        current = element
        while current is not None:
            camera_id = self._camera_for_element(current.get_name())
            if camera_id is not None:
                return camera_id
            current = current.get_parent()
        return None

    def handle_camera_failure(self, camera_id: str, reason: str, *, force: bool = False) -> None:
        if force or self._supervisor.health_for(camera_id).state not in {
            "offline",
            "reconnecting",
        }:
            self._supervisor.disconnect(camera_id, reason)

    def advance(self) -> None:
        self._supervisor.advance()
        for camera_id in self._source_ids:
            health = self._supervisor.health_for(camera_id)
            if (
                health.state == "reconnecting"
                and self._last_rebuild_reconnect_count.get(camera_id) != health.reconnect_count
            ):
                try:
                    self._supervisor.recover(camera_id)
                    self._rebuild_source(camera_id)
                    self._last_rebuild_reconnect_count[camera_id] = health.reconnect_count
                    self._attempt_started_at[camera_id] = self._monotonic()
                except Exception:
                    self._supervisor.disconnect(camera_id, "rtsp_rebuild_failed")

    def first_frame_grace_expired(self, camera_id: str, *, grace_seconds: float) -> bool:
        started = self._attempt_started_at.get(camera_id)
        return started is not None and self._monotonic() - started > grace_seconds

    def _camera_for_element(self, element_name: str) -> str | None:
        prefix, separator, suffix = element_name.rpartition("-")
        if not separator or prefix not in self._SOURCE_ELEMENT_PREFIXES:
            return None
        try:
            return self._camera_by_source_id.get(int(suffix))
        except ValueError:
            return None


def stop_pipeline(pipeline: Any, gst: Any) -> None:
    """Use the class-level NULL enum, never a state enum instance from a pipeline."""
    pipeline.set_state(gst.State.NULL)


@dataclass(frozen=True, slots=True)
class _NvidiaBindings:
    gst: Any
    glib: Any
    pyds: Any


def _load_nvidia_bindings() -> _NvidiaBindings:
    """Import deprecated pyds only inside the NVIDIA target adapter boundary."""
    try:
        gi = importlib.import_module("gi")
        gi.require_version("Gst", "1.0")
        repository = importlib.import_module("gi.repository")
        pyds = importlib.import_module("pyds")
    except (ImportError, ValueError, AttributeError) as exc:
        raise NvidiaBindingsUnavailable(
            "NVIDIA DeepStream bindings are unavailable; run only on the pinned Linux x86_64 L4 image"
        ) from exc
    return _NvidiaBindings(gst=repository.Gst, glib=repository.GLib, pyds=pyds)


RuntimeInfo = Callable[[], tuple[str, str]]
BindingLoader = Callable[[], object]
EvidenceSinkFactory = Callable[[Any, SourcePlan], Any | None]


class DeepStreamDataPlane:
    """Target-only adapter that turns the validated specification into one GStreamer graph."""

    def __init__(
        self,
        *,
        runtime_manifest: RuntimeModelManifestV1,
        runtime_info: RuntimeInfo,
        binding_loader: BindingLoader = _load_nvidia_bindings,
        fatal_callback: Callable[[], None] | None = None,
        evidence_sink_factory: EvidenceSinkFactory | None = None,
        runtime_session_seed_factory: Callable[[], UUID | str] = uuid4,
    ) -> None:
        self._manifest = runtime_manifest
        self._runtime_info = runtime_info
        self._binding_loader = binding_loader
        self._fatal_callback = fatal_callback or (lambda: None)
        self._evidence_sink_factory = evidence_sink_factory
        self._runtime_session_seed_factory = runtime_session_seed_factory
        self._graph: DeepStreamGraphSpec | None = None
        self._pipeline: Any | None = None
        self._supervisor: CameraSupervisor | None = None
        self._bindings: _NvidiaBindings | None = None
        self._recovery: SourceRecoveryCoordinator | None = None
        self._locations: dict[str, str] = {}
        self._metadata_publisher: MetadataPublisher | None = None
        self._failed_reason: str | None = None
        self._invalid_metadata_count = 0
        self._evidence_attachment_failures = 0
        self._started_monotonic: float | None = None
        self._awaiting_frame_since: dict[str, float] = {}
        self._source_time_mapper = SourceTimeMapper()

    def start(self, site: SiteConfig) -> None:
        if self._pipeline is not None:
            raise RuntimeError("DeepStream data plane is already running")
        graph = DeepStreamGraphSpec.from_site(site)
        compute_capability, tensorrt_version = self._runtime_info()
        self._manifest.validate_for_host(
            compute_capability=compute_capability,
            tensorrt_version=tensorrt_version,
            require_files=True,
        )
        assert self._manifest.nvinfer_config_path is not None
        person_config_paths_match(self._manifest, self._manifest.nvinfer_config_path)
        try:
            bindings = self._binding_loader()
        except (ImportError, ModuleNotFoundError, NvidiaBindingsUnavailable) as exc:
            raise NvidiaBindingsUnavailable(
                "NVIDIA DeepStream bindings are unavailable; graph execution is target-host only"
            ) from exc
        if not isinstance(bindings, _NvidiaBindings):
            raise NvidiaBindingsUnavailable("binding loader returned an invalid NVIDIA adapter")
        locations = resolve_rtsp_locations(site)
        self._graph = graph
        self._failed_reason = None
        self._evidence_attachment_failures = 0
        self._started_monotonic = time.monotonic()
        self._bindings = bindings
        self._locations = dict(locations)
        self._supervisor = CameraSupervisor(
            camera_ids=tuple(source.camera_id for source in graph.sources),
            observation_queue_size=site.queues.events,
            monotonic_clock=time.monotonic,
            wall_clock=lambda: datetime.now(UTC),
            runtime_session_seed=self._runtime_session_seed_factory(),
        )
        self._recovery = SourceRecoveryCoordinator(
            supervisor=self._supervisor,
            source_ids={source.camera_id: source.source_id for source in graph.sources},
            rebuild_source=self._rebuild_source,
        )
        self._metadata_publisher = MetadataPublisher(
            supervisor=self._supervisor,
            model_artifact_id=self._manifest.artifact.artifact_id,
        )
        try:
            self._pipeline = self._build_pipeline(bindings, graph, locations)
            bus = self._pipeline.get_bus()
            bus.add_signal_watch()
            bus.connect("message", self._on_bus_message)
            bindings.glib.timeout_add(250, self._advance_recovery)
            state_result = self._pipeline.set_state(bindings.gst.State.PLAYING)
            if state_result == bindings.gst.StateChangeReturn.FAILURE:
                raise RuntimeError("DeepStream pipeline failed to enter PLAYING")
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        if self._pipeline is not None and self._bindings is not None:
            stop_pipeline(self._pipeline, self._bindings.gst)
        if self._graph is not None and hasattr(self._evidence_sink_factory, "disable"):
            for source in self._graph.sources:
                self._evidence_sink_factory.disable(source.camera_id)  # type: ignore[attr-defined]
        self._pipeline = None
        self._graph = None
        self._bindings = None
        self._recovery = None
        self._locations = {}
        self._metadata_publisher = None
        self._started_monotonic = None
        self._awaiting_frame_since = {}
        self._source_time_mapper = SourceTimeMapper()
        if self._supervisor is not None:
            self._supervisor.clear_observations()
        self._supervisor = None

    def health(self) -> list[CameraHealth]:
        return [] if self._supervisor is None else self._supervisor.health()

    @property
    def failed_reason(self) -> str | None:
        """Redacted global failure reason for core graph faults."""
        return self._failed_reason

    @property
    def invalid_metadata_count(self) -> int:
        """Count malformed frame/object metadata dropped without touching GPU surfaces."""
        return self._invalid_metadata_count

    @property
    def evidence_attachment_failures(self) -> int:
        """Count camera writers that safely fell back to encoded-data discard."""
        return self._evidence_attachment_failures

    def drain_observations(self) -> list[Any]:
        """Deliver bounded metadata observations; decoded GPU surfaces never leave the graph."""
        return [] if self._supervisor is None else self._supervisor.drain_observations()

    def _advance_recovery(self) -> bool:
        if self._recovery is not None:
            now = time.monotonic()
            for health in self.health():
                if health.state == "online":
                    if health.last_frame_age_seconds is not None and health.last_frame_age_seconds > 5.0:
                        self._recovery.handle_camera_failure(
                            health.camera_id, "source_frame_timeout", force=True
                        )
                        self._awaiting_frame_since[health.camera_id] = now
                    else:
                        self._awaiting_frame_since.pop(health.camera_id, None)
                    continue
                if health.state == "reconnecting":
                    if self._recovery.first_frame_grace_expired(
                        health.camera_id, grace_seconds=5.0
                    ):
                        self._recovery.handle_camera_failure(
                            health.camera_id, "source_frame_timeout", force=True
                        )
                    continue
                if health.state != "starting":
                    continue
                began = self._awaiting_frame_since.setdefault(
                    health.camera_id,
                    self._started_monotonic if self._started_monotonic is not None else now,
                )
                if now - began > 5.0:
                    self._recovery.handle_camera_failure(health.camera_id, "source_frame_timeout", force=True)
                    self._awaiting_frame_since[health.camera_id] = now
            self._recovery.advance()
        return self._pipeline is not None and self._failed_reason is None

    def _build_pipeline(
        self, bindings: _NvidiaBindings, graph: DeepStreamGraphSpec, locations: Mapping[str, str]
    ) -> Any:
        gst = bindings.gst
        gst.init(None)
        pipeline = gst.Pipeline.new("kuzet-pilot-shared-graph")
        self._pipeline = pipeline
        mux = self._make_element(gst, "nvstreammux", "streammux")
        mux.set_property("batch-size", 20)
        mux.set_property("live-source", 1)
        mux.set_property("nvbuf-memory-type", 2)  # NVBUF_MEM_CUDA_DEVICE on dGPU.
        mux.set_property("batched-push-timeout", 40_000)
        mux.set_property("attach-sys-ts", False)
        pipeline.add(mux)
        for source in graph.sources:
            source_bin = self._build_source_bin(gst, source, locations[source.camera_id])
            pipeline.add(source_bin)
            source_pad = source_bin.get_static_pad("decoded_src")
            sink_pad = mux.request_pad_simple(f"sink_{source.source_id}")
            if source_pad.link(sink_pad) != gst.PadLinkReturn.OK:
                raise RuntimeError(f"failed to link camera {source.camera_id} to streammux")

        primary_queue = self._make_queue(gst, graph.element("primary-queue"))
        person = self._make_element(gst, "nvinfer", "person-primary")
        assert self._manifest.nvinfer_config_path is not None
        person.set_property("config-file-path", str(self._manifest.nvinfer_config_path))
        core_tee = self._make_element(gst, "tee", "conditional-analytics-tee")
        core_queue = self._make_queue(
            gst,
            ElementSpec(
                name="core-analytics-queue",
                factory="queue",
                properties=graph.element("primary-queue").properties,
            ),
        )
        tracker = self._make_element(gst, "nvtracker", "tracker")
        configure_nvtracker(tracker, NVTRACKER_CONFIG_PATH)
        analytics = self._make_element(gst, "nvdsanalytics", "analytics")
        metadata_sink = self._make_element(gst, "fakesink", "metadata-sink")
        metadata_sink.set_property("sync", False)
        for element in (primary_queue, person, core_tee, core_queue, tracker, analytics, metadata_sink):
            pipeline.add(element)
        if not gst.Element.link_many(mux, primary_queue, person, core_tee):
            raise RuntimeError("failed to link shared primary person path")
        if not core_tee.link(core_queue) or not gst.Element.link_many(
            core_queue, tracker, analytics, metadata_sink
        ):
            raise RuntimeError("failed to link shared person/tracker/analytics path")
        for branch in graph.optional_branches:
            branch_queue = self._make_queue(gst, branch.queue)
            valve = self._make_element(gst, "valve", branch.valve.name)
            valve.set_property("drop", True)
            sink = self._make_element(gst, "fakesink", f"{branch.module}-disabled-sink")
            sink.set_property("sync", False)
            sink.set_property("async", False)
            for element in (branch_queue, valve, sink):
                pipeline.add(element)
            if not core_tee.link(branch_queue) or not gst.Element.link_many(branch_queue, valve, sink):
                raise RuntimeError(f"failed to isolate disabled {branch.module} branch")
        analytics.get_static_pad("src").add_probe(gst.PadProbeType.BUFFER, self._metadata_probe, bindings)
        # Task 7 replaces per-source evidence discard sinks with bounded writers;
        # optional model work remains disabled until independently promoted.
        return pipeline

    def _build_source_bin(self, gst: Any, source: SourcePlan, location: str) -> Any:
        source_bin = gst.Bin.new(f"source-{source.source_id}")
        rtspsrc = self._make_element(gst, "rtspsrc", f"rtsp-{source.source_id}")
        rtspsrc.set_property("location", location)
        rtspsrc.set_property("latency", 200)
        depay = self._make_element(gst, source.depay_factory, f"depay-{source.source_id}")
        parser = self._make_element(gst, source.parser_factory, f"parse-{source.source_id}")
        # Repeat codec headers at random-access points so every retained fragment
        # can begin at a decodable keyframe.
        parser.set_property("config-interval", -1)
        tee = self._make_element(gst, "tee", f"encoded-tee-{source.source_id}")
        queue_properties = {
            "max-size-buffers": source.queue_capacity,
            "max-size-bytes": 0,
            "max-size-time": 0,
            "leaky": "downstream",
        }
        evidence_queue = self._make_queue(
            gst,
            ElementSpec(name=f"evidence-{source.source_id}", factory="queue", properties=queue_properties),
        )
        evidence_sink = None
        if self._evidence_sink_factory is not None:
            try:
                evidence_sink = self._evidence_sink_factory(gst, source)
                if (
                    evidence_sink is not None
                    and self._supervisor is not None
                    and hasattr(self._evidence_sink_factory, "bind_writer")
                ):
                    self._evidence_sink_factory.bind_writer(  # type: ignore[attr-defined]
                        evidence_sink,
                        stream_epoch=str(
                            self._supervisor.health_for(source.camera_id).stream_epoch
                        ),
                    )
            except Exception:
                self._evidence_attachment_failures += 1
                raise RuntimeError(
                    f"bounded evidence writer unavailable for {source.camera_id}"
                ) from None
        using_discard = evidence_sink is None
        if using_discard:
            evidence_sink = self._make_element(
                gst, "fakesink", f"evidence-discard-{source.source_id}"
            )
            for name, value in evidence_placeholder_properties().items():
                evidence_sink.set_property(name, value)
        decode_queue = self._make_queue(
            gst,
            ElementSpec(name=f"decode-{source.source_id}", factory="queue", properties=queue_properties),
        )
        decoder = self._make_element(gst, "nvv4l2decoder", f"nvdec-{source.source_id}")
        for element in (
            rtspsrc,
            depay,
            parser,
            tee,
            evidence_queue,
            evidence_sink,
            decode_queue,
            decoder,
        ):
            source_bin.add(element)
        rtspsrc.connect("pad-added", self._link_dynamic_rtsp_pad, depay, source.codec)
        if not gst.Element.link_many(depay, parser, tee):
            raise RuntimeError(f"failed to build encoded branch for {source.camera_id}")
        if not tee.link(evidence_queue):
            raise RuntimeError(f"failed to split evidence/NVDEC branches for {source.camera_id}")
        if not evidence_queue.link(evidence_sink):
            if using_discard:
                raise RuntimeError(f"failed to attach evidence discard for {source.camera_id}")
            self._evidence_attachment_failures += 1
            if hasattr(self._evidence_sink_factory, "disable"):
                self._evidence_sink_factory.disable(source.camera_id)  # type: ignore[attr-defined]
            raise RuntimeError(
                f"failed to attach bounded evidence writer for {source.camera_id}"
            )
        if not tee.link(decode_queue) or not decode_queue.link(decoder):
            raise RuntimeError(f"failed to split evidence/NVDEC branches for {source.camera_id}")
        source_bin.add_pad(gst.GhostPad.new("decoded_src", decoder.get_static_pad("src")))
        return source_bin

    @staticmethod
    def _make_element(gst: Any, factory: str, name: str) -> Any:
        element = gst.ElementFactory.make(factory, name)
        if element is None:
            raise RuntimeError(f"required GStreamer element is unavailable: {factory}")
        return element

    @classmethod
    def _make_queue(cls, gst: Any, spec: ElementSpec) -> Any:
        queue = cls._make_element(gst, "queue", spec.name)
        queue.set_property("max-size-buffers", spec.properties["max-size-buffers"])
        queue.set_property("max-size-bytes", spec.properties["max-size-bytes"])
        queue.set_property("max-size-time", spec.properties["max-size-time"])
        queue.set_property("leaky", 2)  # GstQueueLeaky.DOWNSTREAM
        return queue

    @staticmethod
    def _link_dynamic_rtsp_pad(
        _: Any, pad: Any, depay: Any, codec: Literal["h264", "h265"]
    ) -> None:
        caps = pad.get_current_caps() or pad.query_caps(None)
        fields = rtsp_caps_fields(caps)
        if fields is None or not should_link_rtsp_video_pad(fields, codec):
            return
        sink = depay.get_static_pad("sink")
        if not sink.is_linked():
            if int(pad.link(sink)) != 0:
                raise RuntimeError("failed to link validated RTSP video pad")

    def _metadata_probe(self, _: Any, info: Any, bindings: _NvidiaBindings) -> Any:
        """Publish scalar metadata only; surfaces are neither mapped nor copied to CPU memory."""
        try:
            buffer = info.get_buffer()
            if buffer is not None:
                batch_meta = bindings.pyds.gst_buffer_get_nvds_batch_meta(hash(buffer))
                if batch_meta is not None:
                    self._publish_batch_metadata(batch_meta, bindings.pyds)
        except (AttributeError, OSError, OverflowError, TypeError, ValueError):
            self._invalid_metadata_count += 1
        return bindings.gst.PadProbeReturn.OK

    def _publish_batch_metadata(self, batch_meta: Any, pyds: Any) -> None:
        if self._graph is None or self._metadata_publisher is None:
            return
        try:
            frame_node = batch_meta.frame_meta_list
        except AttributeError:
            self._invalid_metadata_count += 1
            return
        while frame_node is not None:
            try:
                frame_meta = pyds.NvDsFrameMeta.cast(frame_node.data)
                self._publish_frame_metadata(frame_meta, pyds)
            except (AttributeError, OSError, OverflowError, StopIteration, TypeError, ValueError):
                self._invalid_metadata_count += 1
            frame_node = self._next_metadata_node(frame_node)

    def _publish_frame_metadata(self, frame_meta: Any, pyds: Any) -> None:
        assert self._graph is not None
        assert self._metadata_publisher is not None
        source_id = getattr(frame_meta, "source_id", getattr(frame_meta, "pad_index", -1))
        if not isinstance(source_id, int) or not 0 <= source_id < len(self._graph.sources):
            raise ValueError("invalid source ID")
        raw_ntp_timestamp = getattr(frame_meta, "ntp_timestamp", 0)
        ntp_timestamp = (
            raw_ntp_timestamp
            if type(raw_ntp_timestamp) is int
            and 0 < raw_ntp_timestamp < 2**64 - 1
            else 0
        )
        source_time = (
            datetime.fromtimestamp(ntp_timestamp / 1_000_000_000, UTC)
            if ntp_timestamp > 0
            else datetime.now(UTC)
        )
        timestamp_quality = "camera_rtcp" if ntp_timestamp > 0 else "host_ntp_fallback"
        frame_width = int(getattr(frame_meta, "source_frame_width", 0))
        frame_height = int(getattr(frame_meta, "source_frame_height", 0))
        frame_number = int(frame_meta.frame_num)
        if frame_width <= 0 or frame_height <= 0 or frame_number < 0:
            raise ValueError("invalid frame metadata")
        camera_id = self._graph.sources[source_id].camera_id
        if not self._metadata_publisher.record_frame(
            camera_id=camera_id, source_time=source_time, monotonic_seq=frame_number
        ):
            if self._recovery is not None:
                self._recovery.handle_camera_failure(camera_id, "invalid_frame_heartbeat")
            return
        running_time_ns = getattr(frame_meta, "buf_pts", -1)
        if ntp_timestamp <= 0 and self._evidence_sink_factory is not None:
            if self._recovery is not None:
                self._recovery.handle_camera_failure(
                    camera_id,
                    "evidence_source_time_unavailable",
                )
            return
        running_time_is_valid = (
            type(running_time_ns) is int and 0 <= running_time_ns < 2**64 - 1
        )
        if (
            ntp_timestamp > 0
            and not running_time_is_valid
            and self._evidence_sink_factory is not None
        ):
            if self._recovery is not None:
                self._recovery.handle_camera_failure(
                    camera_id,
                    "evidence_source_time_mapping_failed",
                )
            return
        if ntp_timestamp > 0 and running_time_is_valid and self._supervisor is not None:
            stream_epoch = str(self._supervisor.health_for(camera_id).stream_epoch)
            try:
                self._source_time_mapper.anchor(
                    camera_id=camera_id,
                    stream_epoch=stream_epoch,
                    running_time_ns=running_time_ns,
                    source_time=source_time,
                )
            except SourceTimeMappingError:
                if self._recovery is not None:
                    self._recovery.handle_camera_failure(
                        camera_id,
                        "evidence_source_time_mapping_failed",
                    )
                return
        object_node = frame_meta.obj_meta_list
        object_ordinal = 0
        while object_node is not None:
            try:
                object_meta = pyds.NvDsObjectMeta.cast(object_node.data)
                rect = object_meta.rect_params
                raw = (float(rect.left), float(rect.top), float(rect.width), float(rect.height))
                confidence = float(object_meta.confidence)
                if not all(math.isfinite(value) for value in (*raw, confidence)):
                    raise ValueError("non-finite metadata")
                if not 0.0 <= confidence <= 1.0 or raw[2] <= 0.0 or raw[3] <= 0.0:
                    raise ValueError("invalid detection metadata")
                left = max(0.0, min(1.0, raw[0] / frame_width))
                top = max(0.0, min(1.0, raw[1] / frame_height))
                right = max(0.0, min(1.0, (raw[0] + raw[2]) / frame_width))
                bottom = max(0.0, min(1.0, (raw[1] + raw[3]) / frame_height))
                if not (left < right and top < bottom):
                    raise ValueError("invalid normalised bbox")
                self._metadata_publisher.publish(
                    FrameMetadataV1(
                        camera_id=camera_id,
                        source_time=source_time,
                        timestamp_quality=timestamp_quality,
                        monotonic_seq=metadata_observation_sequence(frame_number, object_ordinal),
                        class_name="person",
                        confidence=confidence,
                        bbox=(left, top, right, bottom),
                        track_id=str(object_meta.object_id),
                    )
                )
            except (AttributeError, OSError, OverflowError, StopIteration, TypeError, ValueError):
                self._invalid_metadata_count += 1
            object_ordinal += 1
            object_node = self._next_metadata_node(object_node)

    @staticmethod
    def _next_metadata_node(node: Any) -> Any:
        try:
            return node.next
        except (AttributeError, StopIteration, TypeError):
            return None

    def _on_bus_message(self, _: Any, message: Any) -> None:
        message_type = str(message.type).lower()
        structure = message.get_structure() if hasattr(message, "get_structure") else None
        structure_name = None if structure is None else structure.get_name()
        if structure_name in {
            "splitmuxsink-fragment-opened",
            "splitmuxsink-fragment-closed",
        }:
            self._handle_evidence_message(message, structure)
            return
        is_rtsp_timeout = structure is not None and structure.get_name() == "GstRTSPSrcTimeout"
        if "error" in message_type or "eos" in message_type or is_rtsp_timeout:
            camera_id = (
                None if self._recovery is None else self._recovery.camera_for_element(message.src)
            )
            if camera_id is not None and self._recovery is not None:
                self._recovery.handle_camera_failure(camera_id, "rtsp_pipeline_error")
            else:
                self._failed_reason = "core_pipeline_error"
                if self._pipeline is not None and self._bindings is not None:
                    stop_pipeline(self._pipeline, self._bindings.gst)
                self._fatal_callback()

    def _handle_evidence_message(self, message: Any, structure: Any) -> None:
        factory = self._evidence_sink_factory
        if factory is None or not hasattr(factory, "handle_splitmux_message"):
            self._evidence_attachment_failures += 1
            return
        camera_id = self._camera_for_evidence_element(message.src)
        if camera_id is None or self._graph is None or self._supervisor is None:
            self._evidence_attachment_failures += 1
            return
        try:
            factory.handle_writer_message(  # type: ignore[attr-defined]
                writer=message.src,
                structure=structure,
                source_time_mapper=self._source_time_mapper,
            )
        except Exception:
            self._evidence_attachment_failures += 1
            factory.disable(camera_id)  # type: ignore[attr-defined]
            if self._bindings is not None and hasattr(message.src, "set_state"):
                message.src.set_state(self._bindings.gst.State.NULL)
            if self._recovery is not None:
                self._recovery.handle_camera_failure(
                    camera_id,
                    "evidence_fragment_adoption_failed",
                    force=True,
                )
            else:
                self._supervisor.disconnect(
                    camera_id,
                    "evidence_fragment_adoption_failed",
                )

    def _camera_for_evidence_element(self, element: Any) -> str | None:
        if self._recovery is not None:
            resolved = self._recovery.camera_for_element(element)
            if resolved is not None:
                return resolved
        if self._graph is None:
            return None
        try:
            name = str(element.get_name())
            source_id = int(name.removeprefix("evidence-writer-"))
        except (AttributeError, TypeError, ValueError):
            return None
        return next(
            (
                source.camera_id
                for source in self._graph.sources
                if source.source_id == source_id
            ),
            None,
        )

    def _rebuild_source(self, camera_id: str) -> None:
        """Placeholder for a target-only source-bin rebuild after local backoff.

        Task 7 replaces the source bin's discard sink with an evidence writer.
        Rebuilding stays camera-local so an RTSP error never reconstructs the
        shared model, tracker, or other camera source bins.
        """
        if self._pipeline is None or self._graph is None or self._bindings is None:
            return
        source = next(item for item in self._graph.sources if item.camera_id == camera_id)
        source_name = f"source-{source.source_id}"
        old_bin = self._pipeline.get_by_name(source_name)
        old_writer = (
            None
            if old_bin is None or not hasattr(old_bin, "get_by_name")
            else old_bin.get_by_name(f"evidence-writer-{source.source_id}")
        )
        old_source_pad = None if old_bin is None else old_bin.get_static_pad("decoded_src")
        mux = self._pipeline.get_by_name("streammux")
        mux_sink_pad = (
            None if mux is None else mux.get_static_pad(f"sink_{source.source_id}")
        )
        if mux_sink_pad is None and old_source_pad is not None:
            mux_sink_pad = old_source_pad.get_peer()
        if mux_sink_pad is None:
            raise RuntimeError(f"source bin {camera_id} has no streammux pad")
        replacement = self._build_source_bin(
            self._bindings.gst, source, self._locations[camera_id]
        )
        replacement_writer = (
            None
            if not hasattr(replacement, "get_by_name")
            else replacement.get_by_name(f"evidence-writer-{source.source_id}")
        )
        if old_bin is not None and old_source_pad is not None:
            old_bin.set_state(self._bindings.gst.State.NULL)
            if old_writer is not None and hasattr(
                self._evidence_sink_factory,
                "unbind_writer",
            ):
                self._evidence_sink_factory.unbind_writer(old_writer)  # type: ignore[attr-defined]
            if old_source_pad.unlink(mux_sink_pad) is False:
                replacement.set_state(self._bindings.gst.State.NULL)
                raise RuntimeError(f"failed to unlink old source bin for {camera_id}")
            self._pipeline.remove(old_bin)
        if self._pipeline.add(replacement) is False:
            replacement.set_state(self._bindings.gst.State.NULL)
            if replacement_writer is not None and hasattr(
                self._evidence_sink_factory,
                "unbind_writer",
            ):
                self._evidence_sink_factory.unbind_writer(replacement_writer)  # type: ignore[attr-defined]
            raise RuntimeError(f"failed to add rebuilt source bin for {camera_id}")
        replacement_pad = replacement.get_static_pad("decoded_src")
        replacement_linked = False
        try:
            if replacement_pad.link(mux_sink_pad) != self._bindings.gst.PadLinkReturn.OK:
                raise RuntimeError(f"failed to relink rebuilt source bin for {camera_id}")
            replacement_linked = True
            if not replacement.sync_state_with_parent():
                raise RuntimeError(f"failed to sync rebuilt source bin for {camera_id}")
        except Exception:
            if replacement_linked:
                replacement_pad.unlink(mux_sink_pad)
            replacement.set_state(self._bindings.gst.State.NULL)
            self._pipeline.remove(replacement)
            if replacement_writer is not None and hasattr(
                self._evidence_sink_factory,
                "unbind_writer",
            ):
                self._evidence_sink_factory.unbind_writer(replacement_writer)  # type: ignore[attr-defined]
            raise


def _target_runtime_info() -> tuple[str, str]:
    """Read target facts only after this fail-closed image has been scheduled on NVIDIA."""
    compute_capability = subprocess.run(
        ["nvidia-smi", "--query-gpu=compute_cap", "--format=csv,noheader"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip().splitlines()
    if len(compute_capability) != 1:
        raise RuntimeError("target runtime must expose exactly one NVIDIA GPU")
    tensorrt_version = subprocess.run(
        [sys.executable, "-c", "import tensorrt as trt; print(trt.__version__)"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not tensorrt_version:
        raise RuntimeError("target runtime did not report TensorRT version")
    return compute_capability[0], tensorrt_version


def build_evidence_sink_factory(site: SiteConfig) -> SplitMuxEvidenceSinkFactory:
    """Build the target writer from validated finite spool settings."""
    retention = site.storage.retention
    ring = EncodedFragmentRing(
        retention.encoded_spool_root,
        ring_seconds=retention.encoded_ring_buffer_seconds,
        max_camera_bytes=retention.encoded_ring_max_camera_bytes,
        max_spool_bytes=retention.encoded_ring_max_spool_bytes,
    )
    return SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=retention.encoded_fragment_seconds,
        max_fragment_bytes=retention.encoded_fragment_max_bytes,
    )


def main(argv: list[str] | None = None) -> int:
    """Run only with signed target inputs; bare image invocation exits non-zero."""
    parser = argparse.ArgumentParser(description="Run the Kuzet shared DeepStream data plane")
    parser.add_argument("--site-config", type=Path, required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        import yaml

        site = load_site_config(arguments.site_config)
        runtime_manifest = RuntimeModelManifestV1.model_validate(
            yaml.safe_load(arguments.runtime_manifest.read_text(encoding="utf-8"))
        )
        runtime = DeepStreamDataPlane(
            runtime_manifest=runtime_manifest,
            runtime_info=_target_runtime_info,
            evidence_sink_factory=build_evidence_sink_factory(site),
        )
        runtime.start(site)
    except (GraphContractError, OSError, subprocess.CalledProcessError, ValueError) as exc:
        parser.error(str(exc))
    try:
        assert runtime._bindings is not None
        loop = runtime._bindings.glib.MainLoop()
        runtime._fatal_callback = loop.quit
        if runtime.failed_reason is None:
            loop.run()
    finally:
        runtime.stop()
    return 1 if runtime.failed_reason is not None else 0


if __name__ == "__main__":  # pragma: no cover - target process entrypoint.
    raise SystemExit(main())
