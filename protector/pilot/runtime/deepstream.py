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
import os
import re
import signal
import stat
import subprocess
import sys
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event as ThreadEvent
from threading import RLock
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from protector.pilot.capacity_acceptance import require_measured_primary_capacity
from protector.pilot.config import FrozenModel, SiteConfig
from protector.pilot.gates import (
    CapacityReportV1,
    MeasuredCapacityReportV1,
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
from protector.pilot.runtime.source_probe import CorrelatedNtpV1, SourceProbeLease
from protector.pilot.runtime.supervisor import (
    CameraHealth,
    CameraSupervisor,
    EventDrainBatch,
)
from protector.pilot.telemetry import (
    AsyncRuntimeTelemetryPublisher,
    AuthenticatedTelemetryClient,
    RuntimeTelemetryPublisher,
    TargetResourceMetricsProvider,
    read_machine_token,
)
from protector.pilot.trusted_artifacts import verify_detached_artifact
from protector.pilot.trusted_yaml import StrictYAMLError, load_strict_yaml

DEEPSTREAM_IMAGE = (
    "nvcr.io/nvidia/deepstream:9.1-samples-multiarch"
    "@sha256:10eca409b3894e91c1bac915c9f1346307e56695e552487cbe8cf2f58a3f998f"
)
DEEPSTREAM_X86_TENSORRT = "10.16.0.72"
DEEPSTREAM_X86_CUDA = "13.2"
GPU_MEMORY_TYPE = "nvbuf-mem-cuda-device"
PYDS_REPLACEMENT_ISSUE = "PILOT-DS-001: replace isolated pyds probe with Service Maker API"
NVTRACKER_CONFIG_PATH = Path("/app/deploy/pilot/deepstream/nvtracker.yml")
_GST_NULL_STATE_TIMEOUT_SECONDS = 10
_OBJECT_SEQUENCE_BITS = 16
_MAX_OBJECTS_PER_FRAME = 1 << _OBJECT_SEQUENCE_BITS
_MAX_METADATA_OWNER_ENTRIES = 4_096
_AMBIGUOUS_METADATA_OWNER = object()
_MAX_NVTRACKER_YAML_BYTES = 128 * 1024
_MAX_TARGET_SITE_YAML_BYTES = 1024 * 1024
_MAX_TARGET_AUTHORITY_YAML_BYTES = 8 * 1024 * 1024
_MAX_TARGET_YAML_NODES = 100_000
_MAX_TARGET_YAML_DEPTH = 96
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
    width: int = Field(ge=320, le=7680)
    height: int = Field(ge=240, le=4320)
    fps: float = Field(gt=0, le=120)
    bitrate_kbps: int = Field(gt=0, le=200_000)
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
                source_id=feed.source_index,
                codec=feed.codec,
                width=feed.resolution.width,
                height=feed.resolution.height,
                fps=feed.fps,
                bitrate_kbps=feed.bitrate_kbps,
                queue_capacity=site.queues.decode,
            )
            for feed in feeds
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
                name="metadata-sink",
                factory="fakesink",
                properties={"sync": False, "metadata-only": True},
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
            update={
                "elements": (
                    *self.elements,
                    ElementSpec(name=name, factory=factory, properties=properties),
                )
            }
        )

    def validate(self) -> None:
        if len(self.sources) != 20:
            raise GraphContractError("DeepStream graph requires exactly 20 source bins")
        source_ids = [source.source_id for source in self.sources]
        camera_ids = [source.camera_id for source in self.sources]
        if len(set(source_ids)) != len(source_ids) or len(set(camera_ids)) != len(camera_ids):
            raise GraphContractError("source IDs and camera IDs must be unique")
        if not all(
            source.has_encoded_evidence_branch and source.has_nvdec_branch
            for source in self.sources
        ):
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
        if (
            primary.properties.get("batch-size") != 20
            or primary.properties.get("precision") != "fp16"
        ):
            raise GraphContractError("primary nvinfer must be shared FP16 batch-size=20")

        for element in self.elements:
            if element.factory == "queue":
                self._validate_queue(element)
        if {branch.module for branch in self.optional_branches} != {"fire_smoke", "weapon"}:
            raise GraphContractError("fire_smoke and weapon branches must both be declared")
        for branch in self.optional_branches:
            if branch.enabled or not branch.shadow_only:
                raise GraphContractError(
                    "conditional analytics must start disabled and shadow-only"
                )
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
    registry_entry_sha256: str
    frozen_workload_sha256: str
    expected_workload_sha256: str
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
        if value is not None and (
            len(value) != 64 or any(c not in "0123456789abcdef" for c in value.lower())
        ):
            raise ValueError("engine_sha256 must be a 64-character hexadecimal digest")
        return value

    @field_validator(
        "registry_entry_sha256",
        "frozen_workload_sha256",
        "expected_workload_sha256",
    )
    @classmethod
    def reviewed_binding_is_digest(cls, value: str) -> str:
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value.lower()
        ):
            raise ValueError("reviewed runtime binding must be a SHA-256 digest")
        return value.lower()

    @field_validator("nvinfer_config_sha256")
    @classmethod
    def config_hash_is_digest_when_present(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) != 64 or any(c not in "0123456789abcdef" for c in value.lower())
        ):
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

    def publish(
        self,
        metadata: FrameMetadataV1,
        *,
        complete_event_frame: bool = True,
    ) -> Any:
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
            complete_event_frame=complete_event_frame,
        )

    def record_frame(self, *, camera_id: str, source_time: datetime, monotonic_seq: int) -> bool:
        """Refresh source health even when this decoded frame has zero detections."""
        return self._supervisor.record_frame(
            camera_id=camera_id,
            source_time=source_time,
            monotonic_seq=monotonic_seq,
        )

    def publish_frame(
        self,
        *,
        camera_id: str,
        source_time: datetime,
        monotonic_seq: int,
        metadata: tuple[FrameMetadataV1, ...],
    ) -> tuple[Any, ...] | None:
        """Publish one complete frame before exposing its event watermark."""

        if (
            not isinstance(metadata, tuple)
            or len(metadata) > _MAX_OBJECTS_PER_FRAME
            or any(
                type(item) is not FrameMetadataV1
                or item.camera_id != camera_id
                or item.source_time != source_time
                for item in metadata
            )
        ):
            raise GraphContractError("frame metadata batch is invalid")
        if not self.record_frame(
            camera_id=camera_id,
            source_time=source_time,
            monotonic_seq=monotonic_seq,
        ):
            return None
        published = tuple(
            observation
            for item in metadata
            if (
                observation := self.publish(
                    item,
                    complete_event_frame=False,
                )
            )
            is not None
        )
        if not self._supervisor.complete_frame(
            camera_id=camera_id,
            source_time=source_time,
            monotonic_seq=monotonic_seq,
        ):
            return None
        return published


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
        raise GraphContractError(
            "nvinfer configuration does not match approved person preprocessing"
        )
    if properties.get("onnx-file") != str(manifest.artifact_path) or properties.get(
        "model-engine-file"
    ) != str(manifest.engine_path):
        raise GraphContractError(
            "person nvinfer configuration does not load manifest-verified paths"
        )


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
    try:
        if caps is None or type(caps.get_size()) is not int or caps.get_size() < 1:
            return None
        structure = caps.get_structure(0)
    except (AttributeError, IndexError, OverflowError, TypeError, ValueError):
        return None
    if structure is None:
        return None
    try:
        name = structure.get_name()
        media = structure.get_string("media")
        encoding = structure.get_string("encoding-name")
    except (AttributeError, OverflowError, TypeError, ValueError):
        return None
    if not all(type(value) is str for value in (name, media, encoding)):
        return None
    return {"name": name, "media": media, "encoding-name": encoding}


def decoder_caps_fields(caps: Any | None) -> tuple[int, int, int, int] | None:
    """Extract the exact negotiated decoder geometry and FPS rational."""
    try:
        if caps is None or type(caps.get_size()) is not int or caps.get_size() < 1:
            return None
        structure = caps.get_structure(0)
        if structure is None or structure.get_name() != "video/x-raw":
            return None
        width = structure.get_value("width")
        height = structure.get_value("height")
        framerate = structure.get_value("framerate")
    except (
        AttributeError,
        IndexError,
        KeyError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        return None
    if type(width) is not int or type(height) is not int or width <= 0 or height <= 0:
        return None
    if (
        type(framerate) is tuple
        and len(framerate) == 2
        and type(framerate[0]) is int
        and type(framerate[1]) is int
    ):
        numerator, denominator = framerate
    else:
        try:
            numerator = framerate.numerator
            denominator = framerate.denominator
        except (AttributeError, OverflowError, TypeError, ValueError):
            try:
                numerator = framerate.num
                denominator = framerate.denom
            except (AttributeError, OverflowError, TypeError, ValueError):
                return None
    if (
        type(numerator) is not int
        or type(denominator) is not int
        or numerator <= 0
        or denominator <= 0
    ):
        return None
    return width, height, numerator, denominator


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
        with config_path.open("rb") as config_file:
            payload = config_file.read(_MAX_NVTRACKER_YAML_BYTES + 1)
        raw_config = load_strict_yaml(
            payload,
            max_bytes=_MAX_NVTRACKER_YAML_BYTES,
            max_nodes=2_000,
            max_depth=16,
            require_mapping=True,
        )
        settings = raw_config["tracker"]
        values = {name: settings[name] for name in _NVTRACKER_PROPERTIES}
    except StrictYAMLError as exc:
        raise GraphContractError("invalid NvDCF tracker configuration") from exc
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
        recover_camera: Callable[[str], None] | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._supervisor = supervisor
        self._source_ids = dict(source_ids)
        self._camera_by_source_id = {
            source_id: camera_id for camera_id, source_id in source_ids.items()
        }
        self._rebuild_source = rebuild_source
        self._recover_camera = recover_camera or supervisor.recover
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
                    self._recover_camera(camera_id)
                    self._rebuild_source(camera_id)
                    self._last_rebuild_reconnect_count[camera_id] = health.reconnect_count
                    self._attempt_started_at[camera_id] = self._monotonic()
                except Exception:
                    self._supervisor.disconnect(camera_id, "rtsp_rebuild_failed")

    def first_frame_grace_expired(self, camera_id: str, *, grace_seconds: float) -> bool:
        started = self._attempt_started_at.get(camera_id)
        return started is not None and self._monotonic() - started > grace_seconds

    def _camera_for_element(self, element_name: str) -> str | None:
        generation_match = re.fullmatch(r"source-(\d+)-generation-\d+", element_name)
        if generation_match is not None:
            return self._camera_by_source_id.get(int(generation_match.group(1)))
        prefix, separator, suffix = element_name.rpartition("-")
        if not separator or prefix not in self._SOURCE_ELEMENT_PREFIXES:
            return None
        try:
            return self._camera_by_source_id.get(int(suffix))
        except ValueError:
            return None


def stop_pipeline(pipeline: Any, gst: Any) -> None:
    """Reach Gst NULL synchronously or verify one bounded async transition."""

    state_change_return = getattr(gst, "StateChangeReturn", None)
    success = getattr(state_change_return, "SUCCESS", None)
    failure = getattr(state_change_return, "FAILURE", None)
    asynchronous = getattr(state_change_return, "ASYNC", None)
    if (
        state_change_return is None
        or success is None
        or failure is None
        or asynchronous is None
    ):
        raise RuntimeError("Gst NULL transition authority is unavailable")
    result = pipeline.set_state(gst.State.NULL)
    if result == failure:
        raise RuntimeError("DeepStream pipeline failed to enter Gst NULL")
    if result == success:
        return
    if result != asynchronous:
        raise RuntimeError("DeepStream pipeline Gst NULL transition is unverified")
    second = getattr(gst, "SECOND", None)
    get_state = getattr(pipeline, "get_state", None)
    if type(second) is not int or second < 1 or not callable(get_state):
        raise RuntimeError(
            "DeepStream pipeline async Gst NULL transition is unverified"
        )
    try:
        completed, current, _pending = get_state(
            _GST_NULL_STATE_TIMEOUT_SECONDS * second
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "DeepStream pipeline async Gst NULL transition is unverified"
        ) from exc
    if completed != success or current != gst.State.NULL:
        raise RuntimeError(
            "DeepStream pipeline did not complete its Gst NULL transition"
        )


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


class NativeProbeLeaseFactory(Protocol):
    """Issue one authoritative primitive-only lease for a source generation."""

    def acquire(self, camera_id: str, source_id: int) -> SourceProbeLease: ...


class AcceptanceWorkCompletion(Protocol):
    """Record one real post-shared-analytics frame, including zero detections."""

    def __call__(
        self,
        *,
        camera_id: str,
        source_index: int,
        module: Literal["person"],
        detection_count: int,
    ) -> object: ...


class _TransactionalSourceProbeLease:
    """Stable generation callback target with at most one live inner lease."""

    def __init__(
        self,
        *,
        factory: NativeProbeLeaseFactory,
        camera_id: str,
        source_id: int,
    ) -> None:
        self._factory = factory
        self._camera_id = camera_id
        self._source_id = source_id
        self._inner: SourceProbeLease | None = None
        self._lock = RLock()

    @property
    def active(self) -> bool:
        with self._lock:
            return self._inner is not None

    def activate(self) -> None:
        with self._lock:
            if self._inner is not None:
                raise RuntimeError(f"camera {self._camera_id} source probe lease is already active")
            self._inner = self._factory.acquire(self._camera_id, self._source_id)

    def deactivate(self) -> None:
        with self._lock:
            inner = self._inner
            self._inner = None
        if inner is not None:
            inner.close()

    def observe_rtp_caps(
        self,
        codec: str,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            return (
                False
                if self._inner is None
                else self._inner.observe_rtp_caps(codec, observed_monotonic_ns)
            )

    def observe_decoder_caps(
        self,
        width: int,
        height: int,
        fps_numerator: int,
        fps_denominator: int,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            return (
                False
                if self._inner is None
                else self._inner.observe_decoder_caps(
                    width,
                    height,
                    fps_numerator,
                    fps_denominator,
                    observed_monotonic_ns,
                )
            )

    def observe_parser_buffer(
        self,
        byte_size: int,
        source_timestamp_ns: int,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            return (
                False
                if self._inner is None
                else self._inner.observe_parser_buffer(
                    byte_size,
                    source_timestamp_ns,
                    pts_ns,
                    observed_monotonic_ns,
                )
            )

    def observe_decoded_buffer(
        self,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            return (
                False
                if self._inner is None
                else self._inner.observe_decoded_buffer(
                    pts_ns,
                    observed_monotonic_ns,
                )
            )

    def observe_nvds_ntp(
        self,
        pts_ns: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            return (
                False
                if self._inner is None
                else self._inner.observe_nvds_ntp(
                    pts_ns,
                    source_ntp_ns,
                    observed_monotonic_ns,
                )
            )

    def correlated_ntp(
        self,
        pts_ns: int,
        source_ntp_ns: int,
    ) -> CorrelatedNtpV1 | None:
        with self._lock:
            return (
                None if self._inner is None else self._inner.correlated_ntp(pts_ns, source_ntp_ns)
            )

    def close(self) -> None:
        self.deactivate()


class RuntimeTelemetrySink(Protocol):
    def enqueue(
        self,
        health: list[CameraHealth],
        *,
        analytics_state: str,
        evidence_state: str,
    ) -> None: ...

    def close(self) -> None: ...


@dataclass(slots=True)
class _SourceGeneration:
    """All camera-local resources whose lifetime must advance atomically."""

    camera_id: str
    source_id: int
    ordinal: int
    source_bin: Any
    writer: Any | None
    lease: _TransactionalSourceProbeLease
    lifecycle: Literal[
        "staged",
        "live_unauthorized",
        "authorized",
        "quiescing",
        "retired",
    ] = "staged"
    authorized_running_time_ns: int | None = None
    authorized_stream_epoch: str | None = None
    correlation_not_before_monotonic_ns: int = 0
    evidence_open_location: str | None = None
    authority_revision: int = 0
    _added_to_pipeline: bool = False
    _lease_closed: bool = False
    _writer_bound: bool = False
    _writer_unbound: bool = False
    _cutover_source_pad: Any | None = None
    _cutover_mux_sink_pad: Any | None = None
    _cutover_probe_id: int | None = None
    _flush_stop_pending: bool = False

    def close_lease(self) -> None:
        if self._lease_closed:
            return
        self._lease_closed = True
        self.lease.close()


@dataclass(slots=True)
class _PendingWriterCleanup:
    camera_id: str
    writer: Any
    generation: _SourceGeneration | None


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
        telemetry_publisher_factory: Callable[[str], RuntimeTelemetrySink] | None = None,
        native_probe_lease_factory: NativeProbeLeaseFactory | None = None,
        acceptance_work_completion: AcceptanceWorkCompletion | None = None,
        analytics_publication_gate: Callable[[], bool] | None = None,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if acceptance_work_completion is not None and analytics_publication_gate is None:
            raise GraphContractError(
                "acceptance work accounting requires an explicit publication gate"
            )
        self._manifest = runtime_manifest
        self._runtime_info = runtime_info
        self._binding_loader = binding_loader
        self._fatal_callback = fatal_callback or (lambda: None)
        self._evidence_sink_factory = evidence_sink_factory
        self._runtime_session_seed_factory = runtime_session_seed_factory
        self._telemetry_publisher_factory = telemetry_publisher_factory
        self._native_probe_lease_factory = native_probe_lease_factory
        self._acceptance_work_completion = acceptance_work_completion
        self._analytics_publication_gate = analytics_publication_gate or (lambda: True)
        self._monotonic_ns = monotonic_ns
        self._telemetry_publisher: RuntimeTelemetrySink | None = None
        self._graph: DeepStreamGraphSpec | None = None
        self._pipeline: Any | None = None
        self._supervisor: CameraSupervisor | None = None
        self._draining_supervisor: CameraSupervisor | None = None
        self._bindings: _NvidiaBindings | None = None
        self._recovery: SourceRecoveryCoordinator | None = None
        self._locations: dict[str, str] = {}
        self._metadata_publisher: MetadataPublisher | None = None
        self._failed_reason: str | None = None
        self._invalid_metadata_count = 0
        self._evidence_attachment_failures = 0
        self._telemetry_failures = 0
        self._started_monotonic: float | None = None
        self._awaiting_frame_since: dict[str, float] = {}
        self._source_time_mapper = SourceTimeMapper()
        self._active_source_generations: dict[str, _SourceGeneration] = {}
        self._staged_source_generations: dict[str, _SourceGeneration] = {}
        self._retired_source_generations: dict[str, _SourceGeneration] = {}
        self._metadata_source_generations: dict[str, _SourceGeneration] = {}
        self._source_generation_ordinals: dict[str, int] = {}
        self._pending_writer_cleanup: OrderedDict[int, _PendingWriterCleanup] = OrderedDict()
        self._pending_evidence_disable: set[str] = set()
        self._generation_state_lock = RLock()
        self._metadata_owner_lock = RLock()
        self._metadata_owners: OrderedDict[
            tuple[int, int],
            _SourceGeneration | object,
        ] = OrderedDict()

    def start(self, site: SiteConfig) -> None:
        if (
            self._pipeline is not None
            or self._draining_supervisor is not None
        ):
            raise RuntimeError("DeepStream data plane is already running")
        self._retry_pending_evidence_disable()
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
        if self._native_probe_lease_factory is None:
            raise GraphContractError(
                "target DeepStream startup requires an authoritative native source probe factory"
            )
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
        self._telemetry_publisher = (
            self._telemetry_publisher_factory(self._supervisor.runtime_session_id)
            if self._telemetry_publisher_factory is not None
            else None
        )
        self._recovery = SourceRecoveryCoordinator(
            supervisor=self._supervisor,
            source_ids={source.camera_id: source.source_id for source in graph.sources},
            rebuild_source=self._rebuild_source,
            recover_camera=self._recover_camera_epoch,
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
            if self._telemetry_publisher is not None:
                bindings.glib.timeout_add(1_000, self._publish_telemetry)
            state_result = self._pipeline.set_state(bindings.gst.State.PLAYING)
            if state_result == bindings.gst.StateChangeReturn.FAILURE:
                raise RuntimeError("DeepStream pipeline failed to enter PLAYING")
        except Exception:
            self.stop()
            raise

    def _recover_camera_epoch(self, camera_id: str) -> None:
        with self._generation_state_lock:
            if self._supervisor is None:
                raise RuntimeError("camera supervisor is unavailable")
            generation = self._active_source_generations.get(camera_id)
            if generation is not None:
                self._revoke_generation_authority(
                    generation,
                    lifecycle="quiescing",
                )
            self._supervisor.recover(camera_id)

    def stop(self, *, preserve_observations: bool = False) -> None:
        if type(preserve_observations) is not bool:
            raise TypeError("preserve_observations must be a boolean")
        cleanup_error: BaseException | None = None
        supervisor = self._supervisor
        if self._pipeline is not None:
            if self._bindings is None:
                raise RuntimeError(
                    "DeepStream pipeline Gst NULL authority is unavailable"
                )
            # Do not release telemetry, source leases, evidence writers, or
            # graph references until the target pipeline is verifiably inert.
            stop_pipeline(self._pipeline, self._bindings.gst)

        def cleanup(action: Callable[[], None]) -> None:
            nonlocal cleanup_error
            try:
                action()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc

        generations: list[_SourceGeneration] = []
        seen_generations: set[int] = set()
        for generation in (
            *self._active_source_generations.values(),
            *self._staged_source_generations.values(),
            *self._retired_source_generations.values(),
        ):
            identity = id(generation)
            if identity not in seen_generations:
                seen_generations.add(identity)
                generations.append(generation)
        cleanup(self._retry_pending_writer_cleanup)
        for generation in generations:
            cleanup(
                lambda generation=generation: self._retry_pending_flush_stop(
                    generation,
                    release_block=True,
                )
            )
        if self._telemetry_publisher is not None:
            cleanup(self._telemetry_publisher.close)
        for generation in generations:
            cleanup(lambda generation=generation: self._discard_generation_source_block(generation))
        if self._graph is not None and hasattr(self._evidence_sink_factory, "disable"):
            for source in self._graph.sources:
                self._queue_evidence_disable(source.camera_id)
        cleanup(self._retry_pending_evidence_disable)
        if supervisor is not None and not preserve_observations:
            cleanup(supervisor.clear_observations)
        if (
            not preserve_observations
            and self._draining_supervisor is not None
        ):
            cleanup(self._draining_supervisor.clear_observations)
        for generation in (
            *self._staged_source_generations.values(),
            *self._retired_source_generations.values(),
        ):
            if (
                generation._added_to_pipeline
                and self._pipeline is not None
                and self._bindings is not None
            ):
                cleanup(
                    lambda generation=generation: generation.source_bin.set_state(
                        self._bindings.gst.State.NULL  # type: ignore[union-attr]
                    )
                )
                cleanup(
                    lambda generation=generation: self._remove_generation_from_pipeline(
                        generation,
                        f"staged source bin {generation.camera_id}",
                    )
                )
        for generation in generations:
            cleanup(lambda generation=generation: self._unbind_generation_writer(generation))
            cleanup(generation.close_lease)
        self._pipeline = None
        self._graph = None
        self._bindings = None
        self._recovery = None
        self._locations = {}
        self._metadata_publisher = None
        self._telemetry_publisher = None
        self._started_monotonic = None
        self._awaiting_frame_since = {}
        self._source_time_mapper = SourceTimeMapper()
        self._active_source_generations = {}
        self._staged_source_generations = {}
        self._retired_source_generations = {}
        self._metadata_source_generations = {}
        self._source_generation_ordinals = {}
        with self._metadata_owner_lock:
            self._metadata_owners.clear()
        self._supervisor = None
        if preserve_observations and supervisor is not None:
            self._draining_supervisor = supervisor
        elif not preserve_observations:
            self._draining_supervisor = None
        if cleanup_error is not None:
            raise cleanup_error

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

    @property
    def telemetry_failures(self) -> int:
        """Count failed control-plane publications without leaking provider details."""
        return self._telemetry_failures

    def drain_observations(
        self,
        *,
        max_items: int | None = None,
    ) -> list[Any]:
        """Deliver bounded metadata observations; decoded GPU surfaces never leave the graph."""
        supervisor = self._supervisor or self._draining_supervisor
        return (
            []
            if supervisor is None
            else supervisor.drain_observations(max_items=max_items)
        )

    def drain_event_batch(self, *, max_items: int) -> Any:
        """Atomically deliver metadata and its non-overtaking frame cursors."""

        supervisor = self._supervisor or self._draining_supervisor
        if supervisor is None:
            return EventDrainBatch(
                observations=(),
                cursors=(),
                settled_observation_sequences=(),
            )
        return supervisor.drain_event_batch(max_items=max_items)

    def event_cursors(self) -> tuple[Any, ...]:
        """Expose one bounded per-camera cursor to the off-callback event worker."""

        supervisor = self._supervisor or self._draining_supervisor
        return () if supervisor is None else supervisor.event_cursors()

    def finish_observation_drain(self) -> None:
        """Release a detached supervisor only after its worker has stopped."""

        if self._pipeline is not None or self._supervisor is not None:
            raise RuntimeError(
                "observation drain cannot finish while the graph is active"
            )
        supervisor = self._draining_supervisor
        if supervisor is None:
            return
        supervisor.clear_observations()
        self._draining_supervisor = None

    def _advance_recovery(self) -> bool:
        if self._recovery is not None:
            now = time.monotonic()
            for health in self.health():
                if health.state == "online":
                    if (
                        health.last_frame_age_seconds is not None
                        and health.last_frame_age_seconds > 5.0
                    ):
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
                    self._recovery.handle_camera_failure(
                        health.camera_id, "source_frame_timeout", force=True
                    )
                    self._awaiting_frame_since[health.camera_id] = now
            self._recovery.advance()
        return self._pipeline is not None and self._failed_reason is None

    def _publish_telemetry(self) -> bool:
        publisher = self._telemetry_publisher
        if publisher is not None:
            try:
                publisher.enqueue(
                    self.health(),
                    analytics_state=("failed" if self._failed_reason is not None else "degraded"),
                    evidence_state=(
                        "degraded"
                        if self._evidence_sink_factory is not None
                        and self._evidence_attachment_failures == 0
                        else "failed"
                    ),
                )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                self._telemetry_failures += 1
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
        self._attach_initial_source_generations(
            pipeline,
            mux,
            gst,
            graph,
            locations,
        )

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
        for element in (
            primary_queue,
            person,
            core_tee,
            core_queue,
            tracker,
            analytics,
            metadata_sink,
        ):
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
            if not core_tee.link(branch_queue) or not gst.Element.link_many(
                branch_queue, valve, sink
            ):
                raise RuntimeError(f"failed to isolate disabled {branch.module} branch")
        analytics.get_static_pad("src").add_probe(
            gst.PadProbeType.BUFFER, self._metadata_probe, bindings
        )
        # Task 7 replaces per-source evidence discard sinks with bounded writers;
        # optional model work remains disabled until independently promoted.
        return pipeline

    def _attach_initial_source_generations(
        self,
        pipeline: Any,
        mux: Any,
        gst: Any,
        graph: DeepStreamGraphSpec,
        locations: Mapping[str, str],
    ) -> None:
        for source in graph.sources:
            generation = self._build_source_generation(
                gst,
                source,
                locations[source.camera_id],
            )
            self._staged_source_generations[source.camera_id] = generation
            source_bin = generation.source_bin
            if pipeline.add(source_bin) is False:
                raise RuntimeError(f"failed to add camera {source.camera_id} source generation")
            generation._added_to_pipeline = True
            source_pad = source_bin.get_static_pad("decoded_src")
            sink_pad = mux.request_pad_simple(f"sink_{source.source_id}")
            if source_pad.link(sink_pad) != gst.PadLinkReturn.OK:
                raise RuntimeError(f"failed to link camera {source.camera_id} to streammux")
            generation.lifecycle = "live_unauthorized"
            self._metadata_source_generations[source.camera_id] = generation
            self._active_source_generations[source.camera_id] = generation
            self._staged_source_generations.pop(source.camera_id, None)

    def _bind_generation_writer(
        self,
        generation: _SourceGeneration,
        *,
        stream_epoch: str,
    ) -> None:
        if generation._writer_bound:
            return
        if generation._writer_unbound:
            raise RuntimeError(f"camera {generation.camera_id} evidence writer was already retired")
        writer = generation.writer
        factory = self._evidence_sink_factory
        if writer is None or not hasattr(factory, "bind_writer"):
            generation._writer_bound = True
            return
        factory.bind_writer(  # type: ignore[union-attr]
            writer,
            stream_epoch=stream_epoch,
        )
        generation._writer_bound = True

    def _unbind_generation_writer(self, generation: _SourceGeneration) -> None:
        if generation._writer_unbound:
            return
        writer = generation.writer
        factory = self._evidence_sink_factory
        if writer is None or not hasattr(factory, "unbind_writer"):
            generation._writer_bound = False
            generation._writer_unbound = True
            return
        self._queue_writer_cleanup(
            generation.camera_id,
            writer,
            generation=generation,
        )
        self._retry_pending_writer_cleanup(
            camera_id=generation.camera_id,
            writer=writer,
        )

    def _queue_writer_cleanup(
        self,
        camera_id: str,
        writer: Any,
        *,
        generation: _SourceGeneration | None,
    ) -> None:
        key = id(writer)
        with self._generation_state_lock:
            pending = self._pending_writer_cleanup.get(key)
            if pending is None:
                self._pending_writer_cleanup[key] = _PendingWriterCleanup(
                    camera_id=camera_id,
                    writer=writer,
                    generation=generation,
                )
                return
            if pending.writer is not writer or pending.camera_id != camera_id:
                raise RuntimeError("evidence writer cleanup identity collision")
            if pending.generation is None and generation is not None:
                pending.generation = generation

    def _retry_pending_writer_cleanup(
        self,
        *,
        camera_id: str | None = None,
        writer: Any | None = None,
    ) -> None:
        with self._generation_state_lock:
            pending_items = tuple(
                pending
                for pending in self._pending_writer_cleanup.values()
                if (camera_id is None or pending.camera_id == camera_id)
                and (writer is None or pending.writer is writer)
            )
        cleanup_error: BaseException | None = None
        factory = self._evidence_sink_factory
        for pending in pending_items:
            try:
                if not hasattr(factory, "unbind_writer"):
                    raise RuntimeError(
                        f"camera {pending.camera_id} evidence writer cleanup is unavailable"
                    )
                factory.unbind_writer(pending.writer)  # type: ignore[union-attr]
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
                continue
            with self._generation_state_lock:
                current = self._pending_writer_cleanup.get(id(pending.writer))
                if current is not pending:
                    continue
                if pending.generation is not None:
                    pending.generation._writer_bound = False
                    pending.generation._writer_unbound = True
                self._pending_writer_cleanup.pop(id(pending.writer), None)
        if cleanup_error is not None:
            raise cleanup_error

    def _queue_evidence_disable(self, camera_id: str) -> None:
        with self._generation_state_lock:
            self._pending_evidence_disable.add(camera_id)

    def _disable_evidence(self, camera_id: str) -> None:
        self._queue_evidence_disable(camera_id)
        self._retry_pending_evidence_disable(camera_id=camera_id)

    def _retry_pending_evidence_disable(
        self,
        *,
        camera_id: str | None = None,
    ) -> None:
        with self._generation_state_lock:
            pending_camera_ids = tuple(
                sorted(
                    pending_camera_id
                    for pending_camera_id in self._pending_evidence_disable
                    if camera_id is None or pending_camera_id == camera_id
                )
            )
        cleanup_error: BaseException | None = None
        factory = self._evidence_sink_factory
        for camera_id in pending_camera_ids:
            try:
                if not hasattr(factory, "disable"):
                    raise RuntimeError(
                        f"camera {camera_id} evidence disable cleanup is unavailable"
                    )
                factory.disable(camera_id)  # type: ignore[union-attr]
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
                continue
            with self._generation_state_lock:
                self._pending_evidence_disable.discard(camera_id)
        if cleanup_error is not None:
            raise cleanup_error

    def _revoke_generation_authority(
        self,
        generation: _SourceGeneration,
        *,
        lifecycle: Literal["live_unauthorized", "quiescing"] = "live_unauthorized",
    ) -> None:
        """Revoke one stream epoch without permanently retiring its writer."""
        generation.lifecycle = lifecycle
        generation.authorized_running_time_ns = None
        generation.authorized_stream_epoch = None
        generation.correlation_not_before_monotonic_ns = max(
            generation.correlation_not_before_monotonic_ns,
            self._monotonic_ns(),
        )
        generation.evidence_open_location = None
        generation._writer_bound = False
        generation.authority_revision += 1
        self._clear_metadata_owners(generation.camera_id)
        factory = self._evidence_sink_factory
        if hasattr(factory, "reset_camera"):
            factory.reset_camera(generation.camera_id)  # type: ignore[union-attr]

    def _restore_generation_after_failed_rebuild_locked(
        self,
        generation: _SourceGeneration,
    ) -> None:
        generation.lifecycle = "live_unauthorized"
        generation.correlation_not_before_monotonic_ns = max(
            generation.correlation_not_before_monotonic_ns,
            self._monotonic_ns(),
        )

    def _build_source_generation(
        self,
        gst: Any,
        source: SourcePlan,
        location: str,
        *,
        activate_lease: bool = True,
    ) -> _SourceGeneration:
        factory = self._native_probe_lease_factory
        if factory is None:
            raise GraphContractError(
                "target DeepStream source generation requires a native probe lease"
            )
        ordinal = self._source_generation_ordinals.get(source.camera_id, 0) + 1
        self._source_generation_ordinals[source.camera_id] = ordinal
        lease = _TransactionalSourceProbeLease(
            factory=factory,
            camera_id=source.camera_id,
            source_id=source.source_id,
        )
        try:
            if activate_lease:
                lease.activate()
            source_bin = self._build_source_bin(
                gst,
                source,
                location,
                lease,
                f"source-{source.source_id}-generation-{ordinal}",
            )
            writer = (
                None
                if not hasattr(source_bin, "get_by_name")
                else source_bin.get_by_name(f"evidence-writer-{source.source_id}")
            )
            return _SourceGeneration(
                camera_id=source.camera_id,
                source_id=source.source_id,
                ordinal=ordinal,
                source_bin=source_bin,
                writer=writer,
                lease=lease,
            )
        except BaseException:
            lease.close()
            raise

    def _build_source_bin(
        self,
        gst: Any,
        source: SourcePlan,
        location: str,
        lease: SourceProbeLease | None = None,
        bin_name: str | None = None,
    ) -> Any:
        self._retry_pending_evidence_disable(camera_id=source.camera_id)
        self._retry_pending_writer_cleanup(camera_id=source.camera_id)
        source_bin = gst.Bin.new(bin_name or f"source-{source.source_id}")
        rtspsrc = self._make_element(gst, "rtspsrc", f"rtsp-{source.source_id}")
        rtspsrc.set_property("location", location)
        rtspsrc.set_property("latency", 200)
        if lease is not None:
            bindings = self._bindings
            try:
                configure_ntp = bindings.pyds.configure_source_for_ntp_sync  # type: ignore[union-attr]
            except AttributeError as exc:
                raise RuntimeError(
                    f"camera {source.camera_id} cannot configure RTCP NTP sync"
                ) from exc
            try:
                configured = configure_ntp(hash(rtspsrc))
            except Exception as exc:
                raise RuntimeError(
                    f"camera {source.camera_id} cannot configure RTCP NTP sync"
                ) from exc
            if configured is False:
                raise RuntimeError(f"camera {source.camera_id} cannot configure RTCP NTP sync")
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
            ElementSpec(
                name=f"evidence-{source.source_id}", factory="queue", properties=queue_properties
            ),
        )
        evidence_sink = None
        if self._evidence_sink_factory is not None:
            try:
                evidence_sink = self._evidence_sink_factory(gst, source)
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
            ElementSpec(
                name=f"decode-{source.source_id}", factory="queue", properties=queue_properties
            ),
        )
        decoder = self._make_element(gst, "nvv4l2decoder", f"nvdec-{source.source_id}")
        try:
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
            if lease is None:
                rtspsrc.connect("pad-added", self._link_dynamic_rtsp_pad, depay, source.codec)
            else:
                rtspsrc.connect(
                    "pad-added",
                    self._link_dynamic_rtsp_pad,
                    depay,
                    source.codec,
                    source.camera_id,
                    lease,
                    gst,
                )
            if not gst.Element.link_many(depay, parser, tee):
                raise RuntimeError(f"failed to build encoded branch for {source.camera_id}")
            if not tee.link(evidence_queue):
                raise RuntimeError(
                    f"failed to split evidence/NVDEC branches for {source.camera_id}"
                )
            if not evidence_queue.link(evidence_sink):
                if using_discard:
                    raise RuntimeError(f"failed to attach evidence discard for {source.camera_id}")
                self._evidence_attachment_failures += 1
                raise RuntimeError(
                    f"failed to attach bounded evidence writer for {source.camera_id}"
                )
            if not tee.link(decode_queue) or not decode_queue.link(decoder):
                raise RuntimeError(
                    f"failed to split evidence/NVDEC branches for {source.camera_id}"
                )
            if lease is not None:
                parser.get_static_pad("src").add_probe(
                    gst.PadProbeType.BUFFER,
                    self._parser_buffer_probe,
                    source.camera_id,
                    lease,
                    gst,
                )
                decoder.get_static_pad("src").add_probe(
                    gst.PadProbeType.EVENT_DOWNSTREAM,
                    self._decoder_caps_probe,
                    source.camera_id,
                    lease,
                    gst,
                )
                decoder.get_static_pad("src").add_probe(
                    gst.PadProbeType.BUFFER,
                    self._decoder_buffer_probe,
                    source.camera_id,
                    lease,
                    gst,
                )
            source_bin.add_pad(gst.GhostPad.new("decoded_src", decoder.get_static_pad("src")))
            return source_bin
        except BaseException:
            factory = self._evidence_sink_factory
            if (
                not using_discard
                and evidence_sink is not None
                and hasattr(factory, "unbind_writer")
            ):
                try:
                    self._queue_writer_cleanup(
                        source.camera_id,
                        evidence_sink,
                        generation=None,
                    )
                    self._retry_pending_writer_cleanup(
                        camera_id=source.camera_id,
                        writer=evidence_sink,
                    )
                except BaseException:
                    self._evidence_attachment_failures += 1
            raise

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

    def _link_dynamic_rtsp_pad(
        self,
        _: Any,
        pad: Any,
        depay: Any,
        codec: Literal["h264", "h265"],
        camera_id: str | None = None,
        lease: SourceProbeLease | None = None,
        gst: Any | None = None,
    ) -> None:
        try:
            caps = pad.get_current_caps() or pad.query_caps(None)
        except (AttributeError, IndexError, KeyError, OverflowError, TypeError, ValueError):
            caps = None
        fields = rtsp_caps_fields(caps)
        if lease is None:
            if fields is None or not should_link_rtsp_video_pad(fields, codec):
                return
        else:
            assert camera_id is not None
            assert gst is not None
            if (
                fields is not None
                and fields.get("name") == "application/x-rtp"
                and fields.get("media", "").lower() != "video"
            ):
                return
            encoding = "" if fields is None else fields.get("encoding-name", "").upper()
            observed_codec = {"H264": "h264", "H265": "h265"}.get(encoding, "")
            valid = (
                fields is not None
                and fields.get("name") == "application/x-rtp"
                and fields.get("media", "").lower() == "video"
                and observed_codec in {"h264", "h265"}
            )
            accepted = self._observe_native_primitive(
                camera_id,
                lease,
                lambda: lease.observe_rtp_caps(
                    observed_codec,
                    self._monotonic_ns(),
                ),
                valid=valid,
            )
            if not accepted or observed_codec != codec:
                return
        assert fields is not None
        if not should_link_rtsp_video_pad(fields, codec):
            return
        sink = depay.get_static_pad("sink")
        if not sink.is_linked():
            if int(pad.link(sink)) != 0:
                if camera_id is not None and lease is not None:
                    self._camera_local_probe_failure(
                        camera_id,
                        lease,
                        "rtsp_video_pad_link_failed",
                    )
                    return
                raise RuntimeError("failed to link validated RTSP video pad")

    def _decoder_caps_probe(
        self,
        _: Any,
        info: Any,
        camera_id: str,
        lease: SourceProbeLease,
        gst: Any,
    ) -> Any:
        try:
            event = info.get_event()
            if event is None or event.type != gst.EventType.CAPS:
                return gst.PadProbeReturn.OK
            fields = decoder_caps_fields(event.parse_caps())
        except (
            AttributeError,
            IndexError,
            KeyError,
            OverflowError,
            TypeError,
            ValueError,
        ):
            fields = None
        width, height, numerator, denominator = (0, 0, 0, 0) if fields is None else fields
        self._observe_native_primitive(
            camera_id,
            lease,
            lambda: lease.observe_decoder_caps(
                width,
                height,
                numerator,
                denominator,
                self._monotonic_ns(),
            ),
            valid=fields is not None,
        )
        return gst.PadProbeReturn.OK

    def _parser_buffer_probe(
        self,
        _: Any,
        info: Any,
        camera_id: str,
        lease: SourceProbeLease,
        gst: Any,
    ) -> Any:
        buffer = None
        try:
            buffer = info.get_buffer()
            byte_size = buffer.get_size()
            source_timestamp_ns = buffer.dts
            pts_ns = buffer.pts
        except (AttributeError, OverflowError, TypeError, ValueError):
            byte_size = source_timestamp_ns = pts_ns = 0
        valid = all(
            type(value) is int and 0 < value <= 2**63 - 1
            for value in (byte_size, source_timestamp_ns, pts_ns)
        ) and all(
            value != getattr(gst, "CLOCK_TIME_NONE", 2**64 - 1)
            for value in (source_timestamp_ns, pts_ns)
        )
        self._observe_native_primitive(
            camera_id,
            lease,
            lambda: lease.observe_parser_buffer(
                byte_size if type(byte_size) is int else 0,
                source_timestamp_ns if type(source_timestamp_ns) is int else 0,
                pts_ns if type(pts_ns) is int else 0,
                self._monotonic_ns(),
            ),
            valid=valid,
        )
        return gst.PadProbeReturn.OK

    def _decoder_buffer_probe(
        self,
        _: Any,
        info: Any,
        camera_id: str,
        lease: SourceProbeLease,
        gst: Any,
    ) -> Any:
        try:
            buffer = info.get_buffer()
            pts_ns = buffer.pts
        except (AttributeError, OverflowError, TypeError, ValueError):
            pts_ns = 0
        valid = (
            type(pts_ns) is int
            and 0 < pts_ns <= 2**63 - 1
            and pts_ns != getattr(gst, "CLOCK_TIME_NONE", 2**64 - 1)
        )
        accepted = self._observe_native_primitive(
            camera_id,
            lease,
            lambda: lease.observe_decoded_buffer(
                pts_ns if type(pts_ns) is int else 0,
                self._monotonic_ns(),
            ),
            valid=valid,
        )
        if accepted:
            self._record_metadata_owner(camera_id, lease, pts_ns)
        return gst.PadProbeReturn.OK

    def _generation_for_lease(
        self,
        camera_id: str,
        lease: SourceProbeLease,
    ) -> _SourceGeneration | None:
        candidates = (
            self._active_source_generations.get(camera_id),
            self._staged_source_generations.get(camera_id),
            self._metadata_source_generations.get(camera_id),
        )
        return next(
            (
                generation
                for generation in candidates
                if generation is not None and generation.lease is lease
            ),
            None,
        )

    def _record_metadata_owner(
        self,
        camera_id: str,
        lease: SourceProbeLease,
        pts_ns: int,
    ) -> None:
        if type(pts_ns) is not int or not 0 < pts_ns <= 2**63 - 1:
            return
        with self._generation_state_lock:
            generation = self._generation_for_lease(camera_id, lease)
            if generation is None or not self._generation_accepts_frame_locked(generation):
                return
            key = (generation.source_id, pts_ns)
            with self._metadata_owner_lock:
                existing = self._metadata_owners.get(key)
                if existing is None:
                    self._metadata_owners[key] = generation
                elif existing is not generation:
                    self._metadata_owners[key] = _AMBIGUOUS_METADATA_OWNER
                self._metadata_owners.move_to_end(key)
                while len(self._metadata_owners) > _MAX_METADATA_OWNER_ENTRIES:
                    self._metadata_owners.popitem(last=False)

    def _take_metadata_owner(
        self,
        source_id: int,
        pts_ns: int,
    ) -> _SourceGeneration | None:
        with self._metadata_owner_lock:
            generation = self._metadata_owners.pop((source_id, pts_ns), None)
        return generation if isinstance(generation, _SourceGeneration) else None

    def _current_stream_epoch(self, camera_id: str) -> str | None:
        supervisor = self._supervisor
        if supervisor is None:
            return None
        return str(supervisor.health_for(camera_id).stream_epoch)

    def _generation_accepts_frame_locked(
        self,
        generation: _SourceGeneration,
    ) -> bool:
        if self._active_source_generations.get(generation.camera_id) is not generation:
            return False
        if generation.lifecycle == "live_unauthorized":
            return True
        if generation.lifecycle != "authorized" or not generation._writer_bound:
            return False
        current_epoch = self._current_stream_epoch(generation.camera_id)
        return current_epoch is not None and generation.authorized_stream_epoch == current_epoch

    def _clear_metadata_owners(self, camera_id: str) -> None:
        source_ids = {
            generation.source_id
            for generation in (
                self._active_source_generations.get(camera_id),
                self._staged_source_generations.get(camera_id),
                self._metadata_source_generations.get(camera_id),
            )
            if generation is not None
        }
        with self._metadata_owner_lock:
            self._metadata_owners = OrderedDict(
                (key, generation)
                for key, generation in self._metadata_owners.items()
                if key[0] not in source_ids
            )

    def _observe_native_primitive(
        self,
        camera_id: str,
        lease: SourceProbeLease,
        observation: Callable[[], bool],
        *,
        valid: bool,
        failure_reason: str = "native_source_profile_failed",
    ) -> bool:
        with self._generation_state_lock:
            generation = self._generation_for_lease(camera_id, lease)
            if generation is None or not self._native_probe_is_admissible_locked(camera_id, lease):
                return False
            authority_revision = generation.authority_revision
        try:
            accepted = observation()
        except (OverflowError, TypeError, ValueError):
            accepted = False
        with self._generation_state_lock:
            if (
                generation.authority_revision != authority_revision
                or not self._native_probe_is_admissible_locked(camera_id, lease)
            ):
                return False
        if valid and accepted:
            return True
        self._camera_local_probe_failure(
            camera_id,
            lease,
            failure_reason,
        )
        return False

    def _native_probe_is_admissible_locked(
        self,
        camera_id: str,
        lease: SourceProbeLease,
    ) -> bool:
        active = self._active_source_generations.get(camera_id)
        if active is not None and active.lease is lease:
            return self._generation_accepts_frame_locked(active)
        staged = self._staged_source_generations.get(camera_id)
        return (
            staged is not None
            and staged.lease is lease
            and staged.lifecycle == "staged"
            and lease.active
        )

    def _camera_local_probe_failure(
        self,
        camera_id: str,
        lease: SourceProbeLease,
        reason: str,
    ) -> None:
        with self._generation_state_lock:
            if (
                self._native_probe_is_admissible_locked(camera_id, lease)
                and self._recovery is not None
            ):
                self._recovery.handle_camera_failure(
                    camera_id,
                    reason,
                    force=True,
                )

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
        if type(source_id) is not int or source_id < 0:
            raise ValueError("invalid source ID")
        source = next(
            (candidate for candidate in self._graph.sources if candidate.source_id == source_id),
            None,
        )
        if source is None:
            raise ValueError("invalid source ID")
        camera_id = source.camera_id
        raw_ntp_timestamp = getattr(frame_meta, "ntp_timestamp", 0)
        raw_running_time_ns = getattr(frame_meta, "buf_pts", 0)
        ntp_is_valid = type(raw_ntp_timestamp) is int and 0 < raw_ntp_timestamp <= 2**63 - 1
        running_time_is_valid = (
            type(raw_running_time_ns) is int and 0 < raw_running_time_ns <= 2**63 - 1
        )
        if not running_time_is_valid:
            return
        generation = self._take_metadata_owner(source_id, raw_running_time_ns)
        if (
            generation is None
            or generation.camera_id != camera_id
            or generation.source_id != source_id
        ):
            return
        with self._generation_state_lock:
            if not self._generation_accepts_frame_locked(generation):
                return
            authority_revision = generation.authority_revision
        native_accepted = self._observe_native_primitive(
            camera_id,
            generation.lease,
            lambda: generation.lease.observe_nvds_ntp(
                raw_running_time_ns,
                raw_ntp_timestamp if type(raw_ntp_timestamp) is int else 0,
                self._monotonic_ns(),
            ),
            valid=ntp_is_valid,
            failure_reason="camera_rtcp_time_unavailable",
        )
        if not ntp_is_valid or not native_accepted:
            return
        correlated_ntp = generation.lease.correlated_ntp(
            raw_running_time_ns,
            raw_ntp_timestamp,
        )
        if not isinstance(correlated_ntp, CorrelatedNtpV1):
            return
        ntp_timestamp = raw_ntp_timestamp
        running_time_ns = raw_running_time_ns
        source_time = datetime.fromtimestamp(ntp_timestamp / 1_000_000_000, UTC)
        frame_width = getattr(frame_meta, "source_frame_width", 0)
        frame_height = getattr(frame_meta, "source_frame_height", 0)
        frame_number = getattr(frame_meta, "frame_num", -1)
        if (
            type(frame_width) is not int
            or type(frame_height) is not int
            or type(frame_number) is not int
            or frame_width <= 0
            or frame_height <= 0
            or frame_number < 0
        ):
            raise ValueError("invalid frame metadata")
        with self._generation_state_lock:
            stream_epoch = self._current_stream_epoch(camera_id)
            if (
                stream_epoch is None
                or generation.authority_revision != authority_revision
                or any(
                    observed_monotonic_ns <= generation.correlation_not_before_monotonic_ns
                    for observed_monotonic_ns in (
                        correlated_ntp.parser_observed_monotonic_ns,
                        correlated_ntp.decoded_observed_monotonic_ns,
                        correlated_ntp.ntp_observed_monotonic_ns,
                        correlated_ntp.completed_monotonic_ns,
                    )
                )
                or not self._generation_accepts_frame_locked(generation)
            ):
                return
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
            if not self._authorize_generation(
                generation,
                running_time_ns=running_time_ns,
                stream_epoch=stream_epoch,
            ):
                return
            object_node = frame_meta.obj_meta_list
            object_ordinal = 0
            accepted_metadata: list[FrameMetadataV1] = []
            while object_node is not None:
                try:
                    object_meta = pyds.NvDsObjectMeta.cast(object_node.data)
                    rect = object_meta.rect_params
                    raw = (
                        float(rect.left),
                        float(rect.top),
                        float(rect.width),
                        float(rect.height),
                    )
                    confidence = float(object_meta.confidence)
                    if not all(math.isfinite(value) for value in (*raw, confidence)):
                        raise ValueError("non-finite metadata")
                    if not 0.0 <= confidence <= 1.0 or raw[2] <= 0.0 or raw[3] <= 0.0:
                        raise ValueError("invalid detection metadata")
                    left = max(0.0, min(1.0, raw[0] / frame_width))
                    top = max(0.0, min(1.0, raw[1] / frame_height))
                    right = max(
                        0.0,
                        min(1.0, (raw[0] + raw[2]) / frame_width),
                    )
                    bottom = max(
                        0.0,
                        min(1.0, (raw[1] + raw[3]) / frame_height),
                    )
                    if not (left < right and top < bottom):
                        raise ValueError("invalid normalised bbox")
                    accepted_metadata.append(
                        FrameMetadataV1(
                            camera_id=camera_id,
                            source_time=source_time,
                            timestamp_quality="camera_rtcp",
                            monotonic_seq=metadata_observation_sequence(
                                frame_number,
                                object_ordinal,
                            ),
                            class_name="person",
                            confidence=confidence,
                            bbox=(left, top, right, bottom),
                            track_id=str(object_meta.object_id),
                        )
                    )
                except (
                    AttributeError,
                    OSError,
                    OverflowError,
                    StopIteration,
                    TypeError,
                    ValueError,
                ):
                    self._invalid_metadata_count += 1
                object_ordinal += 1
                object_node = self._next_metadata_node(object_node)
            if self._acceptance_work_completion is not None:
                try:
                    self._acceptance_work_completion(
                        camera_id=camera_id,
                        source_index=source_id,
                        module="person",
                        detection_count=len(accepted_metadata),
                    )
                except (RuntimeError, TypeError, ValueError):
                    self._invalid_metadata_count += 1
                    return
            try:
                publication_enabled = self._analytics_publication_gate()
            except BaseException:
                publication_enabled = False
            published = self._metadata_publisher.publish_frame(
                camera_id=camera_id,
                source_time=source_time,
                monotonic_seq=frame_number,
                metadata=(
                    tuple(accepted_metadata)
                    if publication_enabled is True
                    else ()
                ),
            )
            if published is None and self._recovery is not None:
                self._recovery.handle_camera_failure(
                    camera_id,
                    "invalid_frame_heartbeat",
                    force=True,
                )

    def _authorize_generation(
        self,
        generation: _SourceGeneration,
        *,
        running_time_ns: int,
        stream_epoch: str,
    ) -> bool:
        with self._generation_state_lock:
            if (
                self._active_source_generations.get(generation.camera_id) is not generation
                or self._current_stream_epoch(generation.camera_id) != stream_epoch
                or generation.lifecycle not in {"live_unauthorized", "authorized"}
            ):
                return False
            if generation.lifecycle == "authorized":
                return (
                    generation._writer_bound and generation.authorized_stream_epoch == stream_epoch
                )
            try:
                self._bind_generation_writer(
                    generation,
                    stream_epoch=stream_epoch,
                )
            except Exception:
                if self._recovery is not None:
                    self._recovery.handle_camera_failure(
                        generation.camera_id,
                        "evidence_writer_bind_failed",
                        force=True,
                    )
                return False
            if self._current_stream_epoch(generation.camera_id) != stream_epoch:
                generation._writer_bound = False
                return False
            generation.authorized_running_time_ns = running_time_ns
            generation.authorized_stream_epoch = stream_epoch
            generation.evidence_open_location = None
            generation.lifecycle = "authorized"
            return True

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
        if factory is None or not hasattr(factory, "handle_writer_message"):
            self._evidence_attachment_failures += 1
            return
        try:
            structure_name = structure.get_name()
            running_time_ns = structure.get_value("running-time")
            location = structure.get_value("location")
        except (AttributeError, KeyError, TypeError, ValueError):
            return
        if (
            type(structure_name) is not str
            or type(running_time_ns) is not int
            or running_time_ns < 0
            or running_time_ns >= 2**63
            or type(location) is not str
            or not location
        ):
            return
        with self._generation_state_lock:
            generation = next(
                (
                    candidate
                    for candidate in self._active_source_generations.values()
                    if candidate.writer is message.src
                ),
                None,
            )
            if (
                generation is None
                or generation.lifecycle != "authorized"
                or not generation._writer_bound
                or generation.authorized_running_time_ns is None
                or generation.authorized_stream_epoch
                != self._current_stream_epoch(generation.camera_id)
            ):
                return
            camera_id = generation.camera_id
            if structure_name == "splitmuxsink-fragment-opened":
                if running_time_ns < generation.authorized_running_time_ns:
                    return
                generation.evidence_open_location = location
            elif structure_name == "splitmuxsink-fragment-closed":
                if generation.evidence_open_location != location:
                    return
                generation.evidence_open_location = None
            else:
                return
            try:
                factory.handle_writer_message(  # type: ignore[attr-defined]
                    writer=message.src,
                    structure=structure,
                    source_time_mapper=self._source_time_mapper,
                )
            except Exception:
                self._evidence_attachment_failures += 1

                def cleanup(action: Callable[[], None]) -> None:
                    try:
                        action()
                    except BaseException:
                        return

                cleanup(
                    lambda: self._revoke_generation_authority(
                        generation,
                        lifecycle="quiescing",
                    )
                )
                cleanup(lambda: self._disable_evidence(camera_id))
                if self._bindings is not None and hasattr(message.src, "set_state"):
                    cleanup(lambda: message.src.set_state(self._bindings.gst.State.NULL))
                if self._recovery is not None:
                    cleanup(
                        lambda: self._recovery.handle_camera_failure(
                            camera_id,
                            "evidence_fragment_adoption_failed",
                            force=True,
                        )
                    )
                elif self._supervisor is not None:
                    cleanup(
                        lambda: self._supervisor.disconnect(
                            camera_id,
                            "evidence_fragment_adoption_failed",
                        )
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
            (source.camera_id for source in self._graph.sources if source.source_id == source_id),
            None,
        )

    def _block_and_flush_generation(
        self,
        generation: _SourceGeneration,
        source_pad: Any,
        mux_sink_pad: Any,
    ) -> int:
        assert self._bindings is not None
        gst = self._bindings.gst
        blocked = ThreadEvent()

        def acknowledge_block(_: Any, __: Any) -> Any:
            blocked.set()
            return gst.PadProbeReturn.OK

        probe_id = source_pad.add_probe(
            gst.PadProbeType.IDLE | gst.PadProbeType.BLOCK_DOWNSTREAM,
            acknowledge_block,
        )
        if type(probe_id) is not int or probe_id <= 0:
            raise RuntimeError(f"failed to block old source bin for {generation.camera_id}")
        flush_started = False
        try:
            if not blocked.wait(timeout=2.0):
                raise RuntimeError(f"timed out blocking old source bin for {generation.camera_id}")
            if mux_sink_pad.send_event(gst.Event.new_flush_start()) is not True:
                raise RuntimeError(
                    f"failed to acknowledge source flush start for {generation.camera_id}"
                )
            flush_started = True
            with self._generation_state_lock:
                generation._cutover_source_pad = source_pad
                generation._cutover_mux_sink_pad = mux_sink_pad
                generation._cutover_probe_id = probe_id
                generation._flush_stop_pending = True
                if mux_sink_pad.send_event(gst.Event.new_flush_stop(True)) is not True:
                    raise RuntimeError(
                        f"failed to acknowledge source flush stop for {generation.camera_id}"
                    )
                generation._flush_stop_pending = False
            self._clear_metadata_owners(generation.camera_id)
            return probe_id
        except BaseException:
            if not flush_started:
                source_pad.remove_probe(probe_id)
            raise

    def _retry_pending_flush_stop(
        self,
        generation: _SourceGeneration,
        *,
        release_block: bool,
    ) -> None:
        with self._generation_state_lock:
            probe_id = generation._cutover_probe_id
            source_pad = generation._cutover_source_pad
            mux_sink_pad = generation._cutover_mux_sink_pad
            if probe_id is None:
                return
            if source_pad is None or mux_sink_pad is None:
                raise RuntimeError(f"camera {generation.camera_id} lost source flush ownership")
            if generation._flush_stop_pending:
                if self._bindings is None:
                    raise RuntimeError(
                        f"camera {generation.camera_id} cannot complete source flush stop"
                    )
                if (
                    mux_sink_pad.send_event(self._bindings.gst.Event.new_flush_stop(True))
                    is not True
                ):
                    raise RuntimeError(
                        f"failed to acknowledge source flush stop for {generation.camera_id}"
                    )
                generation._flush_stop_pending = False
            if release_block:
                source_pad.remove_probe(probe_id)
                generation._cutover_source_pad = None
                generation._cutover_mux_sink_pad = None
                generation._cutover_probe_id = None

    def _discard_generation_source_block(
        self,
        generation: _SourceGeneration,
    ) -> None:
        with self._generation_state_lock:
            source_pad = generation._cutover_source_pad
            probe_id = generation._cutover_probe_id
            if source_pad is not None and probe_id is not None:
                source_pad.remove_probe(probe_id)
            generation._cutover_source_pad = None
            generation._cutover_mux_sink_pad = None
            generation._cutover_probe_id = None
            generation._flush_stop_pending = False

    def _rebuild_source(self, camera_id: str) -> None:
        """Replace one camera generation while retaining a rollback-capable old path."""
        if self._pipeline is None or self._graph is None or self._bindings is None:
            return
        with self._generation_state_lock:
            old_generation = self._active_source_generations.get(camera_id)
            if old_generation is None:
                raise RuntimeError(f"source bin {camera_id} has no active generation")
            try:
                if old_generation.lifecycle != "quiescing":
                    self._revoke_generation_authority(
                        old_generation,
                        lifecycle="quiescing",
                    )
            except BaseException:
                self._restore_generation_after_failed_rebuild_locked(old_generation)
                raise

        replacement: _SourceGeneration | None = None
        try:
            self._retry_pending_generation_cleanup(camera_id)
            source = next(item for item in self._graph.sources if item.camera_id == camera_id)
            old_bin = old_generation.source_bin
            old_source_pad = old_bin.get_static_pad("decoded_src")
            mux = self._pipeline.get_by_name("streammux")
            mux_sink_pad = None if mux is None else mux.get_static_pad(f"sink_{source.source_id}")
            if mux_sink_pad is None:
                mux_sink_pad = old_source_pad.get_peer()
            if mux_sink_pad is None:
                raise RuntimeError(f"source bin {camera_id} has no streammux pad")
            replacement = self._build_source_generation(
                self._bindings.gst,
                source,
                self._locations[camera_id],
                activate_lease=False,
            )
            with self._generation_state_lock:
                self._staged_source_generations[camera_id] = replacement
            replacement_bin = replacement.source_bin
            replacement_pad = replacement_bin.get_static_pad("decoded_src")
        except BaseException:
            if replacement is not None:
                replacement_cleanup_failed = False
                try:
                    self._cleanup_replacement_generation(
                        replacement,
                        added=replacement._added_to_pipeline,
                    )
                except BaseException:
                    replacement_cleanup_failed = True
                if not replacement_cleanup_failed:
                    with self._generation_state_lock:
                        if self._staged_source_generations.get(camera_id) is replacement:
                            self._staged_source_generations.pop(camera_id, None)
            with self._generation_state_lock:
                if (
                    self._active_source_generations.get(camera_id) is old_generation
                    and old_generation._cutover_probe_id is None
                ):
                    self._restore_generation_after_failed_rebuild_locked(old_generation)
            raise

        replacement_added = False
        old_unlinked = False
        replacement_linked = False
        old_lease_deactivated = False
        replacement_lease_activated = False
        cutover_probe_id: int | None = None
        try:
            if self._pipeline.add(replacement_bin) is False:
                raise RuntimeError(f"failed to add rebuilt source bin for {camera_id}")
            replacement_added = True
            replacement._added_to_pipeline = True
            cutover_probe_id = self._block_and_flush_generation(
                old_generation,
                old_source_pad,
                mux_sink_pad,
            )
            if old_source_pad.unlink(mux_sink_pad) is False:
                raise RuntimeError(f"failed to unlink old source bin for {camera_id}")
            old_unlinked = True
            if replacement_pad.link(mux_sink_pad) != self._bindings.gst.PadLinkReturn.OK:
                raise RuntimeError(f"failed to relink rebuilt source bin for {camera_id}")
            replacement_linked = True
            old_lease_deactivated = True
            old_generation.lease.deactivate()
            replacement.lease.activate()
            replacement_lease_activated = True
            if not replacement_bin.sync_state_with_parent():
                raise RuntimeError(f"failed to sync rebuilt source bin for {camera_id}")
        except BaseException as primary_error:
            rollback_error: BaseException | None = None
            replacement_cleanup_failed = False
            old_lease_restored = not old_lease_deactivated

            def rollback(action: Callable[[], None]) -> None:
                nonlocal rollback_error
                try:
                    action()
                except BaseException as exc:
                    if rollback_error is None:
                        rollback_error = exc

            if replacement_lease_activated:
                rollback(replacement.lease.deactivate)
            if old_lease_deactivated:
                try:
                    old_generation.lease.activate()
                    old_lease_restored = True
                except BaseException as exc:
                    old_lease_restored = False
                    if rollback_error is None:
                        rollback_error = exc
            if replacement_linked:
                rollback(
                    lambda: self._require_unlink(
                        replacement_pad,
                        mux_sink_pad,
                        f"replacement source bin {camera_id}",
                    )
                )
            try:
                old_peer = old_source_pad.get_peer()
            except (AttributeError, TypeError):
                old_peer = None
            if old_unlinked or old_peer is not mux_sink_pad:
                rollback(
                    lambda: self._require_link(
                        old_source_pad,
                        mux_sink_pad,
                        f"old source bin {camera_id}",
                    )
                )
            with self._generation_state_lock:
                self._metadata_source_generations[camera_id] = old_generation
            if old_lease_restored and rollback_error is None:
                rollback(
                    lambda: self._require_sync(
                        old_bin,
                        f"old source bin {camera_id}",
                    )
                )
            if old_lease_restored and rollback_error is None and cutover_probe_id is not None:
                rollback(
                    lambda: self._retry_pending_flush_stop(
                        old_generation,
                        release_block=True,
                    )
                )
            if rollback_error is not None and old_lease_deactivated and old_lease_restored:
                try:
                    old_generation.lease.deactivate()
                except BaseException:
                    pass
            try:
                self._cleanup_replacement_generation(
                    replacement,
                    added=replacement_added,
                )
            except BaseException as exc:
                replacement_cleanup_failed = True
                if rollback_error is None:
                    rollback_error = exc
            if not replacement_cleanup_failed:
                with self._generation_state_lock:
                    self._staged_source_generations.pop(camera_id, None)
            if rollback_error is not None:
                if self._recovery is not None:
                    self._recovery.handle_camera_failure(
                        camera_id,
                        "rtsp_rebuild_rollback_failed",
                        force=True,
                    )
                raise RuntimeError(
                    f"failed to restore old source generation for {camera_id}"
                ) from rollback_error
            with self._generation_state_lock:
                if (
                    self._active_source_generations.get(camera_id) is old_generation
                    and old_generation._cutover_probe_id is None
                ):
                    self._restore_generation_after_failed_rebuild_locked(old_generation)
            raise primary_error

        with self._generation_state_lock:
            replacement.correlation_not_before_monotonic_ns = max(
                replacement.correlation_not_before_monotonic_ns,
                self._monotonic_ns(),
            )
            replacement.authority_revision += 1
            replacement.lifecycle = "live_unauthorized"
            self._active_source_generations[camera_id] = replacement
            self._metadata_source_generations[camera_id] = replacement
            self._staged_source_generations.pop(camera_id, None)
        retirement_error: BaseException | None = None

        def retire(action: Callable[[], None]) -> None:
            nonlocal retirement_error
            try:
                action()
            except BaseException as exc:
                if retirement_error is None:
                    retirement_error = exc

        with self._generation_state_lock:
            old_generation.lifecycle = "retired"
            self._retired_source_generations[camera_id] = old_generation
        if cutover_probe_id is not None:
            retire(
                lambda: self._retry_pending_flush_stop(
                    old_generation,
                    release_block=True,
                )
            )
        retire(lambda: old_bin.set_state(self._bindings.gst.State.NULL))
        retire(
            lambda: self._remove_generation_from_pipeline(
                old_generation,
                f"old source bin {camera_id}",
            )
        )
        retire(lambda: self._unbind_generation_writer(old_generation))
        retire(old_generation.close_lease)
        if retirement_error is not None:
            if self._recovery is not None:
                self._recovery.handle_camera_failure(
                    camera_id,
                    "rtsp_rebuild_retirement_failed",
                    force=True,
                )
            raise RuntimeError(
                f"failed to retire old source generation for {camera_id}"
            ) from retirement_error
        with self._generation_state_lock:
            self._retired_source_generations.pop(camera_id, None)

    def _retry_pending_generation_cleanup(self, camera_id: str) -> None:
        self._retry_pending_writer_cleanup(camera_id=camera_id)
        active = self._active_source_generations.get(camera_id)
        if active is not None:
            self._retry_pending_flush_stop(
                active,
                release_block=True,
            )
        staged = self._staged_source_generations.get(camera_id)
        if staged is not None:
            self._cleanup_replacement_generation(
                staged,
                added=staged._added_to_pipeline,
            )
            self._staged_source_generations.pop(camera_id, None)
        retired = self._retired_source_generations.get(camera_id)
        if retired is not None:
            self._cleanup_replacement_generation(
                retired,
                added=retired._added_to_pipeline,
            )
            self._retired_source_generations.pop(camera_id, None)

    def _cleanup_replacement_generation(
        self,
        generation: _SourceGeneration,
        *,
        added: bool,
    ) -> None:
        cleanup_error: BaseException | None = None

        def cleanup(action: Callable[[], None]) -> None:
            nonlocal cleanup_error
            try:
                action()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc

        if self._bindings is not None:
            cleanup(lambda: generation.source_bin.set_state(self._bindings.gst.State.NULL))
        if added:
            cleanup(
                lambda: self._remove_generation_from_pipeline(
                    generation,
                    f"replacement source bin {generation.camera_id}",
                )
            )
        generation.lifecycle = "retired"
        cleanup(lambda: self._unbind_generation_writer(generation))
        cleanup(generation.close_lease)
        if cleanup_error is not None:
            raise cleanup_error

    def _require_link(self, source_pad: Any, sink_pad: Any, label: str) -> None:
        assert self._bindings is not None
        if source_pad.link(sink_pad) != self._bindings.gst.PadLinkReturn.OK:
            raise RuntimeError(f"failed to relink {label}")

    @staticmethod
    def _require_unlink(source_pad: Any, sink_pad: Any, label: str) -> None:
        if source_pad.unlink(sink_pad) is False:
            raise RuntimeError(f"failed to unlink {label}")

    @staticmethod
    def _require_sync(source_bin: Any, label: str) -> None:
        if source_bin.sync_state_with_parent() is False:
            raise RuntimeError(f"failed to sync {label}")

    def _require_remove(self, source_bin: Any, label: str) -> None:
        assert self._pipeline is not None
        if self._pipeline.remove(source_bin) is False:
            raise RuntimeError(f"failed to remove {label}")

    def _remove_generation_from_pipeline(
        self,
        generation: _SourceGeneration,
        label: str,
    ) -> None:
        self._require_remove(generation.source_bin, label)
        generation._added_to_pipeline = False


def _target_runtime_info() -> tuple[str, str]:
    """Read target facts only after this fail-closed image has been scheduled on NVIDIA."""
    compute_capability = (
        subprocess.run(
            ["nvidia-smi", "--query-gpu=compute_cap", "--format=csv,noheader"],
            check=True,
            capture_output=True,
            text=True,
        )
        .stdout.strip()
        .splitlines()
    )
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


def _read_reviewed_file(
    path: Path,
    *,
    expected_sha256: str,
    label: str,
    max_bytes: int = 8 * 1024 * 1024,
) -> bytes:
    if (
        not path.is_absolute()
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or not 1 <= max_bytes <= 64 * 1024 * 1024
    ):
        raise RuntimeError(f"reviewed {label} is unavailable")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= max_bytes:
            raise RuntimeError(f"reviewed {label} exceeds finite bound")
        payload = os.read(descriptor, max_bytes + 1)
    except OSError as exc:
        raise RuntimeError(f"reviewed {label} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > max_bytes or hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise RuntimeError(f"reviewed {label} digest mismatch")
    return payload


def _run_main_loop_with_graceful_signals(
    runtime: DeepStreamDataPlane,
    loop: Any,
    *,
    signal_module: Any = signal,
) -> int:
    """Translate operator termination into a clean pipeline drain and exit."""
    previous_handlers: dict[int, Any] = {}

    def request_shutdown(_signum: int, _frame: Any) -> None:
        loop.quit()

    try:
        for signum in (signal_module.SIGTERM, signal_module.SIGINT):
            previous_handlers[signum] = signal_module.getsignal(signum)
            signal_module.signal(signum, request_shutdown)
        if runtime.failed_reason is None:
            loop.run()
    finally:
        try:
            runtime.stop()
        finally:
            for signum, handler in previous_handlers.items():
                signal_module.signal(signum, handler)
    return 1 if runtime.failed_reason is not None else 0


def _load_target_reviewed_mapping(
    payload: bytes,
    *,
    max_bytes: int,
    label: str,
) -> Mapping[str, Any]:
    """Parse one digest-bound target input without ambiguous YAML features."""
    try:
        parsed = load_strict_yaml(
            payload,
            max_bytes=max_bytes,
            max_nodes=_MAX_TARGET_YAML_NODES,
            max_depth=_MAX_TARGET_YAML_DEPTH,
            require_mapping=True,
        )
    except StrictYAMLError as exc:
        raise GraphContractError(f"{label} YAML is invalid") from exc
    assert isinstance(parsed, Mapping)
    return parsed


def main(argv: list[str] | None = None) -> int:
    """Run only with signed target inputs; bare image invocation exits non-zero."""
    # Imported only after this module's graph contracts are initialized.  The
    # acceptance work planner imports those contracts and must not form a
    # module-initialization cycle through the child runtime composition.
    from protector.pilot.runtime.acceptance_runtime import (
        TargetAcceptanceRuntimeV3,
    )

    parser = argparse.ArgumentParser(description="Run the Kuzet shared DeepStream data plane")
    parser.add_argument("--site-config", type=Path, required=True)
    parser.add_argument("--site-config-sha256", required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--runtime-manifest-sha256", required=True)
    parser.add_argument("--measured-capacity-report", type=Path, required=True)
    parser.add_argument("--measured-capacity-sha256", required=True)
    parser.add_argument("--measured-capacity-signature", type=Path, required=True)
    parser.add_argument("--capacity-authority-public-key", type=Path, required=True)
    parser.add_argument("--runtime-image-id-sha256", required=True)
    parser.add_argument("--runtime-image-config-sha256", required=True)
    parser.add_argument("--runtime-code-sha256", required=True)
    parser.add_argument("--mount-contract-sha256", required=True)
    parser.add_argument("--runtime-launch-nonce", required=True)
    parser.add_argument("--control-plane-url", required=True)
    parser.add_argument("--machine-token-file", type=Path, required=True)
    parser.add_argument("--acceptance-channel", type=Path, required=True)
    parser.add_argument("--acceptance-source-secrets-root", type=Path, required=True)
    parser.add_argument("--acceptance-native-projection", type=Path, required=True)
    parser.add_argument("--acceptance-work-projection", type=Path, required=True)
    arguments = parser.parse_args(argv)
    acceptance_runtime: TargetAcceptanceRuntimeV3 | None = None
    runtime: DeepStreamDataPlane | None = None
    try:
        if re.fullmatch(r"[a-f0-9]{32}", arguments.runtime_launch_nonce) is None:
            raise ValueError("runtime launch nonce is invalid")
        site_payload = _read_reviewed_file(
            arguments.site_config,
            expected_sha256=arguments.site_config_sha256,
            label="site configuration",
        )
        runtime_payload = _read_reviewed_file(
            arguments.runtime_manifest,
            expected_sha256=arguments.runtime_manifest_sha256,
            label="runtime manifest",
        )
        verified_capacity = verify_detached_artifact(
            payload_path=arguments.measured_capacity_report,
            signature_path=arguments.measured_capacity_signature,
            trusted_public_key_path=arguments.capacity_authority_public_key,
            expected_payload_sha256=arguments.measured_capacity_sha256,
            max_payload_bytes=8 * 1024 * 1024,
            label="measured capacity report",
        )
        site = SiteConfig.model_validate(
            _load_target_reviewed_mapping(
                site_payload,
                max_bytes=_MAX_TARGET_SITE_YAML_BYTES,
                label="site configuration",
            )
        )
        runtime_manifest = RuntimeModelManifestV1.model_validate(
            _load_target_reviewed_mapping(
                runtime_payload,
                max_bytes=_MAX_TARGET_AUTHORITY_YAML_BYTES,
                label="runtime manifest",
            )
        )
        measured_capacity = MeasuredCapacityReportV1.model_validate(
            _load_target_reviewed_mapping(
                verified_capacity.payload,
                max_bytes=_MAX_TARGET_AUTHORITY_YAML_BYTES,
                label="measured capacity report",
            )
        )
        require_measured_primary_capacity(
            site_config=site,
            runtime_manifest=runtime_manifest,
            report=measured_capacity,
            runtime_image_id_sha256=arguments.runtime_image_id_sha256,
            runtime_image_config_sha256=arguments.runtime_image_config_sha256,
            runtime_code_sha256=arguments.runtime_code_sha256,
            mount_contract_sha256=arguments.mount_contract_sha256,
            runtime_manifest_file_sha256=arguments.runtime_manifest_sha256,
        )
        telemetry_client = AuthenticatedTelemetryClient(
            base_url=arguments.control_plane_url,
            machine_token=read_machine_token(arguments.machine_token_file),
        )
        acceptance_runtime = TargetAcceptanceRuntimeV3(
            channel_path=arguments.acceptance_channel,
            native_source_secrets_root=(
                arguments.acceptance_source_secrets_root
            ),
            native_projection_path=arguments.acceptance_native_projection,
            work_projection_path=arguments.acceptance_work_projection,
        )
        runtime = DeepStreamDataPlane(
            runtime_manifest=runtime_manifest,
            runtime_info=_target_runtime_info,
            evidence_sink_factory=build_evidence_sink_factory(site),
            telemetry_publisher_factory=lambda runtime_session_id: AsyncRuntimeTelemetryPublisher(
                publisher=RuntimeTelemetryPublisher(
                    client=telemetry_client,
                    runtime_session_id=runtime_session_id,
                ),
                extra_metrics_provider=TargetResourceMetricsProvider(
                    spool_root=site.storage.retention.encoded_spool_root,
                ),
            ),
            runtime_session_seed_factory=lambda: f"{arguments.runtime_launch_nonce}.{uuid4().hex}",
            native_probe_lease_factory=(
                acceptance_runtime.native_source_authority
            ),
            acceptance_work_completion=acceptance_runtime.work_completion,
            analytics_publication_gate=(
                acceptance_runtime.analytics_publication_enabled
            ),
        )
        runtime.start(site)
    except (
        GraphContractError,
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        ValueError,
    ) as exc:
        failures: list[BaseException] = [exc]
        if runtime is not None:
            try:
                runtime.stop()
            except BaseException as cleanup:
                failures.append(cleanup)
        if acceptance_runtime is not None:
            try:
                acceptance_runtime.close()
            except BaseException as cleanup:
                failures.append(cleanup)
        if len(failures) > 1:
            raise BaseExceptionGroup(
                "DeepStream startup and acceptance cleanup both failed",
                failures,
            ) from exc
        parser.error(str(exc))
    assert runtime is not None
    assert acceptance_runtime is not None
    assert runtime._bindings is not None
    try:
        loop = runtime._bindings.glib.MainLoop()
        runtime._fatal_callback = loop.quit
        acceptance_runtime.start(runtime._bindings.glib, fatal_callback=loop.quit)
        result = _run_main_loop_with_graceful_signals(runtime, loop)
        if acceptance_runtime.failed is not None:
            result = 1
    except BaseException as primary:
        failures = [primary]
        try:
            runtime.stop()
        except BaseException as cleanup:
            failures.append(cleanup)
        try:
            acceptance_runtime.close()
        except BaseException as cleanup:
            failures.append(cleanup)
        if len(failures) == 1:
            raise
        raise BaseExceptionGroup(
            "DeepStream execution and acceptance cleanup both failed",
            failures,
        ) from primary
    else:
        acceptance_runtime.close()
        return result


if __name__ == "__main__":  # pragma: no cover - target process entrypoint.
    raise SystemExit(main())
