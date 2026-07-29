"""Low-cardinality pilot metrics and fail-closed component health."""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

ComponentState = Literal["healthy", "degraded", "failed"]
CameraState = Literal["starting", "online", "degraded", "offline", "reconnecting"]

_MODULES = frozenset(
    {
        "person",
        "restricted_zone",
        "intrusion",
        "loitering",
        "line_crossing",
        "fire",
        "fire_smoke",
        "weapon",
        "fight",
        "fall",
        "violence",
        "xclip",
        "vit",
    }
)
_QUEUES = frozenset({"decode", "analytics", "verifier", "events", "evidence", "notifications"})
_EVIDENCE_RESULTS = frozenset({"ready", "failed", "unavailable"})
_NOTIFICATION_RESULTS = frozenset({"attempted", "delivered", "failed", "dead_letter"})
_CAMERA_STATES = frozenset({"starting", "online", "degraded", "offline", "reconnecting"})
_COMPONENT_STATES = frozenset({"healthy", "degraded", "failed"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _identifier(value: str, *, name: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _finite_nonnegative(value: float | int, *, name: str) -> float:
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return numeric


def _counter_value(value: int, *, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _byte_value(value: int, *, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer byte count")
    return value


class PilotMetrics:
    """An app-local registry with only configured and finite label dimensions."""

    def __init__(
        self,
        *,
        site_id: str,
        camera_ids: Sequence[str],
        model_artifact_ids: Sequence[str],
        registry: CollectorRegistry | None = None,
    ) -> None:
        self.site_id = _identifier(site_id, name="site_id")
        configured_cameras = tuple(_identifier(item, name="camera_id") for item in camera_ids)
        if len(configured_cameras) != 20 or len(set(configured_cameras)) != 20:
            raise ValueError("pilot metrics require exactly 20 unique configured cameras")
        configured_artifacts = tuple(
            _identifier(item, name="model_artifact_id") for item in model_artifact_ids
        )
        if not configured_artifacts or len(set(configured_artifacts)) != len(configured_artifacts):
            raise ValueError("model artifacts must be a non-empty unique configured set")
        self.camera_ids = frozenset(configured_cameras)
        self.model_artifact_ids = frozenset(configured_artifacts)
        self.registry = registry or CollectorRegistry(auto_describe=True)
        self._snapshots: dict[tuple[str, ...], int] = {}
        self._snapshot_lock = threading.Lock()

        constant = ("site_id",)
        camera = ("site_id", "camera_id")
        analysis = ("site_id", "camera_id", "module", "result")
        self._camera_available = Gauge(
            "kuzet_camera_available",
            "Whether a configured camera currently has an available source.",
            camera,
            registry=self.registry,
        )
        self._last_frame_age = Gauge(
            "kuzet_camera_last_frame_age_seconds",
            "Age of the newest source frame.",
            camera,
            registry=self.registry,
        )
        self._reconnects = Counter(
            "kuzet_camera_reconnects",
            "Cumulative supervised reconnect count.",
            camera,
            registry=self.registry,
        )
        self._samples = Counter(
            "kuzet_analysis_samples",
            "Cumulative scheduled, processed, and dropped analysis samples.",
            analysis,
            registry=self.registry,
        )
        self._queue_age = Gauge(
            "kuzet_queue_age_seconds",
            "Age of the oldest item in a bounded queue.",
            ("site_id", "queue"),
            registry=self.registry,
        )
        self._model_latency = Histogram(
            "kuzet_model_latency_seconds",
            "Shared model inference latency.",
            ("site_id", "module", "model_artifact"),
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2),
            registry=self.registry,
        )
        self._candidates = Counter(
            "kuzet_candidates",
            "Candidate events emitted by module.",
            ("site_id", "module"),
            registry=self.registry,
        )
        self._evidence_latency = Histogram(
            "kuzet_evidence_latency_seconds",
            "Bounded evidence materialisation latency.",
            ("site_id",),
            buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
            registry=self.registry,
        )
        self._evidence_results = Counter(
            "kuzet_evidence_results",
            "Evidence materialisation outcomes.",
            ("site_id", "result"),
            registry=self.registry,
        )
        self._gpu_utilization = Gauge(
            "kuzet_gpu_utilization_percent",
            "Aggregate inference GPU utilization.",
            constant,
            registry=self.registry,
        )
        self._vram_bytes = Gauge(
            "kuzet_vram_bytes",
            "Inference VRAM use and capacity.",
            ("site_id", "state"),
            registry=self.registry,
        )
        self._disk_bytes = Gauge(
            "kuzet_disk_bytes",
            "Pilot bounded-disk use and capacity.",
            ("site_id", "state"),
            registry=self.registry,
        )
        self._notification_results = Counter(
            "kuzet_notification_results",
            "Notification attempt and terminal outcomes.",
            ("site_id", "result"),
            registry=self.registry,
        )

    def update_camera(
        self,
        camera_id: str,
        *,
        available: bool,
        last_frame_age_seconds: float,
        reconnects_total: int,
    ) -> None:
        self._camera(camera_id)
        if not isinstance(available, bool):
            raise ValueError("available must be a boolean")
        age = _finite_nonnegative(last_frame_age_seconds, name="last frame age")
        reconnects = _counter_value(reconnects_total, name="reconnect total")
        labels = (self.site_id, camera_id)
        self._camera_available.labels(*labels).set(1 if available else 0)
        self._last_frame_age.labels(*labels).set(age)
        self._apply_snapshot(
            ("reconnect", camera_id),
            reconnects,
            lambda delta: self._reconnects.labels(*labels).inc(delta),
        )

    def update_samples(
        self,
        camera_id: str,
        *,
        module: str,
        scheduled_total: int,
        processed_total: int,
        dropped_total: int,
    ) -> None:
        self._camera(camera_id)
        module = self._module(module)
        totals = {
            "scheduled": _counter_value(scheduled_total, name="scheduled total"),
            "processed": _counter_value(processed_total, name="processed total"),
            "dropped": _counter_value(dropped_total, name="dropped total"),
        }
        if totals["processed"] + totals["dropped"] > totals["scheduled"]:
            raise ValueError("processed and dropped samples cannot exceed scheduled samples")
        self._apply_snapshots(
            [
                (
                    ("sample", camera_id, module, result),
                    total,
                    lambda delta, result=result: self._samples.labels(
                        self.site_id, camera_id, module, result
                    ).inc(delta),
                )
                for result, total in totals.items()
            ]
        )

    def set_queue_age(self, *, queue: str, age_seconds: float) -> None:
        if queue not in _QUEUES:
            raise ValueError("queue is not a configured finite dimension")
        self._queue_age.labels(self.site_id, queue).set(
            _finite_nonnegative(age_seconds, name="queue age")
        )

    def observe_model_latency(
        self,
        *,
        module: str,
        model_artifact_id: str,
        latency_seconds: float,
    ) -> None:
        module = self._module(module)
        if model_artifact_id not in self.model_artifact_ids:
            raise ValueError("model artifact is not configured")
        self._model_latency.labels(self.site_id, module, model_artifact_id).observe(
            _finite_nonnegative(latency_seconds, name="model latency")
        )

    def record_candidate(self, *, module: str) -> None:
        self._candidates.labels(self.site_id, self._module(module)).inc()

    def record_evidence(self, *, result: str, latency_seconds: float | None = None) -> None:
        if result not in _EVIDENCE_RESULTS:
            raise ValueError("evidence result is not a finite state")
        if latency_seconds is not None:
            self._evidence_latency.labels(self.site_id).observe(
                _finite_nonnegative(latency_seconds, name="evidence latency")
            )
        self._evidence_results.labels(self.site_id, result).inc()

    def set_gpu(
        self,
        *,
        utilization_percent: float,
        vram_used_bytes: int,
        vram_capacity_bytes: int,
    ) -> None:
        utilization = _finite_nonnegative(utilization_percent, name="GPU utilization")
        if utilization > 100:
            raise ValueError("GPU utilization must not exceed 100 percent")
        used = _byte_value(vram_used_bytes, name="VRAM used")
        capacity = _byte_value(vram_capacity_bytes, name="VRAM capacity")
        if capacity <= 0 or used > capacity:
            raise ValueError("VRAM use must fit a positive capacity")
        self._gpu_utilization.labels(self.site_id).set(utilization)
        self._vram_bytes.labels(self.site_id, "used").set(used)
        self._vram_bytes.labels(self.site_id, "capacity").set(capacity)

    def set_disk(self, *, used_bytes: int, capacity_bytes: int) -> None:
        used = _byte_value(used_bytes, name="disk used")
        capacity = _byte_value(capacity_bytes, name="disk capacity")
        if capacity <= 0 or used > capacity:
            raise ValueError("disk use must fit a positive capacity")
        self._disk_bytes.labels(self.site_id, "used").set(used)
        self._disk_bytes.labels(self.site_id, "capacity").set(capacity)

    def record_notification(self, *, result: str) -> None:
        if result not in _NOTIFICATION_RESULTS:
            raise ValueError("notification result is not a finite state")
        self._notification_results.labels(self.site_id, result).inc()

    def render(self) -> bytes:
        return generate_latest(self.registry)

    def _apply_snapshot(
        self,
        key: tuple[str, ...],
        value: int,
        increment: Callable[[int], None],
    ) -> None:
        self._apply_snapshots([(key, value, increment)])

    def _apply_snapshots(
        self,
        updates: list[tuple[tuple[str, ...], int, Callable[[int], None]]],
    ) -> None:
        with self._snapshot_lock:
            for key, value, _ in updates:
                if value < self._snapshots.get(key, 0):
                    raise ValueError("cumulative metric snapshot regressed")
            for key, value, increment in updates:
                previous = self._snapshots.get(key, 0)
                if value > previous:
                    increment(value - previous)
                self._snapshots[key] = value

    def _camera(self, camera_id: str) -> None:
        if camera_id not in self.camera_ids:
            raise ValueError("camera is not configured for this pilot site")

    @staticmethod
    def _module(module: str) -> str:
        if module not in _MODULES:
            raise ValueError("module is not a finite configured dimension")
        return module


@dataclass(frozen=True, slots=True)
class HealthProbeSnapshot:
    site_id: str
    camera_states: Mapping[str, CameraState]
    control_plane: ComponentState
    database: ComponentState
    analytics: ComponentState
    evidence: ComponentState
    notifications: ComponentState

    def __post_init__(self) -> None:
        _identifier(self.site_id, name="site_id")
        if any(state not in _CAMERA_STATES for state in self.camera_states.values()):
            raise ValueError("camera state is not finite")
        for value in (
            self.control_plane,
            self.database,
            self.analytics,
            self.evidence,
            self.notifications,
        ):
            if value not in _COMPONENT_STATES:
                raise ValueError("component state is not finite")


class PilotHealthService:
    """Aggregate injected probes without returning camera or provider details."""

    def __init__(
        self,
        *,
        site_id: str,
        camera_ids: Sequence[str],
        probe: Callable[[], HealthProbeSnapshot],
    ) -> None:
        self.site_id = _identifier(site_id, name="site_id")
        configured = tuple(_identifier(item, name="camera_id") for item in camera_ids)
        if len(configured) != 20 or len(set(configured)) != 20:
            raise ValueError("pilot health requires exactly 20 unique configured cameras")
        if not callable(probe):
            raise ValueError("health probe must be callable")
        self.camera_ids = frozenset(configured)
        self._probe = probe

    def liveness(self) -> dict[str, str]:
        try:
            control_plane = self._probe().control_plane
        except Exception:
            control_plane = "failed"
        return {
            "status": "alive" if control_plane != "failed" else "dead",
            "control_plane": control_plane,
        }

    def readiness(self) -> dict[str, object]:
        try:
            snapshot = self._probe()
        except Exception:
            return self._not_ready_probe_failure()
        site_state = "configured" if snapshot.site_id == self.site_id else "mismatch"
        exact_cameras = set(snapshot.camera_states) == self.camera_ids
        if exact_cameras:
            source_state: ComponentState = (
                "healthy"
                if all(state == "online" for state in snapshot.camera_states.values())
                else "degraded"
            )
        else:
            source_state = "failed"
        components: dict[str, ComponentState] = {
            "control_plane": snapshot.control_plane,
            "database": snapshot.database,
            "sources": source_state,
            "analytics": snapshot.analytics,
            "evidence": snapshot.evidence,
            "notifications": snapshot.notifications,
        }
        ready = site_state == "configured" and all(
            state == "healthy" for state in components.values()
        )
        return {
            "status": "ready" if ready else "not_ready",
            "site": site_state,
            "camera_count": len(snapshot.camera_states) if exact_cameras else 0,
            "components": components,
        }

    def _not_ready_probe_failure(self) -> dict[str, object]:
        return {
            "status": "not_ready",
            "site": "unavailable",
            "camera_count": 0,
            "components": {
                "control_plane": "failed",
                "database": "failed",
                "sources": "failed",
                "analytics": "failed",
                "evidence": "failed",
                "notifications": "failed",
            },
        }
