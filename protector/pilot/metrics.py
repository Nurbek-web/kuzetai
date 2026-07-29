"""Low-cardinality pilot metrics and fail-closed component health."""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
_PUBLISHER_COMPONENTS: Mapping[str, frozenset[str]] = {
    "runtime": frozenset({"analytics", "evidence"}),
    "notifications": frozenset({"notifications"}),
}


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
        self._snapshots: dict[tuple[str, ...], tuple[str, int]] = {}
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
        runtime_session_id: str = "legacy",
    ) -> None:
        self._camera(camera_id)
        if not isinstance(available, bool):
            raise ValueError("available must be a boolean")
        age = _finite_nonnegative(last_frame_age_seconds, name="last frame age")
        reconnects = _counter_value(reconnects_total, name="reconnect total")
        runtime_session_id = _identifier(
            runtime_session_id,
            name="runtime_session_id",
        )
        labels = (self.site_id, camera_id)
        self._camera_available.labels(*labels).set(1 if available else 0)
        self._last_frame_age.labels(*labels).set(age)
        self._apply_snapshot(
            ("reconnect", camera_id),
            reconnects,
            lambda delta: self._reconnects.labels(*labels).inc(delta),
            runtime_session_id=runtime_session_id,
        )

    def update_samples(
        self,
        camera_id: str,
        *,
        module: str,
        scheduled_total: int,
        processed_total: int,
        dropped_total: int,
        runtime_session_id: str = "legacy",
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
        runtime_session_id = _identifier(
            runtime_session_id,
            name="runtime_session_id",
        )
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
            ],
            runtime_session_id=runtime_session_id,
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

    def update_candidate_total(
        self,
        *,
        module: str,
        total: int,
        runtime_session_id: str,
    ) -> None:
        module = self._module(module)
        self._apply_snapshot(
            ("candidate", module),
            _counter_value(total, name="candidate total"),
            lambda delta: self._candidates.labels(self.site_id, module).inc(delta),
            runtime_session_id=_identifier(
                runtime_session_id,
                name="runtime_session_id",
            ),
        )

    def record_evidence(self, *, result: str, latency_seconds: float | None = None) -> None:
        if result not in _EVIDENCE_RESULTS:
            raise ValueError("evidence result is not a finite state")
        if latency_seconds is not None:
            self.observe_evidence_latency(latency_seconds)
        self._evidence_results.labels(self.site_id, result).inc()

    def observe_evidence_latency(self, latency_seconds: float) -> None:
        self._evidence_latency.labels(self.site_id).observe(
            _finite_nonnegative(latency_seconds, name="evidence latency")
        )

    def update_evidence_total(
        self,
        *,
        result: str,
        total: int,
        runtime_session_id: str,
    ) -> None:
        if result not in _EVIDENCE_RESULTS:
            raise ValueError("evidence result is not a finite state")
        self._apply_snapshot(
            ("evidence", result),
            _counter_value(total, name="evidence total"),
            lambda delta: self._evidence_results.labels(self.site_id, result).inc(delta),
            runtime_session_id=_identifier(
                runtime_session_id,
                name="runtime_session_id",
            ),
        )

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

    def update_notification_total(
        self,
        *,
        result: str,
        total: int,
        runtime_session_id: str,
    ) -> None:
        if result not in _NOTIFICATION_RESULTS:
            raise ValueError("notification result is not a finite state")
        self._apply_snapshot(
            ("notification", result),
            _counter_value(total, name="notification total"),
            lambda delta: self._notification_results.labels(self.site_id, result).inc(delta),
            runtime_session_id=_identifier(
                runtime_session_id,
                name="runtime_session_id",
            ),
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)

    def validate_snapshot_values(
        self,
        updates: Sequence[tuple[tuple[str, ...], int]],
        *,
        runtime_session_id: str,
    ) -> None:
        runtime_session_id = _identifier(
            runtime_session_id,
            name="runtime_session_id",
        )
        normalized = [
            (key, _counter_value(value, name="metric snapshot"))
            for key, value in updates
        ]
        if len({key for key, _ in normalized}) != len(normalized):
            raise ValueError("metric snapshot keys must be unique")
        with self._snapshot_lock:
            self._validate_snapshots_locked(normalized, runtime_session_id)

    def _apply_snapshot(
        self,
        key: tuple[str, ...],
        value: int,
        increment: Callable[[int], None],
        *,
        runtime_session_id: str = "legacy",
    ) -> None:
        self._apply_snapshots(
            [(key, value, increment)],
            runtime_session_id=runtime_session_id,
        )

    def _apply_snapshots(
        self,
        updates: list[tuple[tuple[str, ...], int, Callable[[int], None]]],
        *,
        runtime_session_id: str = "legacy",
    ) -> None:
        with self._snapshot_lock:
            self._validate_snapshots_locked(
                [(key, value) for key, value, _ in updates],
                runtime_session_id,
            )
            for key, value, increment in updates:
                previous_session, previous_value = self._snapshots.get(
                    key,
                    (runtime_session_id, 0),
                )
                delta = value if previous_session != runtime_session_id else value - previous_value
                if delta:
                    increment(delta)
                self._snapshots[key] = (runtime_session_id, value)

    def _validate_snapshots_locked(
        self,
        updates: Sequence[tuple[tuple[str, ...], int]],
        runtime_session_id: str,
    ) -> None:
        for key, value in updates:
            previous_session, previous_value = self._snapshots.get(
                key,
                (runtime_session_id, 0),
            )
            if previous_session == runtime_session_id and value < previous_value:
                raise ValueError("cumulative metric snapshot regressed")

    def _camera(self, camera_id: str) -> None:
        if camera_id not in self.camera_ids:
            raise ValueError("camera is not configured for this pilot site")

    @staticmethod
    def _module(module: str) -> str:
        if module not in _MODULES:
            raise ValueError("module is not a finite configured dimension")
        return module


class PilotTelemetryState:
    """Own fresh component states and serialize idempotent publisher updates."""

    def __init__(
        self,
        *,
        site_id: str,
        stale_after_seconds: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.site_id = _identifier(site_id, name="site_id")
        if (
            not isinstance(stale_after_seconds, int)
            or isinstance(stale_after_seconds, bool)
            or not 1 <= stale_after_seconds <= 300
        ):
            raise ValueError("telemetry stale threshold must be between 1 and 300 seconds")
        if clock is not None and not callable(clock):
            raise ValueError("telemetry clock must be callable")
        self._stale_after = timedelta(seconds=stale_after_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._publisher_positions: dict[str, tuple[str, int, datetime, str]] = {}
        self._components: dict[str, tuple[ComponentState, datetime]] = {}
        self._lock = threading.Lock()

    def apply(
        self,
        *,
        publisher: str,
        runtime_session_id: str,
        sequence: int,
        observed_at: datetime,
        components: Mapping[str, ComponentState],
        payload_digest: str,
        update: Callable[[], None],
        authorize: Callable[[], bool] | None = None,
    ) -> bool:
        required_components = _PUBLISHER_COMPONENTS.get(publisher)
        if required_components is None:
            raise ValueError("telemetry publisher is not configured")
        runtime_session_id = _identifier(
            runtime_session_id,
            name="runtime_session_id",
        )
        sequence = _counter_value(sequence, name="telemetry sequence")
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("telemetry timestamp must be UTC-aware")
        observed_at = observed_at.astimezone(UTC)
        current = self._clock()
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("telemetry clock must be UTC-aware")
        current = current.astimezone(UTC)
        age = current - observed_at
        if age < timedelta(0) or age > self._stale_after:
            raise ValueError("telemetry sample is outside the freshness window")
        if set(components) != required_components:
            raise ValueError("publisher must report its exact owned component set")
        if any(state not in _COMPONENT_STATES for state in components.values()):
            raise ValueError("component state is not finite")
        if not callable(update):
            raise ValueError("telemetry update must be callable")
        if authorize is not None and not callable(authorize):
            raise ValueError("telemetry authority must be callable")
        if len(payload_digest) != 64 or any(
            character not in "0123456789abcdef" for character in payload_digest
        ):
            raise ValueError("telemetry payload digest must be hexadecimal SHA-256")

        with self._lock:
            if authorize is not None and not authorize():
                return False
            previous = self._publisher_positions.get(publisher)
            if previous is not None:
                (
                    previous_session,
                    previous_sequence,
                    previous_observed_at,
                    previous_digest,
                ) = previous
                if previous_session == runtime_session_id:
                    if sequence == previous_sequence:
                        if payload_digest != previous_digest:
                            raise ValueError("telemetry sequence was replayed with a different body")
                        return False
                    if sequence < previous_sequence or observed_at < previous_observed_at:
                        raise ValueError("telemetry sequence regressed")
                elif observed_at < previous_observed_at:
                    raise ValueError("telemetry session timestamp regressed")
            update()
            self._publisher_positions[publisher] = (
                runtime_session_id,
                sequence,
                observed_at,
                payload_digest,
            )
            for name, state in components.items():
                self._components[name] = (state, observed_at)
        return True

    def component_states(self) -> dict[str, ComponentState]:
        current = self._clock()
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("telemetry clock must be UTC-aware")
        current = current.astimezone(UTC)
        with self._lock:
            result: dict[str, ComponentState] = {}
            for name in ("analytics", "evidence", "notifications"):
                sample = self._components.get(name)
                if sample is None:
                    result[name] = "failed"
                    continue
                state, observed_at = sample
                age = current - observed_at
                result[name] = (
                    state if timedelta(0) <= age <= self._stale_after else "failed"
                )
            return result


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
