"""Finite shared scheduling for conditional and shadow analytics."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Annotated, Literal

from pydantic import Field, field_validator

from protector.pilot.config import FrozenModel, NonEmptyString
from protector.pilot.gates import ConditionalModelGateResultV1

NormalizedBox = tuple[
    Annotated[float, Field(ge=0, le=1)],
    Annotated[float, Field(ge=0, le=1)],
    Annotated[float, Field(ge=0, le=1)],
    Annotated[float, Field(ge=0, le=1)],
]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("source_time must be UTC-aware")
    return value.astimezone(timezone.utc)


def _valid_box(value: NormalizedBox) -> NormalizedBox:
    if value[0] >= value[2] or value[1] >= value[3]:
        raise ValueError("ROI must have positive normalized area")
    return value


class ConditionalWorkItemV1(FrozenModel):
    schema_version: Literal["conditional-work-item.v1"] = "conditional-work-item.v1"
    work_id: NonEmptyString
    camera_id: NonEmptyString
    module: Literal["fire_smoke", "weapon"]
    source_time: datetime
    roi: NormalizedBox | None
    priority: Literal["full_frame", "full_frame_fallback", "person_roi"]
    artifact_id: NonEmptyString
    gate_mode: Literal["shadow", "operator"] = "shadow"

    @field_validator("source_time")
    @classmethod
    def source_time_is_utc(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("roi")
    @classmethod
    def roi_is_valid(cls, value: NormalizedBox | None) -> NormalizedBox | None:
        return None if value is None else _valid_box(value)


class VerifierCandidateV1(FrozenModel):
    schema_version: Literal["verifier-candidate.v1"] = "verifier-candidate.v1"
    candidate_id: NonEmptyString
    camera_id: NonEmptyString
    source_time: datetime
    confidence: Annotated[float, Field(ge=0, le=1)]
    roi: NormalizedBox
    detector_artifact_id: NonEmptyString

    @field_validator("source_time")
    @classmethod
    def source_time_is_utc(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("roi")
    @classmethod
    def roi_is_valid(cls, value: NormalizedBox) -> NormalizedBox:
        return _valid_box(value)


class VerifierWorkItemV1(FrozenModel):
    schema_version: Literal["verifier-work-item.v1"] = "verifier-work-item.v1"
    candidate_id: NonEmptyString
    camera_id: NonEmptyString
    source_time: datetime
    confidence: Annotated[float, Field(ge=0, le=1)]
    roi: NormalizedBox
    detector_artifact_id: NonEmptyString
    verifier_artifact_id: NonEmptyString
    gate_mode: Literal["shadow"] = "shadow"

    @field_validator("source_time")
    @classmethod
    def source_time_is_utc(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("roi")
    @classmethod
    def roi_is_valid(cls, value: NormalizedBox) -> NormalizedBox:
        return _valid_box(value)


class ShadowWorkItemV1(FrozenModel):
    schema_version: Literal["shadow-work-item.v1"] = "shadow-work-item.v1"
    sample_id: NonEmptyString
    camera_id: NonEmptyString
    source_time: datetime
    module: Literal["fight", "fall"]
    artifact_id: NonEmptyString
    gate_mode: Literal["shadow"] = "shadow"

    @field_validator("source_time")
    @classmethod
    def source_time_is_utc(cls, value: datetime) -> datetime:
        return _utc(value)


@dataclass(frozen=True)
class ConditionalSchedulerMetrics:
    scheduled_total: int
    scheduled_overflow_dropped_total: int
    verifier_enqueued_total: int
    verifier_weak_suppressed_total: int
    verifier_overflow_dropped_total: int
    shadow_enqueued_total: int
    shadow_overflow_dropped_total: int
    regressing_source_time_dropped_total: int
    camera_state_overflow_dropped_total: int
    disabled_work_suppressed_total: int
    person_roi_overflow_dropped_total: int


@dataclass
class _CameraScheduleState:
    last_source_time: datetime
    fire_last_scheduled: datetime | None = None
    weapon_last_scheduled: datetime | None = None


class ConditionalAnalyticsScheduler:
    """One shared finite scheduler; it never owns or launches per-camera model stacks."""

    def __init__(
        self,
        *,
        fire_artifact_id: str,
        weapon_artifact_id: str,
        verifier_artifact_id: str,
        queue_capacity: int,
        verifier_queue_capacity: int,
        verifier_trigger_confidence: float = 0.8,
        fire_hz: float = 1.0,
        weapon_hz: float = 1.0,
        max_camera_states: int = 20,
        shadow_artifacts: dict[str, str] | None = None,
        shadow_queue_capacity: int = 4,
        fire_gate: ConditionalModelGateResultV1 | None = None,
        weapon_gate: ConditionalModelGateResultV1 | None = None,
        verifier_gate: ConditionalModelGateResultV1 | None = None,
        max_person_rois_per_sample: int = 64,
    ) -> None:
        if queue_capacity <= 0 or verifier_queue_capacity <= 0 or shadow_queue_capacity <= 0:
            raise ValueError("conditional queues must be bounded by positive capacities")
        if not 0 < fire_hz <= 2 or not 0 < weapon_hz <= 2:
            raise ValueError("conditional analytics frequencies must be finite and near 1 Hz")
        if not 0 <= verifier_trigger_confidence <= 1:
            raise ValueError("verifier trigger confidence must be normalized")
        if not 1 <= max_camera_states <= 20:
            raise ValueError("camera state bound must be between 1 and 20")
        if not 1 <= max_person_rois_per_sample <= 256:
            raise ValueError("person ROI fanout bound must be between 1 and 256")
        artifacts = {fire_artifact_id, weapon_artifact_id, verifier_artifact_id}
        if len(artifacts) != 3:
            raise ValueError("detector and verifier require separate artifact IDs")
        configured_shadow = dict(shadow_artifacts or {})
        if not set(configured_shadow).issubset({"fight", "fall"}):
            raise ValueError("only fight and fall may use these shadow queues")
        if any(artifact in artifacts for artifact in configured_shadow.values()):
            raise ValueError("shadow experiments require a separate artifact ID")
        if len(set(configured_shadow.values())) != len(configured_shadow):
            raise ValueError("shadow experiments require separate artifact IDs")

        self._artifact_ids = {"fire_smoke": fire_artifact_id, "weapon": weapon_artifact_id}
        self._verifier_artifact_id = verifier_artifact_id
        self._validate_gate_binding(
            fire_gate, module="fire_smoke", artifact_id=fire_artifact_id
        )
        self._validate_gate_binding(
            weapon_gate, module="weapon", artifact_id=weapon_artifact_id
        )
        self._validate_gate_binding(
            verifier_gate, module="weapon", artifact_id=verifier_artifact_id
        )
        self._gates = {
            "fire_smoke": fire_gate,
            "weapon": weapon_gate,
            "verifier": verifier_gate,
        }
        self._queue_capacity = queue_capacity
        self._verifier_queue_capacity = verifier_queue_capacity
        self._verifier_trigger_confidence = verifier_trigger_confidence
        self._intervals = {
            "fire_smoke": 1.0 / fire_hz,
            "weapon": 1.0 / weapon_hz,
        }
        self._max_camera_states = max_camera_states
        self._max_person_rois_per_sample = max_person_rois_per_sample
        self._shadow_artifacts = configured_shadow
        self._shadow_queue_capacity = shadow_queue_capacity
        self._queues: dict[str, deque[ConditionalWorkItemV1]] = {
            "fire_smoke": deque(),
            "weapon": deque(),
        }
        self._verifier_queue: deque[VerifierWorkItemV1] = deque()
        self._shadow_queues: dict[str, deque[ShadowWorkItemV1]] = {
            module: deque() for module in configured_shadow
        }
        self._camera_states: dict[str, _CameraScheduleState] = {}
        self._lock = Lock()
        self._scheduled_total = 0
        self._scheduled_overflow_dropped_total = 0
        self._verifier_enqueued_total = 0
        self._verifier_weak_suppressed_total = 0
        self._verifier_overflow_dropped_total = 0
        self._shadow_enqueued_total = 0
        self._shadow_overflow_dropped_total = 0
        self._regressing_source_time_dropped_total = 0
        self._camera_state_overflow_dropped_total = 0
        self._disabled_work_suppressed_total = 0
        self._person_roi_overflow_dropped_total = 0

    @property
    def camera_state_count(self) -> int:
        with self._lock:
            return len(self._camera_states)

    @staticmethod
    def _validate_gate_binding(
        gate: ConditionalModelGateResultV1 | None,
        *,
        module: str,
        artifact_id: str,
    ) -> None:
        if gate is not None and (
            gate.module != module or gate.artifact_id != artifact_id
        ):
            raise ValueError("conditional gate binding does not match scheduled artifact")

    def _gate_mode(
        self, name: Literal["fire_smoke", "weapon", "verifier"]
    ) -> Literal["disabled", "shadow", "operator"]:
        gate = self._gates[name]
        return "disabled" if gate is None else gate.mode

    def schedule_due(
        self,
        *,
        camera_id: str,
        source_time: datetime,
        person_rois: tuple[NormalizedBox, ...],
    ) -> None:
        if not camera_id.strip():
            raise ValueError("camera_id must not be empty")
        normalized_time = _utc(source_time)
        selected_rois = person_rois[: self._max_person_rois_per_sample]
        normalized_rois = tuple(_valid_box(roi) for roi in selected_rois)
        overflow_rois = len(person_rois) - len(selected_rois)
        with self._lock:
            self._person_roi_overflow_dropped_total += overflow_rois
            state = self._camera_states.get(camera_id)
            if state is None:
                if len(self._camera_states) >= self._max_camera_states:
                    self._camera_state_overflow_dropped_total += 1
                    return
                state = _CameraScheduleState(last_source_time=normalized_time)
                self._camera_states[camera_id] = state
            elif normalized_time < state.last_source_time:
                self._regressing_source_time_dropped_total += 1
                return
            else:
                state.last_source_time = normalized_time

            fire_gate_mode = self._gate_mode("fire_smoke")
            if fire_gate_mode == "disabled":
                self._disabled_work_suppressed_total += 1
            elif self._is_due(state.fire_last_scheduled, normalized_time, "fire_smoke"):
                work = ConditionalWorkItemV1(
                    work_id=f"{camera_id}:fire_smoke:{normalized_time.isoformat()}",
                    camera_id=camera_id,
                    module="fire_smoke",
                    source_time=normalized_time,
                    roi=None,
                    priority="full_frame",
                    artifact_id=self._artifact_ids["fire_smoke"],
                    gate_mode=fire_gate_mode,
                )
                self._enqueue_scheduled(work)
                state.fire_last_scheduled = normalized_time

            weapon_gate_mode = self._gate_mode("weapon")
            if weapon_gate_mode == "disabled":
                self._disabled_work_suppressed_total += 1
            elif self._is_due(state.weapon_last_scheduled, normalized_time, "weapon"):
                rois: tuple[NormalizedBox | None, ...] = normalized_rois or (None,)
                for index, roi in enumerate(rois):
                    work = ConditionalWorkItemV1(
                        work_id=f"{camera_id}:weapon:{normalized_time.isoformat()}:{index}",
                        camera_id=camera_id,
                        module="weapon",
                        source_time=normalized_time,
                        roi=roi,
                        priority="person_roi" if roi is not None else "full_frame_fallback",
                        artifact_id=self._artifact_ids["weapon"],
                        gate_mode=weapon_gate_mode,
                    )
                    self._enqueue_scheduled(work)
                state.weapon_last_scheduled = normalized_time

    def _is_due(
        self,
        previous: datetime | None,
        current: datetime,
        module: Literal["fire_smoke", "weapon"],
    ) -> bool:
        return previous is None or (current - previous).total_seconds() >= self._intervals[module]

    def _enqueue_scheduled(self, item: ConditionalWorkItemV1) -> None:
        queue = self._queues[item.module]
        if len(queue) >= self._queue_capacity:
            self._scheduled_overflow_dropped_total += 1
            return
        queue.append(item)
        self._scheduled_total += 1

    def drain(
        self, module: Literal["fire_smoke", "weapon"], *, limit: int
    ) -> tuple[ConditionalWorkItemV1, ...]:
        if limit <= 0:
            return ()
        with self._lock:
            queue = self._queues[module]
            items = tuple(queue.popleft() for _ in range(min(limit, len(queue))))
        return items

    def submit_verifier(self, candidate: VerifierCandidateV1) -> bool:
        if candidate.detector_artifact_id != self._artifact_ids["weapon"]:
            raise ValueError("verifier candidate does not match the weapon detector artifact")
        with self._lock:
            if (
                self._gate_mode("weapon") == "disabled"
                or self._gate_mode("verifier") == "disabled"
            ):
                self._disabled_work_suppressed_total += 1
                return False
            if candidate.confidence < self._verifier_trigger_confidence:
                self._verifier_weak_suppressed_total += 1
                return False
            if len(self._verifier_queue) >= self._verifier_queue_capacity:
                self._verifier_overflow_dropped_total += 1
                return False
            self._verifier_queue.append(
                VerifierWorkItemV1(
                    candidate_id=candidate.candidate_id,
                    camera_id=candidate.camera_id,
                    source_time=candidate.source_time,
                    confidence=candidate.confidence,
                    roi=candidate.roi,
                    detector_artifact_id=candidate.detector_artifact_id,
                    verifier_artifact_id=self._verifier_artifact_id,
                )
            )
            self._verifier_enqueued_total += 1
            return True

    def drain_verifier(self, *, limit: int) -> tuple[VerifierWorkItemV1, ...]:
        if limit <= 0:
            return ()
        with self._lock:
            items = tuple(
                self._verifier_queue.popleft()
                for _ in range(min(limit, len(self._verifier_queue)))
            )
        return items

    def submit_shadow(
        self,
        *,
        module: Literal["fight", "fall"],
        sample_id: str,
        camera_id: str,
        source_time: datetime,
    ) -> bool:
        artifact_id = self._shadow_artifacts.get(module)
        if artifact_id is None:
            raise ValueError(f"{module} shadow experiment is not configured")
        item = ShadowWorkItemV1(
            sample_id=sample_id,
            camera_id=camera_id,
            source_time=source_time,
            module=module,
            artifact_id=artifact_id,
        )
        with self._lock:
            queue = self._shadow_queues[module]
            if len(queue) >= self._shadow_queue_capacity:
                self._shadow_overflow_dropped_total += 1
                return False
            queue.append(item)
            self._shadow_enqueued_total += 1
            return True

    def drain_shadow(
        self, module: Literal["fight", "fall"], *, limit: int
    ) -> tuple[ShadowWorkItemV1, ...]:
        if limit <= 0:
            return ()
        with self._lock:
            queue = self._shadow_queues.get(module)
            if queue is None:
                raise ValueError(f"{module} shadow experiment is not configured")
            items = tuple(queue.popleft() for _ in range(min(limit, len(queue))))
        return items

    def metrics(self) -> ConditionalSchedulerMetrics:
        with self._lock:
            return ConditionalSchedulerMetrics(
                scheduled_total=self._scheduled_total,
                scheduled_overflow_dropped_total=self._scheduled_overflow_dropped_total,
                verifier_enqueued_total=self._verifier_enqueued_total,
                verifier_weak_suppressed_total=self._verifier_weak_suppressed_total,
                verifier_overflow_dropped_total=self._verifier_overflow_dropped_total,
                shadow_enqueued_total=self._shadow_enqueued_total,
                shadow_overflow_dropped_total=self._shadow_overflow_dropped_total,
                regressing_source_time_dropped_total=self._regressing_source_time_dropped_total,
                camera_state_overflow_dropped_total=self._camera_state_overflow_dropped_total,
                disabled_work_suppressed_total=self._disabled_work_suppressed_total,
                person_roi_overflow_dropped_total=self._person_roi_overflow_dropped_total,
            )


__all__ = [
    "ConditionalAnalyticsScheduler",
    "ConditionalSchedulerMetrics",
    "ConditionalWorkItemV1",
    "ShadowWorkItemV1",
    "VerifierCandidateV1",
    "VerifierWorkItemV1",
]
