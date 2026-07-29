"""Finite shared scheduling for conditional and shadow analytics."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from protector.pilot.config import FrozenModel, NonEmptyString
from protector.pilot.gates import (
    ExpectedConditionalWorkloadV1,
    MeasuredCapacityReportV1,
    ShadowStageEvidenceV1,
    SignedSiteMatrixV1,
)
from protector.pilot.model_registry import (
    ModelRegistryEntryV1,
    evaluate_conditional_promotion,
)

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
    artifact_sha256: str
    site_id: NonEmptyString
    site_config_sha256: str
    expected_workload_sha256: str
    registry_entry_sha256: str
    engine_sha256: str
    target_gpu_architecture: NonEmptyString
    target_compute_capability: NonEmptyString
    tensorrt_version: NonEmptyString
    decision_sha256: str
    verification_boundary: Literal["human_confirmation", "bounded_shadow_verifier"]
    gate_mode: Literal["shadow", "operator"] = "shadow"

    @field_validator(
        "artifact_sha256",
        "site_config_sha256",
        "expected_workload_sha256",
        "registry_entry_sha256",
        "engine_sha256",
        "decision_sha256",
    )
    @classmethod
    def hashes_are_digests(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("conditional work bindings must be sha256 digests")
        return value

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
    site_id: NonEmptyString
    site_config_sha256: str
    detector_expected_workload_sha256: str
    verifier_expected_workload_sha256: str
    detector_registry_entry_sha256: str
    detector_artifact_sha256: str
    detector_engine_sha256: str
    detector_decision_sha256: str
    verifier_registry_entry_sha256: str
    verifier_artifact_sha256: str
    verifier_engine_sha256: str
    verifier_decision_sha256: str
    target_gpu_architecture: NonEmptyString
    target_compute_capability: NonEmptyString
    tensorrt_version: NonEmptyString
    verification_boundary: Literal["bounded_shadow_verifier"] = (
        "bounded_shadow_verifier"
    )
    gate_mode: Literal["shadow"] = "shadow"

    @field_validator(
        "site_config_sha256",
        "detector_expected_workload_sha256",
        "verifier_expected_workload_sha256",
        "detector_registry_entry_sha256",
        "detector_artifact_sha256",
        "detector_engine_sha256",
        "detector_decision_sha256",
        "verifier_registry_entry_sha256",
        "verifier_artifact_sha256",
        "verifier_engine_sha256",
        "verifier_decision_sha256",
    )
    @classmethod
    def hashes_are_digests(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("verifier work bindings must be sha256 digests")
        return value

    @field_validator("source_time")
    @classmethod
    def source_time_is_utc(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("roi")
    @classmethod
    def roi_is_valid(cls, value: NormalizedBox) -> NormalizedBox:
        return _valid_box(value)


class ConditionalDeploymentV1(FrozenModel):
    """Exact registry and signed evidence evaluated by the scheduler itself."""

    schema_version: Literal["conditional-deployment.v1"] = "conditional-deployment.v1"
    entry: ModelRegistryEntryV1
    site_matrix: SignedSiteMatrixV1 | None = None
    shadow_stage: ShadowStageEvidenceV1 | None = None
    capacity_report: MeasuredCapacityReportV1 | None = None
    expected_workload: ExpectedConditionalWorkloadV1
    verification_boundary: Literal["human_confirmation", "bounded_shadow_verifier"]

    @model_validator(mode="after")
    def boundary_matches_module(self) -> ConditionalDeploymentV1:
        if self.entry.module == "fire_smoke" and self.verification_boundary != "human_confirmation":
            raise ValueError("fire deployment requires the human-confirmation boundary")
        if self.entry.module not in {"fire_smoke", "weapon"}:
            raise ValueError("conditional deployment supports only fire and weapon")
        return self


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


@dataclass(frozen=True)
class _EvaluatedDeployment:
    deployment: ConditionalDeploymentV1
    mode: Literal["disabled", "shadow", "operator"]
    decision_sha256: str


class ConditionalAnalyticsScheduler:
    """One shared finite scheduler; it never owns or launches per-camera model stacks."""

    def __init__(
        self,
        *,
        queue_capacity: int,
        verifier_queue_capacity: int,
        verifier_trigger_confidence: float = 0.8,
        max_camera_states: int = 20,
        shadow_artifacts: dict[str, str] | None = None,
        shadow_queue_capacity: int = 4,
        fire_deployment: ConditionalDeploymentV1 | None = None,
        weapon_deployment: ConditionalDeploymentV1 | None = None,
        verifier_deployment: ConditionalDeploymentV1 | None = None,
        max_person_rois_per_sample: int = 64,
    ) -> None:
        if queue_capacity <= 0 or verifier_queue_capacity <= 0 or shadow_queue_capacity <= 0:
            raise ValueError("conditional queues must be bounded by positive capacities")
        if not 0 <= verifier_trigger_confidence <= 1:
            raise ValueError("verifier trigger confidence must be normalized")
        if not 1 <= max_camera_states <= 20:
            raise ValueError("camera state bound must be between 1 and 20")
        if not 1 <= max_person_rois_per_sample <= 256:
            raise ValueError("person ROI fanout bound must be between 1 and 256")
        self._validate_deployment_module(fire_deployment, "fire_smoke")
        self._validate_deployment_module(weapon_deployment, "weapon")
        self._validate_deployment_module(verifier_deployment, "weapon")
        configured_deployments = tuple(
            deployment
            for deployment in (
                fire_deployment,
                weapon_deployment,
                verifier_deployment,
            )
            if deployment is not None
        )
        artifact_ids = {
            deployment.entry.artifact_id for deployment in configured_deployments
        }
        if len(artifact_ids) != len(configured_deployments):
            raise ValueError("detector and verifier require separate artifact IDs")
        configured_shadow = dict(shadow_artifacts or {})
        if not set(configured_shadow).issubset({"fight", "fall"}):
            raise ValueError("only fight and fall may use these shadow queues")
        if any(
            artifact in artifact_ids for artifact in configured_shadow.values()
        ):
            raise ValueError("shadow experiments require a separate artifact ID")
        if len(set(configured_shadow.values())) != len(configured_shadow):
            raise ValueError("shadow experiments require separate artifact IDs")

        self._deployments = {
            "fire_smoke": self._evaluate_deployment(fire_deployment),
            "weapon": self._evaluate_deployment(weapon_deployment),
            "verifier": self._evaluate_deployment(verifier_deployment),
        }
        authority = self._deployments["fire_smoke"] or self._deployments["weapon"]
        if authority is not None:
            authority_site_id = authority.deployment.entry.site_id
            authority_config_sha256 = (
                authority.deployment.expected_workload.site_config_sha256
            )
            for module in ("fire_smoke", "weapon"):
                evaluated = self._deployments[module]
                if evaluated is not None and (
                    evaluated.deployment.entry.site_id != authority_site_id
                    or evaluated.deployment.expected_workload.site_config_sha256
                    != authority_config_sha256
                ):
                    self._deployments[module] = None
        detector = self._deployments["weapon"]
        verifier = self._deployments["verifier"]
        if (
            verifier is not None
            and verifier.deployment.verification_boundary
            != "bounded_shadow_verifier"
        ):
            self._deployments["verifier"] = None
        elif (
            detector is not None
            and verifier is not None
            and (
                detector.deployment.entry.site_id
                != verifier.deployment.entry.site_id
                or detector.deployment.expected_workload.site_config_sha256
                != verifier.deployment.expected_workload.site_config_sha256
            )
        ):
            self._deployments["verifier"] = None
        self._queue_capacity = queue_capacity
        self._verifier_queue_capacity = verifier_queue_capacity
        self._verifier_trigger_confidence = verifier_trigger_confidence
        self._intervals = self._build_intervals()
        self._weapon_inference_fanout = self._build_weapon_inference_fanout()
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
    def _validate_deployment_module(
        deployment: ConditionalDeploymentV1 | None,
        module: Literal["fire_smoke", "weapon"],
    ) -> None:
        if deployment is not None and deployment.entry.module != module:
            raise ValueError("conditional deployment module does not match queue")

    @staticmethod
    def _evaluate_deployment(
        deployment: ConditionalDeploymentV1 | None,
    ) -> _EvaluatedDeployment | None:
        if deployment is None:
            return None
        decision = evaluate_conditional_promotion(
            deployment.entry,
            site_matrix=deployment.site_matrix,
            shadow_stage=deployment.shadow_stage,
            capacity_report=deployment.capacity_report,
            expected_workload=deployment.expected_workload,
        )
        return _EvaluatedDeployment(
            deployment=deployment,
            mode=decision.mode,
            decision_sha256=decision.decision_sha256,
        )

    def _build_intervals(self) -> dict[str, dict[str, float]]:
        intervals: dict[str, dict[str, float]] = {
            "fire_smoke": {},
            "weapon": {},
        }
        for module in ("fire_smoke", "weapon"):
            evaluated = self._deployments[module]
            if evaluated is None:
                continue
            intervals[module] = {
                camera.camera_id: 1.0 / camera.analytics_hz
                for camera in evaluated.deployment.expected_workload.cameras
            }
        return intervals

    def _build_weapon_inference_fanout(self) -> dict[str, int]:
        evaluated = self._deployments["weapon"]
        if evaluated is None:
            return {}
        return {
            camera.camera_id: camera.inferences_per_sample
            for camera in evaluated.deployment.expected_workload.cameras
        }

    def _gate_mode(
        self, name: Literal["fire_smoke", "weapon", "verifier"]
    ) -> Literal["disabled", "shadow", "operator"]:
        deployment = self._deployments[name]
        return "disabled" if deployment is None else deployment.mode

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
        configured_fanout = self._weapon_inference_fanout.get(
            camera_id,
            self._max_person_rois_per_sample,
        )
        roi_limit = min(configured_fanout, self._max_person_rois_per_sample)
        selected_rois = person_rois[:roi_limit]
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
            elif self._is_due(
                state.fire_last_scheduled,
                normalized_time,
                "fire_smoke",
                camera_id,
            ):
                work = self._conditional_work_item(
                    work_id=f"{camera_id}:fire_smoke:{normalized_time.isoformat()}",
                    camera_id=camera_id,
                    module="fire_smoke",
                    source_time=normalized_time,
                    roi=None,
                    priority="full_frame",
                )
                self._enqueue_scheduled(work)
                state.fire_last_scheduled = normalized_time

            weapon_gate_mode = self._gate_mode("weapon")
            if weapon_gate_mode == "disabled":
                self._disabled_work_suppressed_total += 1
            elif self._is_due(
                state.weapon_last_scheduled,
                normalized_time,
                "weapon",
                camera_id,
            ):
                rois: tuple[NormalizedBox | None, ...] = normalized_rois or (None,)
                for index, roi in enumerate(rois):
                    work = self._conditional_work_item(
                        work_id=f"{camera_id}:weapon:{normalized_time.isoformat()}:{index}",
                        camera_id=camera_id,
                        module="weapon",
                        source_time=normalized_time,
                        roi=roi,
                        priority="person_roi" if roi is not None else "full_frame_fallback",
                    )
                    self._enqueue_scheduled(work)
                state.weapon_last_scheduled = normalized_time

    def _is_due(
        self,
        previous: datetime | None,
        current: datetime,
        module: Literal["fire_smoke", "weapon"],
        camera_id: str,
    ) -> bool:
        interval = self._intervals[module].get(camera_id)
        return interval is not None and (
            previous is None or (current - previous).total_seconds() >= interval
        )

    def _conditional_work_item(
        self,
        *,
        work_id: str,
        camera_id: str,
        module: Literal["fire_smoke", "weapon"],
        source_time: datetime,
        roi: NormalizedBox | None,
        priority: Literal["full_frame", "full_frame_fallback", "person_roi"],
    ) -> ConditionalWorkItemV1:
        evaluated = self._deployments[module]
        assert evaluated is not None and evaluated.mode != "disabled"
        deployment = evaluated.deployment
        entry = deployment.entry
        engine = entry.engine
        assert entry.artifact_sha256 is not None
        assert engine is not None and engine.engine_sha256 is not None
        return ConditionalWorkItemV1(
            work_id=work_id,
            camera_id=camera_id,
            module=module,
            source_time=source_time,
            roi=roi,
            priority=priority,
            artifact_id=entry.artifact_id,
            artifact_sha256=entry.artifact_sha256,
            site_id=entry.site_id,
            site_config_sha256=deployment.expected_workload.site_config_sha256,
            expected_workload_sha256=(
                deployment.expected_workload.expected_workload_sha256
            ),
            registry_entry_sha256=entry.registry_entry_sha256,
            engine_sha256=engine.engine_sha256,
            target_gpu_architecture=engine.target_gpu_architecture,
            target_compute_capability=engine.target_compute_capability,
            tensorrt_version=engine.tensorrt_version,
            decision_sha256=evaluated.decision_sha256,
            verification_boundary=deployment.verification_boundary,
            gate_mode=evaluated.mode,
        )

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
        detector = self._deployments["weapon"]
        verifier = self._deployments["verifier"]
        if detector is None:
            with self._lock:
                self._disabled_work_suppressed_total += 1
            return False
        if candidate.detector_artifact_id != detector.deployment.entry.artifact_id:
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
            assert verifier is not None
            detector_entry = detector.deployment.entry
            verifier_entry = verifier.deployment.entry
            detector_engine = detector_entry.engine
            verifier_engine = verifier_entry.engine
            assert detector_entry.artifact_sha256 is not None
            assert verifier_entry.artifact_sha256 is not None
            assert detector_engine is not None
            assert detector_engine.engine_sha256 is not None
            assert verifier_engine is not None
            assert verifier_engine.engine_sha256 is not None
            self._verifier_queue.append(
                VerifierWorkItemV1(
                    candidate_id=candidate.candidate_id,
                    camera_id=candidate.camera_id,
                    source_time=candidate.source_time,
                    confidence=candidate.confidence,
                    roi=candidate.roi,
                    detector_artifact_id=candidate.detector_artifact_id,
                    verifier_artifact_id=verifier_entry.artifact_id,
                    site_id=detector_entry.site_id,
                    site_config_sha256=(
                        detector.deployment.expected_workload.site_config_sha256
                    ),
                    detector_expected_workload_sha256=(
                        detector.deployment.expected_workload.expected_workload_sha256
                    ),
                    verifier_expected_workload_sha256=(
                        verifier.deployment.expected_workload.expected_workload_sha256
                    ),
                    detector_registry_entry_sha256=(
                        detector_entry.registry_entry_sha256
                    ),
                    detector_artifact_sha256=detector_entry.artifact_sha256,
                    detector_engine_sha256=detector_engine.engine_sha256,
                    detector_decision_sha256=detector.decision_sha256,
                    verifier_registry_entry_sha256=(
                        verifier_entry.registry_entry_sha256
                    ),
                    verifier_artifact_sha256=verifier_entry.artifact_sha256,
                    verifier_engine_sha256=verifier_engine.engine_sha256,
                    verifier_decision_sha256=verifier.decision_sha256,
                    target_gpu_architecture=(
                        verifier_engine.target_gpu_architecture
                    ),
                    target_compute_capability=(
                        verifier_engine.target_compute_capability
                    ),
                    tensorrt_version=verifier_engine.tensorrt_version,
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
    "ConditionalDeploymentV1",
    "ConditionalSchedulerMetrics",
    "ConditionalWorkItemV1",
    "ShadowWorkItemV1",
    "VerifierCandidateV1",
    "VerifierWorkItemV1",
]
