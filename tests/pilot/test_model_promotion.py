from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from protector.pilot.gates import ConditionalModelGateResultV1
from protector.pilot.model_registry import (
    MeasuredCapacityReportV1,
    ModelRegistryEntryV1,
    ShadowStageEvidenceV1,
    SignedSiteMatrixV1,
    SiteMatrixSceneV1,
    evaluate_conditional_promotion,
)
from protector.pilot.runtime.conditional import (
    ConditionalAnalyticsScheduler,
    VerifierCandidateV1,
)


def _entry(module: str = "fire_smoke", *, rights_status: str = "approved") -> ModelRegistryEntryV1:
    return ModelRegistryEntryV1.model_validate(
        {
            "schema_version": "model-registry-entry.v1",
            "site_id": "school-01",
            "module": module,
            "artifact_id": f"{module}-artifact-v7",
            "source_uri": f"s3://kz-model-registry/{module}-artifact-v7.onnx",
            "artifact_sha256": "a" * 64,
            "commercial_rights": {
                "schema_version": "commercial-rights-evidence.v1",
                "status": rights_status,
                **(
                    {
                        "evidence_reference": f"contracts/{module}-rights.pdf",
                        "evidence_sha256": "b" * 64,
                        "approved_by": "legal@example.kz",
                        "approved_at": "2026-07-29T08:00:00Z",
                    }
                    if rights_status == "approved"
                    else {}
                ),
            },
            "classes": ["fire", "smoke"] if module == "fire_smoke" else [module],
            "preprocessing": "letterbox-rgb-nchw-640-normalized-0-1",
            "training_provenance": f"registry://training/{module}/run-7",
            "evaluation_provenance": f"registry://evaluation/{module}/baseline-7",
            "thresholds": {"candidate_confidence": 0.7},
            "engine": {
                "schema_version": "engine-record.v1",
                "engine_sha256": "e" * 64,
                "tensorrt_version": "10.16.0.72",
                "target_gpu_architecture": "NVIDIA L4 (Ada)",
                "target_compute_capability": "8.9",
                "precision": "fp16",
            },
        }
    )


def _matrix(entry: ModelRegistryEntryV1, *, passed: bool = True) -> SignedSiteMatrixV1:
    return SignedSiteMatrixV1(
        schema_version="signed-site-matrix.v1",
        site_id=entry.site_id,
        module=entry.module,
        artifact_id=entry.artifact_id,
        artifact_sha256=entry.artifact_sha256,
        registry_entry_sha256=entry.registry_entry_sha256,
        positives=(
            SiteMatrixSceneV1(
                scene_id="positive-01",
                source_sha256="1" * 64,
                expected_event=True,
                result="pass",
            ),
        ),
        hard_negatives=(
            SiteMatrixSceneV1(
                scene_id="hard-negative-01",
                source_sha256="2" * 64,
                expected_event=False,
                result="pass",
            ),
        ),
        passed=passed,
        report_reference=f"reports/site/{entry.artifact_id}.json",
        report_sha256="3" * 64,
        signed_by="site-qa@example.kz",
        signed_at=datetime(2026, 7, 29, 9, 0, tzinfo=UTC),
    )


def _shadow(entry: ModelRegistryEntryV1, *, passed: bool = True) -> ShadowStageEvidenceV1:
    return ShadowStageEvidenceV1(
        schema_version="shadow-stage-evidence.v1",
        site_id=entry.site_id,
        artifact_id=entry.artifact_id,
        artifact_sha256=entry.artifact_sha256,
        registry_entry_sha256=entry.registry_entry_sha256,
        passed=passed,
        report_reference=f"reports/shadow/{entry.artifact_id}.json",
        report_sha256="4" * 64,
        signed_by="site-qa@example.kz",
        signed_at=datetime(2026, 7, 29, 10, 0, tzinfo=UTC),
    )


def _capacity(
    entry: ModelRegistryEntryV1,
    *,
    effective_throughput_hz: float = 50.0,
    required_throughput_hz: float = 40.0,
    passed: bool = True,
) -> MeasuredCapacityReportV1:
    return MeasuredCapacityReportV1(
        schema_version="measured-capacity-report.v1",
        site_id=entry.site_id,
        artifact_id=entry.artifact_id,
        artifact_sha256=entry.artifact_sha256,
        registry_entry_sha256=entry.registry_entry_sha256,
        engine_sha256=entry.engine.engine_sha256,
        precision=entry.engine.precision,
        target_gpu_architecture=entry.engine.target_gpu_architecture,
        target_compute_capability=entry.engine.target_compute_capability,
        tensorrt_version=entry.engine.tensorrt_version,
        frozen_workload_sha256="5" * 64,
        stream_count=20,
        effective_throughput_hz=effective_throughput_hz,
        required_throughput_hz=required_throughput_hz,
        scheduled_drop_fraction=0.005,
        queue_age_p95_seconds=0.5,
        queue_age_p99_seconds=1.2,
        gpu_utilization_max=0.74,
        vram_utilization_max=0.79,
        passed=passed,
        report_reference=f"reports/capacity/{entry.artifact_id}.json",
        report_sha256="6" * 64,
        signed_by="capacity-qa@example.kz",
        signed_at=datetime(2026, 7, 29, 11, 0, tzinfo=UTC),
    )


def _gate(
    artifact_id: str,
    module: str,
    mode: str = "shadow",
) -> ConditionalModelGateResultV1:
    return ConditionalModelGateResultV1(
        site_id="school-01",
        module=module,
        artifact_id=artifact_id,
        registry_entry_sha256="7" * 64,
        mode=mode,
        reasons=() if mode == "operator" else ("target evidence remains shadow",),
    )


def test_site_matrix_requires_both_positive_and_hard_negative_scenes() -> None:
    entry = _entry()
    payload = _matrix(entry).model_dump()
    payload["hard_negatives"] = ()

    with pytest.raises(ValidationError, match="hard_negatives"):
        SignedSiteMatrixV1.model_validate(payload)


def test_operator_promotion_requires_exact_signed_site_shadow_and_capacity_bindings() -> None:
    entry = _entry("weapon")

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
    )

    assert decision.mode == "operator"
    assert decision.reasons == ()
    assert decision.artifact_id == entry.artifact_id
    assert decision.registry_entry_sha256 == entry.registry_entry_sha256

    wrong_site_matrix = _matrix(entry).model_copy(update={"site_id": "another-school"})
    mismatch = evaluate_conditional_promotion(
        entry,
        site_matrix=wrong_site_matrix,
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
    )
    assert mismatch.mode == "disabled"
    assert mismatch.reasons == ("site matrix binding mismatch",)


def test_signed_reports_bind_threshold_preprocess_and_exact_engine_runtime_identity() -> None:
    entry = _entry("weapon")
    matrix = _matrix(entry)
    shadow = _shadow(entry)
    capacity = _capacity(entry)
    changed_entry = entry.model_copy(
        update={"thresholds": {"candidate_confidence": 0.91}}
    )

    changed_threshold = evaluate_conditional_promotion(
        changed_entry,
        site_matrix=matrix,
        shadow_stage=shadow,
        capacity_report=capacity,
    )
    changed_engine = evaluate_conditional_promotion(
        entry,
        site_matrix=matrix,
        shadow_stage=shadow,
        capacity_report=capacity.model_copy(update={"engine_sha256": "9" * 64}),
    )

    assert changed_threshold.mode == "disabled"
    assert changed_threshold.reasons == ("site matrix binding mismatch",)
    assert changed_engine.mode == "disabled"
    assert changed_engine.reasons == ("capacity report binding mismatch",)


def test_missing_quality_shadow_or_capacity_evidence_stays_shadow_with_explicit_reasons() -> None:
    entry = _entry()

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=None,
        shadow_stage=None,
        capacity_report=None,
    )

    assert decision.mode == "shadow"
    assert decision.reasons == (
        "missing signed site matrix",
        "missing successful shadow-stage evidence",
        "missing measured capacity report",
    )


def test_report_pass_flags_cannot_override_a_failing_site_scene() -> None:
    entry = _entry()
    matrix = _matrix(entry)
    failing_positive = matrix.positives[0].model_copy(update={"result": "fail"})

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=matrix.model_copy(update={"positives": (failing_positive,)}),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
    )

    assert decision.mode == "shadow"
    assert "site matrix contains failing scenes" in decision.reasons


def test_unapproved_rights_disable_the_module_even_if_other_reports_pass() -> None:
    entry = _entry(rights_status="ambiguous")

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
    )

    assert decision.mode == "disabled"
    assert "commercial rights status is ambiguous" in decision.reasons


@pytest.mark.parametrize("module", ["fight", "fall"])
def test_fight_and_fall_are_always_shadow_only(module: str) -> None:
    entry = _entry(module)

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
    )

    assert decision.mode == "shadow"
    assert decision.reasons == (f"{module} is shadow-only for this pilot",)


def test_capacity_needs_measured_effective_throughput_with_at_least_twenty_five_percent_headroom() -> None:
    entry = _entry()

    insufficient = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(
            entry,
            effective_throughput_hz=49.59,
            required_throughput_hz=40.0,
        ),
    )
    exact = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(
            entry,
            effective_throughput_hz=50.0,
            required_throughput_hz=40.0,
        ),
    )

    assert insufficient.mode == "shadow"
    assert "measured throughput headroom is below 25%" in insufficient.reasons
    assert exact.mode == "operator"
    assert exact.reasons == ()


def test_int8_engine_cannot_promote_without_registered_calibration_and_exact_report() -> None:
    entry = _entry().model_copy(
        update={"engine": _entry().engine.model_copy(update={"precision": "int8"})}
    )

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
    )

    assert decision.mode == "disabled"
    assert decision.reasons == ("INT8 engine evidence is incomplete",)


@pytest.mark.parametrize(
    ("changes", "expected_reason"),
    [
        ({"stream_count": 19}, "capacity report must cover exactly 20 streams"),
        ({"scheduled_drop_fraction": 0.01}, "scheduled analysis drops must be below 1%"),
        ({"queue_age_p95_seconds": 1.0}, "queue age p95 must be below 1 second"),
        ({"queue_age_p99_seconds": 2.0}, "queue age p99 must be below 2 seconds"),
        ({"gpu_utilization_max": 0.751}, "GPU utilization exceeds 75%"),
        ({"vram_utilization_max": 0.801}, "VRAM utilization exceeds 80%"),
    ],
)
def test_capacity_pass_flag_cannot_override_measured_gate_failures(
    changes: dict[str, object], expected_reason: str
) -> None:
    entry = _entry()

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry).model_copy(update=changes),
    )

    assert decision.mode == "shadow"
    assert expected_reason in decision.reasons


def test_conditional_scheduler_runs_shared_fire_full_frame_and_weapon_roi_work_at_one_hz() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        fire_artifact_id="fire-v7",
        weapon_artifact_id="weapon-v7",
        verifier_artifact_id="weapon-verifier-v2",
        queue_capacity=8,
        verifier_queue_capacity=2,
        fire_gate=_gate("fire-v7", "fire_smoke"),
        weapon_gate=_gate("weapon-v7", "weapon"),
        verifier_gate=_gate("weapon-verifier-v2", "weapon"),
    )
    first = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    rois = ((0.1, 0.2, 0.3, 0.6), (0.5, 0.1, 0.8, 0.9))

    scheduler.schedule_due(camera_id="camera-01", source_time=first, person_rois=rois)
    scheduler.schedule_due(
        camera_id="camera-01",
        source_time=first + timedelta(milliseconds=999),
        person_rois=rois,
    )
    scheduler.schedule_due(
        camera_id="camera-01",
        source_time=first + timedelta(seconds=1),
        person_rois=rois,
    )

    fire = scheduler.drain("fire_smoke", limit=10)
    weapon = scheduler.drain("weapon", limit=10)
    assert [(item.source_time, item.roi) for item in fire] == [
        (first, None),
        (first + timedelta(seconds=1), None),
    ]
    assert [(item.source_time, item.roi, item.priority) for item in weapon] == [
        (first, rois[0], "person_roi"),
        (first, rois[1], "person_roi"),
        (first + timedelta(seconds=1), rois[0], "person_roi"),
        (first + timedelta(seconds=1), rois[1], "person_roi"),
    ]
    assert {item.artifact_id for item in fire} == {"fire-v7"}
    assert {item.artifact_id for item in weapon} == {"weapon-v7"}
    assert all(item.gate_mode == "shadow" for item in (*fire, *weapon))


def test_conditional_scheduler_defaults_disabled_and_uses_explicit_operator_gate_mode() -> None:
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    disabled = ConditionalAnalyticsScheduler(
        fire_artifact_id="fire-v7",
        weapon_artifact_id="weapon-v7",
        verifier_artifact_id="weapon-verifier-v2",
        queue_capacity=4,
        verifier_queue_capacity=1,
    )
    disabled.schedule_due(camera_id="camera-01", source_time=now, person_rois=())
    assert disabled.drain("fire_smoke", limit=5) == ()
    assert disabled.drain("weapon", limit=5) == ()
    assert disabled.metrics().disabled_work_suppressed_total == 2

    operator = ConditionalAnalyticsScheduler(
        fire_artifact_id="fire-v7",
        weapon_artifact_id="weapon-v7",
        verifier_artifact_id="weapon-verifier-v2",
        queue_capacity=4,
        verifier_queue_capacity=1,
        fire_gate=_gate("fire-v7", "fire_smoke", "operator"),
        weapon_gate=_gate("weapon-v7", "weapon", "operator"),
        verifier_gate=_gate("weapon-verifier-v2", "weapon"),
    )
    operator.schedule_due(camera_id="camera-01", source_time=now, person_rois=())
    assert [item.gate_mode for item in operator.drain("fire_smoke", limit=5)] == [
        "operator"
    ]
    assert [item.gate_mode for item in operator.drain("weapon", limit=5)] == [
        "operator"
    ]


def test_heavy_verifier_accepts_only_strong_candidates_and_drops_overflow_observably() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        fire_artifact_id="fire-v7",
        weapon_artifact_id="weapon-v7",
        verifier_artifact_id="weapon-verifier-v2",
        queue_capacity=2,
        verifier_queue_capacity=1,
        verifier_trigger_confidence=0.8,
        fire_gate=_gate("fire-v7", "fire_smoke"),
        weapon_gate=_gate("weapon-v7", "weapon"),
        verifier_gate=_gate("weapon-verifier-v2", "weapon"),
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    assert (
        scheduler.submit_verifier(
            VerifierCandidateV1(
                candidate_id="weak",
                camera_id="camera-01",
                source_time=now,
                confidence=0.79,
                roi=(0.1, 0.1, 0.4, 0.5),
                detector_artifact_id="weapon-v7",
            )
        )
        is False
    )
    assert (
        scheduler.submit_verifier(
            VerifierCandidateV1(
                candidate_id="strong-1",
                camera_id="camera-01",
                source_time=now,
                confidence=0.9,
                roi=(0.1, 0.1, 0.4, 0.5),
                detector_artifact_id="weapon-v7",
            )
        )
        is True
    )
    assert (
        scheduler.submit_verifier(
            VerifierCandidateV1(
                candidate_id="strong-2",
                camera_id="camera-02",
                source_time=now,
                confidence=0.95,
                roi=(0.2, 0.2, 0.5, 0.6),
                detector_artifact_id="weapon-v7",
            )
        )
        is False
    )

    metrics = scheduler.metrics()
    assert metrics.verifier_weak_suppressed_total == 1
    assert metrics.verifier_overflow_dropped_total == 1
    assert [item.candidate_id for item in scheduler.drain_verifier(limit=5)] == ["strong-1"]


def test_scheduler_rejects_regressing_source_time_and_bounds_camera_state() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        fire_artifact_id="fire-v7",
        weapon_artifact_id="weapon-v7",
        verifier_artifact_id="weapon-verifier-v2",
        queue_capacity=10,
        verifier_queue_capacity=1,
        max_camera_states=2,
        fire_gate=_gate("fire-v7", "fire_smoke"),
        weapon_gate=_gate("weapon-v7", "weapon"),
        verifier_gate=_gate("weapon-verifier-v2", "weapon"),
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    scheduler.schedule_due(camera_id="camera-01", source_time=now, person_rois=())
    scheduler.schedule_due(camera_id="camera-02", source_time=now, person_rois=())
    scheduler.schedule_due(
        camera_id="camera-01",
        source_time=now - timedelta(seconds=1),
        person_rois=(),
    )
    scheduler.schedule_due(camera_id="camera-03", source_time=now, person_rois=())

    assert scheduler.camera_state_count == 2
    assert scheduler.metrics().regressing_source_time_dropped_total == 1
    assert scheduler.metrics().camera_state_overflow_dropped_total == 1
    assert {item.camera_id for item in scheduler.drain("fire_smoke", limit=10)} == {
        "camera-01",
        "camera-02",
    }


def test_weapon_roi_fanout_is_finite_and_excess_work_is_counted() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        fire_artifact_id="fire-v7",
        weapon_artifact_id="weapon-v7",
        verifier_artifact_id="weapon-verifier-v2",
        queue_capacity=10,
        verifier_queue_capacity=1,
        fire_gate=_gate("fire-v7", "fire_smoke"),
        weapon_gate=_gate("weapon-v7", "weapon"),
        verifier_gate=_gate("weapon-verifier-v2", "weapon"),
        max_person_rois_per_sample=2,
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    rois = (
        (0.1, 0.1, 0.2, 0.2),
        (0.2, 0.2, 0.3, 0.3),
        (0.3, 0.3, 0.4, 0.4),
    )

    scheduler.schedule_due(camera_id="camera-01", source_time=now, person_rois=rois)

    assert len(scheduler.drain("weapon", limit=10)) == 2
    assert scheduler.metrics().person_roi_overflow_dropped_total == 1


def test_fight_and_fall_shadow_work_use_separate_artifacts_and_bounded_queues() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        fire_artifact_id="fire-v7",
        weapon_artifact_id="weapon-v7",
        verifier_artifact_id="weapon-verifier-v2",
        queue_capacity=2,
        verifier_queue_capacity=1,
        fire_gate=_gate("fire-v7", "fire_smoke"),
        weapon_gate=_gate("weapon-v7", "weapon"),
        verifier_gate=_gate("weapon-verifier-v2", "weapon"),
        shadow_artifacts={"fight": "fight-x3d-shadow-v1", "fall": "fall-tao-shadow-v3"},
        shadow_queue_capacity=1,
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    assert scheduler.submit_shadow(
        module="fight", sample_id="fight-1", camera_id="camera-01", source_time=now
    )
    assert not scheduler.submit_shadow(
        module="fight", sample_id="fight-2", camera_id="camera-02", source_time=now
    )
    assert scheduler.submit_shadow(
        module="fall", sample_id="fall-1", camera_id="camera-03", source_time=now
    )

    fight = scheduler.drain_shadow("fight", limit=5)
    fall = scheduler.drain_shadow("fall", limit=5)
    assert [item.artifact_id for item in fight] == ["fight-x3d-shadow-v1"]
    assert [item.artifact_id for item in fall] == ["fall-tao-shadow-v3"]
    assert all(item.gate_mode == "shadow" for item in (*fight, *fall))
    assert scheduler.metrics().shadow_overflow_dropped_total == 1

    with pytest.raises(ValueError, match="separate artifact"):
        ConditionalAnalyticsScheduler(
            fire_artifact_id="fire-v7",
            weapon_artifact_id="weapon-v7",
            verifier_artifact_id="weapon-verifier-v2",
            queue_capacity=2,
            verifier_queue_capacity=1,
            fire_gate=_gate("fire-v7", "fire_smoke"),
            weapon_gate=_gate("weapon-v7", "weapon"),
            verifier_gate=_gate("weapon-verifier-v2", "weapon"),
            shadow_artifacts={"fight": "weapon-v7"},
        )

    with pytest.raises(ValueError, match="gate binding"):
        ConditionalAnalyticsScheduler(
            fire_artifact_id="fire-v7",
            weapon_artifact_id="weapon-v7",
            verifier_artifact_id="weapon-verifier-v2",
            queue_capacity=2,
            verifier_queue_capacity=1,
            fire_gate=_gate("another-fire", "fire_smoke"),
        )


def test_capacity_report_binds_a_frozen_workload_hash_not_a_gpu_coefficient() -> None:
    entry = _entry()
    report = _capacity(entry)

    payload = report.model_dump(mode="json")
    assert payload["frozen_workload_sha256"] == "5" * 64
    assert "cameras_per_gpu" not in payload
    assert hashlib.sha256(b"twenty-feed-frozen-workload").hexdigest() != ""
