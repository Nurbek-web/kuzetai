from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

import protector.pilot.gates as pilot_gates
from protector.pilot.config import SiteConfig
from protector.pilot.gates import (
    CameraAnalyticScheduleV1,
    ExpectedConditionalWorkloadV1,
)
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
    ConditionalDeploymentV1,
    ConditionalWorkItemV1,
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


def _workload(entry: ModelRegistryEntryV1) -> ExpectedConditionalWorkloadV1:
    return pilot_gates.derive_expected_conditional_workload(
        site_id=entry.site_id,
        module=entry.module,
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
    )


def _capacity(
    entry: ModelRegistryEntryV1,
    *,
    effective_throughput_hz: float | None = None,
    required_throughput_hz: float | None = None,
    passed: bool = True,
) -> MeasuredCapacityReportV1:
    workload = _workload(entry)
    required = (
        workload.required_throughput_hz
        if required_throughput_hz is None
        else required_throughput_hz
    )
    effective = required * 1.25 if effective_throughput_hz is None else effective_throughput_hz
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
        nvidia_driver_version="575.57.08",
        cuda_driver_version="13.0",
        cuda_runtime_version="13.0",
        nvidia_container_toolkit_version="1.17.8",
        gpu_devices=(
            {
                "uuid": "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "product_name": entry.engine.target_gpu_architecture,
                "pci_bus_id": "0000:01:00.0",
                "total_vram_bytes": 24_000_000_000,
                "compute_capability": entry.engine.target_compute_capability,
                "mig_mode": "disabled",
            },
        ),
        site_config_sha256=workload.site_config_sha256,
        runtime_manifest_file_sha256="7" * 64,
        frozen_workload_sha256=workload.frozen_workload_sha256,
        expected_workload_sha256=workload.expected_workload_sha256,
        runtime_image_id_sha256="1" * 64,
        runtime_image_config_sha256="2" * 64,
        runtime_code_sha256="3" * 64,
        mount_contract_sha256="4" * 64,
        stream_count=20,
        effective_throughput_hz=effective,
        required_throughput_hz=required,
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


def _deployment(
    entry: ModelRegistryEntryV1,
    *,
    operator: bool = False,
    verification_boundary: str | None = None,
) -> ConditionalDeploymentV1:
    boundary = verification_boundary or (
        "human_confirmation"
        if entry.module == "fire_smoke"
        else "bounded_shadow_verifier"
    )
    return ConditionalDeploymentV1(
        entry=entry,
        site_matrix=_matrix(entry) if operator else None,
        shadow_stage=_shadow(entry) if operator else None,
        capacity_report=_capacity(entry) if operator else None,
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
        verification_boundary=boundary,
    )


def _verifier_entry() -> ModelRegistryEntryV1:
    base = _entry("weapon")
    return base.model_copy(
        update={
            "artifact_id": "weapon-verifier-artifact-v2",
            "artifact_sha256": "c" * 64,
            "engine": base.engine.model_copy(update={"engine_sha256": "d" * 64}),
        }
    )


def _scheduler_deployments(
    *,
    operator: bool = False,
) -> dict[str, ConditionalDeploymentV1]:
    return {
        "fire_deployment": _deployment(_entry("fire_smoke"), operator=operator),
        "weapon_deployment": _deployment(_entry("weapon"), operator=operator),
        "verifier_deployment": _deployment(_verifier_entry(), operator=False),
    }


def _verifier_candidate(
    scheduler: ConditionalAnalyticsScheduler,
    *,
    candidate_id: str,
    camera_id: str,
    source_time: datetime,
    confidence: float,
    roi: tuple[float, float, float, float] = (0.1, 0.1, 0.4, 0.5),
) -> VerifierCandidateV1:
    scheduler.schedule_due(
        camera_id=camera_id,
        source_time=source_time,
        person_rois=(roi,),
    )
    origin = scheduler.drain("weapon", limit=1)[0]
    return VerifierCandidateV1(
        candidate_id=candidate_id,
        camera_id=camera_id,
        source_time=source_time,
        confidence=confidence,
        roi=roi,
        origin=origin,
    )


def _site_config(*, fire_hz: float = 1.0, weapon_hz: float = 1.0) -> SiteConfig:
    feeds = [
            {
                "camera_id": f"camera-{index:02d}",
                "source_index": index - 1,
                "rtsp_url": {"environment": f"PILOT_CAMERA_{index:02d}_RTSP_URL"},
                "codec": "h264",
                "resolution": {"width": 1920, "height": 1080},
                "fps": 25.0,
                "bitrate_kbps": 2_000,
            "analytics_hz": {
                "person": 10.0,
                "fire_smoke": fire_hz,
                "weapon": weapon_hz,
            },
        }
        for index in range(1, 21)
    ]
    return SiteConfig.model_validate(
        {
            "ready_to_start": {
                "feeds": feeds,
                "ntp_source": "ntp.customer.example",
                "camera_map": "customer-approved-map-v1",
                "site_access": "approved site-access record",
                "compute": "NVIDIA L4 pilot node",
                "notification_channel": "customer-selected Telegram connector",
                "model_rights_decisions": "model-register-v1",
            },
            "storage": {
                "country_code": "KZ",
                "endpoint": "https://object-storage.customer.example",
                "bucket": "kuzet-pilot-evidence",
                "retention": {
                    "continuous_video_owner": "customer_nvr",
                    "continuous_video_storage_enabled": False,
                    "encoded_ring_buffer_seconds": 15,
                    "evidence_retention_days": 30,
                    "metadata_retention_days": 365,
                },
            },
            "queues": {
                "decode": 64,
                "analytics": 256,
                "verifier": 32,
                "events": 128,
            },
        }
    )


def _attested_frozen_replay(
    module: str,
    *,
    site_id: str = "school-01",
    fanout: int | None = None,
):
    manifest_payload = {
        "schema_version": "frozen-replay-fanout-manifest.v1",
        "site_id": site_id,
        "module": module,
        "corpus_id": "school-01-frozen-replay-v1",
        "corpus_sha256": "7" * 64,
        "cameras": [
            {
                "camera_id": f"camera-{index:02d}",
                "inferences_per_sample": (
                    fanout
                    if fanout is not None
                    else (1 if module == "fire_smoke" else 2)
                ),
            }
            for index in range(1, 21)
        ],
    }
    digest = hashlib.sha256(
        json.dumps(
            manifest_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return pilot_gates.AttestedFrozenReplayFanoutV1.model_validate(
        {
            "schema_version": "attested-frozen-replay-fanout.v1",
            "manifest": manifest_payload,
            "manifest_sha256": digest,
            "passed": True,
            "report_reference": f"reports/frozen-replay/{module}.json",
            "report_sha256": "6" * 64,
            "signed_by": "capacity-qa@example.kz",
            "signed_at": "2026-07-29T10:30:00Z",
        }
    )


def test_expected_workload_is_derived_from_site_config_and_exact_attested_fanout() -> None:
    site_config = _site_config(fire_hz=1.5, weapon_hz=1.25)
    frozen_replay = _attested_frozen_replay("weapon", fanout=3)

    workload = pilot_gates.derive_expected_conditional_workload(
        site_id="school-01",
        module="weapon",
        site_config=site_config,
        frozen_replay=frozen_replay,
    )

    assert workload.required_throughput_hz == 75.0
    assert [camera.camera_id for camera in workload.cameras] == [
        f"camera-{index:02d}" for index in range(1, 21)
    ]
    assert {camera.analytics_hz for camera in workload.cameras} == {1.25}
    assert {camera.inferences_per_sample for camera in workload.cameras} == {3}
    serialized_config = json.dumps(
        site_config.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert workload.site_config_sha256 == hashlib.sha256(serialized_config).hexdigest()
    assert workload.frozen_workload_sha256 == frozen_replay.manifest_sha256


@pytest.mark.parametrize(
    "mutation",
    [
        "digest",
        "site",
        "module",
        "missing_camera",
        "extra_camera",
        "duplicate_camera",
        "zero_fanout",
        "failed_attestation",
    ],
)
def test_expected_workload_refuses_unattested_or_mismatched_frozen_fanout(
    mutation: str,
) -> None:
    payload = _attested_frozen_replay("weapon").model_dump(mode="json")
    if mutation == "digest":
        payload["manifest_sha256"] = "0" * 64
    elif mutation == "site":
        payload["manifest"]["site_id"] = "other-school"
    elif mutation == "module":
        payload["manifest"]["module"] = "fire_smoke"
    elif mutation == "missing_camera":
        payload["manifest"]["cameras"].pop()
    elif mutation == "extra_camera":
        payload["manifest"]["cameras"].append(
            {"camera_id": "camera-21", "inferences_per_sample": 2}
        )
    elif mutation == "duplicate_camera":
        payload["manifest"]["cameras"][-1]["camera_id"] = "camera-01"
    elif mutation == "zero_fanout":
        payload["manifest"]["cameras"][0]["inferences_per_sample"] = 0
    else:
        payload["passed"] = False

    with pytest.raises((ValidationError, ValueError)):
        attested = pilot_gates.AttestedFrozenReplayFanoutV1.model_validate(payload)
        pilot_gates.derive_expected_conditional_workload(
            site_id="school-01",
            module="weapon",
            site_config=_site_config(),
            frozen_replay=attested,
        )


def test_expected_workload_refuses_missing_or_zero_site_module_schedule() -> None:
    missing_payload = _site_config().model_dump(mode="python")
    missing_feeds = []
    for feed in missing_payload["ready_to_start"]["feeds"]:
        changed = deepcopy(feed)
        changed["analytics_hz"].pop("weapon")
        missing_feeds.append(changed)
    missing_payload["ready_to_start"]["feeds"] = missing_feeds

    for site_config in (
        SiteConfig.model_validate(missing_payload),
        _site_config(weapon_hz=0.0),
    ):
        with pytest.raises(ValueError, match="schedule"):
            pilot_gates.derive_expected_conditional_workload(
                site_id="school-01",
                module="weapon",
                site_config=site_config,
                frozen_replay=_attested_frozen_replay("weapon"),
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
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
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
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
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
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(changed_entry.module),
    )
    changed_engine = evaluate_conditional_promotion(
        entry,
        site_matrix=matrix,
        shadow_stage=shadow,
        capacity_report=capacity.model_copy(update={"engine_sha256": "9" * 64}),
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
    )

    assert changed_threshold.mode == "disabled"
    assert changed_threshold.reasons == ("site matrix binding mismatch",)
    assert changed_engine.mode == "disabled"
    assert changed_engine.reasons == ("capacity report binding mismatch",)


@pytest.mark.parametrize(
    ("engine_change", "expected_reason"),
    [
        ({"target_gpu_architecture": "NVIDIA RTX 4090"}, "pilot target"),
        ({"target_compute_capability": "9.0"}, "pilot target"),
        ({"tensorrt_version": "10.8.0.43"}, "pilot target"),
    ],
)
def test_matching_reports_for_a_nonpilot_target_remain_disabled(
    engine_change: dict[str, str],
    expected_reason: str,
) -> None:
    base = _entry("weapon")
    entry = base.model_copy(
        update={"engine": base.engine.model_copy(update=engine_change)}
    )

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
    )

    assert decision.mode == "disabled"
    assert any(expected_reason in reason for reason in decision.reasons)


def test_missing_quality_shadow_or_capacity_evidence_stays_shadow_with_explicit_reasons() -> None:
    entry = _entry()

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=None,
        shadow_stage=None,
        capacity_report=None,
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
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
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
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
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
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
        capacity_report=None,
        site_config=None,
        frozen_replay=None,
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
            effective_throughput_hz=24.99,
            required_throughput_hz=20.0,
        ),
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
    )
    exact = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(
            entry,
            effective_throughput_hz=25.0,
            required_throughput_hz=20.0,
        ),
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
    )

    assert insufficient.mode == "shadow"
    assert "measured throughput headroom is below 25%" in insufficient.reasons
    assert exact.mode == "operator"
    assert exact.reasons == ()


def test_self_declared_near_zero_capacity_denominator_cannot_promote() -> None:
    entry = _entry()

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(
            entry,
            effective_throughput_hz=0.125,
            required_throughput_hz=0.1,
        ),
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
    )

    assert decision.mode == "shadow"
    assert "configured site workload" in " ".join(decision.reasons)


def test_capacity_denominator_must_match_higher_actual_site_schedule() -> None:
    entry = _entry("weapon")
    actual_site = _site_config(weapon_hz=2.0)
    frozen_replay = _attested_frozen_replay("weapon", fanout=2)
    actual_workload = pilot_gates.derive_expected_conditional_workload(
        site_id=entry.site_id,
        module="weapon",
        site_config=actual_site,
        frozen_replay=frozen_replay,
    )
    understated = _capacity(entry).model_copy(
        update={
            "site_config_sha256": actual_workload.site_config_sha256,
            "frozen_workload_sha256": actual_workload.frozen_workload_sha256,
            "expected_workload_sha256": actual_workload.expected_workload_sha256,
            "required_throughput_hz": 40.0,
            "effective_throughput_hz": 50.0,
        }
    )

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=understated,
        site_config=actual_site,
        frozen_replay=frozen_replay,
    )

    assert actual_workload.required_throughput_hz == 80.0
    assert decision.mode == "shadow"
    assert (
        "capacity required throughput does not match configured site workload"
        in decision.reasons
    )


def test_int8_engine_cannot_promote_without_registered_calibration_and_exact_report() -> None:
    entry = _entry().model_copy(
        update={"engine": _entry().engine.model_copy(update={"precision": "int8"})}
    )

    decision = evaluate_conditional_promotion(
        entry,
        site_matrix=_matrix(entry),
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
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
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
    )

    assert decision.mode == "shadow"
    assert expected_reason in decision.reasons


def test_conditional_scheduler_runs_shared_fire_full_frame_and_weapon_roi_work_at_one_hz() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=8,
        verifier_queue_capacity=2,
        **_scheduler_deployments(),
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
    assert {item.artifact_id for item in fire} == {"fire_smoke-artifact-v7"}
    assert {item.artifact_id for item in weapon} == {"weapon-artifact-v7"}
    assert all(item.gate_mode == "shadow" for item in (*fire, *weapon))


def test_conditional_scheduler_defaults_disabled_and_uses_explicit_operator_gate_mode() -> None:
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    disabled = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
    )
    disabled.schedule_due(camera_id="camera-01", source_time=now, person_rois=())
    assert disabled.drain("fire_smoke", limit=5) == ()
    assert disabled.drain("weapon", limit=5) == ()
    assert disabled.camera_state_count == 0
    assert disabled.metrics().unconfigured_or_stale_suppressed_total == 1

    operator = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        **_scheduler_deployments(operator=True),
    )
    operator.schedule_due(camera_id="camera-01", source_time=now, person_rois=())
    assert [item.gate_mode for item in operator.drain("fire_smoke", limit=5)] == [
        "operator"
    ]
    assert [item.gate_mode for item in operator.drain("weapon", limit=5)] == [
        "operator"
    ]


def test_caller_constructed_wrong_site_and_registry_gate_cannot_schedule_operator_work() -> None:
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    entry = _entry("fire_smoke")
    wrong_site_matrix = _matrix(entry).model_copy(update={"site_id": "wrong-site"})
    deployment = ConditionalDeploymentV1(
        entry=entry,
        site_matrix=wrong_site_matrix,
        shadow_stage=_shadow(entry),
        capacity_report=_capacity(entry),
        site_config=_site_config(),
        frozen_replay=_attested_frozen_replay(entry.module),
        verification_boundary="human_confirmation",
    )
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        fire_deployment=deployment,
    )

    scheduler.schedule_due(camera_id="camera-01", source_time=now, person_rois=())

    assert scheduler.drain("fire_smoke", limit=5) == ()


def test_conditional_work_preserves_site_registry_engine_runtime_and_decision_bindings() -> None:
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    fire_entry = _entry("fire_smoke")
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        fire_deployment=_deployment(fire_entry, operator=True),
    )
    scheduler.schedule_due(camera_id="camera-01", source_time=now, person_rois=())

    item = scheduler.drain("fire_smoke", limit=1)[0]
    assert item.site_id == "school-01"
    assert item.site_config_sha256 == _workload(fire_entry).site_config_sha256
    assert item.registry_entry_sha256 == fire_entry.registry_entry_sha256
    assert item.artifact_sha256 == fire_entry.artifact_sha256
    assert item.engine_sha256 == fire_entry.engine.engine_sha256
    assert item.target_gpu_architecture == "NVIDIA L4 (Ada)"
    assert item.target_compute_capability == "8.9"
    assert item.tensorrt_version == "10.16.0.72"
    assert item.decision_sha256


def test_scheduler_disables_deployments_from_a_different_site_configuration() -> None:
    fire_entry = _entry("fire_smoke")
    weapon_entry = _entry("weapon").model_copy(update={"site_id": "another-school"})
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        fire_deployment=_deployment(fire_entry),
        weapon_deployment=ConditionalDeploymentV1(
            entry=weapon_entry,
            site_config=_site_config(),
            frozen_replay=_attested_frozen_replay(
                "weapon",
                site_id="another-school",
            ),
            verification_boundary="human_confirmation",
        ),
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    scheduler.schedule_due(camera_id="camera-01", source_time=now, person_rois=())

    assert len(scheduler.drain("fire_smoke", limit=2)) == 1
    assert scheduler.drain("weapon", limit=2) == ()


def test_verifier_queue_requires_the_bounded_shadow_verification_boundary() -> None:
    weapon_entry = _entry("weapon")
    verifier_entry = _verifier_entry()
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        weapon_deployment=_deployment(weapon_entry),
        verifier_deployment=_deployment(
            verifier_entry,
            verification_boundary="human_confirmation",
        ),
    )

    accepted = scheduler.submit_verifier(
        _verifier_candidate(
            scheduler,
            candidate_id="strong",
            camera_id="camera-01",
            source_time=datetime(2026, 7, 29, 12, 0, tzinfo=UTC),
            confidence=0.95,
        )
    )

    assert accepted is False
    assert scheduler.drain_verifier(limit=1) == ()


def test_heavy_verifier_accepts_only_strong_candidates_and_drops_overflow_observably() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=2,
        verifier_queue_capacity=1,
        verifier_trigger_confidence=0.8,
        **_scheduler_deployments(),
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    weak = _verifier_candidate(
        scheduler,
        candidate_id="weak",
        camera_id="camera-01",
        source_time=now,
        confidence=0.79,
    )
    assert scheduler.submit_verifier(weak) is False
    assert (
        scheduler.submit_verifier(
            weak.model_copy(update={"candidate_id": "strong-1", "confidence": 0.9})
        )
        is True
    )
    assert (
        scheduler.submit_verifier(
            _verifier_candidate(
                scheduler,
                candidate_id="strong-2",
                camera_id="camera-02",
                source_time=now,
                confidence=0.95,
                roi=(0.2, 0.2, 0.5, 0.6),
            )
        )
        is False
    )

    metrics = scheduler.metrics()
    assert metrics.verifier_weak_suppressed_total == 1
    assert metrics.verifier_overflow_dropped_total == 1
    verifier_work = scheduler.drain_verifier(limit=5)
    assert [item.candidate_id for item in verifier_work] == ["strong-1"]
    assert verifier_work[0].site_id == "school-01"
    assert (
        verifier_work[0].detector_registry_entry_sha256
        == _entry("weapon").registry_entry_sha256
    )
    assert (
        verifier_work[0].verifier_registry_entry_sha256
        == _verifier_entry().registry_entry_sha256
    )
    assert (
        verifier_work[0].detector_expected_workload_sha256
        == _workload(_entry("weapon")).expected_workload_sha256
    )
    assert (
        verifier_work[0].verifier_expected_workload_sha256
        == _workload(_verifier_entry()).expected_workload_sha256
    )
    assert verifier_work[0].verification_boundary == "bounded_shadow_verifier"
    assert verifier_work[0].gate_mode == "shadow"


def test_unknown_camera_is_rejected_before_state_or_queue_capacity_is_allocated() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        **_scheduler_deployments(),
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    scheduler.schedule_due(camera_id="unknown-camera", source_time=now, person_rois=())

    assert scheduler.camera_state_count == 0
    assert scheduler.drain("fire_smoke", limit=5) == ()
    assert scheduler.drain("weapon", limit=5) == ()
    assert scheduler.metrics().unconfigured_or_stale_suppressed_total == 1


def test_verifier_candidate_must_preserve_an_issued_weapon_work_identity() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        **_scheduler_deployments(),
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    scheduler.schedule_due(
        camera_id="camera-01",
        source_time=now,
        person_rois=((0.1, 0.1, 0.4, 0.5),),
    )
    origin = scheduler.drain("weapon", limit=1)[0]
    candidate = VerifierCandidateV1(
        candidate_id="strong",
        camera_id=origin.camera_id,
        source_time=origin.source_time,
        confidence=0.95,
        roi=origin.roi,
        origin=origin,
    )

    assert scheduler.submit_verifier(candidate) is True
    verifier_work = scheduler.drain_verifier(limit=1)[0]
    assert verifier_work.detector_work_id == origin.work_id


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("site_id", "other-site"),
        ("site_config_sha256", "9" * 64),
        ("expected_workload_sha256", "9" * 64),
        ("registry_entry_sha256", "9" * 64),
        ("artifact_sha256", "9" * 64),
        ("engine_sha256", "9" * 64),
        ("decision_sha256", "9" * 64),
        ("camera_id", "camera-02"),
    ],
)
def test_verifier_rejects_stale_or_cross_deployment_origin_bindings(
    field: str,
    replacement: str,
) -> None:
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        **_scheduler_deployments(),
    )
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    scheduler.schedule_due(
        camera_id="camera-01",
        source_time=now,
        person_rois=((0.1, 0.1, 0.4, 0.5),),
    )
    issued = scheduler.drain("weapon", limit=1)[0]
    stale = issued.model_copy(update={field: replacement})
    candidate_payload = {
        "candidate_id": f"stale-{field}",
        "camera_id": stale.camera_id,
        "source_time": stale.source_time,
        "confidence": 0.95,
        "roi": stale.roi,
        "origin": stale,
    }

    candidate = VerifierCandidateV1.model_validate(candidate_payload)
    assert scheduler.submit_verifier(candidate) is False
    assert scheduler.drain_verifier(limit=1) == ()
    assert scheduler.metrics().unconfigured_or_stale_suppressed_total == 1


def test_verifier_rejects_candidate_for_unconfigured_camera() -> None:
    issued = ConditionalWorkItemV1(
        work_id="unknown-camera:weapon:2026-07-29T12:00:00+00:00:0",
        camera_id="unknown-camera",
        module="weapon",
        source_time=datetime(2026, 7, 29, 12, 0, tzinfo=UTC),
        roi=(0.1, 0.1, 0.4, 0.5),
        priority="person_roi",
        artifact_id="weapon-artifact-v7",
        artifact_sha256="a" * 64,
        site_id="school-01",
        site_config_sha256="8" * 64,
        expected_workload_sha256="5" * 64,
        registry_entry_sha256=_entry("weapon").registry_entry_sha256,
        engine_sha256="e" * 64,
        target_gpu_architecture="NVIDIA L4 (Ada)",
        target_compute_capability="8.9",
        tensorrt_version="10.16.0.72",
        decision_sha256="6" * 64,
        verification_boundary="bounded_shadow_verifier",
    )
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=4,
        verifier_queue_capacity=1,
        **_scheduler_deployments(),
    )
    candidate = VerifierCandidateV1(
        candidate_id="unknown",
        camera_id=issued.camera_id,
        source_time=issued.source_time,
        confidence=0.95,
        roi=issued.roi,
        origin=issued,
    )

    assert scheduler.submit_verifier(candidate) is False
    assert scheduler.camera_state_count == 0
    assert scheduler.metrics().unconfigured_or_stale_suppressed_total == 1


def test_scheduler_rejects_regressing_source_time_and_bounds_camera_state() -> None:
    scheduler = ConditionalAnalyticsScheduler(
        queue_capacity=10,
        verifier_queue_capacity=1,
        max_camera_states=2,
        **_scheduler_deployments(),
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
        queue_capacity=10,
        verifier_queue_capacity=1,
        max_person_rois_per_sample=2,
        **_scheduler_deployments(),
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
        queue_capacity=2,
        verifier_queue_capacity=1,
        shadow_artifacts={"fight": "fight-x3d-shadow-v1", "fall": "fall-tao-shadow-v3"},
        shadow_queue_capacity=1,
        **_scheduler_deployments(),
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
            queue_capacity=2,
            verifier_queue_capacity=1,
            shadow_artifacts={"fight": "weapon-artifact-v7"},
            **_scheduler_deployments(),
        )

    with pytest.raises(ValueError, match="deployment module"):
        ConditionalAnalyticsScheduler(
            queue_capacity=2,
            verifier_queue_capacity=1,
            fire_deployment=_deployment(_entry("weapon")),
        )


def test_capacity_report_binds_a_frozen_workload_hash_not_a_gpu_coefficient() -> None:
    entry = _entry()
    report = _capacity(entry)
    workload = _workload(entry)

    payload = report.model_dump(mode="json")
    assert payload["frozen_workload_sha256"] == workload.frozen_workload_sha256
    assert payload["site_config_sha256"] == workload.site_config_sha256
    assert payload["expected_workload_sha256"] == workload.expected_workload_sha256
    assert workload.required_throughput_hz == 20.0
    assert len({camera.camera_id for camera in workload.cameras}) == 20
    assert "cameras_per_gpu" not in payload
    assert hashlib.sha256(b"twenty-feed-frozen-workload").hexdigest() != ""


def test_expected_weapon_throughput_includes_frozen_roi_inference_fanout() -> None:
    entry = _entry("weapon")
    workload = ExpectedConditionalWorkloadV1(
        schema_version="expected-conditional-workload.v1",
        site_id=entry.site_id,
        module="weapon",
        site_config_sha256="8" * 64,
        frozen_workload_sha256="5" * 64,
        cameras=tuple(
            CameraAnalyticScheduleV1(
                camera_id=f"camera-{index:02d}",
                analytics_hz=1.0,
                inferences_per_sample=3,
            )
            for index in range(1, 21)
        ),
    )

    assert workload.required_throughput_hz == 60.0


def test_signed_report_references_reject_query_fragment_and_control_characters() -> None:
    entry = _entry()

    with pytest.raises(ValidationError, match="credential-free"):
        SignedSiteMatrixV1.model_validate(
            _matrix(entry).model_dump()
            | {"report_reference": "https://reports.example.kz/site.json?token=secret"}
        )
    with pytest.raises(ValidationError, match="credential-free"):
        MeasuredCapacityReportV1.model_validate(
            _capacity(entry).model_dump()
            | {"report_reference": "reports/capacity/result.json#signed-secret"}
        )
