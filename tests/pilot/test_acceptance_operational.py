from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import protector.pilot.acceptance_operational as operational_module
from protector.pilot.acceptance_operational import (
    AcceptanceLimitsV1,
    EvidenceReadyArtifactV1,
    OperationalAcceptanceEvidenceV1,
    QueueLimitV1,
    QueueObservationV1,
    canonical_operational_json,
    evaluate_operational_acceptance,
    operational_evidence_sha256,
)

UTC = timezone.utc
START = datetime(2026, 7, 30, tzinfo=UTC)
END = START + timedelta(hours=8)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
CAMERAS = tuple(f"camera-{index:02}" for index in range(20))
QUEUES = ("decode", "analytics", "verifier", "events", "evidence")
STORES = ("evidence", "metadata")


def _limits_payload() -> dict[str, object]:
    return {
        "schema_version": "acceptance-operational-limits.v1",
        "site_id": "school-01",
        "manifest_sha256": DIGEST_A,
        "gate": "8h",
        "started_at": START,
        "ended_at": END,
        "camera_ids": list(CAMERAS),
        "camera_namespaces": [
            {key: value for key, value in row.items() if key != "observed_camera_ids"}
            for row in _namespace_rows()
        ],
        "queue_sample_cadence_seconds": 60,
        "expected_queue_samples": 481,
        "queues": [
            {"name": name, "capacity": capacity}
            for name, capacity in zip(QUEUES, (8, 64, 4, 64, 32), strict=True)
        ],
        "stores": [
            {
                "name": "evidence",
                "storage_identity": "kz-evidence-store-01",
                "fixed_overhead_bytes": 100,
                "max_object_bytes": 1_000,
                "max_objects": 100,
                "max_bytes": 100_100,
                "retention_window_seconds": 30 * 24 * 60 * 60,
                "plateau_observation_window_seconds": 3_600,
            },
            {
                "name": "metadata",
                "storage_identity": "postgres-metadata-01",
                "fixed_overhead_bytes": 100,
                "max_object_bytes": 100,
                "max_objects": 200,
                "max_bytes": 20_100,
                "retention_window_seconds": 365 * 24 * 60 * 60,
                "plateau_observation_window_seconds": 3_600,
            },
        ],
        "evidence_storage_root": "/srv/kuzet/evidence",
        "evidence_storage_identity": "kz-evidence-store-01",
        "repository_source": {
            "schema_version": "acceptance-repository-source.v1",
            "source_identity": "postgres-school-01",
            "canonical_query_sha256": DIGEST_B,
            "start_high_water": 0,
            "start_snapshot_sha256": DIGEST_C,
        },
        "module_dispositions": [
            {
                "module": "fire_smoke",
                "mode": "shadow",
                "decided_by_role": "admin",
                "decided_by_id": "admin-01",
            },
            {
                "module": "weapon",
                "mode": "disabled",
                "decided_by_role": "admin",
                "decided_by_id": "admin-01",
            },
        ],
        "restart_fault_windows": [
            {
                "fault_id": "fault-runtime-restart",
                "component": "runtime",
                "first_sample_index": 10,
                "last_sample_index": 20,
                "from_boot_id": "runtime-boot-0",
                "to_boot_id": "runtime-boot-1",
                "schedule_sha256": DIGEST_B,
                "signature_sha256": DIGEST_C,
            },
            {
                "fault_id": "fault-api-restart",
                "component": "api",
                "first_sample_index": 30,
                "last_sample_index": 40,
                "from_boot_id": "api-boot-0",
                "to_boot_id": "api-boot-1",
                "schedule_sha256": DIGEST_B,
                "signature_sha256": DIGEST_C,
            },
        ],
    }


def _queue_rows(*, capacities: tuple[int, ...] = (8, 64, 4, 64, 32)) -> list[dict[str, object]]:
    return [
        {
            "name": name,
            "depth": 0,
            "capacity": capacity,
            "dropped_total": 0,
        }
        for name, capacity in zip(QUEUES, capacities, strict=True)
    ]


def _namespace_rows() -> list[dict[str, object]]:
    return [
        {
            "camera_id": camera_id,
            "source_state_id": f"source:{camera_id}",
            "tracker_state_id": f"tracker:{camera_id}",
            "analytic_state_id": f"analytic:{camera_id}",
            "observed_camera_ids": [camera_id],
        }
        for camera_id in CAMERAS
    ]


def _store_rows(
    evidence_bytes: int = 20_000,
    evidence_objects: int = 40,
    metadata_bytes: int = 500,
    metadata_objects: int = 20,
) -> list[dict[str, object]]:
    return [
        {
            "name": "evidence",
            "storage_identity": "kz-evidence-store-01",
            "used_bytes": evidence_bytes,
            "object_count": evidence_objects,
            "declared_max_bytes": 100_100,
            "declared_max_objects": 100,
        },
        {
            "name": "metadata",
            "storage_identity": "postgres-metadata-01",
            "used_bytes": metadata_bytes,
            "object_count": metadata_objects,
            "declared_max_bytes": 20_100,
            "declared_max_objects": 200,
        },
    ]


def _identity_fields(index: int) -> dict[str, object]:
    return {
        "event_id": f"event-{index:02}",
        "evidence_id": f"evidence-{index:02}",
        "camera_id": CAMERAS[index],
        "module": "acceptance_drill",
        "mode": "operator",
        "repository_sequence": index + 1,
    }


def _evidence_payload() -> dict[str, object]:
    candidates: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    reviews: list[dict[str, object]] = []
    audits: list[dict[str, object]] = []
    acknowledgements: list[dict[str, object]] = []
    for index, camera_id in enumerate(CAMERAS):
        identity = _identity_fields(index)
        occurred_at = START + timedelta(seconds=100 + index)
        decision = "confirmed" if index == 0 else "rejected"
        candidates.append(
            {
                **identity,
                "workflow": "acceptance_drill",
                "occurred_at": occurred_at,
                "repository_sequence": index + 1,
                "runtime_boot_id": "runtime-boot-0",
                "api_boot_id": "api-boot-0",
                "accuracy_claimed": False,
            }
        )
        artifacts.append(
            {
                **identity,
                "sha256": f"{index:064x}",
                "byte_size": 400 + index,
                "duration_seconds": 4.0,
                "playable": True,
                "storage_identity": "kz-evidence-store-01",
                "object_key": f"school-01/{camera_id}/event-{index:02}.mp4",
                "ready_at": occurred_at + timedelta(seconds=1),
            }
        )
        reviews.append(
            {
                **identity,
                "review_id": f"review-{index:02}",
                "reviewer_role": "operator",
                "reviewer_id": "operator-01",
                "decision": decision,
                "reviewed_at": occurred_at + timedelta(seconds=2),
            }
        )
        audits.append(
            {
                **identity,
                "audit_id": f"audit-{index:02}",
                "actor_role": "operator",
                "actor_id": "operator-01",
                "action": f"review_{decision}",
                "occurred_at": occurred_at + timedelta(seconds=3),
            }
        )
        acknowledgements.append(
            {
                **identity,
                "acknowledgement_id": f"ack-{index:02}",
                "status": "complete",
                "acknowledged_at": occurred_at
                + timedelta(seconds=6 if decision == "confirmed" else 4),
            }
        )
    retention_drills = []
    for store in STORES:
        storage_identity = "kz-evidence-store-01" if store == "evidence" else "postgres-metadata-01"
        retention_seconds = 30 * 24 * 60 * 60 if store == "evidence" else 365 * 24 * 60 * 60
        for camera_id in CAMERAS:
            retention_drills.append(
                {
                    "drill_id": f"retention:{store}:{camera_id}",
                    "store": store,
                    "camera_id": camera_id,
                    "namespace_id": f"{store}:{camera_id}",
                    "object_identity": f"{store}/{camera_id}/expired-object",
                    "storage_identity": storage_identity,
                    "created_at": START - timedelta(hours=1, seconds=retention_seconds),
                    "expired_at": START - timedelta(hours=1),
                    "deleted_at": START + timedelta(seconds=10),
                    "bytes_reclaimed": 100,
                    "objects_before": 2,
                    "objects_after": 1,
                }
            )
    payload: dict[str, object] = {
        "schema_version": "operational-acceptance-evidence.v1",
        "site_id": "school-01",
        "manifest_sha256": DIGEST_A,
        "started_at": START,
        "ended_at": END,
        "sample_spans": [
            {
                "first_sample_index": 0,
                "sample_count": 481,
                "queues": _queue_rows(),
                "camera_namespaces": _namespace_rows(),
                "stores": _store_rows(),
            }
        ],
        "final_evidence_store_observation": {
            "sample_index": 480,
            "observed_at": END,
            "storage_identity": "kz-evidence-store-01",
            "used_bytes": 20_000,
            "object_count": 40,
            "live_artifacts": [
                {
                    "object_key": row["object_key"],
                    "sha256": row["sha256"],
                    "byte_size": row["byte_size"],
                    "storage_identity": row["storage_identity"],
                }
                for row in artifacts
            ],
        },
        "candidate_events": candidates,
        "evidence_ready": artifacts,
        "human_reviews": reviews,
        "audit_rows": audits,
        "outbox_queued": [
            {
                **_identity_fields(0),
                "outbox_id": "outbox-00",
                "operator_id": "operator-01",
                "queued_at": START + timedelta(seconds=104),
            }
        ],
        "delivery_attempts": [
            {
                **_identity_fields(0),
                "attempt_id": "attempt-00",
                "outbox_id": "outbox-00",
                "operator_id": "operator-01",
                "result": "delivered",
                "attempted_at": START + timedelta(seconds=105),
            }
        ],
        "repository_acknowledgements": acknowledgements,
        "repository_coverage": {
            "source_identity": "postgres-school-01",
            "canonical_query_sha256": DIGEST_B,
            "start_high_water": 0,
            "start_snapshot_sha256": DIGEST_C,
            "final_high_water": 20,
            "candidate_count": 20,
            "event_ids": [f"event-{index:02}" for index in range(20)],
            "acknowledged_event_ids": [f"event-{index:02}" for index in range(20)],
            "rows_sha256": "",
            "final_snapshot_sha256": "",
        },
        "retention_drills": retention_drills,
        "boot_transitions": [
            {
                "fault_id": "fault-runtime-restart",
                "component": "runtime",
                "observed_sample_index": 15,
                "from_boot_id": "runtime-boot-0",
                "to_boot_id": "runtime-boot-1",
                "schedule_sha256": DIGEST_B,
                "signature_sha256": DIGEST_C,
            },
            {
                "fault_id": "fault-api-restart",
                "component": "api",
                "observed_sample_index": 35,
                "from_boot_id": "api-boot-0",
                "to_boot_id": "api-boot-1",
                "schedule_sha256": DIGEST_B,
                "signature_sha256": DIGEST_C,
            },
        ],
    }
    _refresh_repository_claim(payload)
    return payload


def _json_bytes(payload: object) -> bytes:
    def encode(value: object) -> str:
        if isinstance(value, datetime):
            return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
        raise TypeError(f"unsupported test JSON value: {type(value).__name__}")

    return json.dumps(
        payload,
        default=encode,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _repository_rows(payload: dict[str, object]) -> list[dict[str, object]]:
    return [
        {
            "event_id": row["event_id"],
            "evidence_id": row["evidence_id"],
            "camera_id": row["camera_id"],
            "module": row["module"],
            "mode": row["mode"],
            "repository_sequence": row["repository_sequence"],
            "workflow": row["workflow"],
            "occurred_at": (
                row["occurred_at"].astimezone(UTC).isoformat().replace("+00:00", "Z")
                if isinstance(row["occurred_at"], datetime)
                else row["occurred_at"]
            ),
            "runtime_boot_id": row["runtime_boot_id"],
            "api_boot_id": row["api_boot_id"],
            "accuracy_claimed": row["accuracy_claimed"],
        }
        for row in payload["candidate_events"]  # type: ignore[union-attr]
    ]


def _repository_rows_digest(payload: dict[str, object]) -> str:
    return hashlib.sha256(_json_bytes(_repository_rows(payload))).hexdigest()


def _snapshot_digest(
    *,
    source_identity: str,
    canonical_query_sha256: str,
    start_high_water: int,
    final_high_water: int,
    row_count: int,
    rows_sha256: str,
) -> str:
    return hashlib.sha256(
        _json_bytes(
            {
                "schema_version": "authoritative-repository-snapshot.v1",
                "source_identity": source_identity,
                "canonical_query_sha256": canonical_query_sha256,
                "start_high_water": start_high_water,
                "final_high_water": final_high_water,
                "row_count": row_count,
                "rows_sha256": rows_sha256,
            }
        )
    ).hexdigest()


def _refresh_repository_claim(payload: dict[str, object]) -> None:
    coverage = payload["repository_coverage"]
    rows_sha256 = _repository_rows_digest(payload)
    coverage["rows_sha256"] = rows_sha256  # type: ignore[index]
    coverage["final_snapshot_sha256"] = _snapshot_digest(  # type: ignore[index]
        source_identity=coverage["source_identity"],  # type: ignore[index]
        canonical_query_sha256=coverage["canonical_query_sha256"],  # type: ignore[index]
        start_high_water=coverage["start_high_water"],  # type: ignore[index]
        final_high_water=coverage["final_high_water"],  # type: ignore[index]
        row_count=coverage["candidate_count"],  # type: ignore[index]
        rows_sha256=rows_sha256,
    )


def _repository_boundary_payload(
    authoritative_evidence: dict[str, object],
) -> dict[str, object]:
    coverage = authoritative_evidence["repository_coverage"]
    return {
        "schema_version": "authoritative-repository-boundary.v1",
        "site_id": authoritative_evidence["site_id"],
        "manifest_sha256": authoritative_evidence["manifest_sha256"],
        "source_identity": coverage["source_identity"],  # type: ignore[index]
        "canonical_query_sha256": coverage["canonical_query_sha256"],  # type: ignore[index]
        "start_high_water": coverage["start_high_water"],  # type: ignore[index]
        "final_high_water": coverage["final_high_water"],  # type: ignore[index]
        "row_count": coverage["candidate_count"],  # type: ignore[index]
        "ordered_event_ids": coverage["event_ids"],  # type: ignore[index]
        "rows_sha256": coverage["rows_sha256"],  # type: ignore[index]
        "snapshot_sha256": coverage["final_snapshot_sha256"],  # type: ignore[index]
        "captured_at": authoritative_evidence["ended_at"],
    }


def _parse_limits(payload: dict[str, object]) -> AcceptanceLimitsV1:
    return AcceptanceLimitsV1.model_validate_json(_json_bytes(payload))


def _parse_evidence(payload: dict[str, object]) -> OperationalAcceptanceEvidenceV1:
    return OperationalAcceptanceEvidenceV1.model_validate_json(_json_bytes(payload))


def _append_rejected_real_candidate(payload: dict[str, object]) -> None:
    identity = {
        "event_id": "event-real-00",
        "evidence_id": "evidence-real-00",
        "camera_id": CAMERAS[0],
        "module": "fire_smoke",
        "mode": "shadow",
        "repository_sequence": 21,
    }
    occurred_at = START + timedelta(seconds=300)
    payload["candidate_events"].append(  # type: ignore[union-attr]
        {
            **identity,
            "workflow": "real_candidate",
            "occurred_at": occurred_at,
            "runtime_boot_id": "runtime-boot-0",
            "api_boot_id": "api-boot-0",
            "accuracy_claimed": False,
        }
    )
    payload["evidence_ready"].append(  # type: ignore[union-attr]
        {
            **identity,
            "sha256": "f" * 64,
            "byte_size": 500,
            "duration_seconds": 5.0,
            "playable": True,
            "storage_identity": "kz-evidence-store-01",
            "object_key": "school-01/camera-00/event-real-00.mp4",
            "ready_at": occurred_at + timedelta(seconds=1),
        }
    )
    payload["final_evidence_store_observation"]["live_artifacts"].append(  # type: ignore[index,union-attr]
        {
            "object_key": "school-01/camera-00/event-real-00.mp4",
            "sha256": "f" * 64,
            "byte_size": 500,
            "storage_identity": "kz-evidence-store-01",
        }
    )
    payload["human_reviews"].append(  # type: ignore[union-attr]
        {
            **identity,
            "review_id": "review-real-00",
            "reviewer_role": "operator",
            "reviewer_id": "operator-02",
            "decision": "rejected",
            "reviewed_at": occurred_at + timedelta(seconds=2),
        }
    )
    payload["audit_rows"].append(  # type: ignore[union-attr]
        {
            **identity,
            "audit_id": "audit-real-00",
            "actor_role": "operator",
            "actor_id": "operator-02",
            "action": "review_rejected",
            "occurred_at": occurred_at + timedelta(seconds=3),
        }
    )
    payload["repository_acknowledgements"].append(  # type: ignore[union-attr]
        {
            **identity,
            "acknowledgement_id": "ack-real-00",
            "status": "complete",
            "acknowledged_at": occurred_at + timedelta(seconds=4),
        }
    )
    coverage = payload["repository_coverage"]
    coverage["final_high_water"] = 21  # type: ignore[index]
    coverage["candidate_count"] = 21  # type: ignore[index]
    coverage["event_ids"].append("event-real-00")  # type: ignore[index,union-attr]
    coverage["acknowledged_event_ids"].append("event-real-00")  # type: ignore[index,union-attr]
    _refresh_repository_claim(payload)


def _evaluate(
    evidence_payload: dict[str, object],
    limits_payload: dict[str, object] | None = None,
    *,
    authoritative_payload: dict[str, object] | None = None,
):
    limits = _parse_limits(limits_payload or _limits_payload())
    evidence = _parse_evidence(evidence_payload)
    boundary_payload = _repository_boundary_payload(authoritative_payload or evidence_payload)
    boundary = operational_module.AuthoritativeRepositoryBoundaryV1.model_validate_json(
        _json_bytes(boundary_payload)
    )
    return evaluate_operational_acceptance(
        limits,
        evidence,
        environment="target",
        repository_boundary=boundary,
    )


def test_honest_target_operational_evidence_passes_with_derived_summary() -> None:
    result = _evaluate(_evidence_payload())

    assert result.status == "pass"
    assert result.passed
    assert result.reasons == ()
    assert result.covered_sample_count == 481
    assert result.acceptance_drill_count == 20
    assert result.candidate_event_count == 20
    assert result.confirmed_and_delivered_count == 1
    assert result.rejected_count == 19
    assert result.max_store_bytes == {"evidence": 20_000, "metadata": 500}


def test_target_evaluator_fails_closed_when_operational_block_is_omitted() -> None:
    limits = _parse_limits(_limits_payload())

    result = evaluate_operational_acceptance(limits, None, environment="target")
    portable = evaluate_operational_acceptance(limits, None, environment="test_only")

    assert result.status == "fail"
    assert "operational evidence is required for target acceptance" in result.reasons
    assert portable.status == "not_evaluated"


def test_complete_real_candidate_is_accepted_but_any_lifecycle_hole_fails() -> None:
    complete = _evidence_payload()
    _append_rejected_real_candidate(complete)
    incomplete = deepcopy(complete)
    incomplete["evidence_ready"].pop()  # type: ignore[union-attr]

    assert _evaluate(complete).passed
    assert any("evidence-ready coverage" in item for item in _evaluate(incomplete).reasons)


def test_one_bounded_span_can_exhaustively_cover_a_72_hour_schedule() -> None:
    limits = _limits_payload()
    limits["gate"] = "72h"
    limits["ended_at"] = START + timedelta(hours=72)
    limits["expected_queue_samples"] = 4_321
    evidence = _evidence_payload()
    evidence["ended_at"] = START + timedelta(hours=72)
    evidence["sample_spans"][0]["sample_count"] = 4_321  # type: ignore[index]
    evidence["final_evidence_store_observation"]["sample_index"] = 4_320  # type: ignore[index]
    evidence["final_evidence_store_observation"]["observed_at"] = START + timedelta(  # type: ignore[index]
        hours=72
    )

    result = _evaluate(evidence, limits)

    assert result.passed
    assert result.covered_sample_count == 4_321


def test_missing_lifecycle_identity_is_rejected_by_strict_schema() -> None:
    payload = _evidence_payload()
    del payload["human_reviews"][0]["reviewer_id"]  # type: ignore[index]

    with pytest.raises(ValidationError, match="reviewer_id"):
        _parse_evidence(payload)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("playable", False, "playable"),
        ("duration_seconds", 3.9, "4-10 second"),
        ("storage_identity", "foreign-store", "storage identity"),
        ("evidence_id", "wrong-evidence", "identity-linked"),
    ],
)
def test_incomplete_or_unusable_evidence_fails(
    field: str,
    value: object,
    reason: str,
) -> None:
    payload = _evidence_payload()
    payload["evidence_ready"][0][field] = value  # type: ignore[index]

    result = _evaluate(payload)

    assert any(reason in item for item in result.reasons)


def test_shadow_or_disabled_event_can_never_queue_or_attempt_notification() -> None:
    payload = _evidence_payload()
    for collection in (
        "candidate_events",
        "evidence_ready",
        "human_reviews",
        "audit_rows",
        "outbox_queued",
        "delivery_attempts",
        "repository_acknowledgements",
    ):
        payload[collection][0]["module"] = "fire_smoke"  # type: ignore[index]
        payload[collection][0]["mode"] = "shadow"  # type: ignore[index]
    payload["candidate_events"][0]["workflow"] = "real_candidate"  # type: ignore[index]

    result = _evaluate(payload)

    assert any("shadow or disabled" in item for item in result.reasons)


def test_reused_event_identity_and_repository_coverage_holes_fail() -> None:
    reused = _evidence_payload()
    reused["evidence_ready"][1]["event_id"] = "event-00"  # type: ignore[index]
    hole = _evidence_payload()
    hole["repository_acknowledgements"].pop()  # type: ignore[union-attr]

    reused_result = _evaluate(reused)
    hole_result = _evaluate(hole)

    assert any("exactly one evidence-ready" in item for item in reused_result.reasons)
    assert any("repository acknowledgement coverage" in item for item in hole_result.reasons)


def test_orphan_notification_row_and_foreign_object_namespace_fail() -> None:
    orphan = _evidence_payload()
    orphan["outbox_queued"].append(  # type: ignore[union-attr]
        {
            **_identity_fields(0),
            "event_id": "orphan-event",
            "outbox_id": "orphan-outbox",
            "operator_id": "operator-01",
            "queued_at": START + timedelta(seconds=200),
        }
    )
    foreign_object = _evidence_payload()
    foreign_object["evidence_ready"][0]["object_key"] = (  # type: ignore[index]
        "school-01/camera-19/foreign.mp4"
    )

    assert any("orphan notification" in item for item in _evaluate(orphan).reasons)
    assert any("object namespace" in item for item in _evaluate(foreign_object).reasons)


def test_event_boot_identity_must_match_the_transition_timeline() -> None:
    payload = _evidence_payload()
    payload["candidate_events"][0]["occurred_at"] = START + timedelta(seconds=1_000)  # type: ignore[index]

    result = _evaluate(payload)

    assert any("boot identity timeline" in item for item in result.reasons)


@pytest.mark.parametrize("field", ["tracker_state_id", "analytic_state_id"])
def test_tracker_and_analytic_namespaces_cannot_be_shared(field: str) -> None:
    payload = _evidence_payload()
    namespaces = payload["sample_spans"][0]["camera_namespaces"]  # type: ignore[index]
    namespaces[1][field] = namespaces[0][field]

    result = _evaluate(payload)

    assert any("namespace reuse" in item for item in result.reasons)


def test_explicit_cross_camera_namespace_leakage_is_encoded_and_rejected() -> None:
    payload = _evidence_payload()
    payload["sample_spans"][0]["camera_namespaces"][0]["observed_camera_ids"] = [  # type: ignore[index]
        CAMERAS[0],
        CAMERAS[1],
    ]

    result = _evaluate(payload)

    assert any("cross-camera namespace leakage" in item for item in result.reasons)


def test_queue_capacity_mutation_and_counter_regression_fail() -> None:
    mutation = _evidence_payload()
    mutation["sample_spans"][0]["queues"][1]["capacity"] = 1_000_000  # type: ignore[index]
    mutation["sample_spans"][0]["sample_count"] = 240  # type: ignore[index]
    mutation["sample_spans"].append(  # type: ignore[union-attr]
        {
            "first_sample_index": 240,
            "sample_count": 241,
            "queues": _queue_rows(),
            "camera_namespaces": _namespace_rows(),
            "stores": _store_rows(),
        }
    )
    regression = _evidence_payload()
    regression["sample_spans"][0]["sample_count"] = 240  # type: ignore[index]
    first_queues = regression["sample_spans"][0]["queues"]  # type: ignore[index]
    first_queues[1]["dropped_total"] = 2
    second_queues = _queue_rows()
    second_queues[1]["dropped_total"] = 1
    regression["sample_spans"].append(  # type: ignore[union-attr]
        {
            "first_sample_index": 240,
            "sample_count": 241,
            "queues": second_queues,
            "camera_namespaces": _namespace_rows(),
            "stores": _store_rows(),
        }
    )

    mutated_result = _evaluate(mutation)
    regression_result = _evaluate(regression)

    assert any("capacity mutation" in item for item in mutated_result.reasons)
    assert any("counter regression" in item for item in regression_result.reasons)


def test_latest_only_sparse_and_overlapping_queue_coverage_fail() -> None:
    latest = _evidence_payload()
    latest["sample_spans"][0]["first_sample_index"] = 480  # type: ignore[index]
    latest["sample_spans"][0]["sample_count"] = 1  # type: ignore[index]
    overlap = _evidence_payload()
    overlap["sample_spans"][0]["sample_count"] = 300  # type: ignore[index]
    overlap["sample_spans"].append(  # type: ignore[union-attr]
        {
            "first_sample_index": 299,
            "sample_count": 182,
            "queues": _queue_rows(),
            "camera_namespaces": _namespace_rows(),
            "stores": _store_rows(),
        }
    )

    with pytest.raises(ValidationError, match="canonical"):
        _parse_evidence(latest)
    with pytest.raises(ValidationError, match="canonical"):
        _parse_evidence(overlap)


def test_linear_store_growth_fails_even_below_large_declared_limit() -> None:
    limits = _limits_payload()
    evidence_budget = limits["stores"][0]  # type: ignore[index]
    evidence_budget.update(  # type: ignore[union-attr]
        {
            "max_object_bytes": 1_000_000,
            "max_objects": 100,
            "max_bytes": 100_000_100,
        }
    )
    payload = _evidence_payload()
    payload["sample_spans"] = [
        {
            "first_sample_index": 0,
            "sample_count": 61,
            "queues": _queue_rows(),
            "camera_namespaces": _namespace_rows(),
            "stores": _store_rows(evidence_bytes=20_000, evidence_objects=40),
        },
        {
            "first_sample_index": 61,
            "sample_count": 210,
            "queues": _queue_rows(),
            "camera_namespaces": _namespace_rows(),
            "stores": _store_rows(evidence_bytes=21_000, evidence_objects=41),
        },
        {
            "first_sample_index": 271,
            "sample_count": 210,
            "queues": _queue_rows(),
            "camera_namespaces": _namespace_rows(),
            "stores": _store_rows(evidence_bytes=22_000, evidence_objects=42),
        },
    ]
    for span in payload["sample_spans"]:
        store = span["stores"][0]
        store["declared_max_bytes"] = 100_000_100

    result = _evaluate(payload, limits)

    assert any("projected plateau" in item for item in result.reasons)


def test_missing_or_foreign_retention_drill_fails() -> None:
    missing = _evidence_payload()
    missing["retention_drills"].pop()  # type: ignore[union-attr]
    foreign = _evidence_payload()
    foreign["retention_drills"][0]["storage_identity"] = "foreign-store"  # type: ignore[index]

    with pytest.raises(ValidationError, match="canonical"):
        _parse_evidence(missing)
    assert any("retention drill storage identity" in item for item in _evaluate(foreign).reasons)


@pytest.mark.parametrize("mutation", ["extra", "missing", "wrong"])
def test_boot_transitions_exactly_match_signed_restart_windows(mutation: str) -> None:
    payload = _evidence_payload()
    if mutation == "extra":
        payload["boot_transitions"].append(deepcopy(payload["boot_transitions"][0]))  # type: ignore[index,union-attr]
        payload["boot_transitions"][-1]["fault_id"] = "unscheduled-restart"  # type: ignore[index]
    elif mutation == "missing":
        payload["boot_transitions"].pop()  # type: ignore[union-attr]
    else:
        payload["boot_transitions"][0]["to_boot_id"] = "runtime-foreign"  # type: ignore[index]

    if mutation in {"extra", "missing"}:
        with pytest.raises(ValidationError, match="canonical"):
            _parse_evidence(payload)
    else:
        result = _evaluate(payload)
        assert any("boot transitions" in item for item in result.reasons)


def test_fire_and_weapon_dispositions_are_required_even_when_unscheduled() -> None:
    limits = _limits_payload()
    limits["module_dispositions"].pop()  # type: ignore[union-attr]

    with pytest.raises(ValidationError, match="fire_smoke and weapon"):
        _parse_limits(limits)


@pytest.mark.parametrize("mutation", ["count", "camera", "accuracy"])
def test_acceptance_drills_are_exactly_one_per_camera_and_never_accuracy_claims(
    mutation: str,
) -> None:
    payload = _evidence_payload()
    if mutation == "count":
        payload["candidate_events"].pop()  # type: ignore[union-attr]
    elif mutation == "camera":
        payload["candidate_events"][1]["camera_id"] = CAMERAS[0]  # type: ignore[index]
    else:
        payload["candidate_events"][0]["accuracy_claimed"] = True  # type: ignore[index]

    if mutation == "count":
        with pytest.raises(ValidationError, match="canonical"):
            _parse_evidence(payload)
    else:
        result = _evaluate(payload)
        assert any("acceptance drill" in item for item in result.reasons)


def test_nested_input_is_copied_and_models_are_deeply_immutable() -> None:
    payload = _evidence_payload()
    evidence = _parse_evidence(payload)
    payload["sample_spans"][0]["queues"][0]["depth"] = 7  # type: ignore[index]

    assert evidence.sample_spans[0].queues[0].depth == 0
    with pytest.raises(ValidationError):
        evidence.sample_spans[0].queues[0].depth = 7


def test_excessive_rows_spans_and_strings_are_rejected() -> None:
    payload = _evidence_payload()
    payload["candidate_events"] = [deepcopy(payload["candidate_events"][0])] * 4_097  # type: ignore[index]
    with pytest.raises(ValidationError, match="4096"):
        _parse_evidence(payload)

    payload = _evidence_payload()
    payload["sample_spans"] = [deepcopy(payload["sample_spans"][0])] * 10_001  # type: ignore[index]
    with pytest.raises(ValidationError, match="10000"):
        _parse_evidence(payload)

    payload = _evidence_payload()
    payload["candidate_events"][0]["event_id"] = "x" * 129  # type: ignore[index]
    with pytest.raises(ValidationError, match="128"):
        _parse_evidence(payload)


def test_canonical_serialization_and_digest_are_deterministic() -> None:
    first = _parse_evidence(_evidence_payload())
    second = OperationalAcceptanceEvidenceV1.model_validate_json(canonical_operational_json(first))

    assert canonical_operational_json(first) == canonical_operational_json(second)
    assert operational_evidence_sha256(first) == operational_evidence_sha256(second)


def _replace_spans(
    payload: dict[str, object],
    values: list[tuple[int, int, int, int]],
) -> None:
    payload["sample_spans"] = [
        {
            "first_sample_index": first,
            "sample_count": count,
            "queues": _queue_rows(),
            "camera_namespaces": _namespace_rows(),
            "stores": _store_rows(
                evidence_bytes=evidence_bytes,
                evidence_objects=evidence_objects,
            ),
        }
        for first, count, evidence_bytes, evidence_objects in values
    ]
    final_observation = payload["final_evidence_store_observation"]
    final_observation["used_bytes"] = values[-1][2]  # type: ignore[index]
    final_observation["object_count"] = values[-1][3]  # type: ignore[index]


def _stationary_cycle_spans(
    *,
    low_samples: int,
    high_samples: int,
    phase: int,
    total_samples: int = 481,
) -> list[tuple[int, int, int, int]]:
    period = low_samples + high_samples
    values: list[tuple[int, int, int, int]] = []
    for sample_index in range(total_samples):
        cycle_index = (sample_index + phase) % period
        used_bytes = 8_290 if cycle_index < low_samples else 10_000
        object_count = 20 if cycle_index < low_samples else 21
        if values and values[-1][2:] == (used_bytes, object_count):
            first, count, _, _ = values[-1]
            values[-1] = (first, count + 1, used_bytes, object_count)
        else:
            values.append((sample_index, 1, used_bytes, object_count))
    return values


def _stationary_jitter_spans(
    *,
    phase: int,
    total_samples: int = 481,
) -> list[tuple[int, int, int, int]]:
    values: list[tuple[int, int, int, int]] = []
    for sample_index in range(total_samples):
        shifted_index = sample_index + phase
        used_bytes = 8_290 + (shifted_index * 1_103_515_245 + 12_345) % 1_711
        object_count = 20 + ((shifted_index * 2_654_435_761 + 97) % 2)
        values.append((sample_index, 1, used_bytes, object_count))
    return values


def test_repository_coverage_cannot_shift_its_own_authoritative_sequence() -> None:
    payload = _evidence_payload()
    for candidate in payload["candidate_events"]:  # type: ignore[union-attr]
        candidate["repository_sequence"] += 1_000
    for acknowledgement in payload["repository_acknowledgements"]:  # type: ignore[union-attr]
        acknowledgement["repository_sequence"] += 1_000
    coverage = payload["repository_coverage"]
    coverage["start_high_water"] = 1_000  # type: ignore[index]
    coverage["final_high_water"] = 1_020  # type: ignore[index]
    _refresh_repository_claim(payload)

    result = _evaluate(payload, authoritative_payload=_evidence_payload())

    assert any("authoritative repository" in item for item in result.reasons)


def test_repository_evidence_cannot_omit_real_rows_and_rewrite_coverage() -> None:
    payload = _evidence_payload()
    _append_rejected_real_candidate(payload)
    for collection in (
        "candidate_events",
        "evidence_ready",
        "human_reviews",
        "audit_rows",
        "repository_acknowledgements",
    ):
        payload[collection].pop()  # type: ignore[union-attr]
    coverage = payload["repository_coverage"]
    coverage["final_high_water"] = 20  # type: ignore[index]
    coverage["candidate_count"] = 20  # type: ignore[index]
    coverage["event_ids"].pop()  # type: ignore[index,union-attr]
    coverage["acknowledged_event_ids"].pop()  # type: ignore[index,union-attr]
    _refresh_repository_claim(payload)

    authoritative = _evidence_payload()
    _append_rejected_real_candidate(authoritative)
    result = _evaluate(payload, authoritative_payload=authoritative)

    assert any("authoritative repository" in item for item in result.reasons)


def test_target_repository_boundary_is_a_distinct_required_input() -> None:
    assert hasattr(operational_module, "AuthoritativeRepositoryBoundaryV1")
    limits = _parse_limits(_limits_payload())
    evidence = _parse_evidence(_evidence_payload())

    result = evaluate_operational_acceptance(
        limits,
        evidence,
        environment="target",
        repository_boundary=None,
    )

    assert any("authoritative repository boundary is required" in item for item in result.reasons)


@pytest.mark.parametrize("mutation", ["source", "query", "truncated"])
def test_wrong_authoritative_repository_boundary_fails(mutation: str) -> None:
    evidence_payload = _evidence_payload()
    limits = _parse_limits(_limits_payload())
    evidence = _parse_evidence(evidence_payload)
    boundary_payload = _repository_boundary_payload(evidence_payload)
    if mutation == "source":
        boundary_payload["source_identity"] = "postgres-foreign"
    elif mutation == "query":
        boundary_payload["canonical_query_sha256"] = DIGEST_A
    else:
        truncated = deepcopy(evidence_payload)
        for collection in (
            "candidate_events",
            "evidence_ready",
            "human_reviews",
            "audit_rows",
            "repository_acknowledgements",
        ):
            truncated[collection].pop()  # type: ignore[union-attr]
        coverage = truncated["repository_coverage"]
        coverage["final_high_water"] = 19  # type: ignore[index]
        coverage["candidate_count"] = 19  # type: ignore[index]
        coverage["event_ids"].pop()  # type: ignore[index,union-attr]
        coverage["acknowledged_event_ids"].pop()  # type: ignore[index,union-attr]
        _refresh_repository_claim(truncated)
        boundary_payload = _repository_boundary_payload(truncated)
    boundary_payload["snapshot_sha256"] = _snapshot_digest(
        source_identity=boundary_payload["source_identity"],  # type: ignore[arg-type]
        canonical_query_sha256=boundary_payload["canonical_query_sha256"],  # type: ignore[arg-type]
        start_high_water=boundary_payload["start_high_water"],  # type: ignore[arg-type]
        final_high_water=boundary_payload["final_high_water"],  # type: ignore[arg-type]
        row_count=boundary_payload["row_count"],  # type: ignore[arg-type]
        rows_sha256=boundary_payload["rows_sha256"],  # type: ignore[arg-type]
    )
    boundary = operational_module.AuthoritativeRepositoryBoundaryV1.model_validate_json(
        _json_bytes(boundary_payload)
    )

    result = evaluate_operational_acceptance(
        limits,
        evidence,
        environment="target",
        repository_boundary=boundary,
    )

    assert any("authoritative repository" in item for item in result.reasons)


def test_wrong_authoritative_snapshot_digest_is_schema_error() -> None:
    boundary = _repository_boundary_payload(_evidence_payload())
    boundary["snapshot_sha256"] = DIGEST_A

    with pytest.raises(ValidationError, match="snapshot"):
        operational_module.AuthoritativeRepositoryBoundaryV1.model_validate_json(
            _json_bytes(boundary)
        )


def test_portable_evaluation_without_repository_boundary_is_not_evaluated() -> None:
    result = evaluate_operational_acceptance(
        _parse_limits(_limits_payload()),
        _parse_evidence(_evidence_payload()),
        environment="test_only",
        repository_boundary=None,
    )

    assert result.status == "not_evaluated"
    assert not result.passed


@pytest.mark.parametrize("environment", ["portable", True])
def test_unknown_or_non_string_environment_is_rejected(environment: object) -> None:
    with pytest.raises(ValueError, match="environment"):
        evaluate_operational_acceptance(
            _parse_limits(_limits_payload()),
            None,
            environment=environment,  # type: ignore[arg-type]
            repository_boundary=None,
        )


def test_nonlexical_manifest_camera_order_is_valid_when_evidence_matches() -> None:
    limits = _limits_payload()
    camera_order = list(reversed(CAMERAS))
    limits["camera_ids"] = camera_order
    limits["camera_namespaces"] = list(reversed(limits["camera_namespaces"]))  # type: ignore[arg-type]
    evidence = _evidence_payload()
    for span in evidence["sample_spans"]:  # type: ignore[union-attr]
        span["camera_namespaces"] = list(reversed(span["camera_namespaces"]))
    drills = evidence["retention_drills"]
    drills[:20] = list(reversed(drills[:20]))  # type: ignore[index]
    drills[20:] = list(reversed(drills[20:]))  # type: ignore[index]

    result = _evaluate(evidence, limits)

    assert result.passed


def test_stair_step_and_growing_sawtooth_are_not_plateaus() -> None:
    staircase = _evidence_payload()
    _replace_spans(
        staircase,
        [
            (0, 60, 20_000, 40),
            (60, 30, 19_000, 40),
            (90, 30, 21_000, 40),
            (120, 30, 19_500, 40),
            (150, 30, 22_000, 40),
            (180, 30, 20_000, 40),
            (210, 30, 23_000, 40),
            (240, 30, 20_500, 40),
            (270, 30, 24_000, 40),
            (300, 30, 21_000, 40),
            (330, 30, 25_000, 40),
            (360, 30, 21_500, 40),
            (390, 30, 26_000, 40),
            (420, 30, 22_000, 40),
            (450, 31, 27_000, 40),
        ],
    )

    result = _evaluate(staircase)

    assert any("retention-window plateau" in item for item in result.reasons)


def test_one_byte_per_window_rounding_growth_is_not_a_plateau() -> None:
    payload = _evidence_payload()
    values = [(0, 60, 20_000, 40)]
    values.extend((60 + index * 60, 60, 20_001 + index, 40) for index in range(7))
    values.append((480, 1, 20_008, 40))
    _replace_spans(payload, values)

    result = _evaluate(payload)

    assert any("retention-window plateau" in item for item in result.reasons)


def test_bounded_repeating_store_cycle_is_a_valid_plateau() -> None:
    payload = _evidence_payload()
    values = [(0, 60, 20_000, 40)]
    for window in range(7):
        values.extend(
            (
                (60 + window * 60, 30, 19_000, 39),
                (90 + window * 60, 30, 21_000, 41),
            )
        )
    values.append((480, 1, 19_000, 39))
    _replace_spans(payload, values)

    result = _evaluate(payload)

    assert result.passed


@pytest.mark.parametrize(
    ("low_samples", "high_samples", "phase", "window_samples"),
    [
        (30, 30, 0, 70),
        (30, 30, 17, 70),
        (10, 20, 7, 47),
        (20, 20, 31, 83),
    ],
)
def test_stationary_periodic_plateau_is_independent_of_phase_and_window(
    low_samples: int,
    high_samples: int,
    phase: int,
    window_samples: int,
) -> None:
    limits = _limits_payload()
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["plateau_observation_window_seconds"] = window_samples * 60
    payload = _evidence_payload()
    _replace_spans(
        payload,
        _stationary_cycle_spans(
            low_samples=low_samples,
            high_samples=high_samples,
            phase=phase,
        ),
    )

    result = _evaluate(payload, limits)

    assert result.passed, result.reasons


@pytest.mark.parametrize(
    ("phase", "window_samples"),
    [
        (0, 70),
        (13, 70),
        (97, 47),
        (211, 83),
    ],
)
def test_bounded_aperiodic_jitter_does_not_become_growth_from_window_phase(
    phase: int,
    window_samples: int,
) -> None:
    limits = _limits_payload()
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["plateau_observation_window_seconds"] = window_samples * 60
    payload = _evidence_payload()
    _replace_spans(payload, _stationary_jitter_spans(phase=phase))

    result = _evaluate(payload, limits)

    assert result.passed, result.reasons


@pytest.mark.parametrize("metric", ["bytes", "objects", "both"])
@pytest.mark.parametrize("amplitude", [1, 10])
@pytest.mark.parametrize("direction", ["spike", "dip"])
def test_bracketed_single_sample_store_deviation_passes_at_every_internal_index(
    direction: str,
    amplitude: int,
    metric: str,
) -> None:
    for outlier_index in range(1, 480):
        limits = _limits_payload()
        payload = _evidence_payload()
        byte_values = [20_000] * 481
        object_values = [40] * 481
        signed_amplitude = amplitude if direction == "spike" else -amplitude
        if metric in {"bytes", "both"}:
            byte_values[outlier_index] += signed_amplitude
        if metric in {"objects", "both"}:
            object_values[outlier_index] += signed_amplitude
        _replace_spans(payload, _canonical_store_spans(byte_values, object_values))

        result = _evaluate(payload, limits)

        assert result.passed, (
            direction,
            amplitude,
            metric,
            outlier_index,
            result.reasons,
        )


@pytest.mark.parametrize("metric", ["bytes", "objects", "both"])
@pytest.mark.parametrize("direction", ["spike", "dip"])
@pytest.mark.parametrize("deviation_start", [1, 58, 59, 60, 61, 120, 478])
def test_two_sample_store_deviation_after_warmup_clip_fails_closed(
    deviation_start: int,
    direction: str,
    metric: str,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [20_000] * 481
    object_values = [40] * 481
    signed_amplitude = 2 if direction == "spike" else -2
    for sample_index in (deviation_start, deviation_start + 1):
        if metric in {"bytes", "both"}:
            byte_values[sample_index] += signed_amplitude
        if metric in {"objects", "both"}:
            object_values[sample_index] += signed_amplitude
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in reason for reason in result.reasons), (
        deviation_start,
        direction,
        metric,
        result.reasons,
    )


@pytest.mark.parametrize("metric", ["bytes", "objects", "both"])
@pytest.mark.parametrize("direction", ["spike", "dip"])
@pytest.mark.parametrize("deviation_start", [1, 58, 59, 60, 61, 120, 477])
def test_paired_isolated_store_deviations_fail_closed(
    deviation_start: int,
    direction: str,
    metric: str,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [20_000] * 481
    object_values = [40] * 481
    signed_amplitude = 2 if direction == "spike" else -2
    for sample_index in (deviation_start, deviation_start + 2):
        if metric in {"bytes", "both"}:
            byte_values[sample_index] += signed_amplitude
        if metric in {"objects", "both"}:
            object_values[sample_index] += signed_amplitude
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in reason for reason in result.reasons), (
        deviation_start,
        direction,
        metric,
        result.reasons,
    )


@pytest.mark.parametrize("metric", ["bytes", "objects", "both"])
@pytest.mark.parametrize("direction", ["spike", "dip"])
@pytest.mark.parametrize("transition_sample", [1, 58, 59, 60, 61, 120, 479])
def test_unequal_flank_singleton_store_multistep_fails_closed(
    transition_sample: int,
    direction: str,
    metric: str,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [20_000] * 481
    object_values = [40] * 481
    first_delta, second_delta = (2, 1) if direction == "spike" else (-2, -1)
    if metric in {"bytes", "both"}:
        byte_values[transition_sample] += first_delta
        for sample_index in range(transition_sample + 1, 481):
            byte_values[sample_index] += second_delta
    if metric in {"objects", "both"}:
        object_values[transition_sample] += first_delta
        for sample_index in range(transition_sample + 1, 481):
            object_values[sample_index] += second_delta
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in reason for reason in result.reasons), (
        transition_sample,
        direction,
        metric,
        result.reasons,
    )


@pytest.mark.parametrize("metric", ["bytes", "objects", "both"])
@pytest.mark.parametrize("amplitude", [1, 10])
@pytest.mark.parametrize("direction", ["spike", "dip"])
@pytest.mark.parametrize("outlier_index", [0, 480])
def test_unbracketed_boundary_store_deviation_remains_fail_closed(
    outlier_index: int,
    direction: str,
    amplitude: int,
    metric: str,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [20_000] * 481
    object_values = [40] * 481
    signed_amplitude = amplitude if direction == "spike" else -amplitude
    if metric in {"bytes", "both"}:
        byte_values[outlier_index] += signed_amplitude
    if metric in {"objects", "both"}:
        object_values[outlier_index] += signed_amplitude
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in reason for reason in result.reasons), (
        outlier_index,
        direction,
        amplitude,
        metric,
        result.reasons,
    )


def test_nondivisible_rising_duty_cycle_remains_positive_growth() -> None:
    limits = _limits_payload()
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["plateau_observation_window_seconds"] = 70 * 60
    payload = _evidence_payload()
    values: list[tuple[int, int, int, int]] = []
    sample_index = 0
    for high_samples in (5, 10, 15, 20, 25, 30, 35, 40, 45):
        cycle_samples = min(60, 481 - sample_index)
        if cycle_samples <= 0:
            break
        low_samples = min(cycle_samples, 60 - high_samples)
        if low_samples:
            values.append((sample_index, low_samples, 8_290, 20))
            sample_index += low_samples
        remaining = cycle_samples - low_samples
        if remaining:
            values.append((sample_index, remaining, 10_000, 21))
            sample_index += remaining
    _replace_spans(payload, values)

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


def test_artifacts_must_fit_object_limit_and_observed_store_inventory() -> None:
    payload = _evidence_payload()
    payload["evidence_ready"][0]["byte_size"] = 4_000  # type: ignore[index]

    result = _evaluate(payload)

    assert any("artifact inventory" in item for item in result.reasons)


@pytest.mark.parametrize(
    "mutation",
    ["reordered", "unique_foreign", "cross_kind_alias"],
)
def test_namespaces_are_exact_ordered_and_manifest_bound(mutation: str) -> None:
    payload = _evidence_payload()
    namespaces = payload["sample_spans"][0]["camera_namespaces"]  # type: ignore[index]
    if mutation == "reordered":
        namespaces[0], namespaces[1] = namespaces[1], namespaces[0]
    elif mutation == "unique_foreign":
        namespaces[0]["tracker_state_id"] = "tracker:foreign-unique"
    else:
        namespaces[0]["tracker_state_id"] = namespaces[0]["source_state_id"]

    if mutation == "reordered":
        with pytest.raises(ValidationError, match="canonical"):
            _parse_evidence(payload)
    else:
        result = _evaluate(payload)
        assert any("manifest namespace" in item for item in result.reasons)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (QueueLimitV1, {"name": "decode", "capacity": "64"}),
        (
            QueueObservationV1,
            {"name": "decode", "depth": True, "capacity": 8, "dropped_total": 0},
        ),
        (
            EvidenceReadyArtifactV1,
            {
                **_identity_fields(0),
                "sha256": DIGEST_A,
                "byte_size": 500,
                "duration_seconds": "4.0",
                "playable": True,
                "storage_identity": "kz-evidence-store-01",
                "object_key": "school-01/camera-00/event-00.mp4",
                "ready_at": START.isoformat(),
            },
        ),
    ],
)
def test_python_validation_never_coerces_bool_numeric_or_datetime_values(
    model: object,
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)  # type: ignore[attr-defined]


def test_nonfinite_float_is_rejected() -> None:
    payload = {
        **_identity_fields(0),
        "sha256": DIGEST_A,
        "byte_size": 500,
        "duration_seconds": float("nan"),
        "playable": True,
        "storage_identity": "kz-evidence-store-01",
        "object_key": "school-01/camera-00/event-00.mp4",
        "ready_at": START,
    }

    with pytest.raises(ValidationError):
        EvidenceReadyArtifactV1.model_validate(payload)


def test_lifecycle_rows_cannot_escape_run_or_reorder_outbox_before_audit() -> None:
    after_run = _evidence_payload()
    after_run["delivery_attempts"][0]["attempted_at"] = END + timedelta(seconds=1)  # type: ignore[index]
    reordered = _evidence_payload()
    reordered["outbox_queued"][0]["queued_at"] = START + timedelta(seconds=102)  # type: ignore[index]

    after_result = _evaluate(after_run)
    reordered_result = _evaluate(reordered)

    assert any("exact run window" in item for item in after_result.reasons)
    assert any("audit precedes outbox" in item for item in reordered_result.reasons)


@pytest.mark.parametrize(
    ("collection", "field"),
    [
        ("evidence_ready", "object_key"),
        ("audit_rows", "audit_id"),
        ("repository_acknowledgements", "acknowledgement_id"),
        ("retention_drills", "drill_id"),
    ],
)
def test_stage_and_storage_identities_cannot_be_reused(
    collection: str,
    field: str,
) -> None:
    payload = _evidence_payload()
    payload[collection][1][field] = payload[collection][0][field]  # type: ignore[index]

    result = _evaluate(payload)

    assert any("identity reuse" in item for item in result.reasons)


def test_repository_acknowledgement_sequence_cannot_alias() -> None:
    payload = _evidence_payload()
    payload["repository_acknowledgements"][1]["repository_sequence"] = 1  # type: ignore[index]

    result = _evaluate(payload)

    assert any("identity reuse" in item for item in result.reasons)


def test_evidence_hash_cannot_be_reused_by_two_events_on_one_camera() -> None:
    payload = _evidence_payload()
    _append_rejected_real_candidate(payload)
    payload["evidence_ready"][-1]["sha256"] = payload["evidence_ready"][0]["sha256"]  # type: ignore[index]

    result = _evaluate(payload)

    assert any("identity reuse" in item for item in result.reasons)


@pytest.mark.parametrize(
    "collection",
    [
        "sample_spans",
        "candidate_events",
        "evidence_ready",
        "human_reviews",
        "audit_rows",
        "boot_transitions",
        "retention_drills",
    ],
)
def test_noncanonical_row_order_is_validation_error(collection: str) -> None:
    payload = _evidence_payload()
    if collection == "sample_spans":
        _replace_spans(payload, [(0, 240, 1_000, 10), (240, 241, 1_000, 10)])
    rows = payload[collection]
    rows[0], rows[1] = rows[1], rows[0]  # type: ignore[index]

    with pytest.raises(ValidationError, match="canonical"):
        _parse_evidence(payload)


def test_repository_coverage_arrays_and_attempts_require_canonical_order() -> None:
    coverage = _evidence_payload()
    acknowledged = coverage["repository_coverage"]["acknowledged_event_ids"]  # type: ignore[index]
    acknowledged[0], acknowledged[1] = acknowledged[1], acknowledged[0]
    with pytest.raises(ValidationError, match="canonical"):
        _parse_evidence(coverage)

    attempts = _evidence_payload()
    attempts["delivery_attempts"].append(  # type: ignore[union-attr]
        {
            **_identity_fields(0),
            "attempt_id": "attempt-before-delivery",
            "outbox_id": "outbox-00",
            "operator_id": "operator-01",
            "result": "failed",
            "attempted_at": START + timedelta(seconds=104, microseconds=500_000),
        }
    )
    with pytest.raises(ValidationError, match="canonical"):
        _parse_evidence(attempts)


def test_canonical_digest_binds_repository_row_content() -> None:
    payload = _evidence_payload()
    expected = _repository_rows_digest(payload)

    assert hasattr(operational_module, "repository_rows_sha256")
    evidence = _parse_evidence(payload)
    assert operational_module.repository_rows_sha256(evidence.candidate_events) == expected


def _duty_cycle_spans(high_counts: list[int]) -> list[tuple[int, int, int, int]]:
    values: list[tuple[int, int, int, int]] = [(0, 60, 20_000, 40)]
    for window, high_count in enumerate(high_counts):
        start = 60 + window * 60
        values.extend(
            (
                (start, 1, 19_000, 40),
                (start + 1, high_count, 21_000, 40),
                (start + 1 + high_count, 59 - high_count, 19_000, 40),
            )
        )
    values.append((480, 1, 19_000, 40))
    canonical: list[tuple[int, int, int, int]] = []
    for first, count, used_bytes, object_count in values:
        if (
            canonical
            and canonical[-1][0] + canonical[-1][1] == first
            and canonical[-1][2:] == (used_bytes, object_count)
        ):
            previous = canonical[-1]
            canonical[-1] = (
                previous[0],
                previous[1] + count,
                used_bytes,
                object_count,
            )
        else:
            canonical.append((first, count, used_bytes, object_count))
    return canonical


def test_rising_high_water_duty_cycle_fails_weighted_plateau() -> None:
    payload = _evidence_payload()
    _replace_spans(payload, _duty_cycle_spans([1, 9, 17, 25, 33, 41, 49]))

    result = _evaluate(payload)

    assert any("weighted mean" in item for item in result.reasons)


def test_repeating_weighted_duty_cycle_is_a_bounded_plateau() -> None:
    payload = _evidence_payload()
    _replace_spans(payload, _duty_cycle_spans([10] * 7))

    assert _evaluate(payload).passed


def test_evidence_inventory_includes_fixed_store_overhead_at_exact_boundary() -> None:
    too_small = _evidence_payload()
    artifact_bytes = sum(
        row["byte_size"]
        for row in too_small["evidence_ready"]  # type: ignore[union-attr]
    )
    for span in too_small["sample_spans"]:  # type: ignore[union-attr]
        span["stores"][0]["used_bytes"] = artifact_bytes
        span["stores"][0]["object_count"] = 20
    _attach_final_evidence_store_observation(too_small)
    exact = deepcopy(too_small)
    for span in exact["sample_spans"]:  # type: ignore[union-attr]
        span["stores"][0]["used_bytes"] = artifact_bytes + 100
    _attach_final_evidence_store_observation(exact)

    assert any("fixed overhead" in item for item in _evaluate(too_small).reasons)
    assert _evaluate(exact).passed


def test_evidence_inventory_reconciles_observed_object_count() -> None:
    payload = _evidence_payload()
    for span in payload["sample_spans"]:  # type: ignore[union-attr]
        span["stores"][0]["object_count"] = 19
    _attach_final_evidence_store_observation(payload)

    assert any("artifact inventory" in item for item in _evaluate(payload).reasons)


def test_evidence_inventory_must_still_exist_in_the_final_observation() -> None:
    payload = _evidence_payload()
    required_bytes = 100 + sum(
        row["byte_size"]
        for row in payload["evidence_ready"]  # type: ignore[union-attr]
    )
    _replace_spans(
        payload,
        [
            (0, 1, required_bytes, 20),
            (1, 480, 0, 0),
        ],
    )

    result = _evaluate(payload)

    assert any("final observed inventory" in item for item in result.reasons)


def _use_real_retention_windows(
    limits: dict[str, object],
    evidence: dict[str, object],
) -> None:
    retention_seconds = {
        "evidence": 30 * 24 * 60 * 60,
        "metadata": 365 * 24 * 60 * 60,
    }
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["retention_window_seconds"] = retention_seconds[budget["name"]]
        budget["plateau_observation_window_seconds"] = 3_600
    for drill in evidence["retention_drills"]:  # type: ignore[union-attr]
        drill["expired_at"] = START - timedelta(hours=1)
        drill["created_at"] = drill["expired_at"] - timedelta(
            seconds=retention_seconds[drill["store"]]
        )


def test_real_30_day_and_365_day_retention_use_separate_plateau_window() -> None:
    limits = _limits_payload()
    evidence = _evidence_payload()
    _use_real_retention_windows(limits, evidence)

    assert _evaluate(evidence, limits).passed


@pytest.mark.parametrize(
    ("gate", "cadence", "observation_window"),
    [
        ("8h", 60, 14_400),
        ("72h", 1, 1),
    ],
)
def test_impossible_or_excessive_plateau_window_count_is_rejected(
    gate: str,
    cadence: int,
    observation_window: int,
) -> None:
    limits = _limits_payload()
    limits["gate"] = gate
    limits["ended_at"] = START + timedelta(hours=8 if gate == "8h" else 72)
    limits["queue_sample_cadence_seconds"] = cadence
    duration = 28_800 if gate == "8h" else 259_200
    limits["expected_queue_samples"] = duration // cadence + 1
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["plateau_observation_window_seconds"] = observation_window

    with pytest.raises(ValidationError, match="plateau observation"):
        _parse_limits(limits)


def test_artifact_content_hash_is_globally_unique() -> None:
    payload = _evidence_payload()
    payload["evidence_ready"][1]["sha256"] = payload["evidence_ready"][0]["sha256"]  # type: ignore[index]

    result = _evaluate(payload)

    assert any("global identifier namespace" in item for item in result.reasons)


IDENTIFIER_KINDS = (
    "camera",
    "site",
    "state",
    "fault",
    "evidence_storage",
    "metadata_storage",
    "repository_source",
    "boot",
    "principal",
    "namespace",
    "event",
    "evidence",
    "review",
    "audit",
    "outbox",
    "attempt",
    "ack",
    "drill",
    "retention_object",
    "ready_object",
)
IDENTIFIER_ALIAS_PAIRS = tuple(
    (source, target)
    for source_index, source in enumerate(IDENTIFIER_KINDS)
    for target in IDENTIFIER_KINDS[source_index + 1 :]
)


def _identifier_value(
    payload: dict[str, object],
    limits: dict[str, object],
    kind: str,
) -> object:
    if kind == "camera":
        return limits["camera_ids"][0]  # type: ignore[index]
    if kind == "site":
        return limits["site_id"]
    if kind == "state":
        return limits["camera_namespaces"][0]["source_state_id"]  # type: ignore[index]
    if kind == "fault":
        return limits["restart_fault_windows"][0]["fault_id"]  # type: ignore[index]
    if kind == "evidence_storage":
        return limits["stores"][0]["storage_identity"]  # type: ignore[index]
    if kind == "metadata_storage":
        return limits["stores"][1]["storage_identity"]  # type: ignore[index]
    if kind == "repository_source":
        return limits["repository_source"]["source_identity"]  # type: ignore[index]
    if kind == "boot":
        return limits["restart_fault_windows"][0]["from_boot_id"]  # type: ignore[index]
    if kind == "principal":
        return payload["human_reviews"][0]["reviewer_id"]  # type: ignore[index]
    if kind == "namespace":
        return payload["retention_drills"][0]["namespace_id"]  # type: ignore[index]
    if kind == "retention_object":
        return payload["retention_drills"][0]["object_identity"]  # type: ignore[index]
    if kind == "ready_object":
        return payload["evidence_ready"][0]["object_key"]  # type: ignore[index]
    locations = {
        "event": ("candidate_events", "event_id"),
        "evidence": ("candidate_events", "evidence_id"),
        "review": ("human_reviews", "review_id"),
        "audit": ("audit_rows", "audit_id"),
        "outbox": ("outbox_queued", "outbox_id"),
        "attempt": ("delivery_attempts", "attempt_id"),
        "ack": ("repository_acknowledgements", "acknowledgement_id"),
        "drill": ("retention_drills", "drill_id"),
    }
    collection, field = locations[kind]
    return payload[collection][0][field]  # type: ignore[index]


def _set_identifier_alias(
    payload: dict[str, object],
    limits: dict[str, object],
    target: str,
    value: object,
) -> None:
    if target == "site":
        old_site_id = limits["site_id"]
        limits["site_id"] = value
        payload["site_id"] = value
        for artifact in payload["evidence_ready"]:  # type: ignore[union-attr]
            artifact["object_key"] = artifact["object_key"].replace(  # type: ignore[union-attr]
                f"{old_site_id}/",
                f"{value}/",
                1,
            )
    elif target == "state":
        limits["camera_namespaces"][0]["source_state_id"] = value  # type: ignore[index]
        for span in payload["sample_spans"]:  # type: ignore[union-attr]
            span["camera_namespaces"][0]["source_state_id"] = value
    elif target == "fault":
        limits["restart_fault_windows"][0]["fault_id"] = value  # type: ignore[index]
        payload["boot_transitions"][0]["fault_id"] = value  # type: ignore[index]
    elif target == "evidence_storage":
        limits["stores"][0]["storage_identity"] = value  # type: ignore[index]
        limits["evidence_storage_identity"] = value
        for span in payload["sample_spans"]:  # type: ignore[union-attr]
            span["stores"][0]["storage_identity"] = value
        for artifact in payload["evidence_ready"]:  # type: ignore[union-attr]
            artifact["storage_identity"] = value
        for drill in payload["retention_drills"]:  # type: ignore[union-attr]
            if drill["store"] == "evidence":
                drill["storage_identity"] = value
    elif target == "metadata_storage":
        limits["stores"][1]["storage_identity"] = value  # type: ignore[index]
        for span in payload["sample_spans"]:  # type: ignore[union-attr]
            span["stores"][1]["storage_identity"] = value
        for drill in payload["retention_drills"]:  # type: ignore[union-attr]
            if drill["store"] == "metadata":
                drill["storage_identity"] = value
    elif target == "repository_source":
        limits["repository_source"]["source_identity"] = value  # type: ignore[index]
        payload["repository_coverage"]["source_identity"] = value  # type: ignore[index]
        _refresh_repository_claim(payload)
    elif target == "boot":
        limits["restart_fault_windows"][0]["from_boot_id"] = value  # type: ignore[index]
        payload["boot_transitions"][0]["from_boot_id"] = value  # type: ignore[index]
        for candidate in payload["candidate_events"]:  # type: ignore[union-attr]
            candidate["runtime_boot_id"] = value
        _refresh_repository_claim(payload)
    elif target == "principal":
        for review in payload["human_reviews"]:  # type: ignore[union-attr]
            review["reviewer_id"] = value
        for audit in payload["audit_rows"]:  # type: ignore[union-attr]
            audit["actor_id"] = value
        for outbox in payload["outbox_queued"]:  # type: ignore[union-attr]
            outbox["operator_id"] = value
        for attempt in payload["delivery_attempts"]:  # type: ignore[union-attr]
            attempt["operator_id"] = value
    elif target == "namespace":
        payload["retention_drills"][0]["namespace_id"] = value  # type: ignore[index]
    elif target == "event":
        for collection in (
            "candidate_events",
            "evidence_ready",
            "human_reviews",
            "audit_rows",
            "outbox_queued",
            "delivery_attempts",
            "repository_acknowledgements",
        ):
            payload[collection][0]["event_id"] = value  # type: ignore[index]
        coverage = payload["repository_coverage"]
        coverage["event_ids"][0] = value  # type: ignore[index]
        coverage["acknowledged_event_ids"][0] = value  # type: ignore[index]
        _refresh_repository_claim(payload)
    elif target == "evidence":
        payload["candidate_events"][1]["evidence_id"] = value  # type: ignore[index]
        for collection in (
            "evidence_ready",
            "human_reviews",
            "audit_rows",
            "repository_acknowledgements",
        ):
            payload[collection][1]["evidence_id"] = value  # type: ignore[index]
        _refresh_repository_claim(payload)
    elif target == "review":
        payload["human_reviews"][0]["review_id"] = value  # type: ignore[index]
    elif target == "audit":
        payload["audit_rows"][0]["audit_id"] = value  # type: ignore[index]
    elif target == "outbox":
        payload["outbox_queued"][0]["outbox_id"] = value  # type: ignore[index]
        payload["delivery_attempts"][0]["outbox_id"] = value  # type: ignore[index]
    elif target == "attempt":
        payload["delivery_attempts"][0]["attempt_id"] = value  # type: ignore[index]
    elif target == "ack":
        payload["repository_acknowledgements"][0]["acknowledgement_id"] = value  # type: ignore[index]
    elif target == "drill":
        payload["retention_drills"][0]["drill_id"] = value  # type: ignore[index]
    elif target == "retention_object":
        payload["retention_drills"][0]["object_identity"] = value  # type: ignore[index]
    else:
        payload["evidence_ready"][0]["object_key"] = value  # type: ignore[index]
        payload["final_evidence_store_observation"]["live_artifacts"][0][  # type: ignore[index]
            "object_key"
        ] = value


@pytest.mark.parametrize(("source_kind", "target_kind"), IDENTIFIER_ALIAS_PAIRS)
def test_cross_kind_identifier_aliases_are_rejected(
    source_kind: str,
    target_kind: str,
) -> None:
    payload = _evidence_payload()
    limits = _limits_payload()
    _set_identifier_alias(
        payload,
        limits,
        target_kind,
        _identifier_value(payload, limits, source_kind),
    )

    result = _evaluate(payload, limits)

    assert any("global identifier namespace" in item for item in result.reasons)


@pytest.mark.parametrize("store_kind", ["evidence_storage", "metadata_storage"])
def test_repository_source_owner_cannot_alias_a_store_owner(store_kind: str) -> None:
    payload = _evidence_payload()
    limits = _limits_payload()
    _set_identifier_alias(
        payload,
        limits,
        "repository_source",
        _identifier_value(payload, limits, store_kind),
    )

    result = _evaluate(payload, limits)

    assert any("global identifier namespace" in item for item in result.reasons)


def test_boot_owner_ids_cannot_alias_across_components() -> None:
    payload = _evidence_payload()
    limits = _limits_payload()
    shared_boot_id = limits["restart_fault_windows"][0]["from_boot_id"]  # type: ignore[index]
    limits["restart_fault_windows"][1]["from_boot_id"] = shared_boot_id  # type: ignore[index]
    payload["boot_transitions"][1]["from_boot_id"] = shared_boot_id  # type: ignore[index]
    for candidate in payload["candidate_events"]:  # type: ignore[union-attr]
        candidate["api_boot_id"] = shared_boot_id
    _refresh_repository_claim(payload)

    result = _evaluate(payload, limits)

    assert any("global identifier namespace" in item for item in result.reasons)


def test_one_operator_principal_can_repeat_across_its_linked_lifecycle_rows() -> None:
    payload = _evidence_payload()
    operator_id = payload["human_reviews"][0]["reviewer_id"]  # type: ignore[index]

    assert all(
        row["reviewer_id"] == operator_id
        for row in payload["human_reviews"]  # type: ignore[union-attr]
    )
    assert all(
        row["actor_id"] == operator_id
        for row in payload["audit_rows"]  # type: ignore[union-attr]
    )
    assert payload["outbox_queued"][0]["operator_id"] == operator_id  # type: ignore[index]
    assert payload["delivery_attempts"][0]["operator_id"] == operator_id  # type: ignore[index]
    assert _evaluate(payload).passed


@pytest.mark.parametrize(
    "wrong_boundary",
    [
        object(),
        True,
        {"schema_version": "authoritative-repository-boundary.v1"},
        _parse_evidence(_evidence_payload()),
    ],
)
def test_wrong_repository_boundary_type_is_deterministic_fail_closed(
    wrong_boundary: object,
) -> None:
    result = evaluate_operational_acceptance(
        _parse_limits(_limits_payload()),
        _parse_evidence(_evidence_payload()),
        environment="target",
        repository_boundary=wrong_boundary,  # type: ignore[arg-type]
    )

    assert result.status == "fail"
    assert any("boundary type" in item for item in result.reasons)


def test_portable_wrong_repository_boundary_type_is_not_evaluated() -> None:
    result = evaluate_operational_acceptance(
        _parse_limits(_limits_payload()),
        _parse_evidence(_evidence_payload()),
        environment="test_only",
        repository_boundary={},
    )

    assert result.status == "not_evaluated"


def test_plateau_scanner_is_linear_for_72h_10k_runs() -> None:
    assert hasattr(operational_module, "_scan_weighted_plateau_runs")
    total_samples = 259_201
    run_count = 10_000
    base, remainder = divmod(total_samples, run_count)
    runs = []
    first = 0
    for index in range(run_count):
        count = base + (1 if index < remainder else 0)
        runs.append((first, count, 20_000, 40))
        first += count

    scan = operational_module._scan_weighted_plateau_runs(
        tuple(runs),
        window_samples=60,
        expected_samples=total_samples,
    )

    assert scan.window_count == 4_319
    assert scan.windows[-1].weight == 61
    assert min(window.weight for window in scan.windows) >= 60
    assert sum(window.weight for window in scan.windows) == 259_141
    assert scan.scan_steps <= run_count + scan.window_count


def test_phase_independent_trend_traverses_10k_rle_runs_once() -> None:
    assert hasattr(operational_module, "_has_material_positive_store_trend")

    class CountingRuns:
        def __init__(self, rows: tuple[tuple[int, int, int, int], ...]) -> None:
            self.rows = rows
            self.traversed = 0

        def __iter__(self):
            for row in self.rows:
                self.traversed += 1
                yield row

    rows = tuple(
        (sample_index, 1, 8_290 + sample_index % 2, 20 + sample_index % 2)
        for sample_index in range(10_000)
    )
    counted = CountingRuns(rows)

    assert not operational_module._has_material_positive_store_trend(
        counted,
        warmup_samples=0,
        expected_samples=10_000,
    )
    assert counted.traversed == len(rows)


def test_plateau_scanner_rejects_an_excessive_window_count() -> None:
    with pytest.raises(ValueError, match="bounded"):
        operational_module._scan_weighted_plateau_runs(
            ((0, 10_002, 20_000, 40),),
            window_samples=1,
            expected_samples=10_002,
        )


def test_nondivisible_plateau_scanner_covers_the_exact_trailing_remainder() -> None:
    scan = operational_module._scan_weighted_plateau_runs(
        (
            (0, 420, 20_000, 40),
            (420, 60, 90_000, 90),
            (480, 1, 20_000, 40),
        ),
        window_samples=70,
        expected_samples=481,
    )

    assert tuple(window.weight for window in scan.windows) == (70, 70, 70, 70, 131)
    assert sum(window.weight for window in scan.windows) == 411


def test_growth_in_nondivisible_trailing_tail_cannot_reset_at_endpoint() -> None:
    limits = _limits_payload()
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["plateau_observation_window_seconds"] = 4_200
    payload = _evidence_payload()
    _replace_spans(
        payload,
        [
            (0, 420, 20_000, 40),
            (420, 60, 90_000, 90),
            (480, 1, 20_000, 40),
        ],
    )

    result = _evaluate(payload, limits)

    assert any("plateau" in item for item in result.reasons)


def test_artifact_inventory_requires_one_joint_byte_and_object_observation() -> None:
    payload = _evidence_payload()
    values: list[tuple[int, int, int, int]] = []
    for window in range(8):
        values.extend(
            (
                (window * 60, 30, 8_290, 19),
                (window * 60 + 30, 30, 8_289, 20),
            )
        )
    values.append((480, 1, 8_290, 19))
    _replace_spans(payload, values)

    result = _evaluate(payload)

    assert any("final observed inventory" in item for item in result.reasons)


@pytest.mark.parametrize(
    ("field", "before", "after"),
    [
        ("bytes_reclaimed", 1_000_000_000_000, None),
        ("objects_before", 101, 100),
    ],
)
def test_retention_drill_claims_are_bounded_by_the_signed_store_budget(
    field: str,
    before: int,
    after: int | None,
) -> None:
    payload = _evidence_payload()
    drill = payload["retention_drills"][0]  # type: ignore[index]
    drill[field] = before
    if after is not None:
        drill["objects_after"] = after

    result = _evaluate(payload)

    assert any("signed store budget" in item for item in result.reasons)


def test_adjacent_identical_sample_spans_are_not_canonical_rle() -> None:
    payload = _evidence_payload()
    first = deepcopy(payload["sample_spans"][0])  # type: ignore[index]
    second = deepcopy(first)
    first["sample_count"] = 240
    second["first_sample_index"] = 240
    second["sample_count"] = 241
    payload["sample_spans"] = [first, second]

    with pytest.raises(ValidationError, match="canonical RLE"):
        _parse_evidence(payload)


def _set_evidence_store_budget(
    limits: dict[str, object],
    payload: dict[str, object],
    *,
    max_object_bytes: int,
    max_objects: int,
) -> None:
    max_bytes = 100 + max_object_bytes * max_objects
    evidence_budget = limits["stores"][0]  # type: ignore[index]
    evidence_budget["max_object_bytes"] = max_object_bytes
    evidence_budget["max_objects"] = max_objects
    evidence_budget["max_bytes"] = max_bytes
    for span in payload["sample_spans"]:  # type: ignore[union-attr]
        store = span["stores"][0]
        store["declared_max_bytes"] = max_bytes
        store["declared_max_objects"] = max_objects


@pytest.mark.parametrize("outlier_index", [60, 61, 120, 270, 479, 480])
@pytest.mark.parametrize("metric", ["bytes", "objects"])
def test_single_extreme_store_outlier_cannot_hide_sustained_growth(
    outlier_index: int,
    metric: str,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    values: list[tuple[int, int, int, int]] = []
    for sample_index in range(481):
        growing_value = 10_000 + 2_000 * sample_index
        adversarial_value = 10_000_000 if sample_index == outlier_index else growing_value
        values.append(
            (
                sample_index,
                1,
                adversarial_value if metric == "bytes" else 20_000,
                adversarial_value if metric == "objects" else 40,
            )
        )
    _replace_spans(payload, values)
    if metric == "bytes":
        _set_evidence_store_budget(
            limits,
            payload,
            max_object_bytes=100_000,
            max_objects=100,
        )
    else:
        _set_evidence_store_budget(
            limits,
            payload,
            max_object_bytes=1_000,
            max_objects=10_000_000,
        )

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


@pytest.mark.parametrize("phase", [1, 17, 41, 59])
def test_one_byte_per_sample_drift_is_rejected_on_phase_shifted_square_cycle(
    phase: int,
) -> None:
    limits = _limits_payload()
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["plateau_observation_window_seconds"] = 70 * 60
    payload = _evidence_payload()
    values: list[tuple[int, int, int, int]] = []
    for sample_index in range(481):
        cycle_index = (sample_index + phase) % 60
        stationary_value = 8_290 if cycle_index < 30 else 10_000
        values.append((sample_index, 1, stationary_value + sample_index, 40))
    _replace_spans(payload, values)

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


@pytest.mark.parametrize("phase", [0, 7, 19, 39])
def test_object_staircase_is_rejected_on_twenty_sample_square_oscillation(
    phase: int,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    values: list[tuple[int, int, int, int]] = []
    for sample_index in range(481):
        stationary_value = 20 if ((sample_index + phase) // 20) % 2 == 0 else 100
        observation = (20_000, stationary_value + sample_index // 20)
        if values and values[-1][2:] == observation:
            first, count, used_bytes, object_count = values[-1]
            values[-1] = (first, count + 1, used_bytes, object_count)
        else:
            values.append((sample_index, 1, *observation))
    _replace_spans(payload, values)
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=1_000,
        max_objects=200,
    )

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


@pytest.mark.parametrize("phase", range(82))
def test_stationary_82_sample_square_cycle_passes_at_every_phase(phase: int) -> None:
    limits = _limits_payload()
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["plateau_observation_window_seconds"] = 70 * 60
    payload = _evidence_payload()
    _replace_spans(
        payload,
        _stationary_cycle_spans(
            low_samples=54,
            high_samples=28,
            phase=phase,
        ),
    )

    result = _evaluate(payload, limits)

    assert result.passed, (phase, result.reasons)


def _attach_final_evidence_store_observation(payload: dict[str, object]) -> None:
    final_span = payload["sample_spans"][-1]  # type: ignore[index]
    final_store = final_span["stores"][0]
    payload["final_evidence_store_observation"] = {
        "sample_index": 480,
        "observed_at": END,
        "storage_identity": "kz-evidence-store-01",
        "used_bytes": final_store["used_bytes"],
        "object_count": final_store["object_count"],
        "live_artifacts": [
            {
                "object_key": row["object_key"],
                "sha256": row["sha256"],
                "byte_size": row["byte_size"],
                "storage_identity": row["storage_identity"],
            }
            for row in payload["evidence_ready"]  # type: ignore[union-attr]
        ],
    }


def test_signed_final_evidence_store_observation_binds_live_artifact_keys() -> None:
    payload = _evidence_payload()
    _attach_final_evidence_store_observation(payload)

    assert _evaluate(payload).passed

    wrong_identity = deepcopy(payload)
    wrong_identity["final_evidence_store_observation"]["live_artifacts"][-1][  # type: ignore[index]
        "object_key"
    ] = "school-01/camera-19/foreign.mp4"
    result = _evaluate(wrong_identity)

    assert any("exact live artifact inventory" in item for item in result.reasons)


def test_final_evidence_store_observation_must_follow_every_ready_artifact() -> None:
    payload = _evidence_payload()
    for collection, field in (
        ("evidence_ready", "ready_at"),
        ("human_reviews", "reviewed_at"),
        ("audit_rows", "occurred_at"),
        ("repository_acknowledgements", "acknowledged_at"),
    ):
        payload[collection][0][field] = END  # type: ignore[index]
    payload["outbox_queued"][0]["queued_at"] = END  # type: ignore[index]
    payload["delivery_attempts"][0]["attempted_at"] = END  # type: ignore[index]
    _attach_final_evidence_store_observation(payload)

    result = _evaluate(payload)

    assert any("strictly follow every evidence-ready artifact" in item for item in result.reasons)


def test_retention_drill_cannot_alias_a_live_artifact_with_evidence_site_id() -> None:
    limits = _limits_payload()
    limits["site_id"] = "evidence"
    payload = _evidence_payload()
    payload["site_id"] = "evidence"
    for artifact in payload["evidence_ready"]:  # type: ignore[union-attr]
        artifact["object_key"] = artifact["object_key"].replace("school-01/", "evidence/", 1)
    payload["retention_drills"][0]["object_identity"] = payload["evidence_ready"][0][  # type: ignore[index]
        "object_key"
    ]

    result = _evaluate(payload, limits)

    assert any("retention drill object aliases a live artifact" in item for item in result.reasons)


def test_lifecycle_stage_transitions_are_strictly_ordered_before_final_observation() -> None:
    payload = _evidence_payload()
    for collection, field in (
        ("evidence_ready", "ready_at"),
        ("human_reviews", "reviewed_at"),
        ("audit_rows", "occurred_at"),
        ("repository_acknowledgements", "acknowledged_at"),
    ):
        for row in payload[collection]:  # type: ignore[union-attr]
            row[field] = END
    payload["outbox_queued"][0]["queued_at"] = END  # type: ignore[index]
    payload["delivery_attempts"][0]["attempted_at"] = END  # type: ignore[index]

    result = _evaluate(payload)

    assert any("strict lifecycle order" in item for item in result.reasons)


def _canonical_store_spans(
    byte_values: list[int],
    object_values: list[int],
) -> list[tuple[int, int, int, int]]:
    assert len(byte_values) == len(object_values) == 481
    spans: list[tuple[int, int, int, int]] = []
    for sample_index, observation in enumerate(zip(byte_values, object_values, strict=True)):
        if spans and spans[-1][2:] == observation:
            first, count, used_bytes, object_count = spans[-1]
            spans[-1] = (first, count + 1, used_bytes, object_count)
        else:
            spans.append((sample_index, 1, *observation))
    return spans


@pytest.mark.parametrize("metric", ["bytes", "objects"])
def test_two_interior_extreme_samples_cannot_hide_unbounded_store_growth(
    metric: str,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [10_000 + 2_000 * sample_index for sample_index in range(481)]
    object_values = [100 + 10 * sample_index for sample_index in range(481)]
    for sample_index in (120, 270):
        if metric == "bytes":
            byte_values[sample_index] = 100_000_000
        else:
            object_values[sample_index] = 10_000_000
    if metric == "bytes":
        object_values = [40] * 481
    else:
        byte_values = [20_000] * 481
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=1_000_000 if metric == "bytes" else 1_000,
        max_objects=100 if metric == "bytes" else 10_000_000,
    )

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


@pytest.mark.parametrize(
    ("outlier_value", "outlier_positions"),
    [
        (100_000_000, (120, 121, 122, 270, 271, 272)),
        (900_000_000, (119, 120, 121, 269, 270, 271)),
    ],
)
def test_clustered_arbitrary_amplitude_outliers_do_not_restore_a_range_heuristic(
    outlier_value: int,
    outlier_positions: tuple[int, ...],
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [10_000 + 2_000 * sample_index for sample_index in range(481)]
    for sample_index in outlier_positions:
        byte_values[sample_index] = outlier_value
    _replace_spans(
        payload,
        _canonical_store_spans(byte_values, [40] * 481),
    )
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=outlier_value // 100,
        max_objects=100,
    )

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


def test_growing_period_200_sawtooth_is_not_hidden_beyond_a_fixed_lag_horizon() -> None:
    payload = _evidence_payload()
    byte_values = [10_000 + sample_index % 200 + sample_index // 200 for sample_index in range(481)]
    _replace_spans(
        payload,
        _canonical_store_spans(byte_values, [40] * 481),
    )

    result = _evaluate(payload)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


@pytest.mark.parametrize("phase", range(200))
def test_stationary_period_200_sawtooth_passes_at_every_phase(phase: int) -> None:
    payload = _evidence_payload()
    byte_values = [10_000 + (sample_index + phase) % 200 for sample_index in range(481)]
    _replace_spans(
        payload,
        _canonical_store_spans(byte_values, [40] * 481),
    )

    result = _evaluate(payload)

    assert result.passed, (phase, result.reasons)


@pytest.mark.parametrize("phase", [0, 11, 41, 81])
@pytest.mark.parametrize("high_value", [10_001, 100_000_000])
def test_stationary_square_cycle_acceptance_is_independent_of_amplitude(
    phase: int,
    high_value: int,
) -> None:
    limits = _limits_payload()
    for budget in limits["stores"]:  # type: ignore[union-attr]
        budget["plateau_observation_window_seconds"] = 70 * 60
    payload = _evidence_payload()
    byte_values = [
        10_000 if (sample_index + phase) % 82 < 54 else high_value for sample_index in range(481)
    ]
    _replace_spans(
        payload,
        _canonical_store_spans(byte_values, [40] * 481),
    )
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=1_000_000,
        max_objects=100,
    )

    result = _evaluate(payload, limits)

    assert result.passed, (phase, high_value, result.reasons)


def _attach_typed_final_artifact_inventory(payload: dict[str, object]) -> None:
    observation = payload["final_evidence_store_observation"]
    observation["live_artifacts"] = [  # type: ignore[index]
        {
            "object_key": artifact["object_key"],
            "sha256": artifact["sha256"],
            "byte_size": artifact["byte_size"],
            "storage_identity": artifact["storage_identity"],
        }
        for artifact in payload["evidence_ready"]  # type: ignore[union-attr]
    ]
    observation.pop("live_object_keys", None)  # type: ignore[union-attr]


def test_final_inventory_uses_exact_ordered_typed_artifact_rows() -> None:
    payload = _evidence_payload()
    _attach_typed_final_artifact_inventory(payload)

    assert _evaluate(payload).passed

    reordered = deepcopy(payload)
    inventory = reordered["final_evidence_store_observation"]["live_artifacts"]  # type: ignore[index]
    inventory[0], inventory[1] = inventory[1], inventory[0]

    result = _evaluate(reordered)

    assert any("exact live artifact inventory" in item for item in result.reasons)


def test_same_key_artifact_content_swap_fails_with_constant_aggregate_inventory() -> None:
    payload = _evidence_payload()
    _attach_typed_final_artifact_inventory(payload)
    inventory = payload["final_evidence_store_observation"]["live_artifacts"]  # type: ignore[index]
    original_total = sum(row["byte_size"] for row in inventory)
    inventory[0]["sha256"], inventory[1]["sha256"] = (
        inventory[1]["sha256"],
        inventory[0]["sha256"],
    )
    inventory[0]["byte_size"], inventory[1]["byte_size"] = (
        inventory[1]["byte_size"],
        inventory[0]["byte_size"],
    )

    result = _evaluate(payload)

    assert sum(row["byte_size"] for row in inventory) == original_total
    assert any("exact live artifact inventory" in item for item in result.reasons)


def test_final_inventory_rejects_shared_nested_artifact_rows() -> None:
    payload = _evidence_payload()
    _attach_typed_final_artifact_inventory(payload)
    inventory = payload["final_evidence_store_observation"]["live_artifacts"]  # type: ignore[index]
    inventory[1] = inventory[0]

    with pytest.raises(ValidationError, match="unique"):
        _parse_evidence(payload)


def test_typed_final_inventory_is_deeply_copied_and_immutable() -> None:
    payload = _evidence_payload()
    _attach_typed_final_artifact_inventory(payload)
    input_row = payload["final_evidence_store_observation"]["live_artifacts"][0]  # type: ignore[index]
    original_sha256 = input_row["sha256"]
    evidence = _parse_evidence(payload)
    input_row["sha256"] = "f" * 64

    assert evidence.final_evidence_store_observation.live_artifacts[0].sha256 == original_sha256
    with pytest.raises(ValidationError):
        evidence.final_evidence_store_observation.live_artifacts[0].byte_size = 1


@pytest.mark.parametrize(
    ("collection", "field"),
    [
        ("evidence_ready", "ready_at"),
        ("human_reviews", "reviewed_at"),
        ("audit_rows", "occurred_at"),
        ("outbox_queued", "queued_at"),
        ("delivery_attempts", "attempted_at"),
        ("repository_acknowledgements", "acknowledged_at"),
    ],
)
def test_final_inventory_observation_strictly_follows_every_lifecycle_timestamp(
    collection: str,
    field: str,
) -> None:
    payload = _evidence_payload()
    payload[collection][0][field] = END  # type: ignore[index]

    result = _evaluate(payload)

    assert any(
        "strictly follow every terminal lifecycle timestamp" in item for item in result.reasons
    )


@pytest.mark.parametrize("alias_source", ["retention", "ready"])
def test_event_identity_cannot_alias_storage_object_identity(alias_source: str) -> None:
    payload = _evidence_payload()
    old_event_id = payload["candidate_events"][0]["event_id"]  # type: ignore[index]
    if alias_source == "retention":
        alias = payload["retention_drills"][0]["object_identity"]  # type: ignore[index]
    else:
        alias = payload["evidence_ready"][0]["object_key"]  # type: ignore[index]
    for collection in (
        "candidate_events",
        "evidence_ready",
        "human_reviews",
        "audit_rows",
        "outbox_queued",
        "delivery_attempts",
        "repository_acknowledgements",
    ):
        for row in payload[collection]:  # type: ignore[union-attr]
            if row["event_id"] == old_event_id:
                row["event_id"] = alias
    coverage = payload["repository_coverage"]
    coverage["event_ids"][0] = alias  # type: ignore[index]
    coverage["acknowledged_event_ids"][0] = alias  # type: ignore[index]
    _refresh_repository_claim(payload)

    result = _evaluate(payload)

    assert any("identity reuse" in item for item in result.reasons)


def test_intended_event_identity_foreign_key_repetitions_remain_valid() -> None:
    payload = _evidence_payload()
    event_id = payload["candidate_events"][0]["event_id"]  # type: ignore[index]

    assert all(
        collection[0]["event_id"] == event_id
        for collection in (
            payload["evidence_ready"],
            payload["human_reviews"],
            payload["audit_rows"],
            payload["outbox_queued"],
            payload["delivery_attempts"],
            payload["repository_acknowledgements"],
        )
    )
    assert _evaluate(payload).passed


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("byte_size", True),
        ("byte_size", 1.0),
        ("byte_size", float("nan")),
        ("byte_size", 64_000_001),
        ("storage_identity", True),
        ("object_key", ["school-01/camera-00/event-00.mp4"]),
    ],
)
def test_final_artifact_inventory_rows_have_strict_finite_bounded_types(
    field: str,
    value: object,
) -> None:
    payload = {
        "object_key": "school-01/camera-00/event-00.mp4",
        "sha256": DIGEST_A,
        "byte_size": 400,
        "storage_identity": "kz-evidence-store-01",
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        operational_module.FinalEvidenceArtifactObservationV1.model_validate(payload)


def test_final_artifact_inventory_tuple_has_the_signed_event_bound() -> None:
    payload = _evidence_payload()
    row = payload["final_evidence_store_observation"]["live_artifacts"][0]  # type: ignore[index]
    payload["final_evidence_store_observation"]["live_artifacts"] = [  # type: ignore[index]
        {
            **row,
            "object_key": f"school-01/camera-00/object-{index:04}.mp4",
            "sha256": f"{index + 5_000:064x}",
        }
        for index in range(4_097)
    ]

    with pytest.raises(ValidationError, match="4096"):
        _parse_evidence(payload)


def test_full_horizon_rank_arithmetic_handles_10k_max_scale_integer_runs() -> None:
    rows = tuple(
        (
            sample_index,
            1,
            999_999_999_998 + sample_index % 2,
            9_999_998 + sample_index % 2,
        )
        for sample_index in range(10_000)
    )

    assert not operational_module._has_material_positive_store_trend(
        rows,
        warmup_samples=0,
        expected_samples=10_000,
    )


@pytest.mark.parametrize("metric", ["bytes", "objects"])
def test_translated_period_129_store_cycle_is_positive_growth(metric: str) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [
        10_000 + 100_000 * (sample_index % 129) + 1_000_000 * (sample_index // 129)
        for sample_index in range(481)
    ]
    object_values = [
        100 + 1_000 * (sample_index % 129) + 10_000 * (sample_index // 129)
        for sample_index in range(481)
    ]
    if metric == "bytes":
        object_values = [40] * 481
        _set_evidence_store_budget(
            limits,
            payload,
            max_object_bytes=200_000,
            max_objects=100,
        )
    else:
        byte_values = [20_000] * 481
        _set_evidence_store_budget(
            limits,
            payload,
            max_object_bytes=1_000,
            max_objects=200_000,
        )
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


@pytest.mark.parametrize("phase", range(129))
def test_stationary_period_129_store_cycle_passes_at_every_phase(phase: int) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [10_000 + 100_000 * ((sample_index + phase) % 129) for sample_index in range(481)]
    object_values = [100 + 1_000 * ((sample_index + phase) % 129) for sample_index in range(481)]
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=200_000,
        max_objects=200_000,
    )

    result = _evaluate(payload, limits)

    assert result.passed, (phase, result.reasons)


@pytest.mark.parametrize("tail_samples", [1, 2, 3, 7, 17, 51])
@pytest.mark.parametrize("metric", ["bytes", "objects"])
def test_late_monotonic_growth_without_terminal_plateau_fails(
    metric: str,
    tail_samples: int,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [20_000] * 481
    object_values = [100] * 481
    tail_start = 481 - tail_samples
    for sample_index in range(tail_start, 481):
        increment = sample_index - tail_start + 1
        if metric == "bytes":
            byte_values[sample_index] += 10_000 * increment
        else:
            object_values[sample_index] += 1_000 * increment
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=100_000,
        max_objects=100_000,
    )

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


@pytest.mark.parametrize("tail_samples", [17, 51])
@pytest.mark.parametrize("terminal_plateau_samples", [0, 5])
@pytest.mark.parametrize("metric", ["bytes", "objects"])
def test_late_growth_with_outliers_and_no_full_terminal_window_fails(
    metric: str,
    terminal_plateau_samples: int,
    tail_samples: int,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [20_000] * 481
    object_values = [100] * 481
    tail_start = 481 - terminal_plateau_samples - tail_samples
    for sample_index in range(tail_start, tail_start + tail_samples):
        increment = sample_index - tail_start + 1
        if metric == "bytes":
            byte_values[sample_index] += 10_000 * increment
        else:
            object_values[sample_index] += 1_000 * increment
    outlier_index = tail_start + tail_samples // 2
    if metric == "bytes":
        byte_values[outlier_index] = 10_000_000
    else:
        object_values[outlier_index] = 1_000_000
    if terminal_plateau_samples:
        terminal_value = (
            byte_values[tail_start + tail_samples - 1]
            if metric == "bytes"
            else object_values[tail_start + tail_samples - 1]
        )
        for sample_index in range(481 - terminal_plateau_samples, 481):
            if metric == "bytes":
                byte_values[sample_index] = terminal_value
            else:
                object_values[sample_index] = terminal_value
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=100_000,
        max_objects=1_000_000,
    )

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in item for item in result.reasons)


@pytest.mark.parametrize("transition_sample", [150, 200, 270, 350])
@pytest.mark.parametrize("amplitude", [1, 10_000])
@pytest.mark.parametrize("direction", ["up", "down"])
@pytest.mark.parametrize("metric", ["bytes", "objects"])
def test_exact_one_transition_store_plateau_is_bounded(
    metric: str,
    direction: str,
    amplitude: int,
    transition_sample: int,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    low_value = 10_000
    high_value = low_value + amplitude
    before, after = (low_value, high_value) if direction == "up" else (high_value, low_value)
    byte_values = [
        before if sample_index < transition_sample else after for sample_index in range(481)
    ]
    object_values = [100] * 481
    if metric == "objects":
        object_values = byte_values
        byte_values = [20_000] * 481
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=100_000,
        max_objects=100_000,
    )

    result = _evaluate(payload, limits)

    assert result.passed, (
        metric,
        direction,
        amplitude,
        transition_sample,
        result.reasons,
    )


@pytest.mark.parametrize("module", ["fight", "fall", "violence", "xclip", "vit"])
def test_shadow_only_module_disposition_rejects_operator_mode(module: str) -> None:
    with pytest.raises(ValidationError, match="shadow-only"):
        operational_module.OperationalModuleDispositionV1.model_validate(
            {
                "module": module,
                "mode": "operator",
                "decided_by_role": "admin",
                "decided_by_id": "admin-01",
            }
        )


@pytest.mark.parametrize("module", ["fight", "fall", "violence", "xclip", "vit"])
def test_shadow_only_candidate_identity_rejects_operator_mode(module: str) -> None:
    payload = _evidence_payload()["candidate_events"][0]  # type: ignore[index]
    payload["module"] = module
    payload["mode"] = "operator"
    payload["workflow"] = "real_candidate"

    with pytest.raises(ValidationError, match="shadow-only"):
        operational_module.CandidateEventEvidenceV1.model_validate(payload)


@pytest.mark.parametrize("module", ["fight", "fall", "violence", "xclip", "vit"])
@pytest.mark.parametrize("mode", ["shadow", "disabled"])
def test_shadow_only_module_disposition_preserves_nonoperator_modes(
    module: str,
    mode: str,
) -> None:
    disposition = operational_module.OperationalModuleDispositionV1.model_validate(
        {
            "module": module,
            "mode": mode,
            "decided_by_role": "admin",
            "decided_by_id": "admin-01",
        }
    )

    assert disposition.mode == mode


@pytest.mark.parametrize(
    "module",
    [
        "person",
        "restricted_zone",
        "intrusion",
        "loitering",
        "line_crossing",
        "fire_smoke",
        "weapon",
    ],
)
def test_core_and_conditional_module_dispositions_preserve_operator_mode(
    module: str,
) -> None:
    disposition = operational_module.OperationalModuleDispositionV1.model_validate(
        {
            "module": module,
            "mode": "operator",
            "decided_by_role": "admin",
            "decided_by_id": "admin-01",
        }
    )

    assert disposition.mode == "operator"


def _append_confirmed_operator_real_candidate(
    payload: dict[str, object],
    *,
    module: str,
) -> None:
    _append_rejected_real_candidate(payload)
    event_id = "event-real-00"
    for collection in (
        "candidate_events",
        "evidence_ready",
        "human_reviews",
        "audit_rows",
        "repository_acknowledgements",
    ):
        row = next(  # type: ignore[arg-type]
            item for item in payload[collection] if item["event_id"] == event_id
        )
        row["module"] = module
        row["mode"] = "shadow"
    review = payload["human_reviews"][-1]  # type: ignore[index]
    review["decision"] = "confirmed"
    audit = payload["audit_rows"][-1]  # type: ignore[index]
    audit["action"] = "review_confirmed"
    identity = {
        "event_id": event_id,
        "evidence_id": "evidence-real-00",
        "camera_id": CAMERAS[0],
        "module": module,
        "mode": "shadow",
        "repository_sequence": 21,
    }
    occurred_at = START + timedelta(seconds=300)
    payload["outbox_queued"].append(  # type: ignore[union-attr]
        {
            **identity,
            "outbox_id": "outbox-real-00",
            "operator_id": "operator-02",
            "queued_at": occurred_at + timedelta(seconds=4),
        }
    )
    payload["delivery_attempts"].append(  # type: ignore[union-attr]
        {
            **identity,
            "attempt_id": "attempt-real-00",
            "outbox_id": "outbox-real-00",
            "operator_id": "operator-02",
            "result": "delivered",
            "attempted_at": occurred_at + timedelta(seconds=5),
        }
    )
    acknowledgement = payload["repository_acknowledgements"][-1]  # type: ignore[index]
    acknowledgement["acknowledged_at"] = occurred_at + timedelta(seconds=6)
    _refresh_repository_claim(payload)


@pytest.mark.parametrize("module", ["fight", "fall", "violence", "xclip", "vit"])
def test_evaluator_defense_rejects_complete_notified_operator_heavy_candidate(
    module: str,
) -> None:
    limits_payload = _limits_payload()
    limits_payload["module_dispositions"].append(  # type: ignore[union-attr]
        {
            "module": module,
            "mode": "shadow",
            "decided_by_role": "admin",
            "decided_by_id": "admin-01",
        }
    )
    limits = _parse_limits(limits_payload)
    disposition = next(item for item in limits.module_dispositions if item.module == module)
    object.__setattr__(disposition, "mode", "operator")
    payload = _evidence_payload()
    _append_confirmed_operator_real_candidate(payload, module=module)
    evidence = _parse_evidence(payload)
    for collection in (
        evidence.candidate_events,
        evidence.evidence_ready,
        evidence.human_reviews,
        evidence.audit_rows,
        evidence.outbox_queued,
        evidence.delivery_attempts,
        evidence.repository_acknowledgements,
    ):
        for row in collection:
            if row.event_id == "event-real-00":
                object.__setattr__(row, "mode", "operator")
    boundary = operational_module.AuthoritativeRepositoryBoundaryV1.model_validate_json(
        _json_bytes(_repository_boundary_payload(payload))
    )
    rows_sha256 = operational_module.repository_rows_sha256(evidence.candidate_events)
    snapshot_sha256 = operational_module.authoritative_repository_snapshot_sha256(
        source_identity=evidence.repository_coverage.source_identity,
        canonical_query_sha256=evidence.repository_coverage.canonical_query_sha256,
        start_high_water=evidence.repository_coverage.start_high_water,
        final_high_water=evidence.repository_coverage.final_high_water,
        row_count=evidence.repository_coverage.candidate_count,
        rows_sha256=rows_sha256,
    )
    object.__setattr__(evidence.repository_coverage, "rows_sha256", rows_sha256)
    object.__setattr__(
        evidence.repository_coverage,
        "final_snapshot_sha256",
        snapshot_sha256,
    )
    object.__setattr__(boundary, "rows_sha256", rows_sha256)
    object.__setattr__(boundary, "snapshot_sha256", snapshot_sha256)

    result = evaluate_operational_acceptance(
        limits,
        evidence,
        environment="target",
        repository_boundary=boundary,
    )

    assert not result.passed
    assert result.confirmed_and_delivered_count == 1
    assert any("shadow-only" in item and "operator" in item for item in result.reasons)
    assert any("notification" in item for item in result.reasons)


def _final_artifact_row_model(
    *,
    object_key: str = "school-01/camera-00/event-00.mp4",
    sha256: str = DIGEST_A,
) -> operational_module.FinalEvidenceArtifactObservationV1:
    return operational_module.FinalEvidenceArtifactObservationV1.model_validate(
        {
            "object_key": object_key,
            "sha256": sha256,
            "byte_size": 400,
            "storage_identity": "kz-evidence-store-01",
        }
    )


@pytest.mark.parametrize("container_type", [tuple, list])
def test_final_inventory_clones_caller_held_prevalidated_nested_rows(
    container_type: type[tuple] | type[list],
) -> None:
    caller_row = _final_artifact_row_model()
    caller_rows = container_type([caller_row])
    observation = operational_module.FinalEvidenceStoreObservationV1.model_validate(
        {
            "sample_index": 480,
            "observed_at": END,
            "storage_identity": "kz-evidence-store-01",
            "used_bytes": 20_000,
            "object_count": 40,
            "live_artifacts": caller_rows,
        }
    )
    object.__setattr__(caller_row, "sha256", DIGEST_B)
    if type(caller_rows) is list:
        caller_rows[0] = _final_artifact_row_model(sha256=DIGEST_C)

    assert observation.live_artifacts[0].sha256 == DIGEST_A
    assert observation.live_artifacts[0] is not caller_row


def test_final_inventory_clones_caller_held_model_dump_graph() -> None:
    caller_graph = _final_artifact_row_model().model_dump(mode="python", round_trip=True)
    caller_rows = [caller_graph]
    observation = operational_module.FinalEvidenceStoreObservationV1.model_validate(
        {
            "sample_index": 480,
            "observed_at": END,
            "storage_identity": "kz-evidence-store-01",
            "used_bytes": 20_000,
            "object_count": 40,
            "live_artifacts": caller_rows,
        }
    )
    caller_graph["sha256"] = DIGEST_B
    caller_rows[0] = _final_artifact_row_model(sha256=DIGEST_C).model_dump()

    assert observation.live_artifacts[0].sha256 == DIGEST_A


def test_final_inventory_rejects_nested_model_subclasses_before_clone() -> None:
    class ArtifactSubclass(operational_module.FinalEvidenceArtifactObservationV1):
        pass

    caller_row = ArtifactSubclass.model_validate(
        _final_artifact_row_model().model_dump(mode="python", round_trip=True)
    )

    with pytest.raises(ValidationError, match="exact artifact row"):
        operational_module.FinalEvidenceStoreObservationV1.model_validate(
            {
                "sample_index": 480,
                "observed_at": END,
                "storage_identity": "kz-evidence-store-01",
                "used_bytes": 20_000,
                "object_count": 40,
                "live_artifacts": (caller_row,),
            }
        )


def test_max_scale_sequence_trend_proof_uses_only_signed_rle_steps() -> None:
    class CountingRuns:
        def __init__(self, rows: tuple[tuple[int, int, int, int], ...]) -> None:
            self.rows = rows
            self.traversed = 0

        def __iter__(self):
            for row in self.rows:
                self.traversed += 1
                if self.traversed > 10_000:
                    raise AssertionError("trend proof traversed beyond the signed RLE bound")
                yield row

    run_samples = 1_000
    rows = tuple(
        (
            run_index * run_samples,
            run_samples,
            999_999_999_998 + run_index % 2,
            9_999_998 + run_index % 2,
        )
        for run_index in range(10_000)
    )
    counted = CountingRuns(rows)

    assert not operational_module._has_material_positive_store_trend(
        counted,
        warmup_samples=run_samples,
        expected_samples=10_000_000,
    )
    assert counted.traversed == 10_000


@pytest.mark.parametrize("phase", [0, 73])
@pytest.mark.parametrize("metric", ["bytes", "objects"])
def test_irregular_recurring_cycle_compares_its_translated_baseline(
    metric: str,
    phase: int,
) -> None:
    byte_pattern = [10_000 + 100_000 * ((index * 53) % 129) for index in range(129)]
    object_pattern = [100 + 1_000 * ((index * 53) % 129) for index in range(129)]
    byte_values = [
        byte_pattern[(sample_index + phase) % 129] + 1_000 * ((sample_index + phase) // 129)
        for sample_index in range(481)
    ]
    object_values = [
        object_pattern[(sample_index + phase) % 129] + 10 * ((sample_index + phase) // 129)
        for sample_index in range(481)
    ]
    if metric == "bytes":
        object_values = [40] * 481
    else:
        byte_values = [20_000] * 481
    translated_rows = tuple(
        (sample_index, 1, byte_values[sample_index], object_values[sample_index])
        for sample_index in range(481)
    )
    stationary_rows = tuple(
        (
            sample_index,
            1,
            (byte_pattern[(sample_index + phase) % 129] if metric == "bytes" else 20_000),
            (object_pattern[(sample_index + phase) % 129] if metric == "objects" else 40),
        )
        for sample_index in range(481)
    )

    assert operational_module._has_material_positive_store_trend(
        translated_rows,
        warmup_samples=60,
        expected_samples=481,
    )
    assert not operational_module._has_material_positive_store_trend(
        stationary_rows,
        warmup_samples=60,
        expected_samples=481,
    )


def _irregular_period_values(
    *,
    period: int,
    phase: int,
    cycle_shift: int = 0,
) -> list[int]:
    pattern = [10_000 + 100 * ((index * 53) % period) for index in range(period)]
    return [
        pattern[(sample_index + phase) % period] + cycle_shift * ((sample_index + phase) // period)
        for sample_index in range(481)
    ]


@pytest.mark.parametrize("metric", ["bytes", "objects"])
@pytest.mark.parametrize("cycle_shift", [1, 10_000])
def test_full_evaluator_rejects_period_200_irregular_translation_at_every_phase(
    metric: str,
    cycle_shift: int,
) -> None:
    for phase in range(200):
        limits = _limits_payload()
        payload = _evidence_payload()
        translated_values = _irregular_period_values(
            period=200,
            phase=phase,
            cycle_shift=cycle_shift,
        )
        byte_values = translated_values if metric == "bytes" else [20_000] * 481
        object_values = translated_values if metric == "objects" else [40] * 481
        _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
        _set_evidence_store_budget(
            limits,
            payload,
            max_object_bytes=100_000,
            max_objects=100_000,
        )

        result = _evaluate(payload, limits)

        assert any("weighted mean has positive growth" in reason for reason in result.reasons), (
            metric,
            cycle_shift,
            phase,
            result.reasons,
        )


@pytest.mark.parametrize("metric", ["bytes", "objects"])
@pytest.mark.parametrize("period", [61, 82, 129, 200])
def test_full_evaluator_accepts_stationary_irregular_cycle_at_every_phase(
    metric: str,
    period: int,
) -> None:
    for phase in range(period):
        limits = _limits_payload()
        payload = _evidence_payload()
        stationary_values = _irregular_period_values(
            period=period,
            phase=phase,
        )
        byte_values = stationary_values if metric == "bytes" else [20_000] * 481
        object_values = stationary_values if metric == "objects" else [40] * 481
        _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
        _set_evidence_store_budget(
            limits,
            payload,
            max_object_bytes=100_000,
            max_objects=100_000,
        )

        result = _evaluate(payload, limits)

        assert result.passed, (metric, period, phase, result.reasons)


@pytest.mark.parametrize("metric", ["bytes", "objects"])
@pytest.mark.parametrize("duties", [(1, 2, 3), (20, 40, 60)])
def test_full_evaluator_rejects_period_200_rising_duty_at_every_phase(
    metric: str,
    duties: tuple[int, int, int],
) -> None:
    for phase in range(200):
        limits = _limits_payload()
        payload = _evidence_payload()
        rising_values: list[int] = []
        for sample_index in range(481):
            shifted_index = sample_index + phase
            cycle_index = shifted_index // 200
            duty = duties[min(cycle_index, len(duties) - 1)]
            rising_values.append(20_000 if shifted_index % 200 < duty else 10_000)
        byte_values = rising_values if metric == "bytes" else [20_000] * 481
        object_values = rising_values if metric == "objects" else [40] * 481
        _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
        _set_evidence_store_budget(
            limits,
            payload,
            max_object_bytes=100_000,
            max_objects=100_000,
        )

        result = _evaluate(payload, limits)

        assert any("weighted mean has positive growth" in reason for reason in result.reasons), (
            metric,
            duties,
            phase,
            result.reasons,
        )


@pytest.mark.parametrize("metric", ["bytes", "objects"])
@pytest.mark.parametrize("tail_samples", [3, 17, 51])
def test_full_evaluator_rejects_late_downward_without_terminal_plateau(
    metric: str,
    tail_samples: int,
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    byte_values = [100_000] * 481
    object_values = [100_000] * 481
    tail_start = 481 - tail_samples
    for sample_index in range(tail_start, 481):
        falling_value = 100_000 - 1_000 * (sample_index - tail_start + 1)
        if metric == "bytes":
            byte_values[sample_index] = falling_value
        else:
            object_values[sample_index] = falling_value
    if metric == "bytes":
        object_values = [40] * 481
    else:
        byte_values = [20_000] * 481
    _replace_spans(payload, _canonical_store_spans(byte_values, object_values))
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=100_000,
        max_objects=100_000,
    )

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in reason for reason in result.reasons)


@pytest.mark.parametrize("metric", ["bytes", "objects"])
@pytest.mark.parametrize(
    "values",
    [
        ((0, 150, 20_000), (150, 100, 30_000), (250, 231, 20_000)),
        ((0, 150, 30_000), (150, 100, 20_000), (250, 231, 30_000)),
        (
            (0, 100, 20_000),
            (100, 100, 30_000),
            (200, 100, 40_000),
            (300, 181, 50_000),
        ),
    ],
)
def test_full_evaluator_rejects_nonrecurring_multi_transition_trace(
    metric: str,
    values: tuple[tuple[int, int, int], ...],
) -> None:
    limits = _limits_payload()
    payload = _evidence_payload()
    spans = [
        (
            first,
            count,
            value if metric == "bytes" else 20_000,
            value if metric == "objects" else 40,
        )
        for first, count, value in values
    ]
    _replace_spans(payload, spans)
    _set_evidence_store_budget(
        limits,
        payload,
        max_object_bytes=100_000,
        max_objects=100_000,
    )

    result = _evaluate(payload, limits)

    assert any("weighted mean has positive growth" in reason for reason in result.reasons)


@pytest.mark.parametrize(
    "alias",
    [
        "Fight",
        "FIGHT",
        " xclip ",
        "x-clip",
        "vendor/xclip",
        "jaranohaal/vit",
        "VIT",
        " violence ",
    ],
)
def test_evaluator_rejects_rebound_noncanonical_heavy_module_aliases(
    alias: str,
) -> None:
    limits_payload = _limits_payload()
    limits_payload["module_dispositions"].append(  # type: ignore[union-attr]
        {
            "module": "xclip",
            "mode": "shadow",
            "decided_by_role": "admin",
            "decided_by_id": "admin-01",
        }
    )
    limits = _parse_limits(limits_payload)
    disposition = next(item for item in limits.module_dispositions if item.module == "xclip")
    object.__setattr__(disposition, "module", alias)
    object.__setattr__(disposition, "mode", "operator")

    payload = _evidence_payload()
    _append_confirmed_operator_real_candidate(payload, module="xclip")
    evidence = _parse_evidence(payload)
    for collection in (
        evidence.candidate_events,
        evidence.evidence_ready,
        evidence.human_reviews,
        evidence.audit_rows,
        evidence.outbox_queued,
        evidence.delivery_attempts,
        evidence.repository_acknowledgements,
    ):
        for row in collection:
            if row.event_id == "event-real-00":
                object.__setattr__(row, "module", alias)
                object.__setattr__(row, "mode", "operator")

    boundary = operational_module.AuthoritativeRepositoryBoundaryV1.model_validate_json(
        _json_bytes(_repository_boundary_payload(payload))
    )
    rows_sha256 = operational_module.repository_rows_sha256(evidence.candidate_events)
    snapshot_sha256 = operational_module.authoritative_repository_snapshot_sha256(
        source_identity=evidence.repository_coverage.source_identity,
        canonical_query_sha256=evidence.repository_coverage.canonical_query_sha256,
        start_high_water=evidence.repository_coverage.start_high_water,
        final_high_water=evidence.repository_coverage.final_high_water,
        row_count=evidence.repository_coverage.candidate_count,
        rows_sha256=rows_sha256,
    )
    object.__setattr__(evidence.repository_coverage, "rows_sha256", rows_sha256)
    object.__setattr__(
        evidence.repository_coverage,
        "final_snapshot_sha256",
        snapshot_sha256,
    )
    object.__setattr__(boundary, "rows_sha256", rows_sha256)
    object.__setattr__(boundary, "snapshot_sha256", snapshot_sha256)

    result = evaluate_operational_acceptance(
        limits,
        evidence,
        environment="target",
        repository_boundary=boundary,
    )

    assert not result.passed
    assert any("canonical module" in reason or "shadow-only" in reason for reason in result.reasons)


def test_evaluator_rejects_post_validation_module_string_subclass() -> None:
    class ModuleSubclass(str):
        pass

    limits = _parse_limits(_limits_payload())
    disposition = limits.module_dispositions[0]
    object.__setattr__(disposition, "module", ModuleSubclass("fire_smoke"))

    result = evaluate_operational_acceptance(
        limits,
        _parse_evidence(_evidence_payload()),
        environment="target",
        repository_boundary=(
            operational_module.AuthoritativeRepositoryBoundaryV1.model_validate_json(
                _json_bytes(_repository_boundary_payload(_evidence_payload()))
            )
        ),
    )

    assert not result.passed
    assert any("canonical module" in reason for reason in result.reasons)


def test_operational_evidence_clones_prevalidated_outer_final_store_observation() -> None:
    parsed = _parse_evidence(_evidence_payload())
    payload = parsed.model_dump(mode="python", round_trip=True)
    caller_observation = operational_module.FinalEvidenceStoreObservationV1.model_validate(
        payload["final_evidence_store_observation"]
    )
    payload["final_evidence_store_observation"] = caller_observation

    evidence = operational_module.OperationalAcceptanceEvidenceV1.model_validate(payload)
    original_used_bytes = evidence.final_evidence_store_observation.used_bytes
    object.__setattr__(caller_observation, "used_bytes", original_used_bytes + 1)

    assert evidence.final_evidence_store_observation is not caller_observation
    assert evidence.final_evidence_store_observation.used_bytes == original_used_bytes


def test_operational_evidence_rejects_prevalidated_outer_final_store_subclass() -> None:
    class FinalStoreSubclass(operational_module.FinalEvidenceStoreObservationV1):
        pass

    parsed = _parse_evidence(_evidence_payload())
    payload = parsed.model_dump(mode="python", round_trip=True)
    caller_observation = FinalStoreSubclass.model_validate(
        payload["final_evidence_store_observation"]
    )
    payload["final_evidence_store_observation"] = caller_observation

    with pytest.raises(ValidationError, match="exact final evidence store"):
        operational_module.OperationalAcceptanceEvidenceV1.model_validate(payload)
