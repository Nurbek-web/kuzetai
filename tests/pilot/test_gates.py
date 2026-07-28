from __future__ import annotations

from copy import deepcopy

import pytest

from protector.pilot.gates import (
    CapacityReportV1,
    ModelArtifactV1,
    ModelGate,
    TargetSiteReportV1,
)


def _artifact_payload() -> dict[str, object]:
    return {
        "schema_version": "model-artifact.v1",
        "artifact_id": "weapon-rfdetr-2026-07-22",
        "sha256": "a" * 64,
        "source": "https://models.customer.example/weapon-rfdetr-2026-07-22.onnx",
        "commercial_rights": {
            "schema_version": "commercial-rights.v1",
            "record_id": "legal-weapon-001",
            "terms_reference": "contract-2026-07-20",
            "commercial_use_approved": True,
        },
        "class_list": ["handgun", "long_gun", "knife"],
        "preprocessing": "letterbox-640-rgb-nchw-fp16",
        "analytic": "weapon",
    }


def _site_report_payload() -> dict[str, object]:
    return {
        "schema_version": "target-site-report.v1",
        "artifact_id": "weapon-rfdetr-2026-07-22",
        "site_id": "customer-site-01",
        "passed": True,
        "report_reference": "signed-site-matrix-2026-07-22",
    }


def _capacity_report_payload() -> dict[str, object]:
    return {
        "schema_version": "capacity-report.v1",
        "artifact_id": "weapon-rfdetr-2026-07-22",
        "stream_count": 20,
        "passed": True,
        "report_reference": "signed-20-stream-replay-2026-07-22",
    }


def _evaluate(
    artifact_payload: dict[str, object] | None = None,
    site_report_payload: dict[str, object] | None = None,
    capacity_report_payload: dict[str, object] | None = None,
):
    artifact = None if artifact_payload is None else ModelArtifactV1.model_validate(artifact_payload)
    site_report = (
        None if site_report_payload is None else TargetSiteReportV1.model_validate(site_report_payload)
    )
    capacity_report = (
        None
        if capacity_report_payload is None
        else CapacityReportV1.model_validate(capacity_report_payload)
    )
    return ModelGate.evaluate(artifact, site_report, capacity_report)


def test_complete_artifact_and_signed_target_site_and_20_stream_reports_promote_to_operator():
    result = _evaluate(
        _artifact_payload(), _site_report_payload(), _capacity_report_payload()
    )

    assert result.mode == "operator"
    assert result.reasons == ()
    assert result.promotion_path == ("disabled", "shadow", "operator")


@pytest.mark.parametrize(
    "missing_field",
    ["sha256", "source", "commercial_rights", "class_list", "preprocessing"],
)
def test_missing_required_artifact_evidence_fails_closed_to_disabled(missing_field: str):
    artifact_payload = deepcopy(_artifact_payload())
    artifact_payload.pop(missing_field)

    result = _evaluate(artifact_payload, _site_report_payload(), _capacity_report_payload())

    assert result.mode == "disabled"
    assert any(missing_field.replace("_", " ") in reason for reason in result.reasons)


@pytest.mark.parametrize(
    ("site_report", "capacity_report", "expected_reason"),
    [
        (None, _capacity_report_payload(), "missing target-site report"),
        (_site_report_payload(), None, "missing 20-stream capacity report"),
        (
            {**_site_report_payload(), "passed": False},
            _capacity_report_payload(),
            "target-site report did not pass",
        ),
        (
            _site_report_payload(),
            {**_capacity_report_payload(), "stream_count": 19},
            "capacity report must cover exactly 20 streams",
        ),
    ],
)
def test_missing_or_nonpassing_required_reports_fail_closed_to_disabled(
    site_report: dict[str, object] | None,
    capacity_report: dict[str, object] | None,
    expected_reason: str,
):
    result = _evaluate(_artifact_payload(), site_report, capacity_report)

    assert result.mode == "disabled"
    assert expected_reason in result.reasons


@pytest.mark.parametrize("analytic", ["fight", "fall"])
def test_fight_and_fall_are_shadow_only_even_with_complete_evidence(analytic: str):
    artifact_payload = _artifact_payload()
    artifact_payload["analytic"] = analytic

    result = _evaluate(artifact_payload, _site_report_payload(), _capacity_report_payload())

    assert result.mode == "shadow"
    assert result.reasons == (f"{analytic} remains shadow-only for this pilot",)
