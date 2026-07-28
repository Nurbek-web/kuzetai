from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from protector.pilot.gates import (
    CapacityReportV1,
    ModelArtifactV1,
    ModelGate,
    ShadowStageReportV1,
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
        "report_sha256": "b" * 64,
        "signed_by": "site-qa@example.com",
        "signed_at": "2026-07-22T12:00:00Z",
    }


def _capacity_report_payload() -> dict[str, object]:
    return {
        "schema_version": "capacity-report.v1",
        "artifact_id": "weapon-rfdetr-2026-07-22",
        "stream_count": 20,
        "passed": True,
        "report_reference": "signed-20-stream-replay-2026-07-22",
        "report_sha256": "c" * 64,
        "signed_by": "capacity-qa@example.com",
        "signed_at": "2026-07-22T12:05:00Z",
    }


def _shadow_report_payload() -> dict[str, object]:
    return {
        "schema_version": "shadow-stage-report.v1",
        "artifact_id": "weapon-rfdetr-2026-07-22",
        "passed": True,
        "report_reference": "signed-shadow-stage-2026-07-22",
        "report_sha256": "d" * 64,
        "signed_by": "operator-qa@example.com",
        "signed_at": "2026-07-22T12:10:00Z",
    }


def _evaluate(
    artifact_payload: dict[str, object] | None = None,
    site_report_payload: dict[str, object] | None = None,
    capacity_report_payload: dict[str, object] | None = None,
    shadow_report_payload: dict[str, object] | None = None,
    current_mode: str = "disabled",
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
    shadow_report = (
        None
        if shadow_report_payload is None
        else ShadowStageReportV1.model_validate(shadow_report_payload)
    )
    return ModelGate.evaluate(
        artifact,
        site_report,
        capacity_report,
        current_mode=current_mode,
        shadow_stage_report=shadow_report,
    )


def test_complete_artifact_and_signed_reports_first_promote_from_disabled_to_shadow():
    result = _evaluate(
        _artifact_payload(), _site_report_payload(), _capacity_report_payload()
    )

    assert result.mode == "shadow"
    assert result.reasons == ("successful shadow-stage report is required before operator promotion",)


def test_only_a_recorded_successful_shadow_stage_promotes_shadow_to_operator():
    result = _evaluate(
        _artifact_payload(),
        _site_report_payload(),
        _capacity_report_payload(),
        _shadow_report_payload(),
        current_mode="shadow",
    )

    assert result.mode == "operator"
    assert result.reasons == ()


def test_direct_operator_mode_without_a_recorded_shadow_stage_cannot_bypass_promotion():
    result = _evaluate(
        _artifact_payload(),
        _site_report_payload(),
        _capacity_report_payload(),
        current_mode="operator",
    )

    assert result.mode == "shadow"
    assert result.reasons == ("successful shadow-stage report is required before operator promotion",)


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
        (
            _site_report_payload(),
            {**_capacity_report_payload(), "passed": False},
            "capacity report did not pass",
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


@pytest.mark.parametrize("analytic", ["violence", "xclip", "vit", "fight", "fall"])
def test_current_temporal_analytics_are_shadow_only_even_with_complete_evidence(analytic: str):
    artifact_payload = _artifact_payload()
    artifact_payload["analytic"] = analytic

    result = _evaluate(
        artifact_payload,
        _site_report_payload(),
        _capacity_report_payload(),
        _shadow_report_payload(),
        current_mode="shadow",
    )

    assert result.mode == "shadow"
    assert result.reasons == (f"{analytic} remains shadow-only for this pilot",)


def test_unknown_analytics_fail_closed_even_with_complete_operator_evidence():
    artifact_payload = _artifact_payload()
    artifact_payload["analytic"] = "unknown-analytic"

    result = _evaluate(
        artifact_payload,
        _site_report_payload(),
        _capacity_report_payload(),
        _shadow_report_payload(),
        current_mode="shadow",
    )

    assert result.mode == "disabled"
    assert result.reasons == ("analytic is not approved for operator promotion",)


@pytest.mark.parametrize("report_builder", [_site_report_payload, _capacity_report_payload])
def test_gate_reports_require_audit_provenance(report_builder):
    report_payload = report_builder()
    report_payload.pop("report_sha256")

    report_type = TargetSiteReportV1 if report_builder is _site_report_payload else CapacityReportV1
    with pytest.raises(ValidationError):
        report_type.model_validate(report_payload)
