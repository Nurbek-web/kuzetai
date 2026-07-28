"""Fail-closed, evidence-based promotion decisions for conditional analytics."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator

from protector.pilot.config import FrozenModel, NonEmptyString
from protector.pilot.domain import GateMode


class CommercialRightsRecordV1(FrozenModel):
    """An explicit commercial-use decision, not an inferred licence label."""

    schema_version: Literal["commercial-rights.v1"]
    record_id: NonEmptyString
    terms_reference: NonEmptyString
    commercial_use_approved: bool


class ModelArtifactV1(FrozenModel):
    """The exact artifact and metadata required before operational promotion."""

    schema_version: Literal["model-artifact.v1"]
    artifact_id: NonEmptyString
    sha256: str | None = None
    source: NonEmptyString | None = None
    commercial_rights: CommercialRightsRecordV1 | None = None
    class_list: tuple[NonEmptyString, ...] = ()
    preprocessing: NonEmptyString | None = None
    analytic: NonEmptyString

    @field_validator("sha256")
    @classmethod
    def sha256_is_a_digest_when_present(cls, value: str | None) -> str | None:
        if value is not None and len(value) != 64:
            raise ValueError("sha256 must be a 64-character digest")
        if value is not None and any(character not in "0123456789abcdef" for character in value.lower()):
            raise ValueError("sha256 must be hexadecimal")
        return value


class TargetSiteReportV1(FrozenModel):
    """Signed target-site validation for one exact model artifact."""

    schema_version: Literal["target-site-report.v1"]
    artifact_id: NonEmptyString
    site_id: NonEmptyString
    passed: bool
    report_reference: NonEmptyString


class CapacityReportV1(FrozenModel):
    """Signed capacity result for the pilot's exact stream count."""

    schema_version: Literal["capacity-report.v1"]
    artifact_id: NonEmptyString
    stream_count: Annotated[int, Field(ge=1)]
    passed: bool
    report_reference: NonEmptyString


class ModelGateResultV1(FrozenModel):
    """A pure, auditable promotion decision with human-readable evidence gaps."""

    schema_version: Literal["model-gate-result.v1"] = "model-gate-result.v1"
    mode: GateMode
    reasons: tuple[str, ...]
    promotion_path: tuple[GateMode, GateMode, GateMode] = ("disabled", "shadow", "operator")


class ModelGate:
    """Evaluate one model without mutating artifacts, reports, or runtime state."""

    @staticmethod
    def evaluate(
        artifact: ModelArtifactV1 | None,
        target_site_report: TargetSiteReportV1 | None,
        capacity_report: CapacityReportV1 | None,
    ) -> ModelGateResultV1:
        reasons: list[str] = []
        if artifact is None:
            reasons.append("missing model artifact")
        else:
            if artifact.sha256 is None:
                reasons.append("missing sha256")
            if artifact.source is None:
                reasons.append("missing source")
            if artifact.commercial_rights is None:
                reasons.append("missing commercial rights")
            elif not artifact.commercial_rights.commercial_use_approved:
                reasons.append("commercial rights are not approved")
            if not artifact.class_list:
                reasons.append("missing class list")
            if artifact.preprocessing is None:
                reasons.append("missing preprocessing")

        artifact_id = artifact.artifact_id if artifact is not None else None
        if target_site_report is None:
            reasons.append("missing target-site report")
        elif artifact_id is not None and target_site_report.artifact_id != artifact_id:
            reasons.append("target-site report artifact does not match")
        elif not target_site_report.passed:
            reasons.append("target-site report did not pass")

        if capacity_report is None:
            reasons.append("missing 20-stream capacity report")
        elif artifact_id is not None and capacity_report.artifact_id != artifact_id:
            reasons.append("capacity report artifact does not match")
        else:
            if capacity_report.stream_count != 20:
                reasons.append("capacity report must cover exactly 20 streams")
            if not capacity_report.passed:
                reasons.append("capacity report did not pass")

        if reasons:
            return ModelGateResultV1(mode="disabled", reasons=tuple(reasons))
        assert artifact is not None
        if artifact.analytic in {"fight", "fall"}:
            return ModelGateResultV1(
                mode="shadow",
                reasons=(f"{artifact.analytic} remains shadow-only for this pilot",),
            )
        return ModelGateResultV1(mode="operator", reasons=())
