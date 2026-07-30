"""Independent, deterministic V3 acceptance evaluator execution."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from protector.pilot.acceptance import evaluate_acceptance
from protector.pilot.acceptance_operational import evaluate_operational_acceptance
from protector.pilot.acceptance_snapshot import (
    AcceptanceAuthoritySnapshotV3,
    EvaluatorIdentityV3,
)
from protector.pilot.acceptance_trust import canonical_json_bytes

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_MAX_REASONS = 256


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class EvaluatorOutcomeV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-evaluator-outcome.v3"]
    evaluator: EvaluatorIdentityV3
    status: Literal["pass", "fail", "error"]
    passed: bool
    reasons: Annotated[tuple[str, ...], Field(max_length=_MAX_REASONS)]
    result_sha256: Digest | None = None
    error_code: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,127}$")] | None = None

    @model_validator(mode="after")
    def result_is_derived(self) -> EvaluatorOutcomeV3:
        if self.passed != (self.status == "pass"):
            raise ValueError("evaluator outcome status and pass result differ")
        if self.status == "pass" and self.reasons:
            raise ValueError("passing evaluator cannot contain failure reasons")
        if self.status == "error":
            if self.result_sha256 is not None or self.error_code is None or not self.reasons:
                raise ValueError("errored evaluator must contain only bounded error identity")
        elif self.result_sha256 is None or self.error_code is not None:
            raise ValueError("completed evaluator must bind its exact result")
        return self

    @property
    def outcome_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


class AcceptanceEvaluationBundleV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-evaluation-bundle.v3"]
    snapshot_sha256: Digest
    c2_authorized: bool
    standard: EvaluatorOutcomeV3
    operational: EvaluatorOutcomeV3
    accepted: bool

    @model_validator(mode="after")
    def decision_is_mechanical(self) -> AcceptanceEvaluationBundleV3:
        if self.standard.evaluator.name != "standard":
            raise ValueError("standard outcome has the wrong evaluator identity")
        if self.operational.evaluator.name != "operational":
            raise ValueError("operational outcome has the wrong evaluator identity")
        expected = self.c2_authorized and self.standard.passed and self.operational.passed
        if self.accepted is not expected:
            raise ValueError("acceptance must equal C2 and both evaluator results")
        return self

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    @property
    def evaluation_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def _evaluate_standard_snapshot(snapshot: AcceptanceAuthoritySnapshotV3) -> object:
    return evaluate_acceptance(
        snapshot.manifest,
        snapshot.run_record,
        verified_gate_decisions=snapshot.conditional_gate_decisions,
    )


def _evaluate_operational_snapshot(snapshot: AcceptanceAuthoritySnapshotV3) -> object:
    return evaluate_operational_acceptance(
        snapshot.operational_limits,
        snapshot.operational_evidence,
        environment="target",
        repository_boundary=snapshot.repository_boundary,
    )


def _completed_outcome(
    *,
    evaluator: EvaluatorIdentityV3,
    result: object,
) -> EvaluatorOutcomeV3:
    try:
        payload = result.model_dump(mode="json")  # type: ignore[union-attr]
        canonical = canonical_json_bytes(payload)
        passed = result.passed  # type: ignore[union-attr]
        reasons = result.reasons  # type: ignore[union-attr]
    except (AttributeError, TypeError, ValueError):
        raise TypeError("acceptance evaluator returned an invalid result") from None
    if (
        type(passed) is not bool
        or type(reasons) not in {tuple, list}
        or any(type(reason) is not str or not 1 <= len(reason) <= 1024 for reason in reasons)
    ):
        raise TypeError("acceptance evaluator returned an invalid result")
    return EvaluatorOutcomeV3(
        schema_version="acceptance-evaluator-outcome.v3",
        evaluator=evaluator,
        status="pass" if passed else "fail",
        passed=passed,
        reasons=tuple(reasons),
        result_sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _error_outcome(
    *,
    evaluator: EvaluatorIdentityV3,
    error: BaseException,
) -> EvaluatorOutcomeV3:
    code = type(error).__name__
    if (
        not code
        or len(code) > 128
        or not code[0].isalpha()
        or any(not (character.isalnum() or character == "_") for character in code)
    ):
        code = "EvaluatorError"
    return EvaluatorOutcomeV3(
        schema_version="acceptance-evaluator-outcome.v3",
        evaluator=evaluator,
        status="error",
        passed=False,
        reasons=(f"{evaluator.name} evaluator raised {code}",),
        error_code=code,
    )


def _run_one(
    *,
    snapshot: AcceptanceAuthoritySnapshotV3,
    evaluator: EvaluatorIdentityV3,
    function: object,
) -> EvaluatorOutcomeV3:
    try:
        result = function(snapshot)  # type: ignore[operator]
        return _completed_outcome(evaluator=evaluator, result=result)
    except BaseException as error:
        return _error_outcome(evaluator=evaluator, error=error)


def run_dual_evaluation_v3(
    snapshot: AcceptanceAuthoritySnapshotV3,
) -> AcceptanceEvaluationBundleV3:
    """Run both fixed evaluators exactly once in independent exception boundaries."""

    try:
        owned = AcceptanceAuthoritySnapshotV3.model_validate_json(
            snapshot.canonical_bytes,
            strict=True,
        )
    except (AttributeError, ValueError):
        raise ValueError("acceptance snapshot cannot be reconstructed for evaluation") from None
    standard = _run_one(
        snapshot=owned,
        evaluator=owned.standard_evaluator,
        function=_evaluate_standard_snapshot,
    )
    operational = _run_one(
        snapshot=owned,
        evaluator=owned.operational_evaluator,
        function=_evaluate_operational_snapshot,
    )
    accepted = owned.target_authority.authorized and standard.passed and operational.passed
    return AcceptanceEvaluationBundleV3(
        schema_version="acceptance-evaluation-bundle.v3",
        snapshot_sha256=owned.snapshot_sha256,
        c2_authorized=owned.target_authority.authorized,
        standard=standard,
        operational=operational,
        accepted=accepted,
    )
