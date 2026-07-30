from __future__ import annotations

from itertools import product
from pathlib import Path

import pytest

import protector.pilot.acceptance_evaluation as evaluation_module
from protector.pilot.acceptance_evaluation import run_dual_evaluation_v3
from protector.pilot.acceptance_operational import OperationalAcceptanceSummaryV1
from tests.pilot.test_acceptance_snapshot import _snapshot


class _Result:
    def __init__(self, passed: bool) -> None:
        self.passed = passed
        self.reasons = () if passed else ("fixture failure",)

    def model_dump(self, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        return {"passed": self.passed, "reasons": list(self.reasons)}


@pytest.mark.parametrize(
    ("standard_state", "operational_state"),
    tuple(product(("pass", "fail", "error"), repeat=2)),
)
def test_dual_evaluators_always_run_once_without_short_circuit_and_derive_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    standard_state: str,
    operational_state: str,
) -> None:
    snapshot = _snapshot(tmp_path)
    calls: list[str] = []

    def standard(_snapshot: object) -> _Result:
        calls.append("standard")
        if standard_state == "error":
            raise RuntimeError("attacker-controlled standard detail")
        return _Result(standard_state == "pass")

    def operational(_snapshot: object) -> OperationalAcceptanceSummaryV1:
        calls.append("operational")
        if operational_state == "error":
            raise RuntimeError("attacker-controlled operational detail")
        passed = operational_state == "pass"
        return OperationalAcceptanceSummaryV1(
            status="pass" if passed else "fail",
            passed=passed,
            reasons=() if passed else ("fixture failure",),
            covered_sample_count=481,
            acceptance_drill_count=20,
            candidate_event_count=20,
            confirmed_and_delivered_count=1,
            rejected_count=19,
            max_store_bytes={"evidence": 20_000, "metadata": 500},
        )

    monkeypatch.setattr(evaluation_module, "_evaluate_standard_snapshot", standard)
    monkeypatch.setattr(evaluation_module, "_evaluate_operational_snapshot", operational)

    result = run_dual_evaluation_v3(snapshot)

    assert calls == ["standard", "operational"]
    assert result.standard.status == standard_state
    assert result.operational.status == operational_state
    assert result.accepted is (
        snapshot.target_authority.authorized
        and standard_state == "pass"
        and operational_state == "pass"
    )
    for outcome in (result.standard, result.operational):
        if outcome.status == "error":
            assert outcome.error_code == "RuntimeError"
            assert "attacker-controlled" not in outcome.model_dump_json()


def test_public_evaluator_has_no_caller_candidate_or_adapter_parameter(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    with pytest.raises(TypeError):
        run_dual_evaluation_v3(snapshot, candidate={"passed": True})  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        run_dual_evaluation_v3(snapshot, standard_evaluator=lambda _: _Result(True))  # type: ignore[call-arg]
