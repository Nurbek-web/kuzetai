from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from protector.pilot.config import load_site_config
from protector.pilot.domain import RuntimeWriterReceiptV1
from protector.pilot.rules import (
    CompiledCameraRuleV1,
    ModuleRuleSpecV1,
)
from protector.pilot.runtime.production_events import (
    ProductionEventCompositionError,
    ProductionEventDependencies,
    ProductionEventPipeline,
    _validate_runtime_rules,
    build_production_event_pipeline,
)

ROOT = Path(__file__).resolve().parents[2]
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


def _rule(
    *,
    rule_id: str = "rule-1",
    camera_id: str = "camera-01",
    evidence_seconds: int = 4,
    digest: str = DIGEST_C,
    enabled: bool = True,
    gate_mode: str = "operator",
    module: str = "person",
    source_module: str = "person",
) -> CompiledCameraRuleV1:
    return CompiledCameraRuleV1(
        rule_id=rule_id,
        revision=1,
        site_id="site-1",
        camera_id=camera_id,
        module=module,
        enabled=enabled,
        model_artifact_id="person-primary",
        model_decision_sha256=DIGEST_D,
        gate_mode=gate_mode,
        minimum_confidence=0.5,
        minimum_votes=1,
        sample_count=1,
        window_seconds=1.0,
        evidence_seconds=evidence_seconds,
        spec=ModuleRuleSpecV1(
            source_module=source_module,
            class_names=(source_module,),
            reason="reviewed person candidate",
            merge_window_seconds=0.0,
            cooldown_seconds=0.0,
        ),
        rule_revision_sha256=digest,
    )


def _writer(
    digests: dict[str, str] | None = None,
) -> RuntimeWriterReceiptV1:
    return RuntimeWriterReceiptV1._issue(
        site_id="site-1",
        runtime_session_id="runtime-1",
        runtime_writer_generation=7,
        configuration_activation_generation=4,
        config_revision_id="config-1",
        site_config_sha256=DIGEST_A,
        ruleset_revision_id="rules-1",
        ruleset_sha256=DIGEST_B,
        rule_revision_digests=digests or {"rule-1": DIGEST_C},
        issued_at=NOW,
    )


def test_runtime_rules_bind_exact_writer_and_provenance() -> None:
    active, evidence_seconds, bindings = _validate_runtime_rules(
        site_id="site-1",
        compiled_rules=(_rule(),),
        writer_receipt=_writer(),
    )

    assert active[0].rule_id == "rule-1"
    assert evidence_seconds == 4
    assert bindings[0].rule_revision_sha256 == DIGEST_C
    assert bindings[0].model_gate_decision_sha256 == DIGEST_D


def test_runtime_rules_reject_mixed_evidence_windows() -> None:
    rules = (
        _rule(),
        _rule(
            rule_id="rule-2",
            camera_id="camera-02",
            evidence_seconds=6,
            digest=DIGEST_D,
        ),
    )

    with pytest.raises(
        ProductionEventCompositionError,
        match="one reviewed evidence window",
    ):
        _validate_runtime_rules(
            site_id="site-1",
            compiled_rules=rules,
            writer_receipt=_writer(
                {"rule-1": DIGEST_C, "rule-2": DIGEST_D}
            ),
        )


def test_runtime_rules_reject_writer_digest_drift_and_all_disabled() -> None:
    with pytest.raises(ProductionEventCompositionError):
        _validate_runtime_rules(
            site_id="site-1",
            compiled_rules=(_rule(),),
            writer_receipt=_writer({"rule-1": DIGEST_D}),
        )
    with pytest.raises(
        ProductionEventCompositionError,
        match="no enabled",
    ):
        _validate_runtime_rules(
            site_id="site-1",
            compiled_rules=(
                _rule(enabled=False, gate_mode="disabled"),
            ),
            writer_receipt=_writer(),
        )


@pytest.mark.parametrize("gate_mode", ("shadow", "operator"))
def test_runtime_rules_reject_active_modules_without_a_live_producer(
    gate_mode: str,
) -> None:
    with pytest.raises(
        ProductionEventCompositionError,
        match="live metadata producer",
    ):
        _validate_runtime_rules(
            site_id="site-1",
            compiled_rules=(
                _rule(
                    module="weapon",
                    source_module="weapon",
                    gate_mode=gate_mode,
                ),
            ),
            writer_receipt=_writer(),
        )


def test_pipeline_rejects_site_config_outside_writer_authority_before_resources(
    tmp_path: Path,
) -> None:
    site = load_site_config(ROOT / "configs" / "pilot.example.yaml")

    with pytest.raises(
        ProductionEventCompositionError,
        match="does not match writer authority",
    ):
        build_production_event_pipeline(
            site_id="site-1",
            site=site,
            compiled_rules=(_rule(),),
            writer_receipt=_writer(),
            repository=object(),  # type: ignore[arg-type]
            evidence_client=object(),
            preview_client=object(),
            journal_path=(tmp_path / "journal.sqlite3").resolve(),
            preview_workspace_root=(tmp_path / "previews").resolve(),
            preview_context_factory=lambda *_: object(),  # type: ignore[arg-type]
            clock=lambda: NOW,
        )


class _CloseRecorder:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class _Delivery:
    def __init__(self, workspace: _CloseRecorder) -> None:
        self.preview_workspace = workspace


class _Worker:
    def __init__(self, status: object) -> None:
        self.status = status
        self.stopped = 0

    def stop(self) -> None:
        self.stopped += 1


def test_pipeline_cleans_durable_resources_but_reports_degraded_drain() -> None:
    workspace = _CloseRecorder()
    journal = _CloseRecorder()
    pipeline = ProductionEventPipeline(
        dependencies=ProductionEventDependencies(
            evidence_sink_factory=object(),  # type: ignore[arg-type]
            native_source_authority=object(),  # type: ignore[arg-type]
        ),
        router=object(),  # type: ignore[arg-type]
        authority=object(),  # type: ignore[arg-type]
        event_service=object(),  # type: ignore[arg-type]
        journal=journal,  # type: ignore[arg-type]
        delivery=_Delivery(workspace),  # type: ignore[arg-type]
        preview_store=object(),  # type: ignore[arg-type]
        worker_batch_size=1,
        worker_shutdown_batches=1,
    )
    worker = _Worker(
        type(
            "_Status",
            (),
            {
                "failed": False,
                "shutdown_drain_exhausted": True,
            },
        )()
    )
    pipeline._worker = worker  # type: ignore[assignment]

    with pytest.raises(
        ProductionEventCompositionError,
        match="terminated degraded",
    ):
        pipeline.close()

    assert worker.stopped == 1
    assert workspace.closed == 1
    assert journal.closed == 1
    pipeline.close()
    assert worker.stopped == 1
    assert workspace.closed == 1
    assert journal.closed == 1
