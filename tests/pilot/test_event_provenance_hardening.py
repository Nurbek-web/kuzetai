from __future__ import annotations

import copy
import inspect
import json
import math
import pickle
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from protector.pilot.domain import (
    CameraEpochActivationReceiptV1,
    CandidateEventProvenanceV1,
    ConfigurationActivationReceiptV1,
    ProvenancedCandidateEventV2,
    RuntimeWriterReceiptV1,
)
from protector.pilot.gates import OperationalGateDecisionEnvelopeV2
from protector.pilot.rules import (
    CameraRuleV1,
    LineRuleSpecV1,
    ModuleRuleSpecV1,
    ReviewedCameraRulesetV1,
    VerifiedCameraRulesetRevision,
    ZoneRuleSpecV1,
    compile_verified_camera_rules,
    load_verified_camera_ruleset,
)
from protector.pilot.storage.models import (
    CameraEpochAuthorityModel,
    RuntimeWriterSessionModel,
)
from protector.pilot.storage.repositories import (
    IdempotencyConflictError,
    PilotRepository,
    RetiredRuntimeWriterError,
    StaleRuntimeWriterGenerationError,
)
from tests.pilot.test_camera_rule_authority import (
    _decision_envelope,
    _rule,
    _ruleset,
    _sign,
    _verified_decision,
    _verified_inputs,
)
from tests.pilot.test_event_provenance_repository import (
    NOW,
    _envelope,
    _event,
    configured_repository as _configured_repository_fixture,  # noqa: F401
)


@pytest.fixture
def configured_repository(_configured_repository_fixture):  # noqa: F811
    return _configured_repository_fixture

SOURCE_EPOCH_2 = UUID("22222222-2222-2222-2222-222222222222")


def test_verified_capabilities_are_exact_noncopyable_and_never_accept_compiled_authority(
    tmp_path: Path,
) -> None:
    site, rules = _verified_inputs(tmp_path, _rule())
    decision = _verified_decision(tmp_path, _decision_envelope())
    compiled = compile_verified_camera_rules(
        site_revision=site,
        ruleset_revision=rules,
        gate_decisions=(decision,),
    )

    for capability in (site, rules, decision, compiled):
        with pytest.raises(TypeError, match="capability|copy|serialize"):
            copy.copy(capability)
        with pytest.raises(TypeError, match="capability|copy|serialize"):
            copy.deepcopy(capability)
        with pytest.raises((TypeError, pickle.PickleError), match="capability|pickle|serialize"):
            pickle.dumps(capability)

    parameters = inspect.signature(
        PilotRepository.provision_reviewed_configuration
    ).parameters
    assert "compiled_rules" not in parameters
    assert {"site_revision", "ruleset_revision", "gate_decisions"} <= set(parameters)
    with pytest.raises(TypeError):
        VerifiedCameraRulesetRevision(
            authority=object(),
            document=rules.document,
            attestation=rules.attestation,
        )
    forged = object.__new__(VerifiedCameraRulesetRevision)
    object.__setattr__(
        forged,
        "_authority",
        object.__getattribute__(rules, "_authority"),
    )
    object.__setattr__(forged, "_document", rules.document)
    object.__setattr__(forged, "_attestation", rules.attestation)
    with pytest.raises(TypeError, match="altered|capability"):
        compile_verified_camera_rules(
            site_revision=site,
            ruleset_revision=forged,
            gate_decisions=(decision,),
        )


@pytest.mark.parametrize(
    ("review_status", "evidence_status", "history"),
    (
        ("observation", "pending", ("observation",)),
        ("confirmed", "pending", ("observation", "candidate", "confirmed")),
        ("rejected", "pending", ("observation", "candidate", "rejected")),
        ("expired", "pending", ("observation", "candidate", "expired")),
        ("escalated", "pending", ("observation", "candidate", "confirmed", "escalated")),
        ("candidate", "ready", ("observation", "candidate")),
        ("candidate", "failed", ("observation", "candidate")),
        ("candidate", "unavailable", ("observation", "candidate")),
        ("candidate", "pending", ("observation",)),
    ),
)
def test_runtime_provenance_accepts_only_fresh_pending_candidates(
    review_status: str,
    evidence_status: str,
    history: tuple[str, ...],
) -> None:
    event = _event().model_copy(
        update={
            "review_status": review_status,
            "evidence_status": evidence_status,
            "transition_history": history,
        }
    )
    provenance = CandidateEventProvenanceV1(
        site_id="site-1",
        runtime_session_id="runtime-1",
        runtime_writer_generation=1,
        configuration_activation_generation=1,
        source_epoch=UUID("11111111-1111-1111-1111-111111111111"),
        rule_id="camera-01-weapon",
        rule_revision=1,
        rule_revision_sha256="1" * 64,
        ruleset_sha256="2" * 64,
        site_config_sha256="3" * 64,
        model_gate_decision_sha256="4" * 64,
        gate_mode="operator",
    )
    with pytest.raises(ValueError, match="candidate|pending|transition"):
        ProvenancedCandidateEventV2(event=event, provenance=provenance)


def test_gate_envelope_requires_exact_bindings_and_measured_25_percent_headroom() -> None:
    valid = _decision_envelope()
    assert valid.measured_effective_throughput_hz >= (
        valid.required_effective_throughput_hz * 1.25
    )

    for field in (
        "site_config_sha256",
        "target_site_report_sha256",
        "measured_capacity_report_sha256",
        "frozen_workload_sha256",
        "engine_sha256",
        "runtime_manifest_sha256",
    ):
        with pytest.raises(ValidationError):
            OperationalGateDecisionEnvelopeV2.model_validate(
                {**valid.model_dump(mode="json"), field: "not-a-digest"}
            )
    with pytest.raises(ValidationError, match="25%|headroom"):
        OperationalGateDecisionEnvelopeV2.model_validate(
            {
                **valid.model_dump(mode="json"),
                "required_effective_throughput_hz": 100.0,
                "measured_effective_throughput_hz": 124.999,
            }
        )
    for invalid in (True, math.nan, math.inf, -math.inf):
        with pytest.raises(ValidationError):
            OperationalGateDecisionEnvelopeV2.model_validate(
                {
                    **valid.model_dump(mode="json"),
                    "measured_effective_throughput_hz": invalid,
                }
            )


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("revision", True),
        ("revision", "1"),
        ("enabled", 1),
        ("minimum_confidence", True),
        ("minimum_confidence", math.nan),
        ("minimum_confidence", math.inf),
        ("minimum_votes", 2.0),
        ("minimum_votes", "2"),
        ("sample_count", True),
        ("sample_count", "2"),
        ("window_seconds", True),
        ("window_seconds", math.nan),
        ("window_seconds", math.inf),
        ("evidence_seconds", 6.0),
        ("evidence_seconds", "6"),
    ),
)
def test_camera_rule_numerics_are_strict_and_finite(
    field: str,
    invalid: object,
) -> None:
    payload = _rule().model_dump(mode="python")
    payload[field] = invalid
    with pytest.raises(ValidationError):
        CameraRuleV1.model_validate(payload)


def test_ruleset_rejects_gate_replay_after_config_or_workload_change(
    tmp_path: Path,
) -> None:
    site, rules = _verified_inputs(tmp_path, _rule())
    decision = _verified_decision(tmp_path, _decision_envelope())
    changed = decision.decision.model_copy(
        update={"frozen_workload_sha256": "f" * 64}
    )
    changed_verified = _verified_decision(
        tmp_path,
        changed,
        name="changed-workload-decision",
    )

    with pytest.raises(ValueError, match="workload|binding|decision"):
        compile_verified_camera_rules(
            site_revision=site,
            ruleset_revision=rules,
            gate_decisions=(changed_verified,),
        )


def test_signed_parser_rejects_duplicate_keys_aliases_and_excessive_nesting(
    tmp_path: Path,
) -> None:
    document = _ruleset(_rule())
    payload = json.dumps(document.model_dump(mode="json"), separators=(",", ":"))
    duplicate = payload.replace(
        '"schema_version":"reviewed-camera-ruleset.v1"',
        '"schema_version":"reviewed-camera-ruleset.v1","schema_version":"reviewed-camera-ruleset.v1"',
        1,
    ).encode()
    path, signature, public_key = _sign(tmp_path, "duplicate-rules", duplicate)
    with pytest.raises(ValueError, match="duplicate"):
        load_verified_camera_ruleset(
            payload_path=path,
            signature_path=signature,
            trusted_public_key_path=public_key,
            expected_payload_sha256=__import__("hashlib").sha256(duplicate).hexdigest(),
            expected_site_id="site-1",
        )

    alias_payload = b"rules: &rules []\ncopy: *rules\n"
    path, signature, public_key = _sign(tmp_path, "alias-rules", alias_payload)
    with pytest.raises(ValueError, match="JSON|alias|document"):
        load_verified_camera_ruleset(
            payload_path=path,
            signature_path=signature,
            trusted_public_key_path=public_key,
            expected_payload_sha256=__import__("hashlib").sha256(alias_payload).hexdigest(),
            expected_site_id="site-1",
        )


def test_discriminated_rule_specs_are_bounded_and_one_rule_id_is_unique() -> None:
    module = ModuleRuleSpecV1(
        kind="module",
        source_module="weapon",
        class_names=("handgun", "knife"),
        reason="weapon candidate",
        merge_window_seconds=2.0,
        cooldown_seconds=10.0,
    )
    zone = ZoneRuleSpecV1(
        kind="zone",
        mode="loitering",
        polygon=((0.1, 0.1), (0.9, 0.1), (0.9, 0.9), (0.1, 0.9)),
        loiter_seconds=5.0,
        reason="reviewed zone loitering",
        merge_window_seconds=2.0,
        cooldown_seconds=10.0,
    )
    line = LineRuleSpecV1(
        kind="line",
        start=(0.1, 0.5),
        end=(0.9, 0.5),
        direction="positive_to_negative",
        reason="reviewed line crossing",
        merge_window_seconds=0.0,
        cooldown_seconds=2.0,
    )
    assert {module.kind, zone.kind, line.kind} == {"module", "zone", "line"}

    with pytest.raises(ValidationError):
        ZoneRuleSpecV1(
            kind="zone",
            mode="intrusion",
            polygon=((0.0, 0.0),) * 33,
            reason="bad",
            merge_window_seconds=0.0,
            cooldown_seconds=0.0,
        )
    with pytest.raises(ValidationError):
        LineRuleSpecV1(
            kind="line",
            start=(0.1, 0.1),
            end=(0.1, 0.1),
            direction="positive_to_negative",
            reason="bad",
            merge_window_seconds=0.0,
            cooldown_seconds=0.0,
        )
    duplicate = _rule().model_copy(update={"camera_id": "camera-02"})
    base = _ruleset(_rule())
    with pytest.raises(ValidationError, match="rule_id"):
        ReviewedCameraRulesetV1.create(
            ruleset_revision_id=base.ruleset_revision_id,
            ruleset_id=base.ruleset_id,
            revision=base.revision,
            site_id=base.site_id,
            site_config_sha256=base.site_config_sha256,
            frozen_workload_sha256=base.frozen_workload_sha256,
            engine_sha256=base.engine_sha256,
            runtime_manifest_sha256=base.runtime_manifest_sha256,
            rules=(_rule(), duplicate),
            reviewed_by=base.reviewed_by,
            reviewed_at=base.reviewed_at,
            review_reference=base.review_reference,
        )


def test_compiler_constructs_exact_per_camera_event_engines(tmp_path: Path) -> None:
    site, rules = _verified_inputs(
        tmp_path,
        _rule(camera_id="camera-01"),
        _rule(camera_id="camera-02"),
    )
    decision = _verified_decision(tmp_path, _decision_envelope())
    compiled = compile_verified_camera_rules(
        site_revision=site,
        ruleset_revision=rules,
        gate_decisions=(decision,),
    )

    first = compiled.build_event_engine(camera_id="camera-01")
    second = compiled.build_event_engine(camera_id="camera-02")

    assert first is not second
    assert compiled.rule_ids_for_camera("camera-01") == ("camera-01-weapon",)
    assert compiled.rule_ids_for_camera("camera-02") == ("camera-02-weapon",)
    with pytest.raises(KeyError):
        compiled.build_event_engine(camera_id="camera-99")


def test_writer_generation_cas_session_ids_and_camera_epoch_are_non_resurrectable(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    receipt = repository.issue_runtime_writer_receipt(
        site_id="site-1",
        runtime_session_id="runtime-session-1",
        issued_at=NOW,
        expected_writer_generation=activation.runtime_writer_generation,
    )
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(
            (TypeError, pickle.PickleError),
            match="capability|copy|serialize|pickle",
        ):
            operation(receipt)
    with pytest.raises(TypeError, match="repository|receipt"):
        RuntimeWriterReceiptV1()
    with pytest.raises(TypeError, match="copy"):
        receipt.model_copy()
    epoch_receipt = repository.activate_camera_epoch(
        receipt=receipt,
        camera_id="camera-01",
        source_epoch=UUID("11111111-1111-1111-1111-111111111111"),
        expected_source_epoch=None,
        activated_at=NOW,
    )
    assert isinstance(epoch_receipt, CameraEpochActivationReceiptV1)
    assert epoch_receipt.runtime_writer_generation == receipt.runtime_writer_generation
    rotated_epoch = repository.activate_camera_epoch(
        receipt=receipt,
        camera_id="camera-01",
        source_epoch=SOURCE_EPOCH_2,
        expected_source_epoch=epoch_receipt.source_epoch,
        activated_at=NOW + timedelta(milliseconds=1),
    )
    assert rotated_epoch.source_epoch == SOURCE_EPOCH_2
    with pytest.raises(ValueError, match="epoch|stale"):
        repository.activate_camera_epoch(
            receipt=receipt,
            camera_id="camera-01",
            source_epoch=UUID("33333333-3333-3333-3333-333333333333"),
            expected_source_epoch=epoch_receipt.source_epoch,
            activated_at=NOW + timedelta(milliseconds=2),
        )
    with pytest.raises(StaleRuntimeWriterGenerationError):
        repository.issue_runtime_writer_receipt(
            site_id="site-1",
            runtime_session_id="runtime-session-2",
            issued_at=NOW + timedelta(seconds=1),
            expected_writer_generation=receipt.runtime_writer_generation - 1,
        )

    replacement = repository.issue_runtime_writer_receipt(
        site_id="site-1",
        runtime_session_id="runtime-session-2",
        issued_at=NOW + timedelta(seconds=2),
        expected_writer_generation=receipt.runtime_writer_generation,
    )
    with pytest.raises(RetiredRuntimeWriterError, match="epoch|retired"):
        repository.activate_camera_epoch(
            receipt=replacement,
            camera_id="camera-01",
            source_epoch=epoch_receipt.source_epoch,
            expected_source_epoch=rotated_epoch.source_epoch,
            activated_at=NOW + timedelta(seconds=2, milliseconds=1),
        )
    with pytest.raises(RetiredRuntimeWriterError, match="reused|retired"):
        repository.issue_runtime_writer_receipt(
            site_id="site-1",
            runtime_session_id="runtime-session-1",
            issued_at=NOW + timedelta(seconds=3),
            expected_writer_generation=replacement.runtime_writer_generation,
        )
    with repository.session_factory() as session:
        sessions = list(session.scalars(select(RuntimeWriterSessionModel)))
        epoch = session.get(CameraEpochAuthorityModel, "camera-01")
    assert [row.runtime_session_id for row in sessions] == [
        "runtime-session-1",
        "runtime-session-2",
    ]
    assert epoch is not None


def test_activation_receipt_is_immutable_and_activation_uses_generation_cas(
    configured_repository,
) -> None:
    repository, activation = configured_repository

    assert isinstance(activation, ConfigurationActivationReceiptV1)
    assert activation.expected_activation_generation == 0
    with pytest.raises(ValidationError):
        activation.activation_generation = 99  # type: ignore[misc]
    exact_replay = repository.activate_reviewed_configuration(
        site_id="site-1",
        config_revision_id=activation.config_revision_id,
        ruleset_revision_id=activation.ruleset_revision_id,
        activated_by=activation.activated_by,
        activated_at=activation.activated_at,
        idempotency_key=activation.idempotency_key,
        expected_activation_generation=activation.expected_activation_generation,
        force_new_generation=activation.force_new_generation,
    )
    assert exact_replay == activation
    with pytest.raises(IdempotencyConflictError, match="different"):
        repository.activate_reviewed_configuration(
            site_id="site-1",
            config_revision_id=activation.config_revision_id,
            ruleset_revision_id=activation.ruleset_revision_id,
            activated_by="another-admin",
            activated_at=activation.activated_at,
            idempotency_key=activation.idempotency_key,
            expected_activation_generation=activation.expected_activation_generation,
            force_new_generation=activation.force_new_generation,
        )
    with pytest.raises(ValueError, match="activation|generation|stale"):
        repository.activate_reviewed_configuration(
            site_id="site-1",
            config_revision_id=activation.config_revision_id,
            ruleset_revision_id=activation.ruleset_revision_id,
            activated_by="admin-2",
            activated_at=NOW + timedelta(seconds=1),
            idempotency_key="stale-activation",
            expected_activation_generation=activation.activation_generation - 1,
            force_new_generation=True,
        )


def test_candidate_ingest_rejects_unactivated_or_wrong_camera_epoch(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    receipt = repository.issue_runtime_writer_receipt(
        site_id="site-1",
        runtime_session_id="runtime-session-1",
        issued_at=NOW,
        expected_writer_generation=activation.runtime_writer_generation,
    )
    with pytest.raises(RetiredRuntimeWriterError, match="epoch"):
        repository.store_provenanced_event(_envelope(_event(), receipt), receipt=receipt)
    repository.activate_camera_epoch(
        receipt=receipt,
        camera_id="camera-01",
        source_epoch=SOURCE_EPOCH_2,
        expected_source_epoch=None,
        activated_at=NOW,
    )
    with pytest.raises(RetiredRuntimeWriterError, match="epoch"):
        repository.store_provenanced_event(_envelope(_event(), receipt), receipt=receipt)


def test_migration_uses_function_only_atomic_ingest_legacy_cutoff_and_composite_fks() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "migrations/versions/0006_event_provenance.py"
    ).read_text(encoding="utf-8")

    assert "pilot_ingest_candidate" in source
    assert "SECURITY DEFINER" in source
    assert "GRANT EXECUTE ON FUNCTION pilot_ingest_candidate" in source
    assert "GRANT SELECT, INSERT ON TABLE candidate_events TO kuzet_runtime" not in source
    assert (
        "GRANT SELECT, INSERT ON TABLE candidate_event_provenance TO kuzet_runtime"
        not in source
    )
    assert "legacy_candidate_import" in source
    assert "legacy_cutoff_at" in source
    assert "FOR UPDATE" in source
    assert "camera_epoch_authorities" in source
    assert "runtime_writer_sessions" in source
    assert "site_id" in source and "ForeignKeyConstraint" in source
    assert source.index('op.drop_table("candidate_event_provenance")') < source.index(
        "DROP FUNCTION IF EXISTS pilot_ingest_candidate"
    )
