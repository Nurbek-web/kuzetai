from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, update

from protector.pilot.domain import (
    CandidateEventProvenanceV1,
    CandidateEventV1,
    ConfigurationActivationReceiptV1,
    LegacyCandidateImportV1,
    ProvenancedCandidateEventV2,
)
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.provisioning import provision_reviewed_configuration_revisions
from protector.pilot.rules import (
    CameraRuleV1,
)
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    ActivePilotConfigurationModel,
    AuditEntryModel,
    Base,
    CandidateEventModel,
    SiteConfigRevisionModel,
)
from protector.pilot.storage.repositories import (
    IdempotencyConflictError,
    PilotRepository,
    RetiredRuntimeWriterError,
)
from tests.pilot.test_camera_rule_authority import (
    _decision_envelope,
    _verified_decision,
    _verified_inputs,
)

NOW = datetime(2026, 7, 31, 10, 0, tzinfo=UTC)
SOURCE_EPOCH = UUID("11111111-1111-1111-1111-111111111111")
SOURCE_EPOCH_2 = UUID("22222222-2222-2222-2222-222222222222")


@pytest.fixture
def configured_repository(
    tmp_path,
) -> tuple[PilotRepository, ConfigurationActivationReceiptV1]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name="Controlled Pilot")
    for number in range(1, 21):
        repository.add_camera(
            camera_id=f"camera-{number:02d}",
            site_id="site-1",
            name=f"Camera {number:02d}",
            source_reference=f"environment:PILOT_CAMERA_{number:02d}_RTSP_URL",
            codec="h264",
        )
    repository.add_model_artifact(
        ModelArtifactV1(
            schema_version="model-artifact.v1",
            artifact_id="weapon-v1",
            sha256="a" * 64,
            source="s3://registry/weapon-v1.onnx",
            commercial_rights=CommercialRightsRecordV1(
                schema_version="commercial-rights.v1",
                record_id="rights-1",
                terms_reference="contracts/weapon-v1.pdf",
                commercial_use_approved=True,
            ),
            class_list=("weapon",),
            preprocessing="letterbox-rgb",
            analytic="weapon",
        )
    )
    decision = _decision_envelope()
    rule = CameraRuleV1.create(
        rule_id="camera-01-weapon",
        revision=1,
        site_id="site-1",
        camera_id="camera-01",
        module="weapon",
        enabled=True,
        model_artifact_id="weapon-v1",
        model_decision_sha256=decision.authority_sha256,
        minimum_confidence=0.8,
        minimum_votes=2,
        window_seconds=3,
        evidence_seconds=6,
    )
    verified_site, verified_rules = _verified_inputs(tmp_path, rule)
    verified_decision = _verified_decision(
        tmp_path,
        decision,
        name="repository-decision",
    )
    provision_reviewed_configuration_revisions(
        session_factory=repository.session_factory,
        site_revision=verified_site,
        ruleset_revision=verified_rules,
        gate_decisions=(verified_decision,),
    )
    active = repository.activate_reviewed_configuration(
        site_id="site-1",
        config_revision_id="site-config-1",
        ruleset_revision_id="ruleset-1",
        activated_by="admin-1",
        activated_at=NOW,
        idempotency_key="activate-1",
        expected_activation_generation=0,
    )
    return repository, active


def test_activation_is_single_active_redacted_and_revisions_are_immutable(
    configured_repository,
) -> None:
    repository, active = configured_repository
    with repository.session_factory() as session:
        active_rows = list(session.scalars(select(ActivePilotConfigurationModel)))
        audits = list(
            session.scalars(
                select(AuditEntryModel).where(
                    AuditEntryModel.action == "pilot.configuration.activated"
                )
            )
        )
    assert len(active_rows) == 1
    assert isinstance(active, ConfigurationActivationReceiptV1)
    assert active_rows[0].activation_generation == active.activation_generation
    assert len(audits) == 1
    assert set(audits[0].payload) == {
        "activated_by",
        "expected_activation_generation",
        "activation_generation",
        "runtime_writer_generation",
        "config_revision_id",
        "site_config_sha256",
        "ruleset_revision_id",
        "ruleset_sha256",
        "force_new_generation",
    }
    assert "rtsp" not in str(audits[0].payload).lower()
    assert "signature" not in str(audits[0].payload).lower()

    with pytest.raises(ValueError, match="immutable"):
        with repository.session_factory.begin() as session:
            revision = session.get(SiteConfigRevisionModel, "site-config-1")
            assert revision is not None
            revision.reviewed_by = "attacker"
            session.flush()


def _event(*, event_id=None, reason: str = "weapon threshold met") -> CandidateEventV1:
    return CandidateEventV1(
        schema_version="candidate-event.v1",
        event_id=event_id or uuid4(),
        camera_id="camera-01",
        module="weapon",
        opened_at=NOW,
        last_seen_at=NOW + timedelta(seconds=2),
        peak_confidence=0.93,
        reason=reason,
        model_artifact_id="weapon-v1",
        gate_mode="operator",
        evidence_status="pending",
        review_status="candidate",
    )


def _envelope(event: CandidateEventV1, receipt, *, source_epoch=SOURCE_EPOCH):
    return ProvenancedCandidateEventV2(
        event=event,
        provenance=CandidateEventProvenanceV1(
            site_id="site-1",
            runtime_session_id=receipt.runtime_session_id,
            runtime_writer_generation=receipt.runtime_writer_generation,
            configuration_activation_generation=(
                receipt.configuration_activation_generation
            ),
            source_epoch=source_epoch,
            rule_id="camera-01-weapon",
            rule_revision=1,
            rule_revision_sha256=receipt.rule_revision_sha256(
                "camera-01-weapon"
            ),
            ruleset_sha256=receipt.ruleset_sha256,
            site_config_sha256=receipt.site_config_sha256,
            model_gate_decision_sha256=_decision_envelope().authority_sha256,
            gate_mode="operator",
        ),
    )


def _issue_writer(
    repository: PilotRepository,
    activation: ConfigurationActivationReceiptV1,
    *,
    runtime_session_id: str = "runtime-session-1",
    issued_at: datetime = NOW,
    source_epoch: UUID = SOURCE_EPOCH,
):
    receipt = repository.issue_runtime_writer_receipt(
        site_id="site-1",
        runtime_session_id=runtime_session_id,
        issued_at=issued_at,
        expected_writer_generation=activation.runtime_writer_generation,
    )
    repository.activate_camera_epoch(
        receipt=receipt,
        camera_id="camera-01",
        source_epoch=source_epoch,
        expected_source_epoch=None,
        activated_at=issued_at,
    )
    return receipt


def test_candidate_and_full_provenance_round_trip_atomically(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    receipt = _issue_writer(repository, activation)
    envelope = _envelope(_event(), receipt)

    first = repository.store_provenanced_event(envelope, receipt=receipt)
    replay = repository.store_provenanced_event(envelope, receipt=receipt)
    loaded = repository.get_provenanced_event(envelope.event.event_id)

    assert first.event.event_id == replay.event.event_id
    assert loaded.event == envelope.event
    assert loaded.provenance == envelope.provenance
    assert loaded.provenance.source_epoch == SOURCE_EPOCH
    assert loaded.provenance.runtime_session_id == "runtime-session-1"
    assert loaded.provenance.rule_revision_sha256 == receipt.rule_revision_sha256(
        "camera-01-weapon"
    )
    assert loaded.provenance.site_config_sha256 == receipt.site_config_sha256
    assert (
        loaded.provenance.model_gate_decision_sha256
        == _decision_envelope().authority_sha256
    )


def test_same_identity_with_different_body_is_a_replay_conflict(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    receipt = _issue_writer(repository, activation)
    event = _event()
    repository.store_provenanced_event(_envelope(event, receipt), receipt=receipt)

    with pytest.raises(IdempotencyConflictError, match="different"):
        repository.store_provenanced_event(
            _envelope(_event(event_id=event.event_id, reason="tampered"), receipt),
            receipt=receipt,
        )


def test_exact_replay_converges_after_evidence_state_advances(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    receipt = _issue_writer(repository, activation)
    envelope = _envelope(_event(), receipt)
    repository.store_provenanced_event(envelope, receipt=receipt)
    with repository.session_factory.begin() as session:
        session.execute(
            update(CandidateEventModel)
            .where(CandidateEventModel.event_id == str(envelope.event.event_id))
            .values(evidence_status="ready")
        )

    replay = repository.store_provenanced_event(envelope, receipt=receipt)

    assert replay.event.evidence_status == "ready"
    assert replay.provenance == envelope.provenance


def test_new_activation_fences_retired_queued_runtime_generation(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    retired = _issue_writer(repository, activation)
    replacement_activation = repository.activate_reviewed_configuration(
        site_id="site-1",
        config_revision_id="site-config-1",
        ruleset_revision_id="ruleset-1",
        activated_by="admin-1",
        activated_at=NOW + timedelta(minutes=1),
        idempotency_key="activate-2",
        expected_activation_generation=activation.activation_generation,
        force_new_generation=True,
    )

    with pytest.raises(RetiredRuntimeWriterError, match="retired"):
        repository.store_provenanced_event(
            _envelope(_event(), retired),
            receipt=retired,
        )

    current = repository.issue_runtime_writer_receipt(
        site_id="site-1",
        runtime_session_id="runtime-session-2",
        issued_at=NOW + timedelta(minutes=2),
        expected_writer_generation=replacement_activation.runtime_writer_generation,
    )
    repository.activate_camera_epoch(
        receipt=current,
        camera_id="camera-01",
        source_epoch=SOURCE_EPOCH_2,
        expected_source_epoch=None,
        activated_at=NOW + timedelta(minutes=2),
    )
    assert current.runtime_writer_generation > retired.runtime_writer_generation
    repository.store_provenanced_event(
        _envelope(_event(), current, source_epoch=SOURCE_EPOCH_2),
        receipt=current,
    )


def test_historical_v1_candidate_remains_readable_without_fabricated_provenance(
    configured_repository,
) -> None:
    repository, _ = configured_repository
    legacy = _event()
    marker = LegacyCandidateImportV1(
        event_id=legacy.event_id,
        imported_at=NOW + timedelta(seconds=4),
        legacy_cutoff_at=NOW + timedelta(seconds=3),
    )
    repository.import_pre_migration_legacy_event(legacy, marker=marker)

    assert repository.get_event(legacy.event_id) == legacy
    assert repository.get_provenanced_event(legacy.event_id, allow_legacy=True).event == legacy
    assert (
        repository.get_provenanced_event(legacy.event_id, allow_legacy=True).provenance
        is None
    )
    with pytest.raises(KeyError, match="provenance"):
        repository.get_provenanced_event(legacy.event_id)

    unmarked = _event()
    repository.add_event(unmarked)
    with pytest.raises(KeyError, match="legacy|marker|provenance"):
        repository.get_provenanced_event(unmarked.event_id, allow_legacy=True)

    too_late = _event()
    with pytest.raises(ValueError, match="cutoff|legacy"):
        repository.import_pre_migration_legacy_event(
            too_late,
            marker=LegacyCandidateImportV1(
                event_id=too_late.event_id,
                imported_at=NOW + timedelta(seconds=4),
                legacy_cutoff_at=NOW - timedelta(seconds=1),
            ),
        )


def test_disabled_provenance_cannot_be_constructed() -> None:
    event = _event().model_copy(update={"gate_mode": "disabled"})
    with pytest.raises(ValueError, match="disabled"):
        ProvenancedCandidateEventV2(
            event=event,
            provenance=CandidateEventProvenanceV1(
                site_id="site-1",
                runtime_session_id="runtime-session-1",
                runtime_writer_generation=1,
                configuration_activation_generation=1,
                source_epoch=SOURCE_EPOCH,
                rule_id="camera-01-weapon",
                rule_revision=1,
                rule_revision_sha256="1" * 64,
                ruleset_sha256="2" * 64,
                site_config_sha256="3" * 64,
                model_gate_decision_sha256="4" * 64,
                gate_mode="disabled",
            ),
        )
