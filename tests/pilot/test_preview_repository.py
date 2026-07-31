from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, update

from protector.pilot.domain import LegacyCandidateImportV1
from protector.pilot.storage.models import (
    AuditEntryModel,
    CameraRuleRevisionModel,
    CameraRulesetRevisionModel,
    CandidateEventModel,
    PreviewAccessReceiptModel,
    PreviewPublicationModel,
    SiteConfigRevisionModel,
    UserModel,
)
from protector.pilot.storage.preview import (
    PreviewAccessReceipt,
    PreviewObjectContext,
    PreviewObjectReceiptV1,
)
from protector.pilot.storage.repositories import (
    EvidenceInput,
    IdempotencyConflictError,
    ReviewedConfigurationConflictError,
    RetiredRuntimeWriterError,
)
from tests.pilot.test_event_provenance_repository import (
    NOW,
    _envelope,
    _event,
    _issue_writer,
    configured_repository as _configured_repository_fixture,  # noqa: F401
)


@pytest.fixture
def configured_repository(_configured_repository_fixture):  # noqa: F811
    return _configured_repository_fixture


def _stored_candidate(repository, activation):
    writer = _issue_writer(repository, activation)
    envelope = _envelope(_event(), writer)
    repository.store_provenanced_event(envelope, receipt=writer)
    return writer, envelope


def _context(envelope) -> PreviewObjectContext:
    provenance = envelope.provenance
    return PreviewObjectContext(
        site_id=provenance.site_id,
        event_id=envelope.event.event_id,
        evidence_id=uuid4(),
        configuration_sha256=provenance.site_config_sha256,
        runtime_session_id=provenance.runtime_session_id,
        runtime_writer_generation=provenance.runtime_writer_generation,
        configuration_activation_generation=(
            provenance.configuration_activation_generation
        ),
        source_epoch=provenance.source_epoch,
        rule_revision_sha256=provenance.rule_revision_sha256,
        candidate_body_sha256=envelope.body_sha256,
    )


def _object_key(context: PreviewObjectContext, sha256: str) -> str:
    return (
        f"{context.site_id}/{context.event_id}/"
        f"{context.evidence_id}/{sha256}.mp4"
    )


def _prepare(repository, context, *, requested_at=None, expires_at=None):
    requested_at = requested_at or datetime.now(UTC)
    expires_at = expires_at or requested_at + timedelta(minutes=15)
    sha256 = "d" * 64
    return repository.prepare_preview_publication(
        context=context,
        object_key=_object_key(context, sha256),
        sha256=sha256,
        requested_at=requested_at,
        expires_at=expires_at,
    )


def _receipt(intent, *, version_id="version-1", etag='"etag-1"'):
    return PreviewObjectReceiptV1(
        schema_version="preview-object-receipt.v1",
        site_id=intent.site_id,
        event_id=intent.event_id,
        evidence_id=intent.evidence_id,
        object_key=intent.object_key,
        sha256=intent.sha256,
        checksum_sha256=base64.b64encode(bytes.fromhex(intent.sha256)).decode(),
        size_bytes=1024,
        media_type="video/mp4",
        etag=etag,
        version_id=version_id,
        server_side_encryption="AES256",
        kms_key_id=None,
        configuration_sha256=intent.configuration_sha256,
        runtime_session_id=intent.runtime_session_id,
        runtime_writer_generation=intent.runtime_writer_generation,
        configuration_activation_generation=(
            intent.configuration_activation_generation
        ),
        source_epoch=intent.source_epoch,
        rule_revision_sha256=intent.rule_revision_sha256,
        candidate_body_sha256=intent.candidate_body_sha256,
        created_at=intent.created_at,
    )


def _ready_evidence(repository, intent) -> None:
    evidence = EvidenceInput(
        evidence_id=intent.evidence_id,
        event_id=intent.event_id,
        object_key=f"{intent.site_id}/evidence/{intent.evidence_id}.mp4",
        sha256="e" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=6),
        source_reference="runtime-ring:camera-01",
        status="pending",
    )
    repository.finalize_evidence(evidence, status="ready")


def _provision_storage_changed_revision(repository) -> None:
    with repository.session_factory.begin() as session:
        current_config = session.get(SiteConfigRevisionModel, "site-config-1")
        current_ruleset = session.get(
            CameraRulesetRevisionModel,
            "ruleset-1",
        )
        assert current_config is not None
        assert current_ruleset is not None
        config_values = {
            column.name: getattr(current_config, column.name)
            for column in SiteConfigRevisionModel.__table__.columns
        }
        changed_config = copy.deepcopy(current_config.canonical_config)
        changed_config["storage"]["bucket"] = "rotated-preview-bucket"
        config_values.update(
            config_revision_id="site-config-2",
            revision=2,
            config_sha256="f" * 64,
            canonical_config=changed_config,
        )
        session.add(SiteConfigRevisionModel(**config_values))

        ruleset_values = {
            column.name: getattr(current_ruleset, column.name)
            for column in CameraRulesetRevisionModel.__table__.columns
        }
        ruleset_values.update(
            ruleset_revision_id="ruleset-2",
            revision=2,
            config_revision_id="site-config-2",
            site_config_sha256="f" * 64,
            ruleset_sha256="e" * 64,
        )
        session.add(CameraRulesetRevisionModel(**ruleset_values))
        current_rules = list(
            session.scalars(
                select(CameraRuleRevisionModel).where(
                    CameraRuleRevisionModel.ruleset_revision_id == "ruleset-1"
                )
            )
        )
        for current_rule in current_rules:
            rule_values = {
                column.name: getattr(current_rule, column.name)
                for column in CameraRuleRevisionModel.__table__.columns
            }
            rule_values["ruleset_revision_id"] = "ruleset-2"
            session.add(CameraRuleRevisionModel(**rule_values))


def test_activation_blocks_storage_rotation_after_first_activation(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    _provision_storage_changed_revision(repository)

    with pytest.raises(
        ReviewedConfigurationConflictError,
        match="immutable after first activation",
    ):
        repository.activate_reviewed_configuration(
            site_id="site-1",
            config_revision_id="site-config-2",
            ruleset_revision_id="ruleset-2",
            activated_by="admin-1",
            activated_at=NOW + timedelta(minutes=5),
            idempotency_key="activate-storage-rotation",
            expected_activation_generation=activation.activation_generation,
        )


def test_prepare_requires_exact_current_nonlegacy_candidate_provenance(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    writer, envelope = _stored_candidate(repository, activation)
    context = _context(envelope)

    derived = repository.get_preview_object_context(
        site_id=context.site_id,
        event_id=context.event_id,
        evidence_id=context.evidence_id,
        source_epoch=context.source_epoch,
    )
    assert derived == context
    with pytest.raises(RetiredRuntimeWriterError):
        repository.get_preview_object_context(
            site_id=context.site_id,
            event_id=context.event_id,
            evidence_id=context.evidence_id,
            source_epoch=UUID("22222222-2222-2222-2222-222222222222"),
        )

    intent = _prepare(repository, context)
    assert intent.context == context
    assert (
        repository.get_active_site_config_sha256(site_id=context.site_id)
        == context.configuration_sha256
    )

    for changed in (
        replace(context, site_id="site-2"),
        replace(context, runtime_writer_generation=writer.runtime_writer_generation + 1),
        replace(
            context,
            configuration_activation_generation=(
                writer.configuration_activation_generation + 1
            ),
        ),
        replace(
            context,
            source_epoch=UUID("22222222-2222-2222-2222-222222222222"),
        ),
        replace(context, configuration_sha256="1" * 64),
        replace(context, rule_revision_sha256="2" * 64),
        replace(context, candidate_body_sha256="3" * 64),
    ):
        with pytest.raises((ValueError, RetiredRuntimeWriterError)):
            _prepare(repository, changed)

    legacy_event = _event()
    repository.import_pre_migration_legacy_event(
        legacy_event,
        marker=LegacyCandidateImportV1(
            event_id=legacy_event.event_id,
            imported_at=NOW + timedelta(seconds=2),
            legacy_cutoff_at=NOW + timedelta(seconds=1),
        ),
    )
    with pytest.raises(ValueError, match="provenance|legacy"):
        _prepare(repository, replace(context, event_id=legacy_event.event_id))


def test_prepare_is_stable_but_rejects_conflicts_and_retired_authority(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    _, envelope = _stored_candidate(repository, activation)
    context = _context(envelope)
    requested_at = datetime.now(UTC)

    first = _prepare(repository, context, requested_at=requested_at)
    replay = _prepare(
        repository,
        context,
        requested_at=requested_at + timedelta(seconds=5),
        expires_at=requested_at + timedelta(minutes=20),
    )
    assert replay == first

    with pytest.raises(IdempotencyConflictError):
        repository.prepare_preview_publication(
            context=context,
            object_key=first.object_key,
            sha256="f" * 64,
            requested_at=requested_at,
            expires_at=requested_at + timedelta(minutes=15),
        )

    repository.issue_runtime_writer_receipt(
        site_id=context.site_id,
        runtime_session_id="runtime-session-2",
        issued_at=NOW + timedelta(minutes=2),
        expected_writer_generation=activation.runtime_writer_generation,
    )
    with pytest.raises(RetiredRuntimeWriterError):
        _prepare(repository, context)


def test_finalize_is_exact_idempotent_and_visibility_requires_exact_ready_evidence(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    _, envelope = _stored_candidate(repository, activation)
    intent = _prepare(repository, _context(envelope))
    receipt = _receipt(intent)

    repository.finalize_preview_receipt(intent=intent, receipt=receipt)
    repository.finalize_preview_receipt(intent=intent, receipt=receipt)
    assert (
        repository.get_preview_receipt(
            site_id=intent.site_id,
            event_id=intent.event_id,
        )
        is None
    )

    unrelated = EvidenceInput(
        evidence_id=uuid4(),
        event_id=intent.event_id,
        object_key=f"{intent.site_id}/evidence/unrelated.mp4",
        sha256="e" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=6),
        source_reference="runtime-ring:camera-01",
        status="pending",
    )
    repository.finalize_evidence(unrelated, status="ready")
    assert repository.get_preview_receipt(
        site_id=intent.site_id,
        event_id=intent.event_id,
    ) is None

    with repository.session_factory.begin() as session:
        event = session.get(CandidateEventModel, str(intent.event_id))
        assert event is not None
        event.evidence_status = "pending"
    _ready_evidence(repository, intent)
    assert repository.get_preview_receipt(
        site_id=intent.site_id,
        event_id=intent.event_id,
    ) == receipt

    with pytest.raises(IdempotencyConflictError):
        repository.finalize_preview_receipt(
            intent=intent,
            receipt=_receipt(intent, version_id="version-2"),
        )


def test_version_id_identity_is_scoped_to_each_object_key(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    writer = _issue_writer(repository, activation)
    first_envelope = _envelope(_event(reason="first candidate"), writer)
    second_envelope = _envelope(_event(reason="second candidate"), writer)
    repository.store_provenanced_event(first_envelope, receipt=writer)
    repository.store_provenanced_event(second_envelope, receipt=writer)
    first = _prepare(repository, _context(first_envelope))
    second = _prepare(repository, _context(second_envelope))

    repository.finalize_preview_receipt(
        intent=first,
        receipt=_receipt(
            first,
            version_id="provider-key-scoped-version",
            etag='"etag-first"',
        ),
    )
    repository.finalize_preview_receipt(
        intent=second,
        receipt=_receipt(
            second,
            version_id="provider-key-scoped-version",
            etag='"etag-second"',
        ),
    )

    with repository.session_factory() as session:
        rows = list(
            session.scalars(
                select(PreviewPublicationModel).where(
                    PreviewPublicationModel.version_id
                    == "provider-key-scoped-version"
                )
            )
        )
    assert {row.object_key for row in rows} == {
        first.object_key,
        second.object_key,
    }


def test_access_rechecks_actor_receipt_and_evidence_and_audits_redacted(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    _, envelope = _stored_candidate(repository, activation)
    intent = _prepare(repository, _context(envelope))
    receipt = _receipt(intent)
    repository.finalize_preview_receipt(intent=intent, receipt=receipt)
    _ready_evidence(repository, intent)
    repository.add_user(
        user_id="viewer-1",
        username="viewer",
        password_hash="argon2id:test",
        role="viewer",
    )
    access = PreviewAccessReceipt(
        schema_version="preview-access-receipt.v1",
        access_id=uuid4(),
        site_id=intent.site_id,
        event_id=intent.event_id,
        actor_id="viewer-1",
        receipt_sha256=receipt.receipt_sha256,
        occurred_at=datetime.now(UTC),
    )

    assert repository.commit_preview_access(access) is True
    assert repository.commit_preview_access(access) is True
    with pytest.raises(ValueError, match="current server time"):
        repository.commit_preview_access(
            replace(
                access,
                access_id=uuid4(),
                occurred_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
    with repository.session_factory() as session:
        rows = list(session.scalars(select(PreviewAccessReceiptModel)))
        audits = list(
            session.scalars(
                select(AuditEntryModel).where(
                    AuditEntryModel.action == "preview.accessed"
                )
            )
        )
    assert len(rows) == len(audits) == 1
    serialized = str(audits[0].payload).lower()
    for forbidden in (
        intent.object_key,
        receipt.etag.lower(),
        receipt.version_id,
        "kms",
        "source_reference",
    ):
        assert forbidden not in serialized
    assert repository.prune_preview_access_receipts(
        site_id=intent.site_id,
        cutoff_at=access.occurred_at + timedelta(seconds=1),
        limit=1,
    ) == 1
    with repository.session_factory() as session:
        assert session.get(PreviewAccessReceiptModel, str(access.access_id)) is None
        assert session.scalar(
            select(AuditEntryModel).where(
                AuditEntryModel.action == "preview.accessed"
            )
        ) is not None

    with repository.session_factory.begin() as session:
        session.execute(
            update(UserModel)
            .where(UserModel.user_id == "viewer-1")
            .values(is_active=False)
        )
    denied = replace(access, access_id=uuid4())
    assert repository.commit_preview_access(denied) is False


def test_access_audit_failure_rolls_back_receipt_insert(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    _, envelope = _stored_candidate(repository, activation)
    intent = _prepare(repository, _context(envelope))
    receipt = _receipt(intent)
    repository.finalize_preview_receipt(intent=intent, receipt=receipt)
    _ready_evidence(repository, intent)
    repository.add_user(
        user_id="viewer-2",
        username="viewer2",
        password_hash="argon2id:test",
        role="viewer",
    )
    access = PreviewAccessReceipt(
        schema_version="preview-access-receipt.v1",
        access_id=uuid4(),
        site_id=intent.site_id,
        event_id=intent.event_id,
        actor_id="viewer-2",
        receipt_sha256=receipt.receipt_sha256,
        occurred_at=datetime.now(UTC),
    )
    with repository.session_factory.begin() as session:
        session.add(
            AuditEntryModel(
                audit_id=str(uuid4()),
                site_id=intent.site_id,
                occurred_at=access.occurred_at,
                actor_user_id="viewer-2",
                action="conflict",
                entity_type="candidate_event",
                entity_id=str(intent.event_id),
                payload={},
                idempotency_key=f"preview-access:{access.access_id}",
            )
        )

    with pytest.raises(IdempotencyConflictError):
        repository.commit_preview_access(access)
    with repository.session_factory() as session:
        assert session.get(PreviewAccessReceiptModel, str(access.access_id)) is None


def test_retention_terminalizes_retries_and_prunes_finitely(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    _, envelope = _stored_candidate(repository, activation)
    intent = _prepare(repository, _context(envelope))
    receipt = _receipt(intent)
    repository.finalize_preview_receipt(intent=intent, receipt=receipt)
    _ready_evidence(repository, intent)
    cutoff = datetime.now(UTC) + timedelta(days=1)

    claimed = repository.claim_preview_receipts_for_retention(
        site_id=intent.site_id,
        cutoff_at=cutoff,
        limit=1,
    )
    assert claimed == (receipt,)
    assert repository.get_preview_receipt(
        site_id=intent.site_id,
        event_id=intent.event_id,
    ) is None
    assert repository.claim_preview_receipts_for_retention(
        site_id=intent.site_id,
        cutoff_at=cutoff,
        limit=1,
    ) == (receipt,)
    assert repository.preview_version_is_protected(
        site_id=intent.site_id,
        object_key=receipt.object_key,
        version_id=receipt.version_id,
        observed_at=cutoff,
    )
    assert repository.finalize_preview_retirement(
        site_id=intent.site_id,
        event_id=intent.event_id,
        receipt_sha256=receipt.receipt_sha256,
        retired_at=cutoff,
    )
    assert not repository.preview_version_is_protected(
        site_id=intent.site_id,
        object_key=receipt.object_key,
        version_id=receipt.version_id,
        observed_at=cutoff,
    )
    assert repository.finalize_preview_retirement(
        site_id=intent.site_id,
        event_id=intent.event_id,
        receipt_sha256=receipt.receipt_sha256,
        retired_at=cutoff + timedelta(seconds=1),
    )
    with pytest.raises(IdempotencyConflictError, match="retired|terminal"):
        repository.finalize_preview_receipt(intent=intent, receipt=receipt)
    with pytest.raises(IdempotencyConflictError, match="terminal|resurrected"):
        _prepare(repository, intent.context)

    assert repository.prune_preview_access_receipts(
        site_id=intent.site_id,
        cutoff_at=cutoff,
        limit=1,
    ) == 0
    with repository.session_factory() as session:
        row = session.get(PreviewPublicationModel, str(intent.event_id))
        assert row is not None and row.publication_state == "retired"


def test_expired_intent_retirement_is_terminal_and_bounded(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    _, envelope = _stored_candidate(repository, activation)
    context = _context(envelope)
    requested_at = datetime.now(UTC)
    intent = _prepare(
        repository,
        context,
        requested_at=requested_at,
        expires_at=requested_at + timedelta(minutes=1),
    )
    assert repository.preview_version_is_protected(
        site_id=intent.site_id,
        object_key=intent.object_key,
        version_id="unregistered-version",
        observed_at=requested_at + timedelta(seconds=30),
    )
    assert repository.retire_expired_preview_intents(
        site_id=intent.site_id,
        observed_at=intent.expires_at,
        limit=1,
    ) == 1
    assert not repository.preview_version_is_protected(
        site_id=intent.site_id,
        object_key=intent.object_key,
        version_id="unregistered-version",
        observed_at=intent.expires_at,
    )
    with pytest.raises((IdempotencyConflictError, ValueError)):
        _prepare(repository, context)
