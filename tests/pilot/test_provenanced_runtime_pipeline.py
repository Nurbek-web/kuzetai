from __future__ import annotations

import copy
import pickle
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from protector.pilot.domain import (
    CameraEpochActivationReceiptV1,
    CandidateEventV1,
    RuntimeWriterReceiptV1,
)
from protector.pilot.runtime.event_engine import (
    CandidateTrigger,
    DebounceSpec,
    EventEngine,
    ModuleRule,
)
from protector.pilot.runtime.provenance import (
    ProvenanceRuleBinding,
    RuntimeCandidateAuthority,
    RuntimeCandidateAuthorityError,
    RuntimeJournalProcessor,
)
from protector.pilot.storage.journal import JournalItem, SQLiteWALJournal

NOW = datetime(2026, 7, 31, 0, 0, tzinfo=UTC)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


def _writer() -> RuntimeWriterReceiptV1:
    return RuntimeWriterReceiptV1._issue(
        site_id="site-1",
        runtime_session_id="runtime-1",
        runtime_writer_generation=7,
        configuration_activation_generation=4,
        config_revision_id="config-1",
        site_config_sha256=DIGEST_A,
        ruleset_revision_id="rules-1",
        ruleset_sha256=DIGEST_B,
        rule_revision_digests={"rule-1": DIGEST_C},
        issued_at=NOW,
    )


def _binding() -> ProvenanceRuleBinding:
    return ProvenanceRuleBinding(
        rule_id="rule-1",
        revision=3,
        rule_revision_sha256=DIGEST_C,
        camera_id="camera-01",
        module="intrusion",
        model_artifact_id="person-primary",
        model_gate_decision_sha256=DIGEST_D,
        gate_mode="operator",
    )


def _epoch(
    source_epoch: UUID,
    *,
    previous: UUID | None = None,
) -> CameraEpochActivationReceiptV1:
    return CameraEpochActivationReceiptV1(
        site_id="site-1",
        camera_id="camera-01",
        source_epoch=source_epoch,
        previous_source_epoch=previous,
        runtime_session_id="runtime-1",
        runtime_writer_generation=7,
        configuration_activation_generation=4,
        activated_at=NOW,
    )


def _trigger(source_epoch: UUID) -> CandidateTrigger:
    return CandidateTrigger(
        event=CandidateEventV1(
            event_id=uuid4(),
            camera_id="camera-01",
            module="intrusion",
            opened_at=NOW,
            last_seen_at=NOW,
            peak_confidence=0.91,
            reason="reviewed zone entry",
            model_artifact_id="person-primary",
            gate_mode="operator",
            evidence_status="pending",
            review_status="candidate",
        ),
        stream_epoch=source_epoch,
        track_id="track-1",
        rule_id="rule-1",
    )


def test_authority_binds_writer_rule_and_current_camera_epoch() -> None:
    source_epoch = uuid4()
    authority = RuntimeCandidateAuthority(
        writer_receipt=_writer(),
        rule_bindings=(_binding(),),
    )
    authority.activate_camera_epoch(_epoch(source_epoch))

    envelope = authority.build_envelope(_trigger(source_epoch))

    assert envelope.provenance.source_epoch == source_epoch
    assert envelope.provenance.runtime_writer_generation == 7
    assert envelope.provenance.configuration_activation_generation == 4
    assert envelope.provenance.rule_revision == 3
    assert envelope.provenance.rule_revision_sha256 == DIGEST_C
    assert envelope.event.evidence_status == "pending"


def test_authority_rejects_stale_and_noncausal_camera_epochs() -> None:
    first = uuid4()
    second = uuid4()
    authority = RuntimeCandidateAuthority(
        writer_receipt=_writer(),
        rule_bindings=(_binding(),),
    )
    authority.activate_camera_epoch(_epoch(first))

    with pytest.raises(RuntimeCandidateAuthorityError):
        authority.activate_camera_epoch(_epoch(second))
    with pytest.raises(RuntimeCandidateAuthorityError):
        authority.build_envelope(_trigger(second))

    authority.activate_camera_epoch(_epoch(second, previous=first))
    with pytest.raises(RuntimeCandidateAuthorityError):
        authority.build_envelope(_trigger(first))


def test_runtime_authorities_are_not_copyable_or_serializable() -> None:
    authority = RuntimeCandidateAuthority(
        writer_receipt=_writer(),
        rule_bindings=(_binding(),),
    )

    with pytest.raises(TypeError):
        copy.copy(authority)
    with pytest.raises(TypeError):
        copy.deepcopy(authority)
    with pytest.raises(TypeError):
        pickle.dumps(authority)


def test_v2_journal_round_trip_and_missing_seed_detection(tmp_path: Path) -> None:
    source_epoch = uuid4()
    authority = RuntimeCandidateAuthority(
        writer_receipt=_writer(),
        rule_bindings=(_binding(),),
    )
    authority.activate_camera_epoch(_epoch(source_epoch))
    envelope = authority.build_envelope(_trigger(source_epoch))
    journal = SQLiteWALJournal(
        tmp_path / "runtime.sqlite3",
        max_items=4,
    )

    item = journal.enqueue_provenanced_event(envelope)

    assert item.kind == "provenanced_candidate_event"
    assert item.schema_version == "provenanced-candidate-event.v2"
    assert journal.candidate_items_without_pending_evidence() == (item,)


def test_existing_journal_constraint_migrates_to_v2(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE journal_items (
            item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK (
                kind IN ('candidate_event', 'evidence', 'evidence_intent')
            ),
            schema_version TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.commit()
    connection.close()
    source_epoch = uuid4()
    authority = RuntimeCandidateAuthority(
        writer_receipt=_writer(),
        rule_bindings=(_binding(),),
    )
    authority.activate_camera_epoch(_epoch(source_epoch))

    journal = SQLiteWALJournal(path, max_items=4)
    item = journal.enqueue_provenanced_event(
        authority.build_envelope(_trigger(source_epoch))
    )

    assert item.kind == "provenanced_candidate_event"


class _Repository:
    def __init__(self) -> None:
        self.envelopes: list[object] = []
        self.other: list[JournalItem] = []

    def store_provenanced_event(
        self,
        envelope: object,
        *,
        receipt: object,
    ) -> object:
        self.envelopes.append((envelope, receipt))
        return object()

    def persist_journal_item(self, item: JournalItem) -> None:
        self.other.append(item)


def test_runtime_processor_replays_v2_and_rejects_legacy_candidate() -> None:
    source_epoch = uuid4()
    authority = RuntimeCandidateAuthority(
        writer_receipt=_writer(),
        rule_bindings=(_binding(),),
    )
    authority.activate_camera_epoch(_epoch(source_epoch))
    envelope = authority.build_envelope(_trigger(source_epoch))
    repository = _Repository()
    processor = RuntimeJournalProcessor(
        repository=repository,  # type: ignore[arg-type]
        writer_receipt=_writer(),
    )
    v2_item = JournalItem(
        item_id=1,
        kind="provenanced_candidate_event",
        schema_version=envelope.schema_version,
        idempotency_key=envelope.event.dedupe_key,
        payload=envelope.model_dump(mode="json"),
        created_at=NOW,
    )

    processor(v2_item)

    assert len(repository.envelopes) == 1
    legacy = _trigger(source_epoch).event
    with pytest.raises(RuntimeCandidateAuthorityError):
        processor(
            JournalItem(
                item_id=2,
                kind="candidate_event",
                schema_version=legacy.schema_version,
                idempotency_key=legacy.dedupe_key,
                payload=legacy.model_dump(mode="json"),
                created_at=NOW,
            )
        )


def test_event_engine_can_be_frozen_to_pending_production_candidates() -> None:
    engine = EventEngine(
        module_rules=(
            ModuleRule(
                rule_id="rule-1",
                event_module="intrusion",
                source_module="person",
                class_names=("person",),
                gate_mode="operator",
                reason="reviewed zone entry",
                min_confidence=0.5,
                debounce=DebounceSpec(
                    votes_required=1,
                    sample_count=1,
                    window_seconds=1.0,
                ),
            ),
        ),
        initial_evidence_status="pending",
    )

    assert engine.initial_evidence_status == "pending"
    with pytest.raises(ValueError):
        EventEngine(initial_evidence_status="ready")  # type: ignore[arg-type]
