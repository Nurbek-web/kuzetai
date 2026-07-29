from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event, Lock
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from protector.pilot.domain import CandidateEventV1, ObservationV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.runtime.event_engine import (
    DebounceSpec,
    EngineLimits,
    EventEngine,
    EvidencePolicy,
    ModuleRule,
    SiteEventService,
)
from protector.pilot.runtime.evidence import EncodedFragmentRing
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.journal import (
    EvidenceJournalReplayWorker,
    SQLiteWALJournal,
)
from protector.pilot.storage.models import Base
from protector.pilot.storage.object_store import (
    EncryptedLocalObjectStore,
    EncryptedVolumeAttestation,
    EvidenceCoordinator,
    EvidencePublisher,
    PreviewWorkspace,
)
from protector.pilot.storage.repositories import (
    EvidenceInput,
    EvidenceIntent,
    PilotRepository,
)

UTC = timezone.utc
NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
EPOCH_A = UUID("10000000-0000-0000-0000-000000000001")
EPOCH_B = UUID("20000000-0000-0000-0000-000000000002")


def _observation(
    *,
    seq: int,
    seconds: float,
    camera_id: str = "cam-01",
    stream_epoch: UUID = EPOCH_A,
    module: str = "weapon",
    class_name: str = "handgun",
    confidence: float = 0.9,
    bbox: tuple[float, float, float, float] = (0.1, 0.1, 0.3, 0.4),
    track_id: str | None = "track-1",
    sample_kind: str = "fresh",
    runtime_state: str = "online",
    observation_id: UUID | None = None,
    model_artifact_id: str | None = None,
) -> ObservationV1:
    source_time = NOW + timedelta(seconds=seconds)
    return ObservationV1(
        schema_version="observation.v1",
        observation_id=observation_id or uuid4(),
        camera_id=camera_id,
        stream_epoch=stream_epoch,
        source_time=source_time,
        timestamp_quality="camera_rtcp",
        monotonic_seq=seq,
        module=module,
        class_name=class_name,
        confidence=confidence,
        bbox=bbox,
        track_id=track_id,
        model_artifact_id=model_artifact_id or f"{module}-v1",
        sample_kind=sample_kind,
        runtime_state=runtime_state,
        received_at=source_time + timedelta(milliseconds=100),
    )


def _module_rule(
    *,
    gate_mode: str = "operator",
    votes_required: int = 2,
    sample_count: int = 3,
    window_seconds: float = 2.0,
    merge_window_seconds: float = 0.0,
    cooldown_seconds: float = 0.0,
) -> ModuleRule:
    return ModuleRule(
        rule_id="weapon-handgun",
        event_module="weapon",
        source_module="weapon",
        class_names=("handgun",),
        gate_mode=gate_mode,
        reason="handgun candidate",
        min_confidence=0.7,
        debounce=DebounceSpec(
            votes_required=votes_required,
            sample_count=sample_count,
            window_seconds=window_seconds,
        ),
        merge_window_seconds=merge_window_seconds,
        cooldown_seconds=cooldown_seconds,
    )


def test_timestamp_debounce_tolerates_missing_frames_and_tracks_peak_confidence() -> None:
    engine = EventEngine(module_rules=(_module_rule(),))

    first = engine.ingest(_observation(seq=1, seconds=0.0, confidence=0.81))
    second = engine.ingest(_observation(seq=50, seconds=1.5, confidence=0.94))

    assert first.accepted is True
    assert first.triggers == ()
    assert len(second.triggers) == 1
    event = second.triggers[0].event
    assert event.opened_at == NOW
    assert event.last_seen_at == NOW + timedelta(seconds=1.5)
    assert event.peak_confidence == 0.94
    assert event.review_status == "candidate"
    assert event.gate_mode == "operator"


def test_n_of_m_counts_eligible_negative_samples_in_the_observation_window() -> None:
    engine = EventEngine(
        module_rules=(
            _module_rule(
                votes_required=2,
                sample_count=3,
                window_seconds=10,
            ),
        )
    )

    assert engine.ingest(_observation(seq=1, seconds=0, confidence=0.9)).triggers == ()
    assert engine.ingest(_observation(seq=2, seconds=1, confidence=0.2)).triggers == ()
    assert engine.ingest(_observation(seq=3, seconds=2, confidence=0.2)).triggers == ()
    result = engine.ingest(_observation(seq=4, seconds=3, confidence=0.95))

    assert result.triggers == ()


def test_duplicate_identity_cached_display_and_non_online_samples_never_vote() -> None:
    engine = EventEngine(module_rules=(_module_rule(votes_required=1, sample_count=1),))
    original = _observation(seq=1, seconds=0)

    accepted = engine.ingest(original)
    duplicate_id = engine.ingest(original.model_copy(update={"monotonic_seq": 2}))
    duplicate_dedupe = engine.ingest(original.model_copy(update={"observation_id": uuid4()}))
    cached = engine.ingest(_observation(seq=3, seconds=1, sample_kind="cached_display"))
    offline = engine.ingest(_observation(seq=4, seconds=2, runtime_state="reconnecting"))

    assert len(accepted.triggers) == 1
    assert duplicate_id.rejection_reason == "duplicate_observation_id"
    assert duplicate_dedupe.rejection_reason == "duplicate_dedupe_key"
    assert cached.rejection_reason == "cached_display_sample"
    assert offline.rejection_reason == "runtime_not_online"
    assert engine.status.accepted_observations == 1
    assert engine.status.rejected_observations == 4


def test_regressive_sequence_or_source_time_is_rejected_without_poisoning_new_state() -> None:
    engine = EventEngine(module_rules=(_module_rule(),))

    assert engine.ingest(_observation(seq=10, seconds=10)).triggers == ()
    regressive_seq = engine.ingest(_observation(seq=9, seconds=11))
    regressive_time = engine.ingest(_observation(seq=11, seconds=9))
    completed = engine.ingest(_observation(seq=11, seconds=12))

    assert regressive_seq.rejection_reason == "non_increasing_sequence"
    assert regressive_time.rejection_reason == "regressive_source_time"
    assert len(completed.triggers) == 1


def test_equal_camera_sequence_is_allowed_for_a_different_module_sample() -> None:
    engine = EventEngine(module_rules=(_module_rule(),))

    weapon = engine.ingest(_observation(seq=1, seconds=0, module="weapon"))
    fire = engine.ingest(_observation(seq=1, seconds=0, module="fire"))

    assert weapon.accepted is True
    assert fire.accepted is True


def test_stream_epoch_change_resets_votes_and_rejects_a_delayed_old_epoch() -> None:
    engine = EventEngine(module_rules=(_module_rule(),))

    assert engine.ingest(_observation(seq=1, seconds=0, stream_epoch=EPOCH_A)).triggers == ()
    assert engine.ingest(_observation(seq=1, seconds=1, stream_epoch=EPOCH_B)).triggers == ()
    completed = engine.ingest(_observation(seq=2, seconds=2, stream_epoch=EPOCH_B))
    delayed = engine.ingest(_observation(seq=2, seconds=0.5, stream_epoch=EPOCH_A))

    assert len(completed.triggers) == 1
    assert completed.triggers[0].stream_epoch == EPOCH_B
    assert delayed.rejection_reason == "stale_stream_epoch"


def test_unknown_epoch_with_regressive_source_time_cannot_replace_active_epoch() -> None:
    engine = EventEngine(module_rules=(_module_rule(),))
    unknown_epoch = UUID("40000000-0000-0000-0000-000000000004")

    engine.ingest(_observation(seq=1, seconds=10, stream_epoch=EPOCH_A))
    delayed = engine.ingest(_observation(seq=1, seconds=9, stream_epoch=unknown_epoch))
    completed = engine.ingest(_observation(seq=2, seconds=11, stream_epoch=EPOCH_A))

    assert delayed.rejection_reason == "stale_stream_epoch"
    assert len(completed.triggers) == 1


def test_seen_vote_and_track_state_are_bounded() -> None:
    engine = EventEngine(
        module_rules=(_module_rule(votes_required=2, sample_count=2),),
        limits=EngineLimits(
            max_seen_observations=3,
            seen_retention_seconds=60,
            max_vote_groups=2,
            max_tracks_per_camera=2,
        ),
    )

    for seq in range(8):
        engine.ingest(
            _observation(
                seq=seq,
                seconds=seq,
                track_id=f"track-{seq}",
                confidence=0.1,
            )
        )

    assert engine.status.seen_observation_ids <= 3
    assert engine.status.seen_dedupe_keys <= 3
    assert engine.status.vote_groups <= 2
    assert engine.status.tracks <= 2


def test_ordering_stream_registry_refuses_churn_at_a_visible_finite_bound() -> None:
    engine = EventEngine(
        module_rules=(_module_rule(votes_required=2, sample_count=2),),
        limits=EngineLimits(max_ordering_streams=2),
    )

    accepted = [
        engine.ingest(
            _observation(
                seq=1,
                seconds=index,
                confidence=0.1,
                model_artifact_id=f"weapon-v{index}",
            )
        )
        for index in range(3)
    ]

    assert [result.accepted for result in accepted] == [True, True, False]
    assert accepted[-1].rejection_reason == "ordering_stream_capacity_reached"
    assert engine.status.ordering_streams == 2


def test_disabled_gate_emits_nothing_while_shadow_stays_a_review_candidate() -> None:
    disabled = EventEngine(
        module_rules=(
            _module_rule(
                gate_mode="disabled",
                votes_required=1,
                sample_count=1,
            ),
        )
    )
    shadow = EventEngine(
        module_rules=(
            _module_rule(
                gate_mode="shadow",
                votes_required=1,
                sample_count=1,
            ),
        )
    )

    assert disabled.ingest(_observation(seq=1, seconds=0)).triggers == ()
    shadow_event = shadow.ingest(_observation(seq=1, seconds=0)).triggers[0].event

    assert shadow_event.gate_mode == "shadow"
    assert shadow_event.review_status == "candidate"
    assert shadow_event.transition_history == ("observation", "candidate")


def test_merge_window_stabilises_event_payload_and_cooldown_suppresses_reopening() -> None:
    engine = EventEngine(
        module_rules=(
            _module_rule(
                votes_required=1,
                sample_count=1,
                merge_window_seconds=2,
                cooldown_seconds=5,
            ),
        )
    )

    assert engine.ingest(_observation(seq=1, seconds=0, confidence=0.75)).triggers == ()
    assert engine.ingest(_observation(seq=2, seconds=1, confidence=0.96)).triggers == ()
    merged = engine.advance(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=3.1),
    )
    suppressed = engine.ingest(_observation(seq=3, seconds=4, confidence=0.99))
    reopened = engine.ingest(_observation(seq=4, seconds=7, confidence=0.88))
    final = engine.advance(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=9.1),
    )

    assert len(merged) == 1
    assert merged[0].event.opened_at == NOW
    assert merged[0].event.last_seen_at == NOW + timedelta(seconds=1)
    assert merged[0].event.peak_confidence == 0.96
    assert suppressed.triggers == ()
    assert reopened.triggers == ()
    assert len(final) == 1
    assert final[0].event.opened_at == NOW + timedelta(seconds=7)


def test_event_identity_is_deterministic_for_replayed_observations() -> None:
    rule = _module_rule(votes_required=1, sample_count=1)
    observation = _observation(
        seq=1,
        seconds=0,
        observation_id=UUID("30000000-0000-0000-0000-000000000003"),
    )

    first = EventEngine(module_rules=(rule,)).ingest(observation).triggers[0]
    second = EventEngine(module_rules=(rule,)).ingest(observation).triggers[0]

    assert first.event.event_id == second.event.event_id
    assert first.event.dedupe_key == second.event.dedupe_key


def test_simultaneous_tracks_rules_and_epochs_have_distinct_persistence_identity() -> None:
    first_rule = _module_rule(votes_required=1, sample_count=1)
    second_rule = replace(first_rule, rule_id="weapon-handgun-secondary")
    engine = EventEngine(module_rules=(first_rule, second_rule))

    first = engine.ingest(_observation(seq=1, seconds=0, track_id="track-a"))
    second = engine.ingest(_observation(seq=2, seconds=0, track_id="track-b"))
    epoch = engine.ingest(
        _observation(
            seq=1,
            seconds=1,
            track_id="track-a",
            stream_epoch=EPOCH_B,
        )
    )
    events = tuple(
        trigger.event for result in (first, second, epoch) for trigger in result.triggers
    )

    assert len(events) == 6
    assert len({event.event_id for event in events}) == 6
    assert len({event.dedupe_key for event in events}) == 6


def test_event_engine_serializes_duplicate_observation_transitions() -> None:
    engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),),
    )
    observation = _observation(seq=1, seconds=0)
    barrier = Barrier(2)

    def ingest() -> object:
        barrier.wait(timeout=5)
        return engine.ingest(observation)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(ingest), pool.submit(ingest))]

    assert sum(result.accepted for result in results) == 1
    assert sum(len(result.triggers) for result in results) == 1


def test_event_engine_accepts_concurrent_cameras_without_cross_camera_leakage() -> None:
    engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),),
    )
    barrier = Barrier(2)

    def ingest(camera_id: str) -> object:
        barrier.wait(timeout=5)
        return engine.ingest(_observation(seq=1, seconds=0, camera_id=camera_id))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result()
            for future in (
                pool.submit(ingest, "cam-01"),
                pool.submit(ingest, "cam-02"),
            )
        ]

    triggers = tuple(trigger for result in results for trigger in result.triggers)
    assert len(triggers) == 2
    assert {trigger.event.camera_id for trigger in triggers} == {"cam-01", "cam-02"}
    assert len({trigger.event.event_id for trigger in triggers}) == 2


def test_periodic_advance_and_flush_finalize_pending_event_exactly_once() -> None:
    engine = EventEngine(
        module_rules=(
            _module_rule(
                votes_required=1,
                sample_count=1,
                merge_window_seconds=1,
            ),
        )
    )
    assert engine.ingest(_observation(seq=1, seconds=0)).triggers == ()
    barrier = Barrier(2)

    def advance() -> tuple[object, ...]:
        barrier.wait(timeout=5)
        return engine.advance(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=2),
        )

    def flush() -> tuple[object, ...]:
        barrier.wait(timeout=5)
        return engine.flush()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(advance), pool.submit(flush))]

    triggers = tuple(trigger for result in results for trigger in result)
    assert len(triggers) == 1


class _Ring:
    def __init__(
        self,
        *,
        ready: bool = True,
        order: list[str] | None = None,
    ) -> None:
        self.ready = ready
        self.order = order
        self.calls: list[dict[str, object]] = []
        self.released: list[str] = []

    def reserve(self, **kwargs: object) -> SimpleNamespace:
        if self.order is not None:
            self.order.append("reserve")
        self.calls.append(kwargs)
        event_at = kwargs["event_at"]
        assert isinstance(event_at, datetime)
        return SimpleNamespace(
            reservation_id=kwargs["reservation_id"],
            camera_id=kwargs["camera_id"],
            target_start_at=event_at - timedelta(seconds=2),
            target_end_at=event_at + timedelta(seconds=2),
            fragments=(SimpleNamespace(codec="h264"),),
            status="ready" if self.ready else "pending",
        )

    def release(self, reservation_id: str) -> None:
        self.released.append(reservation_id)


class _UnavailableRing(_Ring):
    def reserve(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append(kwargs)
        raise ValueError("pre-roll unavailable")


class _Coordinator:
    def __init__(self, *, order: list[str] | None = None) -> None:
        self.order = order
        self.ring: _Ring | EncodedFragmentRing | None = None
        self.preview_calls: list[tuple[object, object]] = []
        self.complete_calls: list[tuple[object, object]] = []
        self.cancel_calls: list[tuple[str, object]] = []

    def create_preview(self, reservation: object, *, evidence: object) -> SimpleNamespace:
        if self.order is not None:
            self.order.append("preview")
        self.preview_calls.append((reservation, evidence))
        return SimpleNamespace(path="preview.mp4")

    def complete(self, reservation: object, evidence: object) -> object:
        if self.order is not None:
            self.order.append("complete")
        self.complete_calls.append((reservation, evidence))
        assert isinstance(evidence, EvidenceIntent)
        return evidence.materialize(sha256="a" * 64, status="ready")

    def cancel(self, reservation_id: str, *, evidence: object) -> None:
        self.cancel_calls.append((reservation_id, evidence))
        if self.ring is not None:
            self.ring.release(reservation_id)


class _WorkspaceAssembler:
    def assemble_preview(self, reservation: object, output: object) -> SimpleNamespace:
        output.write_bytes(b"preview-bytes")
        return SimpleNamespace(path=output)

    def assemble(self, reservation: object, output: object) -> SimpleNamespace:
        payload = b"final-evidence-bytes"
        output.write_bytes(payload)
        return SimpleNamespace(
            path=output,
            sha256=hashlib.sha256(payload).hexdigest(),
            codec="h264",
            start_at=reservation.target_start_at,
            end_at=reservation.target_end_at,
        )


class _WorkspacePublisher:
    def publish(self, _source: object, evidence: EvidenceInput) -> EvidenceInput:
        return replace(evidence, status="ready")

    def mark_intent_failed(self, _evidence: EvidenceIntent) -> None:
        return None

    def mark_failed(self, _evidence: EvidenceInput) -> None:
        return None


def _workspace_coordinator(
    tmp_path: Path,
    *,
    ring: _Ring,
    assembler: object,
) -> tuple[EvidenceCoordinator, PreviewWorkspace]:
    workspace = PreviewWorkspace(
        tmp_path,
        ttl=timedelta(minutes=5),
        max_items=4,
        max_bytes=10_000,
        max_file_bytes=1_000,
        clock=lambda: NOW,
    )
    return (
        EvidenceCoordinator(
            ring=ring,
            assembler=assembler,
            publisher=_WorkspacePublisher(),  # type: ignore[arg-type]
            preview_workspace=workspace,
        ),
        workspace,
    )


def _real_repository(path: Path) -> PilotRepository:
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name="Pilot School")
    repository.add_camera(
        camera_id="cam-01",
        site_id="site-1",
        name="Entrance",
        source_reference="nvr://cam-01",
        codec="h264",
    )
    repository.add_model_artifact(
        ModelArtifactV1(
            schema_version="model-artifact.v1",
            artifact_id="weapon-v1",
            sha256="b" * 64,
            source="registry://weapon-v1",
            commercial_rights=CommercialRightsRecordV1(
                schema_version="commercial-rights.v1",
                record_id="rights-weapon-v1",
                terms_reference="legal://rights/weapon-v1",
                commercial_use_approved=True,
            ),
            class_list=("handgun",),
            preprocessing="letterbox 640x640",
            analytic="weapon",
        )
    )
    return repository


def _real_evidence_coordinator(
    tmp_path: Path,
    *,
    repository: PilotRepository,
    journal: SQLiteWALJournal,
    ring: _Ring,
    workspace_root: Path,
) -> tuple[EvidenceCoordinator, PreviewWorkspace]:
    object_root = tmp_path / "encrypted-evidence"
    object_root.mkdir(mode=0o700, exist_ok=True)
    object_root.chmod(0o700)
    store = EncryptedLocalObjectStore(
        object_root,
        encrypted_volume_attestation=EncryptedVolumeAttestation(
            volume_id="pilot-test-volume",
            mount_path=object_root,
            record_id="test-attestation",
            verified_at=NOW,
            verifier="test",
            signature_sha256="c" * 64,
            encryption="luks2",
        ),
        attestation_verifier=lambda record: record.signature_sha256 == "c" * 64,
        attestation_max_age=timedelta(days=1),
        evidence_prefix="pilot-evidence",
        max_object_bytes=10_000,
        clock=lambda: NOW,
    )
    workspace = PreviewWorkspace(
        workspace_root,
        ttl=timedelta(minutes=5),
        max_items=4,
        max_bytes=10_000,
        max_file_bytes=1_000,
        clock=lambda: NOW,
    )
    return (
        EvidenceCoordinator(
            ring=ring,
            assembler=_WorkspaceAssembler(),
            publisher=EvidencePublisher(
                store=store,
                repository=repository,
                journal=journal,
            ),
            preview_workspace=workspace,
        ),
        workspace,
    )


def _service(
    tmp_path: Path,
    *,
    journal: SQLiteWALJournal,
    processor: object,
    load_candidate: object,
    mark_evidence_pending: object | None = None,
    mark_evidence_failed: object | None = None,
    ring: _Ring | None = None,
    coordinator: _Coordinator | None = None,
    batch_size: int = 10,
    engine: EventEngine | None = None,
    pending_recovery_backoff_seconds: float = 1.0,
    monotonic_clock: object | None = None,
    source_references: dict[str, str] | None = None,
) -> tuple[SiteEventService, _Ring, _Coordinator, EvidenceJournalReplayWorker]:
    replay = EvidenceJournalReplayWorker(
        journal=journal,
        processor=processor,
        batch_size=batch_size,
        retry_backoff_seconds=1,
    )
    selected_ring = ring or _Ring()
    selected_coordinator = coordinator or _Coordinator()
    selected_coordinator.ring = selected_ring
    service = SiteEventService(
        engine=engine
        or EventEngine(module_rules=(_module_rule(votes_required=1, sample_count=1),)),
        journal=journal,
        replay_worker=replay,
        ring=selected_ring,
        evidence_coordinator=selected_coordinator,
        load_candidate=load_candidate,
        mark_evidence_pending=mark_evidence_pending
        or (
            lambda event_id: load_candidate(event_id).model_copy(
                update={"evidence_status": "pending"}
            )
        ),
        mark_evidence_failed=mark_evidence_failed
        or (
            lambda event_id: load_candidate(event_id).model_copy(
                update={"evidence_status": "failed"}
            )
        ),
        evidence_policy=EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references=source_references
            if source_references is not None
            else {"cam-01": "nvr://cam-01"},
        ),
        pending_recovery_backoff_seconds=pending_recovery_backoff_seconds,
        monotonic_clock=monotonic_clock,  # type: ignore[arg-type]
    )
    return service, selected_ring, selected_coordinator, replay


def test_service_journals_candidate_then_associates_pending_evidence_before_completion(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "events.sqlite3", max_items=10)
    replayed: list[object] = []
    order: list[str] = []

    def persist(item: object) -> None:
        order.append("persist")
        replayed.append(item)

    ring = _Ring(order=order)
    coordinator = _Coordinator(order=order)
    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=lambda event_id: next(
            CandidateEventV1.model_validate(item.payload)
            for item in replayed
            if item.kind == "candidate_event" and item.payload["event_id"] == str(event_id)
        ),
        mark_evidence_pending=lambda event_id: (
            order.append("mark-pending"),
            CandidateEventV1.model_validate(replayed[0].payload).model_copy(
                update={"evidence_status": "pending"}
            ),
        )[1],
        ring=ring,
        coordinator=coordinator,
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert [item.kind for item in replayed] == ["candidate_event"]
    assert journal.depth() == 0
    assert ring.calls[0]["stream_epoch"] == str(EPOCH_A)
    assert len(result.durable_candidates) == 1
    pending = result.durable_candidates[0].pending_evidence
    assert pending is not None
    assert pending.status == "pending"
    assert not hasattr(pending, "sha256")
    assert coordinator.preview_calls[0][1] == pending
    assert coordinator.complete_calls[0][1] == pending
    assert result.durable_candidates[0].evidence.status == "ready"
    assert result.durable_candidates[0].trigger.event.evidence_status == "ready"
    assert result.status.degraded is False
    assert order == ["persist", "reserve", "preview", "mark-pending", "complete"]


def test_pending_transition_failure_stops_completion_and_reconciles_preview_ownership(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "pending-transition.sqlite3", max_items=10)
    replayed: list[object] = []

    def transition_failed(_event_id: UUID) -> None:
        raise sqlite3.OperationalError("database is locked")

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        load_candidate=lambda _event_id: CandidateEventV1.model_validate(
            replayed[0].payload
        ),
        mark_evidence_pending=transition_failed,
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert result.durable_candidates == ()
    assert "evidence_processing_failed" in result.status.reasons
    assert "evidence_pending_transition_unverified" in result.status.reasons
    assert len(coordinator.preview_calls) == 1
    assert coordinator.complete_calls == []
    assert coordinator.cancel_calls
    assert len(ring.released) == 1


def test_evidence_journal_overflow_is_visible_and_never_acquires_a_pin(tmp_path: Path) -> None:
    journal = SQLiteWALJournal(tmp_path / "full.sqlite3", max_items=1)
    existing = (
        EventEngine(module_rules=(_module_rule(votes_required=1, sample_count=1),))
        .ingest(_observation(seq=99, seconds=-10))
        .triggers[0]
        .event
    )
    journal.enqueue_event(existing)
    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: None,
        load_candidate=lambda event_id: (_ for _ in ()).throw(KeyError(event_id)),
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert result.status.degraded is True
    assert "candidate_journal_full" in result.status.reasons
    assert journal.depth() == 1
    assert result.durable_candidates == ()
    assert ring.calls == []
    assert ring.released == []
    assert coordinator.preview_calls == []


def test_reservation_failure_returns_exact_failed_candidate_receipt(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "unavailable.sqlite3", max_items=10)
    replayed: list[object] = []
    ring = _UnavailableRing()
    service, _, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        load_candidate=lambda event_id: CandidateEventV1.model_validate(replayed[0].payload),
        ring=ring,
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert [item.kind for item in replayed] == ["candidate_event"]
    assert replayed[0].payload["evidence_status"] == "unavailable"
    assert result.durable_candidates[0].trigger.event.evidence_status == "failed"
    assert result.durable_candidates[0].pending_evidence is None
    assert ring.released == [
        f"event-{result.durable_candidates[0].trigger.event.event_id}"
    ]
    assert coordinator.preview_calls == []
    assert "evidence_reservation_unavailable" in result.status.reasons


def test_missing_evidence_source_is_visible_and_releases_reserved_fragments(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "missing-source.sqlite3", max_items=10)
    replayed: list[object] = []
    ring = _Ring()
    coordinator = _Coordinator()
    replay = EvidenceJournalReplayWorker(
        journal=journal,
        processor=lambda item: replayed.append(item),
        batch_size=10,
        retry_backoff_seconds=1,
    )
    service = SiteEventService(
        engine=EventEngine(module_rules=(_module_rule(votes_required=1, sample_count=1),)),
        journal=journal,
        replay_worker=replay,
        ring=ring,
        evidence_coordinator=coordinator,
        load_candidate=lambda _event_id: CandidateEventV1.model_validate(replayed[0].payload),
        mark_evidence_pending=lambda _event_id: None,
        mark_evidence_failed=lambda _event_id: None,
        evidence_policy=EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references={"different-camera": "nvr://different-camera"},
        ),
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert result.durable_candidates == ()
    assert "evidence_processing_failed" in result.status.reasons
    assert ring.released == [f"event-{replayed[0].payload['event_id']}"]
    assert coordinator.preview_calls == []


class _BrokenJournal:
    def enqueue_event(self, event: object) -> None:
        raise OSError("disk is read-only")

    def depth(self) -> int:
        return 0


class _ReplayStatus:
    depth = 0
    quarantine_depth = 0
    degraded = False
    last_error = None
    processed_total = 0
    retry_attempts_total = 0
    next_retry_in_seconds = None


class _Replay:
    def __init__(self) -> None:
        self.status = _ReplayStatus()
        self.startup_calls = 0
        self.periodic_calls = 0

    def startup_drain(self) -> int:
        self.startup_calls += 1
        return 0

    def run_periodic_batch(self) -> int:
        self.periodic_calls += 1
        return 0


def test_candidate_journal_write_failure_returns_visible_degraded_without_accepting(
    tmp_path: Path,
) -> None:
    replay = _Replay()
    service = SiteEventService(
        engine=EventEngine(module_rules=(_module_rule(votes_required=1, sample_count=1),)),
        journal=_BrokenJournal(),
        replay_worker=replay,
        ring=_Ring(),
        evidence_coordinator=_Coordinator(),
        load_candidate=lambda event_id: (_ for _ in ()).throw(KeyError(event_id)),
        mark_evidence_pending=lambda _event_id: None,
        mark_evidence_failed=lambda _event_id: None,
        evidence_policy=EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references={"cam-01": "nvr://cam-01"},
        ),
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert result.durable_candidates == ()
    assert result.status.degraded is True
    assert "candidate_journal_write_failed" in result.status.reasons
    assert replay.periodic_calls == 0


def test_service_invokes_bounded_startup_and_periodic_replay_apis(tmp_path: Path) -> None:
    replay = _Replay()
    service = SiteEventService(
        engine=EventEngine(module_rules=()),
        journal=_BrokenJournal(),
        replay_worker=replay,
        ring=_Ring(),
        evidence_coordinator=_Coordinator(),
        load_candidate=lambda event_id: (_ for _ in ()).throw(KeyError(event_id)),
        mark_evidence_pending=lambda _event_id: None,
        mark_evidence_failed=lambda _event_id: None,
        evidence_policy=EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references={"cam-01": "nvr://cam-01"},
        ),
    )

    service.start()
    service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW,
    )

    assert replay.startup_calls == 1
    assert replay.periodic_calls == 1


def test_retryable_replay_failure_keeps_wal_and_surfaces_degraded(tmp_path: Path) -> None:
    journal = SQLiteWALJournal(tmp_path / "retry.sqlite3", max_items=10)

    def unavailable(item: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    service, _, _, replay = _service(
        tmp_path,
        journal=journal,
        processor=unavailable,
        load_candidate=lambda event_id: (_ for _ in ()).throw(KeyError(event_id)),
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert journal.depth() == 1
    assert replay.status.degraded is True
    assert result.status.degraded is True
    assert "journal_replay_degraded" in result.status.reasons


def test_candidate_persistence_check_failure_is_visible_and_releases_pin(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "check-failure.sqlite3", max_items=10)

    def check_failed(_event_id: UUID) -> bool:
        raise OSError("database unavailable")

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda _item: None,
        load_candidate=check_failed,
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert result.durable_candidates == ()
    assert "candidate_persistence_check_failed" in result.status.reasons
    assert "candidate_persistence_pending" in result.status.reasons
    assert ring.calls == []
    assert ring.released == []
    assert coordinator.preview_calls == []


def test_service_requires_exact_persisted_candidate_before_reserving(tmp_path: Path) -> None:
    journal = SQLiteWALJournal(tmp_path / "mismatch.sqlite3", max_items=10)
    replayed: list[object] = []

    def wrong_candidate(_event_id: UUID) -> CandidateEventV1:
        event = CandidateEventV1.model_validate(replayed[0].payload)
        return event.model_copy(update={"reason": "different payload"})

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        load_candidate=wrong_candidate,
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert ring.calls == []
    assert coordinator.preview_calls == []
    assert result.durable_candidates == ()
    assert "candidate_persistence_identity_mismatch" in result.status.reasons


def test_service_claims_same_trigger_once_without_holding_engine_lock_during_io(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "concurrent.sqlite3", max_items=10)
    persisted: dict[UUID, CandidateEventV1] = {}
    persist_lock = Lock()

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        with persist_lock:
            persisted[event.event_id] = event

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
    )
    trigger = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    ).ingest(_observation(seq=1, seconds=0)).triggers[0]
    barrier = Barrier(2)

    def process_trigger() -> object:
        barrier.wait(timeout=5)
        return service._process_triggers((trigger,))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result()
            for future in (pool.submit(process_trigger), pool.submit(process_trigger))
        ]

    assert sum(len(result) for result in results) == 1
    assert len(ring.calls) == 1
    assert len(coordinator.preview_calls) == 1


def test_completed_duplicate_does_not_reenqueue_a_stale_candidate(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "completed-duplicate.sqlite3", max_items=2)
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    trigger = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    ).ingest(_observation(seq=1, seconds=0)).triggers[0]
    service, _, _, replay = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
    )

    assert len(service._process_triggers((trigger,))) == 1
    assert journal.depth() == 0
    assert service._process_triggers((trigger,)) == ()
    assert journal.depth() == 0
    assert replay.status.quarantine_depth == 0


def test_journal_depth_read_failure_is_visible_degraded() -> None:
    class BrokenDepthJournal(_BrokenJournal):
        def depth(self) -> int:
            raise OSError("unreadable")

    service = SiteEventService(
        engine=EventEngine(),
        journal=BrokenDepthJournal(),
        replay_worker=_Replay(),
        ring=_Ring(),
        evidence_coordinator=_Coordinator(),
        load_candidate=lambda event_id: (_ for _ in ()).throw(KeyError(event_id)),
        mark_evidence_pending=lambda _event_id: None,
        mark_evidence_failed=lambda _event_id: None,
        evidence_policy=EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references={"cam-01": "nvr://cam-01"},
        ),
    )

    assert service.status.degraded is True
    assert "journal_depth_failed" in service.status.reasons


@pytest.mark.parametrize(
    "source",
    (
        "nvr://cam-01?token=secret",
        "nvr://cam-01#token=secret",
        "rtsp://user:pass@cam-01/live",
        "rtsp://cam-01/live",
    ),
)
def test_evidence_policy_rejects_secret_bearing_source_references(source: str) -> None:
    with pytest.raises(ValueError, match="credential"):
        EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references={"cam-01": source},
        )


def _append_fragment(
    ring: EncodedFragmentRing,
    *,
    start_seconds: int,
    epoch: UUID = EPOCH_A,
) -> None:
    ring.append(
        camera_id="cam-01",
        payload=f"fragment-{start_seconds}".encode(),
        start_at=NOW + timedelta(seconds=start_seconds),
        end_at=NOW + timedelta(seconds=start_seconds + 1),
        codec="h264",
        starts_with_keyframe=start_seconds == -2,
        stream_epoch=str(epoch),
    )


def test_pending_post_roll_is_reacquired_and_completed_once_with_real_ring(
    tmp_path: Path,
) -> None:
    ring = EncodedFragmentRing(
        tmp_path / "real-ring",
        ring_seconds=15,
        max_camera_bytes=10_000,
        max_spool_bytes=10_000,
    )
    _append_fragment(ring, start_seconds=-2)
    _append_fragment(ring, start_seconds=-1)
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def transition(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    coordinator = _Coordinator()
    service, _, _, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / "post-roll.sqlite3", max_items=10),
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: transition(event_id, "pending"),
        mark_evidence_failed=lambda event_id: transition(event_id, "failed"),
        ring=ring,  # type: ignore[arg-type]
        coordinator=coordinator,
    )

    initial = service.process(_observation(seq=1, seconds=0))
    assert initial.durable_candidates[0].evidence is None
    assert initial.status.pending_evidence_work == 1
    _append_fragment(ring, start_seconds=0)
    _append_fragment(ring, start_seconds=1)

    completed = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )
    duplicate = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert len(coordinator.complete_calls) == 1
    assert completed.durable_candidates[0].evidence is not None
    assert duplicate.durable_candidates == ()
    assert completed.status.pending_evidence_work == 0


def test_pending_post_roll_epoch_change_terminalizes_and_releases(
    tmp_path: Path,
) -> None:
    replayed: list[object] = []
    failed: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        event = CandidateEventV1.model_validate(replayed[0].payload)
        return failed.get(event_id, event)

    def mark_pending(event_id: UUID) -> CandidateEventV1:
        return load(event_id).model_copy(update={"evidence_status": "pending"})

    def mark_failed(event_id: UUID) -> CandidateEventV1:
        failed[event_id] = load(event_id).model_copy(update={"evidence_status": "failed"})
        return failed[event_id]

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / "epoch-terminal.sqlite3", max_items=10),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=mark_pending,
        mark_evidence_failed=mark_failed,
        ring=_Ring(ready=False),
    )
    initial = service.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id

    service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_B,
        source_time=NOW + timedelta(seconds=3),
    )

    assert coordinator.cancel_calls
    assert ring.released == [f"event-{event_id}"]
    assert service.status.pending_evidence_work == 0
    assert failed[event_id].evidence_status == "failed"
    assert "evidence_pending_epoch_changed" in service.status.reasons


def test_pending_post_roll_expires_to_failed_and_cleans_up(tmp_path: Path) -> None:
    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(update={"evidence_status": status})
        return states[event_id]

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / "expiry.sqlite3", max_items=10),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )
    initial = service.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id

    service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=30),
    )

    assert coordinator.cancel_calls
    assert ring.released == [f"event-{event_id}"]
    assert service.status.pending_evidence_work == 0
    assert states[event_id].evidence_status == "failed"
    assert "evidence_pending_expired" in service.status.reasons


def test_pending_post_roll_waits_through_bounded_late_fragment_grace(
    tmp_path: Path,
) -> None:
    replayed: list[object] = []
    service, _ring, coordinator, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / "late-grace.sqlite3", max_items=10),
        processor=lambda item: replayed.append(item),
        load_candidate=lambda _event_id: CandidateEventV1.model_validate(
            replayed[0].payload
        ),
        ring=_Ring(ready=False),
    )
    service.process(_observation(seq=1, seconds=0))

    service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert service.status.pending_evidence_work == 1
    assert coordinator.cancel_calls == []


def test_duplicate_periodic_workers_complete_one_pending_reservation_once(
    tmp_path: Path,
) -> None:
    entered = Barrier(2)
    release = Barrier(2)

    class RefreshingRing(_Ring):
        def reserve(self, **kwargs: object) -> SimpleNamespace:
            reservation = super().reserve(**kwargs)
            if len(self.calls) == 1:
                reservation.status = "pending"
                return reservation
            entered.wait(timeout=5)
            release.wait(timeout=5)
            reservation.status = "ready"
            return reservation

    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(update={"evidence_status": status})
        return states[event_id]

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / "periodic-race.sqlite3", max_items=10),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=RefreshingRing(),
    )
    service.process(_observation(seq=1, seconds=0))

    def periodic() -> object:
        return service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(periodic), pool.submit(periodic))
        entered.wait(timeout=5)
        release.wait(timeout=5)
        results = [future.result() for future in futures]

    assert len(ring.calls) == 2
    assert len(coordinator.complete_calls) == 1
    assert sum(len(result.durable_candidates) for result in results) == 1
    assert service.status.pending_evidence_work == 0


def test_pending_evidence_work_capacity_is_bounded_and_visible(tmp_path: Path) -> None:
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    journal = SQLiteWALJournal(tmp_path / "pending-capacity.sqlite3", max_items=10)
    replay = EvidenceJournalReplayWorker(
        journal=journal,
        processor=persist,
        batch_size=10,
        retry_backoff_seconds=1,
    )
    ring = _Ring(ready=False)
    coordinator = _Coordinator()
    coordinator.ring = ring
    service = SiteEventService(
        engine=EventEngine(
            module_rules=(_module_rule(votes_required=1, sample_count=1),),
            limits=EngineLimits(max_pending_events=1),
        ),
        journal=journal,
        replay_worker=replay,
        ring=ring,
        evidence_coordinator=coordinator,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        evidence_policy=EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references={"cam-01": "nvr://cam-01"},
        ),
    )

    first = service.process(_observation(seq=1, seconds=0, track_id="track-a"))
    second = service.process(_observation(seq=2, seconds=1, track_id="track-b"))

    assert len(first.durable_candidates) == 1
    assert second.durable_candidates == ()
    assert service.status.pending_evidence_work == 1
    assert "pending_evidence_capacity_reached" in service.status.reasons
    assert len(persisted) == 2
    assert len(ring.calls) == 2
    assert len(ring.released) == 1


@pytest.mark.parametrize("failure", ("none", "wrong_event", "wrong_status", "raised"))
def test_pending_transition_requires_exact_durable_receipt_and_cancels(
    tmp_path: Path,
    failure: str,
) -> None:
    replayed: list[object] = []

    def transition(event_id: UUID) -> CandidateEventV1 | None:
        event = CandidateEventV1.model_validate(replayed[0].payload)
        if failure == "none":
            return None
        if failure == "wrong_event":
            return event.model_copy(
                update={"event_id": uuid4(), "evidence_status": "pending"}
            )
        if failure == "wrong_status":
            return event
        raise sqlite3.OperationalError("database is locked")

    def failed(event_id: UUID) -> CandidateEventV1:
        event = CandidateEventV1.model_validate(replayed[0].payload)
        return event.model_copy(update={"evidence_status": "failed"})

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / f"bad-{failure}.sqlite3", max_items=10),
        processor=lambda item: replayed.append(item),
        load_candidate=lambda _event_id: CandidateEventV1.model_validate(
            replayed[0].payload
        ),
        mark_evidence_pending=transition,
        mark_evidence_failed=failed,
    )
    result = service.process(_observation(seq=1, seconds=0))

    assert result.durable_candidates == ()
    assert coordinator.cancel_calls
    assert len(ring.released) == 1
    assert service.status.pending_evidence_work == 0
    assert "evidence_pending_transition_unverified" in result.status.reasons


@pytest.mark.parametrize(
    "failure",
    ("none", "wrong_event", "wrong_status", "retryable", "deterministic"),
)
def test_failed_transition_requires_exact_receipt_and_retries_bounded_cleanup(
    tmp_path: Path,
    failure: str,
) -> None:
    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}
    allow_success = False

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def pending(event_id: UUID) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(update={"evidence_status": "pending"})
        return states[event_id]

    def failed(event_id: UUID) -> CandidateEventV1 | None:
        event = load(event_id)
        if allow_success:
            states[event_id] = event.model_copy(update={"evidence_status": "failed"})
            return states[event_id]
        if failure == "none":
            return None
        if failure == "wrong_event":
            return event.model_copy(
                update={"event_id": uuid4(), "evidence_status": "failed"}
            )
        if failure == "wrong_status":
            return event
        if failure == "retryable":
            raise sqlite3.OperationalError("database is locked")
        raise ValueError("deterministic transition rejection")

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / f"failed-{failure}.sqlite3", max_items=10),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=pending,
        mark_evidence_failed=failed,
        ring=_Ring(ready=False),
    )
    service.process(_observation(seq=1, seconds=0))

    first = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_B,
        source_time=NOW + timedelta(seconds=1),
    )

    assert first.status.pending_evidence_work == 1
    assert "evidence_terminal_transition_failed" in first.status.reasons
    assert len(coordinator.cancel_calls) == 1
    assert len(ring.released) == 1

    allow_success = True
    second = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_B,
        source_time=NOW + timedelta(seconds=2),
    )

    assert second.status.pending_evidence_work == 0
    assert len(coordinator.cancel_calls) == 2
    assert len(ring.released) == 2
    assert len(states) == 1
    assert next(iter(states.values())).evidence_status == "failed"


def test_unique_inflight_claims_are_bounded_and_release_after_io(
    tmp_path: Path,
) -> None:
    entered = Barrier(3)
    release = Barrier(3)

    class RecordingJournal:
        def __init__(self) -> None:
            self.events: dict[UUID, CandidateEventV1] = {}
            self.pending: dict[str, SimpleNamespace] = {}

        def enqueue_event(self, event: CandidateEventV1) -> None:
            self.events[event.event_id] = event

        def seed_pending_evidence_work(
            self,
            *,
            event_id: str,
            reservation_id: str,
            payload: dict[str, object],
        ) -> SimpleNamespace:
            record = SimpleNamespace(
                event_id=event_id,
                reservation_id=reservation_id,
                phase="seed",
                payload=payload,
            )
            self.pending[event_id] = record
            return record

        def reserve_pending_evidence_work(
            self,
            *,
            event_id: str,
            reservation_id: str,
            payload: dict[str, object],
        ) -> SimpleNamespace:
            record = SimpleNamespace(
                event_id=event_id,
                reservation_id=reservation_id,
                phase="reserved",
                payload=payload,
            )
            self.pending[event_id] = record
            return record

        def acknowledge_pending_evidence_work(
            self,
            *,
            event_id: str,
            reservation_id: str,
        ) -> bool:
            self.pending.pop(event_id, None)
            return True

        def depth(self) -> int:
            return len(self.events)

    journal = RecordingJournal()

    def blocking_load(event_id: UUID) -> CandidateEventV1:
        entered.wait(timeout=5)
        release.wait(timeout=5)
        return journal.events[event_id]

    engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),),
        limits=EngineLimits(max_pending_events=2),
    )
    service = SiteEventService(
        engine=engine,
        journal=journal,
        replay_worker=_Replay(),
        ring=_Ring(),
        evidence_coordinator=_Coordinator(),
        load_candidate=blocking_load,
        mark_evidence_pending=lambda event_id: (_ for _ in ()).throw(KeyError(event_id)),
        mark_evidence_failed=lambda event_id: (_ for _ in ()).throw(KeyError(event_id)),
        evidence_policy=EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references={"cam-01": "nvr://cam-01"},
        ),
    )
    triggers = tuple(
        EventEngine(module_rules=(_module_rule(votes_required=1, sample_count=1),))
        .ingest(_observation(seq=index + 1, seconds=index, track_id=f"track-{index}"))
        .triggers[0]
        for index in range(4)
    )

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(service._process_triggers, (trigger,)) for trigger in triggers
        ]
        entered.wait(timeout=5)
        assert service.status.processing_claims == 2
        assert "event_processing_capacity_reached" in service.status.reasons
        release.wait(timeout=5)
        for future in futures:
            future.result()

    assert journal.depth() == 4
    assert service.status.processing_claims == 0


def test_active_pending_evidence_survives_service_restart_and_completes(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "pending-restart.sqlite3"
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    first_journal = SQLiteWALJournal(journal_path, max_items=10)
    first, ring, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )
    initial = first.process(_observation(seq=1, seconds=0))
    assert initial.status.pending_evidence_work == 1
    first_journal.close()

    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    )
    restarted_engine.ingest(
        _observation(
            seq=2,
            seconds=1,
            class_name="background",
            confidence=0.1,
        )
    )
    restarted_journal = SQLiteWALJournal(journal_path, max_items=10)
    ring.ready = True
    restarted_coordinator = _Coordinator()
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=restarted_coordinator,
        engine=restarted_engine,
    )

    started = restarted.start()
    completed = restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert started.pending_evidence_work == 1
    assert len(completed.durable_candidates) == 1
    assert len(restarted_coordinator.complete_calls) == 1
    assert completed.status.pending_evidence_work == 0
    assert restarted_journal.pending_evidence_work_depth() == 0

    restarted_journal.close()
    final_journal = SQLiteWALJournal(journal_path, max_items=10)
    final, _, final_coordinator, _ = _service(
        tmp_path,
        journal=final_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        engine=restarted_engine,
    )
    assert final.start().pending_evidence_work == 0
    assert final_coordinator.complete_calls == []


@pytest.mark.parametrize(
    ("crash_boundary", "record_phase", "candidate_status", "outcome"),
    (
        ("before_preview", "reserved", "unavailable", "failed"),
        ("after_preview", "reserved", "unavailable", "failed"),
        ("after_pending_transition", "active", "pending", "recovered"),
        ("after_ready_assembly", "active", "ready", "acknowledged"),
        ("after_object_publication", "active", "ready", "acknowledged"),
        ("before_pending_work_ack", "active", "ready", "acknowledged"),
    ),
)
def test_restart_reconciles_each_pending_evidence_crash_boundary(
    tmp_path: Path,
    crash_boundary: str,
    record_phase: str,
    candidate_status: str,
    outcome: str,
) -> None:
    journal_path = tmp_path / f"crash-{crash_boundary}.sqlite3"
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    first_journal = SQLiteWALJournal(journal_path, max_items=4)
    first, _, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )
    initial = first.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    persisted[event_id] = persisted[event_id].model_copy(
        update={"evidence_status": candidate_status}
    )
    row = first_journal.pending_evidence_work_items(limit=1)[0]
    payload = row.payload
    payload["trigger"]["event"]["evidence_status"] = candidate_status
    first_journal._connection.execute(
        """
        UPDATE pending_evidence_work
        SET phase = ?, payload_json = ?
        WHERE event_id = ?
        """,
        (
            record_phase,
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            str(event_id),
        ),
    )
    first_journal._connection.commit()
    first_journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    coordinator = _Coordinator()
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda candidate_id: mark(candidate_id, "pending"),
        mark_evidence_failed=lambda candidate_id: mark(candidate_id, "failed"),
        ring=_Ring(ready=False),
        coordinator=coordinator,
    )

    status = restarted.start()

    if outcome == "failed":
        assert persisted[event_id].evidence_status == "failed"
        assert status.pending_evidence_work == 0
        assert restarted_journal.pending_evidence_work_depth() == 0
        assert len(coordinator.cancel_calls) == 1
        assert coordinator.cancel_calls[0][0] == f"event-{event_id}"
        assert isinstance(coordinator.cancel_calls[0][1], EvidenceIntent)
    elif outcome == "recovered":
        assert persisted[event_id].evidence_status == "pending"
        assert status.pending_evidence_work == 1
        assert restarted_journal.pending_evidence_work_depth() == 1
        assert coordinator.cancel_calls == []
    else:
        assert persisted[event_id].evidence_status == "ready"
        assert status.pending_evidence_work == 0
        assert restarted_journal.pending_evidence_work_depth() == 0
        assert coordinator.cancel_calls == []


@pytest.mark.parametrize("corruption", ("malformed", "conflicting"))
def test_corrupt_pending_recovery_is_quarantined_and_cannot_hold_capacity(
    tmp_path: Path,
    corruption: str,
) -> None:
    journal_path = tmp_path / f"corrupt-pending-{corruption}.sqlite3"
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    first_journal = SQLiteWALJournal(journal_path, max_items=2)
    first, _, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )
    initial = first.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    if corruption == "malformed":
        payload = {"schema_version": "corrupt"}
    else:
        payload = first_journal.pending_evidence_work_items(limit=1)[0].payload
        payload["intent"]["source_reference"] = "nvr://different-camera"
    first_journal._connection.execute(
        "UPDATE pending_evidence_work SET payload_json = ?",
        (json.dumps(payload, sort_keys=True, separators=(",", ":")),),
    )
    first_journal._connection.commit()
    first_journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=2)
    coordinator = _Coordinator()
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda candidate_id: mark(candidate_id, "pending"),
        mark_evidence_failed=lambda candidate_id: mark(candidate_id, "failed"),
        ring=_Ring(ready=False),
        coordinator=coordinator,
    )

    status = restarted.start()

    assert status.degraded is True
    assert "pending_evidence_recovery_quarantined" in status.reasons
    assert restarted_journal.pending_evidence_work_depth() == 0
    assert restarted_journal.pending_evidence_quarantine_depth() == 1
    assert coordinator.cancel_calls == [(f"event-{event_id}", None)]
    assert persisted[event_id].evidence_status == "failed"


def test_corrupt_recovery_retains_row_until_cancel_and_quarantine_are_durable(
    tmp_path: Path,
) -> None:
    class FailingCancelCoordinator(_Coordinator):
        attempts = 0

        def cancel(self, reservation_id: str, *, evidence: object) -> None:
            self.cancel_calls.append((reservation_id, evidence))
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("workspace cleanup failed")
            super().cancel(reservation_id, evidence=evidence)

    journal_path = tmp_path / "corrupt-cancel-failure.sqlite3"
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    first_journal = SQLiteWALJournal(journal_path, max_items=2)
    first, _, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )
    initial = first.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    first_journal._connection.execute(
        "UPDATE pending_evidence_work SET payload_json = '{}'"
    )
    first_journal._connection.commit()
    first_journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=2)
    ring = _Ring(ready=False)
    coordinator = FailingCancelCoordinator()
    clock = [0.0]
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda candidate_id: mark(candidate_id, "pending"),
        mark_evidence_failed=lambda candidate_id: mark(candidate_id, "failed"),
        ring=ring,
        coordinator=coordinator,
        pending_recovery_backoff_seconds=1,
        monotonic_clock=lambda: clock[0],
    )

    status = restarted.start()

    assert status.degraded is True
    assert ring.released == [f"event-{event_id}"]
    assert restarted_journal.pending_evidence_work_depth() == 1
    assert restarted_journal.pending_evidence_quarantine_depth() == 0
    assert persisted[event_id].evidence_status == "pending"
    assert status.pending_evidence_next_retry_seconds == 1
    clock[0] = 1
    restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=1),
    )

    assert coordinator.attempts == 2
    assert persisted[event_id].evidence_status == "failed"
    assert restarted_journal.pending_evidence_work_depth() == 0
    assert restarted_journal.pending_evidence_quarantine_depth() == 1


def test_recovery_terminalizes_work_beyond_the_runtime_capacity_bound(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "over-capacity-pending.sqlite3"
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    first_journal = SQLiteWALJournal(journal_path, max_items=4)
    first_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),),
        limits=EngineLimits(max_pending_events=2),
    )
    first, _, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
        engine=first_engine,
    )
    first.process(_observation(seq=1, seconds=0, track_id="track-a"))
    first.process(_observation(seq=2, seconds=1, track_id="track-b"))
    assert first_journal.pending_evidence_work_depth() == 2
    first_journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),),
        limits=EngineLimits(max_pending_events=1),
    )
    restarted_engine.ingest(
        _observation(
            seq=3,
            seconds=2,
            class_name="background",
            confidence=0.1,
        )
    )
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
        engine=restarted_engine,
    )

    status = restarted.start()

    assert status.degraded is True
    assert "pending_evidence_recovery_capacity_exceeded" in status.reasons
    assert status.pending_evidence_work == 1
    assert restarted_journal.pending_evidence_work_depth() == 1
    assert sorted(event.evidence_status for event in persisted.values()) == [
        "failed",
        "pending",
    ]


def test_initial_preview_is_not_drainable_until_pending_receipt_is_verified(
    tmp_path: Path,
) -> None:
    preview_entered = Event()
    release_preview = Event()

    class BlockingPreviewCoordinator(_Coordinator):
        def create_preview(
            self,
            reservation: object,
            *,
            evidence: object,
        ) -> SimpleNamespace:
            self.preview_calls.append((reservation, evidence))
            preview_entered.set()
            assert release_preview.wait(timeout=5)
            return SimpleNamespace(path="preview.mp4")

    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    ring = _Ring(ready=False)
    coordinator = BlockingPreviewCoordinator()
    service, _, _, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / "preview-race.sqlite3", max_items=10),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=coordinator,
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        initial_future = pool.submit(
            service.process,
            _observation(seq=1, seconds=0),
        )
        assert preview_entered.wait(timeout=5)
        pending_record = service._journal.pending_evidence_work_items(limit=1)[0]
        assert pending_record.phase == "reserved"
        ring.ready = True
        periodic = service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert periodic.durable_candidates == ()
        assert coordinator.complete_calls == []
        release_preview.set()
        initial = initial_future.result(timeout=5)

    completed = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert len(initial.durable_candidates) == 1
    assert len(completed.durable_candidates) == 1
    assert len(coordinator.complete_calls) == 1


def test_initial_preview_failure_cannot_race_periodic_completion(
    tmp_path: Path,
) -> None:
    preview_entered = Event()
    release_preview = Event()

    class FailingPreviewCoordinator(_Coordinator):
        def create_preview(
            self,
            reservation: object,
            *,
            evidence: object,
        ) -> SimpleNamespace:
            self.preview_calls.append((reservation, evidence))
            preview_entered.set()
            assert release_preview.wait(timeout=5)
            raise OSError("preview assembly failed")

    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    journal = SQLiteWALJournal(tmp_path / "preview-failure-race.sqlite3", max_items=10)
    ring = _Ring(ready=False)
    coordinator = FailingPreviewCoordinator()
    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=coordinator,
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        initial_future = pool.submit(
            service.process,
            _observation(seq=1, seconds=0),
        )
        assert preview_entered.wait(timeout=5)
        ring.ready = True
        periodic = service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert periodic.durable_candidates == ()
        assert coordinator.complete_calls == []
        release_preview.set()
        initial = initial_future.result(timeout=5)

    assert initial.durable_candidates == ()
    assert coordinator.complete_calls == []
    assert len(coordinator.cancel_calls) == 1
    assert next(iter(states.values())).evidence_status == "failed"
    assert journal.pending_evidence_work_depth() == 0


def test_real_workspace_preview_is_not_closed_by_periodic_completion(
    tmp_path: Path,
) -> None:
    preview_entered = Event()
    release_preview = Event()

    class BlockingPreviewAssembler(_WorkspaceAssembler):
        def assemble_preview(
            self,
            reservation: object,
            output: object,
        ) -> SimpleNamespace:
            preview_entered.set()
            assert release_preview.wait(timeout=5)
            return super().assemble_preview(reservation, output)

    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    ring = _Ring(ready=False)
    coordinator, workspace = _workspace_coordinator(
        tmp_path / "real-preview-race",
        ring=ring,
        assembler=BlockingPreviewAssembler(),
    )
    service, _, _, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(
            tmp_path / "real-preview-race.sqlite3",
            max_items=10,
        ),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=coordinator,  # type: ignore[arg-type]
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        initial_future = pool.submit(
            service.process,
            _observation(seq=1, seconds=0),
        )
        assert preview_entered.wait(timeout=5)
        ring.ready = True
        periodic = service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert periodic.durable_candidates == ()
        release_preview.set()
        initial = initial_future.result(timeout=5)

    completed = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert len(initial.durable_candidates) == 1
    assert len(completed.durable_candidates) == 1
    assert workspace.item_count == 0
    assert workspace._open_targets == set()
    workspace.close()


def test_real_workspace_preview_failure_cannot_race_periodic_cleanup(
    tmp_path: Path,
) -> None:
    preview_entered = Event()
    release_preview = Event()

    class FailingPreviewAssembler(_WorkspaceAssembler):
        def assemble_preview(
            self,
            _reservation: object,
            output: object,
        ) -> SimpleNamespace:
            output.write_bytes(b"partial-preview")
            preview_entered.set()
            assert release_preview.wait(timeout=5)
            raise OSError("preview failed")

    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    ring = _Ring(ready=False)
    coordinator, workspace = _workspace_coordinator(
        tmp_path / "real-preview-failure",
        ring=ring,
        assembler=FailingPreviewAssembler(),
    )
    service, _, _, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(
            tmp_path / "real-preview-failure.sqlite3",
            max_items=10,
        ),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=coordinator,  # type: ignore[arg-type]
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        initial_future = pool.submit(
            service.process,
            _observation(seq=1, seconds=0),
        )
        assert preview_entered.wait(timeout=5)
        ring.ready = True
        periodic = service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert periodic.durable_candidates == ()
        release_preview.set()
        initial = initial_future.result(timeout=5)

    assert initial.durable_candidates == ()
    assert next(iter(states.values())).evidence_status == "failed"
    assert workspace.item_count == 0
    assert workspace._open_targets == set()
    workspace.close()


def test_real_workspace_cleanup_cannot_race_inflight_completion(
    tmp_path: Path,
) -> None:
    completion_entered = Event()
    release_completion = Event()

    class BlockingCompleteAssembler(_WorkspaceAssembler):
        def assemble(self, reservation: object, output: object) -> SimpleNamespace:
            output.write_bytes(b"partial-final")
            completion_entered.set()
            assert release_completion.wait(timeout=5)
            return super().assemble(reservation, output)

    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    ring = _Ring(ready=False)
    coordinator, workspace = _workspace_coordinator(
        tmp_path / "real-cleanup-race",
        ring=ring,
        assembler=BlockingCompleteAssembler(),
    )
    service, _, _, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(
            tmp_path / "real-cleanup-race.sqlite3",
            max_items=10,
        ),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=coordinator,  # type: ignore[arg-type]
    )
    service.process(_observation(seq=1, seconds=0))
    ring.ready = True

    with ThreadPoolExecutor(max_workers=2) as pool:
        completion_future = pool.submit(
            service.run_periodic,
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert completion_entered.wait(timeout=5)
        service.process(
            _observation(
                seq=1,
                seconds=2,
                stream_epoch=EPOCH_B,
                class_name="background",
                confidence=0.1,
            )
        )
        cleanup_attempt = service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_B,
            source_time=NOW + timedelta(seconds=2),
        )
        assert cleanup_attempt.durable_candidates == ()
        assert workspace._open_targets
        release_completion.set()
        completion = completion_future.result(timeout=5)

    assert completion.durable_candidates == ()
    assert next(iter(states.values())).evidence_status == "failed"
    assert workspace.item_count == 0
    assert workspace._open_targets == set()
    workspace.close()


def test_delayed_old_epoch_periodic_call_cannot_complete_after_epoch_switch(
    tmp_path: Path,
) -> None:
    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    ring = _Ring(ready=False)
    service, _, coordinator, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(tmp_path / "old-epoch.sqlite3", max_items=10),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
    )
    initial = service.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    switched = service.process(
        _observation(
            seq=1,
            seconds=1,
            stream_epoch=EPOCH_B,
            class_name="background",
            confidence=0.1,
        )
    )
    assert switched.engine_result is not None
    assert switched.engine_result.accepted is True
    ring.ready = True

    delayed = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert delayed.durable_candidates == ()
    assert coordinator.complete_calls == []
    assert states[event_id].evidence_status == "failed"
    assert delayed.status.pending_evidence_work == 0
    assert "evidence_pending_epoch_changed" in delayed.status.reasons


def test_epoch_switch_during_completion_cannot_emit_or_ack_stale_ready_work(
    tmp_path: Path,
) -> None:
    completion_entered = Event()
    release_completion = Event()

    class BlockingCompleteCoordinator(_Coordinator):
        def complete(self, reservation: object, evidence: object) -> object:
            completion_entered.set()
            assert release_completion.wait(timeout=5)
            return super().complete(reservation, evidence)

    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    ring = _Ring(ready=False)
    coordinator = BlockingCompleteCoordinator()
    service, _, _, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(
            tmp_path / "epoch-switch-during-complete.sqlite3",
            max_items=10,
        ),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=coordinator,
    )
    service.process(_observation(seq=1, seconds=0))
    ring.ready = True

    with ThreadPoolExecutor(max_workers=2) as pool:
        completion = pool.submit(
            service.run_periodic,
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert completion_entered.wait(timeout=5)
        switched = service.process(
            _observation(
                seq=1,
                seconds=2,
                stream_epoch=EPOCH_B,
                class_name="background",
                confidence=0.1,
            )
        )
        assert switched.engine_result is not None
        assert switched.engine_result.accepted is True
        release_completion.set()
        result = completion.result(timeout=5)

    assert result.durable_candidates == ()
    assert "evidence_pending_epoch_changed" in result.status.reasons
    assert result.status.pending_evidence_work == 0
    assert next(iter(states.values())).evidence_status == "failed"


@pytest.mark.parametrize("path", ("immediate", "periodic"))
@pytest.mark.parametrize(
    "mutation",
    (
        "digest",
        "codec",
        "naive_time",
        "reversed_time",
        "duration",
        "interval",
    ),
)
def test_malformed_ready_evidence_fails_closed(
    tmp_path: Path,
    path: str,
    mutation: str,
) -> None:
    class MalformedCoordinator(_Coordinator):
        def complete(self, reservation: object, evidence: object) -> EvidenceInput:
            valid = super().complete(reservation, evidence)
            assert isinstance(valid, EvidenceInput)
            if mutation == "digest":
                return replace(valid, sha256="")
            if mutation == "codec":
                return replace(valid, codec="h265")
            if mutation == "naive_time":
                return replace(valid, start_at=valid.start_at.replace(tzinfo=None))
            if mutation == "reversed_time":
                return replace(
                    valid,
                    start_at=valid.end_at,
                    end_at=valid.start_at,
                )
            if mutation == "duration":
                return replace(
                    valid,
                    start_at=valid.start_at - timedelta(seconds=4),
                    end_at=valid.end_at + timedelta(seconds=4),
                )
            return replace(
                valid,
                start_at=valid.start_at + timedelta(seconds=1),
                end_at=valid.end_at + timedelta(seconds=1),
            )

    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    ring = _Ring(ready=path == "immediate")
    coordinator = MalformedCoordinator()
    service, _, _, _ = _service(
        tmp_path,
        journal=SQLiteWALJournal(
            tmp_path / f"malformed-{path}-{mutation}.sqlite3",
            max_items=10,
        ),
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=coordinator,
    )
    initial = service.process(_observation(seq=1, seconds=0))
    event_id = next(iter(states))
    if path == "immediate":
        result = initial
    else:
        assert len(initial.durable_candidates) == 1
        ring.ready = True
        result = service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=2),
        )

    assert result.durable_candidates == ()
    assert states[event_id].evidence_status == "failed"
    assert coordinator.cancel_calls
    assert result.status.pending_evidence_work == 0


def test_seed_persistence_failure_keeps_candidate_wal_and_never_reserves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "seed-write-failure.sqlite3", max_items=4)
    replayed: list[object] = []
    service, ring, coordinator, replay = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        load_candidate=lambda event_id: (_ for _ in ()).throw(KeyError(event_id)),
    )

    def fail_seed(**_: object) -> object:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(journal, "seed_pending_evidence_work", fail_seed)

    result = service.process(_observation(seq=1, seconds=0))

    assert result.durable_candidates == ()
    assert journal.depth() == 1
    assert replayed == []
    assert replay.status.processed_total == 0
    assert ring.calls == []
    assert coordinator.preview_calls == []
    assert "pending_evidence_seed_write_failed" in result.status.reasons
    service.start()
    service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=1),
    )
    assert journal.depth() == 0
    assert journal.quarantine_depth() == 1
    assert replayed == []
    assert "candidate_replay_missing_recovery_seed" in service.status.reasons
    assert "candidate_replay_seed_quarantined" in service.status.reasons


def test_pending_seed_is_durable_before_candidate_ack_and_ring_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "seed-order.sqlite3", max_items=4)
    order: list[str] = []
    original_seed = journal.seed_pending_evidence_work

    def seed(**kwargs: object) -> object:
        order.append("seed")
        return original_seed(**kwargs)

    monkeypatch.setattr(journal, "seed_pending_evidence_work", seed)
    replayed: list[object] = []

    def persist(item: object) -> None:
        order.append("persist")
        replayed.append(item)

    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=lambda _event_id: CandidateEventV1.model_validate(
            replayed[0].payload
        ),
        ring=_Ring(order=order),
        coordinator=_Coordinator(order=order),
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert len(result.durable_candidates) == 1
    assert order[:3] == ["seed", "persist", "reserve"]


def test_orphan_candidate_is_quarantined_without_blocking_later_seeded_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = SQLiteWALJournal(
        tmp_path / "orphan-then-seeded.sqlite3",
        max_items=4,
        max_quarantine_items=4,
    )
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    original_seed = journal.seed_pending_evidence_work
    seed_attempts = 0

    def fail_first_seed(**kwargs: object) -> object:
        nonlocal seed_attempts
        seed_attempts += 1
        if seed_attempts == 1:
            raise sqlite3.OperationalError("database is locked")
        return original_seed(**kwargs)

    monkeypatch.setattr(journal, "seed_pending_evidence_work", fail_first_seed)
    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )

    first = service.process(
        _observation(seq=1, seconds=0, track_id="orphan-track")
    )
    second = service.process(
        _observation(seq=2, seconds=1, track_id="seeded-track")
    )

    assert first.durable_candidates == ()
    assert len(second.durable_candidates) == 1
    assert journal.quarantine_depth() == 1
    assert journal.depth() == 0
    assert len(persisted) == 1
    assert (
        second.durable_candidates[0].trigger.event.event_id
        in persisted
    )
    assert service.status.pending_evidence_work == 1


def test_active_recovery_remains_retryable_when_task7_startup_marked_failed(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "task7-startup-failed.sqlite3"
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    first_journal = SQLiteWALJournal(journal_path, max_items=4)
    first, ring, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )
    initial = first.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    assert first_journal.pending_evidence_work_items(limit=1)[0].phase == "active"
    first_journal.close()

    # This is the durable state produced when the real Task 7 coordinator
    # terminally reconciles an abandoned preview before Task 8 starts.
    mark(event_id, "failed")
    ring.ready = True
    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    )
    restarted_engine.ingest(
        _observation(
            seq=2,
            seconds=1,
            class_name="background",
            confidence=0.1,
        )
    )
    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted, _, coordinator, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda candidate_id: mark(candidate_id, "pending"),
        mark_evidence_failed=lambda candidate_id: mark(candidate_id, "failed"),
        ring=ring,
        engine=restarted_engine,
    )

    started = restarted.start()
    completed = restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert started.pending_evidence_work == 1
    assert len(completed.durable_candidates) == 1
    assert coordinator.complete_calls
    assert restarted_journal.pending_evidence_work_depth() == 0


def test_retryable_recovery_load_failure_keeps_active_work_for_next_start(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "pending-load-retry.sqlite3"
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    first_journal = SQLiteWALJournal(journal_path, max_items=4)
    first, ring, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )
    initial = first.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    first_journal.close()

    attempts = 0

    def load(event_id_to_load: UUID) -> CandidateEventV1:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("database is locked")
        return persisted[event_id_to_load]

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda candidate_id: mark(candidate_id, "pending"),
        mark_evidence_failed=lambda candidate_id: mark(candidate_id, "failed"),
        ring=ring,
    )

    first_start = restarted.start()
    second_start = restarted.start()

    assert first_start.degraded is True
    assert "pending_evidence_recovery_retryable" in first_start.reasons
    assert restarted_journal.pending_evidence_quarantine_depth() == 0
    assert restarted_journal.pending_evidence_work_depth() == 1
    assert second_start.pending_evidence_work == 1
    assert persisted[event_id].evidence_status == "pending"


def test_terminal_ack_failure_remains_live_and_restores_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "ack-live-retry.sqlite3", max_items=1)
    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    class ReadyCoordinator(_Coordinator):
        def complete(self, reservation: object, evidence: object) -> object:
            result = super().complete(reservation, evidence)
            assert isinstance(evidence, EvidenceIntent)
            mark(evidence.event_id, "ready")
            return result

    service, _, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=True),
        coordinator=ReadyCoordinator(),
        engine=EventEngine(
            module_rules=(_module_rule(votes_required=1, sample_count=1),),
            limits=EngineLimits(max_pending_events=1),
        ),
    )
    original_ack = journal.acknowledge_pending_evidence_work
    attempts = 0

    def fail_once(**kwargs: object) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return False
        return original_ack(**kwargs)

    monkeypatch.setattr(journal, "acknowledge_pending_evidence_work", fail_once)

    initial = service.process(_observation(seq=1, seconds=0))
    recovered = service.start()

    assert initial.durable_candidates == ()
    assert coordinator.complete_calls
    assert recovered.pending_evidence_work == 0
    assert journal.pending_evidence_work_depth() == 0
    assert attempts == 2


def test_terminal_ack_commit_before_return_crash_restores_memory_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "ack-commit-crash.sqlite3", max_items=1)
    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        if event_id in states:
            return states[event_id]
        return next(
            event
            for item in replayed
            if (event := CandidateEventV1.model_validate(item.payload)).event_id
            == event_id
        )

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    class ReadyCoordinator(_Coordinator):
        def complete(self, reservation: object, evidence: object) -> object:
            result = super().complete(reservation, evidence)
            assert isinstance(evidence, EvidenceIntent)
            mark(evidence.event_id, "ready")
            return result

    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=True),
        coordinator=ReadyCoordinator(),
        engine=EventEngine(
            module_rules=(_module_rule(votes_required=1, sample_count=1),),
            limits=EngineLimits(max_pending_events=1),
        ),
    )
    original_ack = journal.acknowledge_pending_evidence_work

    def commit_then_crash(**kwargs: object) -> bool:
        assert original_ack(**kwargs)
        raise SystemExit("ACK committed before process death")

    monkeypatch.setattr(
        journal,
        "acknowledge_pending_evidence_work",
        commit_then_crash,
    )

    with pytest.raises(SystemExit, match="ACK committed"):
        service.process(_observation(seq=1, seconds=0))

    assert journal.pending_evidence_work_depth() == 0
    assert service.status.pending_evidence_memory_work == 1
    monkeypatch.setattr(
        journal,
        "acknowledge_pending_evidence_work",
        original_ack,
    )

    recovered = service.start()

    assert recovered.pending_evidence_work == 0
    assert recovered.pending_evidence_memory_work == 0
    assert service.start().pending_evidence_memory_work == 0
    service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=1),
    )
    admitted = service.process(
        _observation(seq=2, seconds=2, track_id="ready-capacity-proof")
    )
    assert len(admitted.durable_candidates) == 1
    assert admitted.status.pending_evidence_memory_work == 0


def test_durable_ready_publication_wins_concurrent_epoch_switch(
    tmp_path: Path,
) -> None:
    completion_entered = Event()
    release_completion = Event()
    replayed: list[object] = []
    states: dict[UUID, CandidateEventV1] = {}

    def load(event_id: UUID) -> CandidateEventV1:
        return states.get(event_id, CandidateEventV1.model_validate(replayed[0].payload))

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        states[event_id] = load(event_id).model_copy(
            update={"evidence_status": status}
        )
        return states[event_id]

    class PublishedCoordinator(_Coordinator):
        def complete(self, reservation: object, evidence: object) -> object:
            result = super().complete(reservation, evidence)
            assert isinstance(evidence, EvidenceIntent)
            mark(evidence.event_id, "ready")
            completion_entered.set()
            assert release_completion.wait(timeout=5)
            return result

    ring = _Ring(ready=False)
    journal = SQLiteWALJournal(tmp_path / "ready-wins-epoch.sqlite3", max_items=4)
    service, _, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=PublishedCoordinator(),
    )
    service.process(_observation(seq=1, seconds=0))
    ring.ready = True

    with ThreadPoolExecutor(max_workers=2) as pool:
        completion = pool.submit(
            service.run_periodic,
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert completion_entered.wait(timeout=5)
        switched = service.process(
            _observation(
                seq=1,
                seconds=2,
                stream_epoch=EPOCH_B,
                class_name="background",
                confidence=0.1,
            )
        )
        assert switched.engine_result is not None
        assert switched.engine_result.accepted is True
        release_completion.set()
        result = completion.result(timeout=5)

    assert len(result.durable_candidates) == 1
    assert states[next(iter(states))].evidence_status == "ready"
    assert journal.pending_evidence_work_depth() == 0
    assert result.status.pending_evidence_work == 0
    assert coordinator.cancel_calls == []


def test_real_task7_startup_failure_is_reassembled_and_finalized_ready(
    tmp_path: Path,
) -> None:
    repository = _real_repository(tmp_path / "task7-restart.db")
    journal_path = tmp_path / "task7-restart.sqlite3"
    workspace_root = tmp_path / "task7-restart-workspace"
    first_journal = SQLiteWALJournal(journal_path, max_items=4)
    ring = _Ring(ready=False)
    first_coordinator, first_workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=first_journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    first, _, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=first_coordinator,  # type: ignore[arg-type]
    )

    initial = first.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    assert repository.get_event(event_id).evidence_status == "pending"
    assert first_workspace.item_count == 1
    first_workspace.close()
    first_journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted_coordinator, restarted_workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=restarted_journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    assert repository.get_event(event_id).evidence_status == "failed"
    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    )
    restarted_engine.ingest(
        _observation(
            seq=2,
            seconds=1,
            class_name="background",
            confidence=0.1,
        )
    )
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=restarted_coordinator,  # type: ignore[arg-type]
        engine=restarted_engine,
    )

    assert restarted.start().pending_evidence_work == 1
    ring.ready = True
    completed = restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert len(completed.durable_candidates) == 1
    assert repository.get_event(event_id).evidence_status == "ready"
    assert restarted_journal.pending_evidence_work_depth() == 0
    assert restarted_workspace.item_count == 0
    restarted_workspace.close()


def test_system_exit_after_ring_reserve_before_seed_promotion_recovers_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _real_repository(tmp_path / "reserve-crash.db")
    journal_path = tmp_path / "reserve-crash.sqlite3"
    workspace_root = tmp_path / "reserve-crash-workspace"
    journal = SQLiteWALJournal(journal_path, max_items=4)
    ring = _Ring(ready=False)
    coordinator, workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=coordinator,  # type: ignore[arg-type]
    )
    original_promote = journal.reserve_pending_evidence_work

    def crash_before_promote(**_: object) -> object:
        raise SystemExit("simulated process death")

    monkeypatch.setattr(
        journal,
        "reserve_pending_evidence_work",
        crash_before_promote,
    )

    with pytest.raises(SystemExit, match="simulated process death"):
        service.process(_observation(seq=1, seconds=0))

    event_id = next(iter(repository.list_events())).event_id
    assert journal.depth() == 0
    assert journal.pending_evidence_work_items(limit=1)[0].phase == "seed"
    assert len(ring.calls) == 1
    assert workspace.item_count == 0
    monkeypatch.setattr(
        journal,
        "reserve_pending_evidence_work",
        original_promote,
    )
    workspace.close()
    journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted_coordinator, restarted_workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=restarted_journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    )
    restarted_engine.ingest(
        _observation(
            seq=2,
            seconds=1,
            class_name="background",
            confidence=0.1,
        )
    )
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=restarted_coordinator,  # type: ignore[arg-type]
        engine=restarted_engine,
    )
    assert restarted.start().pending_evidence_work == 1
    ring.ready = True
    completed = restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert len(completed.durable_candidates) == 1
    assert repository.get_event(event_id).evidence_status == "ready"
    assert restarted_journal.pending_evidence_work_depth() == 0
    assert ring.released[-1] == f"event-{event_id}"
    assert restarted_workspace.item_count == 0
    restarted_workspace.close()


def test_real_ready_publication_wins_epoch_switch_after_database_commit(
    tmp_path: Path,
) -> None:
    repository = _real_repository(tmp_path / "real-ready-wins.db")
    journal = SQLiteWALJournal(tmp_path / "real-ready-wins.sqlite3", max_items=4)
    workspace_root = tmp_path / "real-ready-wins-workspace"
    ring = _Ring(ready=False)
    real_coordinator, workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    published = Event()
    release = Event()

    class BlockAfterPublication:
        def create_preview(self, reservation: object, *, evidence: object) -> object:
            return real_coordinator.create_preview(reservation, evidence=evidence)

        def complete(self, reservation: object, evidence: object) -> object:
            result = real_coordinator.complete(reservation, evidence)  # type: ignore[arg-type]
            published.set()
            assert release.wait(timeout=5)
            return result

        def cancel(self, reservation_id: str, *, evidence: object) -> None:
            real_coordinator.cancel(reservation_id, evidence=evidence)  # type: ignore[arg-type]

    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=BlockAfterPublication(),  # type: ignore[arg-type]
    )
    initial = service.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    ring.ready = True

    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(
            service.run_periodic,
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert published.wait(timeout=5)
        assert repository.get_event(event_id).evidence_status == "ready"
        service.process(
            _observation(
                seq=1,
                seconds=2,
                stream_epoch=EPOCH_B,
                class_name="background",
                confidence=0.1,
            )
        )
        release.set()
        result = future.result(timeout=5)

    assert len(result.durable_candidates) == 1
    assert repository.get_event(event_id).evidence_status == "ready"
    assert journal.pending_evidence_work_depth() == 0
    assert workspace.item_count == 0
    workspace.close()


def test_real_epoch_switch_wins_before_publication_and_terminalizes(
    tmp_path: Path,
) -> None:
    repository = _real_repository(tmp_path / "real-epoch-wins.db")
    journal = SQLiteWALJournal(tmp_path / "real-epoch-wins.sqlite3", max_items=4)
    workspace_root = tmp_path / "real-epoch-wins-workspace"
    reservation_entered = Event()
    release_reservation = Event()

    class BlockingReadyRing(_Ring):
        def reserve(self, **kwargs: object) -> SimpleNamespace:
            reservation = super().reserve(**kwargs)
            if self.ready:
                reservation_entered.set()
                assert release_reservation.wait(timeout=5)
            return reservation

    ring = BlockingReadyRing(ready=False)
    coordinator, workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=coordinator,  # type: ignore[arg-type]
    )
    initial = service.process(_observation(seq=1, seconds=0))
    event_id = initial.durable_candidates[0].trigger.event.event_id
    ring.ready = True

    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(
            service.run_periodic,
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=1),
        )
        assert reservation_entered.wait(timeout=5)
        service.process(
            _observation(
                seq=1,
                seconds=2,
                stream_epoch=EPOCH_B,
                class_name="background",
                confidence=0.1,
            )
        )
        release_reservation.set()
        result = future.result(timeout=5)

    assert result.durable_candidates == ()
    assert repository.get_event(event_id).evidence_status == "failed"
    assert journal.pending_evidence_work_depth() == 0
    assert workspace.item_count == 0
    workspace.close()


def test_seed_only_crash_reenqueues_exact_candidate_before_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _real_repository(tmp_path / "seed-only-crash.db")
    journal_path = tmp_path / "seed-only-crash.sqlite3"
    workspace_root = tmp_path / "seed-only-crash-workspace"
    journal = SQLiteWALJournal(journal_path, max_items=4)
    ring = _Ring(ready=False)
    coordinator, workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=coordinator,  # type: ignore[arg-type]
    )
    original_enqueue = journal.enqueue_event

    def crash_before_candidate_enqueue(_event: CandidateEventV1) -> object:
        raise SystemExit("seed-only crash")

    monkeypatch.setattr(journal, "enqueue_event", crash_before_candidate_enqueue)

    with pytest.raises(SystemExit, match="seed-only crash"):
        service.process(_observation(seq=1, seconds=0))

    assert repository.list_events() == []
    seed = journal.pending_evidence_work_items(limit=1)[0]
    assert seed.phase == "seed"
    assert journal.depth() == 0
    assert ring.calls == []
    monkeypatch.setattr(journal, "enqueue_event", original_enqueue)
    workspace.close()
    journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted_coordinator, restarted_workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=restarted_journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=restarted_coordinator,  # type: ignore[arg-type]
    )

    started = restarted.start()
    recovered_event = repository.list_events()[0]

    assert recovered_event.event_id == UUID(seed.event_id)
    assert recovered_event.evidence_status == "pending"
    assert started.pending_evidence_work == 1
    assert started.pending_evidence_memory_work == 1
    assert restarted_journal.depth() == 0
    assert len(ring.calls) == 1
    restarted_workspace.close()


def test_periodic_automatically_retries_transient_startup_recovery(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "automatic-recovery.sqlite3"
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    first_journal = SQLiteWALJournal(journal_path, max_items=4)
    first, ring, _, _ = _service(
        tmp_path,
        journal=first_journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=_Ring(ready=False),
    )
    first.process(_observation(seq=1, seconds=0))
    first_journal.close()

    attempts = 0

    def load(event_id: UUID) -> CandidateEventV1:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("database is locked")
        return persisted[event_id]

    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    )
    restarted_engine.ingest(
        _observation(
            seq=2,
            seconds=1,
            class_name="background",
            confidence=0.1,
        )
    )
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        engine=restarted_engine,
        pending_recovery_backoff_seconds=2,
        monotonic_clock=clock,
    )

    started = restarted.start()
    assert started.pending_evidence_work == 1
    assert started.pending_evidence_memory_work == 0
    assert started.pending_evidence_retry_attempts == 1
    assert started.pending_evidence_next_retry_seconds == 2
    clock.now = 1
    before_due = restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=1),
    )
    assert before_due.status.pending_evidence_memory_work == 0
    clock.now = 2
    recovered = restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=2),
    )

    assert attempts >= 2
    assert recovered.status.pending_evidence_work == 1
    assert recovered.status.pending_evidence_memory_work == 1
    assert recovered.status.pending_evidence_next_retry_seconds is None


def test_periodic_admits_persisted_seed_after_initial_candidate_load_lag(
    tmp_path: Path,
) -> None:
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    load_attempts = 0

    def load(event_id: UUID) -> CandidateEventV1:
        nonlocal load_attempts
        load_attempts += 1
        if load_attempts == 1:
            raise KeyError(event_id)
        return persisted[event_id]

    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    journal = SQLiteWALJournal(tmp_path / "live-seed-admission.sqlite3", max_items=4)
    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=load,
        ring=_Ring(ready=False),
        pending_recovery_backoff_seconds=1,
        monotonic_clock=clock,
    )

    initial = service.process(_observation(seq=1, seconds=0))

    assert initial.durable_candidates == ()
    assert journal.pending_evidence_work_items(limit=1)[0].phase == "seed"
    assert initial.status.pending_evidence_next_retry_seconds == 1
    clock.now = 1
    recovered = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=1),
    )

    assert recovered.status.pending_evidence_work == 1
    assert recovered.status.pending_evidence_memory_work == 1
    assert journal.pending_evidence_work_items(limit=1)[0].phase == "active"


@pytest.mark.parametrize(
    ("boundary", "recoverable"),
    (
        ("candidate_enqueue_committed", True),
        ("full_lifecycle_committed", False),
        ("preview_registered", False),
        ("activation_committed", True),
    ),
)
def test_real_restart_converges_actual_lifecycle_crash_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    recoverable: bool,
) -> None:
    repository = _real_repository(tmp_path / f"{boundary}.db")
    journal_path = tmp_path / f"{boundary}.sqlite3"
    workspace_root = tmp_path / f"{boundary}-workspace"
    journal = SQLiteWALJournal(journal_path, max_items=4)
    ring = _Ring(ready=False)
    coordinator, workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=coordinator,  # type: ignore[arg-type]
    )
    if boundary == "candidate_enqueue_committed":
        original = journal.enqueue_event

        def crash_after_candidate(event: CandidateEventV1) -> object:
            original(event)
            raise SystemExit(boundary)

        monkeypatch.setattr(journal, "enqueue_event", crash_after_candidate)
    elif boundary == "full_lifecycle_committed":
        original = journal.reserve_pending_evidence_work

        def crash_after_full(**kwargs: object) -> object:
            original(**kwargs)
            raise SystemExit(boundary)

        monkeypatch.setattr(
            journal,
            "reserve_pending_evidence_work",
            crash_after_full,
        )
    elif boundary == "preview_registered":
        original = coordinator.create_preview

        def crash_after_preview(
            reservation: object,
            *,
            evidence: object,
        ) -> object:
            original(reservation, evidence=evidence)  # type: ignore[arg-type]
            raise SystemExit(boundary)

        monkeypatch.setattr(coordinator, "create_preview", crash_after_preview)
    else:
        original = journal.activate_pending_evidence_work

        def crash_after_activation(**kwargs: object) -> object:
            original(**kwargs)
            raise SystemExit(boundary)

        monkeypatch.setattr(
            journal,
            "activate_pending_evidence_work",
            crash_after_activation,
        )

    with pytest.raises(SystemExit, match=boundary):
        service.process(_observation(seq=1, seconds=0))

    row = journal.pending_evidence_work_items(limit=1)[0]
    event_id = UUID(row.event_id)
    workspace.close()
    journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted_coordinator, restarted_workspace = _real_evidence_coordinator(
        tmp_path,
        repository=repository,
        journal=restarted_journal,
        ring=ring,
        workspace_root=workspace_root,
    )
    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    )
    restarted_engine.ingest(
        _observation(
            seq=2,
            seconds=1,
            class_name="background",
            confidence=0.1,
        )
    )
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=repository.persist_journal_item,
        load_candidate=repository.get_event,
        mark_evidence_pending=repository.mark_candidate_evidence_pending,
        mark_evidence_failed=repository.mark_candidate_evidence_failed,
        ring=ring,
        coordinator=restarted_coordinator,  # type: ignore[arg-type]
        engine=restarted_engine,
    )

    started = restarted.start()
    if not recoverable:
        assert repository.get_event(event_id).evidence_status == "failed"
        assert started.pending_evidence_work == 0
        assert restarted_journal.pending_evidence_work_depth() == 0
    else:
        assert started.pending_evidence_work == 1
        ring.ready = True
        completed = restarted.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=2),
        )
        assert len(completed.durable_candidates) == 1
        assert repository.get_event(event_id).evidence_status == "ready"
        assert restarted_journal.pending_evidence_work_depth() == 0
    assert restarted_workspace.item_count == 0
    restarted_workspace.close()


def test_failed_ack_commit_before_return_releases_capacity_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = SQLiteWALJournal(
        tmp_path / "failed-ack-commit-crash.sqlite3",
        max_items=4,
    )
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    ring = _Ring(ready=False)
    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=load,
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        engine=EventEngine(
            module_rules=(_module_rule(votes_required=1, sample_count=1),),
            limits=EngineLimits(max_pending_events=1),
        ),
    )
    first = service.process(_observation(seq=1, seconds=0))
    first_event_id = first.durable_candidates[0].trigger.event.event_id
    service.process(
        _observation(
            seq=1,
            seconds=1,
            stream_epoch=EPOCH_B,
            class_name="background",
            confidence=0.1,
        )
    )
    original_ack = journal.acknowledge_pending_evidence_work

    def commit_then_crash(**kwargs: object) -> bool:
        assert original_ack(**kwargs)
        raise SystemExit("failed ACK committed before process death")

    monkeypatch.setattr(
        journal,
        "acknowledge_pending_evidence_work",
        commit_then_crash,
    )

    with pytest.raises(SystemExit, match="failed ACK committed"):
        service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_B,
            source_time=NOW + timedelta(seconds=2),
        )

    assert persisted[first_event_id].evidence_status == "failed"
    assert journal.pending_evidence_work_depth() == 0
    assert service.status.pending_evidence_memory_work == 1
    monkeypatch.setattr(
        journal,
        "acknowledge_pending_evidence_work",
        original_ack,
    )

    assert service.start().pending_evidence_memory_work == 0
    assert service.start().pending_evidence_memory_work == 0
    service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_B,
        source_time=NOW + timedelta(seconds=3),
    )

    admitted = service.process(
        _observation(
            seq=2,
            seconds=4,
            stream_epoch=EPOCH_B,
            track_id="second-event",
        )
    )

    assert len(admitted.durable_candidates) == 1
    assert admitted.status.pending_evidence_memory_work == 1
    assert len(persisted) == 2


def test_full_candidate_quarantine_does_not_block_seeded_recovery(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "full-quarantine-recovery.sqlite3"
    journal = SQLiteWALJournal(
        journal_path,
        max_items=6,
        max_quarantine_items=1,
    )
    event_factory = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    )
    filler = event_factory.ingest(
        _observation(seq=1, seconds=-10, track_id="quarantine-filler")
    ).triggers[0].event
    filler_item = journal.enqueue_event(filler)
    journal.quarantine(filler_item, error_type="ExistingForensicRow")
    orphan_one = event_factory.ingest(
        _observation(seq=2, seconds=-9, track_id="orphan-one")
    ).triggers[0].event
    orphan_two = event_factory.ingest(
        _observation(seq=3, seconds=-8, track_id="orphan-two")
    ).triggers[0].event
    orphan_items = (
        journal.enqueue_event(orphan_one),
        journal.enqueue_event(orphan_two),
    )
    persisted: dict[UUID, CandidateEventV1] = {}

    def unavailable(_: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    first, ring, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=unavailable,
        load_candidate=lambda event_id: persisted[event_id],
        ring=_Ring(ready=False),
    )

    first_initial = first.process(
        _observation(seq=1, seconds=0, track_id="seeded-after-orphans")
    )
    second_initial = first.process(
        _observation(seq=2, seconds=1, track_id="second-seeded-after-orphans")
    )

    assert first_initial.durable_candidates == ()
    assert second_initial.durable_candidates == ()
    assert journal.quarantine_depth() == 1
    assert journal.depth() == 4
    assert journal.pending_evidence_work_depth() == 2
    assert (
        "candidate_replay_seed_quarantine_failed"
        in second_initial.status.reasons
    )
    seeded_event_ids = tuple(
        UUID(item.event_id)
        for item in journal.pending_evidence_work_items(limit=2)
    )
    journal.close()

    restarted_journal = SQLiteWALJournal(
        journal_path,
        max_items=6,
        max_quarantine_items=1,
    )

    persisted_order: list[UUID] = []

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event
        persisted_order.append(event.event_id)

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),)
    )
    restarted_engine.ingest(
        _observation(
            seq=3,
            seconds=2,
            class_name="background",
            confidence=0.1,
        )
    )

    class ReadyCoordinator(_Coordinator):
        def complete(self, reservation: object, evidence: object) -> object:
            result = super().complete(reservation, evidence)
            assert isinstance(evidence, EvidenceIntent)
            mark(evidence.event_id, "ready")
            return result

    restarted, _, coordinator, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=ReadyCoordinator(),
        engine=restarted_engine,
    )

    started = restarted.start()

    assert tuple(persisted_order) == seeded_event_ids
    assert all(
        persisted[event_id].evidence_status == "pending"
        for event_id in seeded_event_ids
    )
    assert started.pending_evidence_memory_work == 2
    assert restarted_journal.quarantine_depth() == 1
    assert tuple(item.item_id for item in restarted_journal.items(limit=6)) == tuple(
        item.item_id for item in orphan_items
    )
    ring.ready = True
    completed = restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=3),
    )

    assert len(completed.durable_candidates) == 2
    assert coordinator.complete_calls
    assert all(
        persisted[event_id].evidence_status == "ready"
        for event_id in seeded_event_ids
    )
    assert restarted_journal.pending_evidence_work_depth() == 0
    assert tuple(item.item_id for item in restarted_journal.items(limit=6)) == tuple(
        item.item_id for item in orphan_items
    )


@pytest.mark.parametrize(
    ("failure_target", "failures", "restart", "reserve_raises"),
    (
        ("transition", 1, False, False),
        ("release", 1, False, False),
        ("transition", 2, True, False),
        ("release", 2, True, False),
        ("transition", 1, False, True),
        ("release", 1, False, True),
        ("transition", 2, True, True),
        ("release", 2, True, True),
    ),
)
def test_pre_evidence_failure_retains_seed_until_transition_and_release_converge(
    tmp_path: Path,
    failure_target: str,
    failures: int,
    restart: bool,
    reserve_raises: bool,
) -> None:
    journal_path = tmp_path / (
        f"pre-evidence-{failure_target}-{failures}-{reserve_raises}.sqlite3"
    )
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def load(event_id: UUID) -> CandidateEventV1:
        return persisted[event_id]

    transition_attempts = 0

    def mark_failed(event_id: UUID) -> CandidateEventV1:
        nonlocal transition_attempts
        transition_attempts += 1
        if failure_target == "transition" and transition_attempts <= failures:
            raise sqlite3.OperationalError("database is locked")
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": "failed"}
        )
        return persisted[event_id]

    class FlakyReleaseRing(_Ring):
        def __init__(self) -> None:
            super().__init__(ready=False)
            self.release_attempts = 0
            self.raise_after_reserve = reserve_raises

        def reserve(self, **kwargs: object) -> SimpleNamespace:
            reservation = super().reserve(**kwargs)
            if self.raise_after_reserve:
                raise OSError("reservation metadata unavailable")
            return reservation

        def release(self, reservation_id: str) -> None:
            self.release_attempts += 1
            if failure_target == "release" and self.release_attempts <= failures:
                raise OSError("ring release unavailable")
            super().release(reservation_id)

    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    ring = FlakyReleaseRing()

    def build(journal: SQLiteWALJournal, *, source_configured: bool) -> SiteEventService:
        service, _, _, _ = _service(
            tmp_path,
            journal=journal,
            processor=persist,
            load_candidate=load,
            mark_evidence_pending=lambda event_id: persisted[event_id].model_copy(
                update={"evidence_status": "pending"}
            ),
            mark_evidence_failed=mark_failed,
            ring=ring,
            engine=EventEngine(
                module_rules=(_module_rule(votes_required=1, sample_count=1),),
                limits=EngineLimits(max_pending_events=1),
            ),
            monotonic_clock=clock,
            source_references=(
                {"cam-01": "nvr://cam-01"} if source_configured else {}
            ),
        )
        return service

    journal = SQLiteWALJournal(journal_path, max_items=4)
    service = build(journal, source_configured=reserve_raises)
    initial = service.process(_observation(seq=1, seconds=0))
    first_event_id = next(iter(persisted))

    assert initial.durable_candidates == ()
    assert initial.status.degraded is True
    assert initial.status.pending_evidence_work == 1
    assert journal.pending_evidence_work_items(limit=1)[0].phase == "seed"

    if restart:
        journal.close()
        journal = SQLiteWALJournal(journal_path, max_items=4)
        service = build(journal, source_configured=reserve_raises)
        started = service.start()
        assert started.pending_evidence_work == 1
        assert started.pending_evidence_next_retry_seconds == 1

    clock.now = 1
    recovered = service.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=1),
    )

    assert persisted[first_event_id].evidence_status == "failed"
    assert recovered.status.pending_evidence_work == 0
    assert journal.pending_evidence_work_depth() == 0
    assert ring.release_attempts >= 1

    ring.raise_after_reserve = False
    accepting = build(journal, source_configured=True)
    admitted = accepting.process(
        _observation(
            seq=1,
            seconds=3,
            stream_epoch=EPOCH_B,
            track_id="capacity-proof",
        )
    )

    assert len(admitted.durable_candidates) == 1
    assert admitted.status.pending_evidence_memory_work == 1


def test_recovered_seed_over_capacity_releases_reservation_before_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_path = tmp_path / "seed-capacity-cleanup.sqlite3"
    journal = SQLiteWALJournal(journal_path, max_items=4)
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    ring = _Ring(ready=False)
    first, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        engine=EventEngine(
            module_rules=(_module_rule(votes_required=1, sample_count=1),),
            limits=EngineLimits(max_pending_events=2),
        ),
    )

    def crash_before_seed_promotion(**_: object) -> object:
        raise SystemExit("reservation exists before seed promotion")

    monkeypatch.setattr(
        journal,
        "reserve_pending_evidence_work",
        crash_before_seed_promotion,
    )
    for seq, track_id in ((1, "first-seed"), (2, "second-seed")):
        with pytest.raises(SystemExit, match="reservation exists"):
            first.process(
                _observation(
                    seq=seq,
                    seconds=float(seq - 1),
                    track_id=track_id,
                )
            )

    seed_records = journal.pending_evidence_work_items(limit=2)
    assert tuple(record.phase for record in seed_records) == ("seed", "seed")
    second_event_id = UUID(seed_records[1].event_id)
    second_reservation_id = seed_records[1].reservation_id
    journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),),
        limits=EngineLimits(max_pending_events=1),
    )
    restarted_engine.ingest(
        _observation(
            seq=3,
            seconds=2,
            class_name="background",
            confidence=0.1,
        )
    )
    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        engine=restarted_engine,
    )

    started = restarted.start()

    assert persisted[second_event_id].evidence_status == "failed"
    assert second_reservation_id in ring.released
    assert started.pending_evidence_work == 1
    assert restarted_journal.pending_evidence_work_depth() == 1


@pytest.mark.parametrize("release_failures", (0, 1, 2))
def test_real_ring_partial_reserve_failure_terminalizes_releases_and_acks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    release_failures: int,
) -> None:
    ring = EncodedFragmentRing(
        tmp_path / "partial-reserve-ring",
        ring_seconds=15,
        max_camera_bytes=10_000,
        max_spool_bytes=10_000,
    )
    for offset in (-2, -1, 0, 1):
        _append_fragment(ring, start_seconds=offset)
    original_write_metadata = ring._write_metadata
    metadata_writes = 0
    failing_writes = {2, *(range(3, 3 + release_failures))}

    def fail_second_metadata_write(record: object) -> None:
        nonlocal metadata_writes
        metadata_writes += 1
        if metadata_writes in failing_writes:
            raise OSError("metadata fsync unavailable")
        original_write_metadata(record)  # type: ignore[arg-type]

    monkeypatch.setattr(ring, "_write_metadata", fail_second_metadata_write)
    journal = SQLiteWALJournal(tmp_path / "partial-reserve.sqlite3", max_items=4)
    persisted: dict[UUID, CandidateEventV1] = {}

    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    service, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,  # type: ignore[arg-type]
        engine=EventEngine(
            module_rules=(_module_rule(votes_required=1, sample_count=1),),
            limits=EngineLimits(max_pending_events=1),
        ),
        monotonic_clock=clock,
    )

    result = service.process(_observation(seq=1, seconds=0))
    event_id = next(iter(persisted))
    reservation_id = f"event-{event_id}"

    assert len(result.durable_candidates) == (1 if release_failures == 0 else 0)
    assert persisted[event_id].evidence_status == "failed"
    assert journal.pending_evidence_work_depth() == (
        0 if release_failures == 0 else 1
    )
    for attempt in range(release_failures):
        clock.now = float(attempt + 1)
        service.run_periodic(
            camera_id="cam-01",
            stream_epoch=EPOCH_A,
            source_time=NOW + timedelta(seconds=attempt + 1),
        )

    assert journal.pending_evidence_work_depth() == 0
    assert service.status.pending_evidence_next_retry_seconds is None
    assert ring.release(reservation_id) == 0
    assert all(
        json.loads(path.read_text(encoding="utf-8"))["pins"] == {}
        for path in (tmp_path / "partial-reserve-ring").rglob("*.json")
    )

    admitted = service.process(
        _observation(seq=2, seconds=1, track_id="partial-reserve-capacity-proof")
    )

    assert len(admitted.durable_candidates) == 1
    assert admitted.status.pending_evidence_memory_work == 1


@pytest.mark.parametrize("terminal_status", ("failed", "ready"))
def test_terminal_seed_before_recoverable_seed_does_not_consume_live_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_status: str,
) -> None:
    journal_path = tmp_path / f"terminal-before-seed-{terminal_status}.sqlite3"
    journal = SQLiteWALJournal(journal_path, max_items=4)
    persisted: dict[UUID, CandidateEventV1] = {}

    def persist(item: object) -> None:
        event = CandidateEventV1.model_validate(item.payload)
        persisted[event.event_id] = event

    def mark(event_id: UUID, status: str) -> CandidateEventV1:
        persisted[event_id] = persisted[event_id].model_copy(
            update={"evidence_status": status}
        )
        return persisted[event_id]

    ring = _Ring(ready=False)
    first, _, _, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        engine=EventEngine(
            module_rules=(_module_rule(votes_required=1, sample_count=1),),
            limits=EngineLimits(max_pending_events=2),
        ),
    )

    def crash_before_seed_promotion(**_: object) -> object:
        raise SystemExit("reservation exists before seed promotion")

    monkeypatch.setattr(
        journal,
        "reserve_pending_evidence_work",
        crash_before_seed_promotion,
    )
    for seq, track_id in ((1, "terminal-seed"), (2, "recoverable-seed")):
        with pytest.raises(SystemExit, match="reservation exists"):
            first.process(
                _observation(
                    seq=seq,
                    seconds=float(seq - 1),
                    track_id=track_id,
                )
            )

    seed_records = journal.pending_evidence_work_items(limit=2)
    terminal_event_id = UUID(seed_records[0].event_id)
    recoverable_event_id = UUID(seed_records[1].event_id)
    terminal_reservation_id = seed_records[0].reservation_id
    persisted[terminal_event_id] = persisted[terminal_event_id].model_copy(
        update={"evidence_status": terminal_status}
    )
    journal.close()

    restarted_journal = SQLiteWALJournal(journal_path, max_items=4)
    restarted_engine = EventEngine(
        module_rules=(_module_rule(votes_required=1, sample_count=1),),
        limits=EngineLimits(max_pending_events=1),
    )
    restarted_engine.ingest(
        _observation(
            seq=3,
            seconds=2,
            class_name="background",
            confidence=0.1,
        )
    )

    class ReadyCoordinator(_Coordinator):
        def complete(self, reservation: object, evidence: object) -> object:
            result = super().complete(reservation, evidence)
            assert isinstance(evidence, EvidenceIntent)
            mark(evidence.event_id, "ready")
            return result

    restarted, _, _, _ = _service(
        tmp_path,
        journal=restarted_journal,
        processor=persist,
        load_candidate=lambda event_id: persisted[event_id],
        mark_evidence_pending=lambda event_id: mark(event_id, "pending"),
        mark_evidence_failed=lambda event_id: mark(event_id, "failed"),
        ring=ring,
        coordinator=ReadyCoordinator(),
        engine=restarted_engine,
    )

    started = restarted.start()

    assert persisted[terminal_event_id].evidence_status == terminal_status
    assert terminal_reservation_id in ring.released
    assert persisted[recoverable_event_id].evidence_status == "pending"
    assert started.pending_evidence_memory_work == 1
    assert restarted_journal.pending_evidence_work_depth() == 1
    assert restarted.start().pending_evidence_memory_work == 1
    ring.ready = True
    completed = restarted.run_periodic(
        camera_id="cam-01",
        stream_epoch=EPOCH_A,
        source_time=NOW + timedelta(seconds=3),
    )

    assert len(completed.durable_candidates) == 1
    assert persisted[recoverable_event_id].evidence_status == "ready"
    assert completed.status.pending_evidence_memory_work == 0
    assert restarted_journal.pending_evidence_work_depth() == 0
