from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

from protector.pilot.domain import ObservationV1
from protector.pilot.runtime.event_engine import (
    DebounceSpec,
    EngineLimits,
    EventEngine,
    EvidencePolicy,
    ModuleRule,
    SiteEventService,
)
from protector.pilot.storage.journal import (
    EvidenceJournalReplayWorker,
    SQLiteWALJournal,
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
        model_artifact_id=f"{module}-v1",
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


class _Ring:
    def __init__(self, *, ready: bool = True) -> None:
        self.ready = ready
        self.calls: list[dict[str, object]] = []
        self.released: list[str] = []

    def reserve(self, **kwargs: object) -> SimpleNamespace:
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
    def __init__(self) -> None:
        self.preview_calls: list[tuple[object, object]] = []
        self.complete_calls: list[tuple[object, object]] = []

    def create_preview(self, reservation: object, *, evidence: object) -> SimpleNamespace:
        self.preview_calls.append((reservation, evidence))
        return SimpleNamespace(path="preview.mp4")

    def complete(self, reservation: object, evidence: object) -> object:
        self.complete_calls.append((reservation, evidence))
        return replace(evidence, status="ready")


def _service(
    tmp_path: Path,
    *,
    journal: SQLiteWALJournal,
    processor: object,
    candidate_is_persisted: object,
    ring: _Ring | None = None,
    coordinator: _Coordinator | None = None,
    batch_size: int = 10,
) -> tuple[SiteEventService, _Ring, _Coordinator, EvidenceJournalReplayWorker]:
    replay = EvidenceJournalReplayWorker(
        journal=journal,
        processor=processor,
        batch_size=batch_size,
        retry_backoff_seconds=1,
    )
    selected_ring = ring or _Ring()
    selected_coordinator = coordinator or _Coordinator()
    service = SiteEventService(
        engine=EventEngine(module_rules=(_module_rule(votes_required=1, sample_count=1),)),
        journal=journal,
        replay_worker=replay,
        ring=selected_ring,
        evidence_coordinator=selected_coordinator,
        candidate_is_persisted=candidate_is_persisted,
        evidence_policy=EvidencePolicy(
            pre_roll_seconds=2,
            post_roll_seconds=2,
            source_references={"cam-01": "nvr://cam-01"},
        ),
    )
    return service, selected_ring, selected_coordinator, replay


def test_service_journals_candidate_then_associates_pending_evidence_before_completion(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "events.sqlite3", max_items=10)
    replayed: list[object] = []

    def persist(item: object) -> None:
        replayed.append(item)

    service, ring, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=persist,
        candidate_is_persisted=lambda event_id: any(
            item.kind == "candidate_event" and item.payload["event_id"] == str(event_id)
            for item in replayed
        ),
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert [item.kind for item in replayed] == ["candidate_event"]
    assert journal.depth() == 0
    assert ring.calls[0]["stream_epoch"] == str(EPOCH_A)
    assert len(result.durable_candidates) == 1
    pending = result.durable_candidates[0].pending_evidence
    assert pending is not None
    assert pending.status == "pending"
    assert coordinator.preview_calls[0][1] == pending
    assert coordinator.complete_calls[0][1] == pending
    assert result.durable_candidates[0].evidence.status == "ready"
    assert result.status.degraded is False


def test_evidence_journal_overflow_is_visible_and_releases_the_pin(tmp_path: Path) -> None:
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
        candidate_is_persisted=lambda event_id: False,
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert result.status.degraded is True
    assert "candidate_journal_full" in result.status.reasons
    assert journal.depth() == 1
    assert result.durable_candidates == ()
    assert len(ring.released) == 1
    assert coordinator.preview_calls == []


def test_reservation_failure_freezes_candidate_as_evidence_unavailable(
    tmp_path: Path,
) -> None:
    journal = SQLiteWALJournal(tmp_path / "unavailable.sqlite3", max_items=10)
    replayed: list[object] = []
    ring = _UnavailableRing()
    service, _, coordinator, _ = _service(
        tmp_path,
        journal=journal,
        processor=lambda item: replayed.append(item),
        candidate_is_persisted=lambda event_id: True,
        ring=ring,
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert [item.kind for item in replayed] == ["candidate_event"]
    assert replayed[0].payload["evidence_status"] == "unavailable"
    assert result.durable_candidates[0].trigger.event.evidence_status == "unavailable"
    assert result.durable_candidates[0].pending_evidence is None
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
        candidate_is_persisted=lambda _event_id: True,
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
        candidate_is_persisted=lambda event_id: False,
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
        candidate_is_persisted=lambda event_id: False,
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
        candidate_is_persisted=lambda event_id: False,
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
        candidate_is_persisted=check_failed,
    )

    result = service.process(_observation(seq=1, seconds=0))

    assert result.durable_candidates == ()
    assert "candidate_persistence_check_failed" in result.status.reasons
    assert "candidate_persistence_pending" in result.status.reasons
    assert len(ring.released) == 1
    assert coordinator.preview_calls == []
