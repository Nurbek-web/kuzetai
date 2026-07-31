from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from protector.pilot.runtime.supervisor import CameraSupervisor


class Clocks:
    def __init__(self) -> None:
        self.monotonic_seconds = 0.0
        self.wall_time = datetime(2026, 7, 28, 9, 0, tzinfo=UTC)

    def monotonic(self) -> float:
        return self.monotonic_seconds

    def wall(self) -> datetime:
        return self.wall_time

    def advance(self, seconds: float) -> None:
        self.monotonic_seconds += seconds
        self.wall_time += timedelta(seconds=seconds)


def _supervisor(clocks: Clocks, *, queue_size: int = 2) -> CameraSupervisor:
    return CameraSupervisor(
        camera_ids=("camera-a", "camera-b"),
        observation_queue_size=queue_size,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
        stale_after_seconds=5.0,
        reconnect_initial_seconds=1.0,
        reconnect_max_seconds=4.0,
    )


def test_supervisor_follows_legal_recovery_states_with_capped_backoff() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)

    supervisor.accept_sample(camera_id="camera-a", source_time=clocks.wall(), monotonic_seq=0)
    assert supervisor.health_for("camera-a").state == "online"

    supervisor.mark_degraded("camera-a", "source timeout")
    supervisor.disconnect("camera-a")
    offline = supervisor.health_for("camera-a")
    assert offline.state == "offline"
    assert offline.reconnect_count == 1
    assert offline.next_reconnect_in_seconds == 1.0

    clocks.advance(1.0)
    supervisor.advance()
    assert supervisor.health_for("camera-a").state == "reconnecting"

    supervisor.disconnect("camera-a")
    clocks.advance(2.0)
    supervisor.advance()
    supervisor.disconnect("camera-a")
    clocks.advance(4.0)
    supervisor.advance()
    assert supervisor.health_for("camera-a").reconnect_backoff_seconds == 4.0

    supervisor.accept_sample(camera_id="camera-a", source_time=clocks.wall(), monotonic_seq=1)
    assert supervisor.health_for("camera-a").state == "online"


def test_runtime_session_seed_makes_initial_epochs_process_unique_and_injectable() -> None:
    clocks = Clocks()
    first = CameraSupervisor(
        camera_ids=("camera-a",),
        observation_queue_size=2,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
        runtime_session_seed=UUID("11111111-1111-1111-1111-111111111111"),
    )
    second = CameraSupervisor(
        camera_ids=("camera-a",),
        observation_queue_size=2,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
        runtime_session_seed=UUID("22222222-2222-2222-2222-222222222222"),
    )

    first_observation = first.accept_sample(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=0,
    )

    assert first.health_for("camera-a").stream_epoch != second.health_for(
        "camera-a"
    ).stream_epoch
    assert first_observation is not None
    assert (
        first_observation.stream_epoch
        == first.health_for("camera-a").stream_epoch
    )


def test_default_runtime_session_seed_never_reuses_a_fresh_process_epoch() -> None:
    clocks = Clocks()
    first = CameraSupervisor(
        camera_ids=("camera-a",),
        observation_queue_size=2,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )
    second = CameraSupervisor(
        camera_ids=("camera-a",),
        observation_queue_size=2,
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )

    assert first.health_for("camera-a").stream_epoch != second.health_for(
        "camera-a"
    ).stream_epoch


def test_explicit_empty_runtime_session_seed_is_rejected() -> None:
    clocks = Clocks()

    with pytest.raises(ValueError, match="runtime_session_seed"):
        CameraSupervisor(
            camera_ids=("camera-a",),
            observation_queue_size=2,
            monotonic_clock=clocks.monotonic,
            wall_clock=clocks.wall,
            runtime_session_seed="",
        )


def test_source_time_regression_starts_an_isolated_epoch_and_resets_sequence() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)
    source_time = clocks.wall()

    first = supervisor.accept_sample(camera_id="camera-a", source_time=source_time, monotonic_seq=8)
    other = supervisor.accept_sample(camera_id="camera-b", source_time=source_time, monotonic_seq=41)
    assert first is not None
    assert other is not None

    clocks.advance(1.0)
    restarted = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=source_time - timedelta(seconds=1),
        monotonic_seq=0,
    )

    assert restarted is not None
    assert restarted.stream_epoch != first.stream_epoch
    assert restarted.monotonic_seq == 0
    assert supervisor.health_for("camera-a").tracker_generation == 1
    assert supervisor.health_for("camera-b").stream_epoch == other.stream_epoch
    assert supervisor.health_for("camera-b").last_monotonic_seq == 41
    assert supervisor.health_for("camera-b").tracker_generation == 0


def test_stale_source_regression_still_resets_only_its_camera_epoch() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)
    source_time = clocks.wall()

    first = supervisor.accept_sample(camera_id="camera-a", source_time=source_time, monotonic_seq=5)
    supervisor.accept_sample(camera_id="camera-b", source_time=source_time, monotonic_seq=3)
    clocks.advance(10.0)
    rejected = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=source_time - timedelta(seconds=1),
        monotonic_seq=0,
    )

    assert first is not None
    assert rejected is None
    assert supervisor.health_for("camera-a").stream_epoch != first.stream_epoch
    assert supervisor.health_for("camera-a").tracker_generation == 1
    assert supervisor.health_for("camera-b").tracker_generation == 0


def test_duplicate_sequence_is_dropped_without_poisoning_later_samples_or_another_camera() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)
    source_time = clocks.wall()

    accepted = supervisor.accept_sample(camera_id="camera-a", source_time=source_time, monotonic_seq=2)
    other = supervisor.accept_sample(camera_id="camera-b", source_time=source_time, monotonic_seq=7)
    duplicate = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=source_time + timedelta(milliseconds=1),
        monotonic_seq=2,
    )
    later = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=source_time + timedelta(milliseconds=2),
        monotonic_seq=3,
    )

    assert accepted is not None
    assert other is not None
    assert duplicate is None
    assert later is not None
    assert supervisor.health_for("camera-a").state == "online"
    assert supervisor.health_for("camera-a").degraded_reason is None
    assert supervisor.health_for("camera-a").last_monotonic_seq == 3
    assert supervisor.health_for("camera-b").state == "online"
    assert supervisor.health_for("camera-b").stream_epoch == other.stream_epoch
    assert supervisor.health_for("camera-b").last_monotonic_seq == 7


def test_explicit_source_recovery_starts_a_new_epoch_before_sequence_restarts() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)
    source_time = clocks.wall()

    original = supervisor.accept_sample(camera_id="camera-a", source_time=source_time, monotonic_seq=12)
    supervisor.disconnect("camera-a")
    clocks.advance(1.0)
    supervisor.advance()
    supervisor.recover("camera-a")
    recovered = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=source_time + timedelta(seconds=1),
        monotonic_seq=0,
    )

    assert original is not None
    assert recovered is not None
    assert recovered.stream_epoch != original.stream_epoch
    assert supervisor.health_for("camera-a").tracker_generation == 1


def test_successful_reconnect_resets_backoff_for_a_later_disconnect() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)
    source_time = clocks.wall()

    supervisor.accept_sample(camera_id="camera-a", source_time=source_time, monotonic_seq=1)
    supervisor.disconnect("camera-a")
    clocks.advance(1.0)
    supervisor.advance()
    supervisor.recover("camera-a")
    supervisor.accept_sample(
        camera_id="camera-a",
        source_time=source_time + timedelta(seconds=1),
        monotonic_seq=0,
    )
    supervisor.disconnect("camera-a")

    health = supervisor.health_for("camera-a")
    assert health.reconnect_backoff_seconds == 1.0
    assert health.next_reconnect_in_seconds == 1.0


def test_health_snapshot_reports_age_skew_queue_and_visible_drop_counts() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks, queue_size=1)
    source_time = clocks.wall() - timedelta(seconds=2)

    supervisor.accept_sample(camera_id="camera-a", source_time=source_time, monotonic_seq=0)
    clocks.advance(3.0)
    supervisor.accept_sample(camera_id="camera-a", source_time=clocks.wall(), monotonic_seq=1)
    supervisor.record_scheduled_drop("camera-a", "fixture_drop")

    health = supervisor.health_for("camera-a")
    assert health.last_frame_age_seconds == 0.0
    assert health.source_time_skew_seconds == 0.0
    assert health.scheduled_samples == 3
    assert health.dropped_samples == 2
    assert health.queue_age_seconds == 0.0
    assert health.degraded_reason == "fixture_drop"
    assert [item.monotonic_seq for item in supervisor.drain_observations()] == [1]


def test_decoded_frame_heartbeat_updates_camera_health_without_inventing_a_person_observation() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)

    accepted = supervisor.record_frame(
        camera_id="camera-a", source_time=clocks.wall(), monotonic_seq=0
    )

    health = supervisor.health_for("camera-a")
    assert accepted is True
    assert health.state == "online"
    assert health.last_frame_age_seconds == 0.0
    assert health.scheduled_samples == 0
    assert health.dropped_samples == 0
    assert supervisor.drain_observations() == []


def test_observation_budget_is_global_and_batch_drains_are_ordered_and_finite() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks, queue_size=2)

    first = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=1,
    )
    second = supervisor.accept_sample(
        camera_id="camera-b",
        source_time=clocks.wall(),
        monotonic_seq=1,
    )
    third = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=clocks.wall() + timedelta(milliseconds=1),
        monotonic_seq=2,
    )

    assert first is not None
    assert second is not None
    assert third is not None
    status = supervisor.observation_queue_status()
    assert status.capacity == 2
    assert status.depth == 2
    assert status.dropped_total == 1
    assert supervisor.health_for("camera-a").dropped_samples == 1

    assert supervisor.drain_observations(max_items=1) == [second]
    assert supervisor.observation_queue_status().depth == 1
    assert supervisor.drain_observations(max_items=1) == [third]
    assert supervisor.drain_observations(max_items=1) == []


@pytest.mark.parametrize("max_items", (0, -1, True))
def test_observation_batch_bound_must_be_a_positive_integer(max_items: object) -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)

    with pytest.raises(ValueError, match="max_items"):
        supervisor.drain_observations(max_items=max_items)  # type: ignore[arg-type]


def test_event_cursors_are_one_per_online_camera_and_keep_source_epochs() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)
    first = supervisor.accept_sample(
        camera_id="camera-b",
        source_time=clocks.wall(),
        monotonic_seq=1,
    )
    assert first is not None
    assert supervisor.drain_observations(max_items=1) == [first]
    clocks.advance(0.5)
    assert supervisor.record_frame(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=1,
    )
    assert supervisor.complete_frame(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=1,
    )

    cursors = supervisor.event_cursors()

    assert [cursor.camera_id for cursor in cursors] == [
        "camera-a",
        "camera-b",
    ]
    assert cursors[0].source_time == clocks.wall()
    assert cursors[1].stream_epoch == first.stream_epoch

    supervisor.disconnect("camera-b")
    assert [cursor.camera_id for cursor in supervisor.event_cursors()] == [
        "camera-a"
    ]


def test_atomic_event_batch_fences_only_the_camera_with_pending_observations() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks, queue_size=2)
    source_time = clocks.wall()
    assert supervisor.record_frame(
        camera_id="camera-a",
        source_time=source_time,
        monotonic_seq=1,
    )
    for sequence in (1, 2):
        assert supervisor.accept_sample(
            camera_id="camera-a",
            source_time=source_time,
            monotonic_seq=sequence,
            complete_event_frame=False,
        )
    assert supervisor.complete_frame(
        camera_id="camera-a",
        source_time=source_time,
        monotonic_seq=1,
    )
    assert supervisor.record_frame(
        camera_id="camera-b",
        source_time=source_time,
        monotonic_seq=1,
    )
    assert supervisor.complete_frame(
        camera_id="camera-b",
        source_time=source_time,
        monotonic_seq=1,
    )

    first = supervisor.drain_event_batch(max_items=1)

    assert len(first.observations) == 1
    assert [cursor.camera_id for cursor in first.cursors] == ["camera-b"]
    assert first.cursors[0].observation_sequence == 0

    second = supervisor.drain_event_batch(max_items=1)

    assert len(second.observations) == 1
    assert [cursor.camera_id for cursor in second.cursors] == [
        "camera-a",
        "camera-b",
    ]
    assert second.cursors[0].observation_sequence == 2


def test_leaky_drop_fences_current_epoch_and_recovery_never_returns_stale_cursor() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks, queue_size=1)
    source_time = clocks.wall()
    assert supervisor.record_frame(
        camera_id="camera-a",
        source_time=source_time,
        monotonic_seq=1,
    )
    assert supervisor.accept_sample(
        camera_id="camera-a",
        source_time=source_time,
        monotonic_seq=1,
        complete_event_frame=False,
    )
    assert supervisor.complete_frame(
        camera_id="camera-a",
        source_time=source_time,
        monotonic_seq=1,
    )
    clocks.advance(1.0)
    assert supervisor.record_frame(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=2,
    )
    assert supervisor.accept_sample(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=2,
        complete_event_frame=False,
    )
    assert supervisor.complete_frame(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=2,
    )

    drained = supervisor.drain_event_batch(max_items=1)

    assert len(drained.observations) == 1
    assert drained.cursors == ()

    supervisor.disconnect("camera-a")
    clocks.advance(1.0)
    supervisor.advance()
    supervisor.recover("camera-a")
    assert supervisor.record_frame(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=3,
    )
    assert supervisor.complete_frame(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=3,
    )

    recovered = supervisor.drain_event_batch(max_items=1)

    assert len(recovered.cursors) == 1
    assert recovered.cursors[0].stream_epoch == supervisor.health_for(
        "camera-a"
    ).stream_epoch
    assert recovered.cursors[0].source_time == clocks.wall()
    assert recovered.cursors[0].observation_sequence == 2


def test_epoch_change_hides_old_safe_cursor_until_new_frontier_is_ordered() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks, queue_size=2)
    first = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=1,
    )
    assert first is not None
    initial = supervisor.drain_event_batch(max_items=1)
    assert [cursor.stream_epoch for cursor in initial.cursors] == [
        first.stream_epoch
    ]

    supervisor.disconnect("camera-a")
    clocks.advance(1.0)
    supervisor.advance()
    supervisor.recover("camera-a")
    assert supervisor.record_frame(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=2,
    )

    assert supervisor.drain_event_batch(max_items=1).cursors == ()

    second = supervisor.accept_sample(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=2,
        complete_event_frame=False,
    )
    assert second is not None
    assert supervisor.complete_frame(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=2,
    )
    recovered = supervisor.drain_event_batch(max_items=1)

    assert len(recovered.cursors) == 1
    assert recovered.cursors[0].stream_epoch == second.stream_epoch
    assert recovered.cursors[0].stream_epoch != first.stream_epoch


def test_recovery_epoch_change_serializes_with_atomic_event_drain() -> None:
    clocks = Clocks()
    supervisor = _supervisor(clocks)
    assert supervisor.accept_sample(
        camera_id="camera-a",
        source_time=clocks.wall(),
        monotonic_seq=1,
    )
    supervisor.disconnect("camera-a")
    entered = threading.Event()
    recovered = threading.Event()

    def recover() -> None:
        entered.set()
        supervisor.recover("camera-a")
        recovered.set()

    with supervisor._queue_lock:
        thread = threading.Thread(target=recover)
        thread.start()
        assert entered.wait(timeout=1.0)
        assert recovered.wait(timeout=0.05) is False
        supervisor.drain_event_batch(max_items=1)

    thread.join(timeout=1.0)

    assert thread.is_alive() is False
    assert recovered.is_set()
    assert supervisor.health_for("camera-a").tracker_generation == 1
