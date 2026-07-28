from __future__ import annotations

from datetime import UTC, datetime, timedelta

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
