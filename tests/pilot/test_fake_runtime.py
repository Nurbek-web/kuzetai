from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from protector.pilot.config import (
    CameraFeed,
    EvidenceRetention,
    KazakhstanStorage,
    QueueLimits,
    ReadyToStart,
    Resolution,
    SecretReference,
    SiteConfig,
)
from protector.pilot.runtime.fake import FakeDataPlane, ReplayFixture


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


def _site() -> SiteConfig:
    feeds = tuple(
        CameraFeed(
            camera_id=f"camera-{number:02d}",
            rtsp_url=SecretReference(environment=f"PILOT_CAMERA_{number:02d}_RTSP"),
            codec="h264",
            resolution=Resolution(width=1920, height=1080),
            bitrate_kbps=2048,
            analytics_hz={"person": 5.0},
        )
        for number in range(1, 21)
    )
    return SiteConfig(
        ready_to_start=ReadyToStart(
            feeds=feeds,
            ntp_source="ntp.example.test",
            camera_map="camera-map-v1",
            site_access="approved",
            compute="m2-replay",
            notification_channel="disabled",
            model_rights_decisions="shadow-only",
        ),
        storage=KazakhstanStorage(
            country_code="KZ",
            endpoint="https://objects.example.test",
            bucket="pilot-evidence",
            retention=EvidenceRetention(
                continuous_video_owner="customer_nvr",
                continuous_video_storage_enabled=False,
                encoded_ring_buffer_seconds=15,
                evidence_retention_days=30,
                metadata_retention_days=90,
            ),
        ),
        queues=QueueLimits(decode=2, analytics=2, verifier=2, events=2),
    )


def test_fake_runtime_replays_shared_fixtures_and_publishes_versioned_observations() -> None:
    clocks = Clocks()
    runtime = FakeDataPlane(
        fixtures=(
            ReplayFixture.sample("camera-01", at_seconds=0.0, source_time=clocks.wall(), seq=0),
            ReplayFixture.sample(
                "camera-02",
                at_seconds=1.0,
                source_time=clocks.wall() + timedelta(seconds=1),
                seq=0,
            ),
        ),
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
    )

    runtime.start(_site())
    runtime.run_ready()
    clocks.advance(1.0)
    runtime.run_ready()
    observations = runtime.drain_observations()

    assert [item.camera_id for item in observations] == ["camera-01", "camera-02"]
    assert all(item.schema_version == "observation.v1" for item in observations)
    assert all(item.sample_kind == "fresh" for item in observations)
    assert all(item.runtime_state == "online" for item in observations)
    assert observations[0].stream_epoch == UUID(observations[0].stream_epoch.hex)
    assert all(item.model_artifact_id == "fake-person-v1" for item in observations)


def test_fake_runtime_injects_bad_inputs_and_camera_failure_without_cross_camera_leakage() -> None:
    clocks = Clocks()
    source_time = clocks.wall()
    runtime = FakeDataPlane(
        fixtures=(
            ReplayFixture.sample("camera-01", at_seconds=0.0, source_time=source_time, seq=0),
            ReplayFixture.sample("camera-02", at_seconds=0.0, source_time=source_time, seq=0),
            ReplayFixture.disconnect("camera-01", at_seconds=1.0),
            ReplayFixture.malformed_timestamp("camera-01", at_seconds=2.0),
            ReplayFixture.sample(
                "camera-02",
                at_seconds=2.0,
                source_time=source_time + timedelta(seconds=2),
                seq=1,
            ),
            ReplayFixture.sample(
                "camera-01",
                at_seconds=3.0,
                source_time=source_time - timedelta(seconds=1),
                seq=0,
            ),
            ReplayFixture.drop("camera-02", at_seconds=3.0),
            ReplayFixture.recover("camera-01", at_seconds=4.0),
        ),
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
        reconnect_initial_seconds=1.0,
    )

    runtime.start(_site())
    for _ in range(5):
        runtime.run_ready()
        clocks.advance(1.0)
    observations = runtime.drain_observations()
    health = {item.camera_id: item for item in runtime.health()}

    assert [item.camera_id for item in observations] == ["camera-01", "camera-02", "camera-02", "camera-01"]
    assert health["camera-01"].tracker_generation == 1
    assert health["camera-01"].state == "online"
    assert health["camera-01"].reconnect_count == 1
    assert health["camera-01"].dropped_samples == 1
    assert health["camera-02"].state == "online"
    assert health["camera-02"].last_monotonic_seq == 1
    assert health["camera-02"].dropped_samples == 1


def test_fake_runtime_rejects_stale_and_cached_display_samples_and_preserves_final_health_after_stop() -> None:
    clocks = Clocks()
    runtime = FakeDataPlane(
        fixtures=(
            ReplayFixture.sample(
                "camera-01",
                at_seconds=0.0,
                source_time=clocks.wall() - timedelta(seconds=10),
                seq=0,
            ),
            ReplayFixture.sample(
                "camera-02",
                at_seconds=0.0,
                source_time=clocks.wall(),
                seq=0,
                sample_kind="cached_display",
            ),
        ),
        monotonic_clock=clocks.monotonic,
        wall_clock=clocks.wall,
        stale_after_seconds=5.0,
    )

    runtime.start(_site())
    runtime.run_ready()
    runtime.stop()
    final_health = runtime.health()
    runtime.stop()

    assert runtime.drain_observations() == []
    assert {item.camera_id: item.degraded_reason for item in final_health} == {
        "camera-01": "stale_source_time",
        "camera-02": "cached_display_sample",
        **{f"camera-{number:02d}": None for number in range(3, 21)},
    }
    assert [item.state for item in final_health[:2]] == ["degraded", "degraded"]
    assert final_health[0].source_time_skew_seconds == 10.0
