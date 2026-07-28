"""Deterministic shared multistream replay adapter for non-NVIDIA environments."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from protector.pilot.config import SiteConfig
from protector.pilot.domain import ObservationV1, SampleKind, TimestampQuality
from protector.pilot.runtime.supervisor import CameraHealth, CameraSupervisor

Clock = Callable[[], float]
WallClock = Callable[[], datetime]
FixtureKind = Literal["sample", "disconnect", "recover", "drop", "malformed_timestamp"]


@dataclass(frozen=True, slots=True)
class ReplayFixture:
    """One scheduled replay input; constructors make failure injection explicit."""

    camera_id: str
    at_seconds: float
    kind: FixtureKind
    source_time: datetime | None = None
    seq: int | None = None
    timestamp_quality: TimestampQuality = "camera_rtcp"
    sample_kind: SampleKind = "fresh"
    module: str = "person"
    class_name: str = "person"
    confidence: float = 0.9
    bbox: tuple[float, float, float, float] = (0.1, 0.1, 0.9, 0.9)
    track_id: str | None = "fake-track"
    model_artifact_id: str = "fake-person-v1"

    @classmethod
    def sample(
        cls,
        camera_id: str,
        *,
        at_seconds: float,
        source_time: datetime,
        seq: int,
        sample_kind: SampleKind = "fresh",
    ) -> ReplayFixture:
        return cls(
            camera_id=camera_id,
            at_seconds=at_seconds,
            kind="sample",
            source_time=source_time,
            seq=seq,
            sample_kind=sample_kind,
        )

    @classmethod
    def disconnect(cls, camera_id: str, *, at_seconds: float) -> ReplayFixture:
        return cls(camera_id=camera_id, at_seconds=at_seconds, kind="disconnect")

    @classmethod
    def recover(cls, camera_id: str, *, at_seconds: float) -> ReplayFixture:
        return cls(camera_id=camera_id, at_seconds=at_seconds, kind="recover")

    @classmethod
    def drop(cls, camera_id: str, *, at_seconds: float) -> ReplayFixture:
        return cls(camera_id=camera_id, at_seconds=at_seconds, kind="drop")

    @classmethod
    def malformed_timestamp(cls, camera_id: str, *, at_seconds: float) -> ReplayFixture:
        return cls(camera_id=camera_id, at_seconds=at_seconds, kind="malformed_timestamp")


class FakeDataPlane:
    """One deterministic scheduler that drives all configured cameras without threads."""

    def __init__(
        self,
        *,
        fixtures: Iterable[ReplayFixture],
        monotonic_clock: Clock,
        wall_clock: WallClock,
        stale_after_seconds: float = 5.0,
        reconnect_initial_seconds: float = 1.0,
        reconnect_max_seconds: float = 30.0,
    ) -> None:
        self._fixtures = tuple(sorted(fixtures, key=lambda item: item.at_seconds))
        self._monotonic = monotonic_clock
        self._wall = wall_clock
        self._stale_after_seconds = stale_after_seconds
        self._reconnect_initial_seconds = reconnect_initial_seconds
        self._reconnect_max_seconds = reconnect_max_seconds
        self._supervisor: CameraSupervisor | None = None
        self._next_fixture = 0
        self._started_at: float | None = None
        self._stopped = False

    def start(self, site: SiteConfig) -> None:
        if self._supervisor is not None and not self._stopped:
            raise RuntimeError("fake data plane is already running")
        self._supervisor = CameraSupervisor(
            camera_ids=tuple(feed.camera_id for feed in site.ready_to_start.feeds),
            observation_queue_size=site.queues.analytics,
            monotonic_clock=self._monotonic,
            wall_clock=self._wall,
            stale_after_seconds=self._stale_after_seconds,
            reconnect_initial_seconds=self._reconnect_initial_seconds,
            reconnect_max_seconds=self._reconnect_max_seconds,
        )
        self._next_fixture = 0
        self._started_at = self._monotonic()
        self._stopped = False

    def _require_running(self) -> CameraSupervisor:
        if self._supervisor is None or self._started_at is None or self._stopped:
            raise RuntimeError("fake data plane is not running")
        return self._supervisor

    def run_ready(self) -> None:
        supervisor = self._require_running()
        supervisor.advance()
        elapsed = self._monotonic() - self._started_at
        while self._next_fixture < len(self._fixtures):
            fixture = self._fixtures[self._next_fixture]
            if fixture.at_seconds > elapsed:
                break
            self._next_fixture += 1
            if fixture.kind == "disconnect":
                supervisor.disconnect(fixture.camera_id)
            elif fixture.kind == "recover":
                supervisor.recover(fixture.camera_id)
            elif fixture.kind == "drop":
                supervisor.record_scheduled_drop(fixture.camera_id, "fixture_drop")
            elif fixture.kind == "malformed_timestamp":
                supervisor.reject_malformed_timestamp(fixture.camera_id)
            else:
                assert fixture.source_time is not None
                assert fixture.seq is not None
                supervisor.accept_sample(
                    camera_id=fixture.camera_id,
                    source_time=fixture.source_time,
                    monotonic_seq=fixture.seq,
                    timestamp_quality=fixture.timestamp_quality,
                    module=fixture.module,
                    class_name=fixture.class_name,
                    confidence=fixture.confidence,
                    bbox=fixture.bbox,
                    track_id=fixture.track_id,
                    model_artifact_id=fixture.model_artifact_id,
                    sample_kind=fixture.sample_kind,
                )

    def drain_observations(self) -> list[ObservationV1]:
        if self._supervisor is None:
            return []
        return self._supervisor.drain_observations()

    def health(self) -> list[CameraHealth]:
        return [] if self._supervisor is None else self._supervisor.health()

    def stop(self) -> None:
        if self._supervisor is None or self._stopped:
            return
        self._supervisor.clear_observations()
        self._stopped = True
