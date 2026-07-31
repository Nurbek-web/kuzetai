from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest

from protector.pilot.runtime.event_worker import (
    EventProcessingError,
    EventProcessingWorker,
)
from protector.pilot.runtime.supervisor import CameraSupervisor

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
EPOCH = UUID("10000000-0000-0000-0000-000000000001")


@dataclass(frozen=True)
class _Observation:
    camera_id: str
    stream_epoch: UUID
    source_time: datetime


class _Source:
    def __init__(self, observations: tuple[_Observation, ...] = ()) -> None:
        self.items = deque(observations)
        self.lock = threading.Lock()
        self.drain_bounds: list[int] = []

    def append(self, observation: _Observation) -> None:
        with self.lock:
            self.items.append(observation)

    def drain_observations(self, *, max_items: int) -> list[_Observation]:
        self.drain_bounds.append(max_items)
        with self.lock:
            return [
                self.items.popleft()
                for _ in range(min(max_items, len(self.items)))
            ]


class _Service:
    def __init__(self, *, fail_after: int | None = None) -> None:
        self.started = 0
        self.processed: list[_Observation] = []
        self.periodic: list[_Observation] = []
        self.thread_ids: list[int] = []
        self.processed_signal = threading.Event()
        self.periodic_signal = threading.Event()
        self.fail_after = fail_after

    def start(self) -> object:
        self.started += 1
        return object()

    def process(self, observation: _Observation) -> object:
        if self.fail_after is not None and len(self.processed) >= self.fail_after:
            raise RuntimeError("database secret must never escape")
        self.processed.append(observation)
        self.thread_ids.append(threading.get_ident())
        self.processed_signal.set()
        return object()

    def run_periodic(
        self,
        *,
        camera_id: str,
        stream_epoch: UUID,
        source_time: datetime,
    ) -> object:
        self.periodic.append(
            _Observation(camera_id, stream_epoch, source_time)
        )
        self.periodic_signal.set()
        return object()


def _observation(camera_id: str = "camera-01") -> _Observation:
    return _Observation(camera_id, EPOCH, NOW)


def test_worker_processes_finite_batches_off_the_caller_thread() -> None:
    source = _Source((_observation(),))
    service = _Service()
    caller_thread = threading.get_ident()
    worker = EventProcessingWorker(
        source=source,
        service=service,
        batch_size=2,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=2,
    )

    worker.start()
    assert worker.thread_alive is True
    assert service.processed_signal.wait(timeout=1.0)
    worker.stop()
    assert worker.thread_alive is False

    assert service.started == 1
    assert service.processed == [_observation()]
    assert service.periodic == [_observation()]
    assert service.thread_ids != [caller_thread]
    assert source.drain_bounds
    assert set(source.drain_bounds) == {2}
    assert worker.status.failed is False
    assert worker.status.processed_observations == 1


def test_worker_failure_is_redacted_observable_and_stops_processing() -> None:
    source = _Source((_observation("camera-01"), _observation("camera-02")))
    service = _Service(fail_after=1)
    worker = EventProcessingWorker(
        source=source,
        service=service,
        batch_size=2,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
    )

    worker.start()
    assert worker.wait_failed(timeout=1.0)
    worker.stop()

    assert worker.status.failed is True
    assert worker.status.failure_reason == "event_processing_failed"
    assert "secret" not in worker.status.failure_reason
    assert worker.status.processed_observations == 1


def test_candidate_journal_full_fails_closed_with_bounded_service_status() -> None:
    class JournalFullService(_Service):
        def process(self, observation: _Observation) -> object:
            super().process(observation)
            return {
                "degraded": True,
                "reasons": ("candidate_journal_full",),
                "journal_depth": 128,
            }

    source = _Source((_observation(), _observation("camera-02")))
    service = JournalFullService()
    worker = EventProcessingWorker(
        source=source,
        service=service,
        batch_size=2,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
    )

    worker.start()
    assert worker.wait_failed(timeout=1.0)
    worker.stop()

    status = worker.status
    assert status.failed is True
    assert status.failure_reason == "candidate_journal_full"
    assert status.service_degraded is True
    assert status.service_reasons == ("candidate_journal_full",)
    assert status.journal_depth == 128
    assert status.processed_observations == 0
    assert service.processed == [_observation()]


class _CursorSource(_Source):
    def __init__(self) -> None:
        super().__init__()
        self.cursor = _observation()

    def event_cursors(self) -> tuple[_Observation, ...]:
        return (self.cursor,)


def test_candidate_journal_write_failure_from_periodic_fails_closed() -> None:
    class JournalWriteFailureService(_Service):
        def run_periodic(
            self,
            *,
            camera_id: str,
            stream_epoch: UUID,
            source_time: datetime,
        ) -> object:
            super().run_periodic(
                camera_id=camera_id,
                stream_epoch=stream_epoch,
                source_time=source_time,
            )
            return SimpleNamespace(
                status=SimpleNamespace(
                    degraded=True,
                    reasons=("candidate_journal_write_failed",),
                    journal_depth=-1,
                )
            )

    worker = EventProcessingWorker(
        source=_CursorSource(),
        service=JournalWriteFailureService(),
        batch_size=1,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
    )

    worker.start()
    assert worker.wait_failed(timeout=1.0)
    worker.stop()

    status = worker.status
    assert status.failed is True
    assert status.failure_reason == "candidate_journal_write_failed"
    assert status.service_reasons == ("candidate_journal_write_failed",)
    assert status.journal_depth == -1


def test_candidate_journal_failure_at_startup_prevents_worker_thread() -> None:
    class StartupJournalFailureService(_Service):
        def start(self) -> object:
            super().start()
            return SimpleNamespace(
                degraded=True,
                reasons=("candidate_journal_full",),
                journal_depth=128,
            )

    worker = EventProcessingWorker(
        source=_Source(),
        service=StartupJournalFailureService(),
        batch_size=1,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
    )

    with pytest.raises(EventProcessingError, match="startup failed"):
        worker.start()

    assert worker.thread_alive is False
    assert worker.status.failed is True
    assert worker.status.failure_reason == "candidate_journal_full"


def test_untrusted_service_status_is_bounded_and_redacted() -> None:
    class InvalidStatusService(_Service):
        def process(self, observation: _Observation) -> object:
            super().process(observation)
            return SimpleNamespace(
                status=SimpleNamespace(
                    degraded=True,
                    reasons=("database-password-secret",),
                    journal_depth=2**63,
                )
            )

    worker = EventProcessingWorker(
        source=_Source((_observation(),)),
        service=InvalidStatusService(),
        batch_size=1,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
    )

    worker.start()
    assert worker.wait_failed(timeout=1.0)
    worker.stop()

    status = worker.status
    assert status.failed is True
    assert status.failure_reason == "event_processing_failed"
    assert "secret" not in status.failure_reason
    assert status.service_reasons == ()
    assert status.journal_depth is None


def test_worker_advances_latest_frame_cursor_without_inventing_observations() -> None:
    source = _CursorSource()
    service = _Service()
    worker = EventProcessingWorker(
        source=source,
        service=service,
        batch_size=2,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
        cursor_limit=2,
    )

    worker.start()
    assert service.periodic_signal.wait(timeout=1.0)
    worker.stop()

    assert service.processed == []
    assert service.periodic == [_observation()]
    assert worker.status.processed_observations == 0


def test_worker_waits_for_completed_frame_before_advancing_its_cursor() -> None:
    source = CameraSupervisor(
        camera_ids=("camera-01",),
        observation_queue_size=2,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: NOW,
    )
    service = _Service()
    worker = EventProcessingWorker(
        source=source,
        service=service,
        batch_size=1,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
    )

    assert source.record_frame(
        camera_id="camera-01",
        source_time=NOW,
        monotonic_seq=1,
    )
    worker._process_one_batch()

    assert service.periodic == []

    assert source.complete_frame(
        camera_id="camera-01",
        source_time=NOW,
        monotonic_seq=1,
    )
    worker._process_one_batch()

    assert len(service.periodic) == 1
    assert service.periodic[0].camera_id == "camera-01"
    assert service.periodic[0].source_time == NOW


def test_worker_cursor_never_overtakes_a_same_frame_backlog() -> None:
    source = CameraSupervisor(
        camera_ids=("camera-01",),
        observation_queue_size=128,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: NOW,
    )
    assert source.record_frame(
        camera_id="camera-01",
        source_time=NOW,
        monotonic_seq=1,
    )
    for sequence in range(128):
        assert source.accept_sample(
            camera_id="camera-01",
            source_time=NOW,
            monotonic_seq=sequence,
            track_id=f"track-{sequence}",
            complete_event_frame=False,
        )
    assert source.complete_frame(
        camera_id="camera-01",
        source_time=NOW,
        monotonic_seq=1,
    )
    service = _Service()
    worker = EventProcessingWorker(
        source=source,
        service=service,
        batch_size=64,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
    )

    assert worker._process_one_batch() is True

    assert len(service.processed) == 64
    assert service.periodic == []

    assert worker._process_one_batch() is True

    assert len(service.processed) == 128
    assert len(service.periodic) == 1
    assert service.periodic[0].camera_id == "camera-01"
    assert service.periodic[0].source_time == NOW


class _NeverEmptySource:
    def __init__(self) -> None:
        self.calls = 0
        self.active = False
        self.first_drain = threading.Event()

    def drain_observations(self, *, max_items: int) -> list[_Observation]:
        self.calls += 1
        self.first_drain.set()
        if not self.active:
            return []
        return [_observation()] * max_items


def test_shutdown_drain_is_finite_even_if_source_contract_is_broken() -> None:
    source = _NeverEmptySource()
    service = _Service()
    worker = EventProcessingWorker(
        source=source,
        service=service,
        batch_size=2,
        poll_interval_seconds=60.0,
        shutdown_drain_batches=3,
    )

    worker.start()
    assert source.first_drain.wait(timeout=1.0)
    source.active = True
    worker.stop()

    assert source.calls <= 4
    assert worker.status.shutdown_drain_exhausted is True


class _BlockingSource:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def drain_observations(self, *, max_items: int) -> list[_Observation]:
        assert max_items == 1
        self.entered.set()
        self.release.wait(timeout=2.0)
        return []


def test_stop_timeout_fails_closed_before_runtime_teardown() -> None:
    source = _BlockingSource()
    worker = EventProcessingWorker(
        source=source,
        service=_Service(),
        batch_size=1,
        poll_interval_seconds=0.01,
        shutdown_drain_batches=1,
        join_timeout_seconds=0.01,
    )

    worker.start()
    assert source.entered.wait(timeout=1.0)
    with pytest.raises(EventProcessingError, match="did not stop"):
        worker.stop()

    assert worker.status.failed is True
    assert worker.status.failure_reason == "event_worker_stop_timeout"
    source.release.set()
    worker.stop()


@pytest.mark.parametrize(
    ("batch_size", "poll_interval", "drain_batches", "join_timeout"),
    (
        (0, 0.1, 1, 5.0),
        (1, 0.0, 1, 5.0),
        (1, 0.1, 0, 5.0),
        (True, 0.1, 1, 5.0),
        (1, True, 1, 5.0),
        (1, 0.1, 1, True),
    ),
)
def test_worker_rejects_unbounded_or_invalid_limits(
    batch_size: object,
    poll_interval: float,
    drain_batches: int,
    join_timeout: float,
) -> None:
    with pytest.raises(ValueError):
        EventProcessingWorker(
            source=_Source(),
            service=_Service(),
            batch_size=batch_size,  # type: ignore[arg-type]
            poll_interval_seconds=poll_interval,
            shutdown_drain_batches=drain_batches,
            join_timeout_seconds=join_timeout,
        )
