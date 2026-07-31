"""Bounded off-callback observation delivery into the site event service."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from typing import Any, Protocol

_MAX_SERVICE_REASONS = 64
_MAX_SERVICE_REASON_LENGTH = 96
_MAX_JOURNAL_DEPTH = 2**63 - 1
_SERVICE_REASON_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789_"
)
_TERMINAL_SERVICE_REASONS = frozenset(
    {
        "candidate_journal_full",
        "candidate_journal_write_failed",
    }
)


class EventProcessingError(RuntimeError):
    """The event worker failed closed without exposing an underlying secret."""


class ObservationBatchSource(Protocol):
    def drain_observations(self, *, max_items: int) -> list[Any]: ...


class EventService(Protocol):
    def start(self) -> Any: ...

    def process(self, observation: Any) -> Any: ...

    def run_periodic(
        self,
        *,
        camera_id: str,
        stream_epoch: Any,
        source_time: Any,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class EventWorkerStatus:
    running: bool
    failed: bool
    failure_reason: str | None
    processed_observations: int
    shutdown_drain_exhausted: bool
    service_degraded: bool
    service_reasons: tuple[str, ...]
    journal_depth: int | None


class EventProcessingWorker:
    """Consume one globally bounded source queue on a dedicated thread."""

    def __init__(
        self,
        *,
        source: ObservationBatchSource,
        service: EventService,
        batch_size: int,
        poll_interval_seconds: float,
        shutdown_drain_batches: int,
        join_timeout_seconds: float = 5.0,
        cursor_limit: int = 64,
    ) -> None:
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or batch_size <= 0
        ):
            raise ValueError("batch_size must be a positive integer")
        if (
            not isinstance(shutdown_drain_batches, int)
            or isinstance(shutdown_drain_batches, bool)
            or shutdown_drain_batches <= 0
        ):
            raise ValueError(
                "shutdown_drain_batches must be a positive integer"
            )
        if (
            not isinstance(cursor_limit, int)
            or isinstance(cursor_limit, bool)
            or cursor_limit <= 0
        ):
            raise ValueError("cursor_limit must be a positive integer")
        if (
            isinstance(poll_interval_seconds, bool)
            or isinstance(join_timeout_seconds, bool)
            or not math.isfinite(poll_interval_seconds)
            or poll_interval_seconds <= 0
            or not math.isfinite(join_timeout_seconds)
            or join_timeout_seconds <= 0
        ):
            raise ValueError("worker timing limits must be finite and positive")
        self._source = source
        self._service = service
        self._batch_size = batch_size
        self._poll_interval_seconds = poll_interval_seconds
        self._shutdown_drain_batches = shutdown_drain_batches
        self._join_timeout_seconds = join_timeout_seconds
        self._cursor_limit = cursor_limit
        self._periodic_cursors: dict[str, tuple[Any, ...]] = {}
        self._lock = threading.RLock()
        self._stop_requested = threading.Event()
        self._wake = threading.Event()
        self._failed_signal = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
        self._failed = False
        self._failure_reason: str | None = None
        self._processed_observations = 0
        self._shutdown_drain_exhausted = False
        self._service_degraded = False
        self._service_reasons: tuple[str, ...] = ()
        self._journal_depth: int | None = None

    @property
    def status(self) -> EventWorkerStatus:
        with self._lock:
            return EventWorkerStatus(
                running=self._running,
                failed=self._failed,
                failure_reason=self._failure_reason,
                processed_observations=self._processed_observations,
                shutdown_drain_exhausted=self._shutdown_drain_exhausted,
                service_degraded=self._service_degraded,
                service_reasons=self._service_reasons,
                journal_depth=self._journal_depth,
            )

    @property
    def thread_alive(self) -> bool:
        """Report actual thread liveness for safe downstream teardown."""

        with self._lock:
            thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                raise EventProcessingError("event worker already started")
        try:
            self._observe_service_result(self._service.start())
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if not self.status.failed:
                self._mark_failed("event_startup_failed")
            raise EventProcessingError("event worker startup failed") from exc
        thread = threading.Thread(
            target=self._run,
            name="kuzet-event-processing",
            daemon=True,
        )
        with self._lock:
            self._running = True
            self._thread = thread
        try:
            thread.start()
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            self._mark_failed("event_worker_thread_start_failed")
            raise EventProcessingError("event worker thread failed to start") from exc

    def stop(self) -> None:
        with self._lock:
            thread = self._thread
        if thread is None:
            return
        self._stop_requested.set()
        self._wake.set()
        thread.join(timeout=self._join_timeout_seconds)
        if thread.is_alive():
            self._mark_failed("event_worker_stop_timeout")
            raise EventProcessingError("event worker did not stop within its bound")
        with self._lock:
            self._running = False

    def wait_failed(self, *, timeout: float) -> bool:
        if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout < 0:
            raise ValueError("failure wait timeout must be finite and non-negative")
        return self._failed_signal.wait(timeout)

    def _run(self) -> None:
        try:
            while not self._stop_requested.is_set():
                if not self._process_one_batch():
                    self._wake.wait(self._poll_interval_seconds)
                    self._wake.clear()
            exhausted = True
            for _ in range(self._shutdown_drain_batches):
                if not self._process_one_batch():
                    exhausted = False
                    break
            with self._lock:
                self._shutdown_drain_exhausted = exhausted
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                self._mark_failed("event_processing_interrupted")
                return
            if not self.status.failed:
                self._mark_failed("event_processing_failed")
        finally:
            with self._lock:
                self._running = False

    def _process_one_batch(self) -> bool:
        atomic_reader = getattr(self._source, "drain_event_batch", None)
        cursor_reader = getattr(self._source, "event_cursors", None)
        if callable(atomic_reader):
            batch = atomic_reader(max_items=self._batch_size)
            observations = getattr(batch, "observations", None)
            cursors = getattr(batch, "cursors", None)
            settled = getattr(
                batch,
                "settled_observation_sequences",
                None,
            )
            self._validate_atomic_batch(
                observations=observations,
                cursors=cursors,
                settled=settled,
            )
        else:
            observations = self._source.drain_observations(
                max_items=self._batch_size,
            )
            if (
                not isinstance(observations, list)
                or len(observations) > self._batch_size
            ):
                raise EventProcessingError(
                    "observation source violated the finite batch contract"
                )
            cursors = cursor_reader() if callable(cursor_reader) else None
        for observation in observations:
            self._observe_service_result(
                self._service.process(observation)
            )
            if cursors is None:
                self._run_periodic(observation)
            with self._lock:
                self._processed_observations += 1
        if cursors is not None:
            self._process_current_cursors(cursors)
        return bool(observations)

    def _validate_atomic_batch(
        self,
        *,
        observations: Any,
        cursors: Any,
        settled: Any,
    ) -> None:
        if (
            not isinstance(observations, tuple)
            or len(observations) > self._batch_size
            or not isinstance(cursors, tuple)
            or len(cursors) > self._cursor_limit
            or not isinstance(settled, tuple)
            or len(settled) > self._cursor_limit
        ):
            raise EventProcessingError(
                "atomic event source violated its finite batch contract"
            )
        settled_by_camera: dict[str, int] = {}
        for item in settled:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not item[0]
                or item[0] in settled_by_camera
                or not isinstance(item[1], int)
                or isinstance(item[1], bool)
                or item[1] < 0
            ):
                raise EventProcessingError(
                    "atomic event source sequence frontier is invalid"
                )
            settled_by_camera[item[0]] = item[1]
        for cursor in cursors:
            camera_id = getattr(cursor, "camera_id", None)
            sequence = getattr(cursor, "observation_sequence", None)
            if (
                camera_id not in settled_by_camera
                or not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or sequence < 0
                or sequence > settled_by_camera[camera_id]
            ):
                raise EventProcessingError(
                    "event cursor overtook its observation frontier"
                )

    def _process_current_cursors(self, cursors: Any) -> None:
        if not isinstance(cursors, tuple) or len(cursors) > self._cursor_limit:
            raise EventProcessingError(
                "event cursor source violated its finite contract"
            )
        seen: set[str] = set()
        for cursor in cursors:
            camera_id = cursor.camera_id
            if (
                not isinstance(camera_id, str)
                or not camera_id
                or camera_id in seen
            ):
                raise EventProcessingError(
                    "event cursor identity is invalid"
                )
            seen.add(camera_id)
            sequence = getattr(cursor, "observation_sequence", None)
            identity = (
                cursor.stream_epoch,
                cursor.source_time,
                sequence,
            )
            if self._periodic_cursors.get(camera_id) == identity:
                continue
            self._run_periodic(cursor)
            self._periodic_cursors[camera_id] = identity
        for retired in set(self._periodic_cursors).difference(seen):
            del self._periodic_cursors[retired]

    def _run_periodic(self, cursor: Any) -> None:
        self._observe_service_result(
            self._service.run_periodic(
                camera_id=cursor.camera_id,
                stream_epoch=cursor.stream_epoch,
                source_time=cursor.source_time,
            )
        )

    def _observe_service_result(self, result: Any) -> None:
        """Retain bounded service health and stop before silent candidate loss."""

        if type(result) is dict:
            status = result.get("status", result)
            if type(status) is not dict or len(status) > 32:
                raise EventProcessingError(
                    "event service status violated its bounded contract"
                )
            if "degraded" not in status:
                return
            degraded = status.get("degraded")
            reasons = status.get("reasons")
            journal_depth = status.get("journal_depth")
        else:
            try:
                status = getattr(result, "status", result)
                degraded = getattr(status, "degraded")
            except AttributeError:
                return
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise EventProcessingError(
                    "event service status is unavailable"
                ) from exc
            try:
                reasons = getattr(status, "reasons")
                journal_depth = getattr(status, "journal_depth")
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise EventProcessingError(
                    "event service status is incomplete"
                ) from exc
        if (
            type(degraded) is not bool
            or type(reasons) is not tuple
            or len(reasons) > _MAX_SERVICE_REASONS
            or any(
                type(reason) is not str
                or not 1 <= len(reason) <= _MAX_SERVICE_REASON_LENGTH
                or any(
                    character not in _SERVICE_REASON_CHARACTERS
                    for character in reason
                )
                for reason in reasons
            )
            or len(set(reasons)) != len(reasons)
            or type(journal_depth) is not int
            or not -1 <= journal_depth <= _MAX_JOURNAL_DEPTH
            or degraded != bool(reasons)
        ):
            raise EventProcessingError(
                "event service status violated its bounded contract"
            )
        with self._lock:
            self._service_degraded = degraded
            self._service_reasons = reasons
            self._journal_depth = journal_depth
        terminal_reason = next(
            (
                reason
                for reason in reasons
                if reason in _TERMINAL_SERVICE_REASONS
            ),
            None,
        )
        if terminal_reason is not None:
            self._mark_failed(terminal_reason)
            raise EventProcessingError(
                "event service failed closed before candidate loss"
            )

    def _mark_failed(self, reason: str) -> None:
        with self._lock:
            self._failed = True
            self._failure_reason = reason
            self._running = False
        self._failed_signal.set()
        self._stop_requested.set()
        self._wake.set()
