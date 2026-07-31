"""Deterministic, isolated camera health and observation supervision."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from protector.pilot.domain import ObservationV1, RuntimeState, SampleKind, TimestampQuality

Clock = Callable[[], float]
WallClock = Callable[[], datetime]

_TRANSITIONS: dict[RuntimeState, frozenset[RuntimeState]] = {
    "starting": frozenset({"online", "degraded", "offline"}),
    "online": frozenset({"degraded", "offline"}),
    "degraded": frozenset({"offline"}),
    "offline": frozenset({"reconnecting"}),
    "reconnecting": frozenset({"online", "degraded", "offline"}),
}


@dataclass(frozen=True, slots=True)
class CameraHealth:
    """Inspectable per-camera runtime metrics, sampled without mutating state."""

    camera_id: str
    state: RuntimeState
    stream_epoch: UUID
    last_frame_at: datetime | None
    last_frame_age_seconds: float | None
    reconnect_count: int
    reconnect_backoff_seconds: float
    next_reconnect_in_seconds: float | None
    source_time_skew_seconds: float | None
    scheduled_samples: int
    dropped_samples: int
    queue_age_seconds: float | None
    degraded_reason: str | None
    last_monotonic_seq: int | None
    tracker_generation: int


@dataclass(frozen=True, slots=True)
class ObservationQueueStatus:
    """Finite shared observation-buffer state for readiness and telemetry."""

    capacity: int
    depth: int
    dropped_total: int
    oldest_age_seconds: float | None


@dataclass(frozen=True, slots=True)
class EventCursor:
    """Latest source-time cursor used for evidence/post-roll periodic work."""

    camera_id: str
    stream_epoch: UUID
    source_time: datetime
    observation_sequence: int = 0


@dataclass(frozen=True, slots=True)
class EventDrainBatch:
    """One atomic observation batch and only its delivery-safe cursors."""

    observations: tuple[ObservationV1, ...]
    cursors: tuple[EventCursor, ...]
    settled_observation_sequences: tuple[tuple[str, int], ...]


@dataclass(slots=True)
class _CameraState:
    camera_id: str
    state: RuntimeState
    epoch_number: int
    stream_epoch: UUID
    last_source_time: datetime | None = None
    last_frame_at: datetime | None = None
    last_received_monotonic: float | None = None
    last_monotonic_seq: int | None = None
    last_frame_monotonic_seq: int | None = None
    last_source_time_skew_seconds: float | None = None
    reconnect_count: int = 0
    reconnect_backoff_seconds: float = 0.0
    reconnect_at_monotonic: float | None = None
    scheduled_samples: int = 0
    dropped_samples: int = 0
    degraded_reason: str | None = None


class CameraSupervisor:
    """Owns independent camera state and a bounded drop-old observation queue."""

    def __init__(
        self,
        *,
        camera_ids: tuple[str, ...],
        observation_queue_size: int,
        monotonic_clock: Clock,
        wall_clock: WallClock,
        runtime_session_seed: UUID | str | None = None,
        stale_after_seconds: float = 5.0,
        reconnect_initial_seconds: float = 1.0,
        reconnect_max_seconds: float = 30.0,
    ) -> None:
        if not camera_ids or len(set(camera_ids)) != len(camera_ids):
            raise ValueError("camera_ids must be non-empty and unique")
        if observation_queue_size < 1:
            raise ValueError("observation_queue_size must be positive")
        if stale_after_seconds < 0:
            raise ValueError("stale_after_seconds must be non-negative")
        if reconnect_initial_seconds <= 0 or reconnect_max_seconds < reconnect_initial_seconds:
            raise ValueError("invalid reconnect backoff bounds")
        session_seed = str(uuid4() if runtime_session_seed is None else runtime_session_seed)
        if not session_seed or len(session_seed) > 128:
            raise ValueError("runtime_session_seed must be non-empty and bounded")
        self._runtime_session_seed = session_seed
        self._monotonic = monotonic_clock
        self._wall = wall_clock
        self._stale_after_seconds = stale_after_seconds
        self._reconnect_initial_seconds = reconnect_initial_seconds
        self._reconnect_max_seconds = reconnect_max_seconds
        self._queue_size = observation_queue_size
        self._queue: deque[tuple[int, ObservationV1]] = deque()
        self._queue_lock = RLock()
        self._queue_dropped_total = 0
        self._published_sequences = dict.fromkeys(camera_ids, 0)
        self._settled_observation_sequences = dict.fromkeys(camera_ids, 0)
        self._pending_event_cursors: dict[str, deque[EventCursor]] = {
            camera_id: deque() for camera_id in camera_ids
        }
        self._safe_event_cursors: dict[str, EventCursor] = {}
        self._cursor_delivery_fenced: set[str] = set()
        self._states = {
            camera_id: _CameraState(
                camera_id=camera_id,
                state="starting",
                epoch_number=0,
                stream_epoch=self._epoch_for(camera_id, 0),
            )
            for camera_id in camera_ids
        }

    def _epoch_for(self, camera_id: str, epoch_number: int) -> UUID:
        return uuid5(
            NAMESPACE_URL,
            (
                f"kuzet-pilot:{self._runtime_session_seed}:"
                f"{camera_id}:epoch:{epoch_number}"
            ),
        )

    @property
    def runtime_session_id(self) -> str:
        return self._runtime_session_seed

    def _state_for(self, camera_id: str) -> _CameraState:
        try:
            return self._states[camera_id]
        except KeyError as exc:
            raise ValueError(f"unknown camera_id: {camera_id}") from exc

    def _transition(self, state: _CameraState, target: RuntimeState) -> None:
        if target == state.state:
            return
        if target not in _TRANSITIONS[state.state]:
            raise ValueError(f"illegal camera transition: {state.state} -> {target}")
        state.state = target

    def _degrade(self, state: _CameraState, reason: str) -> None:
        if state.state in {"starting", "online", "reconnecting"}:
            self._transition(state, "degraded")
        state.degraded_reason = reason

    def _begin_epoch(self, state: _CameraState) -> None:
        state.epoch_number += 1
        state.stream_epoch = self._epoch_for(state.camera_id, state.epoch_number)
        state.last_monotonic_seq = None
        state.last_frame_monotonic_seq = None
        state.last_source_time = None
        self._safe_event_cursors.pop(state.camera_id, None)
        self._pending_event_cursors[state.camera_id].clear()
        self._cursor_delivery_fenced.discard(state.camera_id)

    def mark_degraded(self, camera_id: str, reason: str) -> None:
        self._degrade(self._state_for(camera_id), reason)

    def disconnect(self, camera_id: str, reason: str = "source_disconnect") -> None:
        state = self._state_for(camera_id)
        if state.state == "starting":
            self._transition(state, "offline")
        elif state.state != "offline":
            if state.state != "degraded":
                self._degrade(state, reason)
            self._transition(state, "offline")
        state.degraded_reason = reason
        state.reconnect_count += 1
        previous = state.reconnect_backoff_seconds
        state.reconnect_backoff_seconds = min(
            self._reconnect_max_seconds,
            self._reconnect_initial_seconds if previous == 0 else previous * 2,
        )
        state.reconnect_at_monotonic = self._monotonic() + state.reconnect_backoff_seconds

    def advance(self) -> None:
        """Advance reconnect states using the injected monotonic clock."""
        now = self._monotonic()
        for state in self._states.values():
            if state.state == "offline" and state.reconnect_at_monotonic is not None:
                if now >= state.reconnect_at_monotonic:
                    self._transition(state, "reconnecting")

    def recover(self, camera_id: str) -> None:
        """Start a new source epoch; its next frame makes the camera online."""
        with self._queue_lock:
            state = self._state_for(camera_id)
            if state.state == "degraded":
                self._transition(state, "offline")
            if state.state == "offline":
                self._transition(state, "reconnecting")
            if state.state == "reconnecting":
                self._begin_epoch(state)

    def record_scheduled_drop(self, camera_id: str, reason: str) -> None:
        state = self._state_for(camera_id)
        state.scheduled_samples += 1
        state.dropped_samples += 1
        state.degraded_reason = reason

    def record_frame(
        self,
        *,
        camera_id: str,
        source_time: datetime,
        monotonic_seq: int,
    ) -> bool:
        with self._queue_lock:
            return self._record_frame_locked(
                camera_id=camera_id,
                source_time=source_time,
                monotonic_seq=monotonic_seq,
            )

    def _record_frame_locked(
        self,
        *,
        camera_id: str,
        source_time: datetime,
        monotonic_seq: int,
    ) -> bool:
        """Record a decoded-frame heartbeat without creating a synthetic detection."""
        state = self._state_for(camera_id)
        now = self._wall()
        if source_time.tzinfo is None or source_time.utcoffset() is None:
            self._degrade(state, "malformed_source_time")
            return False
        source_time = source_time.astimezone(now.tzinfo)
        state.last_source_time_skew_seconds = abs((now - source_time).total_seconds())
        source_restarted = state.last_source_time is not None and source_time < state.last_source_time
        if source_restarted:
            self._begin_epoch(state)
            if state.state == "degraded":
                self._transition(state, "offline")
                self._transition(state, "reconnecting")
            elif state.state == "offline":
                self._transition(state, "reconnecting")
        if (now - source_time).total_seconds() > self._stale_after_seconds:
            self._degrade(state, "stale_source_time")
            return False
        if (
            state.last_frame_monotonic_seq is not None
            and monotonic_seq <= state.last_frame_monotonic_seq
        ):
            state.degraded_reason = "non_increasing_frame_sequence"
            return False
        reconnected = state.state == "reconnecting"
        if state.state == "starting":
            self._transition(state, "online")
        elif state.state == "reconnecting":
            self._transition(state, "online")
        elif state.state in {"degraded", "offline"}:
            return False
        state.last_source_time = source_time
        state.last_frame_at = now
        state.last_received_monotonic = self._monotonic()
        state.last_frame_monotonic_seq = monotonic_seq
        if reconnected:
            state.reconnect_backoff_seconds = 0.0
            state.reconnect_at_monotonic = None
        state.degraded_reason = None
        return True

    def reject_malformed_timestamp(self, camera_id: str) -> None:
        state = self._state_for(camera_id)
        state.scheduled_samples += 1
        state.dropped_samples += 1
        self._degrade(state, "malformed_source_time")

    def accept_sample(
        self,
        *,
        camera_id: str,
        source_time: datetime,
        monotonic_seq: int,
        timestamp_quality: TimestampQuality = "camera_rtcp",
        module: str = "person",
        class_name: str = "person",
        confidence: float = 0.9,
        bbox: tuple[float, float, float, float] = (0.1, 0.1, 0.9, 0.9),
        track_id: str | None = "fake-track",
        model_artifact_id: str = "fake-person-v1",
        sample_kind: SampleKind = "fresh",
        complete_event_frame: bool = True,
    ) -> ObservationV1 | None:
        if type(complete_event_frame) is not bool:
            raise TypeError("complete_event_frame must be a boolean")
        with self._queue_lock:
            return self._accept_sample_locked(
                camera_id=camera_id,
                source_time=source_time,
                monotonic_seq=monotonic_seq,
                timestamp_quality=timestamp_quality,
                module=module,
                class_name=class_name,
                confidence=confidence,
                bbox=bbox,
                track_id=track_id,
                model_artifact_id=model_artifact_id,
                sample_kind=sample_kind,
                complete_event_frame=complete_event_frame,
            )

    def _accept_sample_locked(
        self,
        *,
        camera_id: str,
        source_time: datetime,
        monotonic_seq: int,
        timestamp_quality: TimestampQuality,
        module: str,
        class_name: str,
        confidence: float,
        bbox: tuple[float, float, float, float],
        track_id: str | None,
        model_artifact_id: str,
        sample_kind: SampleKind,
        complete_event_frame: bool,
    ) -> ObservationV1 | None:
        state = self._state_for(camera_id)
        state.scheduled_samples += 1
        now = self._wall()
        if source_time.tzinfo is None or source_time.utcoffset() is None:
            state.dropped_samples += 1
            self._degrade(state, "malformed_source_time")
            return None
        source_time = source_time.astimezone(now.tzinfo)
        state.last_source_time_skew_seconds = abs((now - source_time).total_seconds())
        if sample_kind != "fresh":
            state.dropped_samples += 1
            self._degrade(state, "cached_display_sample")
            return None
        source_restarted = state.last_source_time is not None and source_time < state.last_source_time
        if source_restarted:
            self._begin_epoch(state)
            if state.state == "degraded":
                self._transition(state, "offline")
                self._transition(state, "reconnecting")
            elif state.state == "offline":
                self._transition(state, "reconnecting")
        if (now - source_time).total_seconds() > self._stale_after_seconds:
            state.dropped_samples += 1
            self._degrade(state, "stale_source_time")
            return None
        if state.last_monotonic_seq is not None and monotonic_seq <= state.last_monotonic_seq:
            state.dropped_samples += 1
            state.degraded_reason = "non_increasing_sequence"
            return None
        reconnected = state.state == "reconnecting"
        if state.state == "starting":
            self._transition(state, "online")
        elif state.state == "reconnecting":
            self._transition(state, "online")
        elif state.state == "degraded":
            state.dropped_samples += 1
            return None
        elif state.state == "offline":
            state.dropped_samples += 1
            return None
        state.last_source_time = source_time
        state.last_frame_at = now
        state.last_received_monotonic = self._monotonic()
        state.last_monotonic_seq = monotonic_seq
        if reconnected:
            state.reconnect_backoff_seconds = 0.0
            state.reconnect_at_monotonic = None
        state.degraded_reason = None
        observation = ObservationV1(
            schema_version="observation.v1",
            observation_id=uuid5(
                NAMESPACE_URL,
                ":".join(
                    (
                        "kuzet-pilot-observation",
                        camera_id,
                        str(state.stream_epoch),
                        str(monotonic_seq),
                        module,
                        model_artifact_id,
                    )
                ),
            ),
            camera_id=camera_id,
            stream_epoch=state.stream_epoch,
            source_time=source_time,
            timestamp_quality=timestamp_quality,
            monotonic_seq=monotonic_seq,
            module=module,
            class_name=class_name,
            confidence=confidence,
            bbox=bbox,
            track_id=track_id,
            model_artifact_id=model_artifact_id,
            sample_kind=sample_kind,
            runtime_state=state.state,
            received_at=now,
        )
        if len(self._queue) == self._queue_size:
            evicted_sequence, evicted = self._queue.popleft()
            self._state_for(evicted.camera_id).dropped_samples += 1
            self._queue_dropped_total += 1
            self._settled_observation_sequences[evicted.camera_id] = max(
                self._settled_observation_sequences[evicted.camera_id],
                evicted_sequence,
            )
            self._cursor_delivery_fenced.add(evicted.camera_id)
            self._pending_event_cursors[evicted.camera_id].clear()
        self._published_sequences[camera_id] += 1
        self._queue.append(
            (self._published_sequences[camera_id], observation)
        )
        if complete_event_frame:
            self._record_completed_cursor_locked(state)
        return observation

    def complete_frame(
        self,
        *,
        camera_id: str,
        source_time: datetime,
        monotonic_seq: int,
    ) -> bool:
        """Publish a frame watermark only after all of its detections were queued."""

        with self._queue_lock:
            state = self._state_for(camera_id)
            now = self._wall()
            if source_time.tzinfo is None or source_time.utcoffset() is None:
                return False
            normalized = source_time.astimezone(now.tzinfo)
            if (
                state.state != "online"
                or state.last_source_time != normalized
                or state.last_frame_monotonic_seq != monotonic_seq
            ):
                return False
            self._record_completed_cursor_locked(state)
            return True

    def _record_completed_cursor_locked(self, state: _CameraState) -> None:
        if (
            state.last_source_time is None
            or state.camera_id in self._cursor_delivery_fenced
        ):
            return
        cursor = EventCursor(
            camera_id=state.camera_id,
            stream_epoch=state.stream_epoch,
            source_time=state.last_source_time,
            observation_sequence=self._published_sequences[state.camera_id],
        )
        pending = self._pending_event_cursors[state.camera_id]
        if pending and pending[-1].observation_sequence == cursor.observation_sequence:
            pending[-1] = cursor
        elif (
            self._safe_event_cursors.get(state.camera_id) is not None
            and self._safe_event_cursors[
                state.camera_id
            ].observation_sequence
            == cursor.observation_sequence
        ):
            self._safe_event_cursors[state.camera_id] = cursor
        else:
            pending.append(cursor)
        self._promote_safe_cursors_locked(state.camera_id)

    def _promote_safe_cursors_locked(self, camera_id: str) -> None:
        if camera_id in self._cursor_delivery_fenced:
            return
        settled = self._settled_observation_sequences[camera_id]
        pending = self._pending_event_cursors[camera_id]
        while pending and pending[0].observation_sequence <= settled:
            self._safe_event_cursors[camera_id] = pending.popleft()

    def drain_observations(
        self,
        *,
        max_items: int | None = None,
    ) -> list[ObservationV1]:
        if max_items is None:
            max_items = self._queue_size
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items <= 0
        ):
            raise ValueError("max_items must be a positive integer")
        with self._queue_lock:
            return list(self._drain_observations_locked(max_items=max_items))

    def _drain_observations_locked(
        self,
        *,
        max_items: int,
    ) -> tuple[ObservationV1, ...]:
        drained = tuple(
            self._queue.popleft()
            for _ in range(min(max_items, len(self._queue)))
        )
        touched: set[str] = set()
        for sequence, observation in drained:
            self._settled_observation_sequences[observation.camera_id] = sequence
            touched.add(observation.camera_id)
        for camera_id in touched:
            self._promote_safe_cursors_locked(camera_id)
        return tuple(observation for _, observation in drained)

    def drain_event_batch(self, *, max_items: int) -> EventDrainBatch:
        """Atomically drain observations and snapshot non-overtaking watermarks."""

        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or max_items <= 0
        ):
            raise ValueError("max_items must be a positive integer")
        with self._queue_lock:
            observations = self._drain_observations_locked(
                max_items=max_items,
            )
            cursors = tuple(
                cursor
                for camera_id in sorted(self._states)
                if self._states[camera_id].state == "online"
                and (cursor := self._safe_event_cursors.get(camera_id))
                is not None
            )
            settled = tuple(
                (camera_id, self._settled_observation_sequences[camera_id])
                for camera_id in sorted(self._states)
            )
            return EventDrainBatch(
                observations=observations,
                cursors=cursors,
                settled_observation_sequences=settled,
            )

    def clear_observations(self) -> None:
        with self._queue_lock:
            for sequence, observation in self._queue:
                self._settled_observation_sequences[
                    observation.camera_id
                ] = max(
                    self._settled_observation_sequences[
                        observation.camera_id
                    ],
                    sequence,
                )
                self._cursor_delivery_fenced.add(observation.camera_id)
                self._pending_event_cursors[observation.camera_id].clear()
            self._queue.clear()

    def observation_queue_status(self) -> ObservationQueueStatus:
        with self._queue_lock:
            oldest_received = self._queue[0][1].received_at if self._queue else None
            oldest_age = (
                None
                if oldest_received is None
                else max(0.0, (self._wall() - oldest_received).total_seconds())
            )
            return ObservationQueueStatus(
                capacity=self._queue_size,
                depth=len(self._queue),
                dropped_total=self._queue_dropped_total,
                oldest_age_seconds=oldest_age,
            )

    def event_cursors(self) -> tuple[EventCursor, ...]:
        """Return only completed cursors that cannot overtake delivery."""

        with self._queue_lock:
            return tuple(
                cursor
                for state in sorted(
                    self._states.values(),
                    key=lambda item: item.camera_id,
                )
                if state.state == "online"
                and (cursor := self._safe_event_cursors.get(state.camera_id))
                is not None
            )

    def health_for(self, camera_id: str) -> CameraHealth:
        state = self._state_for(camera_id)
        now_monotonic = self._monotonic()
        now_wall = self._wall()
        last_frame_age = (
            None
            if state.last_received_monotonic is None
            else max(
                0.0,
                now_monotonic - state.last_received_monotonic,
            )
        )
        with self._queue_lock:
            oldest_received = next(
                (
                    observation.received_at
                    for _, observation in self._queue
                    if observation.camera_id == camera_id
                ),
                None,
            )
        queue_age = (
            None
            if oldest_received is None
            else max(
                0.0,
                (now_wall - oldest_received).total_seconds(),
            )
        )
        next_reconnect = (
            None
            if state.reconnect_at_monotonic is None or state.state != "offline"
            else max(0.0, state.reconnect_at_monotonic - now_monotonic)
        )
        return CameraHealth(
            camera_id=state.camera_id,
            state=state.state,
            stream_epoch=state.stream_epoch,
            last_frame_at=state.last_frame_at,
            last_frame_age_seconds=last_frame_age,
            reconnect_count=state.reconnect_count,
            reconnect_backoff_seconds=state.reconnect_backoff_seconds,
            next_reconnect_in_seconds=next_reconnect,
            source_time_skew_seconds=state.last_source_time_skew_seconds,
            scheduled_samples=state.scheduled_samples,
            dropped_samples=state.dropped_samples,
            queue_age_seconds=queue_age,
            degraded_reason=state.degraded_reason,
            last_monotonic_seq=state.last_monotonic_seq,
            tracker_generation=state.epoch_number,
        )

    def health(self) -> list[CameraHealth]:
        return [self.health_for(camera_id) for camera_id in sorted(self._states)]
