"""Timestamp-driven, camera-isolated candidate event fusion for the pilot."""

from __future__ import annotations

import math
import threading
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from protector.pilot.domain import (
    CandidateEventV1,
    GateMode,
    NormalisedBoundingBox,
    ObservationV1,
)
from protector.pilot.storage.journal import JournalFullError
from protector.pilot.storage.repositories import EvidenceInput, EvidenceIntent

UTC = timezone.utc
_EVENT_NAMESPACE = uuid5(NAMESPACE_URL, "kuzet-ai/pilot/candidate-event/v1")


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be UTC-aware")
    return value.astimezone(UTC)


def _finite_non_negative(value: float, *, field: str) -> float:
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return value


def _normalised_point(point: tuple[float, float], *, field: str) -> tuple[float, float]:
    if len(point) != 2 or not all(math.isfinite(value) for value in point):
        raise ValueError(f"{field} must contain two finite coordinates")
    if not all(0.0 <= value <= 1.0 for value in point):
        raise ValueError(f"{field} must be normalised to [0, 1]")
    return point


@dataclass(frozen=True, slots=True)
class DebounceSpec:
    votes_required: int
    sample_count: int
    window_seconds: float

    def __post_init__(self) -> None:
        if self.votes_required < 1 or self.sample_count < 1:
            raise ValueError("debounce vote and sample counts must be positive")
        if self.votes_required > self.sample_count:
            raise ValueError("debounce votes_required cannot exceed sample_count")
        if not math.isfinite(self.window_seconds) or self.window_seconds <= 0:
            raise ValueError("debounce window_seconds must be finite and positive")


@dataclass(frozen=True, slots=True)
class EngineLimits:
    max_seen_observations: int = 20_000
    seen_retention_seconds: float = 120.0
    max_vote_groups: int = 4_096
    max_tracks_per_camera: int = 2_048
    max_pending_events: int = 4_096
    max_cameras: int = 64
    max_ordering_streams: int = 4_096

    def __post_init__(self) -> None:
        if (
            self.max_seen_observations < 1
            or self.max_vote_groups < 1
            or self.max_tracks_per_camera < 1
            or self.max_pending_events < 1
            or self.max_cameras < 1
            or self.max_ordering_streams < 1
        ):
            raise ValueError("event-engine item limits must be positive")
        if not math.isfinite(self.seen_retention_seconds) or self.seen_retention_seconds <= 0:
            raise ValueError("seen retention must be finite and positive")


@dataclass(frozen=True, slots=True)
class ModuleRule:
    rule_id: str
    event_module: str
    source_module: str
    class_names: tuple[str, ...]
    gate_mode: GateMode
    reason: str
    min_confidence: float
    debounce: DebounceSpec
    merge_window_seconds: float = 0.0
    cooldown_seconds: float = 0.0

    def __post_init__(self) -> None:
        _validate_common_rule(self)
        if (
            not self.source_module
            or not self.class_names
            or any(not item for item in self.class_names)
        ):
            raise ValueError("module rule source and class names must be non-empty")


@dataclass(frozen=True, slots=True)
class ZoneRule:
    rule_id: str
    event_module: str
    polygon: tuple[tuple[float, float], ...]
    mode: Literal["intrusion", "loitering"]
    gate_mode: GateMode
    reason: str
    min_confidence: float
    debounce: DebounceSpec
    loiter_seconds: float = 0.0
    merge_window_seconds: float = 0.0
    cooldown_seconds: float = 0.0

    def __post_init__(self) -> None:
        _validate_common_rule(self)
        if self.mode not in ("intrusion", "loitering"):
            raise ValueError("zone mode must be intrusion or loitering")
        if len(self.polygon) < 3:
            raise ValueError("zone polygon requires at least three points")
        for index, point in enumerate(self.polygon):
            _normalised_point(point, field=f"polygon[{index}]")
        area = sum(
            x1 * y2 - x2 * y1
            for (x1, y1), (x2, y2) in zip(
                self.polygon,
                (*self.polygon[1:], self.polygon[0]),
            )
        )
        if abs(area) <= 1e-12:
            raise ValueError("zone polygon must have non-zero area")
        if not _is_simple_polygon(self.polygon):
            raise ValueError("zone polygon must not self-intersect")
        _finite_non_negative(self.loiter_seconds, field="loiter_seconds")
        if self.mode == "loitering" and self.loiter_seconds <= 0:
            raise ValueError("loitering requires a positive duration")


@dataclass(frozen=True, slots=True)
class LineRule:
    rule_id: str
    event_module: str
    start: tuple[float, float]
    end: tuple[float, float]
    direction: Literal["positive_to_negative", "negative_to_positive"]
    gate_mode: GateMode
    reason: str
    min_confidence: float
    debounce: DebounceSpec
    merge_window_seconds: float = 0.0
    cooldown_seconds: float = 0.0

    def __post_init__(self) -> None:
        _validate_common_rule(self)
        _normalised_point(self.start, field="line start")
        _normalised_point(self.end, field="line end")
        if self.start == self.end:
            raise ValueError("line endpoints must differ")
        if self.direction not in ("positive_to_negative", "negative_to_positive"):
            raise ValueError("unsupported line direction")
        if self.debounce.votes_required != 1 or self.debounce.sample_count != 1:
            raise ValueError("line crossing debounce must be 1-of-1")


def _validate_common_rule(rule: Any) -> None:
    if not rule.rule_id or not rule.event_module or not rule.reason:
        raise ValueError("rule identifiers and reason must be non-empty")
    if rule.gate_mode not in ("disabled", "shadow", "operator"):
        raise ValueError("invalid gate mode")
    if not math.isfinite(rule.min_confidence) or not 0.0 <= rule.min_confidence <= 1.0:
        raise ValueError("minimum confidence must be within [0, 1]")
    _finite_non_negative(rule.merge_window_seconds, field="merge_window_seconds")
    _finite_non_negative(rule.cooldown_seconds, field="cooldown_seconds")


def bottom_centre(bbox: NormalisedBoundingBox) -> tuple[float, float]:
    left, _top, right, bottom = bbox
    return ((left + right) / 2.0, bottom)


def _point_in_polygon(
    point: tuple[float, float],
    polygon: tuple[tuple[float, float], ...],
) -> bool:
    x, y = point
    inside = False
    previous = polygon[-1]
    for current in polygon:
        x1, y1 = previous
        x2, y2 = current
        cross = (x - x1) * (y2 - y1) - (y - y1) * (x2 - x1)
        if (
            abs(cross) <= 1e-12
            and min(x1, x2) - 1e-12 <= x <= max(x1, x2) + 1e-12
            and min(y1, y2) - 1e-12 <= y <= max(y1, y2) + 1e-12
        ):
            return True
        if (y1 > y) != (y2 > y):
            crossing_x = (x2 - x1) * (y - y1) / (y2 - y1) + x1
            if x < crossing_x:
                inside = not inside
        previous = current
    return inside


def _orientation(
    first: tuple[float, float],
    second: tuple[float, float],
    third: tuple[float, float],
) -> float:
    return (second[0] - first[0]) * (third[1] - first[1]) - (second[1] - first[1]) * (
        third[0] - first[0]
    )


def _segments_intersect(
    first_start: tuple[float, float],
    first_end: tuple[float, float],
    second_start: tuple[float, float],
    second_end: tuple[float, float],
) -> bool:
    orientations = (
        _orientation(first_start, first_end, second_start),
        _orientation(first_start, first_end, second_end),
        _orientation(second_start, second_end, first_start),
        _orientation(second_start, second_end, first_end),
    )
    if orientations[0] * orientations[1] < -1e-12 and orientations[2] * orientations[3] < -1e-12:
        return True

    def on_segment(
        start: tuple[float, float],
        point: tuple[float, float],
        end: tuple[float, float],
    ) -> bool:
        return (
            abs(_orientation(start, end, point)) <= 1e-12
            and min(start[0], end[0]) - 1e-12
            <= point[0]
            <= max(start[0], end[0]) + 1e-12
            and min(start[1], end[1]) - 1e-12
            <= point[1]
            <= max(start[1], end[1]) + 1e-12
        )

    return (
        (abs(orientations[0]) <= 1e-12 and on_segment(first_start, second_start, first_end))
        or (abs(orientations[1]) <= 1e-12 and on_segment(first_start, second_end, first_end))
        or (abs(orientations[2]) <= 1e-12 and on_segment(second_start, first_start, second_end))
        or (abs(orientations[3]) <= 1e-12 and on_segment(second_start, first_end, second_end))
    )


def _is_simple_polygon(polygon: tuple[tuple[float, float], ...]) -> bool:
    if len(set(polygon)) != len(polygon):
        return False
    edges = tuple(zip(polygon, (*polygon[1:], polygon[0])))
    for first_index, (first_start, first_end) in enumerate(edges):
        for second_index, (second_start, second_end) in enumerate(edges):
            if second_index <= first_index:
                continue
            if second_index in {first_index - 1, first_index + 1} or {
                first_index,
                second_index,
            } == {0, len(edges) - 1}:
                continue
            if _segments_intersect(
                first_start,
                first_end,
                second_start,
                second_end,
            ):
                return False
    return True


def _line_side(
    point: tuple[float, float],
    start: tuple[float, float],
    end: tuple[float, float],
) -> int:
    value = (end[0] - start[0]) * (point[1] - start[1]) - (end[1] - start[1]) * (
        point[0] - start[0]
    )
    if abs(value) <= 1e-12:
        return 0
    return 1 if value > 0 else -1


@dataclass(frozen=True, slots=True)
class CandidateTrigger:
    event: CandidateEventV1
    stream_epoch: UUID
    track_id: str | None
    rule_id: str


@dataclass(frozen=True, slots=True)
class EngineIngestResult:
    accepted: bool
    rejection_reason: str | None
    triggers: tuple[CandidateTrigger, ...]


@dataclass(frozen=True, slots=True)
class EngineStatus:
    accepted_observations: int
    rejected_observations: int
    seen_observation_ids: int
    seen_dedupe_keys: int
    vote_groups: int
    tracks: int
    pending_events: int
    ordering_streams: int


@dataclass(frozen=True, slots=True)
class _Vote:
    source_time: datetime
    positive: bool
    confidence: float
    model_artifact_id: str


@dataclass(slots=True)
class _Aggregate:
    rule: ModuleRule | ZoneRule | LineRule
    camera_id: str
    stream_epoch: UUID
    track_id: str | None
    model_artifact_id: str
    opened_at: datetime
    last_seen_at: datetime
    peak_confidence: float


@dataclass(slots=True)
class _GeometryState:
    entered_at: datetime | None = None
    loiter_emitted: bool = False
    intrusion_emitted: bool = False
    line_side: int | None = None
    line_point: tuple[float, float] | None = None


Rule = ModuleRule | ZoneRule | LineRule
StateKey = tuple[str, UUID, str, str, str]


class EventEngine:
    """Finite source-time event fusion with strict camera/epoch isolation."""

    def __init__(
        self,
        *,
        module_rules: tuple[ModuleRule, ...] = (),
        zone_rules: tuple[ZoneRule, ...] = (),
        line_rules: tuple[LineRule, ...] = (),
        limits: EngineLimits | None = None,
    ) -> None:
        self.module_rules = module_rules
        self.zone_rules = zone_rules
        self.line_rules = line_rules
        rule_ids = [rule.rule_id for rule in (*module_rules, *zone_rules, *line_rules)]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("event rule IDs must be unique")
        self.limits = limits or EngineLimits()
        self._seen_ids: OrderedDict[UUID, datetime] = OrderedDict()
        self._seen_dedupe: OrderedDict[str, datetime] = OrderedDict()
        self._active_epochs: dict[str, UUID] = {}
        self._retired_epochs: OrderedDict[tuple[str, UUID], None] = OrderedDict()
        self._last_samples: dict[
            tuple[str, UUID, str, str],
            tuple[int, datetime],
        ] = {}
        self._camera_watermarks: dict[str, datetime] = {}
        self._votes: OrderedDict[StateKey, deque[_Vote]] = OrderedDict()
        self._tracks: OrderedDict[tuple[str, UUID, str], None] = OrderedDict()
        self._geometry: dict[StateKey, _GeometryState] = {}
        self._pending: OrderedDict[StateKey, _Aggregate] = OrderedDict()
        self._cooldowns: OrderedDict[StateKey, datetime] = OrderedDict()
        self._accepted = 0
        self._rejected = 0
        self._lock = threading.RLock()

    @property
    def status(self) -> EngineStatus:
        with self._lock:
            return EngineStatus(
                accepted_observations=self._accepted,
                rejected_observations=self._rejected,
                seen_observation_ids=len(self._seen_ids),
                seen_dedupe_keys=len(self._seen_dedupe),
                vote_groups=len(self._votes),
                tracks=len(self._tracks),
                pending_events=len(self._pending),
                ordering_streams=len(self._last_samples),
            )

    def ingest(self, observation: ObservationV1) -> EngineIngestResult:
        with self._lock:
            return self._ingest_unlocked(observation)

    def _ingest_unlocked(self, observation: ObservationV1) -> EngineIngestResult:
        if observation.sample_kind != "fresh":
            return self._reject("cached_display_sample")
        if observation.runtime_state != "online":
            return self._reject("runtime_not_online")
        if observation.observation_id in self._seen_ids:
            return self._reject("duplicate_observation_id")
        if observation.dedupe_key in self._seen_dedupe:
            return self._reject("duplicate_dedupe_key")
        sample_key = (
            observation.camera_id,
            observation.stream_epoch,
            observation.module,
            observation.model_artifact_id,
        )
        if sample_key not in self._last_samples:
            active_epoch = self._active_epochs.get(observation.camera_id)
            retained = (
                sum(key[0] != observation.camera_id for key in self._last_samples)
                if active_epoch is not None and active_epoch != observation.stream_epoch
                else len(self._last_samples)
            )
            if retained >= self.limits.max_ordering_streams:
                return self._reject("ordering_stream_capacity_reached")
        epoch_rejection = self._accept_epoch(observation)
        if epoch_rejection is not None:
            return self._reject(epoch_rejection)
        previous = self._last_samples.get(sample_key)
        if previous is not None:
            previous_seq, previous_time = previous
            if observation.monotonic_seq <= previous_seq:
                return self._reject("non_increasing_sequence")
            if observation.source_time < previous_time:
                return self._reject("regressive_source_time")

        self._remember_observation(observation)
        self._last_samples[sample_key] = (
            observation.monotonic_seq,
            observation.source_time,
        )
        self._camera_watermarks[observation.camera_id] = observation.source_time
        if observation.track_id is not None:
            self._touch_track(
                observation.camera_id,
                observation.stream_epoch,
                observation.track_id,
            )
        self._accepted += 1

        triggers = list(
            self._finalize_due(
                camera_id=observation.camera_id,
                stream_epoch=observation.stream_epoch,
                source_time=observation.source_time,
            )
        )
        for rule in self.module_rules:
            if observation.module == rule.source_module:
                positive = (
                    observation.class_name in rule.class_names
                    and observation.confidence >= rule.min_confidence
                )
                triggers.extend(self._signal(rule, observation, positive=positive))
        if observation.module == "person" and observation.track_id is not None:
            for rule in self.zone_rules:
                triggers.extend(self._zone_signal(rule, observation))
            for rule in self.line_rules:
                triggers.extend(self._line_signal(rule, observation))
        return EngineIngestResult(
            accepted=True,
            rejection_reason=None,
            triggers=tuple(triggers),
        )

    def advance(
        self,
        *,
        camera_id: str,
        stream_epoch: UUID,
        source_time: datetime,
    ) -> tuple[CandidateTrigger, ...]:
        with self._lock:
            source_time = _utc(source_time, field="source_time")
            if self._active_epochs.get(camera_id) != stream_epoch:
                return ()
            return self._finalize_due(
                camera_id=camera_id,
                stream_epoch=stream_epoch,
                source_time=source_time,
            )

    def flush(self) -> tuple[CandidateTrigger, ...]:
        with self._lock:
            triggers = tuple(
                self._trigger_from_aggregate(key, aggregate)
                for key, aggregate in sorted(
                    self._pending.items(),
                    key=lambda item: (
                        item[1].opened_at,
                        item[1].camera_id,
                        item[1].rule.rule_id,
                    ),
                )
            )
            self._pending.clear()
            return triggers

    def _reject(self, reason: str) -> EngineIngestResult:
        self._rejected += 1
        return EngineIngestResult(False, reason, ())

    def _accept_epoch(self, observation: ObservationV1) -> str | None:
        camera_id = observation.camera_id
        epoch = observation.stream_epoch
        active = self._active_epochs.get(camera_id)
        if active is None:
            if len(self._active_epochs) >= self.limits.max_cameras:
                return "camera_capacity_reached"
            self._active_epochs[camera_id] = epoch
            return None
        if active == epoch:
            return None
        if (camera_id, epoch) in self._retired_epochs:
            return "stale_stream_epoch"
        watermark = self._camera_watermarks.get(camera_id)
        if watermark is not None and observation.source_time < watermark:
            return "stale_stream_epoch"
        self._retired_epochs[(camera_id, active)] = None
        while len(self._retired_epochs) > self.limits.max_seen_observations:
            self._retired_epochs.popitem(last=False)
        self._active_epochs[camera_id] = epoch
        self._reset_camera_state(camera_id)
        return None

    def _reset_camera_state(self, camera_id: str) -> None:
        self._last_samples = {
            key: value for key, value in self._last_samples.items() if key[0] != camera_id
        }
        for collection in (self._votes, self._tracks):
            for key in tuple(collection):
                if key[0] == camera_id:
                    collection.pop(key, None)
        for collection in (self._geometry, self._pending, self._cooldowns):
            for key in tuple(collection):
                if key[0] == camera_id:
                    collection.pop(key, None)

    def _remember_observation(self, observation: ObservationV1) -> None:
        cutoff = observation.source_time - timedelta(seconds=self.limits.seen_retention_seconds)
        for collection in (self._seen_ids, self._seen_dedupe):
            for key, seen_at in tuple(collection.items()):
                if seen_at < cutoff:
                    collection.pop(key, None)
        self._seen_ids[observation.observation_id] = observation.source_time
        self._seen_dedupe[observation.dedupe_key] = observation.source_time
        while len(self._seen_ids) > self.limits.max_seen_observations:
            self._seen_ids.popitem(last=False)
        while len(self._seen_dedupe) > self.limits.max_seen_observations:
            self._seen_dedupe.popitem(last=False)

    def _touch_track(self, camera_id: str, epoch: UUID, track_id: str) -> None:
        key = (camera_id, epoch, track_id)
        self._tracks.pop(key, None)
        self._tracks[key] = None
        camera_keys = [item for item in self._tracks if item[0] == camera_id]
        while len(camera_keys) > self.limits.max_tracks_per_camera:
            victim = camera_keys.pop(0)
            self._tracks.pop(victim, None)
            for collection in (self._geometry, self._pending, self._cooldowns, self._votes):
                for state_key in tuple(collection):
                    if (
                        state_key[0] == victim[0]
                        and state_key[1] == victim[1]
                        and state_key[3] == victim[2]
                    ):
                        collection.pop(state_key, None)

    @staticmethod
    def _state_key(rule: Rule, observation: ObservationV1) -> StateKey:
        return (
            observation.camera_id,
            observation.stream_epoch,
            rule.rule_id,
            observation.track_id or "__camera__",
            observation.model_artifact_id,
        )

    def _zone_signal(
        self,
        rule: ZoneRule,
        observation: ObservationV1,
    ) -> tuple[CandidateTrigger, ...]:
        key = self._state_key(rule, observation)
        if observation.confidence < rule.min_confidence:
            self._geometry.pop(key, None)
            self._votes.pop(key, None)
            return ()
        state = self._geometry.setdefault(key, _GeometryState())
        inside = _point_in_polygon(bottom_centre(observation.bbox), rule.polygon)
        if rule.mode == "intrusion":
            if not inside:
                state.intrusion_emitted = False
                return self._signal(rule, observation, positive=False)
            if state.intrusion_emitted:
                return self._signal(rule, observation, positive=False)
            triggers = self._signal(rule, observation, positive=True)
            if triggers or key in self._pending:
                state.intrusion_emitted = True
            return triggers
        if not inside:
            state.entered_at = None
            state.loiter_emitted = False
            return self._signal(rule, observation, positive=False)
        if state.entered_at is None:
            state.entered_at = observation.source_time
            return self._signal(rule, observation, positive=False)
        if state.loiter_emitted:
            return self._signal(rule, observation, positive=False)
        positive = (
            observation.source_time - state.entered_at
        ).total_seconds() >= rule.loiter_seconds
        triggers = self._signal(
            rule,
            observation,
            positive=positive,
            opened_at_override=observation.source_time if positive else None,
        )
        if positive:
            state.loiter_emitted = True
        return triggers

    def _line_signal(
        self,
        rule: LineRule,
        observation: ObservationV1,
    ) -> tuple[CandidateTrigger, ...]:
        key = self._state_key(rule, observation)
        if observation.confidence < rule.min_confidence:
            self._geometry.pop(key, None)
            self._votes.pop(key, None)
            return ()
        state = self._geometry.setdefault(key, _GeometryState())
        point = bottom_centre(observation.bbox)
        side = _line_side(point, rule.start, rule.end)
        previous = state.line_side
        previous_point = state.line_point
        if side != 0:
            state.line_side = side
            state.line_point = point
        if previous is None or previous_point is None or side == 0 or previous == side:
            return ()
        # Closed line endpoints count; crossings of only the infinite extension do not.
        if not _segments_intersect(previous_point, point, rule.start, rule.end):
            return ()
        positive = (rule.direction == "positive_to_negative" and previous > 0 and side < 0) or (
            rule.direction == "negative_to_positive" and previous < 0 and side > 0
        )
        if not positive:
            return ()
        return self._signal(rule, observation, positive=True)

    def _signal(
        self,
        rule: Rule,
        observation: ObservationV1,
        *,
        positive: bool,
        opened_at_override: datetime | None = None,
    ) -> tuple[CandidateTrigger, ...]:
        if rule.gate_mode == "disabled":
            return ()
        key = self._state_key(rule, observation)
        aggregate = self._pending.get(key)
        if aggregate is not None:
            if positive:
                aggregate.last_seen_at = observation.source_time
                aggregate.peak_confidence = max(
                    aggregate.peak_confidence,
                    observation.confidence,
                )
            return ()
        cooldown_until = self._cooldowns.get(key)
        if cooldown_until is not None and observation.source_time < cooldown_until:
            return ()
        if cooldown_until is not None:
            self._cooldowns.pop(key, None)

        votes = self._votes.get(key)
        if votes is None:
            votes = deque()
            self._votes[key] = votes
            while len(self._votes) > self.limits.max_vote_groups:
                self._votes.popitem(last=False)
        else:
            self._votes.move_to_end(key)
        votes.append(
            _Vote(
                source_time=observation.source_time,
                positive=positive,
                confidence=observation.confidence,
                model_artifact_id=observation.model_artifact_id,
            )
        )
        cutoff = observation.source_time - timedelta(seconds=rule.debounce.window_seconds)
        while votes and votes[0].source_time < cutoff:
            votes.popleft()
        while len(votes) > rule.debounce.sample_count:
            votes.popleft()
        positive_votes = [vote for vote in votes if vote.positive]
        if len(positive_votes) < rule.debounce.votes_required:
            return ()

        opened_at = (
            opened_at_override if opened_at_override is not None else positive_votes[0].source_time
        )
        aggregate = _Aggregate(
            rule=rule,
            camera_id=observation.camera_id,
            stream_epoch=observation.stream_epoch,
            track_id=observation.track_id,
            model_artifact_id=observation.model_artifact_id,
            opened_at=opened_at,
            last_seen_at=positive_votes[-1].source_time,
            peak_confidence=max(vote.confidence for vote in positive_votes),
        )
        votes.clear()
        if rule.merge_window_seconds > 0:
            self._pending[key] = aggregate
            forced: tuple[CandidateTrigger, ...] = ()
            if len(self._pending) > self.limits.max_pending_events:
                oldest_key, oldest = self._pending.popitem(last=False)
                forced = (self._trigger_from_aggregate(oldest_key, oldest),)
            return forced
        trigger = self._trigger_from_aggregate(key, aggregate)
        return (trigger,)

    def _finalize_due(
        self,
        *,
        camera_id: str,
        stream_epoch: UUID,
        source_time: datetime,
    ) -> tuple[CandidateTrigger, ...]:
        due = [
            (key, aggregate)
            for key, aggregate in self._pending.items()
            if key[0] == camera_id
            and key[1] == stream_epoch
            and source_time
            >= aggregate.last_seen_at + timedelta(seconds=aggregate.rule.merge_window_seconds)
        ]
        triggers = []
        for key, aggregate in due:
            self._pending.pop(key, None)
            triggers.append(self._trigger_from_aggregate(key, aggregate))
        return tuple(triggers)

    def _trigger_from_aggregate(
        self,
        key: StateKey,
        aggregate: _Aggregate,
    ) -> CandidateTrigger:
        material = "|".join(
            (
                aggregate.camera_id,
                str(aggregate.stream_epoch),
                aggregate.rule.rule_id,
                aggregate.track_id or "__camera__",
                aggregate.model_artifact_id,
                aggregate.opened_at.isoformat(),
            )
        )
        event = CandidateEventV1(
            schema_version="candidate-event.v1",
            event_id=uuid5(_EVENT_NAMESPACE, material),
            camera_id=aggregate.camera_id,
            module=aggregate.rule.event_module,
            opened_at=aggregate.opened_at,
            last_seen_at=aggregate.last_seen_at,
            peak_confidence=aggregate.peak_confidence,
            reason=aggregate.rule.reason,
            model_artifact_id=aggregate.model_artifact_id,
            gate_mode=aggregate.rule.gate_mode,
            evidence_status="unavailable",
            review_status="candidate",
        )
        self._cooldowns[key] = aggregate.last_seen_at + timedelta(
            seconds=aggregate.rule.cooldown_seconds
        )
        self._cooldowns.move_to_end(key)
        while len(self._cooldowns) > self.limits.max_vote_groups:
            self._cooldowns.popitem(last=False)
        return CandidateTrigger(
            event=event,
            stream_epoch=aggregate.stream_epoch,
            track_id=aggregate.track_id,
            rule_id=aggregate.rule.rule_id,
        )


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    pre_roll_seconds: float
    post_roll_seconds: float
    source_references: Mapping[str, str]

    def __post_init__(self) -> None:
        pre = _finite_non_negative(self.pre_roll_seconds, field="pre_roll_seconds")
        post = _finite_non_negative(self.post_roll_seconds, field="post_roll_seconds")
        if not 4.0 <= pre + post <= 10.0:
            raise ValueError("evidence pre/post window must total 4-10 seconds")
        if any(not camera or not source for camera, source in self.source_references.items()):
            raise ValueError("evidence source references must be non-empty")
        for source in self.source_references.values():
            parsed = urlsplit(source)
            if (
                parsed.scheme != "nvr"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "evidence source references must be opaque credential-free NVR identifiers"
                )
        object.__setattr__(
            self,
            "source_references",
            MappingProxyType(dict(self.source_references)),
        )


@dataclass(frozen=True, slots=True)
class DurableCandidate:
    trigger: CandidateTrigger
    pending_evidence: EvidenceIntent | None
    evidence: EvidenceInput | None


@dataclass(frozen=True, slots=True)
class SiteEventStatus:
    degraded: bool
    reasons: tuple[str, ...]
    journal_depth: int
    journal_quarantine_depth: int


@dataclass(frozen=True, slots=True)
class SiteEventResult:
    engine_result: EngineIngestResult | None
    durable_candidates: tuple[DurableCandidate, ...]
    status: SiteEventStatus


class SiteEventService:
    """WAL-first candidate persistence and Task 7 evidence orchestration."""

    def __init__(
        self,
        *,
        engine: EventEngine,
        journal: Any,
        replay_worker: Any,
        ring: Any,
        evidence_coordinator: Any,
        load_candidate: Callable[[UUID], CandidateEventV1],
        mark_evidence_pending: Callable[[UUID], CandidateEventV1 | None],
        mark_evidence_failed: Callable[[UUID], CandidateEventV1 | None],
        evidence_policy: EvidencePolicy,
    ) -> None:
        self.engine = engine
        self._journal = journal
        self._replay_worker = replay_worker
        self._ring = ring
        self._evidence_coordinator = evidence_coordinator
        self._load_candidate = load_candidate
        self._mark_evidence_pending = mark_evidence_pending
        self._mark_evidence_failed = mark_evidence_failed
        self._evidence_policy = evidence_policy
        self._reasons: OrderedDict[str, None] = OrderedDict()
        self._state_lock = threading.RLock()
        self._processing: set[UUID] = set()
        self._completed: OrderedDict[UUID, None] = OrderedDict()

    @property
    def status(self) -> SiteEventStatus:
        try:
            replay_status = self._replay_worker.status
            replay_degraded = bool(replay_status.degraded)
            quarantine_depth = int(replay_status.quarantine_depth)
        except Exception:
            self._degrade("journal_status_failed")
            replay_degraded = True
            quarantine_depth = -1
        with self._state_lock:
            reasons = list(self._reasons)
        if replay_degraded and "journal_replay_degraded" not in reasons:
            reasons.append("journal_replay_degraded")
        try:
            depth = int(self._journal.depth())
        except Exception:
            depth = -1
            self._degrade("journal_depth_failed")
            with self._state_lock:
                reasons = list(self._reasons)
        return SiteEventStatus(
            degraded=bool(reasons) or replay_degraded,
            reasons=tuple(reasons),
            journal_depth=depth,
            journal_quarantine_depth=quarantine_depth,
        )

    def start(self) -> SiteEventStatus:
        try:
            self._replay_worker.startup_drain()
        except Exception:
            self._degrade("journal_startup_replay_failed")
        return self.status

    def process(self, observation: ObservationV1) -> SiteEventResult:
        engine_result = self.engine.ingest(observation)
        durable = self._process_triggers(engine_result.triggers)
        return SiteEventResult(engine_result, durable, self.status)

    def run_periodic(
        self,
        *,
        camera_id: str,
        stream_epoch: UUID,
        source_time: datetime,
    ) -> SiteEventResult:
        triggers = self.engine.advance(
            camera_id=camera_id,
            stream_epoch=stream_epoch,
            source_time=source_time,
        )
        durable = self._process_triggers(triggers)
        try:
            self._replay_worker.run_periodic_batch()
        except Exception:
            self._degrade("journal_periodic_replay_failed")
        return SiteEventResult(None, durable, self.status)

    def _process_triggers(
        self,
        triggers: tuple[CandidateTrigger, ...],
    ) -> tuple[DurableCandidate, ...]:
        durable: list[DurableCandidate] = []
        for original_trigger in triggers:
            if not self._claim(original_trigger.event.event_id):
                continue
            completed = False
            try:
                candidate = self._process_trigger(original_trigger)
                if candidate is not None:
                    durable.append(candidate)
                    completed = True
            finally:
                self._finish_claim(original_trigger.event.event_id, completed=completed)
        return tuple(durable)

    def _process_trigger(
        self,
        original_trigger: CandidateTrigger,
    ) -> DurableCandidate | None:
        trigger = original_trigger
        reservation: Any | None = None
        reservation_id = f"event-{trigger.event.event_id}"
        try:
            self._journal.enqueue_event(trigger.event)
        except JournalFullError:
            self._degrade("candidate_journal_full")
            return None
        except Exception:
            self._degrade("candidate_journal_write_failed")
            return None

        try:
            self._replay_worker.run_periodic_batch()
        except Exception:
            self._degrade("journal_replay_failed")
        try:
            replay_degraded = bool(self._replay_worker.status.degraded)
        except Exception:
            replay_degraded = True
            self._degrade("journal_status_failed")
        if replay_degraded:
            self._degrade("journal_replay_degraded")
        try:
            persisted = self._load_candidate(trigger.event.event_id)
        except KeyError:
            persisted = None
        except Exception:
            persisted = None
            self._degrade("candidate_persistence_check_failed")
        if persisted is None:
            self._degrade("candidate_persistence_pending")
            return None
        if not self._same_candidate(persisted, trigger.event):
            self._degrade("candidate_persistence_identity_mismatch")
            return None

        try:
            reservation = self._ring.reserve(
                reservation_id=reservation_id,
                camera_id=trigger.event.camera_id,
                stream_epoch=str(trigger.stream_epoch),
                event_at=trigger.event.last_seen_at,
                pre_roll=self._evidence_policy.pre_roll_seconds,
                post_roll=self._evidence_policy.post_roll_seconds,
            )
        except Exception:
            self._degrade("evidence_reservation_unavailable")
            return DurableCandidate(trigger, None, None)

        try:
            pending = self._pending_evidence(trigger, reservation)
        except Exception:
            self._degrade("evidence_processing_failed")
            self._terminalize_candidate(trigger.event.event_id)
            self._safe_release(reservation_id)
            return None
        try:
            self._evidence_coordinator.create_preview(
                reservation,
                evidence=pending,
            )
            self._mark_evidence_pending(trigger.event.event_id)
            pending_event = trigger.event.model_copy(update={"evidence_status": "pending"})
            trigger = replace(trigger, event=pending_event)
            evidence = (
                self._evidence_coordinator.complete(reservation, pending)
                if reservation.status == "ready"
                else None
            )
        except Exception:
            self._degrade("evidence_processing_failed")
            return None
        return DurableCandidate(trigger, pending, evidence)

    @staticmethod
    def _same_candidate(persisted: CandidateEventV1, expected: CandidateEventV1) -> bool:
        return persisted.model_dump(mode="json") == expected.model_dump(mode="json")

    def _claim(self, event_id: UUID) -> bool:
        with self._state_lock:
            if event_id in self._processing or event_id in self._completed:
                return False
            self._processing.add(event_id)
            return True

    def _finish_claim(self, event_id: UUID, *, completed: bool) -> None:
        with self._state_lock:
            self._processing.discard(event_id)
            if completed:
                self._completed[event_id] = None
                while len(self._completed) > self.engine.limits.max_pending_events:
                    self._completed.popitem(last=False)

    def _terminalize_candidate(self, event_id: UUID) -> None:
        try:
            self._mark_evidence_failed(event_id)
        except Exception:
            self._degrade("evidence_terminal_transition_failed")

    def _pending_evidence(
        self,
        trigger: CandidateTrigger,
        reservation: Any,
    ) -> EvidenceIntent:
        source = self._evidence_policy.source_references.get(trigger.event.camera_id)
        if source is None:
            raise ValueError("camera evidence source reference is not configured")
        codec = reservation.fragments[0].codec
        return EvidenceIntent(
            schema_version="evidence-intent.v1",
            evidence_id=uuid5(_EVENT_NAMESPACE, f"evidence:{trigger.event.event_id}"),
            event_id=trigger.event.event_id,
            object_key=f"events/{trigger.event.event_id}.mp4",
            codec=codec,
            start_at=reservation.target_start_at,
            end_at=reservation.target_end_at,
            source_reference=source,
            status="pending",
        )

    def _safe_release(self, reservation_id: str) -> None:
        try:
            self._ring.release(reservation_id)
        except Exception:
            self._degrade("evidence_release_failed")

    def _degrade(self, reason: str) -> None:
        with self._state_lock:
            self._reasons.pop(reason, None)
            self._reasons[reason] = None
            while len(self._reasons) > 32:
                self._reasons.popitem(last=False)
