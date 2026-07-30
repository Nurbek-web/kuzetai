"""Strict target-only operational evidence for pilot acceptance.

The portable acceptance record may omit this block.  A target evaluator does
not: it derives its result from exhaustive, identity-linked evidence and fails
closed when the block is absent.
"""

from __future__ import annotations

import hashlib
import json
import math
from bisect import bisect_left
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BoundedId = Annotated[str, Field(min_length=1, max_length=128)]
QueueName = Literal["decode", "analytics", "verifier", "events", "evidence"]
StoreName = Literal["evidence", "metadata"]
Mode = Literal["operator", "shadow", "disabled"]
ModuleName = Literal[
    "acceptance_drill",
    "person",
    "restricted_zone",
    "intrusion",
    "loitering",
    "line_crossing",
    "fire_smoke",
    "weapon",
    "fight",
    "fall",
    "violence",
    "xclip",
    "vit",
]

_QUEUE_NAMES: tuple[QueueName, ...] = (
    "decode",
    "analytics",
    "verifier",
    "events",
    "evidence",
)
_STORE_NAMES: tuple[StoreName, ...] = ("evidence", "metadata")
_MAX_EVENTS = 4_096
_MAX_SPANS = 10_000
_MAX_ATTEMPTS = 8_192
_MAX_PLATEAU_WINDOWS = 10_000
_RANK_SIGNIFICANCE_MULTIPLIER_SQUARED = 25
_MODULE_NAMES = frozenset(
    {
        "acceptance_drill",
        "person",
        "restricted_zone",
        "intrusion",
        "loitering",
        "line_crossing",
        "fire_smoke",
        "weapon",
        "fight",
        "fall",
        "violence",
        "xclip",
        "vit",
    }
)
_MODES = frozenset({"operator", "shadow", "disabled"})
_SHADOW_ONLY_ANALYTICS = frozenset({"fight", "fall", "violence", "xclip", "vit"})


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be UTC-aware")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be UTC")
    return value.astimezone(timezone.utc)


def _canonical_relative_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        value != value.strip()
        or value.startswith("/")
        or "\\" in value
        or "//" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError(f"{label} must be a canonical relative path")
    return value


class QueueLimitV1(_FrozenModel):
    name: QueueName
    capacity: Annotated[int, Field(ge=1, le=10_000)]


class StoreBudgetV1(_FrozenModel):
    name: StoreName
    storage_identity: BoundedId
    fixed_overhead_bytes: Annotated[int, Field(ge=0, le=1_000_000_000_000)]
    max_object_bytes: Annotated[int, Field(gt=0, le=1_000_000_000_000)]
    max_objects: Annotated[int, Field(gt=0, le=10_000_000)]
    max_bytes: Annotated[int, Field(gt=0, le=1_000_000_000_000)]
    retention_window_seconds: Annotated[int, Field(gt=0, le=31_536_000)]
    plateau_observation_window_seconds: Annotated[
        int,
        Field(gt=0, le=259_200),
    ]

    @model_validator(mode="after")
    def budget_is_the_projected_plateau(self) -> StoreBudgetV1:
        projected = self.fixed_overhead_bytes + self.max_object_bytes * self.max_objects
        if projected != self.max_bytes:
            raise ValueError(
                "store max_bytes must equal fixed_overhead_bytes plus "
                "max_object_bytes times max_objects"
            )
        return self

    @property
    def projected_plateau_bytes(self) -> int:
        return self.fixed_overhead_bytes + self.max_object_bytes * self.max_objects


@dataclass(frozen=True)
class _WeightedPlateauWindow:
    weight: int
    byte_sum: int
    object_sum: int
    min_bytes: int
    max_bytes: int
    min_objects: int
    max_objects: int
    first_bytes: int
    first_objects: int


@dataclass(frozen=True)
class _WeightedPlateauScan:
    windows: tuple[_WeightedPlateauWindow, ...]
    scan_steps: int

    @property
    def window_count(self) -> int:
        return len(self.windows)


def _scan_weighted_plateau_runs(
    runs: Sequence[tuple[int, int, int, int]],
    *,
    window_samples: int,
    expected_samples: int,
) -> _WeightedPlateauScan:
    """Aggregate complete post-warmup windows without expanding RLE samples."""

    if (
        type(window_samples) is not int
        or type(expected_samples) is not int
        or window_samples <= 0
        or expected_samples <= 0
    ):
        raise ValueError("plateau scan dimensions must be positive integers")

    coverage_cursor = 0
    for first_sample_index, sample_count, _used_bytes, _object_count in runs:
        if first_sample_index != coverage_cursor or sample_count <= 0:
            raise ValueError("plateau runs must be canonical and contiguous")
        coverage_cursor += sample_count
    if coverage_cursor != expected_samples:
        raise ValueError("plateau runs do not exactly cover expected samples")

    complete_windows = (expected_samples - window_samples) // window_samples
    if complete_windows < 1:
        raise ValueError("plateau scan lacks a full post-warmup observation window")
    if complete_windows > _MAX_PLATEAU_WINDOWS:
        raise ValueError("plateau scan window count must remain bounded")
    run_index = 0
    while run_index < len(runs) and runs[run_index][0] + runs[run_index][1] <= window_samples:
        run_index += 1

    windows: list[_WeightedPlateauWindow] = []
    scan_steps = 0
    for window_index in range(max(0, complete_windows)):
        window_start = window_samples * (window_index + 1)
        window_end = (
            expected_samples
            if window_index == complete_windows - 1
            else window_start + window_samples
        )
        expected_weight = window_end - window_start
        sample_cursor = window_start
        weight = 0
        byte_sum = 0
        object_sum = 0
        min_bytes: int | None = None
        max_bytes: int | None = None
        min_objects: int | None = None
        max_objects: int | None = None
        first_bytes: int | None = None
        first_objects: int | None = None

        while sample_cursor < window_end:
            if run_index >= len(runs):
                raise ValueError("plateau window lacks complete sample coverage")
            run_start, run_count, used_bytes, object_count = runs[run_index]
            run_end = run_start + run_count
            if run_start > sample_cursor or run_end <= sample_cursor:
                raise ValueError("plateau runs do not align with the scan cursor")

            overlap_end = min(run_end, window_end)
            overlap_weight = overlap_end - sample_cursor
            if first_bytes is None:
                first_bytes = used_bytes
                first_objects = object_count
            weight += overlap_weight
            byte_sum += used_bytes * overlap_weight
            object_sum += object_count * overlap_weight
            min_bytes = used_bytes if min_bytes is None else min(min_bytes, used_bytes)
            max_bytes = used_bytes if max_bytes is None else max(max_bytes, used_bytes)
            min_objects = object_count if min_objects is None else min(min_objects, object_count)
            max_objects = object_count if max_objects is None else max(max_objects, object_count)
            sample_cursor = overlap_end
            scan_steps += 1
            if sample_cursor == run_end:
                run_index += 1

        if (
            weight != expected_weight
            or weight < window_samples
            or min_bytes is None
            or max_bytes is None
            or min_objects is None
            or max_objects is None
            or first_bytes is None
            or first_objects is None
        ):
            raise ValueError("plateau window does not have its exact expected weight")
        windows.append(
            _WeightedPlateauWindow(
                weight=weight,
                byte_sum=byte_sum,
                object_sum=object_sum,
                min_bytes=min_bytes,
                max_bytes=max_bytes,
                min_objects=min_objects,
                max_objects=max_objects,
                first_bytes=first_bytes,
                first_objects=first_objects,
            )
        )

    if sum(window.weight for window in windows) != expected_samples - window_samples:
        raise ValueError("plateau windows do not exactly cover post-warmup samples")
    return _WeightedPlateauScan(windows=tuple(windows), scan_steps=scan_steps)


def _has_material_positive_store_trend(
    runs: Sequence[tuple[int, int, int, int]],
    *,
    warmup_samples: int,
    expected_samples: int,
) -> bool:
    """Detect unbounded growth from exact weighted RLE sequence proofs.

    Equal-duration early and late post-warmup halves are represented as
    weighted integer histograms, never expanded into samples. A weighted
    Mann-Whitney sign score rejects general positive drift without depending
    on ranges or a fixed number of removable outliers. Its integer threshold
    is ``score > 5 / sqrt(N)`` after normalization.

    Two sequence proofs cover cases whose half distributions are phase
    imbalanced: identical long recurring cycles with a positive baseline
    translation, and late increasing subsequences that follow a sustained
    plateau but lack one full terminal plateau window. Conversely, an exact
    one-transition step is accepted only after its terminal value persists
    for a full signed plateau window. An isolated one-sample deviation is
    bounded only when the same baseline is observed on both sides; an
    unbracketed boundary change remains fail-closed.

    Sorting and longest-subsequence search over at most the signed 10k RLE
    rows gives O(R log R) runtime and O(R) bounded memory. Samples are never
    expanded, and all comparisons and thresholds use Python integers.
    """

    if (
        type(warmup_samples) is not int
        or type(expected_samples) is not int
        or warmup_samples < 0
        or expected_samples <= warmup_samples + 1
    ):
        raise ValueError("store trend dimensions are invalid")

    canonical_runs = tuple(runs)
    if not canonical_runs or len(canonical_runs) > _MAX_SPANS:
        raise ValueError("store trend RLE must remain within the signed span bound")
    coverage_cursor = 0
    for run_start, run_count, _used_bytes, _object_count in canonical_runs:
        if run_start != coverage_cursor or run_count <= 0:
            raise ValueError("store trend runs must be canonical and contiguous")
        coverage_cursor += run_count
    if coverage_cursor != expected_samples:
        raise ValueError("store trend does not exactly cover expected samples")

    post_warmup_samples = expected_samples - warmup_samples
    half_samples = post_warmup_samples // 2
    if half_samples < 1:
        raise ValueError("store trend requires two non-empty comparison halves")
    early_start = warmup_samples
    early_end = early_start + half_samples
    late_start = expected_samples - half_samples
    late_end = expected_samples
    early_bytes: dict[int, int] = defaultdict(int)
    late_bytes: dict[int, int] = defaultdict(int)
    early_objects: dict[int, int] = defaultdict(int)
    late_objects: dict[int, int] = defaultdict(int)
    early_weight = 0
    late_weight = 0

    for run_start, run_count, used_bytes, object_count in canonical_runs:
        run_end = run_start + run_count
        early_overlap = max(0, min(run_end, early_end) - max(run_start, early_start))
        if early_overlap:
            early_bytes[used_bytes] += early_overlap
            early_objects[object_count] += early_overlap
            early_weight += early_overlap
        late_overlap = max(0, min(run_end, late_end) - max(run_start, late_start))
        if late_overlap:
            late_bytes[used_bytes] += late_overlap
            late_objects[object_count] += late_overlap
            late_weight += late_overlap
    if early_weight != half_samples or late_weight != half_samples:
        raise ValueError("store trend halves lack exact RLE coverage")

    def metric_runs_from(
        value_index: Literal[2, 3],
        first_sample: int,
    ) -> tuple[tuple[int, int, int], ...]:
        metric_runs: list[tuple[int, int, int]] = []
        for run_start, run_count, used_bytes, object_count in canonical_runs:
            run_end = run_start + run_count
            clipped_start = max(run_start, first_sample)
            if clipped_start >= run_end:
                continue
            value = used_bytes if value_index == 2 else object_count
            clipped_count = run_end - clipped_start
            if (
                metric_runs
                and metric_runs[-1][0] + metric_runs[-1][1] == clipped_start
                and metric_runs[-1][2] == value
            ):
                previous_start, previous_count, _previous_value = metric_runs[-1]
                metric_runs[-1] = (
                    previous_start,
                    previous_count + clipped_count,
                    value,
                )
            else:
                metric_runs.append((clipped_start, clipped_count, value))
        if sum(run_count for _run_start, run_count, _value in metric_runs) != (
            expected_samples - first_sample
        ):
            raise ValueError("store trend metric runs lack exact coverage")
        return tuple(metric_runs)

    plateau_proof_samples = max(1, warmup_samples)

    def is_exact_bounded_step(metric_runs: Sequence[tuple[int, int, int]]) -> bool:
        if len(metric_runs) == 1:
            return True
        return len(metric_runs) == 2 and metric_runs[-1][1] >= plateau_proof_samples

    def is_exact_single_sample_deviation(
        metric_runs: Sequence[tuple[int, int, int]],
    ) -> bool:
        return (
            len(metric_runs) == 3
            and metric_runs[0][2] == metric_runs[2][2]
            and metric_runs[1][1] == 1
        )

    def recurring_cycle_is_changing(
        metric_runs: Sequence[tuple[int, int, int]],
    ) -> bool | None:
        transitions = tuple(
            (
                run_count,
                metric_runs[index + 1][2] - value,
            )
            for index, (_run_start, run_count, value) in enumerate(metric_runs[:-1])
        )
        if len(transitions) < 3:
            return None

        # The first post-warmup run can be a clipped fragment, so its duration
        # token is not recurrence evidence. Every later transition token has
        # its complete signed RLE duration.
        recurring_tokens = transitions[1:]
        token_count = len(recurring_tokens)
        recurring_deltas = tuple(delta for _run_count, delta in recurring_tokens)
        z_values = [0] * token_count
        match_start = 0
        match_end = 0
        for index in range(1, token_count):
            if index < match_end:
                z_values[index] = min(
                    match_end - index,
                    z_values[index - match_start],
                )
            while (
                index + z_values[index] < token_count
                and recurring_deltas[z_values[index]] == recurring_deltas[index + z_values[index]]
            ):
                z_values[index] += 1
            if index + z_values[index] > match_end:
                match_start = index
                match_end = index + z_values[index]

        duration_prefix = [0]
        for run_count, _delta in recurring_tokens:
            duration_prefix.append(duration_prefix[-1] + run_count)
        # Two complete cycles are the maximum provable horizon for a signed
        # 481-sample trace with a 200-sample recurrence. The full remaining
        # transition suffix must repeat, so a short local coincidence is not
        # treated as a cycle.
        for transition_period in range(1, token_count // 2 + 1):
            if z_values[transition_period] < token_count - transition_period:
                continue
            if duration_prefix[transition_period] < plateau_proof_samples:
                continue
            baseline_shift = metric_runs[transition_period + 1][2] - metric_runs[1][2]
            durations_repeat = all(
                recurring_tokens[index][0] == recurring_tokens[index % transition_period][0]
                for index in range(transition_period, token_count)
            )
            return baseline_shift != 0 or not durations_repeat
        return None

    def has_unfinished_late_change(
        metric_runs: Sequence[tuple[int, int, int]],
    ) -> bool:
        if metric_runs[-1][1] >= plateau_proof_samples:
            return False
        if len(metric_runs) == 2:
            return metric_runs[-1][2] != metric_runs[0][2]
        anchor_index: int | None = None
        for index, (_run_start, run_count, _value) in enumerate(metric_runs[:-1]):
            if run_count >= plateau_proof_samples:
                anchor_index = index
        if anchor_index is None:
            return False

        increasing_tails: list[int] = []
        decreasing_tails: list[int] = []
        tail_values = tuple(value for _start, _count, value in metric_runs[anchor_index:])
        if len(tail_values) == 2:
            return tail_values[0] != tail_values[1]
        for value in tail_values:
            insertion_index = bisect_left(increasing_tails, value)
            if insertion_index == len(increasing_tails):
                increasing_tails.append(value)
            else:
                increasing_tails[insertion_index] = value
            decreasing_value = -value
            insertion_index = bisect_left(decreasing_tails, decreasing_value)
            if insertion_index == len(decreasing_tails):
                decreasing_tails.append(decreasing_value)
            else:
                decreasing_tails[insertion_index] = decreasing_value
        return len(increasing_tails) >= 3 or len(decreasing_tails) >= 3

    def has_nonrecurring_multi_transition(
        metric_runs: Sequence[tuple[int, int, int]],
    ) -> bool:
        if len(metric_runs) < 3:
            return False
        values = tuple(value for _start, _count, value in metric_runs)
        increasing = all(left < right for left, right in zip(values, values[1:]))
        decreasing = all(left > right for left, right in zip(values, values[1:]))
        sustained_runs = sum(
            run_count >= plateau_proof_samples for _run_start, run_count, _value in metric_runs
        )
        return increasing or decreasing or sustained_runs >= 2

    def has_nonexempt_short_deviation(
        metric_runs: Sequence[tuple[int, int, int]],
    ) -> bool:
        if len(metric_runs) < 3:
            return False
        has_sustained_baseline = any(
            run_count >= plateau_proof_samples for _run_start, run_count, _value in metric_runs
        )
        has_short_interior_run = any(
            run_count < plateau_proof_samples for _run_start, run_count, _value in metric_runs[1:-1]
        )
        return has_sustained_baseline and has_short_interior_run

    def is_exact_bounded_modular_orbit(
        metric_runs: Sequence[tuple[int, int, int]],
    ) -> bool:
        if len(metric_runs) < 3 or any(
            run_count != 1 for _run_start, run_count, _value in metric_runs
        ):
            return False
        values = tuple(value for _run_start, _run_count, value in metric_runs)
        raw_deltas = tuple(right - left for left, right in zip(values, values[1:]))
        distinct_deltas = set(raw_deltas)
        if len(distinct_deltas) != 2:
            return False
        negative_delta, positive_delta = sorted(distinct_deltas)
        if negative_delta >= 0 or positive_delta <= 0:
            return False
        if raw_deltas.count(negative_delta) < 2 or raw_deltas.count(positive_delta) < 2:
            return False
        modulus = positive_delta - negative_delta
        return max(values) - min(values) < modulus

    def has_positive_rank_score(
        early_histogram: Mapping[int, int],
        late_histogram: Mapping[int, int],
    ) -> bool:
        early_items = sorted(early_histogram.items())
        early_index = 0
        early_less_weight = 0
        score = 0
        for late_value, late_value_weight in sorted(late_histogram.items()):
            while early_index < len(early_items) and early_items[early_index][0] < late_value:
                early_less_weight += early_items[early_index][1]
                early_index += 1
            early_equal_weight = (
                early_items[early_index][1]
                if early_index < len(early_items) and early_items[early_index][0] == late_value
                else 0
            )
            early_greater_weight = half_samples - early_less_weight - early_equal_weight
            score += late_value_weight * (early_less_weight - early_greater_weight)
        pair_count = half_samples * half_samples
        compared_samples = 2 * half_samples
        return (
            score > 0
            and score * score * compared_samples
            > _RANK_SIGNIFICANCE_MULTIPLIER_SQUARED * pair_count * pair_count
        )

    def has_majority_positive_quantile_translation(
        early_histogram: Mapping[int, int],
        late_histogram: Mapping[int, int],
    ) -> bool:
        early_items = sorted(early_histogram.items())
        late_items = sorted(late_histogram.items())
        early_index = 0
        late_index = 0
        early_remaining = early_items[0][1]
        late_remaining = late_items[0][1]
        positive_shift_weights: dict[int, int] = defaultdict(int)

        while early_index < len(early_items) and late_index < len(late_items):
            paired_weight = min(early_remaining, late_remaining)
            shift = late_items[late_index][0] - early_items[early_index][0]
            if shift < 0:
                return False
            if shift > 0:
                positive_shift_weights[shift] += paired_weight

            early_remaining -= paired_weight
            late_remaining -= paired_weight
            if early_remaining == 0:
                early_index += 1
                if early_index < len(early_items):
                    early_remaining = early_items[early_index][1]
            if late_remaining == 0:
                late_index += 1
                if late_index < len(late_items):
                    late_remaining = late_items[late_index][1]

        if early_index != len(early_items) or late_index != len(late_items):
            raise ValueError("store trend quantiles lack equal weighted coverage")
        majority_shift_weight = max(positive_shift_weights.values(), default=0)
        return 2 * majority_shift_weight > half_samples

    for value_index, early_histogram, late_histogram in (
        (2, early_bytes, late_bytes),
        (3, early_objects, late_objects),
    ):
        full_metric_runs = metric_runs_from(value_index, 0)
        if len(full_metric_runs) == 2 and full_metric_runs[0][1] == 1:
            return True
        if is_exact_single_sample_deviation(full_metric_runs):
            continue
        metric_runs = metric_runs_from(value_index, warmup_samples)
        if is_exact_bounded_modular_orbit(metric_runs):
            continue
        recurring_change = recurring_cycle_is_changing(metric_runs)
        if recurring_change is False:
            continue
        if has_nonexempt_short_deviation(full_metric_runs):
            return True
        if is_exact_bounded_step(metric_runs):
            continue
        if (
            recurring_change is True
            or has_unfinished_late_change(metric_runs)
            or has_nonrecurring_multi_transition(metric_runs)
            or has_positive_rank_score(early_histogram, late_histogram)
            or has_majority_positive_quantile_translation(
                early_histogram,
                late_histogram,
            )
        ):
            return True
    return False


ExcludeAcceptanceDrill = Literal[
    "person",
    "restricted_zone",
    "intrusion",
    "loitering",
    "line_crossing",
    "fire_smoke",
    "weapon",
    "fight",
    "fall",
    "violence",
    "xclip",
    "vit",
]


class OperationalModuleDispositionV1(_FrozenModel):
    module: ExcludeAcceptanceDrill
    mode: Mode
    decided_by_role: Literal["admin"]
    decided_by_id: BoundedId

    @model_validator(mode="after")
    def shadow_only_analytics_cannot_be_operator(self) -> OperationalModuleDispositionV1:
        if self.module in _SHADOW_ONLY_ANALYTICS and self.mode == "operator":
            raise ValueError(f"{self.module} is shadow-only and cannot use operator mode")
        return self


class CameraNamespaceExpectationV1(_FrozenModel):
    camera_id: BoundedId
    source_state_id: BoundedId
    tracker_state_id: BoundedId
    analytic_state_id: BoundedId


class RepositorySourceContractV1(_FrozenModel):
    schema_version: Literal["acceptance-repository-source.v1"]
    source_identity: BoundedId
    canonical_query_sha256: Digest
    start_high_water: Annotated[int, Field(ge=0, le=9_223_372_036_854_775_807)]
    start_snapshot_sha256: Digest


class SignedRestartFaultWindowV1(_FrozenModel):
    fault_id: BoundedId
    component: Literal["runtime", "api"]
    first_sample_index: Annotated[int, Field(ge=0, le=10_000_000)]
    last_sample_index: Annotated[int, Field(ge=0, le=10_000_000)]
    from_boot_id: BoundedId
    to_boot_id: BoundedId
    schedule_sha256: Digest
    signature_sha256: Digest

    @model_validator(mode="after")
    def window_and_boot_ids_are_distinct(self) -> SignedRestartFaultWindowV1:
        if self.last_sample_index < self.first_sample_index:
            raise ValueError("restart fault window is reversed")
        if self.from_boot_id == self.to_boot_id:
            raise ValueError("restart fault must change boot identity")
        return self


class AcceptanceLimitsV1(_FrozenModel):
    """Manifest-owned finite limits for one exact 8h or 72h target run."""

    schema_version: Literal["acceptance-operational-limits.v1"]
    site_id: BoundedId
    manifest_sha256: Digest
    gate: Literal["8h", "72h"]
    started_at: datetime
    ended_at: datetime
    camera_ids: Annotated[tuple[BoundedId, ...], Field(min_length=20, max_length=20)]
    camera_namespaces: Annotated[
        tuple[CameraNamespaceExpectationV1, ...],
        Field(min_length=20, max_length=20),
    ]
    queue_sample_cadence_seconds: Annotated[float, Field(gt=0, le=300)]
    expected_queue_samples: Annotated[int, Field(ge=2, le=10_000_000)]
    queues: Annotated[tuple[QueueLimitV1, ...], Field(min_length=5, max_length=5)]
    stores: Annotated[tuple[StoreBudgetV1, ...], Field(min_length=2, max_length=2)]
    evidence_storage_root: Annotated[str, Field(min_length=1, max_length=512)]
    evidence_storage_identity: BoundedId
    repository_source: RepositorySourceContractV1
    module_dispositions: Annotated[
        tuple[OperationalModuleDispositionV1, ...],
        Field(max_length=16),
    ]
    restart_fault_windows: Annotated[
        tuple[SignedRestartFaultWindowV1, ...],
        Field(min_length=2, max_length=2),
    ]

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _utc(value, "acceptance limit timestamp")

    @field_validator("queue_sample_cadence_seconds")
    @classmethod
    def cadence_is_finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("queue cadence must be finite")
        return value

    @field_validator("evidence_storage_root")
    @classmethod
    def storage_root_is_absolute_and_canonical(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not value.startswith("/")
            or "\\" in value
            or "//" in value
            or any(part in {".", ".."} for part in path.parts)
            or path.as_posix() != value
        ):
            raise ValueError("evidence storage root must be an absolute canonical path")
        return value

    @model_validator(mode="after")
    def exact_manifest_limits(self) -> AcceptanceLimitsV1:
        expected_duration = 28_800 if self.gate == "8h" else 259_200
        duration = (self.ended_at - self.started_at).total_seconds()
        intervals = duration / self.queue_sample_cadence_seconds
        if duration != expected_duration:
            raise ValueError("acceptance limit duration differs from gate")
        if (
            not math.isclose(intervals, round(intervals), abs_tol=1e-9)
            or self.expected_queue_samples != round(intervals) + 1
        ):
            raise ValueError("expected queue samples do not exactly cover the run")
        if len(set(self.camera_ids)) != 20:
            raise ValueError("acceptance limits require exact 20 unique cameras")
        namespace_camera_ids = tuple(item.camera_id for item in self.camera_namespaces)
        namespace_ids = tuple(
            state_id
            for item in self.camera_namespaces
            for state_id in (
                item.source_state_id,
                item.tracker_state_id,
                item.analytic_state_id,
            )
        )
        if namespace_camera_ids != self.camera_ids or len(set(namespace_ids)) != 60:
            raise ValueError(
                "manifest namespace expectations must follow exact camera order "
                "and be globally unique"
            )
        if tuple(item.name for item in self.queues) != _QUEUE_NAMES:
            raise ValueError("acceptance limits require exact five canonical queues")
        if tuple(item.name for item in self.stores) != _STORE_NAMES:
            raise ValueError("acceptance limits require evidence and metadata stores")
        for budget in self.stores:
            observation_intervals = (
                budget.plateau_observation_window_seconds / self.queue_sample_cadence_seconds
            )
            if not math.isclose(
                observation_intervals,
                round(observation_intervals),
                rel_tol=0.0,
                abs_tol=1e-9,
            ):
                raise ValueError("plateau observation window must align with sample cadence")
            observation_samples = round(observation_intervals)
            complete_windows = (
                self.expected_queue_samples - observation_samples
            ) // observation_samples
            if not 2 <= complete_windows <= _MAX_PLATEAU_WINDOWS:
                raise ValueError(
                    "plateau observation window must provide 2-10000 complete post-warmup windows"
                )
        evidence_store = self.stores[0]
        if evidence_store.storage_identity != self.evidence_storage_identity:
            raise ValueError("evidence storage identity differs from store budget")
        disposition_modules = tuple(item.module for item in self.module_dispositions)
        if len(set(disposition_modules)) != len(disposition_modules) or not {
            "fire_smoke",
            "weapon",
        }.issubset(disposition_modules):
            raise ValueError("fire_smoke and weapon require explicit unique dispositions")
        if tuple(item.component for item in self.restart_fault_windows) != (
            "runtime",
            "api",
        ):
            raise ValueError("canonical signed restart windows require runtime then API")
        if any(
            item.last_sample_index >= self.expected_queue_samples
            for item in self.restart_fault_windows
        ):
            raise ValueError("restart fault window exceeds scheduled sample coverage")
        return self


class QueueObservationV1(_FrozenModel):
    name: QueueName
    depth: Annotated[int, Field(ge=0, le=1_000_000)]
    capacity: Annotated[int, Field(gt=0, le=1_000_000)]
    dropped_total: Annotated[int, Field(ge=0, le=9_223_372_036_854_775_807)]

    @model_validator(mode="after")
    def depth_fits_capacity(self) -> QueueObservationV1:
        if self.depth > self.capacity:
            raise ValueError("queue depth exceeds capacity")
        return self


class CameraNamespaceObservationV1(_FrozenModel):
    camera_id: BoundedId
    source_state_id: BoundedId
    tracker_state_id: BoundedId
    analytic_state_id: BoundedId
    observed_camera_ids: Annotated[
        tuple[BoundedId, ...],
        Field(min_length=1, max_length=20),
    ]


class StoreObservationV1(_FrozenModel):
    name: StoreName
    storage_identity: BoundedId
    used_bytes: Annotated[int, Field(ge=0, le=1_000_000_000_000)]
    object_count: Annotated[int, Field(ge=0, le=10_000_000)]
    declared_max_bytes: Annotated[int, Field(gt=0, le=1_000_000_000_000)]
    declared_max_objects: Annotated[int, Field(gt=0, le=10_000_000)]


class OperationalSampleSpanV1(_FrozenModel):
    """Run-length encoding of identical exhaustive scheduled observations."""

    first_sample_index: Annotated[int, Field(ge=0, le=10_000_000)]
    sample_count: Annotated[int, Field(ge=1, le=10_000_000)]
    queues: Annotated[
        tuple[QueueObservationV1, ...],
        Field(min_length=5, max_length=5),
    ]
    camera_namespaces: Annotated[
        tuple[CameraNamespaceObservationV1, ...],
        Field(min_length=20, max_length=20),
    ]
    stores: Annotated[
        tuple[StoreObservationV1, ...],
        Field(min_length=2, max_length=2),
    ]


class EventIdentityV1(_FrozenModel):
    event_id: BoundedId
    evidence_id: BoundedId
    camera_id: BoundedId
    module: ModuleName
    mode: Mode
    repository_sequence: Annotated[
        int,
        Field(ge=1, le=9_223_372_036_854_775_807),
    ]

    @model_validator(mode="after")
    def shadow_only_analytics_cannot_be_operator(self) -> EventIdentityV1:
        if self.module in _SHADOW_ONLY_ANALYTICS and self.mode == "operator":
            raise ValueError(f"{self.module} is shadow-only and cannot use operator mode")
        return self


class CandidateEventEvidenceV1(EventIdentityV1):
    workflow: Literal["acceptance_drill", "real_candidate"]
    occurred_at: datetime
    runtime_boot_id: BoundedId
    api_boot_id: BoundedId
    accuracy_claimed: bool

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "candidate event timestamp")


class EvidenceReadyArtifactV1(EventIdentityV1):
    sha256: Digest
    byte_size: Annotated[int, Field(gt=0, le=64_000_000)]
    duration_seconds: Annotated[float, Field(gt=0, le=60)]
    playable: bool
    storage_identity: BoundedId
    object_key: Annotated[str, Field(min_length=1, max_length=512)]
    ready_at: datetime

    @field_validator("duration_seconds")
    @classmethod
    def duration_is_finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("evidence duration must be finite")
        return value

    @field_validator("object_key")
    @classmethod
    def object_key_is_canonical(cls, value: str) -> str:
        return _canonical_relative_path(value, "evidence object key")

    @field_validator("ready_at")
    @classmethod
    def ready_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "evidence ready timestamp")


class HumanReviewEvidenceV1(EventIdentityV1):
    review_id: BoundedId
    reviewer_role: Literal["operator", "admin"]
    reviewer_id: BoundedId
    decision: Literal["confirmed", "rejected"]
    reviewed_at: datetime

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "human review timestamp")


class AuditEvidenceRowV1(EventIdentityV1):
    audit_id: BoundedId
    actor_role: Literal["operator", "admin"]
    actor_id: BoundedId
    action: Literal["review_confirmed", "review_rejected"]
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "audit timestamp")


class OutboxQueuedEvidenceV1(EventIdentityV1):
    outbox_id: BoundedId
    operator_id: BoundedId
    queued_at: datetime

    @field_validator("queued_at")
    @classmethod
    def queued_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "outbox timestamp")


class DeliveryAttemptEvidenceV1(EventIdentityV1):
    attempt_id: BoundedId
    outbox_id: BoundedId
    operator_id: BoundedId
    result: Literal["delivered", "failed", "dead_letter"]
    attempted_at: datetime

    @field_validator("attempted_at")
    @classmethod
    def attempted_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "delivery attempt timestamp")


class RepositoryAcknowledgementV1(EventIdentityV1):
    acknowledgement_id: BoundedId
    status: Literal["complete"]
    acknowledged_at: datetime

    @field_validator("acknowledged_at")
    @classmethod
    def acknowledged_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "repository acknowledgement timestamp")


class RepositoryCoverageV1(_FrozenModel):
    source_identity: BoundedId
    canonical_query_sha256: Digest
    start_high_water: Annotated[int, Field(ge=0, le=9_223_372_036_854_775_807)]
    start_snapshot_sha256: Digest
    final_high_water: Annotated[int, Field(ge=1, le=9_223_372_036_854_775_807)]
    candidate_count: Annotated[int, Field(ge=1, le=_MAX_EVENTS)]
    event_ids: Annotated[
        tuple[BoundedId, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]
    acknowledged_event_ids: Annotated[
        tuple[BoundedId, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]
    rows_sha256: Digest
    final_snapshot_sha256: Digest

    @model_validator(mode="after")
    def self_claim_is_internally_contiguous(self) -> RepositoryCoverageV1:
        if (
            self.final_high_water - self.start_high_water != self.candidate_count
            or len(self.event_ids) != self.candidate_count
            or len(self.acknowledged_event_ids) != self.candidate_count
        ):
            raise ValueError("repository coverage boundary is not contiguous")
        return self


class RetentionDrillEvidenceV1(_FrozenModel):
    drill_id: BoundedId
    store: StoreName
    camera_id: BoundedId
    namespace_id: BoundedId
    object_identity: Annotated[str, Field(min_length=1, max_length=512)]
    storage_identity: BoundedId
    created_at: datetime
    expired_at: datetime
    deleted_at: datetime
    bytes_reclaimed: Annotated[int, Field(ge=0, le=1_000_000_000_000)]
    objects_before: Annotated[int, Field(ge=0, le=10_000_000)]
    objects_after: Annotated[int, Field(ge=0, le=10_000_000)]

    @field_validator("object_identity")
    @classmethod
    def object_identity_is_canonical(cls, value: str) -> str:
        return _canonical_relative_path(value, "retention object identity")

    @field_validator("created_at", "expired_at", "deleted_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _utc(value, "retention drill timestamp")

    @model_validator(mode="after")
    def retention_order_is_possible(self) -> RetentionDrillEvidenceV1:
        if not self.created_at < self.expired_at <= self.deleted_at:
            raise ValueError("retention drill timestamps are out of order")
        if self.objects_after > self.objects_before:
            raise ValueError("retention drill cannot increase object count")
        return self


class BootTransitionEvidenceV1(_FrozenModel):
    fault_id: BoundedId
    component: Literal["runtime", "api"]
    observed_sample_index: Annotated[int, Field(ge=0, le=10_000_000)]
    from_boot_id: BoundedId
    to_boot_id: BoundedId
    schedule_sha256: Digest
    signature_sha256: Digest


class FinalEvidenceArtifactObservationV1(_FrozenModel):
    object_key: Annotated[str, Field(min_length=1, max_length=512)]
    sha256: Digest
    byte_size: Annotated[int, Field(gt=0, le=64_000_000)]
    storage_identity: BoundedId

    @field_validator("object_key")
    @classmethod
    def object_key_is_canonical(cls, value: str) -> str:
        return _canonical_relative_path(value, "final evidence artifact object key")


class FinalEvidenceStoreObservationV1(_FrozenModel):
    """Signed final aggregate plus identities of acceptance artifacts still live."""

    sample_index: Annotated[int, Field(ge=0, le=10_000_000)]
    observed_at: datetime
    storage_identity: BoundedId
    used_bytes: Annotated[int, Field(ge=0, le=1_000_000_000_000)]
    object_count: Annotated[int, Field(ge=0, le=10_000_000)]
    live_artifacts: Annotated[
        tuple[FinalEvidenceArtifactObservationV1, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]

    @field_validator("live_artifacts", mode="before")
    @classmethod
    def live_artifact_rows_are_exact_detached_copies(
        cls,
        value: object,
    ) -> tuple[FinalEvidenceArtifactObservationV1, ...]:
        if type(value) not in {list, tuple}:
            raise ValueError("final evidence store live artifacts require an exact list or tuple")
        if not 1 <= len(value) <= _MAX_EVENTS:  # type: ignore[arg-type]
            raise ValueError(
                f"final evidence store live artifacts require 1-{_MAX_EVENTS} exact artifact rows"
            )

        detached_rows: list[FinalEvidenceArtifactObservationV1] = []
        for row in value:  # type: ignore[union-attr]
            if type(row) is FinalEvidenceArtifactObservationV1:
                row_payload = row.model_dump(mode="python", round_trip=True)
            elif type(row) is dict:
                row_payload = dict(row)
            else:
                raise ValueError(
                    "final evidence store live artifacts require an exact artifact row "
                    "model or object"
                )
            detached_rows.append(FinalEvidenceArtifactObservationV1.model_validate(row_payload))
        return tuple(detached_rows)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "final evidence store observation timestamp")

    @model_validator(mode="after")
    def live_artifact_rows_are_unique(self) -> FinalEvidenceStoreObservationV1:
        object_keys = tuple(item.object_key for item in self.live_artifacts)
        if len(set(object_keys)) != len(object_keys):
            raise ValueError("final evidence store live artifact rows must be unique")
        return self


class OperationalAcceptanceEvidenceV1(_FrozenModel):
    """Bounded exhaustive rows captured from target operational stores."""

    schema_version: Literal["operational-acceptance-evidence.v1"]
    site_id: BoundedId
    manifest_sha256: Digest
    started_at: datetime
    ended_at: datetime
    sample_spans: Annotated[
        tuple[OperationalSampleSpanV1, ...],
        Field(min_length=1, max_length=_MAX_SPANS),
    ]
    final_evidence_store_observation: FinalEvidenceStoreObservationV1
    candidate_events: Annotated[
        tuple[CandidateEventEvidenceV1, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]
    evidence_ready: Annotated[
        tuple[EvidenceReadyArtifactV1, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]
    human_reviews: Annotated[
        tuple[HumanReviewEvidenceV1, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]
    audit_rows: Annotated[
        tuple[AuditEvidenceRowV1, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]
    outbox_queued: Annotated[
        tuple[OutboxQueuedEvidenceV1, ...],
        Field(max_length=_MAX_EVENTS),
    ]
    delivery_attempts: Annotated[
        tuple[DeliveryAttemptEvidenceV1, ...],
        Field(max_length=_MAX_ATTEMPTS),
    ]
    repository_acknowledgements: Annotated[
        tuple[RepositoryAcknowledgementV1, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]
    repository_coverage: RepositoryCoverageV1
    retention_drills: Annotated[
        tuple[RetentionDrillEvidenceV1, ...],
        Field(min_length=1, max_length=64),
    ]
    boot_transitions: Annotated[
        tuple[BootTransitionEvidenceV1, ...],
        Field(max_length=16),
    ]

    @field_validator("final_evidence_store_observation", mode="before")
    @classmethod
    def final_store_observation_is_an_exact_detached_copy(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> FinalEvidenceStoreObservationV1 | dict[str, object]:
        if type(value) is FinalEvidenceStoreObservationV1:
            payload = value.model_dump(mode="python", round_trip=True)
        elif type(value) is dict:
            payload = dict(value)
        else:
            raise ValueError(
                "operational evidence requires an exact final evidence store observation"
            )
        if info.mode == "json":
            return FinalEvidenceStoreObservationV1.model_validate_json(
                json.dumps(
                    payload,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        return FinalEvidenceStoreObservationV1.model_validate(payload)

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _utc(value, "operational evidence timestamp")

    @model_validator(mode="after")
    def run_window_and_canonical_order(
        self,
    ) -> OperationalAcceptanceEvidenceV1:
        if self.ended_at <= self.started_at:
            raise ValueError("operational evidence run window is reversed")
        cursor = 0
        first_namespaces: (
            tuple[
                tuple[str, str, str, str],
                ...,
            ]
            | None
        ) = None
        previous_span: OperationalSampleSpanV1 | None = None
        for span in self.sample_spans:
            if span.first_sample_index != cursor:
                raise ValueError("sample spans must use canonical contiguous sample order")
            if (
                previous_span is not None
                and span.queues == previous_span.queues
                and span.camera_namespaces == previous_span.camera_namespaces
                and span.stores == previous_span.stores
            ):
                raise ValueError(
                    "adjacent identical sample spans must be coalesced into canonical RLE"
                )
            cursor += span.sample_count
            if tuple(item.name for item in span.queues) != _QUEUE_NAMES:
                raise ValueError("queue rows must use canonical queue order")
            if tuple(item.name for item in span.stores) != _STORE_NAMES:
                raise ValueError("store rows must use canonical store order")
            namespace_rows = tuple(
                (
                    item.camera_id,
                    item.source_state_id,
                    item.tracker_state_id,
                    item.analytic_state_id,
                )
                for item in span.camera_namespaces
            )
            if first_namespaces is None:
                first_namespaces = namespace_rows
            elif namespace_rows != first_namespaces:
                raise ValueError("camera namespace identities must remain canonical across spans")
            previous_span = span
        candidate_sequences = tuple(item.repository_sequence for item in self.candidate_events)
        expected_sequences = tuple(
            range(
                self.repository_coverage.start_high_water + 1,
                self.repository_coverage.final_high_water + 1,
            )
        )
        candidate_event_ids = tuple(item.event_id for item in self.candidate_events)
        if (
            candidate_sequences != expected_sequences
            or candidate_event_ids != self.repository_coverage.event_ids
            or candidate_event_ids != self.repository_coverage.acknowledged_event_ids
        ):
            raise ValueError("candidate rows must use canonical contiguous repository order")
        stage_rows: tuple[Sequence[EventIdentityV1], ...] = (
            self.evidence_ready,
            self.human_reviews,
            self.audit_rows,
            self.outbox_queued,
            self.repository_acknowledgements,
        )
        if any(
            tuple(item.repository_sequence for item in rows)
            != tuple(sorted(item.repository_sequence for item in rows))
            for rows in stage_rows
        ):
            raise ValueError("lifecycle stage rows must use canonical repository order")
        attempt_keys = tuple(
            (item.repository_sequence, item.attempted_at, item.attempt_id)
            for item in self.delivery_attempts
        )
        if attempt_keys != tuple(sorted(attempt_keys)):
            raise ValueError("delivery attempts must use canonical order")
        if tuple(item.component for item in self.boot_transitions) != (
            "runtime",
            "api",
        ):
            raise ValueError("boot transitions must use canonical runtime/API order")
        expected_retention_keys = tuple(
            (store_name, namespace[0])
            for store_name in _STORE_NAMES
            for namespace in (first_namespaces or ())
        )
        retention_keys = tuple((item.store, item.camera_id) for item in self.retention_drills)
        if retention_keys != expected_retention_keys:
            raise ValueError("retention drills must use canonical store/camera order")
        return self


def repository_rows_sha256(
    rows: Sequence[CandidateEventEvidenceV1],
) -> str:
    """Digest exact canonical candidate rows in repository sequence order."""
    return hashlib.sha256(
        json.dumps(
            [row.model_dump(mode="json") for row in rows],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def authoritative_repository_snapshot_sha256(
    *,
    source_identity: str,
    canonical_query_sha256: str,
    start_high_water: int,
    final_high_water: int,
    row_count: int,
    rows_sha256: str,
) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "schema_version": "authoritative-repository-snapshot.v1",
                "source_identity": source_identity,
                "canonical_query_sha256": canonical_query_sha256,
                "start_high_water": start_high_water,
                "final_high_water": final_high_water,
                "row_count": row_count,
                "rows_sha256": rows_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class AuthoritativeRepositoryBoundaryV1(_FrozenModel):
    """Authority-owned final snapshot, supplied separately from run evidence."""

    schema_version: Literal["authoritative-repository-boundary.v1"]
    site_id: BoundedId
    manifest_sha256: Digest
    source_identity: BoundedId
    canonical_query_sha256: Digest
    start_high_water: Annotated[int, Field(ge=0, le=9_223_372_036_854_775_807)]
    final_high_water: Annotated[int, Field(ge=1, le=9_223_372_036_854_775_807)]
    row_count: Annotated[int, Field(ge=1, le=_MAX_EVENTS)]
    ordered_event_ids: Annotated[
        tuple[BoundedId, ...],
        Field(min_length=1, max_length=_MAX_EVENTS),
    ]
    rows_sha256: Digest
    snapshot_sha256: Digest
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def captured_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "repository boundary timestamp")

    @model_validator(mode="after")
    def boundary_is_contiguous_and_digest_bound(
        self,
    ) -> AuthoritativeRepositoryBoundaryV1:
        if (
            self.final_high_water - self.start_high_water != self.row_count
            or len(self.ordered_event_ids) != self.row_count
            or len(set(self.ordered_event_ids)) != self.row_count
        ):
            raise ValueError("authoritative repository boundary is not contiguous")
        expected = authoritative_repository_snapshot_sha256(
            source_identity=self.source_identity,
            canonical_query_sha256=self.canonical_query_sha256,
            start_high_water=self.start_high_water,
            final_high_water=self.final_high_water,
            row_count=self.row_count,
            rows_sha256=self.rows_sha256,
        )
        if self.snapshot_sha256 != expected:
            raise ValueError("authoritative repository snapshot digest mismatch")
        return self


class OperationalAcceptanceSummaryV1(_FrozenModel):
    status: Literal["pass", "fail", "not_evaluated"]
    passed: bool
    reasons: tuple[str, ...]
    covered_sample_count: Annotated[int, Field(ge=0)]
    acceptance_drill_count: Annotated[int, Field(ge=0)]
    candidate_event_count: Annotated[int, Field(ge=0)]
    confirmed_and_delivered_count: Annotated[int, Field(ge=0)]
    rejected_count: Annotated[int, Field(ge=0)]
    max_store_bytes: Mapping[StoreName, int]

    @field_validator("max_store_bytes")
    @classmethod
    def freeze_store_maxima(
        cls,
        value: Mapping[StoreName, int],
    ) -> Mapping[StoreName, int]:
        return MappingProxyType(dict(value))

    @field_serializer("max_store_bytes")
    def serialize_store_maxima(
        self,
        value: Mapping[StoreName, int],
    ) -> dict[StoreName, int]:
        return dict(value)

    @model_validator(mode="after")
    def status_and_pass_are_derived_consistently(self) -> OperationalAcceptanceSummaryV1:
        if self.passed != (self.status == "pass"):
            raise ValueError("operational summary status and pass result differ")
        if self.status == "pass" and self.reasons:
            raise ValueError("passing operational summary cannot contain failures")
        return self


def canonical_operational_json(model: BaseModel) -> bytes:
    """Serialize a strict operational model deterministically."""
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def operational_evidence_sha256(evidence: OperationalAcceptanceEvidenceV1) -> str:
    return hashlib.sha256(canonical_operational_json(evidence)).hexdigest()


def _rows_by_event(rows: Sequence[EventIdentityV1]) -> dict[str, list[EventIdentityV1]]:
    grouped: dict[str, list[EventIdentityV1]] = defaultdict(list)
    for row in rows:
        grouped[row.event_id].append(row)
    return grouped


def _identity_matches(candidate: CandidateEventEvidenceV1, row: EventIdentityV1) -> bool:
    return (
        candidate.event_id,
        candidate.evidence_id,
        candidate.camera_id,
        candidate.module,
        candidate.mode,
        candidate.repository_sequence,
    ) == (
        row.event_id,
        row.evidence_id,
        row.camera_id,
        row.module,
        row.mode,
        row.repository_sequence,
    )


def evaluate_operational_acceptance(
    limits: AcceptanceLimitsV1,
    evidence: OperationalAcceptanceEvidenceV1 | None,
    *,
    environment: Literal["test_only", "target"],
    repository_boundary: AuthoritativeRepositoryBoundaryV1 | None = None,
) -> OperationalAcceptanceSummaryV1:
    """Purely derive target operational acceptance from exhaustive evidence."""

    if type(environment) is not str or environment not in {"test_only", "target"}:
        raise ValueError("operational acceptance environment is invalid")
    if evidence is None:
        target = environment == "target"
        return OperationalAcceptanceSummaryV1(
            status="fail" if target else "not_evaluated",
            passed=False,
            reasons=(("operational evidence is required for target acceptance",) if target else ()),
            covered_sample_count=0,
            acceptance_drill_count=0,
            candidate_event_count=0,
            confirmed_and_delivered_count=0,
            rejected_count=0,
            max_store_bytes={},
        )
    if repository_boundary is None:
        target = environment == "target"
        return OperationalAcceptanceSummaryV1(
            status="fail" if target else "not_evaluated",
            passed=False,
            reasons=(
                ("authoritative repository boundary is required for target acceptance",)
                if target
                else ()
            ),
            covered_sample_count=0,
            acceptance_drill_count=0,
            candidate_event_count=len(evidence.candidate_events),
            confirmed_and_delivered_count=0,
            rejected_count=0,
            max_store_bytes={},
        )
    if type(repository_boundary) is not AuthoritativeRepositoryBoundaryV1:
        target = environment == "target"
        return OperationalAcceptanceSummaryV1(
            status="fail" if target else "not_evaluated",
            passed=False,
            reasons=(("authoritative repository boundary type is invalid",) if target else ()),
            covered_sample_count=0,
            acceptance_drill_count=0,
            candidate_event_count=len(evidence.candidate_events),
            confirmed_and_delivered_count=0,
            rejected_count=0,
            max_store_bytes={},
        )

    reasons: list[str] = []

    def fail(reason: str) -> None:
        if reason not in reasons:
            reasons.append(reason)

    typed_module_rows: tuple[tuple[Sequence[EventIdentityV1], type[EventIdentityV1]], ...] = (
        (evidence.candidate_events, CandidateEventEvidenceV1),
        (evidence.evidence_ready, EvidenceReadyArtifactV1),
        (evidence.human_reviews, HumanReviewEvidenceV1),
        (evidence.audit_rows, AuditEvidenceRowV1),
        (evidence.outbox_queued, OutboxQueuedEvidenceV1),
        (evidence.delivery_attempts, DeliveryAttemptEvidenceV1),
        (evidence.repository_acknowledgements, RepositoryAcknowledgementV1),
    )
    canonical_modules = all(
        type(disposition) is OperationalModuleDispositionV1
        and type(disposition.module) is str
        and disposition.module in _MODULE_NAMES
        and type(disposition.mode) is str
        and disposition.mode in _MODES
        for disposition in limits.module_dispositions
    ) and all(
        type(row) is expected_type
        and type(row.module) is str
        and row.module in _MODULE_NAMES
        and type(row.mode) is str
        and row.mode in _MODES
        for rows, expected_type in typed_module_rows
        for row in rows
    )
    if not canonical_modules:
        fail("operational evidence contains a noncanonical module type or vocabulary")

    if (
        evidence.site_id != limits.site_id
        or evidence.manifest_sha256 != limits.manifest_sha256
        or evidence.started_at != limits.started_at
        or evidence.ended_at != limits.ended_at
    ):
        fail("operational evidence is not bound to the exact manifest run")

    source = limits.repository_source
    coverage = evidence.repository_coverage
    computed_rows_sha256 = repository_rows_sha256(evidence.candidate_events)
    expected_snapshot_sha256 = authoritative_repository_snapshot_sha256(
        source_identity=coverage.source_identity,
        canonical_query_sha256=coverage.canonical_query_sha256,
        start_high_water=coverage.start_high_water,
        final_high_water=coverage.final_high_water,
        row_count=coverage.candidate_count,
        rows_sha256=computed_rows_sha256,
    )
    if (
        repository_boundary.site_id != limits.site_id
        or repository_boundary.manifest_sha256 != limits.manifest_sha256
        or repository_boundary.source_identity != source.source_identity
        or repository_boundary.canonical_query_sha256 != source.canonical_query_sha256
        or repository_boundary.start_high_water != source.start_high_water
        or repository_boundary.captured_at != limits.ended_at
    ):
        fail("authoritative repository boundary differs from manifest/start contract")
    if (
        coverage.source_identity != source.source_identity
        or coverage.canonical_query_sha256 != source.canonical_query_sha256
        or coverage.start_high_water != source.start_high_water
        or coverage.start_snapshot_sha256 != source.start_snapshot_sha256
        or coverage.final_high_water != repository_boundary.final_high_water
        or coverage.candidate_count != repository_boundary.row_count
        or coverage.event_ids != repository_boundary.ordered_event_ids
        or coverage.acknowledged_event_ids != repository_boundary.ordered_event_ids
        or computed_rows_sha256 != repository_boundary.rows_sha256
        or coverage.rows_sha256 != computed_rows_sha256
        or coverage.final_snapshot_sha256 != repository_boundary.snapshot_sha256
        or coverage.final_snapshot_sha256 != expected_snapshot_sha256
    ):
        fail("authoritative repository snapshot does not exactly cover candidate rows")

    queue_limits = {item.name: item for item in limits.queues}
    store_limits = {item.name: item for item in limits.stores}
    camera_ids = set(limits.camera_ids)
    cursor = 0
    previous_drops = {name: 0 for name in _QUEUE_NAMES}
    namespace_owners: dict[str, tuple[str, str]] = {}
    max_store_bytes: dict[StoreName, int] = {name: 0 for name in _STORE_NAMES}
    store_runs: dict[StoreName, list[tuple[int, int, int, int]]] = {
        name: [] for name in _STORE_NAMES
    }

    for span in evidence.sample_spans:
        if span.first_sample_index != cursor:
            fail("operational sample coverage contains a gap, overlap, or latest-only trace")
        cursor = max(cursor, span.first_sample_index + span.sample_count)
        if tuple(item.name for item in span.queues) != _QUEUE_NAMES:
            fail("every scheduled sample must contain the exact five queues")
        for queue in span.queues:
            expected = queue_limits[queue.name]
            if queue.capacity != expected.capacity:
                fail(f"{queue.name} queue capacity mutation differs from manifest limits")
            if queue.dropped_total < previous_drops[queue.name]:
                fail(f"{queue.name} queue drop counter regression")
            previous_drops[queue.name] = queue.dropped_total

        namespace_rows = {item.camera_id: item for item in span.camera_namespaces}
        observed_namespace_contract = tuple(
            (
                item.camera_id,
                item.source_state_id,
                item.tracker_state_id,
                item.analytic_state_id,
            )
            for item in span.camera_namespaces
        )
        expected_namespace_contract = tuple(
            (
                item.camera_id,
                item.source_state_id,
                item.tracker_state_id,
                item.analytic_state_id,
            )
            for item in limits.camera_namespaces
        )
        if len(namespace_rows) != 20 or set(namespace_rows) != camera_ids:
            fail("every scheduled sample must contain exact 20 camera namespaces")
        if observed_namespace_contract != expected_namespace_contract:
            fail("camera rows differ from exact ordered manifest namespace expectations")
        for namespace in span.camera_namespaces:
            if namespace.camera_id not in camera_ids:
                fail("camera namespace references a foreign camera")
            if tuple(namespace.observed_camera_ids) != (namespace.camera_id,):
                fail("explicit cross-camera namespace leakage was observed")
            for kind, state_id in (
                ("source", namespace.source_state_id),
                ("tracker", namespace.tracker_state_id),
                ("analytic", namespace.analytic_state_id),
            ):
                owner = namespace_owners.setdefault(
                    state_id,
                    (namespace.camera_id, kind),
                )
                if owner != (namespace.camera_id, kind):
                    fail(f"{kind} namespace reuse across configured cameras")

        if tuple(item.name for item in span.stores) != _STORE_NAMES:
            fail("every scheduled sample must contain exact evidence and metadata stores")
        for store in span.stores:
            budget = store_limits[store.name]
            if (
                store.storage_identity != budget.storage_identity
                or store.declared_max_bytes != budget.max_bytes
                or store.declared_max_objects != budget.max_objects
            ):
                fail(f"{store.name} store declared budget or storage identity mutated")
            if (
                store.used_bytes > budget.projected_plateau_bytes
                or store.object_count > budget.max_objects
            ):
                fail(f"{store.name} store exceeded its projected plateau")
            max_store_bytes[store.name] = max(
                max_store_bytes[store.name],
                store.used_bytes,
            )
            store_runs[store.name].append(
                (
                    span.first_sample_index,
                    span.sample_count,
                    store.used_bytes,
                    store.object_count,
                )
            )

    if cursor != limits.expected_queue_samples:
        fail("operational sample coverage does not contain every scheduled sample")
    for store_name, budget in store_limits.items():
        window_samples = round(
            budget.plateau_observation_window_seconds / limits.queue_sample_cadence_seconds
        )
        complete_windows = (limits.expected_queue_samples - window_samples) // window_samples
        try:
            scan = _scan_weighted_plateau_runs(
                store_runs[store_name],
                window_samples=window_samples,
                expected_samples=limits.expected_queue_samples,
            )
        except ValueError:
            fail(f"{store_name} store lacks complete retention-window plateau coverage")
            continue
        if complete_windows < 2 or scan.window_count != complete_windows:
            fail(f"{store_name} store lacks complete retention-window plateau coverage")
            continue
        try:
            positive_trend = _has_material_positive_store_trend(
                store_runs[store_name],
                warmup_samples=window_samples,
                expected_samples=limits.expected_queue_samples,
            )
        except ValueError:
            fail(f"{store_name} store lacks complete retention-window plateau coverage")
            continue
        if positive_trend:
            fail(
                f"{store_name} store retention-window plateau weighted mean "
                "has positive growth beyond its projected plateau"
            )

    expected_drills = {
        (store_name, camera_id) for store_name in _STORE_NAMES for camera_id in limits.camera_ids
    }
    actual_drills = {(item.store, item.camera_id) for item in evidence.retention_drills}
    if actual_drills != expected_drills or len(actual_drills) != len(evidence.retention_drills):
        fail("namespaced retention drill coverage is not exact for both stores and 20 cameras")
    artifact_object_keys = {item.object_key for item in evidence.evidence_ready}
    namespace_ids: set[str] = set()
    for drill in evidence.retention_drills:
        if drill.object_identity in artifact_object_keys:
            fail("retention drill object aliases a live artifact")
        if drill.store not in store_limits or drill.camera_id not in camera_ids:
            fail("retention drill references a foreign store or camera")
            continue
        budget = store_limits[drill.store]
        if drill.storage_identity != budget.storage_identity:
            fail("retention drill storage identity differs from the manifest store")
        if drill.namespace_id in namespace_ids or not drill.object_identity.startswith(
            f"{drill.store}/{drill.camera_id}/"
        ):
            fail("retention drill namespace is shared or foreign")
        namespace_ids.add(drill.namespace_id)
        if (
            (drill.expired_at - drill.created_at).total_seconds() != budget.retention_window_seconds
            or not limits.started_at <= drill.deleted_at <= limits.ended_at
            or drill.bytes_reclaimed <= 0
            or drill.bytes_reclaimed > budget.max_object_bytes
            or drill.bytes_reclaimed > budget.max_bytes
            or drill.objects_before - drill.objects_after != 1
            or drill.objects_before > budget.max_objects
            or drill.objects_after > budget.max_objects
        ):
            fail(
                "retention drill does not prove one bounded expired-object "
                "deletion within the signed store budget"
            )

    expected_windows = {
        (item.component, item.fault_id): item for item in limits.restart_fault_windows
    }
    actual_transitions = {
        (item.component, item.fault_id): item for item in evidence.boot_transitions
    }
    if set(actual_transitions) != set(expected_windows) or len(actual_transitions) != len(
        evidence.boot_transitions
    ):
        fail("runtime/API boot transitions differ from canonical signed restart windows")
    for key, window in expected_windows.items():
        transition = actual_transitions.get(key)
        if transition is None:
            continue
        if (
            transition.from_boot_id != window.from_boot_id
            or transition.to_boot_id != window.to_boot_id
            or transition.schedule_sha256 != window.schedule_sha256
            or transition.signature_sha256 != window.signature_sha256
            or not (
                window.first_sample_index
                <= transition.observed_sample_index
                <= window.last_sample_index
            )
        ):
            fail("runtime/API boot transitions have a wrong boot ID or signed window")

    candidates_by_id = {item.event_id: item for item in evidence.candidate_events}
    if len(candidates_by_id) != len(evidence.candidate_events):
        fail("candidate event identities must be unique")
    if len({item.evidence_id for item in evidence.candidate_events}) != len(
        evidence.candidate_events
    ):
        fail("candidate evidence identities must be unique")
    if len({item.repository_sequence for item in evidence.candidate_events}) != len(
        evidence.candidate_events
    ):
        fail("candidate repository sequences must be unique")
    lifecycle_timestamps = (
        tuple(item.occurred_at for item in evidence.candidate_events)
        + tuple(item.ready_at for item in evidence.evidence_ready)
        + tuple(item.reviewed_at for item in evidence.human_reviews)
        + tuple(item.occurred_at for item in evidence.audit_rows)
        + tuple(item.queued_at for item in evidence.outbox_queued)
        + tuple(item.attempted_at for item in evidence.delivery_attempts)
        + tuple(item.acknowledged_at for item in evidence.repository_acknowledgements)
    )
    if any(
        not limits.started_at <= timestamp <= limits.ended_at for timestamp in lifecycle_timestamps
    ):
        fail("every lifecycle timestamp must remain inside the exact run window")
    if any(
        timestamp >= evidence.final_evidence_store_observation.observed_at
        for timestamp in lifecycle_timestamps
    ):
        fail(
            "final evidence-store observation must strictly follow every "
            "terminal lifecycle timestamp"
        )

    drills = [item for item in evidence.candidate_events if item.workflow == "acceptance_drill"]
    drill_cameras = Counter(item.camera_id for item in drills)
    if (
        len(drills) != 20
        or drill_cameras != Counter({camera_id: 1 for camera_id in limits.camera_ids})
        or any(
            item.module != "acceptance_drill" or item.mode != "operator" or item.accuracy_claimed
            for item in drills
        )
    ):
        fail(
            "acceptance drill evidence must contain exactly one non-accuracy "
            "platform workflow event per configured camera"
        )

    dispositions = {item.module: item.mode for item in limits.module_dispositions}
    if any(
        item.module in _SHADOW_ONLY_ANALYTICS and item.mode == "operator"
        for item in limits.module_dispositions
    ):
        fail("shadow-only analytic disposition cannot use operator mode")
    valid_runtime_ids = {
        boot_id
        for window in limits.restart_fault_windows
        if window.component == "runtime"
        for boot_id in (window.from_boot_id, window.to_boot_id)
    }
    valid_api_ids = {
        boot_id
        for window in limits.restart_fault_windows
        if window.component == "api"
        for boot_id in (window.from_boot_id, window.to_boot_id)
    }
    transition_by_component = {item.component: item for item in evidence.boot_transitions}
    for candidate in evidence.candidate_events:
        if (
            candidate.camera_id not in camera_ids
            or not limits.started_at <= candidate.occurred_at <= limits.ended_at
        ):
            fail("candidate event contains a foreign camera or out-of-run timestamp")
        if (
            candidate.runtime_boot_id not in valid_runtime_ids
            or candidate.api_boot_id not in valid_api_ids
        ):
            fail("candidate event contains an extra runtime or API boot ID")
        event_sample_index = math.floor(
            (candidate.occurred_at - limits.started_at).total_seconds()
            / limits.queue_sample_cadence_seconds
        )
        for component, boot_id in (
            ("runtime", candidate.runtime_boot_id),
            ("api", candidate.api_boot_id),
        ):
            transition = transition_by_component.get(component)
            if transition is None:
                continue
            expected_boot_id = (
                transition.to_boot_id
                if event_sample_index >= transition.observed_sample_index
                else transition.from_boot_id
            )
            if boot_id != expected_boot_id:
                fail("candidate event boot identity timeline differs from restart evidence")
        if candidate.workflow == "real_candidate":
            if candidate.module == "acceptance_drill":
                fail("real candidate cannot reuse the acceptance drill module")
            elif dispositions.get(candidate.module) != candidate.mode:
                fail("real candidate module mode differs from explicit disposition")
            if candidate.module in _SHADOW_ONLY_ANALYTICS and candidate.mode == "operator":
                fail("shadow-only analytic candidate cannot use operator mode")
            if candidate.accuracy_claimed:
                fail("real candidate workflow cannot assert an observer accuracy claim")

    row_collections: tuple[
        tuple[str, Sequence[EventIdentityV1], int],
        ...,
    ] = (
        ("evidence-ready", evidence.evidence_ready, 1),
        ("human review", evidence.human_reviews, 1),
        ("audit", evidence.audit_rows, 1),
        ("repository acknowledgement", evidence.repository_acknowledgements, 1),
    )
    grouped_collections = {label: _rows_by_event(rows) for label, rows, _count in row_collections}
    for label, rows, expected_count in row_collections:
        grouped = grouped_collections[label]
        if set(grouped) != set(candidates_by_id):
            fail(f"{label} coverage is not exhaustive for all candidate events")
        for event_id, candidate in candidates_by_id.items():
            matches = grouped.get(event_id, [])
            if len(matches) != expected_count:
                fail(f"every candidate requires exactly one {label} row")
            elif not _identity_matches(candidate, matches[0]):
                fail(f"{label} row is not identity-linked to its candidate")

    artifacts = {
        event_id: rows[0]
        for event_id, rows in grouped_collections["evidence-ready"].items()
        if len(rows) == 1 and isinstance(rows[0], EvidenceReadyArtifactV1)
    }
    reviews = {
        event_id: rows[0]
        for event_id, rows in grouped_collections["human review"].items()
        if len(rows) == 1 and isinstance(rows[0], HumanReviewEvidenceV1)
    }
    audits = {
        event_id: rows[0]
        for event_id, rows in grouped_collections["audit"].items()
        if len(rows) == 1 and isinstance(rows[0], AuditEvidenceRowV1)
    }
    acknowledgements = {
        event_id: rows[0]
        for event_id, rows in grouped_collections["repository acknowledgement"].items()
        if len(rows) == 1 and isinstance(rows[0], RepositoryAcknowledgementV1)
    }
    principal_ids = (
        {item.decided_by_id for item in limits.module_dispositions}
        | {item.reviewer_id for item in evidence.human_reviews}
        | {item.actor_id for item in evidence.audit_rows}
        | {item.operator_id for item in evidence.outbox_queued}
        | {item.operator_id for item in evidence.delivery_attempts}
    )
    # Register each semantic owner once. Repeated evidence camera/state/fault,
    # storage/source, boot, principal, and lifecycle values are validated above
    # as explicit foreign-key references and do not create another owner.
    global_identifiers = (
        (limits.site_id,)
        + tuple(limits.camera_ids)
        + tuple(
            state_id
            for item in limits.camera_namespaces
            for state_id in (
                item.source_state_id,
                item.tracker_state_id,
                item.analytic_state_id,
            )
        )
        + tuple(item.storage_identity for item in limits.stores)
        + (source.source_identity,)
        + tuple(item.fault_id for item in limits.restart_fault_windows)
        + tuple(
            boot_id
            for item in limits.restart_fault_windows
            for boot_id in (item.from_boot_id, item.to_boot_id)
        )
        + tuple(sorted(principal_ids))
        + tuple(item.namespace_id for item in evidence.retention_drills)
        + tuple(item.object_identity for item in evidence.retention_drills)
        + tuple(item.object_key for item in evidence.evidence_ready)
        + tuple(item.event_id for item in evidence.candidate_events)
        + tuple(item.evidence_id for item in evidence.candidate_events)
        + tuple(item.review_id for item in evidence.human_reviews)
        + tuple(item.audit_id for item in evidence.audit_rows)
        + tuple(item.outbox_id for item in evidence.outbox_queued)
        + tuple(item.attempt_id for item in evidence.delivery_attempts)
        + tuple(item.acknowledgement_id for item in evidence.repository_acknowledgements)
        + tuple(item.drill_id for item in evidence.retention_drills)
    )
    if (
        len({item.object_key for item in evidence.evidence_ready}) != len(evidence.evidence_ready)
        or len({item.sha256 for item in evidence.evidence_ready}) != len(evidence.evidence_ready)
        or len(set(global_identifiers)) != len(global_identifiers)
        or len({item.repository_sequence for item in evidence.repository_acknowledgements})
        != len(evidence.repository_acknowledgements)
    ):
        fail("global identifier namespace contains lifecycle or storage identity reuse")
    evidence_budget = store_limits["evidence"]
    required_evidence_bytes = evidence_budget.fixed_overhead_bytes + sum(
        item.byte_size for item in evidence.evidence_ready
    )
    required_evidence_objects = len(evidence.evidence_ready)
    _first, _count, final_evidence_bytes, final_evidence_objects = store_runs["evidence"][-1]
    final_observation = evidence.final_evidence_store_observation
    expected_final_sample_index = limits.expected_queue_samples - 1
    expected_final_observed_at = limits.started_at + timedelta(
        seconds=expected_final_sample_index * limits.queue_sample_cadence_seconds
    )
    if (
        final_observation.sample_index != expected_final_sample_index
        or final_observation.observed_at != expected_final_observed_at
        or final_observation.storage_identity != evidence_budget.storage_identity
        or final_observation.used_bytes != final_evidence_bytes
        or final_observation.object_count != final_evidence_objects
    ):
        fail(
            "final evidence-store observation is not bound to the exact final "
            "scheduled store sample"
        )
    expected_live_artifacts = tuple(
        (
            item.object_key,
            item.sha256,
            item.byte_size,
            item.storage_identity,
        )
        for item in evidence.evidence_ready
    )
    observed_live_artifacts = tuple(
        (
            item.object_key,
            item.sha256,
            item.byte_size,
            item.storage_identity,
        )
        for item in final_observation.live_artifacts
    )
    if observed_live_artifacts != expected_live_artifacts:
        fail("final observed inventory does not bind the exact live artifact inventory")
    if any(final_observation.observed_at <= item.ready_at for item in evidence.evidence_ready):
        fail("final evidence-store observation must strictly follow every evidence-ready artifact")
    has_final_joint_evidence_inventory = (
        final_evidence_bytes >= required_evidence_bytes
        and final_evidence_objects >= required_evidence_objects
    )
    if (
        any(
            item.byte_size > evidence_budget.max_object_bytes
            or item.storage_identity != evidence_budget.storage_identity
            for item in evidence.evidence_ready
        )
        or len(evidence.evidence_ready) > evidence_budget.max_objects
        or not has_final_joint_evidence_inventory
    ):
        fail(
            "evidence artifact inventory plus fixed overhead exceeds manifest "
            "or final observed inventory lacks the required joint bytes and objects"
        )
    for event_id, candidate in candidates_by_id.items():
        artifact = artifacts.get(event_id)
        review = reviews.get(event_id)
        audit = audits.get(event_id)
        acknowledgement = acknowledgements.get(event_id)
        if artifact is not None:
            if not 4 <= artifact.duration_seconds <= 10 or not artifact.playable:
                fail("evidence-ready artifact lacks a playable 4-10 second result")
            if artifact.storage_identity != limits.evidence_storage_identity:
                fail("evidence-ready artifact storage identity differs from manifest")
            if not artifact.object_key.startswith(f"{limits.site_id}/{candidate.camera_id}/"):
                fail("evidence-ready artifact object namespace differs from event identity")
            if artifact.ready_at <= candidate.occurred_at:
                fail("evidence-ready artifact precedes its candidate")
                fail("event stages violate strict lifecycle order")
        if review is not None and artifact is not None:
            if review.reviewed_at <= artifact.ready_at:
                fail("human review precedes evidence readiness")
                fail("event stages violate strict lifecycle order")
        if audit is not None and review is not None:
            if (
                audit.action != f"review_{review.decision}"
                or audit.actor_role != review.reviewer_role
                or audit.actor_id != review.reviewer_id
                or audit.occurred_at <= review.reviewed_at
            ):
                fail("audit row does not bind the exact human review")
            if audit.occurred_at <= review.reviewed_at:
                fail("event stages violate strict lifecycle order")
        if acknowledgement is not None and audit is not None:
            if (
                acknowledgement.repository_sequence != candidate.repository_sequence
                or acknowledgement.acknowledged_at <= audit.occurred_at
            ):
                fail("repository acknowledgement does not bind the complete lifecycle")
            if acknowledgement.acknowledged_at <= audit.occurred_at:
                fail("event stages violate strict lifecycle order")

    ordered_candidates = sorted(
        evidence.candidate_events,
        key=lambda item: item.repository_sequence,
    )
    expected_sequences = list(
        range(
            evidence.repository_coverage.start_high_water + 1,
            evidence.repository_coverage.final_high_water + 1,
        )
    )
    actual_sequences = [item.repository_sequence for item in ordered_candidates]
    ordered_event_ids = tuple(item.event_id for item in ordered_candidates)
    if (
        evidence.repository_coverage.candidate_count != len(ordered_candidates)
        or expected_sequences != actual_sequences
        or tuple(evidence.repository_coverage.event_ids) != ordered_event_ids
        or tuple(evidence.repository_coverage.acknowledged_event_ids) != ordered_event_ids
        or set(acknowledgements) != set(ordered_event_ids)
    ):
        fail("repository acknowledgement coverage has event or sequence holes")

    outbox_by_event = _rows_by_event(evidence.outbox_queued)
    attempts_by_event = _rows_by_event(evidence.delivery_attempts)
    if not set(outbox_by_event).issubset(candidates_by_id) or not set(attempts_by_event).issubset(
        candidates_by_id
    ):
        fail("orphan notification lifecycle row references an unknown candidate")
    outbox_by_id = {item.outbox_id: item for item in evidence.outbox_queued}
    if len(outbox_by_id) != len(evidence.outbox_queued):
        fail("notification outbox identities must be unique")
    if len({item.attempt_id for item in evidence.delivery_attempts}) != len(
        evidence.delivery_attempts
    ):
        fail("delivery attempt identities must be unique")
    confirmed_and_delivered = 0
    rejected_count = 0
    for event_id, candidate in candidates_by_id.items():
        review = reviews.get(event_id)
        if review is None:
            continue
        outbox_rows = outbox_by_event.get(event_id, [])
        attempt_rows = attempts_by_event.get(event_id, [])
        shadow_only_analytic = candidate.module in _SHADOW_ONLY_ANALYTICS
        should_notify = (
            review.decision == "confirmed"
            and candidate.mode == "operator"
            and not shadow_only_analytic
        )
        if review.decision == "rejected":
            rejected_count += 1
        if shadow_only_analytic and (outbox_rows or attempt_rows):
            fail("shadow-only analytic lifecycle entered notification delivery")
        if candidate.mode in {"shadow", "disabled"} and (outbox_rows or attempt_rows):
            fail("shadow or disabled lifecycle entered notification delivery")
        if should_notify:
            if len(outbox_rows) != 1 or not attempt_rows:
                fail("confirmed operator lifecycle lacks queued and attempted stages")
            elif any(
                not _identity_matches(candidate, row) for row in (*outbox_rows, *attempt_rows)
            ):
                fail("notification lifecycle is not identity-linked to its candidate")
            else:
                outbox = outbox_rows[0]
                if isinstance(outbox, OutboxQueuedEvidenceV1):
                    audit = audits.get(event_id)
                    if (
                        outbox.operator_id != review.reviewer_id
                        or audit is None
                        or outbox.queued_at <= audit.occurred_at
                    ):
                        fail("confirmed audit precedes outbox and binds the confirming operator")
                    if audit is not None and outbox.queued_at <= audit.occurred_at:
                        fail("event stages violate strict lifecycle order")
                    for attempt in attempt_rows:
                        if not isinstance(attempt, DeliveryAttemptEvidenceV1):
                            continue
                        if (
                            attempt.outbox_id != outbox.outbox_id
                            or attempt.operator_id != review.reviewer_id
                            or attempt.attempted_at <= outbox.queued_at
                        ):
                            fail("delivery attempt does not bind its queued outbox row")
                        if attempt.attempted_at <= outbox.queued_at:
                            fail("event stages violate strict lifecycle order")
                    acknowledgement = acknowledgements.get(event_id)
                    if acknowledgement is None or any(
                        isinstance(attempt, DeliveryAttemptEvidenceV1)
                        and acknowledgement.acknowledged_at <= attempt.attempted_at
                        for attempt in attempt_rows
                    ):
                        fail("repository acknowledgement precedes a delivery attempt")
                    if acknowledgement is not None and any(
                        isinstance(attempt, DeliveryAttemptEvidenceV1)
                        and acknowledgement.acknowledged_at <= attempt.attempted_at
                        for attempt in attempt_rows
                    ):
                        fail("event stages violate strict lifecycle order")
                    if any(
                        isinstance(attempt, DeliveryAttemptEvidenceV1)
                        and attempt.result == "delivered"
                        for attempt in attempt_rows
                    ):
                        confirmed_and_delivered += 1
        elif outbox_rows or attempt_rows:
            fail("rejected or notification-ineligible lifecycle entered outbox delivery")

    for attempt in evidence.delivery_attempts:
        if attempt.outbox_id not in outbox_by_id:
            fail("delivery attempt references an unknown outbox row")
    if confirmed_and_delivered < 1:
        fail("operational evidence requires at least one confirmed and delivered outcome")
    if rejected_count < 1:
        fail("operational evidence requires at least one rejected outcome")

    passed = not reasons
    return OperationalAcceptanceSummaryV1(
        status="pass" if passed else "fail",
        passed=passed,
        reasons=tuple(reasons),
        covered_sample_count=cursor,
        acceptance_drill_count=len(drills),
        candidate_event_count=len(evidence.candidate_events),
        confirmed_and_delivered_count=confirmed_and_delivered,
        rejected_count=rejected_count,
        max_store_bytes=max_store_bytes,
    )
