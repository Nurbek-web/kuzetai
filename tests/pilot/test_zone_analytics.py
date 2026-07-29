from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from protector.pilot.domain import ObservationV1
from protector.pilot.runtime.event_engine import (
    DebounceSpec,
    EventEngine,
    LineRule,
    ZoneRule,
    bottom_centre,
)

UTC = timezone.utc
NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
EPOCH_A = UUID("10000000-0000-0000-0000-000000000001")
EPOCH_B = UUID("20000000-0000-0000-0000-000000000002")


def _person(
    *,
    seq: int,
    seconds: float,
    bbox: tuple[float, float, float, float],
    camera_id: str = "cam-01",
    stream_epoch: UUID = EPOCH_A,
    track_id: str = "track-1",
    confidence: float = 0.9,
) -> ObservationV1:
    source_time = NOW + timedelta(seconds=seconds)
    return ObservationV1(
        schema_version="observation.v1",
        observation_id=uuid4(),
        camera_id=camera_id,
        stream_epoch=stream_epoch,
        source_time=source_time,
        timestamp_quality="camera_rtcp",
        monotonic_seq=seq,
        module="person",
        class_name="person",
        confidence=confidence,
        bbox=bbox,
        track_id=track_id,
        model_artifact_id="person-v1",
        sample_kind="fresh",
        runtime_state="online",
        received_at=source_time + timedelta(milliseconds=100),
    )


def _zone_rule(*, mode: str, loiter_seconds: float = 0) -> ZoneRule:
    return ZoneRule(
        rule_id=f"north-{mode}",
        event_module=mode,
        polygon=((0.2, 0.5), (0.8, 0.5), (0.8, 0.95), (0.2, 0.95)),
        mode=mode,
        gate_mode="operator",
        reason=f"north {mode}",
        min_confidence=0.5,
        debounce=DebounceSpec(votes_required=1, sample_count=1, window_seconds=2),
        loiter_seconds=loiter_seconds,
        merge_window_seconds=0,
        cooldown_seconds=0,
    )


def test_bottom_centre_uses_normalised_feet_not_bbox_centre() -> None:
    bbox = (0.4, 0.1, 0.6, 0.8)

    assert bottom_centre(bbox) == (0.5, 0.8)

    engine = EventEngine(zone_rules=(_zone_rule(mode="intrusion"),))
    result = engine.ingest(_person(seq=1, seconds=0, bbox=bbox))
    assert len(result.triggers) == 1
    assert result.triggers[0].event.module == "intrusion"


def test_intrusion_emits_once_per_entry_until_the_track_leaves() -> None:
    engine = EventEngine(zone_rules=(_zone_rule(mode="intrusion"),))
    inside = (0.4, 0.1, 0.6, 0.8)
    outside = (0.0, 0.0, 0.1, 0.1)

    assert len(engine.ingest(_person(seq=1, seconds=0, bbox=inside)).triggers) == 1
    assert engine.ingest(_person(seq=2, seconds=1, bbox=inside)).triggers == ()
    assert engine.ingest(_person(seq=3, seconds=2, bbox=outside)).triggers == ()
    assert len(engine.ingest(_person(seq=4, seconds=3, bbox=inside)).triggers) == 1


@pytest.mark.parametrize(
    "polygon",
    [
        ((0.1, 0.1), (0.2, 0.2)),
        ((0.1, 0.1), (0.2, 0.2), (0.3, 0.3)),
        ((-0.1, 0.1), (0.8, 0.1), (0.8, 0.8)),
    ],
)
def test_zone_rule_rejects_non_normalised_or_degenerate_polygons(
    polygon: tuple[tuple[float, float], ...],
) -> None:
    with pytest.raises(ValueError):
        ZoneRule(
            rule_id="bad-zone",
            event_module="intrusion",
            polygon=polygon,
            mode="intrusion",
            gate_mode="operator",
            reason="bad",
            min_confidence=0.5,
            debounce=DebounceSpec(1, 1, 1),
            loiter_seconds=0,
            merge_window_seconds=0,
            cooldown_seconds=0,
        )


def test_loitering_uses_source_duration_across_missing_frames() -> None:
    engine = EventEngine(zone_rules=(_zone_rule(mode="loitering", loiter_seconds=5),))
    inside = (0.4, 0.1, 0.6, 0.8)

    first = engine.ingest(_person(seq=1, seconds=0, bbox=inside))
    later = engine.ingest(_person(seq=100, seconds=5.2, bbox=inside))

    assert first.triggers == ()
    assert len(later.triggers) == 1
    assert later.triggers[0].event.opened_at == NOW + timedelta(seconds=5.2)


def test_leaving_zone_or_changing_epoch_resets_loitering_track_state() -> None:
    engine = EventEngine(zone_rules=(_zone_rule(mode="loitering", loiter_seconds=5),))
    inside = (0.4, 0.1, 0.6, 0.8)
    outside = (0.0, 0.0, 0.1, 0.1)

    engine.ingest(_person(seq=1, seconds=0, bbox=inside))
    engine.ingest(_person(seq=2, seconds=3, bbox=outside))
    assert engine.ingest(_person(seq=3, seconds=6, bbox=inside)).triggers == ()
    assert (
        engine.ingest(
            _person(
                seq=1,
                seconds=8,
                bbox=inside,
                stream_epoch=EPOCH_B,
            )
        ).triggers
        == ()
    )
    assert (
        engine.ingest(
            _person(
                seq=2,
                seconds=12,
                bbox=inside,
                stream_epoch=EPOCH_B,
            )
        ).triggers
        == ()
    )


def _line_rule(direction: str) -> LineRule:
    return LineRule(
        rule_id=f"door-{direction}",
        event_module="line_crossing",
        start=(0.5, 0.1),
        end=(0.5, 0.9),
        direction=direction,
        gate_mode="operator",
        reason="door line crossed",
        min_confidence=0.5,
        debounce=DebounceSpec(votes_required=1, sample_count=1, window_seconds=2),
        merge_window_seconds=0,
        cooldown_seconds=0,
    )


def test_directional_line_crossing_is_track_camera_and_epoch_isolated() -> None:
    engine = EventEngine(line_rules=(_line_rule("positive_to_negative"),))
    left = (0.2, 0.2, 0.4, 0.5)
    right = (0.6, 0.2, 0.8, 0.5)

    assert engine.ingest(_person(seq=1, seconds=0, bbox=left)).triggers == ()
    crossed = engine.ingest(_person(seq=2, seconds=1, bbox=right))
    wrong_camera = engine.ingest(
        _person(
            seq=1,
            seconds=1,
            bbox=right,
            camera_id="cam-02",
        )
    )
    new_epoch = engine.ingest(
        _person(
            seq=1,
            seconds=2,
            bbox=left,
            stream_epoch=EPOCH_B,
        )
    )

    assert len(crossed.triggers) == 1
    assert wrong_camera.triggers == ()
    assert new_epoch.triggers == ()


def test_opposite_line_direction_does_not_trigger() -> None:
    engine = EventEngine(line_rules=(_line_rule("negative_to_positive"),))
    left = (0.2, 0.2, 0.4, 0.5)
    right = (0.6, 0.2, 0.8, 0.5)

    engine.ingest(_person(seq=1, seconds=0, bbox=left))
    result = engine.ingest(_person(seq=2, seconds=1, bbox=right))

    assert result.triggers == ()


def test_line_rule_rejects_non_normalised_or_degenerate_lines() -> None:
    with pytest.raises(ValueError):
        _line_rule("sideways")
    with pytest.raises(ValueError):
        LineRule(
            rule_id="bad-line",
            event_module="line_crossing",
            start=(0.5, 0.5),
            end=(0.5, 0.5),
            direction="positive_to_negative",
            gate_mode="operator",
            reason="bad",
            min_confidence=0.5,
            debounce=DebounceSpec(1, 1, 1),
            merge_window_seconds=0,
            cooldown_seconds=0,
        )
