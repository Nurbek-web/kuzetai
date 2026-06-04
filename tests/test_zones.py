"""Tests for protector/zones.py — pure Python, no model dependencies."""
from __future__ import annotations

from shapely.geometry import Polygon as ShapelyPolygon

from protector.types import Person
from protector.zones import Zone, ZoneEvaluator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A simple 100×100 rectangle zone with corners at (10,10)–(110,110)
RECT_POLYGON = ShapelyPolygon([(10, 10), (110, 10), (110, 110), (10, 110)])


def make_person(track_id: int, foot_point: tuple[int, int] | None = None) -> Person:
    return Person(
        track_id=track_id,
        bbox=(50, 50, 150, 150),  # x1,y1,x2,y2
        keypoints=None,
        foot_point=foot_point,
    )


# ---------------------------------------------------------------------------
# Intrusion tests
# ---------------------------------------------------------------------------


def test_intrusion_inside_emits_event():
    """Person foot_point inside polygon → ZoneEvent emitted."""
    zone = Zone(name="lobby", polygon=RECT_POLYGON, rule="intrusion")
    evaluator = ZoneEvaluator([zone])

    person = make_person(track_id=1, foot_point=(60, 60))  # inside rect
    events = evaluator.evaluate(frame_idx=10, fps=30.0, persons=[person])

    assert len(events) == 1
    assert events[0].zone_name == "lobby"
    assert events[0].rule == "intrusion"
    assert events[0].track_id == 1
    assert events[0].frame_idx == 10


def test_intrusion_outside_no_event():
    """Person foot_point outside polygon → no event."""
    zone = Zone(name="lobby", polygon=RECT_POLYGON, rule="intrusion")
    evaluator = ZoneEvaluator([zone])

    person = make_person(track_id=2, foot_point=(5, 5))  # outside rect
    events = evaluator.evaluate(frame_idx=10, fps=30.0, persons=[person])

    assert len(events) == 0


# ---------------------------------------------------------------------------
# Loitering tests
# ---------------------------------------------------------------------------


def test_loitering_below_threshold_no_event():
    """Person inside for < loiter_seconds → no event."""
    zone = Zone(name="corridor", polygon=RECT_POLYGON, rule="loitering", loiter_seconds=5.0)
    evaluator = ZoneEvaluator([zone])

    fps = 30.0
    person = make_person(track_id=3, foot_point=(60, 60))

    # Simulate 4 seconds of frames (< 5.0 s threshold)
    events = []
    for frame_idx in range(0, int(4.0 * fps)):
        events.extend(evaluator.evaluate(frame_idx=frame_idx, fps=fps, persons=[person]))

    assert len(events) == 0


def test_loitering_at_or_above_threshold_emits_event():
    """Person inside for >= loiter_seconds → ZoneEvent emitted."""
    zone = Zone(name="corridor", polygon=RECT_POLYGON, rule="loitering", loiter_seconds=5.0)
    evaluator = ZoneEvaluator([zone])

    fps = 30.0
    person = make_person(track_id=4, foot_point=(60, 60))

    # Simulate enough frames to cross the 5-second threshold
    events = []
    for frame_idx in range(0, int(6.0 * fps)):
        events.extend(evaluator.evaluate(frame_idx=frame_idx, fps=fps, persons=[person]))

    assert len(events) > 0
    assert all(e.rule == "loitering" for e in events)
    assert all(e.zone_name == "corridor" for e in events)


# ---------------------------------------------------------------------------
# reset() test
# ---------------------------------------------------------------------------


def test_reset_clears_loitering_state():
    """After reset(), a track_id that previously loitered does not re-trigger early."""
    zone = Zone(name="corridor", polygon=RECT_POLYGON, rule="loitering", loiter_seconds=5.0)
    evaluator = ZoneEvaluator([zone])

    fps = 30.0
    person = make_person(track_id=5, foot_point=(60, 60))

    # Trigger the loitering threshold
    for frame_idx in range(0, int(6.0 * fps)):
        evaluator.evaluate(frame_idx=frame_idx, fps=fps, persons=[person])

    # Reset clears all loitering state
    evaluator.reset()

    # Now re-evaluate for only 2 seconds (< threshold) — should get no events
    events = []
    for frame_idx in range(0, int(2.0 * fps)):
        events.extend(evaluator.evaluate(frame_idx=frame_idx, fps=fps, persons=[person]))

    assert len(events) == 0
