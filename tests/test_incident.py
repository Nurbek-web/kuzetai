"""Tests for protector/incident.py — pure Python, no model dependencies."""
from __future__ import annotations

from collections import deque

from protector.config import IncidentRule
from protector.incident import IncidentFuser, n_of_m
from protector.types import ZoneEvent

# ---------------------------------------------------------------------------
# n_of_m helper
# ---------------------------------------------------------------------------


def test_n_of_m_empty_deque_returns_false():
    assert n_of_m(deque(), 1, 3) is False


def test_n_of_m_three_of_five_true():
    window: deque[bool] = deque([True, False, True, False, True])
    assert n_of_m(window, 3, 5) is True


def test_n_of_m_two_of_five_false_when_n_is_three():
    window: deque[bool] = deque([True, False, True, False, False])
    assert n_of_m(window, 3, 5) is False


# ---------------------------------------------------------------------------
# IncidentFuser — violence
# ---------------------------------------------------------------------------


def test_push_violence_fires_after_three_consecutive():
    """3 consecutive violent clips should open a violence incident."""
    rule = IncidentRule(xclip_threshold=0.55, vit_threshold=0.6, n_of_m_clip=(3, 5))
    fuser = IncidentFuser(fps=30.0, rule=rule)

    for frame in [0, 10, 20]:
        fuser.push_violence(frame, xclip_prob=0.9, vit_prob=0.9)

    incidents = fuser.flush(20)
    violence = [i for i in incidents if i.module == "violence"]
    assert len(violence) == 1


def test_push_violence_does_not_fire_with_two_consecutive():
    """Only 2 violent clips — should not open an incident."""
    rule = IncidentRule(xclip_threshold=0.55, vit_threshold=0.6, n_of_m_clip=(3, 5))
    fuser = IncidentFuser(fps=30.0, rule=rule)

    for frame in [0, 10]:
        fuser.push_violence(frame, xclip_prob=0.9, vit_prob=0.9)
    # Push a non-violent clip to ensure no rounding
    fuser.push_violence(20, xclip_prob=0.1, vit_prob=0.1)

    incidents = fuser.flush(20)
    violence = [i for i in incidents if i.module == "violence"]
    assert len(violence) == 0


# ---------------------------------------------------------------------------
# IncidentFuser — weapon
# ---------------------------------------------------------------------------


def test_push_weapon_fires_after_five_of_ten():
    """5 of 10 frames with weapon detection should open an incident."""
    rule = IncidentRule(weapon_conf_threshold=0.5, n_of_m_weapon=(5, 10))
    fuser = IncidentFuser(fps=30.0, rule=rule)

    # Push 5 detections then 5 non-detections
    for frame in range(5):
        fuser.push_weapon(frame, max_conf=0.8)
    for frame in range(5, 10):
        fuser.push_weapon(frame, max_conf=0.1)

    incidents = fuser.flush(9)
    weapons = [i for i in incidents if i.module == "weapon"]
    assert len(weapons) == 1


def test_active_incident_tracks_peak_confidence_and_reason():
    rule = IncidentRule(weapon_conf_threshold=0.5, n_of_m_weapon=(5, 10))
    fuser = IncidentFuser(fps=10.0, rule=rule)

    for frame in range(5):
        fuser.push_weapon(frame, max_conf=0.51)
    fuser.push_weapon(5, max_conf=0.88)

    incidents = fuser.flush(5)
    weapon = next(inc for inc in incidents if inc.module == "weapon")

    assert weapon.confidence == 0.88
    assert weapon.reason == "weapon conf=0.88"


# ---------------------------------------------------------------------------
# IncidentFuser — fire
# ---------------------------------------------------------------------------


def test_push_fire_fires_after_eight_of_fifteen():
    """8 of 15 frames with fire detection should open an incident."""
    rule = IncidentRule(fire_conf_threshold=0.45, n_of_m_fire=(8, 15))
    fuser = IncidentFuser(fps=30.0, rule=rule)

    # Push 8 positive detections
    for frame in range(8):
        fuser.push_fire(frame, max_conf=0.9)
    # Push 7 non-detections
    for frame in range(8, 15):
        fuser.push_fire(frame, max_conf=0.1)

    incidents = fuser.flush(14)
    fires = [i for i in incidents if i.module == "fire_smoke"]
    assert len(fires) == 1


# ---------------------------------------------------------------------------
# IncidentFuser — flush
# ---------------------------------------------------------------------------


def test_flush_returns_incidents_list():
    """flush() should return a list (possibly empty)."""
    fuser = IncidentFuser(fps=30.0)
    result = fuser.flush(0)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# IncidentFuser — zone
# ---------------------------------------------------------------------------


def test_push_zone_emits_incident_immediately():
    """Zone events bypass debouncing and emit an Incident right away."""
    fuser = IncidentFuser(fps=30.0)
    event = ZoneEvent(
        zone_name="lobby",
        rule="intrusion",
        track_id=42,
        frame_idx=15,
        timestamp=0.5,
    )
    fuser.push_zone(15, event)

    incidents = fuser.flush(15)
    zone_incidents = [i for i in incidents if i.module == "zone"]
    assert len(zone_incidents) == 1
    inc = zone_incidents[0]
    assert "intrusion" in inc.reason
    assert "lobby" in inc.reason
    assert inc.confidence == 1.0
    assert inc.frame_start == 15
    assert inc.frame_end == 15
