from __future__ import annotations

import time

import numpy as np

from protector import webcam_session as wcs
from protector.config import IncidentRule
from protector.types import Detection

# ---------------------------------------------------------------------------
# Shared fake objects
# ---------------------------------------------------------------------------


def _fake_frame(h: int = 64, w: int = 64) -> np.ndarray:
    return np.zeros((h, w, 3), dtype=np.uint8)


def _make_weapon_detection() -> Detection:
    return Detection(class_id=0, class_name="weapon", confidence=0.90, x1=5, y1=5, x2=15, y2=15)


def _make_fire_detection() -> Detection:
    return Detection(class_id=0, class_name="fire", confidence=0.80, x1=1, y1=1, x2=10, y2=10)


class FakePoseResult:
    def __init__(self):
        self.persons = []


class FakePoseTracker:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    def track(self, frames):
        for _ in frames:
            self.calls += 1
            yield FakePoseResult()

    def release(self):
        pass


class FakeDetector:
    def __init__(self, *, return_dets=None):
        self.calls = 0
        self._return = return_dets or []

    def detect(self, frame):
        self.calls += 1
        return list(self._return)

    def release(self):
        pass


class FakeRenderer:
    def __init__(self, *args, **kwargs):
        pass

    def draw_frame(self, frame, fd, active, zone_evts, frame_idx):
        return frame.copy()


def _install_fakes(monkeypatch, weapon_dets=None, fire_dets=None):
    """Patch webcam_session so no real models load; return the fake objects."""
    fake_pose = FakePoseTracker()
    fake_weapon = FakeDetector(return_dets=weapon_dets or [])
    fake_fire = FakeDetector(return_dets=fire_dets or [])

    monkeypatch.setattr(wcs, "PoseTracker", lambda **kwargs: fake_pose)
    monkeypatch.setattr(wcs, "make_weapon_detector", lambda **kwargs: fake_weapon)
    monkeypatch.setattr(wcs, "make_fire_smoke_detector", lambda: fake_fire)
    monkeypatch.setattr(wcs, "OverlayRenderer", FakeRenderer)
    return fake_pose, fake_weapon, fake_fire


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_kpis_safe_before_any_frame():
    """Brand-new session returns sensible zero state without errors."""
    sess = wcs.WebcamSession()
    kpis = sess.kpis()
    assert kpis.fps == 0.0
    assert kpis.frames == 0
    assert kpis.incidents == 0
    assert kpis.last_incident_str == "—"
    assert all(not m["loaded"] for m in kpis.modules)


def test_process_frame_pose_every_frame_weapon_fire_interleave(monkeypatch):
    """Pose runs 4×; weapon on frames 0,2; fire on frames 1,3."""
    fake_pose, fake_weapon, fake_fire = _install_fakes(monkeypatch)
    sess = wcs.WebcamSession()

    for _ in range(4):
        sess.process_frame(_fake_frame())

    assert fake_pose.calls == 4
    assert fake_weapon.calls == 2  # frames 0, 2
    assert fake_fire.calls == 2    # frames 1, 3


def test_process_frame_caches_last_detection_on_off_frame(monkeypatch):
    """Off-frames reuse the last detection from the previous run."""
    weapon_det = _make_weapon_detection()
    fake_pose, fake_weapon, fake_fire = _install_fakes(monkeypatch, weapon_dets=[weapon_det])
    sess = wcs.WebcamSession()

    # Frame 0: weapon runs → last_weapon = [weapon_det]
    # Frame 1: fire runs → fd.weapons should still be [weapon_det] from cache
    captured = []

    orig_process = wcs.WebcamSession.process_frame

    def patched(self, frame_bgr):
        result = orig_process(self, frame_bgr)
        captured.append(list(self._last_weapon))
        return result

    monkeypatch.setattr(wcs.WebcamSession, "process_frame", patched)
    sess = wcs.WebcamSession()
    sess.process_frame(_fake_frame())  # frame 0 — weapon runs
    sess.process_frame(_fake_frame())  # frame 1 — fire runs, weapon cached

    assert len(captured[0]) == 1   # after frame 0, last_weapon populated
    assert len(captured[1]) == 1   # after frame 1, last_weapon still there


def test_incident_counter_increments_once_per_open(monkeypatch):
    """Counter goes to 1 when weapon opens; stays at 1 while it stays open."""
    # Use a rule where weapon debounce fires quickly: 2 of last 3 frames
    rule = IncidentRule()
    rule.live_weapon_conf = 0.50
    rule.live_n_of_m_weapon = (2, 3)

    weapon_det = _make_weapon_detection()  # conf=0.90
    fake_pose, fake_weapon, fake_fire = _install_fakes(monkeypatch, weapon_dets=[weapon_det])
    sess = wcs.WebcamSession(rule=rule)

    # Feed 6 frames — incident should open after frame 2 (2 of 3 positive) and stay open
    for _ in range(6):
        sess.process_frame(_fake_frame())

    kpis = sess.kpis()
    assert kpis.incidents == 1
    assert kpis.last_incident_str != "—"


def test_reset_clears_counters_keeps_detectors(monkeypatch):
    """reset() zeros KPI state but keeps the same detector object identities."""
    fake_pose, fake_weapon, fake_fire = _install_fakes(monkeypatch)
    sess = wcs.WebcamSession()

    sess.process_frame(_fake_frame())
    assert sess.kpis().frames == 1

    pose_id_before = id(sess._pose_tracker)
    weapon_id_before = id(sess._weapon_det)
    fire_id_before = id(sess._fire_det)

    sess.reset()

    kpis = sess.kpis()
    assert kpis.frames == 0
    assert kpis.incidents == 0
    assert kpis.last_incident_str == "—"
    assert len(sess.recent_incidents()) == 0
    # Detectors are the same objects — no reload
    assert id(sess._pose_tracker) == pose_id_before
    assert id(sess._weapon_det) == weapon_id_before
    assert id(sess._fire_det) == fire_id_before


def test_active_modules_reflects_loaded_state(monkeypatch):
    """Modules show loaded=False before first frame, loaded=True after."""
    fake_pose, fake_weapon, fake_fire = _install_fakes(monkeypatch)
    sess = wcs.WebcamSession()

    before = sess.kpis()
    assert all(not m["loaded"] for m in before.modules)

    sess.process_frame(_fake_frame())

    after = sess.kpis()
    assert all(m["loaded"] for m in after.modules)


def test_release_clears_detector_handles(monkeypatch):
    """release() sets detector references to None."""
    fake_pose, fake_weapon, fake_fire = _install_fakes(monkeypatch)
    sess = wcs.WebcamSession()
    sess.process_frame(_fake_frame())  # ensure loaded

    assert sess._pose_tracker is not None
    sess.release()
    assert sess._pose_tracker is None
    assert sess._weapon_det is None
    assert sess._fire_det is None
    assert not sess._loaded


def test_fps_buffer_non_zero_after_two_frames(monkeypatch):
    """After two frames with a small sleep, measured FPS is finite and positive."""
    fake_pose, fake_weapon, fake_fire = _install_fakes(monkeypatch)
    sess = wcs.WebcamSession()

    sess.process_frame(_fake_frame())
    time.sleep(0.02)
    sess.process_frame(_fake_frame())

    assert sess.kpis().fps > 0
