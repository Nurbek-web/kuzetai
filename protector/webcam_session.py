from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass, field

import numpy as np

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

from protector.config import DEVICE, IncidentRule  # noqa: E402
from protector.fire_smoke import make_fire_smoke_detector  # noqa: E402
from protector.incident import IncidentFuser  # noqa: E402
from protector.overlay import OverlayRenderer  # noqa: E402
from protector.pose import PoseTracker  # noqa: E402
from protector.types import FrameDetections, Incident  # noqa: E402
from protector.weapons import make_weapon_detector  # noqa: E402


@dataclass
class SessionKpis:
    elapsed_str: str
    fps: float
    frames: int
    incidents: int
    last_incident_str: str
    weapon_conf: float = 0.0
    modules: list[dict] = field(default_factory=list)


class WebcamSession:
    """
    Encapsulates per-session detector stack and KPI accounting for the Gradio
    live-camera tab. Keeps Gradio UI code thin; all detection logic lives here.

    Detectors are loaded lazily on the first process_frame() call so the Gradio
    tab opens instantly.

    Interleaving: weapons run on even frames, fire on odd frames.
    Expected cost on M2 CPU: ~170 ms/frame → ~6 fps.
    """

    def __init__(self, rule: IncidentRule | None = None) -> None:
        self._rule = IncidentRule() if rule is None else rule
        # Apply live-mode overrides for confidence and N-of-M gate
        self._rule.weapon_conf_threshold = self._rule.live_weapon_conf
        self._rule.n_of_m_weapon = self._rule.live_n_of_m_weapon

        # Detector handles — None until ensure_loaded()
        self._pose_tracker = None
        self._weapon_det = None
        self._fire_det = None
        self._fuser: IncidentFuser | None = None
        self._renderer = None

        # Per-frame state
        self._frame_idx: int = 0
        self._last_weapon: list = []
        self._last_fire: list = []
        self._prev_active: set[str] = set()

        # KPI tracking
        self._fps_buffer: deque[float] = deque(maxlen=30)
        self._last_frame_time: float = 0.0
        self._session_start: float = 0.0
        self._incident_count: int = 0
        self._last_incident_at: float | None = None
        self._recent_incidents: list[Incident] = []
        self._last_weapon_conf: float = 0.0
        self._loaded: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ensure_loaded(self, frame_w: int, frame_h: int) -> None:
        """Lazily load detectors. Safe to call multiple times."""
        if self._loaded:
            return

        print("[webcam] loading pose tracker ...", flush=True)
        self._pose_tracker = PoseTracker(device=DEVICE)
        print("[webcam] loading weapon detector ...", flush=True)
        self._weapon_det = make_weapon_detector(use_verifier=False, live_mode=True)
        print("[webcam] loading fire/smoke detector ...", flush=True)
        self._fire_det = make_fire_smoke_detector()
        self._fuser = IncidentFuser(fps=15.0, rule=self._rule)
        self._renderer = OverlayRenderer(
            frame_width=frame_w,
            frame_height=frame_h,
            fps=15.0,
            zones=[],
            active_modules=["pose", "weapons", "fire_smoke"],
        )
        self._session_start = time.time()
        self._loaded = True
        print("[webcam] ready.", flush=True)

    def process_frame(self, frame_bgr: np.ndarray) -> np.ndarray:
        """Run detection on one BGR frame; return annotated BGR frame."""
        h, w = frame_bgr.shape[:2]
        self.ensure_loaded(w, h)

        now = time.time()
        if self._last_frame_time > 0:
            dt = now - self._last_frame_time
            if dt > 0:
                self._fps_buffer.append(1.0 / dt)
        self._last_frame_time = now

        fd = FrameDetections(frame_idx=self._frame_idx)

        # Pose runs every frame — cheap and provides the skeleton visual
        for result in self._pose_tracker.track(iter([(self._frame_idx, frame_bgr)])):
            fd.persons = result.persons

        # Interleave weapons / fire to keep latency under 200 ms/frame
        if self._frame_idx % 2 == 0:
            self._last_weapon = self._weapon_det.detect(frame_bgr)
        else:
            self._last_fire = self._fire_det.detect(frame_bgr)

        fd.weapons = list(self._last_weapon)
        fd.fire_smoke = list(self._last_fire)

        # Feed both signals to the fuser every frame so N-of-M windows advance
        weapon_conf = max((d.confidence for d in fd.weapons), default=0.0)
        fire_conf = max((d.confidence for d in fd.fire_smoke), default=0.0)
        self._last_weapon_conf = weapon_conf
        self._fuser.push_weapon(self._frame_idx, weapon_conf)
        self._fuser.push_fire(self._frame_idx, fire_conf)

        # Detect newly-opened incidents
        new_active = set(self._fuser._active.keys())
        newly_opened = new_active - self._prev_active
        if newly_opened:
            self._incident_count += len(newly_opened)
            self._last_incident_at = now
            for module in newly_opened:
                for inc in reversed(self._fuser._incidents):
                    if inc.module == module:
                        self._recent_incidents.append(inc)
                        break
            if len(self._recent_incidents) > 5:
                self._recent_incidents = self._recent_incidents[-5:]
        self._prev_active = new_active

        # Build the active-incident list the renderer expects
        active = [
            next(inc for inc in reversed(self._fuser._incidents) if inc.module == module)
            for module in self._fuser._active
        ]

        annotated = self._renderer.draw_frame(frame_bgr, fd, active, [], self._frame_idx)
        self._frame_idx += 1
        return annotated

    def kpis(self) -> SessionKpis:
        fps = float(sum(self._fps_buffer) / len(self._fps_buffer)) if self._fps_buffer else 0.0

        if self._session_start:
            elapsed = time.time() - self._session_start
        else:
            elapsed = 0.0
        minutes = int(elapsed) // 60
        seconds = int(elapsed) % 60
        elapsed_str = f"{minutes:02d}:{seconds:02d}"

        if self._last_incident_at is not None:
            secs_ago = int(time.time() - self._last_incident_at)
            last_str = f"{secs_ago} сек назад"
        else:
            last_str = "—"

        modules = [
            {
                "label": "Поза",
                "key": "pose",
                "loaded": self._pose_tracker is not None,
                "active": False,
            },
            {
                "label": "Оружие",
                "key": "weapon",
                "loaded": self._weapon_det is not None,
                "active": "weapon" in self._prev_active,
            },
            {
                "label": "Дым/огонь",
                "key": "fire_smoke",
                "loaded": self._fire_det is not None,
                "active": "fire_smoke" in self._prev_active,
            },
        ]

        return SessionKpis(
            elapsed_str=elapsed_str,
            fps=round(fps, 1),
            frames=self._frame_idx,
            incidents=self._incident_count,
            last_incident_str=last_str,
            weapon_conf=self._last_weapon_conf,
            modules=modules,
        )

    def recent_incidents(self) -> list[Incident]:
        return list(reversed(self._recent_incidents))

    def reset(self) -> None:
        """Zero counters and reset fuser — detectors stay loaded."""
        self._frame_idx = 0
        self._last_weapon = []
        self._last_fire = []
        self._prev_active = set()
        self._fps_buffer.clear()
        self._last_frame_time = 0.0
        self._session_start = time.time() if self._loaded else 0.0
        self._incident_count = 0
        self._last_incident_at = None
        self._recent_incidents = []
        self._last_weapon_conf = 0.0
        if self._fuser is not None:
            self._fuser = IncidentFuser(fps=15.0, rule=self._rule)

    def release(self) -> None:
        """Tear down all detector objects."""
        if self._pose_tracker:
            self._pose_tracker.release()
        if self._weapon_det:
            self._weapon_det.release()
        if self._fire_det:
            self._fire_det.release()
        try:
            import torch
            if torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception:
            pass
        self._loaded = False
        self._pose_tracker = None
        self._weapon_det = None
        self._fire_det = None
        self._fuser = None
        self._renderer = None
