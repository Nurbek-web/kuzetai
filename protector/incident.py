from __future__ import annotations

from collections import deque

from protector.config import IncidentRule
from protector.types import Incident, ZoneEvent


def n_of_m(window: deque[bool], n: int, m: int) -> bool:
    """Returns True if at least n of the last m values in window are True."""
    recent = list(window)[-m:]
    return sum(recent) >= n


class IncidentFuser:
    def __init__(self, fps: float, rule: IncidentRule | None = None):
        self._fps = fps
        self._rule = rule or IncidentRule()
        # Sliding windows (deque of bool per module)
        self._violence_window: deque[bool] = deque(maxlen=self._rule.n_of_m_clip[1])
        self._weapon_window: deque[bool] = deque(maxlen=self._rule.n_of_m_weapon[1])
        self._fire_window: deque[bool] = deque(maxlen=self._rule.n_of_m_fire[1])
        self._incidents: list[Incident] = []
        self._active: dict[str, int] = {}  # module → frame where current incident started

    def push_violence(self, frame_idx: int, xclip_prob: float, vit_prob: float) -> None:
        """Push violence signals for this frame/window."""
        is_violent = (
            xclip_prob >= self._rule.xclip_threshold
            or vit_prob >= self._rule.vit_threshold
        )
        self._violence_window.append(is_violent)
        if n_of_m(self._violence_window, *self._rule.n_of_m_clip):
            self._open_incident("violence", frame_idx, max(xclip_prob, vit_prob),
                                f"xclip={xclip_prob:.2f} vit={vit_prob:.2f}")
        else:
            self._close_incident("violence", frame_idx)

    def push_weapon(self, frame_idx: int, max_conf: float) -> None:
        is_weapon = max_conf >= self._rule.weapon_conf_threshold
        self._weapon_window.append(is_weapon)
        if n_of_m(self._weapon_window, *self._rule.n_of_m_weapon):
            self._open_incident("weapon", frame_idx, max_conf, f"weapon conf={max_conf:.2f}")
        else:
            self._close_incident("weapon", frame_idx)

    def push_fire(self, frame_idx: int, max_conf: float) -> None:
        is_fire = max_conf >= self._rule.fire_conf_threshold
        self._fire_window.append(is_fire)
        if n_of_m(self._fire_window, *self._rule.n_of_m_fire):
            self._open_incident("fire_smoke", frame_idx, max_conf, f"fire conf={max_conf:.2f}")
        else:
            self._close_incident("fire_smoke", frame_idx)

    def push_zone(self, frame_idx: int, event: ZoneEvent) -> None:
        """Zone events bypass debouncing — emit an incident immediately."""
        t = frame_idx / self._fps
        self._incidents.append(Incident(
            module="zone",
            start_t=t, end_t=t,
            reason=f"{event.rule} in zone '{event.zone_name}' track_id={event.track_id}",
            confidence=1.0,
            frame_start=frame_idx, frame_end=frame_idx,
        ))

    def flush(self, final_frame_idx: int) -> list[Incident]:
        """Close any open incidents and return all incidents so far."""
        for module in list(self._active.keys()):
            self._close_incident(module, final_frame_idx)
        return self._incidents.copy()

    def _open_incident(self, module: str, frame_idx: int, conf: float, reason: str) -> None:
        if module not in self._active:
            self._active[module] = frame_idx
            self._incidents.append(Incident(
                module=module,
                start_t=self._active[module] / self._fps,
                end_t=frame_idx / self._fps,
                reason=reason,
                confidence=conf,
                frame_start=self._active[module],
                frame_end=frame_idx,
            ))
            return

        for inc in reversed(self._incidents):
            if inc.module == module:
                if conf > inc.confidence:
                    inc.confidence = conf
                    inc.reason = reason
                break

    def _close_incident(self, module: str, frame_idx: int) -> None:
        if module in self._active:
            # Update end time of the last incident for this module
            for inc in reversed(self._incidents):
                if inc.module == module:
                    inc.end_t = frame_idx / self._fps
                    inc.frame_end = frame_idx
                    break
            del self._active[module]
