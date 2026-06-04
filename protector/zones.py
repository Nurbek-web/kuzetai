from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from shapely.geometry import Point
from shapely.geometry import Polygon as ShapelyPolygon

from protector.types import Person, ZoneEvent


@dataclass
class Zone:
    name: str
    polygon: ShapelyPolygon          # image coordinates (pixels)
    rule: Literal["intrusion", "loitering"]
    loiter_seconds: float = 5.0      # only relevant when rule == "loitering"


def zone_from_dict(d: dict) -> Zone:
    """
    Parse a zone from a clips_manifest.yaml zone dict, e.g.:
    {name: "corridor", polygon: [[x,y], ...], rule: "loitering", loiter_seconds: 3.0}
    """
    return Zone(
        name=d["name"],
        polygon=ShapelyPolygon(d["polygon"]),
        rule=d["rule"],
        loiter_seconds=float(d.get("loiter_seconds", 5.0)),
    )


class ZoneEvaluator:
    def __init__(self, zones: list[Zone]):
        self._zones = zones
        # For loitering: track how long each track_id has been in each zone
        # Key: (zone_name, track_id) → first_frame_idx
        self._entry_frames: dict[tuple[str, int], int] = {}

    def evaluate(
        self,
        frame_idx: int,
        fps: float,
        persons: list[Person],
    ) -> list[ZoneEvent]:
        """
        Check each person's foot_point against all zones.
        Returns list of ZoneEvents triggered in this frame.
        """
        events: list[ZoneEvent] = []

        for zone in self._zones:
            for person in persons:
                # Determine the foot point to use
                if person.foot_point is not None:
                    fx, fy = person.foot_point
                else:
                    # Fall back to bottom-center of bbox
                    x1, y1, x2, y2 = person.bbox
                    fx = (x1 + x2) // 2
                    fy = y2

                inside = Point(fx, fy).within(zone.polygon)
                key = (zone.name, person.track_id)

                if zone.rule == "intrusion":
                    if inside:
                        events.append(ZoneEvent(
                            zone_name=zone.name,
                            rule="intrusion",
                            track_id=person.track_id,
                            frame_idx=frame_idx,
                            timestamp=frame_idx / fps,
                        ))
                else:  # loitering
                    if inside:
                        if key not in self._entry_frames:
                            self._entry_frames[key] = frame_idx
                        else:
                            entry_frame = self._entry_frames[key]
                            elapsed = (frame_idx - entry_frame) / fps
                            if elapsed >= zone.loiter_seconds:
                                events.append(ZoneEvent(
                                    zone_name=zone.name,
                                    rule="loitering",
                                    track_id=person.track_id,
                                    frame_idx=frame_idx,
                                    timestamp=frame_idx / fps,
                                ))
                    else:
                        # Person has left the zone — clear tracking state
                        if key in self._entry_frames:
                            del self._entry_frames[key]

        return events

    def reset(self) -> None:
        """Clear loitering state (call between clips)."""
        self._entry_frames.clear()
