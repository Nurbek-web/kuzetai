from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import numpy as np


@dataclass
class Detection:
    """A single bounding box detection."""

    class_id: int
    class_name: str
    confidence: float
    x1: int
    y1: int
    x2: int
    y2: int
    track_id: int | None = None


@dataclass
class Person:
    """A tracked person with pose keypoints."""

    track_id: int
    bbox: tuple[int, int, int, int]  # x1, y1, x2, y2
    keypoints: np.ndarray | None = None  # shape (17, 3) — x, y, conf
    foot_point: tuple[int, int] | None = None  # midpoint of ankles or bottom of bbox


@dataclass
class FrameDetections:
    """All detections for a single frame."""

    frame_idx: int
    persons: list[Person] = field(default_factory=list)
    weapons: list[Detection] = field(default_factory=list)
    fire_smoke: list[Detection] = field(default_factory=list)


@dataclass
class ZoneEvent:
    """An intrusion or loitering event from a zone."""

    zone_name: str
    rule: Literal["intrusion", "loitering"]
    track_id: int
    frame_idx: int
    timestamp: float  # seconds


@dataclass
class Incident:
    """A fused, debounced incident to log and render."""

    module: Literal["violence", "weapon", "fire_smoke", "zone"]
    start_t: float  # seconds
    end_t: float
    reason: str
    confidence: float
    frame_start: int
    frame_end: int
