from __future__ import annotations

from typing import Iterator

import cv2
import numpy as np


def iter_frames(
    source: str | int,
    stride: int = 1,
) -> Iterator[tuple[int, np.ndarray]]:
    """
    Yield (frame_index, bgr_frame) from a video file or webcam.

    Args:
        source: Path to video file (str) or camera index (int, e.g. 0).
        stride: Yield every Nth frame (1 = every frame, 2 = every other, etc.)

    Yields:
        (frame_index, frame) where frame is a uint8 BGR numpy array.
        frame_index starts at 0 and increments by 1 per yielded frame.

    Raises:
        RuntimeError if the source cannot be opened.
    """
    cap = cv2.VideoCapture(source)
    if not cap.isOpened():
        raise RuntimeError(f"Cannot open video source: {source!r}")

    frame_index = 0
    raw_index = 0
    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            if raw_index % stride == 0:
                yield frame_index, frame
                frame_index += 1
            raw_index += 1
    finally:
        cap.release()


def get_video_info(source: str) -> dict:
    """Returns dict with 'fps', 'width', 'height', 'frame_count' for a file."""
    cap = cv2.VideoCapture(source)
    if not cap.isOpened():
        raise RuntimeError(f"Cannot open video file: {source!r}")
    try:
        return {
            "fps": cap.get(cv2.CAP_PROP_FPS),
            "width": int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
            "height": int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
            "frame_count": int(cap.get(cv2.CAP_PROP_FRAME_COUNT)),
        }
    finally:
        cap.release()
