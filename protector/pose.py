from __future__ import annotations

import os

# Must be set before any torch/ultralytics import for MPS fallback support
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

from typing import Iterator

import numpy as np

from protector.config import DEVICE, POSE_MODEL
from protector.types import FrameDetections, Person


class PoseTracker:
    def __init__(self, device: str = DEVICE, conf: float = 0.4):
        """Load YOLOv8n-pose model. Model is downloaded on first use."""
        from ultralytics import YOLO

        self._device = device
        self._conf = conf
        self._model = YOLO(POSE_MODEL)

    def track(
        self,
        frames: Iterator[tuple[int, np.ndarray]],
    ) -> Iterator[FrameDetections]:
        """
        Run pose+tracking on an iterator of (frame_idx, bgr_frame) tuples.
        Yields one FrameDetections per frame (persons only; weapons/fire fields empty).
        """
        for frame_idx, frame in frames:
            results = self._model.track(
                source=frame,
                tracker="bytetrack.yaml",
                persist=True,
                verbose=False,
                device=self._device,
                conf=self._conf,
                stream=False,
            )[0]

            persons: list[Person] = []

            boxes = results.boxes
            keypoints = results.keypoints

            if boxes is not None and len(boxes) > 0:
                xyxy = boxes.xyxy.cpu().numpy()
                track_ids = boxes.id
                ids_arr = track_ids.cpu().numpy() if track_ids is not None else None

                kp_xy = keypoints.xy.cpu().numpy() if keypoints is not None else None
                kp_conf = keypoints.conf.cpu().numpy() if keypoints is not None else None

                for i in range(len(xyxy)):
                    x1, y1, x2, y2 = (int(v) for v in xyxy[i])
                    track_id = int(ids_arr[i]) if ids_arr is not None else -1

                    # Build keypoints array (17, 3) — [x, y, conf]
                    if kp_xy is not None and kp_conf is not None:
                        xy = kp_xy[i]       # (17, 2)
                        conf = kp_conf[i]   # (17,)
                        kp_array = np.concatenate(
                            [xy, conf[:, np.newaxis]], axis=1
                        ).astype(np.float32)  # (17, 3)
                    else:
                        kp_array = None

                    # Compute foot_point
                    if kp_array is not None:
                        left_ankle_conf = kp_array[15, 2]
                        right_ankle_conf = kp_array[16, 2]
                        if left_ankle_conf >= 0.3 or right_ankle_conf >= 0.3:
                            fx = int((kp_array[15, 0] + kp_array[16, 0]) / 2)
                            fy = int((kp_array[15, 1] + kp_array[16, 1]) / 2)
                            foot_point: tuple[int, int] | None = (fx, fy)
                        else:
                            bbox_center_x = (x1 + x2) // 2
                            foot_point = (bbox_center_x, y2)
                    else:
                        bbox_center_x = (x1 + x2) // 2
                        foot_point = (bbox_center_x, y2)

                    persons.append(
                        Person(
                            track_id=track_id,
                            bbox=(x1, y1, x2, y2),
                            keypoints=kp_array,
                            foot_point=foot_point,
                        )
                    )

            yield FrameDetections(
                frame_idx=frame_idx,
                persons=persons,
                weapons=[],
                fire_smoke=[],
            )

    def release(self) -> None:
        """Release model and clear MPS cache."""
        del self._model
        self._model = None  # type: ignore[assignment]
        try:
            import torch

            if torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception:
            pass
