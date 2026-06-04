from __future__ import annotations

import os

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"  # before any torch import

from typing import Protocol, runtime_checkable

import numpy as np

from protector.config import DEVICE, FIRE_BACKEND, LOCAL_FIRE_MODEL_PATH
from protector.types import Detection


@runtime_checkable
class FireSmokeDetector(Protocol):
    def detect(self, frame: np.ndarray) -> list[Detection]: ...

    def release(self) -> None: ...


class KeremberkeFireDetector:
    """Fire/smoke detector using keremberke/yolov8n-fire-detection from HuggingFace."""

    def __init__(self) -> None:
        from ultralytics import YOLO

        self._device = DEVICE
        try:
            self._model = YOLO("keremberke/yolov8n-fire-detection")
        except Exception:
            # Fall back to base YOLOv8n if the HF model ID is not resolvable
            import warnings

            warnings.warn(
                "Could not load keremberke/yolov8n-fire-detection; "
                "falling back to yolov8n.pt (no fire class).",
                stacklevel=2,
            )
            self._model = YOLO("yolov8n.pt")

    def detect(self, frame: np.ndarray) -> list[Detection]:
        results = self._model(frame, conf=0.3, verbose=False, device=self._device)
        detections: list[Detection] = []
        for r in results:
            if r.boxes is None:
                continue
            names = r.names
            for box in r.boxes:
                cls_id = int(box.cls[0])
                cls_name = names.get(cls_id, str(cls_id))
                conf = float(box.conf[0])
                x1, y1, x2, y2 = (int(v) for v in box.xyxy[0])
                detections.append(
                    Detection(
                        class_id=cls_id,
                        class_name=cls_name,
                        confidence=conf,
                        x1=x1,
                        y1=y1,
                        x2=x2,
                        y2=y2,
                        track_id=None,
                    )
                )
        return detections

    def release(self) -> None:
        del self._model
        try:
            import torch

            if torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception:
            pass


class HfYoloFireDetector:
    """Fire/smoke detector backed by any HuggingFace / local YOLO .pt model."""

    def __init__(
        self,
        model_path: str,
        fire_class_names: list[str],
        device: str = DEVICE,
    ) -> None:
        from ultralytics import YOLO

        self._model = YOLO(model_path)
        self._fire_class_names = {n.lower() for n in fire_class_names}
        self._device = device

    def detect(self, frame: np.ndarray) -> list[Detection]:
        results = self._model(frame, conf=0.3, verbose=False, device=self._device)
        detections: list[Detection] = []
        for r in results:
            if r.boxes is None:
                continue
            names = r.names
            for box in r.boxes:
                cls_id = int(box.cls[0])
                cls_name = names.get(cls_id, "").lower()
                if cls_name not in self._fire_class_names:
                    continue
                conf = float(box.conf[0])
                x1, y1, x2, y2 = (int(v) for v in box.xyxy[0])
                detections.append(
                    Detection(
                        class_id=cls_id,
                        class_name=cls_name,
                        confidence=conf,
                        x1=x1,
                        y1=y1,
                        x2=x2,
                        y2=y2,
                        track_id=None,
                    )
                )
        return detections

    def release(self) -> None:
        del self._model
        try:
            import torch

            if torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception:
            pass


def make_fire_smoke_detector(backend: str = FIRE_BACKEND) -> FireSmokeDetector:
    """Returns the configured FireSmokeDetector based on PROTECTOR_FIRE_BACKEND."""
    if backend == "keremberke":
        if LOCAL_FIRE_MODEL_PATH.exists():
            return HfYoloFireDetector(str(LOCAL_FIRE_MODEL_PATH), ["fire", "smoke"])
        return KeremberkeFireDetector()
    if backend.startswith("hf:"):
        parts = backend.split(":")
        return HfYoloFireDetector(
            parts[1],
            parts[2].split(",") if len(parts) > 2 else ["fire"],
        )
    raise ValueError(f"Unknown fire/smoke backend: {backend!r}")
