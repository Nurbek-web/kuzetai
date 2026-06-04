from __future__ import annotations

import os

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"  # before any torch import

from typing import Protocol, runtime_checkable

import numpy as np

from protector.config import (
    COCO_KNIFE_CLASS,
    DEVICE,
    GUN_BG_INFERENCE_SIZE,
    GUN_INFERENCE_SIZE,
    LOCAL_GUN_BG_MODEL_PATH,
    LOCAL_GUN_MODEL_PATH,
    LOCAL_WEAPON_MODEL_PATH,
    WEAPON_BACKEND,
    WEAPON_DETR_ENABLED,
    WEAPON_DETR_LABEL,
    WEAPON_DETR_MAX_AREA_FRACTION,
    WEAPON_DETR_MODEL,
    WEAPON_DETR_STRIDE_FRAMES,
    WEAPON_DETR_THRESHOLD,
    WEAPON_INFERENCE_SIZE,
    WEAPON_LIVE_INFERENCE_SIZE,
    WEAPON_LIVE_MAX_AREA_FRACTION,
    WEAPON_MAX_AREA_FRACTION,
    WEAPON_MODEL,
    WEAPON_NMS_IOU_THRESHOLD,
    WEAPON_VERIFIED_CONF_CAP,
    WEAPON_VERIFIED_CONF_THRESHOLD,
    WEAPON_VERIFIER_BACKEND,
    WEAPON_VERIFIER_MODEL,
    WEAPON_VERIFY_CACHE_TTL_FRAMES,
    WEAPON_VERIFY_SCORE_THRESHOLD,
    WEAPON_VERIFY_STRIDE_FRAMES,
    WEAPON_VERIFY_TRIGGER_CONF,
)
from protector.types import Detection


@runtime_checkable
class WeaponDetector(Protocol):
    def detect(self, frame: np.ndarray) -> list[Detection]: ...

    def release(self) -> None: ...


@runtime_checkable
class WeaponVerifier(Protocol):
    def verify(self, frame: np.ndarray) -> list[Detection]: ...

    def release(self) -> None: ...


class CocoKnifeDetector:
    """Detects knives using the COCO-trained YOLOv8n model (class 43)."""

    def __init__(self) -> None:
        from ultralytics import YOLO

        self._model = YOLO(WEAPON_MODEL)
        self._device = DEVICE

    def detect(self, frame: np.ndarray) -> list[Detection]:
        results = self._model(frame, conf=0.3, verbose=False, device=self._device)
        detections: list[Detection] = []
        for r in results:
            if r.boxes is None:
                continue
            for box in r.boxes:
                cls_id = int(box.cls[0])
                if cls_id != COCO_KNIFE_CLASS:
                    continue
                conf = float(box.conf[0])
                x1, y1, x2, y2 = (int(v) for v in box.xyxy[0])
                detections.append(
                    Detection(
                        class_id=cls_id,
                        class_name="knife",
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


def _normalize_class_name(name: object) -> str:
    return str(name).lower().replace("-", " ").replace("_", " ").strip()


def _box_iou(a: Detection, b: Detection) -> float:
    ix1 = max(a.x1, b.x1)
    iy1 = max(a.y1, b.y1)
    ix2 = min(a.x2, b.x2)
    iy2 = min(a.y2, b.y2)
    inter = max(0, ix2 - ix1) * max(0, iy2 - iy1)
    area_a = max(0, a.x2 - a.x1) * max(0, a.y2 - a.y1)
    area_b = max(0, b.x2 - b.x1) * max(0, b.y2 - b.y1)
    denom = area_a + area_b - inter
    return inter / denom if denom else 0.0


def _nms_detections(detections: list[Detection], iou_threshold: float) -> list[Detection]:
    kept: list[Detection] = []
    for det in sorted(detections, key=lambda d: d.confidence, reverse=True):
        if all(_box_iou(det, existing) < iou_threshold for existing in kept):
            kept.append(det)
    return kept


def _fused_confidence(
    detector_confidence: float,
    verifier_confidence: float,
    cap: float = WEAPON_VERIFIED_CONF_CAP,
) -> float:
    verifier_evidence = min(0.95, max(0.0, verifier_confidence / 0.5))
    return min(cap, 1.0 - ((1.0 - detector_confidence) * (1.0 - verifier_evidence)))


class HfYoloWeaponDetector:
    """Weapon detector backed by any HuggingFace / local YOLO .pt model."""

    def __init__(
        self,
        model_path: str,
        weapon_class_names: list[str],
        device: str = DEVICE,
        imgsz: int = WEAPON_INFERENCE_SIZE,
        max_area_fraction: float | None = WEAPON_MAX_AREA_FRACTION,
        output_class_name: str | None = "weapon",
        allowed_class_ids: set[int] | None = None,
    ) -> None:
        from ultralytics import YOLO

        self._model = YOLO(model_path)
        self._weapon_class_names = {_normalize_class_name(n) for n in weapon_class_names}
        self._allowed_class_ids = allowed_class_ids
        self._device = device
        self._imgsz = imgsz
        self._max_area_fraction = max_area_fraction
        self._output_class_name = output_class_name

    def detect(self, frame: np.ndarray) -> list[Detection]:
        results = self._model(
            frame,
            conf=0.3,
            verbose=False,
            device=self._device,
            imgsz=self._imgsz,
        )
        detections: list[Detection] = []
        frame_h, frame_w = frame.shape[:2]
        frame_area = max(1, frame_w * frame_h)
        for r in results:
            if r.boxes is None:
                continue
            names = r.names  # dict[int, str]
            for box in r.boxes:
                cls_id = int(box.cls[0])
                cls_name = _normalize_class_name(names.get(cls_id, ""))
                # Index-based allowlist takes priority (for models with non-semantic
                # class names, e.g. {0: "0"} — manual class-index → weapon mapping).
                if self._allowed_class_ids is not None:
                    if cls_id not in self._allowed_class_ids:
                        continue
                elif cls_name not in self._weapon_class_names:
                    continue
                conf = float(box.conf[0])
                x1, y1, x2, y2 = (int(v) for v in box.xyxy[0])
                box_area = max(0, x2 - x1) * max(0, y2 - y1)
                if (
                    self._max_area_fraction is not None
                    and box_area / frame_area > self._max_area_fraction
                ):
                    continue
                detections.append(
                    Detection(
                        class_id=cls_id,
                        class_name=self._output_class_name or cls_name,
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


class WeaponEnsembleDetector:
    """Combines local weapon detectors and removes duplicate boxes."""

    def __init__(
        self,
        detectors: list[WeaponDetector],
        iou_threshold: float = WEAPON_NMS_IOU_THRESHOLD,
    ) -> None:
        self._detectors = detectors
        self._iou_threshold = iou_threshold

    def detect(self, frame: np.ndarray) -> list[Detection]:
        detections: list[Detection] = []
        for detector in self._detectors:
            detections.extend(detector.detect(frame))
        return _nms_detections(detections, self._iou_threshold)

    def release(self) -> None:
        for detector in self._detectors:
            detector.release()


class OwlV2WeaponVerifier:
    """Zero-shot verifier for strong weapon candidates.

    OWLv2 is deliberately used as a second stage because it is slower than YOLO
    but tends to draw tighter boxes on visible handguns/knives in the demo clips.
    """

    def __init__(
        self,
        model_id: str = WEAPON_VERIFIER_MODEL,
        score_threshold: float = WEAPON_VERIFY_SCORE_THRESHOLD,
        device: str = DEVICE,
    ) -> None:
        self._model_id = model_id
        self._score_threshold = score_threshold
        self._device = device
        self._pipeline = None
        self._labels = ["handgun", "pistol", "gun", "knife", "blade"]

    def _load(self):
        if self._pipeline is None:
            from transformers import pipeline

            # Pipeline device support differs across transformer versions; CPU is
            # slower but reliable for the sparse verifier calls used here.
            device = -1 if self._device == "mps" else self._device
            self._pipeline = pipeline(
                "zero-shot-object-detection",
                model=self._model_id,
                device=device,
            )
        return self._pipeline

    def verify(self, frame: np.ndarray) -> list[Detection]:
        import cv2
        from PIL import Image

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        image = Image.fromarray(rgb)
        results = self._load()(
            image,
            candidate_labels=self._labels,
            threshold=self._score_threshold,
        )

        detections: list[Detection] = []
        for idx, result in enumerate(results):
            label = _normalize_class_name(result.get("label", "weapon"))
            box = result.get("box", {})
            detections.append(
                Detection(
                    class_id=idx,
                    class_name=label,
                    confidence=float(result.get("score", 0.0)),
                    x1=int(box.get("xmin", 0)),
                    y1=int(box.get("ymin", 0)),
                    x2=int(box.get("xmax", 0)),
                    y2=int(box.get("ymax", 0)),
                    track_id=None,
                )
            )
        return detections

    def release(self) -> None:
        self._pipeline = None
        try:
            import torch

            if torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception:
            pass


class NabilaDetrWeaponDetector:
    """Pre-render-only candidate detector using NabilaLM/detr-weapons-detection_40ep.

    Filters to a single label (default LABEL_2) and enforces a strict area cap
    so large person-sized boxes are never emitted. LABEL_3 fires on people/scenes
    and must not be used — only LABEL_2 was clean on benign clips in benchmarks.

    Disabled for live webcam; enabled only for run_file when use_detr=True.
    """

    def __init__(
        self,
        model_id: str = WEAPON_DETR_MODEL,
        target_label: str = WEAPON_DETR_LABEL,
        score_threshold: float = WEAPON_DETR_THRESHOLD,
        max_area_fraction: float = WEAPON_DETR_MAX_AREA_FRACTION,
        device: str = DEVICE,
        stride_frames: int = WEAPON_DETR_STRIDE_FRAMES,
    ) -> None:
        self._model_id = model_id
        self._target_label = target_label
        self._score_threshold = score_threshold
        self._max_area_fraction = max_area_fraction
        # MPS often hits missing-kernel errors in DETR's attention ops; CPU is
        # reliable and the model is only called on pre-render clips (not live).
        self._device = "cpu" if device == "mps" else device
        self._stride_frames = stride_frames
        self._frame_idx = -1
        self._cached: list[Detection] = []
        self._cache_frame_idx = -(10**9)
        self._model = None
        self._processor = None

    def _load(self):
        if self._model is None:
            print(f"[DETR] loading {self._model_id} on {self._device} ...", flush=True)
            from transformers import AutoImageProcessor, AutoModelForObjectDetection

            self._processor = AutoImageProcessor.from_pretrained(self._model_id)
            self._model = AutoModelForObjectDetection.from_pretrained(self._model_id)
            self._model.to(self._device)
            self._model.eval()
            print("[DETR] model ready", flush=True)
        return self._model, self._processor

    def detect(self, frame: np.ndarray) -> list[Detection]:
        self._frame_idx += 1
        # Return cached result on non-stride frames — avoids running DETR every frame
        if (
            self._frame_idx != 0
            and self._frame_idx % self._stride_frames != 0
        ):
            return self._cached

        import cv2
        import torch
        from PIL import Image

        model, processor = self._load()
        h, w = frame.shape[:2]
        frame_area = max(1, w * h)

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        image = Image.fromarray(rgb)
        inputs = processor(images=image, return_tensors="pt")
        inputs = {k: v.to(self._device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)

        results = processor.post_process_object_detection(
            outputs,
            threshold=self._score_threshold,
            target_sizes=[(h, w)],
        )[0]

        detections: list[Detection] = []
        for score, label_id, box in zip(
            results["scores"], results["labels"], results["boxes"]
        ):
            label = model.config.id2label.get(int(label_id), "")
            if label != self._target_label:
                continue
            x1, y1, x2, y2 = (int(v) for v in box.tolist())
            box_area = max(0, x2 - x1) * max(0, y2 - y1)
            if box_area / frame_area > self._max_area_fraction:
                continue
            detections.append(
                Detection(
                    class_id=int(label_id),
                    class_name="weapon",
                    confidence=float(score),
                    x1=x1,
                    y1=y1,
                    x2=x2,
                    y2=y2,
                    track_id=None,
                )
            )
        self._cached = detections
        self._cache_frame_idx = self._frame_idx
        return detections

    def verify(self, frame: np.ndarray) -> list[Detection]:
        """Verifier interface — bypasses stride cache, always runs inference.

        Called by VerifiedWeaponDetector (which manages its own stride). Using DETR
        as the verifier replaces the slow OWLv2 when use_detr=True.
        """
        import cv2
        import torch
        from PIL import Image

        model, processor = self._load()
        h, w = frame.shape[:2]
        frame_area = max(1, w * h)

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        image = Image.fromarray(rgb)
        inputs = processor(images=image, return_tensors="pt")
        inputs = {k: v.to(self._device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)

        results = processor.post_process_object_detection(
            outputs,
            threshold=self._score_threshold,
            target_sizes=[(h, w)],
        )[0]

        detections: list[Detection] = []
        for score, label_id, box in zip(
            results["scores"], results["labels"], results["boxes"]
        ):
            label = model.config.id2label.get(int(label_id), "")
            if label != self._target_label:
                continue
            x1, y1, x2, y2 = (int(v) for v in box.tolist())
            box_area = max(0, x2 - x1) * max(0, y2 - y1)
            if box_area / frame_area > self._max_area_fraction:
                continue
            detections.append(
                Detection(
                    class_id=int(label_id),
                    class_name="weapon",
                    confidence=float(score),
                    x1=x1,
                    y1=y1,
                    x2=x2,
                    y2=y2,
                    track_id=None,
                )
            )
        return detections

    def release(self) -> None:
        self._model = None
        self._processor = None
        try:
            import torch

            if torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception:
            pass


class VerifiedWeaponDetector:
    """Runs fast YOLO first, then confirms strong candidates with a slower verifier."""

    def __init__(
        self,
        detector: WeaponDetector,
        verifier: WeaponVerifier,
        trigger_confidence: float = WEAPON_VERIFY_TRIGGER_CONF,
        verifier_iou_threshold: float = 0.1,
        verifier_stride_frames: int = WEAPON_VERIFY_STRIDE_FRAMES,
        verifier_cache_ttl_frames: int = WEAPON_VERIFY_CACHE_TTL_FRAMES,
        minimum_fused_confidence: float = WEAPON_VERIFIED_CONF_THRESHOLD,
        verified_confidence_cap: float = WEAPON_VERIFIED_CONF_CAP,
    ) -> None:
        self._detector = detector
        self._verifier = verifier
        self._trigger_confidence = trigger_confidence
        self._verifier_iou_threshold = verifier_iou_threshold
        self._verifier_stride_frames = verifier_stride_frames
        self._verifier_cache_ttl_frames = verifier_cache_ttl_frames
        self._minimum_fused_confidence = minimum_fused_confidence
        self._verified_confidence_cap = verified_confidence_cap
        self._frame_idx = -1
        self._cached_verified: list[Detection] = []
        self._cache_frame_idx = -10**9
        self._verifier_failed = False

    def detect(self, frame: np.ndarray) -> list[Detection]:
        self._frame_idx += 1
        candidates = [
            det
            for det in self._detector.detect(frame)
            if det.confidence >= self._trigger_confidence
        ]
        if not candidates:
            return []

        verified = self._fresh_cached_verified()
        should_verify = not verified or self._frame_idx % self._verifier_stride_frames == 0
        if should_verify and not self._verifier_failed:
            try:
                verified = self._verifier.verify(frame)
                self._cached_verified = verified
                self._cache_frame_idx = self._frame_idx
            except Exception:
                self._verifier_failed = True
                verified = []

        fused = self._fuse(candidates, verified)
        return _nms_detections(fused, WEAPON_NMS_IOU_THRESHOLD)

    def _fresh_cached_verified(self) -> list[Detection]:
        if self._frame_idx - self._cache_frame_idx <= self._verifier_cache_ttl_frames:
            return self._cached_verified
        return []

    def _fuse(self, candidates: list[Detection], verified: list[Detection]) -> list[Detection]:
        fused: list[Detection] = []
        for verified_det in verified:
            best_candidate = None
            best_iou = 0.0
            for candidate in candidates:
                overlap = _box_iou(candidate, verified_det)
                if overlap > best_iou:
                    best_candidate = candidate
                    best_iou = overlap
            if best_candidate is None or best_iou < self._verifier_iou_threshold:
                continue
            confidence = _fused_confidence(
                best_candidate.confidence,
                verified_det.confidence,
                self._verified_confidence_cap,
            )
            if confidence < self._minimum_fused_confidence:
                continue
            fused.append(
                Detection(
                    class_id=best_candidate.class_id,
                    class_name="weapon",
                    confidence=confidence,
                    x1=verified_det.x1,
                    y1=verified_det.y1,
                    x2=verified_det.x2,
                    y2=verified_det.y2,
                    track_id=None,
                )
            )
        return fused

    def release(self) -> None:
        self._detector.release()
        self._verifier.release()


def _maybe_verified(
    detector: WeaponDetector, use_verifier: bool, use_detr: bool = False
) -> WeaponDetector:
    if use_detr:
        # DETR replaces OWLv2: faster (~1s/call vs 10-30s/call) and clean on benign clips.
        return VerifiedWeaponDetector(detector, NabilaDetrWeaponDetector())
    if use_verifier and WEAPON_VERIFIER_BACKEND == "owlv2":
        return VerifiedWeaponDetector(detector, OwlV2WeaponVerifier())
    return detector


def make_weapon_detector(
    backend: str = WEAPON_BACKEND,
    use_verifier: bool = True,
    use_detr: bool = WEAPON_DETR_ENABLED,
    live_mode: bool = False,
) -> WeaponDetector:
    """Returns the configured WeaponDetector based on PROTECTOR_WEAPON_BACKEND.

    use_detr=True: DETR replaces OWLv2 as the second-stage verifier. Faster and
    cleaner for pre-render. Never enable for live webcam (live_mode=True).

    live_mode=True: uses WEAPON_LIVE_INFERENCE_SIZE (640px) for YOLO — needed for
    real-time webcam. use_detr must be False in live mode.
    """
    yolo_imgsz = WEAPON_LIVE_INFERENCE_SIZE if live_mode else WEAPON_INFERENCE_SIZE
    gun_imgsz = WEAPON_LIVE_INFERENCE_SIZE if live_mode else GUN_INFERENCE_SIZE
    area_cap = WEAPON_LIVE_MAX_AREA_FRACTION if live_mode else WEAPON_MAX_AREA_FRACTION

    if backend == "coco_knife":
        if LOCAL_WEAPON_MODEL_PATH.exists():
            detectors: list[WeaponDetector] = [
                HfYoloWeaponDetector(
                    str(LOCAL_WEAPON_MODEL_PATH),
                    ["pistol", "knife", "gun"],
                    imgsz=yolo_imgsz,
                    max_area_fraction=area_cap,
                )
            ]
            if LOCAL_GUN_MODEL_PATH.exists():
                detectors.append(
                    HfYoloWeaponDetector(
                        str(LOCAL_GUN_MODEL_PATH),
                        ["gun", "knife"],
                        imgsz=gun_imgsz,
                        max_area_fraction=area_cap,
                    )
                )
            if LOCAL_GUN_BG_MODEL_PATH.exists():
                # Zcket/gun_dtct background-1k: gun-only auxiliary model.
                # model.names == {0: "0"} so we use index-based mapping (class 0 → gun).
                # Benchmarked clean at 640px: benign hug max 0.159, 0 frames ≥0.30.
                detectors.append(
                    HfYoloWeaponDetector(
                        str(LOCAL_GUN_BG_MODEL_PATH),
                        [],  # name allow-list unused — index filter handles selection
                        imgsz=GUN_BG_INFERENCE_SIZE if not live_mode else WEAPON_LIVE_INFERENCE_SIZE,
                        allowed_class_ids={0},
                        max_area_fraction=area_cap,
                    )
                )
            detector = detectors[0] if len(detectors) == 1 else WeaponEnsembleDetector(detectors)
            return _maybe_verified(detector, use_verifier, use_detr)
        return CocoKnifeDetector()
    if backend == "coco_knife_strict":
        return CocoKnifeDetector()
    if backend.startswith("hf:"):
        # e.g. "hf:Hadi959/weapon-detection-yolov8:pistol,knife"
        parts = backend.split(":")
        model_id = parts[1]
        classes = parts[2].split(",") if len(parts) > 2 else ["weapon"]
        detector = HfYoloWeaponDetector(model_id, classes, imgsz=yolo_imgsz)
        return _maybe_verified(detector, use_verifier, use_detr)
    if backend == "hadi_wuhp_ensemble":
        detectors_e: list[WeaponDetector] = [
            HfYoloWeaponDetector(
                str(LOCAL_WEAPON_MODEL_PATH),
                ["pistol", "knife", "gun"],
                imgsz=yolo_imgsz,
            ),
            HfYoloWeaponDetector(
                str(LOCAL_GUN_MODEL_PATH),
                ["gun", "knife"],
                imgsz=gun_imgsz,
            ),
        ]
        if LOCAL_GUN_BG_MODEL_PATH.exists():
            detectors_e.append(
                HfYoloWeaponDetector(
                    str(LOCAL_GUN_BG_MODEL_PATH),
                    [],
                    imgsz=GUN_BG_INFERENCE_SIZE if not live_mode else WEAPON_LIVE_INFERENCE_SIZE,
                    allowed_class_ids={0},
                )
            )
        detector = WeaponEnsembleDetector(detectors_e)
        return _maybe_verified(detector, use_verifier, use_detr)
    raise ValueError(f"Unknown weapon backend: {backend!r}")
