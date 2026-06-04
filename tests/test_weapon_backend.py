import sys
from types import SimpleNamespace

import numpy as np
import pytest

from protector import weapons
from protector.types import Detection


def test_default_weapon_backend_prefers_local_gun_knife_model(monkeypatch):
    calls = {}

    class ExistingPath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/weapon.pt"

    class MissingPath:
        def exists(self):
            return False

    class FakeDetector:
        def __init__(self, model_path, class_names, imgsz=640, **kwargs):
            calls["model_path"] = model_path
            calls["class_names"] = class_names
            calls["imgsz"] = imgsz
            calls["kwargs"] = kwargs

        def release(self):
            pass

    monkeypatch.setattr(weapons, "LOCAL_WEAPON_MODEL_PATH", ExistingPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_MODEL_PATH", MissingPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_BG_MODEL_PATH", MissingPath())
    monkeypatch.setattr(weapons, "HfYoloWeaponDetector", FakeDetector)

    detector = weapons.make_weapon_detector("coco_knife", use_verifier=False)

    assert isinstance(detector, FakeDetector)
    assert calls == {
        "model_path": "/tmp/weapon.pt",
        "class_names": ["pistol", "knife", "gun"],
        "imgsz": 1280,
        "kwargs": {"max_area_fraction": 0.05},
    }


def test_default_weapon_backend_adds_auxiliary_gun_model(monkeypatch):
    """With only the primary two paths present the ensemble has exactly 2 detectors."""
    calls = []

    class PrimaryPath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/hadi.pt"

    class GunPath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/guns.pt"

    class MissingPath:
        def exists(self):
            return False

    class FakeDetector:
        def __init__(self, model_path, class_names, imgsz=640, **kwargs):
            calls.append((model_path, class_names, imgsz, kwargs))

        def detect(self, frame):
            return []

        def release(self):
            pass

    monkeypatch.setattr(weapons, "LOCAL_WEAPON_MODEL_PATH", PrimaryPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_MODEL_PATH", GunPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_BG_MODEL_PATH", MissingPath())
    monkeypatch.setattr(weapons, "HfYoloWeaponDetector", FakeDetector)

    detector = weapons.make_weapon_detector("coco_knife", use_verifier=False)

    assert isinstance(detector, weapons.WeaponEnsembleDetector)
    assert calls == [
        ("/tmp/hadi.pt", ["pistol", "knife", "gun"], 1280, {"max_area_fraction": 0.05}),
        ("/tmp/guns.pt", ["gun", "knife"], 960, {"max_area_fraction": 0.05}),
    ]


def test_default_weapon_backend_wraps_file_pipeline_with_verifier(monkeypatch):
    class PrimaryPath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/hadi.pt"

    class MissingPath:
        def exists(self):
            return False

    class FakeDetector:
        def __init__(self, *args, **kwargs):
            pass

        def detect(self, frame):
            return []

        def release(self):
            pass

    class FakeVerifier:
        def verify(self, frame):
            return []

        def release(self):
            pass

    monkeypatch.setattr(weapons, "LOCAL_WEAPON_MODEL_PATH", PrimaryPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_MODEL_PATH", MissingPath())
    monkeypatch.setattr(weapons, "HfYoloWeaponDetector", FakeDetector)
    monkeypatch.setattr(weapons, "OwlV2WeaponVerifier", FakeVerifier)

    detector = weapons.make_weapon_detector("coco_knife")

    assert isinstance(detector, weapons.VerifiedWeaponDetector)


def test_explicit_coco_knife_backend_skips_local_model(monkeypatch):
    class FakeCocoDetector:
        pass

    monkeypatch.setattr(weapons, "CocoKnifeDetector", FakeCocoDetector)

    detector = weapons.make_weapon_detector("coco_knife_strict")

    assert isinstance(detector, FakeCocoDetector)


def test_hf_yolo_weapon_detector_uses_configured_image_size(monkeypatch):
    calls = {}

    class FakeBox:
        cls = [0]
        conf = [0.88]
        xyxy = [[1, 2, 3, 4]]

    class FakeModel:
        def __init__(self, model_path):
            calls["model_path"] = model_path

        def __call__(self, frame, conf, verbose, device, imgsz):
            calls["conf"] = conf
            calls["imgsz"] = imgsz
            calls["device"] = device
            return [SimpleNamespace(boxes=[FakeBox()], names={0: "knife"})]

    monkeypatch.setitem(sys.modules, "ultralytics", SimpleNamespace(YOLO=FakeModel))

    detector = weapons.HfYoloWeaponDetector(
        "/tmp/weapon.pt",
        ["knife"],
        imgsz=1280,
        max_area_fraction=None,
    )
    detections = detector.detect(np.zeros((8, 8, 3), dtype=np.uint8))

    assert calls["model_path"] == "/tmp/weapon.pt"
    assert calls["imgsz"] == 1280
    assert calls["conf"] == 0.3
    assert detections[0].class_name == "weapon"


def test_hf_yolo_weapon_detector_filters_oversized_boxes(monkeypatch):
    class SmallBox:
        cls = [0]
        conf = [0.88]
        xyxy = [[1, 1, 5, 5]]

    class LargeBox:
        cls = [0]
        conf = [0.99]
        xyxy = [[0, 0, 10, 10]]

    class FakeModel:
        def __init__(self, model_path):
            pass

        def __call__(self, frame, conf, verbose, device, imgsz):
            return [SimpleNamespace(boxes=[LargeBox(), SmallBox()], names={0: "knife"})]

    monkeypatch.setitem(sys.modules, "ultralytics", SimpleNamespace(YOLO=FakeModel))

    detector = weapons.HfYoloWeaponDetector(
        "/tmp/weapon.pt",
        ["knife"],
        max_area_fraction=0.5,
    )
    detections = detector.detect(np.zeros((10, 10, 3), dtype=np.uint8))

    assert len(detections) == 1
    assert detections[0].confidence == 0.88


def test_weapon_ensemble_suppresses_overlapping_boxes():
    class FirstDetector:
        def detect(self, frame):
            return [
                Detection(
                    class_id=0,
                    class_name="weapon",
                    confidence=0.6,
                    x1=0,
                    y1=0,
                    x2=10,
                    y2=10,
                )
            ]

        def release(self):
            pass

    class SecondDetector:
        def detect(self, frame):
            return [
                Detection(
                    class_id=0,
                    class_name="weapon",
                    confidence=0.9,
                    x1=1,
                    y1=1,
                    x2=11,
                    y2=11,
                )
            ]

        def release(self):
            pass

    detector = weapons.WeaponEnsembleDetector([FirstDetector(), SecondDetector()])
    detections = detector.detect(np.zeros((16, 16, 3), dtype=np.uint8))

    assert len(detections) == 1
    assert detections[0].confidence == 0.9


def test_verified_weapon_detector_ignores_candidates_below_trigger_confidence():
    class PrimaryDetector:
        def detect(self, frame):
            return [
                Detection(
                    class_id=0,
                    class_name="weapon",
                    confidence=0.64,
                    x1=10,
                    y1=10,
                    x2=30,
                    y2=30,
                )
            ]

        def release(self):
            pass

    class Verifier:
        calls = 0

        def verify(self, frame):
            self.calls += 1
            return [
                Detection(
                    class_id=0,
                    class_name="knife",
                    confidence=0.4,
                    x1=10,
                    y1=10,
                    x2=30,
                    y2=30,
                )
            ]

        def release(self):
            pass

    verifier = Verifier()
    detector = weapons.VerifiedWeaponDetector(
        PrimaryDetector(),
        verifier,
        trigger_confidence=0.65,
    )

    assert detector.detect(np.zeros((64, 64, 3), dtype=np.uint8)) == []
    assert verifier.calls == 0


def test_verified_weapon_detector_returns_fused_verified_box():
    class PrimaryDetector:
        def detect(self, frame):
            return [
                Detection(
                    class_id=0,
                    class_name="weapon",
                    confidence=0.72,
                    x1=10,
                    y1=10,
                    x2=40,
                    y2=40,
                )
            ]

        def release(self):
            pass

    class Verifier:
        def verify(self, frame):
            return [
                Detection(
                    class_id=0,
                    class_name="knife",
                    confidence=0.39,
                    x1=12,
                    y1=12,
                    x2=42,
                    y2=42,
                )
            ]

        def release(self):
            pass

    detector = weapons.VerifiedWeaponDetector(
        PrimaryDetector(),
        Verifier(),
        trigger_confidence=0.65,
        verifier_iou_threshold=0.1,
        verified_confidence_cap=0.96,
    )

    detections = detector.detect(np.zeros((64, 64, 3), dtype=np.uint8))

    assert len(detections) == 1
    assert detections[0].class_name == "weapon"
    assert detections[0].confidence > 0.9
    assert (detections[0].x1, detections[0].y1, detections[0].x2, detections[0].y2) == (
        12,
        12,
        42,
        42,
    )


def test_verified_weapon_detector_drops_confirmations_below_minimum_fused_confidence():
    class PrimaryDetector:
        def detect(self, frame):
            return [
                Detection(
                    class_id=0,
                    class_name="weapon",
                    confidence=0.65,
                    x1=10,
                    y1=10,
                    x2=40,
                    y2=40,
                )
            ]

        def release(self):
            pass

    class Verifier:
        def verify(self, frame):
            return [
                Detection(
                    class_id=0,
                    class_name="knife",
                    confidence=0.12,
                    x1=10,
                    y1=10,
                    x2=40,
                    y2=40,
                )
            ]

        def release(self):
            pass

    detector = weapons.VerifiedWeaponDetector(
        PrimaryDetector(),
        Verifier(),
        trigger_confidence=0.65,
        minimum_fused_confidence=0.8,
    )

    assert detector.detect(np.zeros((64, 64, 3), dtype=np.uint8)) == []


def test_make_weapon_detector_with_detr_uses_detr_as_verifier(monkeypatch):
    """use_detr=True makes DETR the verifier (replaces OWLv2); YOLO ensemble stays 2 models."""

    class PrimaryPath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/hadi.pt"

    class GunPath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/guns.pt"

    class MissingPath:
        def exists(self):
            return False

    class FakeYoloDetector:
        def __init__(self, *args, **kwargs):
            pass

        def detect(self, frame):
            return []

        def release(self):
            pass

    class FakeDetrDetector:
        _instances: list = []

        def __init__(self, *args, **kwargs):
            FakeDetrDetector._instances.append(self)

        def verify(self, frame):
            return []

        def release(self):
            pass

    FakeDetrDetector._instances.clear()
    monkeypatch.setattr(weapons, "LOCAL_WEAPON_MODEL_PATH", PrimaryPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_MODEL_PATH", GunPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_BG_MODEL_PATH", MissingPath())
    monkeypatch.setattr(weapons, "HfYoloWeaponDetector", FakeYoloDetector)
    monkeypatch.setattr(weapons, "NabilaDetrWeaponDetector", FakeDetrDetector)

    detector = weapons.make_weapon_detector("coco_knife", use_verifier=True, use_detr=True)

    # DETR replaces OWLv2: result is still a VerifiedWeaponDetector...
    assert isinstance(detector, weapons.VerifiedWeaponDetector)
    # ...but the inner YOLO ensemble stays at 2 models (DETR is not a candidate)
    inner = detector._detector
    assert isinstance(inner, weapons.WeaponEnsembleDetector)
    assert len(inner._detectors) == 2
    # ...and the verifier is the DETR instance, not OWLv2
    assert isinstance(detector._verifier, FakeDetrDetector)


def test_make_weapon_detector_without_detr_is_unchanged(monkeypatch):
    """use_detr=False with bg model missing → 2-detector ensemble still works."""

    class PrimaryPath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/hadi.pt"

    class GunPath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/guns.pt"

    class MissingPath:
        def exists(self):
            return False

    class FakeYoloDetector:
        def __init__(self, *args, **kwargs):
            pass

        def detect(self, frame):
            return []

        def release(self):
            pass

    class FakeVerifier:
        def verify(self, frame):
            return []

        def release(self):
            pass

    monkeypatch.setattr(weapons, "LOCAL_WEAPON_MODEL_PATH", PrimaryPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_MODEL_PATH", GunPath())
    monkeypatch.setattr(weapons, "LOCAL_GUN_BG_MODEL_PATH", MissingPath())
    monkeypatch.setattr(weapons, "HfYoloWeaponDetector", FakeYoloDetector)
    monkeypatch.setattr(weapons, "OwlV2WeaponVerifier", FakeVerifier)

    detector = weapons.make_weapon_detector("coco_knife", use_verifier=True, use_detr=False)

    assert isinstance(detector, weapons.VerifiedWeaponDetector)
    inner = detector._detector
    assert isinstance(inner, weapons.WeaponEnsembleDetector)
    assert len(inner._detectors) == 2


def test_detr_detector_filters_to_configured_label_and_area(monkeypatch):
    """NabilaDetrWeaponDetector emits only LABEL_2 boxes under the area cap."""
    from types import SimpleNamespace

    import torch

    class FakeConfig:
        id2label = {0: "LABEL_0", 1: "LABEL_1", 2: "LABEL_2", 3: "LABEL_3"}

    class FakeProcessor:
        @staticmethod
        def from_pretrained(model_id):
            return FakeProcessor()

        def __call__(self, images, return_tensors):
            return {"pixel_values": torch.zeros(1, 3, 4, 4)}

        def post_process_object_detection(self, outputs, threshold, target_sizes):
            h, w = target_sizes[0]
            # label_id 2 (LABEL_2) — small box, should pass
            # label_id 3 (LABEL_3) — person-sized box (>5% area), should be dropped
            # label_id 2 again — oversized box, should be dropped
            return [
                {
                    "scores": torch.tensor([0.70, 0.90, 0.80]),
                    "labels": torch.tensor([2, 3, 2]),
                    "boxes": torch.tensor([
                        [0, 0, 20, 20],      # LABEL_2, area=400, frame=100*100=10000 → 4% pass
                        [0, 0, 100, 100],    # LABEL_3, person-sized → must be dropped by label
                        [0, 0, 60, 60],      # LABEL_2, area=3600/10000=36% → dropped by area cap
                    ], dtype=torch.float),
                }
            ]

    class FakeModel:
        config = FakeConfig()

        @staticmethod
        def from_pretrained(model_id):
            return FakeModel()

        def to(self, device):
            return self

        def eval(self):
            return self

        def __call__(self, **kwargs):
            return SimpleNamespace()

    fake_transformers = SimpleNamespace(
        AutoImageProcessor=FakeProcessor,
        AutoModelForObjectDetection=FakeModel,
    )
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers)

    det = weapons.NabilaDetrWeaponDetector(
        model_id="fake/model",
        target_label="LABEL_2",
        score_threshold=0.55,
        max_area_fraction=0.05,
        device="cpu",
    )
    frame = np.zeros((100, 100, 3), dtype=np.uint8)
    detections = det.detect(frame)

    assert len(detections) == 1
    assert detections[0].class_name == "weapon"
    assert detections[0].confidence == pytest.approx(0.70, abs=1e-4)
    assert detections[0].x1 == 0 and detections[0].y1 == 0
    assert detections[0].x2 == 20 and detections[0].y2 == 20


def test_zcket_bg_gun_candidate_added_when_present(monkeypatch):
    """When LOCAL_GUN_BG_MODEL_PATH exists the ensemble grows to 3 detectors."""
    calls = []

    class ExistingPath:
        def __init__(self, path):
            self._path = path

        def exists(self):
            return True

        def __str__(self):
            return self._path

    class MissingPath:
        def exists(self):
            return False

    class FakeDetector:
        def __init__(self, model_path, class_names, imgsz=640, **kwargs):
            calls.append({"path": model_path, "class_names": class_names, "imgsz": imgsz, **kwargs})

        def detect(self, frame):
            return []

        def release(self):
            pass

    monkeypatch.setattr(weapons, "LOCAL_WEAPON_MODEL_PATH", ExistingPath("/tmp/hadi.pt"))
    monkeypatch.setattr(weapons, "LOCAL_GUN_MODEL_PATH", ExistingPath("/tmp/guns.pt"))
    monkeypatch.setattr(weapons, "LOCAL_GUN_BG_MODEL_PATH", ExistingPath("/tmp/bg1k.pt"))
    monkeypatch.setattr(weapons, "HfYoloWeaponDetector", FakeDetector)

    detector = weapons.make_weapon_detector("coco_knife", use_verifier=False)

    assert isinstance(detector, weapons.WeaponEnsembleDetector)
    assert len(calls) == 3
    # Third entry: Zcket bg1k gun-only candidate
    third = calls[2]
    assert third["path"] == "/tmp/bg1k.pt"
    assert third["class_names"] == []
    assert third["imgsz"] == weapons.GUN_BG_INFERENCE_SIZE
    assert third.get("allowed_class_ids") == {0}


def test_zcket_bg_gun_candidate_skipped_when_missing(monkeypatch):
    """When LOCAL_GUN_BG_MODEL_PATH does not exist the ensemble stays at 2 detectors."""
    calls = []

    class ExistingPath:
        def __init__(self, path):
            self._path = path

        def exists(self):
            return True

        def __str__(self):
            return self._path

    class MissingPath:
        def exists(self):
            return False

    class FakeDetector:
        def __init__(self, model_path, class_names, imgsz=640, **kwargs):
            calls.append(model_path)

        def detect(self, frame):
            return []

        def release(self):
            pass

    monkeypatch.setattr(weapons, "LOCAL_WEAPON_MODEL_PATH", ExistingPath("/tmp/hadi.pt"))
    monkeypatch.setattr(weapons, "LOCAL_GUN_MODEL_PATH", ExistingPath("/tmp/guns.pt"))
    monkeypatch.setattr(weapons, "LOCAL_GUN_BG_MODEL_PATH", MissingPath())
    monkeypatch.setattr(weapons, "HfYoloWeaponDetector", FakeDetector)

    detector = weapons.make_weapon_detector("coco_knife", use_verifier=False)

    assert isinstance(detector, weapons.WeaponEnsembleDetector)
    assert len(calls) == 2


def test_hf_yolo_weapon_detector_index_based_class_mapping(monkeypatch):
    """allowed_class_ids keeps boxes by index regardless of the model's class name string."""

    class FakeBox0:
        cls = [0]
        conf = [0.72]
        xyxy = [[1, 1, 3, 3]]

    class FakeBox1:
        cls = [1]
        conf = [0.90]
        xyxy = [[1, 1, 3, 3]]

    class FakeModel:
        def __init__(self, model_path):
            pass

        def __call__(self, frame, conf, verbose, device, imgsz):
            # Model with non-semantic name "0" — mirrors the real Zcket weight
            return [SimpleNamespace(boxes=[FakeBox0(), FakeBox1()], names={0: "0", 1: "other"})]

    monkeypatch.setitem(sys.modules, "ultralytics", SimpleNamespace(YOLO=FakeModel))

    detector = weapons.HfYoloWeaponDetector(
        "/tmp/bg1k.pt",
        [],                      # name allow-list unused
        imgsz=640,
        max_area_fraction=None,
        allowed_class_ids={0},   # only class index 0 → gun
    )
    detections = detector.detect(np.zeros((8, 8, 3), dtype=np.uint8))

    # Only the class-0 box should survive
    assert len(detections) == 1
    assert detections[0].class_name == "weapon"
    assert detections[0].confidence == pytest.approx(0.72, abs=1e-4)


def test_verified_weapon_detector_uses_cached_verification_between_stride_frames():
    class PrimaryDetector:
        def detect(self, frame):
            return [
                Detection(
                    class_id=0,
                    class_name="weapon",
                    confidence=0.74,
                    x1=10,
                    y1=10,
                    x2=40,
                    y2=40,
                )
            ]

        def release(self):
            pass

    class Verifier:
        def __init__(self):
            self.calls = 0

        def verify(self, frame):
            self.calls += 1
            return [
                Detection(
                    class_id=0,
                    class_name="handgun",
                    confidence=0.42,
                    x1=9,
                    y1=9,
                    x2=39,
                    y2=39,
                )
            ]

        def release(self):
            pass

    verifier = Verifier()
    detector = weapons.VerifiedWeaponDetector(
        PrimaryDetector(),
        verifier,
        trigger_confidence=0.65,
        verifier_stride_frames=5,
        verifier_cache_ttl_frames=4,
    )

    first = detector.detect(np.zeros((64, 64, 3), dtype=np.uint8))
    second = detector.detect(np.zeros((64, 64, 3), dtype=np.uint8))

    assert len(first) == 1
    assert len(second) == 1
    assert verifier.calls == 1
