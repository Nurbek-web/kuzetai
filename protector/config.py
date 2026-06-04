import os
import pathlib
from dataclasses import dataclass

import torch

# ---------------------------------------------------------------------------
# Device selection
# ---------------------------------------------------------------------------


def get_device() -> str:
    """Returns 'mps', 'cuda', or 'cpu'."""
    if torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


DEVICE = get_device()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BRAND_NAME = "Kuzet AI"
REPO_ROOT = pathlib.Path(__file__).parent.parent
LOGO_PATH = REPO_ROOT / "demos" / "brand" / "logo.png"
CACHE_DIR = REPO_ROOT / "out" / ".frame_cache"
LOCAL_FIRE_MODEL_PATH = REPO_ROOT / "data" / "models" / "e1250_safety_detection" / "yolo_smoke_fire.pt"
LOCAL_WEAPON_MODEL_PATH = (
    REPO_ROOT
    / "data"
    / "models"
    / "Hadi959__weapon-detection-yolov8"
    / "best.pt"
)
LOCAL_GUN_MODEL_PATH = REPO_ROOT / "data" / "models" / "wuhp__guns-100-11m" / "Guns-100-11m.pt"
LOCAL_GUN_BG_MODEL_PATH = (
    REPO_ROOT / "data" / "models" / "Zcket__gun_dtct" / "yolov8_background1k_best.pt"
)
WEAPON_INFERENCE_SIZE = 1280
GUN_INFERENCE_SIZE = 960
GUN_BG_INFERENCE_SIZE = 640  # benchmarked-clean size for the Zcket background-1k model
WEAPON_MAX_AREA_FRACTION = 0.05
WEAPON_NMS_IOU_THRESHOLD = 0.45
WEAPON_VERIFIER_MODEL = os.environ.get(
    "PROTECTOR_WEAPON_VERIFIER_MODEL",
    "google/owlv2-base-patch16-ensemble",
)
WEAPON_VERIFIER_BACKEND = os.environ.get("PROTECTOR_WEAPON_VERIFIER", "owlv2")
WEAPON_VERIFY_TRIGGER_CONF = float(os.environ.get("PROTECTOR_WEAPON_VERIFY_TRIGGER_CONF", "0.65"))
WEAPON_VERIFY_SCORE_THRESHOLD = float(os.environ.get("PROTECTOR_WEAPON_VERIFY_SCORE", "0.12"))
WEAPON_VERIFY_STRIDE_FRAMES = int(os.environ.get("PROTECTOR_WEAPON_VERIFY_STRIDE", "15"))
WEAPON_VERIFY_CACHE_TTL_FRAMES = int(os.environ.get("PROTECTOR_WEAPON_VERIFY_CACHE_TTL", "20"))
WEAPON_VERIFIED_CONF_THRESHOLD = float(os.environ.get("PROTECTOR_WEAPON_VERIFIED_CONF", "0.80"))
WEAPON_VERIFIED_CONF_CAP = float(os.environ.get("PROTECTOR_WEAPON_VERIFIED_CONF_CAP", "0.96"))
WEAPON_DETR_MODEL = os.environ.get(
    "PROTECTOR_WEAPON_DETR_MODEL",
    "NabilaLM/detr-weapons-detection_40ep",
)
WEAPON_DETR_LABEL = os.environ.get("PROTECTOR_WEAPON_DETR_LABEL", "LABEL_2")
WEAPON_DETR_THRESHOLD = float(os.environ.get("PROTECTOR_WEAPON_DETR_THRESHOLD", "0.55"))
WEAPON_DETR_MAX_AREA_FRACTION = float(os.environ.get("PROTECTOR_WEAPON_DETR_MAX_AREA", "0.05"))
WEAPON_DETR_ENABLED = os.environ.get("PROTECTOR_WEAPON_DETR_ENABLED", "0") == "1"
WEAPON_DETR_STRIDE_FRAMES = int(os.environ.get("PROTECTOR_WEAPON_DETR_STRIDE", "15"))
# Smaller YOLO inference size for live webcam — trades recall for speed (~30fps capable)
WEAPON_LIVE_INFERENCE_SIZE = int(os.environ.get("PROTECTOR_WEAPON_LIVE_INFERENCE_SIZE", "640"))
# Area cap for live mode — more generous than pre-render (0.05) because a weapon held
# directly towards a webcam occupies a larger fraction of the frame.
WEAPON_LIVE_MAX_AREA_FRACTION = float(os.environ.get("PROTECTOR_WEAPON_LIVE_MAX_AREA", "0.20"))

# ---------------------------------------------------------------------------
# Brand palette — BGR tuples (cv2 uses BGR)
# ---------------------------------------------------------------------------

BRAND_RED = (72, 29, 225)        # #E11D48 → BGR
BRAND_BLUE = (235, 99, 37)       # #2563EB → BGR
BRAND_CYAN = (255, 200, 0)       # #00C8FF → BGR (accent cyan for joints)
BRAND_AMBER = (0, 165, 255)      # #FFA500 → BGR (fire/smoke)
BRAND_PURPLE = (128, 0, 128)     # #800080 → BGR (zones)
BRAND_DARK = (20, 20, 20)        # near-black for panel backgrounds
BRAND_WHITE = (255, 255, 255)

# Alpha for alert banner pulse (alternates between these)
BANNER_ALPHA_HI = 1.0
BANNER_ALPHA_LO = 0.65
BANNER_PULSE_FRAMES = 8          # frames per half-cycle

# ---------------------------------------------------------------------------
# Incident thresholds
# ---------------------------------------------------------------------------


@dataclass
class IncidentRule:
    xclip_threshold: float = 0.55       # X-CLIP fight probability
    vit_threshold: float = 0.6           # ViT violence probability
    weapon_conf_threshold: float = 0.5   # YOLO weapon confidence
    fire_conf_threshold: float = 0.45    # fire/smoke confidence
    n_of_m_clip: tuple[int, int] = (3, 5)      # 3 of last 5 windows violent
    n_of_m_weapon: tuple[int, int] = (5, 10)   # 5 of last 10 frames weapon
    n_of_m_fire: tuple[int, int] = (8, 15)     # 8 of last 15 frames fire
    live_weapon_conf: float = 0.40       # confidence threshold for live webcam mode
    live_n_of_m_weapon: tuple[int, int] = (3, 8)  # faster trigger for live (N, window)

# ---------------------------------------------------------------------------
# Backend selection (override via env vars)
# ---------------------------------------------------------------------------

WEAPON_BACKEND: str = os.environ.get("PROTECTOR_WEAPON_BACKEND", "coco_knife")
FIRE_BACKEND: str = os.environ.get("PROTECTOR_FIRE_BACKEND", "keremberke")

# ---------------------------------------------------------------------------
# Model / window constants
# ---------------------------------------------------------------------------

CLIP_WINDOW_FRAMES = 16   # frames per X-CLIP window
CLIP_STRIDE_FRAMES = 8    # sliding window stride
XCLIP_SIZE = 224          # input resolution for X-CLIP
POSE_MODEL = "yolov8n-pose.pt"
WEAPON_MODEL = "yolov8n.pt"
COCO_KNIFE_CLASS = 43
