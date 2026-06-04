import os
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).parent.parent))
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

import cv2
import numpy as np
from pathlib import Path

def load_frames(path: str) -> list:
    cap = cv2.VideoCapture(path)
    frames = []
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frames.append(frame)
    cap.release()
    return frames

def score_clip(scorer, frames: list) -> float:
    """Sample 8 frames from the middle of the clip and score."""
    if len(frames) < 4:
        return 0.0
    # Take middle 8 frames (or all if fewer)
    mid = len(frames) // 2
    start = max(0, mid - 4)
    window = frames[start:start + 8]
    result = scorer.score_clip(window)
    return result["violence_prob"]

if __name__ == "__main__":
    from protector.violence_xclip import XClipScorer
    from protector.config import DEVICE

    print(f"Loading X-CLIP on {DEVICE} ...")
    scorer = XClipScorer(device=DEVICE)
    print("X-CLIP loaded.")

    clips_dir = Path("demos/clips")
    results = []

    for clip_path in sorted(clips_dir.glob("fight_*.mp4")):
        print(f"Scoring {clip_path.name} ...", end=" ", flush=True)
        frames = load_frames(str(clip_path))
        score = score_clip(scorer, frames)
        results.append((score, clip_path))
        print(f"violence_prob={score:.3f}")

    scorer.release()

    # Sort by score descending
    results.sort(key=lambda x: x[0], reverse=True)

    print("\n=== TOP FIGHT CLIPS ===")
    for score, path in results:
        print(f"{score:.3f}  {path.name}")

    print(f"\nTop 3: {[r[1].name for r in results[:3]]}")
