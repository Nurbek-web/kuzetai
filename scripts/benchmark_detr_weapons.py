#!/usr/bin/env python3
"""Benchmark NabilaDetrWeaponDetector on demo weapon/benign clips.

Sweeps score thresholds [0.50, 0.55, 0.60] and writes per-clip per-threshold
counts to out/model_research/detr_weapon_benchmark_v2.json.

Usage:
    uv run python scripts/benchmark_detr_weapons.py \\
        --clips demos/clips/weapon_gun_youtube.mp4 \\
                demos/clips/weapon_knife_youtube.mp4 \\
                demos/clips/benign_hug_pexels.mp4 \\
        --out out/model_research/detr_weapon_benchmark_v2.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

# Allow running from repo root without install
sys.path.insert(0, str(Path(__file__).parent.parent))

import cv2  # noqa: E402

from protector.weapons import NabilaDetrWeaponDetector  # noqa: E402

STRIDE = 20
THRESHOLDS = [0.50, 0.55, 0.60]


def _sample_frames(clip_path: str, stride: int) -> list:
    cap = cv2.VideoCapture(clip_path)
    frames = []
    idx = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        if idx % stride == 0:
            frames.append((idx, frame))
        idx += 1
    cap.release()
    return frames


def _benchmark_clip(
    clip_path: str,
    detector: NabilaDetrWeaponDetector,
    threshold: float,
    stride: int,
) -> dict:
    frames = _sample_frames(clip_path, stride)
    detector._score_threshold = threshold
    # Force reload with new threshold by resetting cached model
    # (processor stays loaded; only threshold matters at post-process time)

    max_conf = 0.0
    hits_50 = 0
    hits_55 = 0
    hits_60 = 0
    first_50 = None
    top: list[dict] = []
    t0 = time.time()

    for frame_idx, frame in frames:
        dets = detector.detect(frame)
        for d in dets:
            c = d.confidence
            if c > max_conf:
                max_conf = c
            if c >= 0.50:
                hits_50 += 1
                if first_50 is None:
                    first_50 = frame_idx
            if c >= 0.55:
                hits_55 += 1
            if c >= 0.60:
                hits_60 += 1
            top.append(
                {
                    "frame": frame_idx,
                    "score": round(c, 4),
                    "box": [d.x1, d.y1, d.x2, d.y2],
                }
            )

    elapsed = round(time.time() - t0, 2)
    return {
        "threshold": threshold,
        "max": round(max_conf, 4),
        "ge50": hits_50,
        "ge55": hits_55,
        "ge60": hits_60,
        "first50": first_50,
        "frames_sampled": len(frames),
        "stride": stride,
        "seconds": elapsed,
        "top": sorted(top, key=lambda x: -x["score"])[:20],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clips", nargs="+", required=True, help="Clip paths to benchmark")
    parser.add_argument(
        "--out",
        default="out/model_research/detr_weapon_benchmark_v2.json",
        help="Output JSON path",
    )
    parser.add_argument("--stride", type=int, default=STRIDE, help="Frame sampling stride")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print("[benchmark] Loading NabilaDetrWeaponDetector (first use fetches from HF Hub)...")
    detector = NabilaDetrWeaponDetector()

    results: dict[str, dict] = {}
    model_key = "NabilaLM/detr-weapons-detection_40ep"
    results[model_key] = {}

    for clip_path in args.clips:
        clip_name = Path(clip_path).stem
        print(f"\n[benchmark] Clip: {clip_name}")
        results[model_key][clip_name] = {}

        for thresh in THRESHOLDS:
            print(f"  threshold={thresh:.2f} ...", end=" ", flush=True)
            stats = _benchmark_clip(clip_path, detector, thresh, args.stride)
            results[model_key][clip_name][str(thresh)] = stats
            print(
                f"max={stats['max']:.3f}  ge50={stats['ge50']}  "
                f"ge55={stats['ge55']}  ge60={stats['ge60']}  "
                f"({stats['seconds']}s)"
            )

    detector.release()

    out_path.write_text(json.dumps(results, indent=2))
    print(f"\n[benchmark] Written to {out_path}")

    # Print summary table
    print("\n--- Summary (LABEL_2, area<=5%) ---")
    print(f"{'Clip':<35} {'thresh':>7} {'max':>6} {'ge50':>5} {'ge55':>5} {'ge60':>5}")
    print("-" * 65)
    for clip_path in args.clips:
        clip_name = Path(clip_path).stem
        for thresh in THRESHOLDS:
            s = results[model_key][clip_name][str(thresh)]
            print(
                f"{clip_name:<35} {thresh:>7.2f} {s['max']:>6.3f} "
                f"{s['ge50']:>5} {s['ge55']:>5} {s['ge60']:>5}"
            )


if __name__ == "__main__":
    main()
