from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from dataclasses import asdict
from pathlib import Path

import cv2
import numpy as np

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

from protector.config import (
    CACHE_DIR,
    CLIP_STRIDE_FRAMES,
    CLIP_WINDOW_FRAMES,
    DEVICE,
    WEAPON_DETR_ENABLED,
    IncidentRule,
)
from protector.incident import IncidentFuser
from protector.io_video import get_video_info, iter_frames
from protector.overlay import OverlayRenderer
from protector.types import FrameDetections, Incident
from protector.zones import ZoneEvaluator, zone_from_dict


def _make_cache_root() -> Path:
    return Path(CACHE_DIR) / f"run_{int(time.time())}_{uuid.uuid4().hex[:8]}"


def run_file(
    input_path: str,
    output_path: str,
    zones: list[dict] | None = None,
    enabled_modules: list[str] | None = None,
    rule: IncidentRule | None = None,
    use_detr: bool | None = None,
) -> list[Incident]:
    """
    Process a video file end-to-end.
    Returns list of Incident objects; also writes annotated MP4 and JSON event log.

    Args:
        input_path: path to source video
        output_path: path for annotated output MP4
        zones: list of zone dicts (parsed from clips_manifest.yaml format)
        enabled_modules: subset of ["pose","weapons","fire_smoke","violence","zones"]
                         defaults to all
        rule: IncidentRule thresholds (defaults to IncidentRule())
    """
    rule = rule or IncidentRule()
    enabled = set(enabled_modules or ["pose", "weapons", "fire_smoke", "violence", "zones"])
    info = get_video_info(input_path)
    fps = info["fps"] or 30.0
    zone_objs = [zone_from_dict(z) for z in (zones or [])]
    zone_evaluator = ZoneEvaluator(zone_objs)

    cache_root = _make_cache_root()
    cache_root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Pass 1 — YOLO inference
    # ------------------------------------------------------------------
    from protector.fire_smoke import make_fire_smoke_detector
    from protector.pose import PoseTracker
    from protector.weapons import make_weapon_detector

    _use_detr = WEAPON_DETR_ENABLED if use_detr is None else use_detr
    tracker = PoseTracker(device=DEVICE) if "pose" in enabled else None
    weapon_det = make_weapon_detector(use_verifier=True, use_detr=_use_detr) if "weapons" in enabled else None
    fire_det = make_fire_smoke_detector() if "fire_smoke" in enabled else None

    total_frames = info.get("frame_count") or 0
    frame_data: list[FrameDetections] = []
    frame_cache: list[Path] = []  # paths to per-frame .npy files

    for frame_idx, frame in iter_frames(input_path):
        fd = FrameDetections(frame_idx=frame_idx)

        if tracker is not None:
            # track() is a generator — call it on a single-frame iterator
            for result in tracker.track(iter([(frame_idx, frame)])):
                fd.persons = result.persons

        if weapon_det is not None:
            fd.weapons = weapon_det.detect(frame)

        if fire_det is not None:
            fd.fire_smoke = fire_det.detect(frame)

        # Zone evaluation (needs persons with track IDs)
        zone_evaluator.evaluate(frame_idx, fps, fd.persons)

        # Save frame and metadata
        npy_path = cache_root / f"frame_{frame_idx:06d}.npy"
        np.save(str(npy_path), frame)
        frame_cache.append(npy_path)
        frame_data.append(fd)

        if frame_idx % 30 == 0 and frame_idx > 0:
            suffix = f"/{total_frames}" if total_frames else ""
            print(f"  [pass1] frame {frame_idx}{suffix}", flush=True)

    # Unload YOLO
    if tracker:
        tracker.release()
    if weapon_det:
        weapon_det.release()
    if fire_det:
        fire_det.release()

    import torch

    if torch.backends.mps.is_available():
        torch.mps.empty_cache()

    # ------------------------------------------------------------------
    # Pass 2 — Violence classification (only if "violence" in enabled)
    # ------------------------------------------------------------------
    xclip_scores: list[float] = [0.0] * len(frame_data)
    vit_scores: list[float] = [0.0] * len(frame_data)

    if "violence" in enabled:
        from protector.violence_xclip import XClipScorer

        scorer = XClipScorer(device=DEVICE)

        # Sliding window: every CLIP_STRIDE_FRAMES, score a window of CLIP_WINDOW_FRAMES
        for start in range(0, len(frame_cache) - CLIP_WINDOW_FRAMES + 1, CLIP_STRIDE_FRAMES):
            window_paths = frame_cache[start : start + CLIP_WINDOW_FRAMES]
            frames_np = [np.load(str(p)) for p in window_paths]
            result = scorer.score_clip(frames_np)
            vp = result["violence_prob"]
            # Assign score to the center frame of this window
            center = start + CLIP_WINDOW_FRAMES // 2
            xclip_scores[center] = vp

        scorer.release()
        if torch.backends.mps.is_available():
            torch.mps.empty_cache()

        from protector.violence_vit import ViTViolenceClassifier

        vit = ViTViolenceClassifier(device=DEVICE)
        SAMPLE_STRIDE = 4  # run ViT on every 4th frame to keep it fast
        for i in range(0, len(frame_cache), SAMPLE_STRIDE):
            frame_np = np.load(str(frame_cache[i]))
            score = vit.score_frames([frame_np])[0]
            # Fill in surrounding frames with same score
            for j in range(i, min(i + SAMPLE_STRIDE, len(frame_cache))):
                vit_scores[j] = score
        vit.release()
        if torch.backends.mps.is_available():
            torch.mps.empty_cache()

    # ------------------------------------------------------------------
    # Pass 3 — Fuse + render + write
    # ------------------------------------------------------------------
    fuser = IncidentFuser(fps=fps, rule=rule)
    zone_evaluator.reset()  # re-run zone evaluation during render pass for event log

    renderer = OverlayRenderer(
        frame_width=info["width"],
        frame_height=info["height"],
        fps=fps,
        zones=zone_objs,
        active_modules=list(enabled),
    )

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(str(out_path), fourcc, fps, (info["width"], info["height"]))

    all_zone_events = []

    for i, (npy_path, fd) in enumerate(zip(frame_cache, frame_data)):
        frame = np.load(str(npy_path))

        # Push signals to fuser
        fuser.push_violence(i, xclip_scores[i], vit_scores[i])
        weapon_conf = max((d.confidence for d in fd.weapons), default=0.0)
        fuser.push_weapon(i, weapon_conf)
        fire_conf = max((d.confidence for d in fd.fire_smoke), default=0.0)
        fuser.push_fire(i, fire_conf)

        zone_evts = zone_evaluator.evaluate(i, fps, fd.persons)
        for ze in zone_evts:
            fuser.push_zone(i, ze)
        all_zone_events.extend(zone_evts)

        # Get current active incidents: modules that are open right now
        active = [
            next(inc for inc in reversed(fuser._incidents) if inc.module == module)
            for module in fuser._active
        ]

        # Draw overlay
        annotated = renderer.draw_frame(frame, fd, active, zone_evts, i)
        writer.write(annotated)

    writer.release()
    incidents = fuser.flush(len(frame_data) - 1)

    # Write JSON event log
    log_path = out_path.with_suffix(".json")
    with open(log_path, "w") as f:
        json.dump(
            {
                "incidents": [asdict(inc) for inc in incidents],
                "total_frames": len(frame_data),
                "fps": fps,
            },
            f,
            indent=2,
        )

    # Cleanup cache
    shutil.rmtree(str(cache_root), ignore_errors=True)

    return incidents


def run_webcam(
    camera_idx: int = 0,
    zones: list[dict] | None = None,
    rule: IncidentRule | None = None,
) -> None:
    """
    Live single-pass mode. Runs pose + weapons + fire + zones only.
    Opens a cv2 window. Press 'q' to quit.
    """
    rule = rule or IncidentRule()
    zone_objs = [zone_from_dict(z) for z in (zones or [])]
    zone_evaluator = ZoneEvaluator(zone_objs)

    from protector.fire_smoke import make_fire_smoke_detector
    from protector.pose import PoseTracker
    from protector.weapons import make_weapon_detector

    tracker = PoseTracker(device=DEVICE)
    weapon_det = make_weapon_detector(use_verifier=False, live_mode=True)
    fire_det = make_fire_smoke_detector()
    fuser = IncidentFuser(fps=30.0, rule=rule)

    cap = cv2.VideoCapture(camera_idx)
    if not cap.isOpened():
        raise RuntimeError(f"Cannot open camera {camera_idx}")

    renderer = OverlayRenderer(
        frame_width=int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
        frame_height=int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
        fps=30.0,
        zones=zone_objs,
        active_modules=["POSE", "WEAPONS", "FIRE"],
    )
    # Higher confidence threshold in live mode
    rule.weapon_conf_threshold = rule.live_weapon_conf

    frame_idx = 0
    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break

            fd = FrameDetections(frame_idx=frame_idx)
            for result in tracker.track(iter([(frame_idx, frame)])):
                fd.persons = result.persons
            fd.weapons = weapon_det.detect(frame)
            fd.fire_smoke = fire_det.detect(frame)

            zone_evts = zone_evaluator.evaluate(frame_idx, 30.0, fd.persons)
            weapon_conf = max((d.confidence for d in fd.weapons), default=0.0)
            fire_conf = max((d.confidence for d in fd.fire_smoke), default=0.0)
            fuser.push_weapon(frame_idx, weapon_conf)
            fuser.push_fire(frame_idx, fire_conf)
            for ze in zone_evts:
                fuser.push_zone(frame_idx, ze)

            active = [
                next(inc for inc in reversed(fuser._incidents) if inc.module == module)
                for module in fuser._active
            ]
            annotated = renderer.draw_frame(frame, fd, active, zone_evts, frame_idx)

            cv2.imshow("Kuzet AI — Live [q to quit]", annotated)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break
            frame_idx += 1
    finally:
        cap.release()
        cv2.destroyAllWindows()
        tracker.release()
        weapon_det.release()
        fire_det.release()
