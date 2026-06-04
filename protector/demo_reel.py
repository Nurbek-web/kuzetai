from __future__ import annotations

import os

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

from pathlib import Path

import cv2
import numpy as np
import yaml
from PIL import Image, ImageDraw, ImageFont

from protector.config import BRAND_RED
from protector.pipeline import run_file


def _load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in (
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except (IOError, OSError):
            continue
    return ImageFont.load_default()


def _make_title_card_frames(
    text_lines: list[str],
    duration_s: float,
    fps: float,
    width: int,
    height: int,
    subtitle_lines: list[str] | None = None,
) -> list[np.ndarray]:
    """
    Returns list of BGR numpy frames for a title card.

    Layout:
    - Black background
    - Main title: large white text, vertically centered
    - Subtitle: smaller text below title (grey color)
    - Thin red horizontal rule above/below title if title is one line
    """
    img = Image.new("RGB", (width, height), color=(0, 0, 0))
    draw = ImageDraw.Draw(img)

    title_font = _load_font(72)
    subtitle_font = _load_font(32)

    # Measure title block height
    title_text = "\n".join(text_lines)
    title_bbox = draw.textbbox((0, 0), title_text, font=title_font)
    title_w = title_bbox[2] - title_bbox[0]
    title_h = title_bbox[3] - title_bbox[1]

    # Measure subtitle block height (if any)
    subtitle_text = "\n".join(subtitle_lines) if subtitle_lines else ""
    subtitle_h = 0
    if subtitle_text.strip():
        sub_bbox = draw.textbbox((0, 0), subtitle_text, font=subtitle_font)
        subtitle_h = sub_bbox[3] - sub_bbox[1]

    gap = 20  # gap between title and subtitle
    rule_gap = 20  # gap between rule and title text
    rule_thickness = 2

    # Total block height including rules above/below title
    block_h = (
        rule_thickness + rule_gap
        + title_h
        + rule_gap + rule_thickness
        + (gap + subtitle_h if subtitle_text.strip() else 0)
    )

    # Vertically center the block
    block_top = (height - block_h) // 2

    rule_width = int(width * 0.6)
    rule_x0 = (width - rule_width) // 2
    rule_x1 = rule_x0 + rule_width

    # BRAND_RED is BGR; convert to RGB for Pillow
    brand_red_rgb = (BRAND_RED[2], BRAND_RED[1], BRAND_RED[0])

    y_cursor = block_top

    # Top rule
    draw.rectangle(
        [rule_x0, y_cursor, rule_x1, y_cursor + rule_thickness],
        fill=brand_red_rgb,
    )
    y_cursor += rule_thickness + rule_gap

    # Title text — centered horizontally
    title_x = (width - title_w) // 2
    draw.text((title_x, y_cursor), title_text, font=title_font, fill=(255, 255, 255), align="center")
    y_cursor += title_h + rule_gap

    # Bottom rule
    draw.rectangle(
        [rule_x0, y_cursor, rule_x1, y_cursor + rule_thickness],
        fill=brand_red_rgb,
    )
    y_cursor += rule_thickness

    # Subtitle text — centered horizontally, grey
    if subtitle_text.strip():
        y_cursor += gap
        sub_bbox = draw.textbbox((0, 0), subtitle_text, font=subtitle_font)
        sub_w = sub_bbox[2] - sub_bbox[0]
        sub_x = (width - sub_w) // 2
        draw.text((sub_x, y_cursor), subtitle_text, font=subtitle_font, fill=(170, 170, 170), align="center")

    # Convert PIL (RGB) to BGR numpy array
    frame_bgr = np.array(img)[:, :, ::-1]
    n_frames = max(1, int(duration_s * fps))
    return [frame_bgr] * n_frames


def _video_to_frames(path: str, target_fps: float | None = None) -> list[np.ndarray]:
    """
    Read all frames from a video file.
    If target_fps is given, repeat each frame so playback speed matches target_fps.
    """
    cap = cv2.VideoCapture(path)
    source_fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
    repeat = max(1, round(target_fps / source_fps)) if target_fps else 1
    frames: list[np.ndarray] = []
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        for _ in range(repeat):
            frames.append(frame)
    cap.release()
    return frames


def _write_frames_to_video(
    frames: list[np.ndarray],
    out_path: Path | str,
    fps: float,
    width: int,
    height: int,
) -> None:
    """Write a list of BGR frames to an MP4 using cv2.VideoWriter + mp4v codec."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(str(out_path), fourcc, fps, (width, height))
    for frame in frames:
        writer.write(frame)
    writer.release()


def build_reel(
    manifest_path: str | Path,
    out_dir: str | Path | None = None,
) -> Path:
    """
    Build the full investor demo reel from the clips manifest.

    1. For each clip in the manifest (that exists on disk), run the pipeline
       to produce an annotated MP4 in out_dir/annotated/.
    2. Build title card MP4s for opening, inter-clip, and closing cards.
    3. Stitch everything in order into the final reel MP4.

    Returns path to the final reel MP4.
    Clips that don't exist on disk are skipped with a warning.
    """
    manifest_path = Path(manifest_path)
    demos_dir = manifest_path.parent

    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)

    reel_cfg = manifest.get("reel", {})
    fps = float(reel_cfg.get("fps", 30))
    width, height = reel_cfg.get("resolution", [1920, 1080])

    out_dir = Path(out_dir) if out_dir else demos_dir / "reel"
    out_dir.mkdir(parents=True, exist_ok=True)
    annotated_dir = out_dir / "annotated"
    annotated_dir.mkdir(exist_ok=True)

    # Collect all frame sequences in order
    all_frame_seqs: list[list[np.ndarray]] = []

    # Opening card
    oc = reel_cfg.get("opening_card", {})
    all_frame_seqs.append(
        _make_title_card_frames(
            [oc.get("title", "Kuzet AI")],
            oc.get("duration_s", 2.0),
            fps,
            width,
            height,
            subtitle_lines=[oc.get("subtitle", "")],
        )
    )

    # Process each clip
    for clip_entry in manifest.get("clips", []):
        if clip_entry.get("include_in_reel") is False:
            print(f"[skip] {clip_entry['id']} marked library-only")
            continue

        clip_path = demos_dir / clip_entry["clip"]
        if not clip_path.exists():
            print(f"[skip] {clip_path} not found")
            continue

        # Inter-clip title card
        all_frame_seqs.append(
            _make_title_card_frames(
                [clip_entry.get("title", clip_entry["id"])],
                reel_cfg.get("inter_clip_duration_s", 1.0),
                fps,
                width,
                height,
            )
        )

        # Run pipeline on this clip
        annotated_path = annotated_dir / f"{clip_entry['id']}_annotated.mp4"
        zones = clip_entry.get("zones", [])
        enabled = clip_entry.get("modules", ["pose", "weapons", "fire_smoke", "violence", "zones"])
        # Always enable pose for tracking (needed for zones)
        if "zones" in enabled and "pose" not in enabled:
            enabled = list(enabled) + ["pose"]

        if annotated_path.exists():
            print(f"[cached] {clip_entry['id']}")
        else:
            print(f"[render] {clip_entry['id']} ...")
            run_file(
                str(clip_path),
                str(annotated_path),
                zones=zones,
                enabled_modules=enabled,
            )

        # Resize annotated frames to reel resolution (repeat frames to match reel fps)
        clip_frames = _video_to_frames(str(annotated_path), target_fps=fps)
        resized = [cv2.resize(f, (width, height)) for f in clip_frames]
        all_frame_seqs.append(resized)

    # Closing card
    cc = reel_cfg.get("closing_card", {})
    subtitle = cc.get("subtitle", "") + "\n\n" + cc.get("contact", "")
    all_frame_seqs.append(
        _make_title_card_frames(
            [cc.get("title", "Kuzet AI")],
            cc.get("duration_s", 2.5),
            fps,
            width,
            height,
            subtitle_lines=[subtitle],
        )
    )

    # Stitch all sequences into the final reel
    reel_output = reel_cfg.get("output", "protectorai_investor_reel.mp4")
    reel_path = out_dir / reel_output.split("/")[-1]
    all_frames = [f for seq in all_frame_seqs for f in seq]
    _write_frames_to_video(all_frames, reel_path, fps, width, height)

    print(f"[done] Reel written to {reel_path}  ({len(all_frames)} frames)")
    return reel_path
