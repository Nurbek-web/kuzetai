from __future__ import annotations

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

from protector.config import (
    BANNER_ALPHA_HI,
    BANNER_ALPHA_LO,
    BANNER_PULSE_FRAMES,
    BRAND_AMBER,
    BRAND_BLUE,
    BRAND_CYAN,
    BRAND_DARK,
    BRAND_NAME,
    BRAND_PURPLE,
    BRAND_RED,
    BRAND_WHITE,
    LOGO_PATH,
)
from protector.types import FrameDetections, Incident, ZoneEvent
from protector.zones import Zone

# COCO skeleton bone pairs
BONES = [
    (0, 1), (0, 2), (1, 3), (2, 4),
    (5, 6), (5, 7), (7, 9), (6, 8), (8, 10),
    (5, 11), (6, 12), (11, 12),
    (11, 13), (13, 15), (12, 14), (14, 16),
]


MODULE_LABELS = {
    "violence": "Агрессия",
    "weapon": "Оружие",
    "weapons": "Оружие",
    "fire": "Дым / огонь",
    "fire_smoke": "Дым / огонь",
    "zone": "Запретная зона",
    "zones": "Запретная зона",
    "pose": "Люди",
}


def module_label(module: str) -> str:
    return MODULE_LABELS.get(module.lower(), module)


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
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


class OverlayRenderer:
    def __init__(
        self,
        frame_width: int,
        frame_height: int,
        fps: float,
        zones: list[Zone] | None = None,
        active_modules: list[str] | None = None,
    ):
        self._w = frame_width
        self._h = frame_height
        self._fps = fps
        self._zones = zones or []
        self._active_modules = active_modules or ["POSE", "WEAPONS", "FIRE", "ZONE", "VIOLENCE"]
        self._logo: np.ndarray | None = self._load_logo()
        self._font_sm = _font(16)
        self._font_md = _font(22)
        self._font_lg = _font(30)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def draw_frame(
        self,
        frame: np.ndarray,
        detections: FrameDetections,
        active_incidents: list[Incident],
        zone_events: list[ZoneEvent],
        frame_idx: int,
    ) -> np.ndarray:
        """Draw all overlays in-place; returns the same frame."""
        self._draw_zones(frame)
        self._draw_skeletons(frame, detections.persons)
        self._draw_detection_boxes(frame, detections)
        self._draw_alert_banner(frame, active_incidents, frame_idx)
        self._draw_status_chips(frame, active_incidents)
        self._draw_event_ticker(frame, active_incidents)
        self._draw_logo(frame)
        return frame

    # ------------------------------------------------------------------
    # Sub-methods
    # ------------------------------------------------------------------

    def _load_logo(self) -> np.ndarray | None:
        """Load logo from LOGO_PATH, resize to height=30. Return None if missing."""
        if LOGO_PATH.exists():
            img = cv2.imread(str(LOGO_PATH))
            if img is not None:
                h, w = img.shape[:2]
                new_h = 30
                new_w = int(w * new_h / h)
                return cv2.resize(img, (new_w, new_h))
        return None

    def _draw_zones(self, frame: np.ndarray) -> None:
        for zone in self._zones:
            pts = np.array(
                [[int(x), int(y)] for x, y in zone.polygon.exterior.coords[:-1]],
                np.int32,
            )
            overlay = frame.copy()
            cv2.fillPoly(overlay, [pts], BRAND_PURPLE)
            cv2.addWeighted(overlay, 0.12, frame, 0.88, 0, frame)
            cv2.polylines(frame, [pts], True, BRAND_PURPLE, 3)
            # centroid label
            cx = int(np.mean(pts[:, 0]))
            cy = int(np.mean(pts[:, 1]))
            self._label_badge(frame, cx, cy, zone.name)

    def _draw_skeletons(self, frame: np.ndarray, persons) -> None:
        for person in persons:
            x1, y1, x2, y2 = person.bbox
            gap = 10
            color = BRAND_BLUE
            thickness = 2

            # Rounded-corner box effect — short lines at each corner
            # Top-left corner
            cv2.line(frame, (x1 + gap, y1), (x1, y1), color, thickness)
            cv2.line(frame, (x1, y1 + gap), (x1, y1), color, thickness)
            cv2.circle(frame, (x1, y1), 4, color, -1)
            # Top-right corner
            cv2.line(frame, (x2 - gap, y1), (x2, y1), color, thickness)
            cv2.line(frame, (x2, y1 + gap), (x2, y1), color, thickness)
            cv2.circle(frame, (x2, y1), 4, color, -1)
            # Bottom-left corner
            cv2.line(frame, (x1 + gap, y2), (x1, y2), color, thickness)
            cv2.line(frame, (x1, y2 - gap), (x1, y2), color, thickness)
            cv2.circle(frame, (x1, y2), 4, color, -1)
            # Bottom-right corner
            cv2.line(frame, (x2 - gap, y2), (x2, y2), color, thickness)
            cv2.line(frame, (x2, y2 - gap), (x2, y2), color, thickness)
            cv2.circle(frame, (x2, y2), 4, color, -1)

            kp = person.keypoints
            if kp is None:
                continue

            # Draw bones
            for a, b in BONES:
                if a < len(kp) and b < len(kp):
                    if kp[a][2] > 0.3 and kp[b][2] > 0.3:
                        pa = (int(kp[a][0]), int(kp[a][1]))
                        pb = (int(kp[b][0]), int(kp[b][1]))
                        cv2.line(frame, pa, pb, BRAND_BLUE, 1)

            # Draw keypoints
            for i in range(len(kp)):
                if kp[i][2] > 0.3:
                    px, py = int(kp[i][0]), int(kp[i][1])
                    cv2.circle(frame, (px, py), 3, BRAND_CYAN, -1)

    def _draw_rounded_corner_box(
        self,
        frame: np.ndarray,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        color: tuple,
        thickness: int = 3,
    ) -> None:
        """Draw a bounding box with a rounded-corner effect."""
        gap = 10
        # Top-left
        cv2.line(frame, (x1 + gap, y1), (x1, y1), color, thickness)
        cv2.line(frame, (x1, y1 + gap), (x1, y1), color, thickness)
        cv2.circle(frame, (x1, y1), 4, color, -1)
        # Top-right
        cv2.line(frame, (x2 - gap, y1), (x2, y1), color, thickness)
        cv2.line(frame, (x2, y1 + gap), (x2, y1), color, thickness)
        cv2.circle(frame, (x2, y1), 4, color, -1)
        # Bottom-left
        cv2.line(frame, (x1 + gap, y2), (x1, y2), color, thickness)
        cv2.line(frame, (x1, y2 - gap), (x1, y2), color, thickness)
        cv2.circle(frame, (x1, y2), 4, color, -1)
        # Bottom-right
        cv2.line(frame, (x2 - gap, y2), (x2, y2), color, thickness)
        cv2.line(frame, (x2, y2 - gap), (x2, y2), color, thickness)
        cv2.circle(frame, (x2, y2), 4, color, -1)

    def _draw_detection_boxes(self, frame: np.ndarray, detections: FrameDetections) -> None:
        for det in detections.weapons:
            self._draw_rounded_corner_box(frame, det.x1, det.y1, det.x2, det.y2, BRAND_RED, 3)
            label = f"{module_label('weapon')} {det.confidence:.0%}"
            self._label_badge(frame, det.x1, det.y1 + 16, label)

        for det in detections.fire_smoke:
            self._draw_rounded_corner_box(frame, det.x1, det.y1, det.x2, det.y2, BRAND_AMBER, 3)
            det_label = "Дым" if det.class_name.lower() == "smoke" else "Огонь"
            label = f"{det_label} {det.confidence:.0%}"
            self._label_badge(frame, det.x1, det.y1 + 16, label)

    def _draw_alert_banner(
        self,
        frame: np.ndarray,
        active_incidents: list[Incident],
        frame_idx: int,
    ) -> None:
        if not active_incidents:
            return

        inc = active_incidents[0]
        pulse_alpha = BANNER_ALPHA_HI if (frame_idx // BANNER_PULSE_FRAMES) % 2 == 0 else BANNER_ALPHA_LO

        banner_h = 64
        overlay = frame.copy()
        cv2.rectangle(overlay, (0, 0), (self._w, banner_h), BRAND_RED, -1)
        cv2.addWeighted(overlay, pulse_alpha, frame, 1.0 - pulse_alpha, 0, frame)

        text = f"ИНЦИДЕНТ: {module_label(inc.module)} · {inc.confidence:.0%} · {inc.start_t:.1f} сек"
        tw, th = self._text_size(text, self._font_md)
        tx = max(16, (self._w - tw) // 2)
        ty = (banner_h - th) // 2 - 1
        self._draw_text(frame, text, tx, ty, self._font_md, BRAND_WHITE)

    def _draw_status_chips(self, frame: np.ndarray, active_incidents: list[Incident]) -> None:
        y = self._h - 18
        x = 10
        active_module_names = {inc.module.lower() for inc in active_incidents}

        for module in self._active_modules:
            normalized = module.lower()
            bg = BRAND_RED if normalized in active_module_names else BRAND_DARK
            rw, rh = self._label_badge(frame, x, y, module_label(normalized), bg_color=bg)
            x += rw + 6

    def _draw_event_ticker(self, frame: np.ndarray, active_incidents: list[Incident]) -> None:
        if not active_incidents:
            return

        # Show last 3 incidents (most recent last)
        recent = active_incidents[-3:]
        count = len(recent)
        panel_h = count * 18 + 8
        panel_w = 280
        x0 = self._w - panel_w - 10
        y0 = self._h - panel_h - 40

        # Draw translucent dark rect (40% alpha)
        overlay = frame.copy()
        cv2.rectangle(overlay, (x0, y0), (x0 + panel_w, y0 + panel_h), BRAND_DARK, -1)
        cv2.addWeighted(overlay, 0.4, frame, 0.6, 0, frame)

        for i, inc in enumerate(recent):
            line = f"{module_label(inc.module)} {inc.start_t:.1f} сек {inc.reason[:22]}"
            tx = x0 + 6
            ty = y0 + 6 + (i + 1) * 16
            self._draw_text(frame, line, tx, ty - 13, self._font_sm, BRAND_WHITE)

    def _draw_clock_fps(self, frame: np.ndarray, frame_idx: int) -> None:
        text = f"FR {frame_idx:05d}  {self._fps:.0f}fps"
        font = cv2.FONT_HERSHEY_SIMPLEX
        scale = 0.45
        thickness = 1
        (tw, th), _ = cv2.getTextSize(text, font, scale, thickness)
        tx = self._w - tw - 8
        ty = th + 8
        cv2.putText(frame, text, (tx, ty), font, scale, BRAND_WHITE, thickness, cv2.LINE_AA)

    def _draw_logo(self, frame: np.ndarray) -> None:
        if self._logo is not None:
            lh, lw = self._logo.shape[:2]
            x0, y0 = 15, 8
            # Clamp to frame bounds
            x1 = min(x0 + lw, self._w)
            y1 = min(y0 + lh, self._h)
            roi = frame[y0:y1, x0:x1]
            logo_crop = self._logo[:y1 - y0, :x1 - x0]
            if roi.shape == logo_crop.shape and roi.size > 0:
                cv2.addWeighted(logo_crop, 0.9, roi, 0.1, 0, roi)
                frame[y0:y1, x0:x1] = roi
        else:
            # Fallback text watermark at 60% alpha
            text = BRAND_NAME
            tw, th = self._text_size(text, self._font_md)
            x0, y0 = 15, 8
            x1 = min(x0 + tw + 14, self._w)
            y1 = min(y0 + th + 12, self._h)
            roi = frame[y0:y1, x0:x1]
            if roi.size > 0:
                overlay_roi = roi.copy()
                cv2.rectangle(overlay_roi, (0, 0), (x1 - x0, y1 - y0), BRAND_DARK, -1)
                cv2.addWeighted(overlay_roi, 0.55, roi, 0.45, 0, roi)
                frame[y0:y1, x0:x1] = roi
                self._draw_text(frame, text, x0 + 7, y0 + 5, self._font_md, BRAND_WHITE)
            else:
                # Frame might be smaller than the text — draw directly
                self._draw_text(frame, text, 15, 8, self._font_md, BRAND_WHITE)

    def _label_badge(
        self,
        frame: np.ndarray,
        x: int,
        y: int,
        text: str,
        bg_color: tuple = BRAND_DARK,
        text_color: tuple = BRAND_WHITE,
    ) -> tuple[int, int]:
        tw, th = self._text_size(text, self._font_sm)
        pad = 4
        rx, ry = x, y - th - pad
        rw, rh = tw + pad * 2, th + pad * 2
        cv2.rectangle(frame, (rx, ry), (rx + rw, ry + rh), bg_color, -1)
        self._draw_text(frame, text, rx + pad, ry + pad - 1, self._font_sm, text_color)
        return rw, rh

    def _text_size(self, text: str, font: ImageFont.ImageFont) -> tuple[int, int]:
        bbox = font.getbbox(text)
        return bbox[2] - bbox[0], bbox[3] - bbox[1]

    def _draw_text(
        self,
        frame: np.ndarray,
        text: str,
        x: int,
        y: int,
        font: ImageFont.ImageFont,
        color_bgr: tuple[int, int, int],
    ) -> None:
        img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        draw = ImageDraw.Draw(img)
        color_rgb = (color_bgr[2], color_bgr[1], color_bgr[0])
        draw.text((int(x), int(y)), text, font=font, fill=color_rgb)
        frame[:, :] = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
