# ProtectorAI Brand Palette

## Colors

| Name | Hex | BGR (cv2) | Usage |
|------|-----|-----------|-------|
| Brand Red | `#E11D48` | `(72, 29, 225)` | Alert banners, active module chips, accent |
| Brand Blue | `#2563EB` | `(235, 99, 37)` | Pose skeletons, person boxes, logo text |
| Accent Cyan | `#00C8FF` | `(255, 200, 0)` | Keypoint joints |
| Amber | `#FFA500` | `(0, 165, 255)` | Fire/smoke boxes |
| Purple | `#800080` | `(128, 0, 128)` | Restricted zone fills |
| Dark | `#0f172a` | `(20, 20, 20)` | Backgrounds, label badges |

## Typography (cv2)

- Alert banner: `cv2.FONT_HERSHEY_DUPLEX`, scale 0.7, white, thickness 2
- Labels: `cv2.FONT_HERSHEY_SIMPLEX`, scale 0.42, white, thickness 1
- Clock: `cv2.FONT_HERSHEY_SIMPLEX`, scale 0.45, white, thickness 1
- Watermark: `cv2.FONT_HERSHEY_DUPLEX`, scale 0.55, Brand Blue, thickness 1

## Layout Zones

- Top-left: Logo watermark (15px margin)
- Top-right: Frame counter + FPS
- Top (full-width): Alert banner (only when incident active)
- Bottom-left: Module status chips
- Bottom-right: Event ticker panel
