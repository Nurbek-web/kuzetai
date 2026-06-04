# Kuzet AI — Project Context for AI Agents

## What This Is

Computer-vision school/camp safety system, **MVP stage**, built to win investor funding.
Runs locally on Apple M2 (8 GB RAM, MPS, no CUDA). Python 3.12, managed with `uv`.

**Two deliverables:**
1. **Pre-rendered investor reel** — `demos/reel/kuzet_ai_investor_reel.mp4` (Russian investor demo, rebuilt with verified weapon clips)
2. **Gradio web dashboard** — `protector/app.py` (Russian dashboard, manifest-driven scenario buttons, simulated Telegram preview)

**Scope for the investor MVP:**
- ✅ Event Analysis — fight/aggression/violence detection
- ✅ Alarm Detection — fire + smoke detection
- ✅ Weapon Detection — pistol/gun + knife with a two-stage verified cascade
- ✅ False-positive story — benign hug/contact example should stay clean
- ⚠️ Restricted Zone Control — code still exists, but it is not part of the current investor reel
- ❌ Emotion analysis — dropped (regulatory risk)
- ❌ Criminal-DB face matching — dropped (illegal in K-12)
- ❌ PPE Control — dropped (not a school feature)
- ❌ RWF-2000 accuracy benchmark — deferred to v2

---

## Environment Setup

```bash
cd "/Users/nurbek/Projects/kuzet ai"

# Install deps
uv sync

# Required env var — set before ANY torch/ultralytics import
export PYTORCH_ENABLE_MPS_FALLBACK=1
```

**All scripts and the CLI set this env var themselves.** Do not remove it.

---

## CLI Commands

```bash
# Process a video file (all modules)
uv run python -m cli run-file --input demos/clips/fight_007.mp4 --output out/test.mp4

# Process with specific modules only
uv run python -m cli run-file --input demos/clips/fire_youtube.mp4 --output out/fire.mp4 --modules fire_smoke

# Process weapons with the current verified cascade
uv run python -m cli run-file --input demos/clips/weapon_gun_youtube.mp4 --output out/gun.mp4 --modules weapons

# Live webcam (lightweight: pose+weapons+fire+zones only)
uv run python -m cli run-webcam --camera 0

# Build/rebuild the investor reel
uv run python -m cli build-reel --manifest demos/clips_manifest.yaml --out demos/reel/

# Launch Gradio dashboard
uv run python -m cli serve --port 7860

# Audit rendered demo logs against manifest expectations
uv run python -m cli audit-reel --manifest demos/clips_manifest.yaml --annotated-dir demos/reel/annotated --out demos/reel/audit_report.json

# Score a folder of candidate clips before promoting them
uv run python -m cli score-folder --input-dir data/candidates/weapons --out out/candidate_scores/weapons --modules weapons --expected weapon
```

Enabled modules string: `pose,weapons,fire_smoke,violence,zones`

---

## Architecture

```
protector/
  config.py         # device, brand palette (BGR), IncidentRule thresholds, env var backends
  types.py          # Detection, Person, FrameDetections, ZoneEvent, Incident dataclasses
  io_video.py       # iter_frames(source, stride) + get_video_info()
  pose.py           # YOLOv8n-pose + ByteTrack → Person objects with keypoints + foot_point
  weapons.py        # YOLO ensemble + optional OWLv2 verifier cascade
  fire_smoke.py     # Same Protocol; KeremberkeFireDetector (falls back to yolov8n.pt)
  violence_xclip.py # X-CLIP zero-shot — 5 prompts, 8 frames, returns violence_prob
  violence_vit.py   # jaranohaal ViT via timm — per-frame, returns median over 8 sampled frames
  zones.py          # Zone dataclass + ZoneEvaluator (intrusion/loitering via Shapely)
  incident.py       # IncidentFuser — N-of-M sliding window debouncing per module
  overlay.py        # OverlayRenderer — branded cv2 drawing: skeletons, boxes, banner, ticker
  pipeline.py       # run_file() 3-pass orchestrator; run_webcam() single-pass
  demo_reel.py      # build_reel() — title cards (Pillow) + stitch from clips_manifest.yaml
  demo_audit.py     # Manifest/log audit helpers for missing detections and false alarms
  demo_scenarios.py # Russian dashboard scenario metadata + summaries
  app.py            # Gradio dashboard: reel scenarios, live overlay, architecture accordion
cli.py              # argparse entrypoint: run-file, run-webcam, build-reel, serve
scripts/
  fast_render.py    # Quick pose-only render (no X-CLIP/ViT) for fast colleague demos
  score_fights.py   # X-CLIP scoring across fight clips to find best ones
  render_clips.py   # Render all manifest clips individually (without stitching reel)
demos/
  clips_manifest.yaml   # curated clips + reel config
  clips/                # raw input clips (gitignored)
  reel/                 # final reel MP4 + per-clip annotated MP4s (gitignored)
  brand/logo.png        # 400×80px PIL-generated logo
tests/
  test_weapon_backend.py # weapon model selection + verified cascade tests
  test_demo_*.py         # dashboard scenario and audit tests
  test_incident.py       # IncidentFuser + n_of_m tests
  test_zones.py          # ZoneEvaluator tests
  test_smoke.py          # pipeline smoke test (imports only)
```

### Three-Pass Pipeline (run_file)

1. **Pass 1** — YOLO/verified detectors: pose tracking + weapon detection + fire detection. Caches each frame as `.npy` to `out/.frame_cache/run_{timestamp}/`.
2. **Pass 2** — Violence (only if `"violence"` in enabled_modules): X-CLIP sliding 8-frame windows + ViT every 4th frame. Models unloaded + `torch.mps.empty_cache()` between sub-passes.
3. **Pass 3** — Fusion + render: `IncidentFuser` consumes per-frame signals, `OverlayRenderer` draws branded overlay, `cv2.VideoWriter` writes output MP4. Also writes `<output>.json` event log.

Cache dir cleaned up after each run.

---

## Models

| Module | Model | Notes |
|---|---|---|
| Pose | `yolov8n-pose.pt` | Auto-downloaded by Ultralytics |
| Weapons fast pass | `data/models/Hadi959__weapon-detection-yolov8/best.pt` at 1280px + `data/models/wuhp__guns-100-11m/Guns-100-11m.pt` at 960px | Local YOLO ensemble for weapon candidates |
| Weapons verifier | `google/owlv2-base-patch16-ensemble` | Zero-shot second stage. Runs only for strong YOLO candidates, confirms handgun/pistol/gun/knife/blade boxes, then fuses confidence |
| Fire/smoke | `data/models/e1250_safety_detection/yolo_smoke_fire.pt` | Local fire/smoke model when present |
| Violence (primary) | `microsoft/xclip-base-patch32` (MIT) | Zero-shot, 8 frames @ 224². Loaded via `transformers` |
| Violence (secondary) | `jaranohaal/vit-base-violence-detection` (Apache-2.0) | Loaded via `timm.create_model('vit_base_patch16_224', num_classes=2)` + `hf_hub_download` for weights |

### Critical ViT loading detail
The HuggingFace model card for `jaranohaal/vit-base-violence-detection` has no `model_type` field, so `AutoModel` fails. **Must use timm directly:**
```python
model = timm.create_model('vit_base_patch16_224', pretrained=False, num_classes=2)
path = hf_hub_download("jaranohaal/vit-base-violence-detection", "pytorch_model.bin")
state_dict = torch.load(path, map_location="cpu", weights_only=True)
model.load_state_dict(state_dict, strict=True)
```
This is already implemented in `protector/violence_vit.py`.

### X-CLIP frame count
`microsoft/xclip-base-patch32` expects exactly **8 frames**, not 16. `violence_xclip.py` hardcodes `_n_frames = 8` and pads/trims accordingly. `CLIP_WINDOW_FRAMES=16` in config is a legacy value — do not use it for X-CLIP directly.

### Model backends (pluggable via env vars)
```bash
# Weapon backend
export PROTECTOR_WEAPON_BACKEND=coco_knife          # default
export PROTECTOR_WEAPON_BACKEND=hf:Hadi959/weapon-detection-yolov8:pistol,knife,gun

# Weapon verifier
export PROTECTOR_WEAPON_VERIFIER=owlv2              # default for run-file/reel
export PROTECTOR_WEAPON_VERIFIER=none               # disable second-stage verification
export PROTECTOR_WEAPON_VERIFY_TRIGGER_CONF=0.65    # YOLO candidate must reach this before OWLv2 runs
export PROTECTOR_WEAPON_VERIFIED_CONF=0.80          # minimum fused confidence to emit a verified weapon
export PROTECTOR_WEAPON_VERIFIED_CONF_CAP=0.96      # cap fused two-model confidence

# Fire backend
export PROTECTOR_FIRE_BACKEND=keremberke            # default (falls back to yolov8n.pt)
```

### Weapon cascade details

`protector/weapons.py` now has:
- `WeaponEnsembleDetector`: combines Hadi weapon YOLO and WUHP gun/knife YOLO, then NMS-merges overlaps.
- `OwlV2WeaponVerifier`: slow but stronger zero-shot verifier for handgun/pistol/gun/knife/blade.
- `VerifiedWeaponDetector`: only sends YOLO candidates above `WEAPON_VERIFY_TRIGGER_CONF` to OWLv2. If OWLv2 returns an overlapping box, the detection is promoted to a fused confidence. It must be at least `WEAPON_VERIFIED_CONF_THRESHOLD` (80% by default) and is capped at `WEAPON_VERIFIED_CONF_CAP`. Weak unverified boxes are suppressed.

`run_file()` uses the verifier. `run_webcam()` calls `make_weapon_detector(use_verifier=False)` so live mode stays lightweight.

---

## Brand Palette (BGR — cv2 convention)

```python
BRAND_RED    = (72, 29, 225)    # #E11D48 — alert banner, title card rules
BRAND_BLUE   = (235, 99, 37)    # #2563EB — pose skeleton bones
BRAND_CYAN   = (255, 200, 0)    # #00C8FF — skeleton joints
BRAND_AMBER  = (0, 165, 255)    # #FFA500 — fire/smoke bounding boxes
BRAND_PURPLE = (128, 0, 128)    # #800080 — zone polygons
BRAND_DARK   = (20, 20, 20)     # panel backgrounds
```

---

## Current Demo Clips

Located in `demos/clips/` (gitignored). Current investor reel clips:

| File | Source | Notes |
|---|---|---|
| `benign_hug_pexels.mp4` | Pexels | Benign contact / false-positive check. Expected: no incidents |
| `weapon_gun_youtube.mp4` | YouTube segment | Gun example. Verified cascade now peaks at 96% |
| `weapon_knife_youtube.mp4` | YouTube segment | Knife example. Verified cascade now produces one high-precision 94% event near the clear blade frames |
| `fire_youtube.mp4` | YouTube segment | Fire example |
| `fight_institution.mp4` | RWF-2000/security footage | Violence/aggression example |
| `fight_hallway.mp4` | RWF-2000 | Library-only extra violence example |
| `nonfight_001.mp4` | RWF-2000 non-fight | Library-only calm monitoring |

### ViT scores for fight clips (ranked)
```
fight_009: 0.953    fight_010: 0.953    fight_005: 0.949
fight_006: 0.948    fight_004: 0.948    fight_014: 0.947
fight_015: 0.943    fight_007: 0.940    fight_012: 0.939
fight_013: 0.938    fight_008: 0.924    fight_011: 0.912
fight_001: 0.299    fight_002: 0.201    fight_003: 0.089
```

**fight_014 is the best-looking clip** for investors — actual institutional security footage, no YouTube watermarks, 0.947 ViT score.

---

## Current Investor Reel

**`demos/reel/kuzet_ai_investor_reel.mp4`** — Russian-language 1280×720 @ 30fps reel.

Scene order:
1. Opening title card: "Kuzet AI"
2. Benign contact — no false alarm
3. Weapon — gun, verified cascade peak 96%
4. Weapon — knife, verified cascade peak 94%
5. Fire/smoke
6. Aggression / institutional camera
7. Closing card with contact

Reel re-build: `uv run python -m cli build-reel` — uses cached `demos/reel/annotated/*.mp4` if they exist (skips re-render). Delete an annotated clip to force re-render of just that clip.

Current audit after the verified weapon update:
```bash
uv run python -m cli audit-reel --manifest demos/clips_manifest.yaml --annotated-dir demos/reel/annotated --out demos/reel/audit_report.json
# Audited 7 clip(s). Passed: 7  Failed: 0  Missing: 0  False alarms: 0
```

---

## Key Bugs Fixed (do not regress)

### 1. Active-incident detection in pipeline.py
The old code used `inc.frame_start <= i <= inc.frame_end` to find "currently active" incidents during render pass. This was wrong because `frame_end` is only updated when the incident *closes*. Fix (in `pipeline.py` Pass 3 and `run_webcam`):
```python
active = [
    next(inc for inc in reversed(fuser._incidents) if inc.module == module)
    for module in fuser._active
]
```

### 2. 10fps clips play too fast in 30fps reel
`_video_to_frames()` in `demo_reel.py` now takes `target_fps` and repeats each frame `round(target_fps / source_fps)` times. Without this, 10fps clips played as 1.7s instead of 5s.

### 3. X-CLIP frame count mismatch
Model expects 8 frames, not 16. Fixed in `violence_xclip.py` with `_n_frames = 8`.

### 4. ViT model loading
Cannot use `AutoModel` — must use `timm` directly. Fixed in `violence_vit.py`.

### 5. sys.path in scripts/
All scripts under `scripts/` need: `sys.path.insert(0, str(Path(__file__).parent.parent))` to find the `protector` package. Already present in all scripts.

### 6. lap package
ByteTrack requires `lap`. It must be installed via `uv add lap` — Ultralytics' auto-install via pip fails in uv-managed venvs (no pip module). Already in `pyproject.toml`.

---

## Overlay Renderer Details

`protector/overlay.py` — `OverlayRenderer.draw_frame(frame, fd, active_incidents, zone_events, frame_idx)`

- **Logo** — loaded from `demos/brand/logo.png`; fallback draws "ProtectorAI" text at 60% alpha
- **Alert banner** — full-width top strip, BRAND_RED, pulsing alpha every 8 frames, shows `[!] INCIDENT: {MODULE} | {conf}% | {elapsed}s`
- **Pose skeleton** — COCO 17-keypoint bones in BRAND_BLUE, joints as BRAND_CYAN stars; only drawn if conf >= 0.3
- **Bounding boxes** — rounded-corner hack (4 short lines + filled circle at each corner); color by module
- **Zone polygons** — code exists, but zones are not part of the current investor reel
- **Status chips** — bottom-left; red background when module is currently active in an incident
- **Event ticker** — bottom-right translucent panel; last 3 incidents

---

## Incident Fusion Logic

`protector/incident.py` — `IncidentFuser`

Per-module N-of-M sliding window debounce (default thresholds in `config.py`):
- Violence: 3 of last 5 windows above threshold → open incident
- Weapon: 5 of last 10 frames. In `run_file`, weapon detections are already two-model verified before they reach the fuser
- Fire: 8 of last 15 frames
- Zone events: bypass debounce, emit immediately with conf=1.0

Active incidents now keep the **peak confidence and reason** observed while the incident is open. Do not regress this; otherwise dashboard/reel cards can show weaker early confidence instead of the strongest verified signal.

An incident stays "open" (`module in fuser._active`) until the N-of-M condition fails. `flush(final_frame)` closes all open incidents and returns the full list.

---

## Zone Evaluator

`protector/zones.py` — `ZoneEvaluator`

- Uses `shapely.geometry.Point.within(polygon)` for containment
- Foot point = ankle midpoint if both ankles detected (conf >= 0.3), else bbox bottom-center
- Intrusion: fires every frame the person is inside
- Loitering: tracks `(zone_name, track_id) → entry_frame`; fires when `(current - entry) / fps >= loiter_seconds`
- Call `reset()` between clips (clears loitering state)

Zone polygons are defined per-clip in `demos/clips_manifest.yaml`.

---

## What's NOT Done Yet (v2 / to-do)

1. **Weapon accuracy beyond demo clips** — The current investor clips now use a high-precision YOLO → OWLv2 cascade. This is good for pre-rendered demo assets, but not a production benchmark. For v2, build a real gun/knife validation set and measure precision/recall.

2. **Weapon model speed** — OWLv2 is intentionally slow. It is used only for `run_file`/reel rendering. Live webcam keeps `use_verifier=False`. Do not enable OWLv2 in live mode without profiling.

3. **More examples per class** — The manifest supports multiple examples. User may add more fire/gun/knife clips manually; run `score-folder`, promote only passing examples, then rebuild/audit.

4. **Real fire/smoke benchmark** — Current fire clip works for demo. For v2, validate on a real fire/smoke dataset before making accuracy claims.

5. **RWF-2000 accuracy benchmark** — Deferred. 2000 clips × ~17s = ~9 hours on M2. Not needed for investor pitch. Run if v2 requires accuracy claims.

6. **Reel audio** — No audio in the reel. Plan was royalty-free alert sting at -20dB on fire/fight clips. Deferred.

7. **More fight clips** — Only 15 RWF-2000 fight clips downloaded. Fight_009 and fight_010 (ViT 0.953) aren't in the reel yet. Consider adding them for variety.

---

## Running Tests

```bash
uv run pytest tests/ -v
uv run ruff check protector tests cli.py
git diff --check
uv run python -m cli audit-reel --manifest demos/clips_manifest.yaml --annotated-dir demos/reel/annotated --out demos/reel/audit_report.json
```

---

## File Sizes & Git Status

Gitignored (large/generated):
- `demos/clips/` — raw input clips
- `demos/reel/` — rendered reel + annotated clips
- `out/` — ad-hoc renders
- `.venv/`
- `data/`

Tracked (small):
- All `protector/*.py` source
- `cli.py`, `scripts/*.py`
- `tests/*.py`
- `demos/clips_manifest.yaml`
- `demos/brand/logo.png`
- `pyproject.toml`, `uv.lock`

---

## Contact / Context

This is a pre-seed startup demo, not a production system. The strategy is: **only show clips where the pipeline already works**. Every clip in the reel was hand-curated to fire correctly. The investor pitch is about the vision and the working prototype, not production accuracy numbers.

Nurbek Baknurtaizhanov — baknurtaizhanov@gmail.com
