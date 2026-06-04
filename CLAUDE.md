# Kuzet AI - Claude Code Project Handoff

This is the active handoff file for Claude Code. The project has moved from the
old ProtectorAI naming to **Kuzet AI** for the investor demo.

## Project Goal

Kuzet AI is a local computer-vision school/camp safety demo built to raise
pre-seed funding. The current product story is:

- Detect aggression / fights.
- Detect fire and smoke.
- Detect weapons: gun / pistol and knife.
- Show false-positive discipline: a benign hug/contact clip should not alert.
- Present everything in Russian for Russian-speaking investors.

Do not bring zone intrusion back into the investor demo unless Nurbek explicitly
asks for it. The zone code still exists, but it is not part of the current pitch.

## Environment

```bash
cd "/Users/nurbek/Projects/kuzetai"
uv sync
export PYTORCH_ENABLE_MPS_FALLBACK=1
```

The machine is an Apple M2 with 8 GB RAM, no CUDA. Use CPU/MPS-friendly models.
All scripts and CLI paths should preserve `PYTORCH_ENABLE_MPS_FALLBACK=1` before
Torch, Ultralytics, or Transformers import.

## Main Commands

```bash
# Run one clip with all modules
uv run python -m cli run-file --input demos/clips/weapon_gun_youtube.mp4 --output out/gun.mp4

# Run one clip with weapons only
uv run python -m cli run-file --input demos/clips/weapon_knife_youtube.mp4 --output out/knife.mp4 --modules weapons

# Build the investor reel
uv run python -m cli build-reel --manifest demos/clips_manifest.yaml --out demos/reel/

# Audit rendered clips against manifest expectations
uv run python -m cli audit-reel --manifest demos/clips_manifest.yaml --annotated-dir demos/reel/annotated --out demos/reel/audit_report.json

# Launch the Gradio dashboard
uv run python -m cli serve --port 7860

# Tests
uv run python -m pytest tests/ -v
uv run ruff check protector tests cli.py
```

The app is usually viewed at `http://127.0.0.1:7860/`.

## Current Deliverables

- Main reel: `demos/reel/kuzet_ai_investor_reel.mp4`
- Dashboard: `protector/app.py`
- Demo manifest: `demos/clips_manifest.yaml`
- Model/research notes: `quality.md`
- Demo curation notes: `docs/demo_curation_workflow.md`

Generated clips and model files are large and often gitignored. Do not assume
they are tracked.

## Current Clip Strategy

Investor reel should focus on:

1. Benign hug/contact: no false alarm.
2. Gun detection.
3. Knife detection.
4. Fire/smoke detection.
5. Aggression/fight detection.

Nurbek is likely to keep curating better raw videos himself. Any new candidate
clip should be promoted only after it passes:

- visible detection boxes,
- expected incident in the JSON log,
- no false alert on benign clips,
- clean Russian dashboard/reel copy.

## Architecture Map

```text
protector/
  config.py         thresholds, model paths, env-driven settings
  weapons.py        YOLO candidate ensemble + OWLv2 verifier cascade
  fire_smoke.py     fire/smoke detector backends
  violence_xclip.py X-CLIP zero-shot video scoring, exactly 8 frames
  violence_vit.py   timm ViT violence classifier
  incident.py       N-of-M temporal debouncing
  overlay.py        cv2 branded overlays
  pipeline.py       run_file / run_webcam orchestration
  demo_reel.py      title cards and reel stitching
  demo_audit.py     manifest-vs-log audit
  demo_scenarios.py Russian dashboard scenario copy
  app.py            Gradio UI
```

## Current Weapon Stack

Read `quality.md` before changing the weapon stack.

Current default for pre-rendered clips (all three candidates on by default):

```text
YOLO candidates:
  data/models/Hadi959__weapon-detection-yolov8/best.pt   imgsz=1280, classes: pistol/knife/gun
  data/models/wuhp__guns-100-11m/Guns-100-11m.pt         imgsz=960,  classes: gun/knife
  data/models/Zcket__gun_dtct/yolov8_background1k_best.pt  imgsz=640, class 0→gun (index-mapped)

Verifier:
  google/owlv2-base-patch16-ensemble  (default)
  NabilaLM/detr-weapons-detection_40ep  (opt-in: PROTECTOR_WEAPON_DETR_ENABLED=1 or --detr)
```

The Zcket bg1k model has `model.names == {0: "0"}` — non-semantic class name.
`HfYoloWeaponDetector` uses `allowed_class_ids={0}` (index-based filter) to map it.
Do not pass `weapon_class_names=["gun"]` for this model; it will return nothing.

Important thresholds in `protector/config.py`:

```python
WEAPON_INFERENCE_SIZE = 1280
GUN_INFERENCE_SIZE = 960
GUN_BG_INFERENCE_SIZE = 640
WEAPON_MAX_AREA_FRACTION = 0.05
WEAPON_VERIFY_TRIGGER_CONF = 0.65
WEAPON_VERIFY_SCORE_THRESHOLD = 0.12
WEAPON_VERIFIED_CONF_THRESHOLD = 0.80
WEAPON_VERIFIED_CONF_CAP = 0.96
```

`run_file()` uses the heavy verified cascade. `run_webcam()` disables the OWLv2
verifier for speed. Zcket bg1k runs in both modes (uses `WEAPON_LIVE_INFERENCE_SIZE=640`
in live mode, same as its benchmark size, so no quality loss).

## Latest Weapon Research

The root cause of weak weapon quality is not just thresholding. The gun/knife
objects are small, blurry, and partly occluded. Bigger image sizes and lower
thresholds raise recall but create large false boxes and false alarms.

See `quality.md`, section `Deep Weapon Model Research - 2026-05-28`.

**What has been integrated (as of 2026-05-29):**

- 3-model YOLO ensemble: Hadi959 + wuhp + Zcket bg1k (gun-only, index-mapped).
- Optional DETR verifier: `NabilaLM/detr-weapons-detection_40ep`, LABEL_2 only,
  area ≤ 5%, threshold 0.55. Replaces OWLv2 when enabled. Both hit conf cap 0.96.
- Reel audit 7/7, 0 false alarms. Benign hug: 0 weapon incidents.

**What is NOT integrated and why:**

- `Accurateinfosolution` / similar "man with gun" models: person-sized boxes, bad visually.
- `Subh775/Firearm`: false alarms on benign (0.762), giant boxes.
- `Izzy-Oliver1961`: good knife recall but mislabels guns as knives.
- Do not replace the ensemble with a single public YOLO model.

**Remaining gap:**

- Knife recall weaker than gun (knife depends mostly on Hadi959 + wuhp).
- Pexels weapon variants (`weapon_gun_pexels.mp4`, `weapon_knife_pexels.mp4`) still
  miss — harder clips, not in the manifest, not a regression.
- Real deployment accuracy requires fine-tuning on a hard-negative dataset.

Raw research reports:

```text
out/model_research/hf_yolo_weapon_benchmark_sampled.json
out/model_research/active_downloaded_yolo_benchmark_sampled.json
out/model_research/manual_label_lowconf_benchmark_sampled.json
out/model_research/detr_weapon_benchmark_sampled.json
out/model_research/detr_weapon_benchmark_v2.json  (post DETR integration)
```

## Rules For Future Changes

- Keep the demo investor-first, but do not fake detections.
- Show only clips where the pipeline actually works.
- Avoid production accuracy claims until there is a real validation set.
- Preserve Russian UI/copy unless asked otherwise.
- Keep generated files out of git unless explicitly requested.
- Do not revert unrelated dirty files.
- When touching model logic, add or update focused tests.
- After model/reel changes, run audit and inspect JSON logs.

## Verification Baseline

Current baseline (2026-05-29): 62 tests pass, reel audit 7/7, 0 false alarms.

```bash
uv run python -m pytest tests/ -v
uv run ruff check protector tests cli.py
uv run python -m cli audit-reel --manifest demos/clips_manifest.yaml --annotated-dir demos/reel/annotated --out demos/reel/audit_report.json
```

After any code change, re-run the relevant subset at minimum. For docs-only
handoff edits, `git diff --check` is enough.
