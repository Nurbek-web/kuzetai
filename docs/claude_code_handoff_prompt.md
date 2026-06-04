# Claude Code Startup Prompt

Paste this into a new Claude Code chat from the project root:

```text
We are continuing work on Kuzet AI in:

/Users/nurbek/Projects/kuzet ai

This is an investor demo for a computer-vision school/camp safety system. The
investors are Russian-speaking, so the dashboard/reel copy should stay Russian.
The current pitch scope is aggression/fight, fire/smoke, weapon detection
(gun/pistol/knife), and a benign hug/contact false-positive example. Do not
bring zone intrusion back into the investor reel unless I explicitly ask.

First read these files:

1. CLAUDE.md
2. quality.md
3. docs/demo_curation_workflow.md
4. protector/weapons.py
5. protector/config.py
6. demos/clips_manifest.yaml

Environment:

cd "/Users/nurbek/Projects/kuzet ai"
uv sync
export PYTORCH_ENABLE_MPS_FALLBACK=1

Important commands:

uv run python -m cli run-file --input demos/clips/weapon_gun_youtube.mp4 --output out/gun.mp4 --modules weapons
uv run python -m cli run-file --input demos/clips/weapon_knife_youtube.mp4 --output out/knife.mp4 --modules weapons
uv run python -m cli build-reel --manifest demos/clips_manifest.yaml --out demos/reel/
uv run python -m cli audit-reel --manifest demos/clips_manifest.yaml --annotated-dir demos/reel/annotated --out demos/reel/audit_report.json
uv run python -m pytest tests/ -v
uv run ruff check protector tests cli.py

Current weapon detection stack:

- YOLO candidate ensemble:
  - data/models/Hadi959__weapon-detection-yolov8/best.pt
  - data/models/wuhp__guns-100-11m/Guns-100-11m.pt
- OWLv2 verifier:
  - google/owlv2-base-patch16-ensemble
- The current reel audit previously passed 7/7 with no false alarms, but weapon
  quality is still the key concern.

Recent deep research is saved in quality.md under:

Deep Weapon Model Research - 2026-05-28

Key conclusion:

Do not replace the current weapon stack with a single public YOLO model. Most
public weights either miss the gun, hallucinate on the hug clip, or draw
person-sized boxes. The best next experiment is to add an optional pre-render-only
DETR branch using NabilaLM/detr-weapons-detection_40ep, LABEL_2 only, area <= 0.05,
threshold around 0.55-0.60. Consider Zcket/gun_dtct/yolov8_background1k_best.pt
as a gun-only candidate with manual class mapping 0 -> gun.

Your immediate task:

Make the technical weapon detection stack more robust without making fake or
visually misleading alerts. Prefer a small, testable integration:

1. Add a clean detector/verifier abstraction for the Nabila DETR LABEL_2 branch,
   disabled for live webcam and enabled only for pre-render/reel if it passes tests.
2. Keep strict area caps and temporal debounce.
3. Benchmark on:
   - demos/clips/weapon_gun_youtube.mp4
   - demos/clips/weapon_knife_youtube.mp4
   - demos/clips/benign_hug_pexels.mp4
4. Do not promote a model if it fires on the benign hug clip.
5. Update quality.md with exact measured results and any new thresholds.
6. Run focused tests, ruff, and audit the reel if you change model behavior.

Please work evidence-first: inspect JSON logs and rendered clips before claiming
the model is better. Keep the codebase conservative and do not revert unrelated
dirty changes.
```
