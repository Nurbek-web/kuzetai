# Weapon Detection Backend Notes

## Status (v1 MVP)

**Active backend:** `coco_knife` (default)  
Model: `yolov8n.pt` (COCO), class 43 = "knife"

**Known limitations:**
- Trained on kitchen/food photography knives — biased toward horizontal blades on clean backgrounds
- No gun/pistol/rifle classes in COCO
- High false-positive rate: phones, pens, water bottles, umbrellas under CCTV lighting
- No firearm detection in v1

## Evaluated Candidates

| Model | HF Repo | Status | Notes |
|---|---|---|---|
| COCO knife | `yolov8n.pt` class 43 | ✅ Active | Weak on CCTV, but transparent & dependency-free |
| Hadi959 weapon | `Hadi959/weapon-detection-yolov8` | ⚠ Pending eval | No model card, no mAP, no license disclosure |
| tsaffold weapon | `tsaffold/The-Guardian-YOLOv8-Weapon-Detection` | ⚠ Pending eval | Same concerns as above |

## Swapping Backends

Set env var before running:
```bash
export PROTECTOR_WEAPON_BACKEND="hf:Hadi959/weapon-detection-yolov8:pistol,knife"
uv run python -m cli run-file --input clip.mp4 --output out/clip_annotated.mp4
```

## V2 Plan

Fine-tune `yolov8n` on [Joseph Nelson's Pistols dataset](https://universe.roboflow.com/joseph-nelson/pistols) (CC BY 4.0, ~3k images) to add firearm detection. Estimate: ~1 day of data prep + training on a rented GPU.
