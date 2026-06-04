# Kuzet AI Model Quality Notes

This file explains the current model stack, the exact weights in use, and what to look for when researching alternatives.

## Current Goal

The MVP is optimized for an investor demo, not for a published accuracy claim. The strategy is:

1. Use fast local CV models to produce visible detections.
2. Debounce signals over time so single-frame noise does not become an incident.
3. For weapons, require two-model confirmation before showing high-confidence results in the reel.
4. Audit every rendered clip against expected incidents and false alarms.

Current verified reel audit:

```bash
uv run python -m cli audit-reel --manifest demos/clips_manifest.yaml --annotated-dir demos/reel/annotated --out demos/reel/audit_report.json
# Audited 7 clip(s). Passed: 7  Failed: 0  Missing: 0  False alarms: 0
```

## High-Level Pipeline

```text
Video frames
  |
  |-- Pose / tracking: YOLOv8n-pose + ByteTrack
  |-- Weapons: YOLO ensemble -> OWLv2 verifier -> fused verified weapon boxes
  |-- Fire/smoke: local YOLO fire/smoke model
  |-- Violence: X-CLIP window score + ViT frame classifier
  |
IncidentFuser
  |
N-of-M temporal debounce
  |
Overlay renderer + MP4 + JSON event log
```

`run_file()` uses the heavier verified weapon cascade. `run_webcam()` keeps weapons lightweight by calling `make_weapon_detector(use_verifier=False)`.

## Models In Use

| Module | Model / weight | Local path | Role |
|---|---|---|---|
| Pose | `yolov8n-pose.pt` | Ultralytics cache | Person skeletons and tracking input |
| Weapon candidate 1 | `Hadi959/weapon-detection-yolov8` `best.pt` | `data/models/Hadi959__weapon-detection-yolov8/best.pt` | High-res pistol/knife/gun candidate detector |
| Weapon candidate 2 | `wuhp/guns-100-11m` `Guns-100-11m.pt` | `data/models/wuhp__guns-100-11m/Guns-100-11m.pt` | Auxiliary gun/knife candidate detector |
| Weapon verifier | `google/owlv2-base-patch16-ensemble` | Hugging Face cache | Zero-shot second-stage confirmation |
| Fire/smoke | `yolo_smoke_fire.pt` | `data/models/e1250_safety_detection/yolo_smoke_fire.pt` | Fire/smoke object detector |
| Violence primary | `microsoft/xclip-base-patch32` | Hugging Face cache | Zero-shot video/text violence scoring over 8 frames |
| Violence secondary | `jaranohaal/vit-base-violence-detection` | Hugging Face cache | Per-frame violence classifier via timm ViT |

Useful model-card links:

- Hadi weapon YOLO: https://huggingface.co/Hadi959/weapon-detection-yolov8
- WUHP guns/knife YOLO11: https://huggingface.co/wuhp/guns-100-11m
- OWLv2 verifier: https://huggingface.co/google/owlv2-base-patch16-ensemble
- X-CLIP: https://huggingface.co/microsoft/xclip-base-patch32
- ViT violence: https://huggingface.co/jaranohaal/vit-base-violence-detection

## Weapon Architecture

Weapon detection is the most sensitive part of the demo, so it now uses a cascade.

### Stage 1: Fast YOLO Candidate Ensemble

`protector/weapons.py` loads two local YOLO models through Ultralytics:

1. `Hadi959__weapon-detection-yolov8/best.pt`
   - Classes used: `pistol`, `knife`, `gun`
   - Inference image size: `1280`
   - Good for small visible objects in the knife/gun clips.

2. `wuhp__guns-100-11m/Guns-100-11m.pt`
   - Classes used: `Gun`, `Knife`
   - Inference image size: `960`
   - Adds cleaner gun/knife candidate coverage.

The ensemble filters out giant false boxes with:

```python
WEAPON_MAX_AREA_FRACTION = 0.05
```

That means any candidate box larger than 5% of the frame is discarded before fusion. This prevents person-sized boxes from being treated as weapons.

Overlapping YOLO boxes are merged with NMS:

```python
WEAPON_NMS_IOU_THRESHOLD = 0.45
```

### Stage 2: OWLv2 Zero-Shot Verifier

Only strong YOLO candidates are sent to the slower verifier:

```python
WEAPON_VERIFY_TRIGGER_CONF = 0.65
```

The verifier is:

```python
google/owlv2-base-patch16-ensemble
```

It is queried with these text labels:

```python
["handgun", "pistol", "gun", "knife", "blade"]
```

OWLv2 is slower than YOLO, but it is useful because it can confirm whether a tight region actually looks like the requested object. It runs every few frames and caches recent verifier boxes:

```python
WEAPON_VERIFY_STRIDE_FRAMES = 5
WEAPON_VERIFY_CACHE_TTL_FRAMES = 8
```

### Stage 3: Verified Fusion

A YOLO candidate is emitted only if:

1. YOLO confidence is at least `0.65`.
2. OWLv2 returns an overlapping weapon-like box.
3. The fused confidence is at least `0.80`.

The final emitted confidence is capped:

```python
WEAPON_VERIFIED_CONF_THRESHOLD = 0.80
WEAPON_VERIFIED_CONF_CAP = 0.96
```

This is why the current reel now shows:

- Gun: peak `96%`
- Knife: peak `94%`

Those numbers are calibrated demo confidence values, not published benchmark accuracy.

### Stage 4: Temporal Incident Fusion

After verified boxes are produced, `IncidentFuser` applies temporal debounce:

```python
n_of_m_weapon = (5, 10)
```

So a weapon incident opens only when enough recent frames have a verified weapon signal. Active incidents keep the peak confidence observed while they are open.

## Fire/Smoke Architecture

Fire/smoke uses a local YOLO weight:

```text
data/models/e1250_safety_detection/yolo_smoke_fire.pt
```

The fuser threshold is:

```python
fire_conf_threshold = 0.45
n_of_m_fire = (8, 15)
```

This means the detector can show boxes frame-by-frame, but an incident needs 8 of the last 15 frames above threshold.

## Violence/Aggression Architecture

Violence is intentionally a two-signal system:

1. `microsoft/xclip-base-patch32`
   - Zero-shot video/text model.
   - Uses exactly 8 frames at 224x224.
   - Scores prompts such as fighting/aggression versus calm behavior.

2. `jaranohaal/vit-base-violence-detection`
   - ViT image classifier.
   - Loaded via `timm` because the Hugging Face model metadata does not load cleanly through `AutoModel` in this project.
   - Samples frames and returns a median violence probability.

The fuser threshold is:

```python
xclip_threshold = 0.55
vit_threshold = 0.60
n_of_m_clip = (3, 5)
```

## Models Downloaded But Not Currently Used

These weights exist locally from model exploration, but they are not the active default:

| Model | Local path | Why not default |
|---|---|---|
| `Subh775/Threat-Detection-YOLOv8n` | `data/models/Subh775__Threat-Detection-YOLOv8n/weights/best.pt` | Weaker on our gun/knife clips |
| `Subh775/Firearm_Detection_Yolov8n` | `data/models/Subh775__Firearm_Detection_Yolov8n/weights/best.pt` | Gun-only and produced less useful boxes |
| `Zcket/gun_dtct` | `data/models/Zcket__gun_dtct/best.pt` | Class mapping did not work well in our benchmark |
| `HaiderKhan6410/weapon-yolo26x` | `data/models/HaiderKhan6410__weapon-yolo26x/model/best.pt` | Large and slow, did not outperform current cascade |
| `Accurateinfosolution/Suspicious_activity_detection_Yolov11_Custom` | `data/models/Accurateinfosolution__Suspicious_activity_detection_Yolov11_Custom/Suspicious_Activities_nano.pt` | High confidence but often person-sized boxes, visually misleading |

Also researched but not usable here:

- `SyncRobotic/weapon-detection-yolov8n-v2`: looked promising on the model card, but weight download returned 401 Unauthorized in this environment.

## What To Look For In Better Weapon Alternatives

If researching replacements, prioritize models with:

1. Directly downloadable `.pt`, `.onnx`, or safetensors weights.
2. Classes that separate `handgun`, `pistol`, `rifle`, `knife`, and `blade`.
3. Training data that resembles CCTV/security footage, not only close-up product photos.
4. Validation metrics with precision/recall curves, not only example screenshots.
5. Small-object performance at 720p/1080p.
6. Usable license for commercial/investor demos.
7. Inference speed acceptable on Apple M2 CPU/MPS.

Good candidates to investigate:

- YOLOv8/YOLO11 weapon detectors trained on security-camera data.
- RT-DETR or YOLOWorld style open-vocabulary detectors if they run fast enough.
- Fine-tuning the current YOLO model on 100-300 curated CCTV gun/knife frames.

For this project, a model is only worth switching to if it beats the current cascade on:

```text
demos/clips/weapon_gun_youtube.mp4
demos/clips/weapon_knife_youtube.mp4
benign/no-weapon clips
```

Use:

```bash
uv run python -m cli score-folder --input-dir data/candidates/weapons --out out/candidate_scores/weapons --modules weapons --expected weapon
uv run python -m cli score-folder --input-dir data/candidates/benign_contact --out out/candidate_scores/benign_contact --modules violence,pose --expected ""
```

## Deep Weapon Model Research - 2026-05-28

The weapon miss is not mainly a threshold problem. The root cause is that the
gun and knife are small, partially occluded objects in moving video. Raising
image size improves recall, but it also creates confident false boxes on hands,
people, shadows, and clothing. Lowering confidence alone makes this worse.

The benchmark used these exact local clips:

```text
demos/clips/weapon_gun_youtube.mp4
demos/clips/weapon_knife_youtube.mp4
demos/clips/benign_hug_pexels.mp4
```

Raw benchmark reports are saved locally:

```text
out/model_research/hf_yolo_weapon_benchmark_sampled.json
out/model_research/active_downloaded_yolo_benchmark_sampled.json
out/model_research/manual_label_lowconf_benchmark_sampled.json
out/model_research/detr_weapon_benchmark_sampled.json
```

### Sources Checked

- `Hadi959/weapon-detection-yolov8`: https://huggingface.co/Hadi959/weapon-detection-yolov8
- `wuhp/guns-100-11m`: https://huggingface.co/wuhp/guns-100-11m
- `Zcket/gun_dtct`: https://huggingface.co/Zcket/gun_dtct
- `Subh775/Threat-Detection-YOLOv8n`: https://huggingface.co/Subh775/Threat-Detection-YOLOv8n
- `Subh775/Firearm_Detection_Yolov8n`: https://huggingface.co/Subh775/Firearm_Detection_Yolov8n
- `HaiderKhan6410/weapon-yolo26x`: https://huggingface.co/HaiderKhan6410/weapon-yolo26x
- `NabilaLM/detr-weapons-detection_40ep`: https://huggingface.co/NabilaLM/detr-weapons-detection_40ep
- `KIRANKALLA/WeaponDetection`: https://huggingface.co/KIRANKALLA/WeaponDetection
- `Subh775/WeaponDetection` dataset: https://huggingface.co/datasets/Subh775/WeaponDetection
- `GingerBrains/object-detection`: https://github.com/GingerBrains/object-detection
- CCTV-Gun paper/repo: https://arxiv.org/abs/2303.10703 and https://github.com/srikarym/CCTV-Gun
- OWLv2 verifier: https://huggingface.co/google/owlv2-base-patch16-ensemble
- YOLO-World open-vocabulary detector: https://docs.ultralytics.com/models/yolo-world/

`SyncRobotic/weapon-detection-yolov8n-v2` looked promising because its model
card claims CCTV-oriented YOLOv8n training at `imgsz=960`, but the files API
returned `401 Repository Not Found` without authentication, so it was not
benchmarkable in this environment.

### Best Measured Candidates

For YOLO rows below, clips were sampled every 10 frames. `Gun` and `Knife` show
`max_conf / frames >= 0.50`. `Benign` shows peak false-positive confidence on
the hug clip.

| Candidate | Gun | Knife | Benign | Decision |
|---|---:|---:|---:|---|
| Current `Hadi959` at 640 | `0.692 / 6` | `0.739 / 3` | `0.000` | Keep as candidate, but do not trust alone |
| Current `wuhp` at 960 | `0.709 / 4` | `0.553 / 1` | `0.000` | Keep; clean gun signal, weak knife signal |
| `Zcket/gun_dtct` background model at 640, class `0 -> gun` | `0.705 / 15` | `0.552 / 1` | `0.159` | Promising gun-only auxiliary; needs manual class mapping |
| `Shantanukadam/weapon_detection` `gun.pt` at 640 | `0.679 / 15` | `0.558 / 5` | `0.000` | Good recall, but generic `weapon` class and 8 large gun-frame boxes |
| `Izzy-Oliver1961/weapon-detector-yolov8` at 960 | `0.673 / 3` | `0.825 / 16` | `0.204` | Strong knife auxiliary; gun appears mislabeled as `knife` |
| `Accurateinfosolution` suspicious activity YOLO11 | `0.767 / 5` | `0.898 / 9` | `0.000` | Reject for object detection: person-sized boxes, visually misleading |
| `Subh775/Firearm_Detection_Yolov8n` at 960 | `0.608 / 4` | `0.647 / 4` | `0.762` | Reject: false alarms and giant boxes |
| `HaiderKhan6410/weapon-yolo26x` at low conf | `0.159 / 0` | `0.778 / 1` | `0.000` | Reject for this demo: slow and misses the gun clip |
| `GingerBrains/object-detection` | `0.000 / 0` | `0.755 / 20` | `0.311` | Reject: misses gun, knife boxes are mostly huge |

The most interesting non-YOLO result is `NabilaLM/detr-weapons-detection_40ep`.
Its labels are not documented (`LABEL_0`...`LABEL_3`), but measured behavior
suggests `LABEL_2` is a tight weapon-like class. Sampling every 20 frames and
filtering to `LABEL_2` with `area <= 0.05`:

| DETR candidate | Gun | Knife | Benign | Decision |
|---|---:|---:|---:|---|
| `NabilaLM/detr-weapons-detection_40ep`, `LABEL_2`, area <= 5% | `0.991 / 8` | `0.942 / 6` | `0.271 / 0` | Most promising second verifier/candidate, but label semantics must be confirmed |

Important: `LABEL_3` from the same DETR model fires strongly on people, including
the benign hug clip. Do not use all labels. Only `LABEL_2` looked clean in this
small benchmark.

### Recommendation

Do not replace the current weapon stack with a single public YOLO model. The best
available public weights either miss the gun, hallucinate on benign contact, or
draw person-sized boxes that look bad in an investor reel.

Best next architecture for the demo:

1. Keep the current YOLO candidate ensemble plus OWLv2 verifier.
2. Add an optional pre-render-only `NabilaDetrWeaponDetector` branch using
   `NabilaLM/detr-weapons-detection_40ep`, `LABEL_2` only, `area <= 0.05`,
   and a threshold around `0.55-0.60`.
3. Consider adding `Zcket/gun_dtct/yolov8_background1k_best.pt` as a gun-only
   candidate with manual class mapping `0 -> gun`, threshold around `0.55`,
   and strict area cap.
4. Keep `Izzy` or `Shantanukadam` as optional research branches, not defaults,
   until they pass more benign hard negatives.
5. Never show weapon alerts unless the signal survives temporal debounce and
   either OWLv2 or DETR/YOLO agreement.

Best production path:

- Build a small hard-negative training set from hugs, phones, pointing hands,
  backpacks, dark clothing, and calm school/camp footage.
- Extract missed gun/knife frames from the actual demo videos and label tight
  boxes.
- Fine-tune one compact detector at 960 or 1280 px, then validate on the exact
  demo clips plus benign clips.
- If weapons stay tiny in frame, test tiled/SAHI-style inference around person
  upper-body and hand regions instead of only whole-frame detection.

The CCTV-Gun paper confirms why this is hard: real CCTV handguns are often small,
non-salient, occluded, and visually close to other small objects. That matches
the failure mode seen in our clips.

## DETR Candidate Branch Integration — 2026-05-28

`NabilaDetrWeaponDetector` has been integrated as an optional third candidate in
the YOLO ensemble. It is disabled by default (`PROTECTOR_WEAPON_DETR_ENABLED=0`)
and must never be used for live webcam (`run_webcam` is unchanged). Enable for
pre-render / reel builds:

```bash
PROTECTOR_WEAPON_DETR_ENABLED=1 uv run python -m cli run-file ...
# or
uv run python -m cli run-file --detr ...
```

### Measured Results on Demo Clips (2026-05-28)

Benchmark script: `scripts/benchmark_detr_weapons.py`
Output: `out/model_research/detr_weapon_benchmark_v2.json`
Settings: `LABEL_2` only, `area <= 0.05`, stride = 20 frames

| Clip | threshold | max_conf | ge50 | ge55 | ge60 |
|---|---:|---:|---:|---:|---:|
| `weapon_gun_youtube` | 0.50 | **0.991** | 9 | 8 | 8 |
| `weapon_gun_youtube` | 0.55 | **0.991** | 8 | 8 | 8 |
| `weapon_gun_youtube` | 0.60 | **0.991** | 8 | 8 | 8 |
| `weapon_knife_youtube` | 0.50 | **0.942** | 6 | 6 | 5 |
| `weapon_knife_youtube` | 0.55 | **0.942** | 6 | 6 | 5 |
| `weapon_knife_youtube` | 0.60 | **0.942** | 5 | 5 | 5 |
| `benign_hug_pexels` | 0.50 | **0.000** | 0 | 0 | 0 |
| `benign_hug_pexels` | 0.55 | **0.000** | 0 | 0 | 0 |
| `benign_hug_pexels` | 0.60 | **0.000** | 0 | 0 | 0 |

Key result: LABEL_2 with `area <= 0.05` produces **zero detections on the benign
hug clip at every tested threshold**. The earlier sampled-benchmark result of
`0.271 / 0 hits` was also clean (no hits ≥ 0.40); the integrated runtime now
confirms 0.000 max, which is stronger.

Selected threshold: `WEAPON_DETR_THRESHOLD = 0.55` (default). Changing to 0.60
drops knife to 5 hits vs 6 at 0.55 with no benefit on benign. 0.50 adds one
extra gun hit but is unnecessary given existing recall.

### DETR Cascade Position

DETR enters as a candidate, not a standalone verifier. The full flow:

```text
YOLO ensemble (Hadi + WUHP + [DETR if enabled])
  → NMS merge
  → trigger_conf filter (>= 0.65)
  → OWLv2 verifier (still required)
  → fused confidence >= 0.80
  → temporal debounce (5 of 10 frames)
  → Incident
```

DETR cannot trigger a weapon alert alone. OWLv2 confirmation is still
required. This preserves the two-model discipline from the original cascade.

### Test Coverage

Three new mock-based tests in `tests/test_weapon_backend.py`:
- `test_make_weapon_detector_with_detr_appends_to_ensemble`
- `test_make_weapon_detector_without_detr_is_unchanged`
- `test_detr_detector_filters_to_configured_label_and_area`

All 51 tests pass.

## Honest Quality Status

Current status:

- Fire/smoke: visually strong for the demo clip.
- Aggression: visually strong for the demo clip and backed by two independent signals.
- Weapons: now much stricter and more investor-presentable because boxes are two-model verified.
- False positives: benign contact scenario is included and should remain clean.

Remaining risk:

- This is not a measured production accuracy benchmark.
- OWLv2 makes pre-rendered weapon detection slower.
- Weapon performance still depends heavily on camera angle, blur, distance, and whether the object is visible.

Do not claim production-grade weapon accuracy until there is a real validation set and measured precision/recall.
