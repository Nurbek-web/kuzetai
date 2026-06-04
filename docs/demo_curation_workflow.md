# Kuzet AI Demo Curation Workflow

This workflow is for adding multiple investor-quality examples per detection class.

## 1. Put Candidate Videos In A Folder

Example:

```bash
mkdir -p data/candidates/fire
```

Drop raw `.mp4`, `.mov`, `.mkv`, `.avi`, or `.webm` files there.

## 2. Score A Folder Before Promoting Clips

Fire/smoke:

```bash
uv run python -m cli score-folder \
  --input-dir data/candidates/fire \
  --out out/candidate_scores/fire \
  --modules fire_smoke \
  --expected fire_smoke
```

Weapon:

```bash
uv run python -m cli score-folder \
  --input-dir data/candidates/weapons \
  --out out/candidate_scores/weapons \
  --modules weapons \
  --expected weapon
```

The default `run-file` weapon path is now a high-precision cascade:

1. Hadi weapon YOLO at 1280px + WUHP gun/knife YOLO at 960px propose candidates.
2. Candidates below `PROTECTOR_WEAPON_VERIFY_TRIGGER_CONF` are dropped.
3. OWLv2 (`google/owlv2-base-patch16-ensemble`) verifies strong candidates with
   handgun/pistol/gun/knife/blade prompts.
4. Only overlapping two-model-confirmed boxes with fused confidence >=
   `PROTECTOR_WEAPON_VERIFIED_CONF` (80% by default) are promoted to the output.

Favor clips where the red box clearly lands on the weapon. If a clip only passes
because of a giant person-sized box or a barely visible object, do not promote it.

Benign contact / false-positive check:

```bash
uv run python -m cli score-folder \
  --input-dir data/candidates/benign_contact \
  --out out/candidate_scores/benign_contact \
  --modules violence,pose \
  --expected ""
```

The output folder contains annotated videos plus `audit_report.json`.

## 3. Promote Only Clips That Pass

Copy the best-looking passing clips into `demos/clips/`, then add them to
`demos/clips_manifest.yaml`.

Use repeated categories for multiple examples:

```yaml
- id: fire_01
  clip: clips/fire_01.mp4
  category: fire_smoke
  expected_modules: [fire_smoke]
  title: "Дым / огонь — пример 1"
  modules: [fire_smoke]
  zones: []

- id: fire_02
  clip: clips/fire_02.mp4
  category: fire_smoke
  expected_modules: [fire_smoke]
  title: "Дым / огонь — пример 2"
  modules: [fire_smoke]
  zones: []
```

The dashboard scenario buttons are manifest-driven, so new reel clips appear
without Python changes.

## 4. Rebuild And Audit The Reel

```bash
uv run python -m cli build-reel --manifest demos/clips_manifest.yaml --out demos/reel
uv run python -m cli audit-reel --manifest demos/clips_manifest.yaml --annotated-dir demos/reel/annotated --out demos/reel/audit_report.json
```

A demo clip should pass only when expected modules appear and no unexpected
modules fire. Benign examples should have zero incidents.
