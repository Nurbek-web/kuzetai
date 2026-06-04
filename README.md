# ProtectorAI

Computer vision pipeline for school safety threat detection.

Detects fights, weapons, fire/smoke, and restricted-zone intrusions in video.
Runs locally on Apple Silicon (M1/M2/M3) — no cloud required.

## Quickstart

```bash
# Install uv first: https://astral.sh/uv
uv run python -m cli run-file --in path/to/video.mp4 --out out/annotated.mp4
uv run python -m cli serve          # Gradio dashboard
uv run python -m cli build-reel     # Build investor demo reel
```

## Modules

- **Event Analysis** — fight / aggression detection (X-CLIP zero-shot + ViT)
- **Alarm Detection** — weapons (YOLO) + fire/smoke detection
- **Restricted Zone Control** — polygon-based intrusion and loitering detection
