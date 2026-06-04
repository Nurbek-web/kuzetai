"""Fast render: pose + fire only, no X-CLIP/ViT. Produces annotated MP4s in minutes."""
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path when running script directly
sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
from protector.pipeline import run_file

out_dir = Path("out/fast")
out_dir.mkdir(parents=True, exist_ok=True)

# Fight clips — first 5 for speed
fight_clips = [f"demos/clips/fight_{i:03d}.mp4" for i in range(1, 6)]

# Fire clip
extra_clips = [
    ("demos/clips/fire_hallway.mp4", ["fire_smoke"]),
    ("demos/clips/nonfight_001.mp4", ["pose", "zones"]),
]

FIGHT_MODULES = ["pose", "weapons"]   # skip violence (no X-CLIP/ViT)

print("=== Fast render pass (no X-CLIP/ViT) ===\n")

for clip in fight_clips:
    p = Path(clip)
    if not p.exists():
        print(f"[skip] {p.name}")
        continue
    out = out_dir / f"{p.stem}_annotated.mp4"
    print(f"[render] {p.name} -> {out.name} ...", flush=True)
    try:
        incidents = run_file(str(p), str(out), enabled_modules=FIGHT_MODULES)
        print(f"  done. incidents={len(incidents)}")
    except Exception as e:
        print(f"  ERROR: {e}")

# Zone demo — nonfight clip with a polygon in the center
zone_def = [{
    "name": "Restricted Area",
    "polygon": [[160, 50], [480, 50], [480, 310], [160, 310]],
    "rule": "loitering",
    "loiter_seconds": 2.0,
}]
p = Path("demos/clips/nonfight_001.mp4")
if p.exists():
    out = out_dir / "zone_demo_annotated.mp4"
    print(f"\n[render] {p.name} (zone demo) -> {out.name} ...", flush=True)
    try:
        incidents = run_file(str(p), str(out), zones=zone_def, enabled_modules=["pose", "zones"])
        print(f"  done. incidents={len(incidents)}")
    except Exception as e:
        print(f"  ERROR: {e}")

# Fire clip
p = Path("demos/clips/fire_hallway.mp4")
if p.exists():
    out = out_dir / "fire_annotated.mp4"
    print(f"\n[render] {p.name} -> {out.name} ...", flush=True)
    try:
        incidents = run_file(str(p), str(out), enabled_modules=["fire_smoke"])
        print(f"  done. incidents={len(incidents)}")
    except Exception as e:
        print(f"  ERROR: {e}")

print("\n=== Done ===")
import subprocess
subprocess.run(["ls", "-lh", str(out_dir)])
