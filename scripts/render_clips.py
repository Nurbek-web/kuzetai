import os
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).parent.parent))
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

from pathlib import Path
import yaml

from protector.pipeline import run_file

DEMOS = Path("demos")
manifest_path = DEMOS / "clips_manifest.yaml"
annotated_dir = DEMOS / "reel" / "annotated"
annotated_dir.mkdir(parents=True, exist_ok=True)

with open(manifest_path) as f:
    manifest = yaml.safe_load(f)

for clip_entry in manifest.get("clips", []):
    clip_path = DEMOS / clip_entry["clip"]
    if not clip_path.exists():
        print(f"[skip] {clip_path.name} not found")
        continue

    out_path = annotated_dir / f"{clip_entry['id']}_annotated.mp4"
    zones = clip_entry.get("zones", [])
    modules = clip_entry.get("modules", None)

    print(f"\n[render] {clip_entry['id']} ({clip_path.name}) ...")
    try:
        incidents = run_file(
            input_path=str(clip_path),
            output_path=str(out_path),
            zones=zones,
            enabled_modules=modules,
        )
        print(f"  -> {len(incidents)} incident(s), output: {out_path.name}")
    except Exception as e:
        import traceback
        print(f"  -> ERROR: {e}")
        traceback.print_exc()

print("\n[done] All clips rendered.")
