#!/usr/bin/env python3
"""Kuzet AI command-line interface."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

# Must be set before any torch/ultralytics import
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

import yaml  # noqa: E402

from protector.demo_audit import (  # noqa: E402
    audit_log,
    audit_manifest_logs,
    summarize_results,
    write_audit_report,
)
from protector.pipeline import run_file  # noqa: E402


def cmd_run_file(args) -> None:
    print(f"[kuzetai] Processing {args.input} ...")
    incidents = run_file(
        input_path=args.input,
        output_path=args.output,
        zones=None,
        enabled_modules=args.modules.split(",") if args.modules else None,
        use_detr=args.detr if args.detr else None,
    )
    print(f"[kuzetai] Done. {len(incidents)} incident(s) detected.")
    print(f"[kuzetai] Output: {args.output}")
    log = args.output.replace(".mp4", ".json")
    print(f"[kuzetai] Event log: {log}")


def cmd_run_webcam(args) -> None:
    from protector.pipeline import run_webcam

    print(f"[kuzetai] Starting webcam {args.camera} — press q to quit")
    run_webcam(camera_idx=args.camera)


def cmd_build_reel(args) -> None:
    from protector.demo_reel import build_reel

    manifest = args.manifest or "demos/clips_manifest.yaml"
    out_dir = args.out or "demos/reel"
    print(f"[kuzetai] Building reel from {manifest} ...")
    reel_path = build_reel(manifest, out_dir)
    print(f"[kuzetai] Reel ready: {reel_path}")


def cmd_audit_reel(args) -> None:
    manifest_path = Path(args.manifest or "demos/clips_manifest.yaml")
    annotated_dir = Path(args.annotated_dir or "demos/reel/annotated")
    out_path = Path(args.out or "demos/reel/audit_report.json")
    manifest = yaml.safe_load(manifest_path.read_text()) or {"clips": []}
    results = audit_manifest_logs(manifest, annotated_dir)
    write_audit_report(results, out_path)

    summary = summarize_results(results)
    print(f"[kuzetai] Audited {len(results)} clip(s).")
    print(
        f"[kuzetai] Passed: {summary['passed']}  Failed: {summary['failed']}  "
        f"Missing: {summary['missing_expected']}  False alarms: {summary['false_alarm']}"
    )
    print(f"[kuzetai] Report: {out_path}")


def _video_files(input_dir: Path) -> list[Path]:
    suffixes = {".mp4", ".mov", ".mkv", ".avi", ".webm"}
    return sorted(path for path in input_dir.iterdir() if path.suffix.lower() in suffixes)


def cmd_score_folder(args) -> None:
    input_dir = Path(args.input_dir)
    out_dir = Path(args.out or "out/candidate_scores")
    out_dir.mkdir(parents=True, exist_ok=True)
    modules = [module.strip() for module in args.modules.split(",") if module.strip()]
    expected = [module.strip() for module in args.expected.split(",") if module.strip()]

    results = []
    for video_path in _video_files(input_dir):
        out_path = out_dir / f"{video_path.stem}_annotated.mp4"
        if args.force or not out_path.with_suffix(".json").exists():
            print(f"[score-folder] render {video_path.name}")
            run_file(
                input_path=str(video_path),
                output_path=str(out_path),
                zones=None,
                enabled_modules=modules,
            )
        result = audit_log(video_path.stem, out_path.with_suffix(".json"), expected)
        results.append(result)

    report_path = out_dir / "audit_report.json"
    write_audit_report(results, report_path)
    summary = summarize_results(results)
    print(f"[score-folder] Audited {len(results)} candidate(s).")
    print(
        f"[score-folder] Passed: {summary['passed']}  Failed: {summary['failed']}  "
        f"Missing: {summary['missing_expected']}  False alarms: {summary['false_alarm']}"
    )
    print(f"[score-folder] Report: {report_path}")


def cmd_serve(args) -> None:
    from protector.app import launch

    port = args.port or 7860
    print(f"[kuzetai] Starting dashboard at http://localhost:{port}")
    launch(port=port)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="kuzetai",
        description="Kuzet AI — behavior-aware safety for educational institutions",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # run-file
    p_file = sub.add_parser("run-file", help="Process a video file")
    p_file.add_argument("--input", "-i", required=True, help="Input video path")
    p_file.add_argument("--output", "-o", required=True, help="Output annotated MP4 path")
    p_file.add_argument(
        "--modules",
        "-m",
        default=None,
        help="Comma-separated modules to enable (default: all). "
        "Options: pose,weapons,fire_smoke,violence,zones",
    )
    p_file.add_argument(
        "--detr",
        action="store_true",
        default=False,
        help="Enable NabilaLM DETR weapon candidate branch (pre-render only). "
        "Also toggleable via PROTECTOR_WEAPON_DETR_ENABLED=1.",
    )
    p_file.set_defaults(func=cmd_run_file)

    # run-webcam
    p_cam = sub.add_parser("run-webcam", help="Live webcam mode (lightweight)")
    p_cam.add_argument("--camera", "-c", type=int, default=0, help="Camera index (default: 0)")
    p_cam.set_defaults(func=cmd_run_webcam)

    # build-reel
    p_reel = sub.add_parser("build-reel", help="Build investor demo reel")
    p_reel.add_argument("--manifest", "-m", default=None, help="Manifest YAML path")
    p_reel.add_argument("--out", "-o", default=None, help="Output directory")
    p_reel.set_defaults(func=cmd_build_reel)

    # audit-reel
    p_audit = sub.add_parser("audit-reel", help="Audit rendered demo logs against expectations")
    p_audit.add_argument("--manifest", "-m", default=None, help="Manifest YAML path")
    p_audit.add_argument(
        "--annotated-dir",
        default=None,
        help="Directory containing *_annotated.json logs",
    )
    p_audit.add_argument("--out", "-o", default=None, help="Output audit JSON path")
    p_audit.set_defaults(func=cmd_audit_reel)

    # score-folder
    p_score = sub.add_parser("score-folder", help="Render and audit a folder of candidate clips")
    p_score.add_argument("--input-dir", "-i", required=True, help="Directory of candidate videos")
    p_score.add_argument("--out", "-o", default=None, help="Output directory for renders/report")
    p_score.add_argument(
        "--modules",
        "-m",
        required=True,
        help="Comma-separated modules to run, e.g. fire_smoke or weapons",
    )
    p_score.add_argument(
        "--expected",
        "-e",
        required=True,
        help="Comma-separated expected incident modules, e.g. fire_smoke or weapon. "
        "Use an empty string only for no-alert validation.",
    )
    p_score.add_argument("--force", action="store_true", help="Re-render existing candidate outputs")
    p_score.set_defaults(func=cmd_score_folder)

    # serve
    p_serve = sub.add_parser("serve", help="Launch Gradio dashboard")
    p_serve.add_argument("--port", "-p", type=int, default=7860, help="Port (default: 7860)")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
