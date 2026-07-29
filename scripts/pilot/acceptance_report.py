#!/usr/bin/env python3
"""Validate an observed run and emit an externally signed acceptance report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from protector.pilot.acceptance import (  # noqa: E402
    evaluate_acceptance,
    load_acceptance_manifest,
    load_conditional_gate_decisions,
    load_run_record,
    verify_signed_report,
    write_signed_report,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--manifest", type=Path, required=True)
    generate.add_argument("--run-record", type=Path, required=True)
    generate.add_argument("--out-dir", type=Path, required=True)
    generate.add_argument("--private-key", type=Path, required=True)
    generate.add_argument("--public-key", type=Path, required=True)
    generate.add_argument(
        "--conditional-gate-decision",
        type=Path,
        action="append",
        default=[],
        help="Bounded authoritative ConditionalModelGateResultV1 JSON; repeat per module.",
    )
    verify = subparsers.add_parser("verify")
    verify.add_argument("--metadata", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "verify":
        return 0 if verify_signed_report(arguments.metadata, public_key=arguments.public_key) else 2
    try:
        manifest = load_acceptance_manifest(arguments.manifest)
        run = load_run_record(arguments.run_record)
        decisions = load_conditional_gate_decisions(arguments.conditional_gate_decision)
        report = evaluate_acceptance(
            manifest,
            run,
            verified_gate_decisions=decisions,
        )
        write_signed_report(
            report,
            output_dir=arguments.out_dir,
            private_key=arguments.private_key,
            public_key=arguments.public_key,
        )
        return 0 if report.passed else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"acceptance report refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
