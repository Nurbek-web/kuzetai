#!/usr/bin/env python3
"""Audit an exact conditional-model registry entry without exporting or deploying it."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from protector.pilot.model_registry import (  # noqa: E402
    atomic_write_json,
    audit_model_entry,
    load_model_entry,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--artifact",
        type=Path,
        help="Exact ONNX file. Omission is recorded as a fail-closed audit refusal.",
    )
    parser.add_argument(
        "--engine",
        type=Path,
        help="Exact engine file required for deployment-scope approval.",
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--scope",
        choices=("export", "deployment"),
        default="deployment",
        help="Exit success only when this stage is complete.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        entry = load_model_entry(arguments.manifest)
        result = audit_model_entry(entry, arguments.artifact, engine_path=arguments.engine)
    except (OSError, ValueError) as exc:
        atomic_write_json(
            arguments.out,
            {
                "schema_version": "model-audit-result.v1",
                "approved_for_export": False,
                "approved_for_deployment": False,
                "reasons": [str(exc)],
                "export_reasons": [str(exc)],
                "deployment_reasons": [str(exc)],
                "record": {},
            },
        )
        return 2
    payload = result.model_dump(mode="json")
    atomic_write_json(arguments.out, payload)
    approved = (
        result.approved_for_export
        if arguments.scope == "export"
        else result.approved_for_deployment
    )
    return 0 if approved else 2


if __name__ == "__main__":
    raise SystemExit(main())
