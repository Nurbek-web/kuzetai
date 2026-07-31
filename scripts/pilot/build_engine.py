#!/usr/bin/env python3
"""Build an atomic, unattested TensorRT candidate after rights/hash preflight.

Run this only on the pinned DeepStream 9.1 target image. A successful build records
configured L4/TensorRT identity but does not attest the host or prove 20-stream capacity.
Operator promotion still requires the exact signed site, shadow, and frozen-workload
capacity reports.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from protector.pilot.model_registry import (  # noqa: E402
    EngineBuildError,
    EngineBuildSpecV1,
    build_engine,
    load_model_entry,
)
from protector.pilot.trusted_yaml import StrictYAMLError, load_strict_yaml  # noqa: E402

_MAX_ENGINE_BUILD_SPEC_YAML_BYTES = 256 * 1024
_MAX_ENGINE_BUILD_SPEC_YAML_NODES = 4_000
_MAX_ENGINE_BUILD_SPEC_YAML_DEPTH = 32


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument(
        "--calibration",
        type=Path,
        help="Exact local INT8 calibration cache; required for INT8 builds.",
    )
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument(
        "--trtexec",
        type=Path,
        default=Path("/usr/src/tensorrt/bin/trtexec"),
    )
    parser.add_argument(
        "--build-spec",
        type=Path,
        help="Optional engine-build-spec.v1 YAML; default is configured L4 FP16.",
    )
    parser.add_argument("--result", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=1_800)
    parser.add_argument("--max-output-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-engine-bytes", type=int, default=2_000_000_000)
    return parser


def _load_build_spec(path: Path | None) -> EngineBuildSpecV1:
    if path is None:
        return EngineBuildSpecV1()
    with path.open("rb") as build_spec_file:
        encoded = build_spec_file.read(_MAX_ENGINE_BUILD_SPEC_YAML_BYTES + 1)
    try:
        payload = load_strict_yaml(
            encoded,
            max_bytes=_MAX_ENGINE_BUILD_SPEC_YAML_BYTES,
            max_nodes=_MAX_ENGINE_BUILD_SPEC_YAML_NODES,
            max_depth=_MAX_ENGINE_BUILD_SPEC_YAML_DEPTH,
            require_mapping=True,
        )
    except StrictYAMLError as exc:
        raise ValueError("build spec YAML is invalid") from exc
    return EngineBuildSpecV1.model_validate(payload)


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result_path = arguments.result or arguments.engine.with_suffix(
        arguments.engine.suffix + ".build.json"
    )
    try:
        entry = load_model_entry(arguments.manifest)
        spec = _load_build_spec(arguments.build_spec)
        build_engine(
            entry,
            artifact_path=arguments.artifact,
            output_path=arguments.engine,
            receipt_path=result_path,
            build_spec=spec,
            trtexec_path=arguments.trtexec,
            calibration_path=arguments.calibration,
            timeout_seconds=arguments.timeout_seconds,
            max_output_bytes=arguments.max_output_bytes,
            max_engine_bytes=arguments.max_engine_bytes,
        )
    except (EngineBuildError, OSError, ValueError) as exc:
        print(f"engine build refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
