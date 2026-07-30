#!/usr/bin/env python3
"""Validate and emit the exact safe bind-mount argv for target acceptance."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from protector.pilot.config import SiteConfig
from protector.pilot.runtime.deepstream import RuntimeModelManifestV1
from protector.pilot.runtime.mount_contract import (
    RuntimeMountContractV1,
    validate_runtime_mount_contract,
)

_MAX_INPUT_BYTES = 8 * 1024 * 1024


def _read_reviewed(path: Path, expected_sha256: str, label: str) -> bytes:
    if (
        not path.is_absolute()
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise ValueError(f"{label} identity is invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= _MAX_INPUT_BYTES
        ):
            raise ValueError(f"{label} is not one bounded regular file")
        payload = os.read(descriptor, _MAX_INPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError(f"{label} digest does not match reviewed input")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site-config", type=Path, required=True)
    parser.add_argument("--site-config-sha256", required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--runtime-manifest-sha256", required=True)
    parser.add_argument("--measured-capacity-report", type=Path, required=True)
    parser.add_argument("--measured-capacity-sha256", required=True)
    parser.add_argument("--measured-capacity-signature", type=Path, required=True)
    parser.add_argument("--capacity-authority-public-key", type=Path, required=True)
    parser.add_argument("--mount-contract", type=Path, required=True)
    parser.add_argument("--mount-contract-sha256", required=True)
    parser.add_argument("--image-id", required=True)
    arguments = parser.parse_args(argv)
    try:
        site_payload = _read_reviewed(
            arguments.site_config,
            arguments.site_config_sha256,
            "site configuration",
        )
        runtime_payload = _read_reviewed(
            arguments.runtime_manifest,
            arguments.runtime_manifest_sha256,
            "runtime manifest",
        )
        _read_reviewed(
            arguments.measured_capacity_report,
            arguments.measured_capacity_sha256,
            "measured capacity report",
        )
        contract_payload = _read_reviewed(
            arguments.mount_contract,
            arguments.mount_contract_sha256,
            "runtime mount contract",
        )
        site = SiteConfig.model_validate(yaml.safe_load(site_payload))
        runtime = RuntimeModelManifestV1.model_validate(yaml.safe_load(runtime_payload))
        contract = RuntimeMountContractV1.model_validate(
            yaml.safe_load(contract_payload)
        )
        mount_argv = validate_runtime_mount_contract(
            site_config=site,
            runtime_manifest=runtime,
            contract=contract,
            expected_image_id=arguments.image_id,
            site_config_source=arguments.site_config,
            runtime_manifest_source=arguments.runtime_manifest,
            measured_capacity_source=arguments.measured_capacity_report,
            measured_capacity_signature_source=(
                arguments.measured_capacity_signature
            ),
            capacity_authority_public_key_source=(
                arguments.capacity_authority_public_key
            ),
        )
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    for argument in mount_argv:
        print(argument)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
