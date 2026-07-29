#!/usr/bin/env python3
"""Provision the reviewed one-site pilot database after migrations."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

from protector.pilot.provisioning import load_reviewed_inputs, provision_reviewed_pilot
from protector.pilot.storage.db import create_engine, create_session_factory

_MAX_SECRET_BYTES = 16 * 1024


def _read_secret(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_SECRET_BYTES:
            raise RuntimeError("provisioning database secret is invalid")
        value = os.read(descriptor, _MAX_SECRET_BYTES + 1).decode("utf-8").strip()
    finally:
        os.close(descriptor)
    if not value:
        raise RuntimeError("provisioning database secret is empty")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url-secret", type=Path, required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--site-name", required=True)
    parser.add_argument("--timezone", default="Asia/Almaty")
    parser.add_argument("--site-config", type=Path, required=True)
    parser.add_argument("--site-config-sha256", required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--runtime-manifest-sha256", required=True)
    parser.add_argument("--measured-capacity-report", type=Path, required=True)
    parser.add_argument("--measured-capacity-sha256", required=True)
    arguments = parser.parse_args()
    site_config, runtime_manifest, _ = load_reviewed_inputs(
        site_id=arguments.site_id,
        site_config_path=arguments.site_config,
        site_config_sha256=arguments.site_config_sha256,
        runtime_manifest_path=arguments.runtime_manifest,
        runtime_manifest_sha256=arguments.runtime_manifest_sha256,
        measured_capacity_path=arguments.measured_capacity_report,
        measured_capacity_sha256=arguments.measured_capacity_sha256,
    )
    engine = create_engine(_read_secret(arguments.database_url_secret))
    try:
        provision_reviewed_pilot(
            session_factory=create_session_factory(engine),
            site_id=arguments.site_id,
            site_name=arguments.site_name,
            timezone_name=arguments.timezone,
            site_config=site_config,
            runtime_manifest=runtime_manifest,
        )
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
