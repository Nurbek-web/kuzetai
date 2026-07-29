#!/usr/bin/env python3
"""Run Alembic with a bounded Docker-secret database URL."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

from alembic import command
from alembic.config import Config


def _read_secret(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 16 * 1024:
            raise RuntimeError("migration database secret is invalid")
        value = os.read(descriptor, 16 * 1024 + 1).decode("utf-8").strip()
    finally:
        os.close(descriptor)
    if not value:
        raise RuntimeError("migration database secret is empty")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url-secret", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("/app/alembic.ini"))
    arguments = parser.parse_args()
    configuration = Config(str(arguments.config))
    configuration.set_main_option(
        "sqlalchemy.url",
        _read_secret(arguments.database_url_secret).replace("%", "%%"),
    )
    command.upgrade(configuration, "head")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
