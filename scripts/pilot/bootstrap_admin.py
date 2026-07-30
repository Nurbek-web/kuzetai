#!/usr/bin/env python3
"""One-shot first-admin bootstrap using file-mounted secrets only."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pyotp

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from protector.pilot.api.auth import PasswordService, TotpService
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.repositories import PilotRepository

_MAX_SECRET_BYTES = 16 * 1024


def _read_secret(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_SECRET_BYTES:
            raise RuntimeError("bootstrap secret file is invalid")
        value = os.read(descriptor, _MAX_SECRET_BYTES + 1).decode("utf-8").strip()
    finally:
        os.close(descriptor)
    if not value:
        raise RuntimeError("bootstrap secret file is empty")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url-secret", type=Path, required=True)
    parser.add_argument("--username-secret", type=Path, required=True)
    parser.add_argument("--password-secret", type=Path, required=True)
    parser.add_argument("--totp-secret", type=Path, required=True)
    parser.add_argument("--totp-encryption-key-secret", type=Path, required=True)
    arguments = parser.parse_args()

    database_url = _read_secret(arguments.database_url_secret)
    username = _read_secret(arguments.username_secret)
    password = _read_secret(arguments.password_secret)
    totp_seed = _read_secret(arguments.totp_secret)
    pyotp.TOTP(totp_seed).now()
    totp = TotpService(encryption_key=_read_secret(arguments.totp_encryption_key_secret))
    repository = PilotRepository(
        create_session_factory(create_engine(database_url)),
        totp_encryption_key=_read_secret(arguments.totp_encryption_key_secret),
    )
    user = repository.bootstrap_first_admin(
        user_id=str(uuid4()),
        username=username,
        password_hash=PasswordService().hash(password),
        totp_secret_encrypted=totp.encrypt_secret(totp_seed),
        occurred_at=datetime.now(timezone.utc),
    )
    print(
        json.dumps(
            {
                "status": "bootstrapped",
                "user_id": user.user_id,
                "username": user.username,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
