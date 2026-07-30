from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pyotp
from sqlalchemy import func, select

from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import AuditEntryModel, Base, UserModel

TOTP_KEY = base64.urlsafe_b64encode(b"b" * 32).decode()


def _secret(path: Path, value: str) -> Path:
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def test_bootstrap_admin_consumes_only_secret_files_and_is_one_shot(tmp_path: Path) -> None:
    database = tmp_path / "bootstrap.db"
    engine = create_engine(f"sqlite+pysqlite:///{database}")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        from protector.pilot.storage.models import SiteModel

        session.add(SiteModel(site_id="site-1", name="School 1"))

    password = "bootstrap-password-never-log"
    totp_secret = pyotp.random_base32()
    command = [
        sys.executable,
        "scripts/pilot/bootstrap_admin.py",
        "--database-url-secret",
        str(_secret(tmp_path / "database-url", f"sqlite+pysqlite:///{database}")),
        "--username-secret",
        str(_secret(tmp_path / "username", "  Ａｄｍｉｎ  ")),
        "--password-secret",
        str(_secret(tmp_path / "password", password)),
        "--totp-secret",
        str(_secret(tmp_path / "totp", totp_secret)),
        "--totp-encryption-key-secret",
        str(_secret(tmp_path / "totp-key", TOTP_KEY)),
    ]

    first = subprocess.run(command, cwd=Path.cwd(), capture_output=True, text=True, check=False)
    second = subprocess.run(command, cwd=Path.cwd(), capture_output=True, text=True, check=False)

    assert first.returncode == 0, first.stderr
    result = json.loads(first.stdout)
    assert result["status"] == "bootstrapped"
    assert password not in first.stdout + first.stderr
    assert totp_secret not in first.stdout + first.stderr
    assert second.returncode != 0
    assert password not in second.stdout + second.stderr
    assert totp_secret not in second.stdout + second.stderr

    with session_factory() as session:
        user = session.scalar(select(UserModel))
        audit_count = session.scalar(select(func.count()).select_from(AuditEntryModel))
    assert user is not None
    assert user.username == "Admin"
    assert user.normalized_username == "admin"
    assert user.role == "admin"
    assert user.is_active is True
    assert user.auth_generation == 1
    assert user.password_hash != password
    assert totp_secret not in user.totp_secret_encrypted
    assert audit_count == 1
