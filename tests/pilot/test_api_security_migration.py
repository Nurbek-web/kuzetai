from __future__ import annotations

import base64
from io import StringIO
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from protector.pilot.api.auth import PasswordService, TotpService
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import Base
from protector.pilot.storage.repositories import PilotRepository

TOTP_KEY = base64.urlsafe_b64encode(b"m" * 32).decode()
ROTATION_INSTRUCTION = "rotate TOTP seeds before upgrading"


def _config(database: Path, *, totp_encryption_key: str | None = None) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database}")
    if totp_encryption_key is not None:
        config.attributes["totp_encryption_key"] = totp_encryption_key
    return config


def _insert_legacy_user(database: Path, seed: str) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{database}")
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                """
                INSERT INTO users (
                    user_id, username, password_hash, totp_secret_encrypted,
                    role, is_active, created_at
                ) VALUES (
                    'operator-1', 'operator', 'hash', :seed,
                    'operator', 1, CURRENT_TIMESTAMP
                )
                """
            ),
            {"seed": seed},
        )


def test_encrypted_totp_envelope_is_versioned_and_repository_rejects_plaintext(
    tmp_path: Path,
) -> None:
    service = TotpService(encryption_key=TOTP_KEY)
    secret = service.enrol("operator").secret
    encrypted = service.encrypt_secret(secret)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'repository.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(
        create_session_factory(engine),
        totp_encryption_key=TOTP_KEY,
    )

    assert encrypted.startswith("totp:v1:")
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash=PasswordService().hash("password"),
        role="operator",
        totp_secret_encrypted=encrypted,
    )
    with pytest.raises(ValueError, match=ROTATION_INSTRUCTION):
        repository.add_user(
            user_id="operator-2",
            username="legacy",
            password_hash=PasswordService().hash("password"),
            role="operator",
            totp_secret_encrypted=secret,
        )


def test_repository_rejects_structural_envelope_with_forged_authentication_tag(
    tmp_path: Path,
) -> None:
    service = TotpService(encryption_key=TOTP_KEY)
    encrypted = service.encrypt_secret(service.enrol("operator").secret)
    forged = f"{encrypted[:-1]}{'A' if encrypted[-1] != 'A' else 'B'}"
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'forged-repository.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(
        create_session_factory(engine),
        totp_encryption_key=TOTP_KEY,
    )

    with pytest.raises(ValueError, match="invalid encrypted TOTP secret"):
        repository.add_user(
            user_id="operator-forged",
            username="forged",
            password_hash=PasswordService().hash("password"),
            role="operator",
            totp_secret_encrypted=forged,
        )
    assert TOTP_KEY not in repr(repository)


def test_migration_aborts_before_schema_change_when_plaintext_seed_exists(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    config = _config(database, totp_encryption_key=TOTP_KEY)
    command.upgrade(config, "0001_pilot_core")
    _insert_legacy_user(database, "PLAINTEXTBASE32SEED")

    with pytest.raises(RuntimeError, match=ROTATION_INSTRUCTION):
        command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    assert "totp_last_accepted_counter" not in {
        column["name"] for column in inspect(engine).get_columns("users")
    }
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0001_pilot_core"
        )


def test_migration_accepts_versioned_envelope_and_database_rejects_plaintext(
    tmp_path: Path,
) -> None:
    database = tmp_path / "encrypted.sqlite3"
    config = _config(database, totp_encryption_key=TOTP_KEY)
    command.upgrade(config, "0001_pilot_core")
    service = TotpService(encryption_key=TOTP_KEY)
    encrypted = service.encrypt_secret(service.enrol("operator").secret)
    _insert_legacy_user(database, encrypted)

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    assert "totp_last_accepted_counter" in {
        column["name"] for column in inspect(engine).get_columns("users")
    }
    with engine.begin() as connection:
        with pytest.raises(IntegrityError, match="encrypted_envelope"):
            connection.execute(
                sa.text(
                    """
                    INSERT INTO users (
                        user_id, username, password_hash, totp_secret_encrypted,
                        role, is_active, created_at
                    ) VALUES (
                        'operator-2', 'plaintext', 'hash', 'PLAINTEXTBASE32SEED',
                        'operator', 1, CURRENT_TIMESTAMP
                    )
                    """
                )
            )


def test_migration_rejects_forged_tag_before_schema_change(tmp_path: Path) -> None:
    database = tmp_path / "forged-migration.sqlite3"
    config = _config(database, totp_encryption_key=TOTP_KEY)
    command.upgrade(config, "0001_pilot_core")
    service = TotpService(encryption_key=TOTP_KEY)
    encrypted = service.encrypt_secret(service.enrol("operator").secret)
    forged = f"{encrypted[:-1]}{'A' if encrypted[-1] != 'A' else 'B'}"
    _insert_legacy_user(database, forged)

    with pytest.raises(RuntimeError, match=ROTATION_INSTRUCTION):
        command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    assert "totp_last_accepted_counter" not in {
        column["name"] for column in inspect(engine).get_columns("users")
    }
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0001_pilot_core"
        )


def test_existing_envelope_migration_requires_one_time_totp_key(tmp_path: Path) -> None:
    database = tmp_path / "missing-key.sqlite3"
    config = _config(database)
    command.upgrade(config, "0001_pilot_core")
    service = TotpService(encryption_key=TOTP_KEY)
    _insert_legacy_user(database, service.encrypt_secret(service.enrol("operator").secret))

    with pytest.raises(RuntimeError, match="PILOT_TOTP_ENCRYPTION_KEY"):
        command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0001_pilot_core"
        )


def test_empty_user_migration_does_not_require_totp_key(tmp_path: Path) -> None:
    database = tmp_path / "empty.sqlite3"
    config = _config(database)

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    assert "totp_last_accepted_counter" in {
        column["name"] for column in inspect(engine).get_columns("users")
    }


def test_database_rejects_malformed_urlsafe_base64_with_valid_outer_length(
    tmp_path: Path,
) -> None:
    database = tmp_path / "malformed.sqlite3"
    config = _config(database)
    command.upgrade(config, "head")
    malformed = f"totp:v1:{'A' * 107}!"

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    with engine.begin() as connection:
        with pytest.raises(IntegrityError, match="encrypted_envelope"):
            connection.execute(
                sa.text(
                    """
                    INSERT INTO users (
                        user_id, username, password_hash, totp_secret_encrypted,
                        role, is_active, created_at
                    ) VALUES (
                        'operator-malformed', 'malformed', 'hash', :seed,
                        'operator', 1, CURRENT_TIMESTAMP
                    )
                    """
                ),
                {"seed": malformed},
            )


def test_postgresql_offline_migration_contains_fail_stop_and_envelope_constraint() -> None:
    output = StringIO()
    config = Config("alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+psycopg://localhost/kuzet_pilot_test",
    )

    command.upgrade(config, "head", sql=True)

    sql = output.getvalue()
    assert ROTATION_INSTRUCTION in sql
    assert "ck_users_totp_encrypted_envelope" in sql
    assert "totp_last_accepted_counter" in sql
    assert "decode(" in sql
    assert "get_byte(" in sql
    assert "{108}" in sql
