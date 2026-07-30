from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from protector.pilot.storage.db import create_engine


def _config(database: Path) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database}")
    return config


def _insert_site_and_user(database: Path, *, user_id: str, username: str) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{database}")
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                """
                INSERT OR IGNORE INTO sites (
                    site_id, name, timezone_name, created_at
                ) VALUES (
                    'site-1', 'School 1', 'Asia/Almaty', CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(
            sa.text(
                """
                INSERT INTO users (
                    user_id, username, password_hash, totp_secret_encrypted,
                    totp_last_accepted_counter, role, is_active, created_at
                ) VALUES (
                    :user_id, :username, 'hash', NULL,
                    NULL, 'admin', 1, CURRENT_TIMESTAMP
                )
                """
            ),
            {"user_id": user_id, "username": username},
        )


def test_migration_0005_backfills_canonical_identity_and_positive_generation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "backfill.db"
    config = _config(database)
    command.upgrade(config, "0004_operational_retention")
    _insert_site_and_user(database, user_id="admin-1", username="  Ｓｔｒａßｅ  ")

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
    assert {"normalized_username", "auth_generation"} <= user_columns
    with engine.connect() as connection:
        row = connection.execute(
            sa.text(
                """
                SELECT username, normalized_username, auth_generation
                FROM users WHERE user_id = 'admin-1'
                """
            )
        ).one()
        revision = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
    assert row == ("Straße", "strasse", 1)
    assert revision == "0005_auth_lifecycle"

    with engine.begin() as connection:
        with pytest.raises(IntegrityError, match="auth_generation"):
            connection.execute(
                sa.text(
                    """
                    UPDATE users SET auth_generation = 0
                    WHERE user_id = 'admin-1'
                    """
                )
            )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.text(
                    """
                    INSERT INTO users (
                        user_id, username, normalized_username, password_hash,
                        totp_secret_encrypted, totp_last_accepted_counter,
                        auth_generation, role, is_active, created_at
                    ) VALUES (
                        'admin-2', 'STRASSE', 'strasse', 'hash',
                        NULL, NULL, 1, 'admin', 1, CURRENT_TIMESTAMP
                    )
                    """
                )
            )


def test_migration_0005_rejects_existing_nfkc_casefold_collision_before_schema_change(
    tmp_path: Path,
) -> None:
    database = tmp_path / "collision.db"
    config = _config(database)
    command.upgrade(config, "0004_operational_retention")
    _insert_site_and_user(database, user_id="admin-1", username="Straße")
    _insert_site_and_user(database, user_id="admin-2", username="ＳＴＲＡＳＳＥ")

    with pytest.raises(RuntimeError, match="normalized username collision"):
        command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
    assert "normalized_username" not in user_columns
    assert "auth_generation" not in user_columns
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0004_operational_retention"
        )


def test_offline_migration_fails_closed_before_canonical_backfill_is_skipped() -> None:
    output = StringIO()
    config = Config("alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+psycopg://localhost/kuzet_pilot_test",
    )

    command.upgrade(config, "head", sql=True)

    rendered = output.getvalue()
    assert "migration 0005 requires an online canonical username backfill" in rendered
