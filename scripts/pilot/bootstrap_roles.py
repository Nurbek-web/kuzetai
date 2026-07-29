#!/usr/bin/env python3
"""Create least-privilege PostgreSQL pilot roles and apply post-migration grants."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

import psycopg
from psycopg import sql

_MAX_SECRET_BYTES = 16 * 1024
_LOGIN_ROLES = ("kuzet_migrator", "kuzet_api", "kuzet_retention")


def _read_secret(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_SECRET_BYTES:
            raise RuntimeError("database bootstrap secret is invalid")
        value = os.read(descriptor, _MAX_SECRET_BYTES + 1).decode("utf-8").strip()
    finally:
        os.close(descriptor)
    if not value:
        raise RuntimeError("database bootstrap secret is empty")
    return value


def _ensure_roles(
    connection: psycopg.Connection[tuple[object, ...]],
    passwords: dict[str, str],
) -> None:
    connection.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_owner') THEN
            CREATE ROLE kuzet_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
              NOINHERIT NOREPLICATION NOBYPASSRLS;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_migrator') THEN
            CREATE ROLE kuzet_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
              INHERIT NOREPLICATION NOBYPASSRLS;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_api') THEN
            CREATE ROLE kuzet_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
              NOINHERIT NOREPLICATION NOBYPASSRLS;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_retention') THEN
            CREATE ROLE kuzet_retention LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
              NOINHERIT NOREPLICATION NOBYPASSRLS;
          END IF;
        END
        $$;
        """
    )
    for role in _LOGIN_ROLES:
        connection.execute(
            sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(role),
                sql.Literal(passwords[role]),
            )
        )
    connection.execute("GRANT kuzet_owner TO kuzet_migrator")
    connection.execute("ALTER ROLE kuzet_migrator SET ROLE TO kuzet_owner")
    database_name = connection.execute("SELECT current_database()").fetchone()[0]
    connection.execute(
        sql.SQL("ALTER DATABASE {} OWNER TO kuzet_owner").format(
            sql.Identifier(str(database_name))
        )
    )
    connection.execute("ALTER SCHEMA public OWNER TO kuzet_owner")


def _grant_runtime_access(
    connection: psycopg.Connection[tuple[object, ...]],
) -> None:
    database_name = connection.execute("SELECT current_database()").fetchone()[0]
    connection.execute(
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
            sql.Identifier(str(database_name))
        )
    )
    connection.execute(
        sql.SQL(
            "GRANT CONNECT ON DATABASE {} TO kuzet_migrator, kuzet_api, kuzet_retention"
        ).format(sql.Identifier(str(database_name)))
    )
    connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    connection.execute("GRANT USAGE ON SCHEMA public TO kuzet_api, kuzet_retention")
    connection.execute(
        "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO kuzet_api"
    )
    connection.execute(
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kuzet_api"
    )
    connection.execute("REVOKE UPDATE, DELETE ON TABLE audit_entries FROM kuzet_api")
    connection.execute(
        """
        REVOKE ALL ON TABLE
          audit_archive_receipts, audit_archive_items, audit_prune_authorizations
          FROM kuzet_api
        """
    )
    connection.execute(
        "REVOKE ALL ON TABLE audit_prune_authorizations FROM kuzet_api, kuzet_retention"
    )
    connection.execute(
        """
        GRANT SELECT ON TABLE sites, cameras, candidate_events, evidence, audit_entries
          TO kuzet_retention
        """
    )
    connection.execute(
        "GRANT UPDATE ON TABLE candidate_events, evidence TO kuzet_retention"
    )
    connection.execute("GRANT DELETE ON TABLE evidence TO kuzet_retention")
    connection.execute(
        """
        GRANT SELECT, INSERT ON TABLE
          audit_archive_receipts, audit_archive_items
          TO kuzet_retention
        """
    )
    connection.execute(
        "GRANT EXECUTE ON FUNCTION pilot_prune_archived_audit(text) TO kuzet_retention"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("ensure", "grants"), required=True)
    parser.add_argument("--admin-database-url-secret", type=Path, required=True)
    parser.add_argument("--migrator-password-secret", type=Path)
    parser.add_argument("--api-password-secret", type=Path)
    parser.add_argument("--retention-password-secret", type=Path)
    arguments = parser.parse_args()
    with psycopg.connect(_read_secret(arguments.admin_database_url_secret)) as connection:
        if arguments.phase == "ensure":
            secret_paths = {
                "kuzet_migrator": arguments.migrator_password_secret,
                "kuzet_api": arguments.api_password_secret,
                "kuzet_retention": arguments.retention_password_secret,
            }
            if any(path is None for path in secret_paths.values()):
                parser.error("ensure phase requires all role password secrets")
            _ensure_roles(
                connection,
                {
                    role: _read_secret(path)
                    for role, path in secret_paths.items()
                    if path is not None
                },
            )
        else:
            _grant_runtime_access(connection)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
