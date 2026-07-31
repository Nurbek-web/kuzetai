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
_LOGIN_ROLES = (
    "kuzet_migrator",
    "kuzet_api",
    "kuzet_runtime",
    "kuzet_retention",
)


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


def _assert_service_roles_are_unprivileged(
    connection: psycopg.Connection[tuple[object, ...]],
) -> None:
    valid = connection.execute(
        """
        SELECT count(*) = 3
           AND bool_and(
                 role.rolcanlogin
                 AND NOT role.rolsuper
                 AND NOT role.rolcreatedb
                 AND NOT role.rolcreaterole
                 AND NOT role.rolinherit
                 AND NOT role.rolreplication
                 AND NOT role.rolbypassrls
                 AND NOT EXISTS (
                   SELECT 1
                     FROM pg_auth_members membership
                    WHERE membership.member = role.oid
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM pg_database owned_database
                    WHERE owned_database.datdba = role.oid
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM pg_namespace owned_schema
                    WHERE owned_schema.nspowner = role.oid
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM pg_class owned_relation
                    WHERE owned_relation.relowner = role.oid
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM pg_proc owned_routine
                    WHERE owned_routine.proowner = role.oid
                 )
               )
          FROM pg_roles role
         WHERE role.rolname IN (
           'kuzet_api',
           'kuzet_runtime',
           'kuzet_retention'
         )
        """
    ).fetchone()
    if valid is None or valid[0] is not True:
        raise RuntimeError("pilot service roles are not least privilege")


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
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_runtime') THEN
            CREATE ROLE kuzet_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
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
        inheritance = sql.SQL("INHERIT" if role == "kuzet_migrator" else "NOINHERIT")
        connection.execute(
            sql.SQL(
                "ALTER ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE {} NOREPLICATION NOBYPASSRLS"
            ).format(
                sql.Identifier(role),
                sql.Literal(passwords[role]),
                inheritance,
            )
        )
    connection.execute("GRANT kuzet_owner TO kuzet_migrator")
    connection.execute(
        "REVOKE kuzet_owner FROM kuzet_api, kuzet_runtime, kuzet_retention"
    )
    # Remove every pre-existing direct membership, not just kuzet_owner.
    # NOINHERIT alone still permits SET ROLE and is therefore not a fence.
    connection.execute(
        """
        DO $$
        DECLARE
          inherited record;
        BEGIN
          FOR inherited IN
            SELECT granted.rolname AS granted_role,
                   member.rolname AS member_role
              FROM pg_auth_members membership
              JOIN pg_roles granted
                ON granted.oid = membership.roleid
              JOIN pg_roles member
                ON member.oid = membership.member
             WHERE member.rolname IN (
               'kuzet_api',
               'kuzet_runtime',
               'kuzet_retention'
             )
          LOOP
            EXECUTE format(
              'REVOKE %I FROM %I',
              inherited.granted_role,
              inherited.member_role
            );
          END LOOP;
        END
        $$;
        """
    )
    _assert_service_roles_are_unprivileged(connection)
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
    _assert_service_roles_are_unprivileged(connection)
    database_name = connection.execute("SELECT current_database()").fetchone()[0]
    connection.execute(
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
            sql.Identifier(str(database_name))
        )
    )
    connection.execute(
        sql.SQL(
            "GRANT CONNECT ON DATABASE {} TO "
            "kuzet_migrator, kuzet_api, kuzet_runtime, kuzet_retention"
        ).format(sql.Identifier(str(database_name)))
    )
    connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    connection.execute(
        "GRANT USAGE ON SCHEMA public TO kuzet_api, kuzet_runtime, kuzet_retention"
    )
    # The grants phase runs after every migration.  Start from no direct data
    # privileges so a table added by a later migration cannot silently inherit
    # the API's historical blanket DML grant.  Sensitive runtime, provenance,
    # preview, and retention state is reachable only through the migration-owned
    # SECURITY DEFINER functions granted to the exact service role.
    connection.execute(
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM kuzet_api, kuzet_runtime, kuzet_retention"
    )
    connection.execute(
        "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM kuzet_api, kuzet_runtime, kuzet_retention"
    )
    connection.execute(
        "REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM kuzet_api, kuzet_runtime, kuzet_retention"
    )
    connection.execute(
        """
        GRANT SELECT ON TABLE
          sites, cameras, camera_health_samples, telemetry_publisher_epochs,
          model_artifacts, candidate_events, evidence, users, reviews,
          audit_entries, notification_outbox, delivery_attempts
          TO kuzet_api
        """
    )
    connection.execute(
        """
        GRANT INSERT ON TABLE
          telemetry_publisher_epochs, users, reviews, audit_entries,
          notification_outbox
          TO kuzet_api
        """
    )
    connection.execute(
        """
        GRANT UPDATE ON TABLE
          cameras, telemetry_publisher_epochs, candidate_events, users
          TO kuzet_api
        """
    )
    connection.execute(
        """
        GRANT SELECT ON TABLE
          sites, cameras, candidate_events, evidence, reviews,
          notification_outbox, delivery_attempts, audit_entries
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
        """
        GRANT EXECUTE ON FUNCTION
          public.pilot_get_active_site_config_sha256(text),
          public.pilot_upsert_camera_health_sample(text, jsonb),
          public.pilot_get_preview_receipt(text, uuid),
          public.pilot_commit_preview_access(jsonb)
          TO kuzet_api
        """
    )
    connection.execute(
        """
        GRANT EXECUTE ON FUNCTION
          public.pilot_get_runtime_claim_state(text),
          public.pilot_claim_runtime_writer(text, text),
          public.pilot_get_runtime_configuration(text, text),
          public.pilot_get_runtime_event(text, text, uuid),
          public.pilot_activate_runtime_camera_epoch(
            text, text, text, uuid, uuid, timestamptz
          ),
          public.pilot_set_runtime_candidate_evidence_status(
            text, text, uuid, text
          ),
          public.pilot_finalize_runtime_evidence(text, text, jsonb),
          public.pilot_ingest_candidate(jsonb, jsonb),
          public.pilot_get_active_site_config_sha256(text),
          public.pilot_get_preview_object_context(text, uuid, uuid, uuid),
          public.pilot_prepare_preview_publication(jsonb),
          public.pilot_finalize_preview_receipt(jsonb, jsonb)
          TO kuzet_runtime
        """
    )
    connection.execute(
        """
        GRANT EXECUTE ON FUNCTION
          public.pilot_prune_archived_audit(text),
          public.pilot_get_active_site_config_sha256(text),
          public.pilot_claim_preview_receipts_for_retention(
            text, timestamptz, integer
          ),
          public.pilot_finalize_preview_retirement(
            text, uuid, text, timestamptz
          ),
          public.pilot_preview_version_is_protected(
            text, text, text, timestamptz
          ),
          public.pilot_prune_preview_access_receipts(
            text, timestamptz, integer
          ),
          public.pilot_prune_operational_metadata(
            text, timestamptz, integer
          ),
          public.pilot_retire_expired_preview_intents(
            text, timestamptz, integer
          )
          TO kuzet_retention
        """
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("ensure", "grants"), required=True)
    parser.add_argument("--admin-database-url-secret", type=Path, required=True)
    parser.add_argument("--migrator-password-secret", type=Path)
    parser.add_argument("--api-password-secret", type=Path)
    parser.add_argument("--runtime-password-secret", type=Path)
    parser.add_argument("--retention-password-secret", type=Path)
    arguments = parser.parse_args()
    with psycopg.connect(_read_secret(arguments.admin_database_url_secret)) as connection:
        if arguments.phase == "ensure":
            secret_paths = {
                "kuzet_migrator": arguments.migrator_password_secret,
                "kuzet_api": arguments.api_password_secret,
                "kuzet_runtime": arguments.runtime_password_secret,
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
