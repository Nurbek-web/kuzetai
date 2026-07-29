#!/usr/bin/env python3
"""Create a pg_dump and ready-evidence manifest from one exported snapshot."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

import psycopg

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_OBJECT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$")


def _write(path: Path, value: str) -> None:
    temporary = path.with_suffix(f"{path.suffix}.incomplete")
    temporary.write_text(value, encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--max-database-bytes", type=int, required=True)
    parser.add_argument("--max-evidence-objects", type=int, required=True)
    parser.add_argument("--max-manifest-bytes", type=int, required=True)
    parser.add_argument("--dump", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--evidence-manifest", type=Path, required=True)
    arguments = parser.parse_args()
    if _IDENTIFIER.fullmatch(arguments.site_id) is None:
        parser.error("site identity is invalid")
    if not 1 <= arguments.max_database_bytes <= 107_374_182_400:
        parser.error("database byte bound is invalid")
    if not 1 <= arguments.max_evidence_objects <= 100_000:
        parser.error("evidence object bound is invalid")
    if not 1 <= arguments.max_manifest_bytes <= 67_108_864:
        parser.error("manifest byte bound is invalid")
    for path in (arguments.dump, arguments.metadata, arguments.evidence_manifest):
        if not path.is_absolute() or path.exists() or path.parent.is_symlink():
            parser.error("snapshot output path is unsafe")

    with psycopg.connect(f"service={arguments.service}") as connection:
        connection.execute(
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
        )
        source_database, schema_revision, database_bytes, snapshot_id = connection.execute(
            """
            SELECT
                current_database(),
                (SELECT version_num FROM alembic_version),
                pg_database_size(current_database()),
                pg_export_snapshot()
            """
        ).fetchone()
        site_count, minimum_site, maximum_site = connection.execute(
            "SELECT count(*), min(site_id), max(site_id) FROM sites"
        ).fetchone()
        if (
            site_count != 1
            or minimum_site != arguments.site_id
            or maximum_site != arguments.site_id
        ):
            raise RuntimeError(
                "database backup requires exactly one authoritative matching site"
            )
        if (
            _IDENTIFIER.fullmatch(source_database) is None
            or _IDENTIFIER.fullmatch(schema_revision) is None
            or not isinstance(database_bytes, int)
            or database_bytes <= 0
            or database_bytes > arguments.max_database_bytes
        ):
            raise RuntimeError("database snapshot metadata exceeds configured bounds")
        manifest: list[str] = []
        seen: set[str] = set()
        manifest_bytes = 0
        row_count = 0
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT evidence.object_key, evidence.sha256
              FROM evidence
              JOIN candidate_events AS event
                ON event.event_id = evidence.event_id
              JOIN cameras AS camera
                ON camera.camera_id = event.camera_id
             WHERE camera.site_id = %s
               AND evidence.status = 'ready'
             ORDER BY evidence.object_key
            """,
            (arguments.site_id,),
        )
        while rows := cursor.fetchmany(256):
            for object_key, sha256 in rows:
                parts = object_key.split("/") if isinstance(object_key, str) else []
                if (
                    not isinstance(object_key, str)
                    or _OBJECT_KEY.fullmatch(object_key) is None
                    or any(part in {"", ".", ".."} for part in parts)
                    or object_key in seen
                    or not isinstance(sha256, str)
                    or re.fullmatch(r"[a-f0-9]{64}", sha256) is None
                ):
                    raise RuntimeError("database evidence manifest is invalid")
                row_count += 1
                if row_count > arguments.max_evidence_objects:
                    raise RuntimeError(
                        "database evidence manifest exceeds object bound"
                    )
                line = f"{sha256}\t{object_key}\n"
                manifest_bytes += len(line.encode("utf-8"))
                if manifest_bytes > arguments.max_manifest_bytes:
                    raise RuntimeError("database evidence manifest exceeds byte bound")
                seen.add(object_key)
                manifest.append(line)
        subprocess.run(
            [
                "pg_dump",
                f"--dbname=service={arguments.service}",
                "--format=custom",
                "--no-owner",
                "--no-acl",
                f"--snapshot={snapshot_id}",
                f"--file={arguments.dump}",
            ],
            check=True,
        )

    _write(
        arguments.metadata,
        (
            f"source_database={source_database}\n"
            f"schema_revision={schema_revision}\n"
            f"database_bytes={database_bytes}\n"
        ),
    )
    _write(arguments.evidence_manifest, "".join(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
