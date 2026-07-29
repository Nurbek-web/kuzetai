"""Singleton production retention worker for bounded evidence and audit metadata."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import boto3
import psycopg

from protector.pilot.audit_archive import EncryptedAuditArchiveStore
from protector.pilot.config import SiteConfig, load_site_config
from protector.pilot.retention import (
    AuditArchiveCoordinator,
    AuditArchiveStore,
    EvidenceDeleteStore,
    EvidenceRetentionCoordinator,
    PostgresReceiptBoundAuditPruner,
)
from protector.pilot.storage.db import (
    SessionFactory,
    create_engine,
    create_session_factory,
)
from protector.pilot.storage.object_store import S3CompatibleObjectStore

_MAX_SECRET_BYTES = 16 * 1024


def _read_secret(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_SECRET_BYTES:
            raise RuntimeError("retention secret is invalid")
        value = os.read(descriptor, _MAX_SECRET_BYTES + 1).decode("utf-8").strip()
    finally:
        os.close(descriptor)
    if not value:
        raise RuntimeError("retention secret is empty")
    return value


def _reviewed_config(path: Path, expected_sha256: str) -> SiteConfig:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise RuntimeError("retention site configuration is unavailable")
    if not 0 < path.stat().st_size <= 1024 * 1024:
        raise RuntimeError("retention site configuration exceeds finite bound")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
        raise RuntimeError("retention site configuration digest mismatch")
    return load_site_config(path)


def _bounded_integer(*, minimum: int, maximum: int, label: str) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{label} must be an integer") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{label} must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def parse_retention_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url-secret", type=Path, required=True)
    parser.add_argument("--access-key-secret", type=Path, required=True)
    parser.add_argument("--secret-key-secret", type=Path, required=True)
    parser.add_argument("--archive-age-recipient", type=Path, required=True)
    parser.add_argument("--archive-signing-private-key", type=Path, required=True)
    parser.add_argument("--archive-signing-public-key", type=Path, required=True)
    parser.add_argument("--archive-signing-key-id", required=True)
    parser.add_argument("--archive-prefix", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--site-config", type=Path, required=True)
    parser.add_argument("--site-config-sha256", required=True)
    parser.add_argument(
        "--interval-seconds",
        type=_bounded_integer(
            minimum=5,
            maximum=3_600,
            label="retention interval",
        ),
        default=60,
    )
    parser.add_argument(
        "--evidence-batch-size",
        type=_bounded_integer(
            minimum=1,
            maximum=1_000,
            label="evidence retention batch",
        ),
        default=100,
    )
    parser.add_argument(
        "--audit-batch-size",
        type=_bounded_integer(
            minimum=1,
            maximum=10_000,
            label="audit retention batch",
        ),
        default=100,
    )
    return parser.parse_args(argv)


def build_retention_coordinators(
    *,
    arguments: argparse.Namespace,
    site: SiteConfig,
    sessions: SessionFactory,
    evidence_store: EvidenceDeleteStore,
    archive_store: AuditArchiveStore,
    clock: Callable[[], datetime] | None = None,
) -> tuple[EvidenceRetentionCoordinator, AuditArchiveCoordinator]:
    evidence = EvidenceRetentionCoordinator(
        session_factory=sessions,
        object_store=evidence_store,
        pilot_site_id=arguments.site_id,
        retention_days=site.storage.retention.evidence_retention_days,
        batch_size=arguments.evidence_batch_size,
        clock=clock,
    )
    audit = AuditArchiveCoordinator(
        session_factory=sessions,
        archive_store=archive_store,
        pruner=PostgresReceiptBoundAuditPruner(sessions),
        pilot_site_id=arguments.site_id,
        retention_days=site.storage.retention.metadata_retention_days,
        batch_size=arguments.audit_batch_size,
        clock=clock,
    )
    return evidence, audit


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_retention_arguments(argv)
    site = _reviewed_config(arguments.site_config, arguments.site_config_sha256)
    if site.storage.evidence_prefix.split("/")[-1] != arguments.site_id:
        raise RuntimeError("retention evidence prefix is not site scoped")
    archive_prefix = arguments.archive_prefix.rstrip("/")
    evidence_prefix = site.storage.evidence_prefix.rstrip("/")
    if (
        archive_prefix.split("/")[-1] != arguments.site_id
        or archive_prefix == evidence_prefix
        or archive_prefix.startswith(f"{evidence_prefix}/")
    ):
        raise RuntimeError("audit archive prefix must be separate and site scoped")
    database_url = _read_secret(arguments.database_url_secret)
    lock_connection = psycopg.connect(database_url, autocommit=True)
    acquired = lock_connection.execute(
        "SELECT pg_try_advisory_lock(hashtextextended(%s, 12))",
        (f"kuzet-retention:{arguments.site_id}",),
    ).fetchone()[0]
    if acquired is not True:
        lock_connection.close()
        raise RuntimeError("another retention worker already owns the site lease")
    engine = create_engine(database_url)
    sessions = create_session_factory(engine)
    client = boto3.client(
        "s3",
        endpoint_url=str(site.storage.endpoint).rstrip("/"),
        aws_access_key_id=_read_secret(arguments.access_key_secret),
        aws_secret_access_key=_read_secret(arguments.secret_key_secret),
    )
    evidence_store = S3CompatibleObjectStore(
        client=client,
        endpoint=str(site.storage.endpoint).rstrip("/"),
        bucket=site.storage.bucket,
        country_code=site.storage.country_code,
        evidence_prefix=site.storage.evidence_prefix,
        max_object_bytes=site.storage.max_evidence_object_bytes,
        server_side_encryption=site.storage.server_side_encryption,
        kms_key_id=site.storage.kms_key_id,
    )
    archive_store = EncryptedAuditArchiveStore(
        client=client,
        bucket=site.storage.bucket,
        archive_prefix=arguments.archive_prefix,
        site_id=arguments.site_id,
        age_recipient_file=arguments.archive_age_recipient,
        signing_private_key_file=arguments.archive_signing_private_key,
        signing_public_key_file=arguments.archive_signing_public_key,
        signing_key_id=arguments.archive_signing_key_id,
        server_side_encryption=site.storage.server_side_encryption,
        kms_key_id=site.storage.kms_key_id,
    )
    evidence, audit = build_retention_coordinators(
        arguments=arguments,
        site=site,
        sessions=sessions,
        evidence_store=evidence_store,
        archive_store=archive_store,
        clock=lambda: datetime.now(UTC),
    )
    try:
        while True:
            evidence_result = evidence.run_once()
            audit_result = audit.run_once()
            if evidence_result.failed or audit_result.failed:
                raise RuntimeError("retention batch failed closed")
            time.sleep(arguments.interval_seconds)
    finally:
        engine.dispose()
        lock_connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
