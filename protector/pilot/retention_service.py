"""Singleton production retention worker for bounded evidence and audit metadata."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import boto3
import psycopg
from botocore.config import Config

from protector.pilot.audit_archive import EncryptedAuditArchiveStore
from protector.pilot.config import SiteConfig
from protector.pilot.gates import site_config_sha256
from protector.pilot.operational_retention import (
    OperationalMetadataRetentionCoordinator,
)
from protector.pilot.preview_retention import (
    PreviewOrphanSweeper,
    PreviewRetentionCoordinator,
)
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
    require_dbapi_database_role,
    require_sqlalchemy_database_role,
)
from protector.pilot.storage.object_store import S3CompatibleObjectStore
from protector.pilot.storage.preview import S3PreviewObjectStore
from protector.pilot.storage.repositories import PilotRepository
from protector.pilot.trusted_yaml import load_strict_yaml

_MAX_SECRET_BYTES = 16 * 1024
_MAX_CONFIG_BYTES = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REGION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_PREVIEW_BYTES = 16 * 1024 * 1024
_S3_CLIENT_CONFIG = Config(
    connect_timeout=5,
    read_timeout=30,
    retries={"max_attempts": 3, "mode": "standard"},
)


@dataclass(frozen=True, slots=True)
class _RetentionLease:
    backend_pid: int
    class_id: int
    object_id: int


def _acquire_retention_lease(
    connection: object,
    *,
    site_id: str,
) -> _RetentionLease:
    lease_name = f"kuzet-retention:{site_id}"
    identity = connection.execute(  # type: ignore[attr-defined]
        "SELECT pg_backend_pid(), hashtextextended(%s, 12)",
        (lease_name,),
    ).fetchone()
    if (
        not isinstance(identity, (tuple, list))
        or len(identity) != 2
        or type(identity[0]) is not int
        or type(identity[1]) is not int
    ):
        raise RuntimeError("retention lease identity is unavailable")
    backend_pid, lock_key = identity
    acquired = connection.execute(  # type: ignore[attr-defined]
        "SELECT pg_try_advisory_lock(%s)",
        (lock_key,),
    ).fetchone()
    if (
        not isinstance(acquired, (tuple, list))
        or len(acquired) != 1
        or acquired[0] is not True
    ):
        raise RuntimeError("another retention worker already owns the site lease")
    return _RetentionLease(
        backend_pid=backend_pid,
        class_id=(lock_key >> 32) & 0xFFFFFFFF,
        object_id=lock_key & 0xFFFFFFFF,
    )


def _require_retention_lease(
    connection: object,
    *,
    lease: _RetentionLease,
) -> None:
    """Fail closed if a restart or broken connection released the exact lock."""

    observed = connection.execute(  # type: ignore[attr-defined]
        """
        SELECT pg_backend_pid(),
               EXISTS (
                 SELECT 1
                   FROM pg_locks
                  WHERE locktype = 'advisory'
                    AND pid = pg_backend_pid()
                    AND pid = %s
                    AND classid::bigint = %s
                    AND objid::bigint = %s
                    AND objsubid = 1
                    AND mode = 'ExclusiveLock'
                    AND granted
               )
        """,
        (
            lease.backend_pid,
            lease.class_id,
            lease.object_id,
        ),
    ).fetchone()
    if (
        not isinstance(observed, (tuple, list))
        or len(observed) != 2
        or observed[0] != lease.backend_pid
        or observed[1] is not True
    ):
        raise RuntimeError("retention site lease was lost")


def _require_separate_site_scoped_prefixes(
    *,
    archive_prefix: str,
    evidence_prefix: str,
    site_id: str,
) -> None:
    archive_prefix = archive_prefix.rstrip("/")
    evidence_prefix = evidence_prefix.rstrip("/")
    if (
        archive_prefix.split("/")[-1] != site_id
        or evidence_prefix.split("/")[-1] != site_id
        or archive_prefix == evidence_prefix
        or archive_prefix.startswith(f"{evidence_prefix}/")
        or evidence_prefix.startswith(f"{archive_prefix}/")
    ):
        raise RuntimeError("audit archive prefix must be separate and site scoped")


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
    if (
        not path.is_absolute()
        or path == Path(path.anchor)
        or _SHA256.fullmatch(expected_sha256) is None
    ):
        raise RuntimeError("retention site configuration is unavailable")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= _MAX_CONFIG_BYTES
        ):
            raise RuntimeError(
                "retention site configuration exceeds finite bound"
            )
        payload = os.read(descriptor, _MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise RuntimeError(
            "retention site configuration is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) != metadata.st_size:
        raise RuntimeError("retention site configuration changed during read")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise RuntimeError("retention site configuration digest mismatch")
    parsed = load_strict_yaml(
        payload,
        max_bytes=_MAX_CONFIG_BYTES,
        max_nodes=20_000,
        max_depth=64,
        require_mapping=True,
    )
    return SiteConfig.model_validate(parsed)


def _require_active_reviewed_configuration(
    *,
    repository: PilotRepository,
    site_id: str,
    site: SiteConfig,
) -> None:
    """Fence object deletion against the canonical active DB revision."""

    canonical_digest = site_config_sha256(site)
    try:
        active_digest = repository.get_active_site_config_sha256(
            site_id=site_id,
        )
    except Exception as exc:
        raise RuntimeError(
            "retention active reviewed configuration is unavailable"
        ) from exc
    if active_digest != canonical_digest:
        raise RuntimeError(
            "retention mounted configuration is not the active reviewed revision"
        )


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


def _bounded_region(value: str) -> str:
    if _REGION.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("object-store region is invalid")
    return value


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
        "--object-store-region",
        type=_bounded_region,
        required=True,
    )
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
    parser.add_argument(
        "--preview-batch-size",
        type=_bounded_integer(
            minimum=1,
            maximum=1_000,
            label="preview retention batch",
        ),
        default=100,
    )
    parser.add_argument(
        "--preview-publication-grace-seconds",
        type=_bounded_integer(
            minimum=60,
            maximum=86_400,
            label="preview publication grace",
        ),
        default=3_600,
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


def build_preview_retention_coordinators(
    *,
    arguments: argparse.Namespace,
    site: SiteConfig,
    repository: PilotRepository,
    preview_store: S3PreviewObjectStore,
    clock: Callable[[], datetime],
) -> tuple[PreviewRetentionCoordinator, PreviewOrphanSweeper]:
    """Build finite registered and crash-gap preview cleanup workers."""

    registered = PreviewRetentionCoordinator(
        repository=repository,
        object_store=preview_store,
        site_id=arguments.site_id,
        retention_days=site.storage.retention.evidence_retention_days,
        metadata_retention_days=(
            site.storage.retention.metadata_retention_days
        ),
        batch_size=arguments.preview_batch_size,
        clock=clock,
    )
    orphan = PreviewOrphanSweeper(
        repository=repository,
        object_store=preview_store,
        site_id=arguments.site_id,
        batch_size=arguments.preview_batch_size,
        publication_grace_seconds=(
            arguments.preview_publication_grace_seconds
        ),
        clock=clock,
    )
    return registered, orphan


def _advance_preview_cursor(
    *,
    previous: tuple[str | None, str | None],
    next_cursor: tuple[str | None, str | None],
) -> tuple[str | None, str | None]:
    """Accept one complete, finite, forward-moving S3 version cursor."""

    key_marker, version_marker = next_cursor
    if (key_marker is None) != (version_marker is None):
        raise RuntimeError("preview orphan cursor is incomplete")
    for marker in next_cursor:
        if marker is not None and (
            not marker
            or len(marker) > 2_048
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in marker
            )
        ):
            raise RuntimeError("preview orphan cursor is invalid")
    if next_cursor == previous and next_cursor != (None, None):
        raise RuntimeError("preview orphan cursor did not advance")
    return next_cursor


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_retention_arguments(argv)
    site = _reviewed_config(arguments.site_config, arguments.site_config_sha256)
    _require_separate_site_scoped_prefixes(
        archive_prefix=arguments.archive_prefix,
        evidence_prefix=site.storage.evidence_prefix,
        site_id=arguments.site_id,
    )
    database_url = _read_secret(arguments.database_url_secret)
    lock_connection = psycopg.connect(database_url, autocommit=True)
    try:
        require_dbapi_database_role(
            lock_connection,
            expected_role="kuzet_retention",
        )
        lease = _acquire_retention_lease(
            lock_connection,
            site_id=arguments.site_id,
        )
    except BaseException:
        lock_connection.close()
        raise
    engine = create_engine(database_url)
    try:
        require_sqlalchemy_database_role(
            engine,
            expected_role="kuzet_retention",
        )
    except BaseException:
        engine.dispose()
        lock_connection.close()
        raise
    sessions = create_session_factory(engine)
    repository = PilotRepository(sessions)
    try:
        _require_active_reviewed_configuration(
            repository=repository,
            site_id=arguments.site_id,
            site=site,
        )
    except BaseException:
        engine.dispose()
        lock_connection.close()
        raise
    client = boto3.client(
        "s3",
        endpoint_url=str(site.storage.endpoint).rstrip("/"),
        region_name=arguments.object_store_region,
        aws_access_key_id=_read_secret(arguments.access_key_secret),
        aws_secret_access_key=_read_secret(arguments.secret_key_secret),
        config=_S3_CLIENT_CONFIG,
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
    evidence_store.attest_bounded_lifecycle(
        retention_days=site.storage.retention.evidence_retention_days,
    )
    preview_store = S3PreviewObjectStore(
        client=client,
        endpoint=str(site.storage.endpoint).rstrip("/"),
        bucket=site.storage.bucket,
        country_code=site.storage.country_code,
        preview_prefix=f"{site.storage.evidence_prefix}/previews",
        max_preview_bytes=min(
            _MAX_PREVIEW_BYTES,
            site.storage.max_evidence_object_bytes,
        ),
        server_side_encryption=site.storage.server_side_encryption,
        kms_key_id=site.storage.kms_key_id,
    )
    preview_store.attest_bounded_lifecycle(
        retention_days=site.storage.retention.evidence_retention_days,
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
    preview, preview_orphans = build_preview_retention_coordinators(
        arguments=arguments,
        site=site,
        repository=repository,
        preview_store=preview_store,
        clock=lambda: datetime.now(UTC),
    )
    metadata = OperationalMetadataRetentionCoordinator(
        repository=repository,
        site_id=arguments.site_id,
        metadata_retention_days=(
            site.storage.retention.metadata_retention_days
        ),
        batch_size=arguments.preview_batch_size,
        clock=lambda: datetime.now(UTC),
    )
    preview_cursor: tuple[str | None, str | None] = (None, None)
    try:
        while True:
            _require_retention_lease(
                lock_connection,
                lease=lease,
            )
            _require_active_reviewed_configuration(
                repository=repository,
                site_id=arguments.site_id,
                site=site,
            )
            evidence_store.attest_bounded_lifecycle(
                retention_days=(
                    site.storage.retention.evidence_retention_days
                ),
            )
            preview_store.attest_bounded_lifecycle(
                retention_days=(
                    site.storage.retention.evidence_retention_days
                ),
            )
            _require_retention_lease(
                lock_connection,
                lease=lease,
            )
            evidence_result = evidence.run_once()
            _require_retention_lease(
                lock_connection,
                lease=lease,
            )
            audit_result = audit.run_once()
            _require_retention_lease(
                lock_connection,
                lease=lease,
            )
            preview_result = preview.run_once()
            _require_retention_lease(
                lock_connection,
                lease=lease,
            )
            metadata_result = metadata.run_once()
            _require_retention_lease(
                lock_connection,
                lease=lease,
            )
            orphan_result = preview_orphans.run_once(
                key_marker=preview_cursor[0],
                version_id_marker=preview_cursor[1],
            )
            preview_cursor = _advance_preview_cursor(
                previous=preview_cursor,
                next_cursor=(
                    orphan_result.next_key_marker,
                    orphan_result.next_version_id_marker,
                ),
            )
            if (
                evidence_result.failed
                or audit_result.failed
                or preview_result.failed
                or metadata_result.failed
                or orphan_result.failed
            ):
                raise RuntimeError("retention batch failed closed")
            time.sleep(arguments.interval_seconds)
    finally:
        engine.dispose()
        lock_connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
