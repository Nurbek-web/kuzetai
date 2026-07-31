"""Finite registered-preview retention and crash-gap orphan reconciliation."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from protector.pilot.storage.preview import (
    PreviewObjectReceiptV1,
    PreviewObjectVersionPageV1,
    PreviewObjectVersionV1,
)

_SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class PreviewRetentionRepository(Protocol):
    """Atomic database transitions owned by the retention identity."""

    def claim_preview_receipts_for_retention(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> tuple[PreviewObjectReceiptV1, ...]: ...

    def finalize_preview_retirement(
        self,
        *,
        site_id: str,
        event_id: UUID,
        receipt_sha256: str,
        retired_at: datetime,
    ) -> bool: ...

    def preview_version_is_protected(
        self,
        *,
        site_id: str,
        object_key: str,
        version_id: str,
        observed_at: datetime,
    ) -> bool: ...

    def prune_preview_access_receipts(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> int: ...

    def retire_expired_preview_intents(
        self,
        *,
        site_id: str,
        observed_at: datetime,
        limit: int,
    ) -> int: ...


class PreviewRetentionStore(Protocol):
    def delete_exact(self, receipt: PreviewObjectReceiptV1) -> None: ...

    def list_versions(
        self,
        *,
        max_items: int,
        key_marker: str | None = None,
        version_id_marker: str | None = None,
    ) -> PreviewObjectVersionPageV1: ...

    def delete_version(
        self,
        *,
        object_key: str,
        version_id: str,
        etag: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class PreviewRetentionResult:
    scanned: int
    retired: int
    retained: int
    expired_intents_retired: int
    access_receipts_pruned: int
    failed: int
    failure_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PreviewOrphanSweepResult:
    scanned: int
    deleted: int
    protected: int
    grace_retained: int
    failed: int
    failure_reasons: tuple[str, ...]
    next_key_marker: str | None
    next_version_id_marker: str | None


def _utc_now(
    clock: Callable[[], datetime],
    *,
    label: str,
) -> datetime:
    value = clock()
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{label} must return a timezone-aware time")
    return value.astimezone(UTC)


class PreviewRetentionCoordinator:
    """Terminalize receipt visibility before exact version deletion."""

    def __init__(
        self,
        *,
        repository: PreviewRetentionRepository,
        object_store: PreviewRetentionStore,
        site_id: str,
        retention_days: int,
        metadata_retention_days: int,
        batch_size: int,
        clock: Callable[[], datetime],
    ) -> None:
        if _SITE_ID.fullmatch(site_id) is None:
            raise ValueError("preview retention site identity is invalid")
        for value, label in (
            (retention_days, "preview retention"),
            (metadata_retention_days, "preview metadata retention"),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= 365
            ):
                raise ValueError(f"{label} must be between 1 and 365 days")
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or not 1 <= batch_size <= 1_000
        ):
            raise ValueError("preview retention batch must be between 1 and 1000")
        if not callable(clock):
            raise TypeError("preview retention clock must be callable")
        self._repository = repository
        self._store = object_store
        self.site_id = site_id
        self.retention_days = retention_days
        self.metadata_retention_days = metadata_retention_days
        self.batch_size = batch_size
        self._clock = clock

    def run_once(self) -> PreviewRetentionResult:
        now = _utc_now(self._clock, label="preview retention clock")
        cutoff = now - timedelta(days=self.retention_days)
        try:
            expired_intents = (
                self._repository.retire_expired_preview_intents(
                    site_id=self.site_id,
                    observed_at=now,
                    limit=self.batch_size,
                )
            )
            if (
                not isinstance(expired_intents, int)
                or isinstance(expired_intents, bool)
                or not 0 <= expired_intents <= self.batch_size
            ):
                raise RuntimeError(
                    "expired preview intent retirement exceeded its bound"
                )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            expired_intents = 0
            intent_retirement_failed = True
        else:
            intent_retirement_failed = False
        receipts = self._repository.claim_preview_receipts_for_retention(
            site_id=self.site_id,
            cutoff_at=cutoff,
            limit=self.batch_size,
        )
        if (
            not isinstance(receipts, tuple)
            or len(receipts) > self.batch_size
            or any(
                not isinstance(receipt, PreviewObjectReceiptV1)
                or receipt.site_id != self.site_id
                for receipt in receipts
            )
        ):
            raise RuntimeError(
                "preview retention repository violated its finite claim"
            )
        retired = 0
        failed = 0
        reasons: set[str] = set()
        if intent_retirement_failed:
            failed += 1
            reasons.add("preview_intent_retirement_failed")
        for receipt in receipts:
            try:
                self._store.delete_exact(receipt)
                finalized = self._repository.finalize_preview_retirement(
                    site_id=self.site_id,
                    event_id=receipt.event_id,
                    receipt_sha256=receipt.receipt_sha256,
                    retired_at=now,
                )
                if finalized is not True:
                    raise RuntimeError(
                        "preview retirement finalization lost its claim"
                    )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                failed += 1
                reasons.add("preview_retirement_failed")
                continue
            retired += 1
        try:
            pruned = self._repository.prune_preview_access_receipts(
                site_id=self.site_id,
                cutoff_at=now
                - timedelta(days=self.metadata_retention_days),
                limit=self.batch_size,
            )
            if (
                not isinstance(pruned, int)
                or isinstance(pruned, bool)
                or not 0 <= pruned <= self.batch_size
            ):
                raise RuntimeError(
                    "preview access prune violated its finite batch"
                )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            pruned = 0
            failed += 1
            reasons.add("preview_access_prune_failed")
        return PreviewRetentionResult(
            scanned=len(receipts),
            retired=retired,
            retained=failed,
            expired_intents_retired=expired_intents,
            access_receipts_pruned=pruned,
            failed=failed,
            failure_reasons=tuple(sorted(reasons)),
        )


class PreviewOrphanSweeper:
    """Delete only exact old versions lacking a durable receipt or live intent."""

    def __init__(
        self,
        *,
        repository: PreviewRetentionRepository,
        object_store: PreviewRetentionStore,
        site_id: str,
        batch_size: int,
        publication_grace_seconds: int,
        clock: Callable[[], datetime],
    ) -> None:
        if _SITE_ID.fullmatch(site_id) is None:
            raise ValueError("preview orphan site identity is invalid")
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or not 1 <= batch_size <= 1_000
        ):
            raise ValueError("preview orphan batch must be between 1 and 1000")
        if (
            not isinstance(publication_grace_seconds, int)
            or isinstance(publication_grace_seconds, bool)
            or not 60 <= publication_grace_seconds <= 86_400
        ):
            raise ValueError(
                "preview orphan grace must be between 60 and 86400 seconds"
            )
        if not callable(clock):
            raise TypeError("preview orphan clock must be callable")
        self._repository = repository
        self._store = object_store
        self.site_id = site_id
        self.batch_size = batch_size
        self._grace = timedelta(seconds=publication_grace_seconds)
        self._clock = clock

    def run_once(
        self,
        *,
        key_marker: str | None = None,
        version_id_marker: str | None = None,
    ) -> PreviewOrphanSweepResult:
        now = _utc_now(self._clock, label="preview orphan clock")
        page = self._store.list_versions(
            max_items=self.batch_size,
            key_marker=key_marker,
            version_id_marker=version_id_marker,
        )
        if (
            not isinstance(page, PreviewObjectVersionPageV1)
            or len(page.versions) > self.batch_size
        ):
            raise RuntimeError(
                "preview orphan store violated its finite page"
            )
        deleted = 0
        protected = 0
        grace_retained = 0
        failed = 0
        reasons: set[str] = set()
        for version in page.versions:
            if not isinstance(version, PreviewObjectVersionV1):
                raise RuntimeError("preview orphan version is invalid")
            if (
                version.last_modified > now
                or now - version.last_modified < self._grace
            ):
                grace_retained += 1
                continue
            if version.object_key.split("/", 1)[0] != self.site_id:
                failed += 1
                reasons.add("preview_orphan_site_mismatch")
                continue
            try:
                is_protected = self._repository.preview_version_is_protected(
                    site_id=self.site_id,
                    object_key=version.object_key,
                    version_id=version.version_id,
                    observed_at=now,
                )
                if is_protected is True:
                    protected += 1
                    continue
                if is_protected is not False:
                    raise RuntimeError(
                        "preview orphan protection result is invalid"
                    )
                self._store.delete_version(
                    object_key=version.object_key,
                    version_id=version.version_id,
                    etag=version.etag,
                )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                failed += 1
                reasons.add("preview_orphan_reconciliation_failed")
                continue
            deleted += 1
        return PreviewOrphanSweepResult(
            scanned=len(page.versions),
            deleted=deleted,
            protected=protected,
            grace_retained=grace_retained,
            failed=failed,
            failure_reasons=tuple(sorted(reasons)),
            next_key_marker=page.next_key_marker,
            next_version_id_marker=page.next_version_id_marker,
        )
