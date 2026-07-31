from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from protector.pilot.preview_retention import (
    PreviewOrphanSweeper,
    PreviewRetentionCoordinator,
)
from protector.pilot.storage.preview import (
    PreviewObjectReceiptV1,
    PreviewObjectVersionPageV1,
    PreviewObjectVersionV1,
)

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


def _receipt(*, event_id: UUID | None = None) -> PreviewObjectReceiptV1:
    selected_event = event_id or uuid4()
    evidence_id = uuid4()
    return PreviewObjectReceiptV1(
        schema_version="preview-object-receipt.v1",
        site_id="site-1",
        event_id=selected_event,
        evidence_id=evidence_id,
        object_key=(
            f"site-1/{selected_event}/{evidence_id}/{'a' * 64}.mp4"
        ),
        sha256="a" * 64,
        checksum_sha256="qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
        size_bytes=1024,
        media_type="video/mp4",
        etag='"preview-etag"',
        version_id="version-1",
        server_side_encryption="AES256",
        kms_key_id=None,
        configuration_sha256="b" * 64,
        runtime_session_id="runtime-1",
        runtime_writer_generation=3,
        configuration_activation_generation=2,
        source_epoch=uuid4(),
        rule_revision_sha256="c" * 64,
        candidate_body_sha256="d" * 64,
        created_at=NOW - timedelta(days=31),
    )


class _Repository:
    def __init__(self, receipts: tuple[PreviewObjectReceiptV1, ...]) -> None:
        self.receipts = receipts
        self.operations: list[str] = []
        self.finalized: list[str] = []
        self.protected: set[tuple[str, str]] = set()
        self.pruned = 0
        self.expired_intents = 0

    def claim_preview_receipts_for_retention(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> tuple[PreviewObjectReceiptV1, ...]:
        assert site_id == "site-1"
        assert cutoff_at == NOW - timedelta(days=30)
        self.operations.append("claim")
        return self.receipts[:limit]

    def finalize_preview_retirement(
        self,
        *,
        site_id: str,
        event_id: UUID,
        receipt_sha256: str,
        retired_at: datetime,
    ) -> bool:
        assert site_id == "site-1"
        assert retired_at == NOW
        self.operations.append("finalize")
        self.finalized.append(f"{event_id}:{receipt_sha256}")
        return True

    def preview_version_is_protected(
        self,
        *,
        site_id: str,
        object_key: str,
        version_id: str,
        observed_at: datetime,
    ) -> bool:
        assert site_id == "site-1"
        assert observed_at == NOW
        return (object_key, version_id) in self.protected

    def prune_preview_access_receipts(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> int:
        assert site_id == "site-1"
        assert cutoff_at == NOW - timedelta(days=90)
        assert limit == 10
        return self.pruned

    def retire_expired_preview_intents(
        self,
        *,
        site_id: str,
        observed_at: datetime,
        limit: int,
    ) -> int:
        assert site_id == "site-1"
        assert observed_at == NOW
        assert limit == 10
        return self.expired_intents


class _Store:
    def __init__(
        self,
        page: PreviewObjectVersionPageV1 | None = None,
    ) -> None:
        self.operations: list[str] = []
        self.deleted_receipts: list[PreviewObjectReceiptV1] = []
        self.deleted_versions: list[tuple[str, str, str]] = []
        self.fail_delete = False
        self.page = page or PreviewObjectVersionPageV1(
            versions=(),
            next_key_marker=None,
            next_version_id_marker=None,
        )

    def delete_exact(self, receipt: PreviewObjectReceiptV1) -> None:
        self.operations.append("delete")
        if self.fail_delete:
            raise RuntimeError("object store unavailable")
        self.deleted_receipts.append(receipt)

    def list_versions(
        self,
        *,
        max_items: int,
        key_marker: str | None = None,
        version_id_marker: str | None = None,
    ) -> PreviewObjectVersionPageV1:
        assert max_items == 10
        assert (key_marker, version_id_marker) in (
            (None, None),
            ("next-key", "next-version"),
        )
        return self.page

    def delete_version(
        self,
        *,
        object_key: str,
        version_id: str,
        etag: str,
    ) -> None:
        if self.fail_delete:
            raise RuntimeError("object store unavailable")
        self.deleted_versions.append((object_key, version_id, etag))


def _coordinator(
    repository: _Repository,
    store: _Store,
) -> PreviewRetentionCoordinator:
    return PreviewRetentionCoordinator(
        repository=repository,
        object_store=store,
        site_id="site-1",
        retention_days=30,
        metadata_retention_days=90,
        batch_size=10,
        clock=lambda: NOW,
    )


def test_registered_preview_is_claimed_before_exact_delete_and_finalize() -> None:
    receipt = _receipt()
    repository = _Repository((receipt,))
    store = _Store()

    result = _coordinator(repository, store).run_once()

    assert repository.operations == ["claim", "finalize"]
    assert store.operations == ["delete"]
    assert store.deleted_receipts == [receipt]
    assert result.scanned == 1
    assert result.retired == 1
    assert result.expired_intents_retired == 0
    assert result.failed == 0


def test_delete_failure_keeps_terminal_claim_retryable() -> None:
    receipt = _receipt()
    repository = _Repository((receipt,))
    store = _Store()
    store.fail_delete = True
    coordinator = _coordinator(repository, store)

    failed = coordinator.run_once()
    store.fail_delete = False
    recovered = coordinator.run_once()

    assert failed.failed == 1
    assert failed.retired == 0
    assert recovered.retired == 1
    assert store.deleted_receipts == [receipt]


def _version(
    name: str,
    *,
    age_seconds: int,
) -> PreviewObjectVersionV1:
    return PreviewObjectVersionV1(
        object_key=f"site-1/{name}",
        version_id=f"version-{name}",
        etag=f'"etag-{name}"',
        size_bytes=128,
        last_modified=NOW - timedelta(seconds=age_seconds),
    )


def test_orphan_sweep_respects_grace_and_durable_protection() -> None:
    protected = _version("protected.mp4", age_seconds=7200)
    orphan = _version("orphan.mp4", age_seconds=7200)
    fresh = _version("fresh.mp4", age_seconds=30)
    page = PreviewObjectVersionPageV1(
        versions=(protected, orphan, fresh),
        next_key_marker="next-key",
        next_version_id_marker="next-version",
    )
    repository = _Repository(())
    repository.protected.add(
        (protected.object_key, protected.version_id)
    )
    store = _Store(page)
    sweeper = PreviewOrphanSweeper(
        repository=repository,
        object_store=store,
        site_id="site-1",
        batch_size=10,
        publication_grace_seconds=60,
        clock=lambda: NOW,
    )

    result = sweeper.run_once()

    assert store.deleted_versions == [
        (orphan.object_key, orphan.version_id, orphan.etag)
    ]
    assert result.deleted == 1
    assert result.protected == 1
    assert result.grace_retained == 1
    assert result.next_key_marker == "next-key"
    assert result.next_version_id_marker == "next-version"


@pytest.mark.parametrize(
    ("batch_size", "grace"),
    ((0, 60), (1001, 60), (10, 59), (10, 86401), (True, 60)),
)
def test_orphan_sweep_rejects_unbounded_configuration(
    batch_size: object,
    grace: object,
) -> None:
    with pytest.raises(ValueError):
        PreviewOrphanSweeper(
            repository=_Repository(()),
            object_store=_Store(),
            site_id="site-1",
            batch_size=batch_size,  # type: ignore[arg-type]
            publication_grace_seconds=grace,  # type: ignore[arg-type]
            clock=lambda: NOW,
        )
