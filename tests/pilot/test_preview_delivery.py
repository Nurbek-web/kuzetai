from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest

from protector.pilot.storage.preview import (
    DurablePreviewPublisher,
    DurablePreviewEvidenceCoordinator,
    PreviewAccessDenied,
    PreviewAccessReceipt,
    PreviewIntegrityError,
    PreviewObjectContext,
    PreviewObjectReceiptV1,
    PreviewPublicationIntentV1,
    PreviewPayload,
    ProductionPreviewProvider,
    S3PreviewObjectStore,
)

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
SOURCE_EPOCH = UUID("30000000-0000-0000-0000-000000000003")
OTHER_SOURCE_EPOCH = UUID("40000000-0000-0000-0000-000000000004")


class _Body:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._offset = 0
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._payload) - self._offset
        result = self._payload[self._offset : self._offset + size]
        self._offset += len(result)
        return result

    def close(self) -> None:
        self.closed = True


class _S3:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}
        self.head_calls: list[str] = []
        self.get_calls: list[str] = []
        self.put_calls: list[str] = []
        self.short_read = False

    def head_object(
        self,
        *,
        Bucket: str,
        Key: str,
        ChecksumMode: str,
        **kwargs: str,
    ) -> dict[str, Any]:
        assert ChecksumMode == "ENABLED"
        self.head_calls.append(Key)
        try:
            stored = self.objects[(Bucket, Key)]
        except KeyError as exc:
            raise KeyError(Key) from exc
        if "VersionId" in kwargs:
            assert kwargs["VersionId"] == stored["VersionId"]
        return {
            name: stored[name]
            for name in (
                "ContentLength",
                "ChecksumSHA256",
                "ServerSideEncryption",
                "SSEKMSKeyId",
                "ContentType",
                "ETag",
                "VersionId",
                "Metadata",
            )
            if name in stored
        }

    def put_object(self, **arguments: Any) -> dict[str, str]:
        key = str(arguments["Key"])
        self.put_calls.append(key)
        assert arguments["IfNoneMatch"] == "*"
        assert arguments["ChecksumAlgorithm"] == "SHA256"
        assert arguments["ContentType"] == "video/mp4"
        identity = (str(arguments["Bucket"]), key)
        if identity in self.objects:
            error = RuntimeError("precondition failed")
            error.response = {"Error": {"Code": "PreconditionFailed"}}  # type: ignore[attr-defined]
            raise error
        payload = bytes(arguments["Body"])
        self.objects[identity] = {
            "Body": payload,
            "ContentLength": len(payload),
            "ChecksumSHA256": arguments["ChecksumSHA256"],
            "ServerSideEncryption": arguments["ServerSideEncryption"],
            "ContentType": arguments["ContentType"],
            "ETag": '"preview-etag"',
            "VersionId": "preview-version-1",
            "Metadata": dict(arguments["Metadata"]),
        }
        if "SSEKMSKeyId" in arguments:
            self.objects[identity]["SSEKMSKeyId"] = arguments["SSEKMSKeyId"]
        return {
            "ETag": '"preview-etag"',
            "VersionId": "preview-version-1",
        }

    def get_object(self, **arguments: Any) -> dict[str, Any]:
        key = str(arguments["Key"])
        self.get_calls.append(key)
        stored = self.objects[(str(arguments["Bucket"]), key)]
        assert arguments["Range"] == (
            f"bytes=0-{int(stored['ContentLength']) - 1}"
        )
        assert arguments["IfMatch"] == stored["ETag"]
        assert arguments["VersionId"] == stored["VersionId"]
        payload = bytes(stored["Body"])
        if self.short_read:
            payload = payload[:-1]
        return {
            "Body": _Body(payload),
            "ContentLength": len(payload),
            "ContentRange": (
                f"bytes 0-{int(stored['ContentLength']) - 1}/"
                f"{int(stored['ContentLength'])}"
            ),
            "ETag": stored["ETag"],
            "VersionId": stored["VersionId"],
        }


def _store(client: _S3) -> S3PreviewObjectStore:
    return S3PreviewObjectStore(
        client=client,
        endpoint="https://objects.example.test",
        bucket="pilot-evidence",
        country_code="KZ",
        preview_prefix="site-previews",
        max_preview_bytes=1024,
        server_side_encryption="aws:kms",
        kms_key_id="alias/kuzet-preview",
    )


def _evidence_id(event_id: UUID) -> UUID:
    return uuid5(NAMESPACE_URL, f"kuzet-preview:{event_id}")


def _context(event_id: UUID) -> PreviewObjectContext:
    return PreviewObjectContext(
        site_id="site-1",
        event_id=event_id,
        evidence_id=_evidence_id(event_id),
        configuration_sha256="a" * 64,
        runtime_session_id="runtime-session-1",
        runtime_writer_generation=7,
        configuration_activation_generation=4,
        source_epoch=SOURCE_EPOCH,
        rule_revision_sha256="b" * 64,
        candidate_body_sha256="c" * 64,
    )


def _intent(
    store: S3PreviewObjectStore,
    event_id: UUID,
    sha256: str,
    *,
    created_at: datetime = NOW,
) -> PreviewPublicationIntentV1:
    context = _context(event_id)
    return PreviewPublicationIntentV1(
        schema_version="preview-publication-intent.v1",
        site_id=context.site_id,
        event_id=context.event_id,
        evidence_id=context.evidence_id,
        object_key=store.planned_object_key(context, sha256),
        sha256=sha256,
        configuration_sha256=context.configuration_sha256,
        runtime_session_id=context.runtime_session_id,
        runtime_writer_generation=context.runtime_writer_generation,
        configuration_activation_generation=(
            context.configuration_activation_generation
        ),
        source_epoch=context.source_epoch,
        rule_revision_sha256=context.rule_revision_sha256,
        candidate_body_sha256=context.candidate_body_sha256,
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=15),
    )


def test_preview_publish_is_conditional_verified_and_replay_safe(
    tmp_path: Path,
) -> None:
    client = _S3()
    store = _store(client)
    event_id = uuid4()
    payload = b"bounded-browser-preview"
    source = tmp_path / "preview.mp4"
    source.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    intent = _intent(store, event_id, digest)
    first = store.publish(source, intent=intent, sha256=digest)
    second = store.publish(source, intent=intent, sha256=digest)

    assert first == second
    assert len(client.put_calls) == 1
    assert first.schema_version == "preview-object-receipt.v1"
    assert first.site_id == "site-1"
    assert first.event_id == event_id
    assert first.sha256 == digest
    assert first.size_bytes == len(payload)
    assert first.checksum_sha256 == base64.b64encode(
        hashlib.sha256(payload).digest()
    ).decode()
    assert first.etag == '"preview-etag"'
    assert first.version_id == "preview-version-1"
    assert first.server_side_encryption == "aws:kms"
    assert first.kms_key_id == "alias/kuzet-preview"
    assert "site-1" in first.object_key
    assert str(event_id) in first.object_key


def test_preview_publish_rejects_existing_object_with_changed_identity(
    tmp_path: Path,
) -> None:
    client = _S3()
    store = _store(client)
    event_id = uuid4()
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    receipt = store.publish(
        source,
        intent=_intent(store, event_id, digest),
        sha256=digest,
    )
    remote = client.objects[("pilot-evidence", f"site-previews/{receipt.object_key}")]
    remote["Metadata"]["runtime-session-id"] = "different-runtime"

    with pytest.raises(PreviewIntegrityError):
        store.publish(
            source,
            intent=_intent(store, event_id, digest),
            sha256=digest,
        )


def test_preview_replay_cannot_rebind_existing_object_creation_time(
    tmp_path: Path,
) -> None:
    client = _S3()
    store = _store(client)
    event_id = uuid4()
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    store.publish(
        source,
        intent=_intent(store, event_id, digest),
        sha256=digest,
    )

    with pytest.raises(PreviewIntegrityError):
        store.publish(
            source,
            intent=_intent(
                store,
                event_id,
                digest,
                created_at=NOW + timedelta(seconds=1),
            ),
            sha256=digest,
        )


def test_preview_read_revalidates_receipt_and_uses_exact_range(
    tmp_path: Path,
) -> None:
    client = _S3()
    store = _store(client)
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview-for-browser")
    event_id = uuid4()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    receipt = store.publish(
        source,
        intent=_intent(store, event_id, digest),
        sha256=digest,
    )

    assert store.read(receipt, max_bytes=1024) == source.read_bytes()
    assert len(client.get_calls) == 1

    client.short_read = True
    with pytest.raises(PreviewIntegrityError):
        store.read(receipt, max_bytes=1024)


def test_preview_exact_delete_accepts_provider_no_such_version_verification(
    tmp_path: Path,
) -> None:
    class _VersionDeletingS3(_S3):
        def __init__(self) -> None:
            super().__init__()
            self.deleted: list[tuple[str, str, str, str]] = []
            self.deleted_versions: set[tuple[str, str, str]] = set()

        def delete_object(
            self,
            *,
            Bucket: str,
            Key: str,
            VersionId: str,
            IfMatch: str,
        ) -> None:
            stored = self.objects[(Bucket, Key)]
            assert VersionId == stored["VersionId"]
            assert IfMatch == stored["ETag"]
            self.deleted.append((Bucket, Key, VersionId, IfMatch))
            self.deleted_versions.add((Bucket, Key, VersionId))

        def head_object(
            self,
            *,
            Bucket: str,
            Key: str,
            ChecksumMode: str,
            **kwargs: str,
        ) -> dict[str, Any]:
            version_id = kwargs.get("VersionId")
            if (
                version_id is not None
                and (Bucket, Key, version_id) in self.deleted_versions
            ):
                error = RuntimeError("version was deleted")
                error.response = {  # type: ignore[attr-defined]
                    "Error": {"Code": "NoSuchVersion"}
                }
                raise error
            return super().head_object(
                Bucket=Bucket,
                Key=Key,
                ChecksumMode=ChecksumMode,
                **kwargs,
            )

    client = _VersionDeletingS3()
    store = _store(client)
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview-for-exact-deletion")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    receipt = store.publish(
        source,
        intent=_intent(store, uuid4(), digest),
        sha256=digest,
    )

    store.delete_exact(receipt)

    assert client.deleted == [
        (
            "pilot-evidence",
            f"site-previews/{receipt.object_key}",
            receipt.version_id,
            receipt.etag,
        )
    ]


def test_evidence_coordinator_publishes_preview_before_returning_it(
    tmp_path: Path,
) -> None:
    event_id = uuid4()
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"bounded-preview")
    assembled = SimpleNamespace(
        path=source,
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    calls: list[tuple[object, object]] = []

    class _Delegate:
        def create_preview(self, reservation: object, *, evidence: object) -> object:
            calls.append((reservation, evidence))
            return assembled

        def complete(self, reservation: object, evidence: object) -> object:
            return (reservation, evidence)

        def cancel(self, reservation_id: str, *, evidence: object) -> None:
            del reservation_id, evidence

    class _Publisher:
        def __init__(self) -> None:
            self.items: list[tuple[object, PreviewObjectContext, str]] = []

        def publish(
            self,
            item: object,
            *,
            context: PreviewObjectContext,
            sha256: str,
        ) -> object:
            self.items.append((item, context, sha256))
            return object()

    reservation = SimpleNamespace(
        stream_epoch=str(SOURCE_EPOCH),
        reservation_id=f"event-{event_id}",
    )
    evidence = SimpleNamespace(
        event_id=event_id,
        evidence_id=_evidence_id(event_id),
    )
    publisher = _Publisher()
    coordinator = DurablePreviewEvidenceCoordinator(
        delegate=_Delegate(),
        publisher=publisher,
        context_factory=lambda _reservation, _evidence: _context(event_id),
    )

    assert coordinator.create_preview(reservation, evidence=evidence) is assembled
    assert calls == [(reservation, evidence)]
    assert publisher.items == [
        (assembled.path, _context(event_id), assembled.sha256)
    ]


def test_evidence_coordinator_rejects_preview_context_for_another_event(
    tmp_path: Path,
) -> None:
    event_id = uuid4()
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"bounded-preview")
    calls: list[object] = []

    class _Delegate:
        def create_preview(self, reservation: object, *, evidence: object) -> object:
            calls.append(reservation)
            return SimpleNamespace(
                path=source,
                sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            )

        def complete(self, reservation: object, evidence: object) -> object:
            return object()

        def cancel(self, reservation_id: str, *, evidence: object) -> None:
            del reservation_id, evidence

    coordinator = DurablePreviewEvidenceCoordinator(
        delegate=_Delegate(),
        publisher=SimpleNamespace(publish=lambda *args, **kwargs: object()),
        context_factory=lambda _reservation, _evidence: _context(uuid4()),
    )

    with pytest.raises(PreviewIntegrityError, match="event|epoch"):
        coordinator.create_preview(
            SimpleNamespace(
                stream_epoch=str(SOURCE_EPOCH),
                reservation_id=f"event-{event_id}",
            ),
            evidence=SimpleNamespace(
                event_id=event_id,
                evidence_id=_evidence_id(event_id),
            ),
        )
    assert calls == []


@pytest.mark.parametrize(
    "mutation",
    (
        {"size_bytes": 2048},
        {"sha256": "c" * 64},
        {"etag": '"changed-etag"'},
        {"version_id": "changed-version"},
        {"server_side_encryption": "AES256", "kms_key_id": None},
        {"configuration_sha256": "d" * 64},
        {"runtime_session_id": "changed-runtime"},
        {"source_epoch": OTHER_SOURCE_EPOCH},
        {"rule_revision_sha256": "e" * 64},
    ),
)
def test_preview_read_fails_closed_when_receipt_or_remote_identity_changes(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    client = _S3()
    store = _store(client)
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview")
    event_id = uuid4()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    receipt = store.publish(
        source,
        intent=_intent(store, event_id, digest),
        sha256=digest,
    )

    with pytest.raises((PreviewIntegrityError, ValueError)):
        store.read(replace(receipt, **mutation), max_bytes=1024)

    assert client.get_calls == []


class _ReceiptRepository:
    def __init__(self) -> None:
        self.intents: dict[tuple[str, UUID], PreviewPublicationIntentV1] = {}
        self.receipts: dict[tuple[str, UUID], PreviewObjectReceiptV1] = {}
        self.saved: list[PreviewObjectReceiptV1] = []
        self.accesses: list[PreviewAccessReceipt] = []
        self.fail_save = False
        self.fail_access = False

    def prepare_preview_publication(
        self,
        *,
        context: PreviewObjectContext,
        object_key: str,
        sha256: str,
        requested_at: datetime,
        expires_at: datetime,
    ) -> PreviewPublicationIntentV1:
        identity = (context.site_id, context.event_id)
        current = self.intents.get(identity)
        if current is not None:
            if (
                current.context != context
                or current.object_key != object_key
                or current.sha256 != sha256
            ):
                raise PreviewIntegrityError(
                    "preview publication identity conflict"
                )
            return current
        intent = PreviewPublicationIntentV1(
            schema_version="preview-publication-intent.v1",
            site_id=context.site_id,
            event_id=context.event_id,
            evidence_id=context.evidence_id,
            object_key=object_key,
            sha256=sha256,
            configuration_sha256=context.configuration_sha256,
            runtime_session_id=context.runtime_session_id,
            runtime_writer_generation=context.runtime_writer_generation,
            configuration_activation_generation=(
                context.configuration_activation_generation
            ),
            source_epoch=context.source_epoch,
            rule_revision_sha256=context.rule_revision_sha256,
            candidate_body_sha256=context.candidate_body_sha256,
            created_at=requested_at,
            expires_at=expires_at,
        )
        self.intents[identity] = intent
        return intent

    def finalize_preview_receipt(
        self,
        *,
        intent: PreviewPublicationIntentV1,
        receipt: PreviewObjectReceiptV1,
    ) -> None:
        if self.fail_save:
            raise RuntimeError("database unavailable")
        if receipt.event_id != intent.event_id:
            raise PreviewIntegrityError("preview intent changed")
        identity = (receipt.site_id, receipt.event_id)
        current = self.receipts.get(identity)
        if current is not None and current != receipt:
            raise PreviewIntegrityError("preview receipt identity conflict")
        if current is not None:
            return
        self.receipts[identity] = receipt
        self.saved.append(receipt)

    def get_preview_receipt(
        self,
        *,
        site_id: str,
        event_id: UUID,
    ) -> PreviewObjectReceiptV1 | None:
        return self.receipts.get((site_id, event_id))

    def commit_preview_access(self, access: PreviewAccessReceipt) -> bool:
        if self.fail_access:
            raise RuntimeError("audit unavailable")
        current = self.receipts.get((access.site_id, access.event_id))
        if current is None or current.receipt_sha256 != access.receipt_sha256:
            return False
        self.accesses.append(access)
        return True


def test_publish_crash_after_remote_upload_is_retryable_without_overwrite(
    tmp_path: Path,
) -> None:
    client = _S3()
    store = _store(client)
    repository = _ReceiptRepository()
    publisher = DurablePreviewPublisher(
        store=store,
        repository=repository,
        clock=lambda: NOW,
    )
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview")
    context = _context(uuid4())
    repository.fail_save = True

    with pytest.raises(RuntimeError, match="database unavailable"):
        publisher.publish(
            source,
            context=context,
            sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert len(client.put_calls) == 1
    repository.fail_save = False
    receipt = publisher.publish(
        source,
        context=context,
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    assert len(client.put_calls) == 1
    assert repository.saved == [receipt]


def test_preview_publication_rechecks_storage_policy_before_durable_intent(
    tmp_path: Path,
) -> None:
    client = _S3()
    store = _store(client)
    repository = _ReceiptRepository()
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview")

    def drifted_policy() -> None:
        raise PreviewIntegrityError("preview lifecycle drifted")

    publisher = DurablePreviewPublisher(
        store=store,
        repository=repository,
        clock=lambda: NOW,
        storage_policy_check=drifted_policy,
    )

    with pytest.raises(PreviewIntegrityError, match="lifecycle drifted"):
        publisher.publish(
            source,
            context=_context(uuid4()),
            sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert repository.intents == {}
    assert client.put_calls == []


def test_preview_read_fails_closed_when_storage_policy_drifted() -> None:
    client = _S3()
    repository = _ReceiptRepository()

    def drifted_policy() -> None:
        raise PreviewIntegrityError("preview lifecycle drifted")

    provider = ProductionPreviewProvider(
        store=_store(client),
        repository=repository,
        clock=lambda: NOW,
        storage_policy_check=drifted_policy,
    )

    with pytest.raises(PreviewAccessDenied, match="re-attested"):
        provider.get_preview(
            site_id="site-1",
            event_id=uuid4(),
            actor_id="operator-1",
            max_bytes=1024,
        )

    assert client.head_calls == []
    assert client.get_calls == []


def test_provider_scopes_lookup_before_get_and_commits_audit_before_return(
    tmp_path: Path,
) -> None:
    client = _S3()
    store = _store(client)
    repository = _ReceiptRepository()
    publisher = DurablePreviewPublisher(
        store=store,
        repository=repository,
        clock=lambda: NOW,
    )
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview")
    event_id = uuid4()
    publisher.publish(
        source,
        context=_context(event_id),
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    provider = ProductionPreviewProvider(
        store=store,
        repository=repository,
        clock=lambda: NOW,
    )

    assert provider.get_preview(
        site_id="other-site",
        event_id=event_id,
        actor_id="operator-1",
        max_bytes=1024,
    ) is None
    assert client.get_calls == []

    result = provider.get_preview(
        site_id="site-1",
        event_id=event_id,
        actor_id="operator-1",
        max_bytes=1024,
    )
    assert result == PreviewPayload(content=b"preview", media_type="video/mp4")
    assert len(repository.accesses) == 1


def test_provider_returns_no_bytes_when_access_audit_cannot_commit(
    tmp_path: Path,
) -> None:
    client = _S3()
    store = _store(client)
    repository = _ReceiptRepository()
    source = tmp_path / "preview.mp4"
    source.write_bytes(b"preview")
    event_id = uuid4()
    DurablePreviewPublisher(
        store=store,
        repository=repository,
        clock=lambda: NOW,
    ).publish(
        source,
        context=_context(event_id),
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    repository.fail_access = True
    provider = ProductionPreviewProvider(
        store=store,
        repository=repository,
        clock=lambda: NOW,
    )

    with pytest.raises(PreviewAccessDenied):
        provider.get_preview(
            site_id="site-1",
            event_id=event_id,
            actor_id="operator-1",
            max_bytes=1024,
        )
