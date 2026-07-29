from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import DataError, IntegrityError, OperationalError, ProgrammingError

from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.runtime.evidence import EncodedFragmentRing
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.journal import JournalFullError, SQLiteWALJournal
from protector.pilot.storage.models import Base, EvidenceModel
from protector.pilot.storage.object_store import (
    EncryptedLocalObjectStore,
    EncryptedVolumeAttestation,
    EvidenceCoordinator,
    EvidencePublisher,
    ObjectIntegrityError,
    ObjectPublishError,
    PreviewWorkspace,
    PreviewWorkspaceCapacityError,
    S3CompatibleObjectStore,
    build_s3_evidence_delivery,
    validate_object_key,
)
from protector.pilot.storage.repositories import (
    EvidenceInput,
    EvidenceIntent,
    IdempotencyConflictError,
    PilotRepository,
)

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


class FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_put_once = False

    def head_object(
        self,
        *,
        Bucket: str,
        Key: str,
        ChecksumMode: str,
    ) -> dict[str, Any]:
        assert ChecksumMode == "ENABLED"
        try:
            stored = self.objects[(Bucket, Key)]
        except KeyError as exc:
            raise KeyError(Key) from exc
        head = {
            "ContentLength": len(stored["Body"]),
            "ChecksumSHA256": stored["ChecksumSHA256"],
            "ServerSideEncryption": stored["ServerSideEncryption"],
        }
        if "SSEKMSKeyId" in stored:
            head["SSEKMSKeyId"] = stored["SSEKMSKeyId"]
        return head

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        IfNoneMatch: str,
        ChecksumAlgorithm: str,
        ChecksumSHA256: str,
        ServerSideEncryption: str,
        **kwargs: object,
    ) -> None:
        self.calls.append(("put", Key))
        if self.fail_put_once:
            self.fail_put_once = False
            raise OSError("simulated interrupted upload")
        if (Bucket, Key) in self.objects:
            error = RuntimeError("precondition failed")
            error.response = {"Error": {"Code": "PreconditionFailed"}}  # type: ignore[attr-defined]
            raise error
        assert IfNoneMatch == "*"
        assert ChecksumAlgorithm == "SHA256"
        assert ChecksumSHA256 == base64.b64encode(hashlib.sha256(Body).digest()).decode()
        self.objects[(Bucket, Key)] = {
            "Body": bytes(Body),
            "ChecksumSHA256": ChecksumSHA256,
            "ServerSideEncryption": ServerSideEncryption,
            "LastModified": NOW,
            **kwargs,
        }

    def delete_object(self, *, Bucket: str, Key: str) -> None:
        self.calls.append(("delete", Key))
        self.objects.pop((Bucket, Key), None)

    def list_objects_v2(self, *, Bucket: str, Prefix: str = "") -> dict[str, Any]:
        return {
            "Contents": [
                {"Key": key, "LastModified": value["LastModified"]}
                for (bucket, key), value in self.objects.items()
                if bucket == Bucket and key.startswith(Prefix)
            ],
            "IsTruncated": False,
        }


def _s3_store(client: FakeS3Client, **overrides: object) -> S3CompatibleObjectStore:
    arguments: dict[str, object] = {
        "client": client,
        "endpoint": "https://objects.example.test",
        "bucket": "evidence",
        "country_code": "KZ",
        "evidence_prefix": "pilot-evidence",
        "max_object_bytes": 1_000_000,
        "server_side_encryption": "AES256",
    }
    arguments.update(overrides)
    return S3CompatibleObjectStore(**arguments)


def _attestation(root: Path) -> EncryptedVolumeAttestation:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    return EncryptedVolumeAttestation(
        volume_id="kuzet-evidence-01",
        mount_path=root,
        record_id="attestation-2026-07-28",
        verified_at=NOW,
        verifier="customer-security",
        signature_sha256="a" * 64,
        encryption="luks2",
    )


def _local_store(root: Path, **overrides: object) -> EncryptedLocalObjectStore:
    arguments: dict[str, object] = {
        "encrypted_volume_attestation": _attestation(root),
        "attestation_verifier": lambda record: record.signature_sha256 == "a" * 64,
        "attestation_max_age": timedelta(days=1),
        "evidence_prefix": "pilot-evidence",
        "max_object_bytes": 1_000_000,
        "clock": lambda: NOW,
    }
    arguments.update(overrides)
    return EncryptedLocalObjectStore(root, **arguments)


def _repository() -> PilotRepository:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name="Pilot School")
    repository.add_camera(
        camera_id="camera-01",
        site_id="site-1",
        name="Entrance",
        source_reference="nvr://camera/01",
        codec="h264",
    )
    repository.add_model_artifact(
        ModelArtifactV1(
            schema_version="model-artifact.v1",
            artifact_id="person-v1",
            sha256="a" * 64,
            source="s3://model-registry/person-v1.onnx",
            commercial_rights=CommercialRightsRecordV1(
                schema_version="commercial-rights.v1",
                record_id="rights-1",
                terms_reference="legal://rights/1",
                commercial_use_approved=True,
            ),
            class_list=("person",),
            preprocessing="letterbox 640x640",
            analytic="person",
        )
    )
    return repository


def _event() -> CandidateEventV1:
    return CandidateEventV1(
        schema_version="candidate-event.v1",
        event_id=uuid4(),
        camera_id="camera-01",
        module="person",
        opened_at=NOW,
        last_seen_at=NOW + timedelta(seconds=2),
        peak_confidence=0.91,
        reason="restricted zone intrusion",
        model_artifact_id="person-v1",
        gate_mode="operator",
        evidence_status="pending",
        review_status="candidate",
    )


def _evidence(event: CandidateEventV1, path: Path, *, status: str = "pending") -> EvidenceInput:
    import hashlib

    return EvidenceInput(
        evidence_id=uuid4(),
        event_id=event.event_id,
        object_key=f"events/camera-01/{event.event_id}.mp4",
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        codec="h264",
        start_at=NOW - timedelta(seconds=2),
        end_at=NOW + timedelta(seconds=4),
        source_reference="nvr://camera/01?source-time=2026-07-28T12:00:00Z",
        status=status,
    )


class _RecordingRing:
    def __init__(self) -> None:
        self.released: list[str] = []

    def release(self, reservation_id: str) -> int:
        self.released.append(reservation_id)
        return 1


class _FinalBytesAssembler:
    def __init__(self, payload: bytes = b"final-browser-evidence") -> None:
        self.payload = payload

    def assemble(self, _: object, output: object) -> object:
        output.write_bytes(self.payload)  # type: ignore[attr-defined]
        return SimpleNamespace(
            path=output,
            sha256=hashlib.sha256(self.payload).hexdigest(),
            start_at=NOW - timedelta(seconds=2),
            end_at=NOW + timedelta(seconds=4),
        )


@pytest.mark.parametrize(
    "key",
    (
        "../escape.mp4",
        "events/../../escape.mp4",
        "/absolute.mp4",
        "events\\escape.mp4",
        ".incomplete/user-controlled.mp4",
        "events//empty.mp4",
    ),
)
def test_object_keys_cannot_escape_or_impersonate_incomplete_uploads(key: str) -> None:
    with pytest.raises(ValueError):
        validate_object_key(key)


def test_s3_requires_kz_https_boundary_and_never_accepts_credentials() -> None:
    client = FakeS3Client()
    with pytest.raises(ValueError, match="HTTPS"):
        _s3_store(
            client,
            endpoint="http://objects.example.test",
        )
    with pytest.raises(ValueError, match="Kazakhstan"):
        _s3_store(
            client,
            country_code="US",
        )
    with pytest.raises(TypeError):
        _s3_store(
            client,
            access_key="must-not-be-accepted",
        )
    for endpoint in (
        "https://access:TOPSECRET@objects.example.test",
        "https://objects.example.test?credential=secret",
        "https://objects.example.test/#ambiguous",
        "https://objects.example.test/tenant/path",
    ):
        with pytest.raises(ValueError, match="credential|ambiguous"):
            _s3_store(client, endpoint=endpoint)


def test_s3_publish_verifies_digest_promotes_then_cleans_incomplete_key(
    tmp_path: Path,
) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    client = FakeS3Client()
    store = _s3_store(client)

    stored = store.publish(source, "events/camera-01/evidence.mp4", sha256=digest)

    assert stored.key == "events/camera-01/evidence.mp4"
    assert stored.sha256 == digest
    remote_key = f"pilot-evidence/{stored.key}"
    assert client.objects[("evidence", remote_key)]["Body"] == source.read_bytes()
    assert client.objects[("evidence", remote_key)]["ServerSideEncryption"] == "AES256"
    assert [operation for operation, _ in client.calls] == ["put"]


def test_s3_interrupted_upload_is_cleaned_and_retry_is_idempotent(tmp_path: Path) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    client = FakeS3Client()
    client.fail_put_once = True
    store = _s3_store(client)

    with pytest.raises(ObjectPublishError, match="publish"):
        store.publish(source, "events/camera-01/evidence.mp4", sha256=digest)
    assert not client.objects

    first = store.publish(source, "events/camera-01/evidence.mp4", sha256=digest)
    calls_before_retry = list(client.calls)
    second = store.publish(source, "events/camera-01/evidence.mp4", sha256=digest)

    assert first == second
    assert client.calls == calls_before_retry


def test_publish_rejects_wrong_digest_before_any_remote_write(tmp_path: Path) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    client = FakeS3Client()
    store = _s3_store(client)

    with pytest.raises(ObjectIntegrityError, match="SHA-256"):
        store.publish(source, "events/camera-01/evidence.mp4", sha256="0" * 64)
    assert client.calls == []


def test_encrypted_local_volume_requires_attestation_and_publishes_atomically(
    tmp_path: Path,
) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    root = tmp_path / "volume"
    with pytest.raises((TypeError, ValueError), match="attestation"):
        EncryptedLocalObjectStore(
            root,
            encrypted_volume_attestation="x",  # type: ignore[arg-type]
            attestation_verifier=lambda _: True,
            attestation_max_age=timedelta(days=1),
            evidence_prefix="pilot-evidence",
            max_object_bytes=1_000_000,
        )
    store = _local_store(root)

    stored = store.publish(source, "events/camera-01/evidence.mp4", sha256=digest)

    assert stored.path is not None
    assert stored.path.read_bytes() == source.read_bytes()
    assert not list((tmp_path / "volume").rglob("*.part"))
    assert store.publish(source, stored.key, sha256=digest) == stored


def test_encrypted_local_attestation_rejects_forged_wrong_mount_and_stale_records(
    tmp_path: Path,
) -> None:
    root = tmp_path / "volume"
    attestation = _attestation(root)
    common = {
        "evidence_prefix": "pilot-evidence",
        "max_object_bytes": 1_000_000,
        "attestation_max_age": timedelta(days=1),
        "clock": lambda: NOW,
    }
    with pytest.raises(ValueError, match="signature"):
        EncryptedLocalObjectStore(
            root,
            encrypted_volume_attestation=replace(attestation, signature_sha256="b" * 64),
            attestation_verifier=lambda record: record.signature_sha256 == "a" * 64,
            **common,
        )
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="mounted root"):
        EncryptedLocalObjectStore(
            root,
            encrypted_volume_attestation=replace(attestation, mount_path=other),
            attestation_verifier=lambda _: True,
            **common,
        )
    with pytest.raises(ValueError, match="stale"):
        EncryptedLocalObjectStore(
            root,
            encrypted_volume_attestation=replace(
                attestation,
                verified_at=NOW - timedelta(days=2),
            ),
            attestation_verifier=lambda _: True,
            **common,
        )


def test_local_store_refuses_symlink_escape_and_retention_deletes_only_expired(
    tmp_path: Path,
) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    root = tmp_path / "volume"
    store = _local_store(root)
    old = store.publish(source, "events/camera-01/old.mp4", sha256=digest)
    current = store.publish(source, "events/camera-01/current.mp4", sha256=digest)
    assert old.path is not None and current.path is not None
    os.utime(old.path, (NOW.timestamp() - 100, NOW.timestamp() - 100))
    os.utime(current.path, (NOW.timestamp(), NOW.timestamp()))
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "pilot-evidence" / "events" / "linked").symlink_to(
        outside, target_is_directory=True
    )

    with pytest.raises(ObjectPublishError, match="publish"):
        store.publish(source, "events/linked/escape.mp4", sha256=digest)
    assert store.delete_older_than(NOW - timedelta(seconds=50)) == ("events/camera-01/old.mp4",)
    assert current.path.exists()
    assert not old.path.exists()


def test_s3_retention_deletes_expired_final_objects_not_incomplete(tmp_path: Path) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    client = FakeS3Client()
    store = _s3_store(client)
    store.publish(source, "events/camera-01/old.mp4", sha256=digest)
    client.objects[("evidence", "pilot-evidence/events/camera-01/old.mp4")][
        "LastModified"
    ] = NOW - timedelta(days=2)
    client.objects[("evidence", "pilot-evidence/.incomplete/crash.part")] = {
        "Body": b"partial",
        "ChecksumSHA256": "",
        "ServerSideEncryption": "AES256",
        "LastModified": NOW - timedelta(days=2),
    }
    client.objects[("evidence", "unrelated/customer-data.bin")] = {
        "Body": b"must-stay",
        "ChecksumSHA256": "",
        "ServerSideEncryption": "AES256",
        "LastModified": NOW - timedelta(days=20),
    }

    assert store.delete_older_than(NOW - timedelta(days=1)) == (
        ".incomplete/crash.part",
        "events/camera-01/old.mp4",
    )
    assert ("evidence", "pilot-evidence/.incomplete/crash.part") not in client.objects
    assert ("evidence", "unrelated/customer-data.bin") in client.objects


def test_local_store_removes_crash_left_incomplete_files_on_restart(tmp_path: Path) -> None:
    root = tmp_path / "volume"
    root.mkdir()
    unrelated = root / "events" / ".clip.crash.part"
    unrelated.parent.mkdir()
    unrelated.write_bytes(b"unrelated")
    incomplete = root / "pilot-evidence" / ".incomplete" / "crash.part"
    incomplete.parent.mkdir(parents=True)
    incomplete.write_bytes(b"partial")

    _local_store(root)

    assert not incomplete.exists()
    assert unrelated.exists()


def test_s3_existing_object_requires_service_checksum_and_is_never_deleted_on_conflict(
    tmp_path: Path,
) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"declared-evidence")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    client = FakeS3Client()
    remote_key = "pilot-evidence/events/camera-01/conflict.mp4"
    conflicting = b"different-bytes!!"
    assert len(conflicting) == source.stat().st_size
    client.objects[("evidence", remote_key)] = {
        "Body": conflicting,
        "ChecksumSHA256": base64.b64encode(hashlib.sha256(conflicting).digest()).decode(),
        "ServerSideEncryption": "AES256",
        "LastModified": NOW,
    }

    with pytest.raises(ObjectIntegrityError, match="checksum"):
        _s3_store(client).publish(
            source,
            "events/camera-01/conflict.mp4",
            sha256=digest,
        )

    assert client.objects[("evidence", remote_key)]["Body"] == conflicting
    assert not [call for call in client.calls if call == ("delete", remote_key)]


def test_s3_kms_head_must_match_the_configured_key(tmp_path: Path) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"kms-evidence")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    client = FakeS3Client()
    store = _s3_store(
        client,
        server_side_encryption="aws:kms",
        kms_key_id="arn:kms:kz:approved-key",
    )
    stored = store.publish(source, "events/camera-01/kms.mp4", sha256=digest)
    remote = client.objects[("evidence", f"pilot-evidence/{stored.key}")]
    assert remote["SSEKMSKeyId"] == "arn:kms:kz:approved-key"
    remote["SSEKMSKeyId"] = "arn:kms:other-key"

    with pytest.raises(ObjectIntegrityError, match="KMS key"):
        store.publish(source, stored.key, sha256=digest)


def test_s3_conditional_create_keeps_one_immutable_owner_under_conflicting_publishers(
    tmp_path: Path,
) -> None:
    first_source = tmp_path / "first.mp4"
    second_source = tmp_path / "second.mp4"
    first_source.write_bytes(b"first-immutable")
    second_source.write_bytes(b"other-immutable")
    client = FakeS3Client()
    store = _s3_store(client)
    outcomes: list[object] = []

    def publish(source: Path) -> None:
        try:
            outcomes.append(
                store.publish(
                    source,
                    "events/camera-01/one-key.mp4",
                    sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            outcomes.append(exc)

    workers = [
        threading.Thread(target=publish, args=(first_source,)),
        threading.Thread(target=publish, args=(second_source,)),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=2)

    assert sum(isinstance(item, ObjectIntegrityError) for item in outcomes) == 1
    assert sum(not isinstance(item, BaseException) for item in outcomes) == 1
    final = client.objects[("evidence", "pilot-evidence/events/camera-01/one-key.mp4")]
    assert final["Body"] in {first_source.read_bytes(), second_source.read_bytes()}


@pytest.mark.parametrize("backend", ("s3", "local"))
def test_object_upload_size_is_bounded_before_publication(
    tmp_path: Path,
    backend: str,
) -> None:
    source = tmp_path / "large.mp4"
    source.write_bytes(b"12345")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    client = FakeS3Client()
    store = (
        _s3_store(client, max_object_bytes=4)
        if backend == "s3"
        else _local_store(tmp_path / "volume", max_object_bytes=4)
    )

    with pytest.raises(ObjectPublishError, match="maximum"):
        store.publish(source, "events/camera-01/large.mp4", sha256=digest)

    assert client.calls == []


def test_local_existing_object_readback_is_bounded(tmp_path: Path) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"1234")
    store = _local_store(tmp_path / "volume", max_object_bytes=4)
    existing = (
        tmp_path
        / "volume"
        / "pilot-evidence"
        / "events"
        / "camera-01"
        / "bounded.mp4"
    )
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"oversized")

    with pytest.raises(ObjectIntegrityError, match="maximum"):
        store.publish(
            source,
            "events/camera-01/bounded.mp4",
            sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )


def test_publisher_marks_failed_upload_visible_but_never_ready(tmp_path: Path) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"encoded-browser-evidence")
    evidence = _evidence(event, clip)
    client = FakeS3Client()
    client.fail_put_once = True
    publisher = EvidencePublisher(
        store=_s3_store(client),
        repository=repository,
    )

    with pytest.raises(ObjectPublishError):
        publisher.publish(clip, evidence)

    assert repository.get_event(event.event_id).evidence_status == "failed"
    with repository.session_factory() as session:
        row = session.scalar(select(EvidenceModel))
        assert row is not None
        assert row.status == "failed"


def test_upload_success_and_database_finalization_are_atomic_and_retryable(
    tmp_path: Path,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"encoded-browser-evidence")
    evidence = _evidence(event, clip)
    client = FakeS3Client()
    store = _s3_store(client)
    publisher = EvidencePublisher(store=store, repository=repository)

    ready = publisher.publish(clip, evidence)
    retried = publisher.publish(clip, evidence)

    assert ready.status == retried.status == "ready"
    assert repository.get_event(event.event_id).evidence_status == "ready"
    with repository.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceModel)) == 1


def test_database_finalization_failure_rolls_back_row_and_candidate_status(
    tmp_path: Path,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"encoded-browser-evidence")
    evidence = _evidence(event, clip)
    too_short = EvidenceInput(
        **{
            **evidence.__dict__,
            "end_at": evidence.start_at + timedelta(seconds=3),
        }
    )

    with pytest.raises(Exception, match="evidence duration"):
        repository.finalize_evidence(too_short, status="ready")

    assert repository.get_event(event.event_id).evidence_status == "pending"
    with repository.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceModel)) == 0


@pytest.mark.parametrize("upload_succeeds", (True, False))
def test_database_outage_journals_ready_or_failed_finalization_for_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    upload_succeeds: bool,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"encoded-browser-evidence")
    evidence = _evidence(event, clip)
    client = FakeS3Client()
    client.fail_put_once = not upload_succeeds
    journal = SQLiteWALJournal(tmp_path / "evidence-journal.sqlite3", max_items=10)
    publisher = EvidencePublisher(
        store=_s3_store(client),
        repository=repository,
        journal=journal,
    )
    original_finalize = repository.finalize_evidence

    def unavailable(*_: object, **__: object) -> object:
        raise OSError("database unavailable")

    monkeypatch.setattr(repository, "finalize_evidence", unavailable)
    if upload_succeeds:
        assert publisher.publish(clip, evidence).status == "ready"
    else:
        with pytest.raises(ObjectPublishError):
            publisher.publish(clip, evidence)
    assert journal.depth() == 1

    monkeypatch.setattr(repository, "finalize_evidence", original_finalize)
    assert journal.replay(repository.persist_journal_item) == 1
    expected = "ready" if upload_succeeds else "failed"
    assert repository.get_event(event.event_id).evidence_status == expected
    with repository.session_factory() as session:
        row = session.scalar(select(EvidenceModel))
        assert row is not None
        assert row.status == expected


def test_evidence_coordinator_owns_preview_finalization_failure_and_cleanup(
    tmp_path: Path,
) -> None:
    class Ring:
        def __init__(self) -> None:
            self.released: list[str] = []

        def release(self, reservation_id: str) -> int:
            self.released.append(reservation_id)
            return 1

    class Assembler:
        fail = False

        def assemble_preview(self, reservation: object, output: Path) -> object:
            output.write_bytes(b"preview")
            return SimpleNamespace(path=output)

        def assemble(self, reservation: object, output: Path) -> object:
            if self.fail:
                raise OSError("assembly failed")
            output.write_bytes(b"final")
            return SimpleNamespace(
                path=output,
                sha256=hashlib.sha256(b"final").hexdigest(),
                start_at=NOW - timedelta(seconds=2),
                end_at=NOW + timedelta(seconds=4),
            )

    class Publisher:
        def __init__(self) -> None:
            self.published: list[EvidenceInput] = []
            self.failed: list[EvidenceInput] = []

        def publish(self, source: Path, evidence: EvidenceInput) -> EvidenceInput:
            assert source.read_bytes() == b"final"
            self.published.append(evidence)
            return replace(evidence, status="ready")

        def mark_failed(self, evidence: EvidenceInput) -> EvidenceInput:
            self.failed.append(evidence)
            return replace(evidence, status="failed")

    ring = Ring()
    assembler = Assembler()
    publisher = Publisher()
    coordinator = EvidenceCoordinator(
        ring=ring,  # type: ignore[arg-type]
        assembler=assembler,  # type: ignore[arg-type]
        publisher=publisher,  # type: ignore[arg-type]
        preview_workspace=PreviewWorkspace(
            tmp_path / "previews",
            ttl=timedelta(minutes=5),
            max_items=4,
            max_bytes=1_000,
            clock=lambda: NOW,
        ),
    )
    reservation = SimpleNamespace(reservation_id="reservation-1", status="pending")

    preview = coordinator.create_preview(reservation)
    preview_path = preview.path
    assert preview_path.read_bytes() == b"preview"
    assert ring.released == []

    event = _event()
    seed = tmp_path / "seed.mp4"
    seed.write_bytes(b"seed")
    pending = _evidence(event, seed)
    # _evidence hashes its input; the coordinator replaces it with assembled bytes.
    final_path = coordinator.preview_workspace.path_for(
        reservation.reservation_id,
        kind="final",
    )
    ready = coordinator.complete(reservation, pending)

    assert ready.status == "ready"
    assert publisher.published[0].sha256 == hashlib.sha256(b"final").hexdigest()
    assert ring.released == ["reservation-1"]
    assert not preview_path.exists()
    assert not final_path.exists()

    failed_reservation = SimpleNamespace(
        reservation_id="reservation-2",
        status="ready",
    )
    assembler.fail = True
    with pytest.raises(OSError, match="assembly"):
        coordinator.complete(failed_reservation, pending)
    assert publisher.failed[-1].evidence_id == pending.evidence_id
    assert len(publisher.failed) == 1
    assert ring.released[-1] == "reservation-2"

    fresh_reservation = SimpleNamespace(reservation_id="reservation-3", status="ready")
    assembler.fail = False
    assert coordinator.retry(fresh_reservation, pending).status == "ready"


def test_coordinator_cleanup_attempts_mark_release_and_partial_unlink_independently(
    tmp_path: Path,
) -> None:
    class Ring:
        released: list[str] = []

        def release(self, reservation_id: str) -> int:
            self.released.append(reservation_id)
            raise OSError("release failed")

    class Assembler:
        def assemble(self, _: object, output: Path) -> object:
            output.write_bytes(b"partial")
            raise OSError("assembly failed")

    class Publisher:
        marked = 0

        def mark_failed(self, _: EvidenceInput) -> EvidenceInput:
            self.marked += 1
            raise RuntimeError("mark failed")

    workspace = PreviewWorkspace(
        tmp_path / "cleanup-previews",
        ttl=timedelta(minutes=5),
        max_items=4,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    coordinator = EvidenceCoordinator(
        ring=Ring(),
        assembler=Assembler(),
        publisher=Publisher(),  # type: ignore[arg-type]
        preview_workspace=workspace,
    )
    reservation = SimpleNamespace(reservation_id="reservation-partial", status="ready")
    seed = tmp_path / "seed.mp4"
    seed.write_bytes(b"seed")

    with pytest.raises(ExceptionGroup) as failure:
        coordinator.complete(reservation, _evidence(_event(), seed))

    assert [type(error) for error in failure.value.exceptions] == [
        OSError,
        RuntimeError,
        OSError,
    ]
    assert Ring.released == ["reservation-partial"]
    assert not workspace.path_for("reservation-partial", kind="final").exists()


def test_cleanup_attestation_failure_preserves_primary_order_and_reconciliation(
    tmp_path: Path,
) -> None:
    class Ring:
        released: list[str] = []

        def release(self, reservation_id: str) -> int:
            self.released.append(reservation_id)
            return 1

    class Assembler:
        def __init__(self, marker: Path) -> None:
            self._marker = marker

        def assemble(self, _: object, output: Path) -> object:
            output.write_bytes(b"partial")
            self._marker.write_bytes(b"forged")
            raise OSError("assembly failed")

    class Publisher:
        failed: list[EvidenceInput] = []

        def mark_failed(self, evidence: EvidenceInput) -> EvidenceInput:
            self.failed.append(evidence)
            return replace(evidence, status="failed")

    root = tmp_path / "attestation-cleanup-previews"
    workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=4,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    reservation_id = "reservation-attestation-cleanup"
    key = hashlib.sha256(reservation_id.encode()).hexdigest()
    coordinator = EvidenceCoordinator(
        ring=Ring(),
        assembler=Assembler(root / PreviewWorkspace._MARKER),
        publisher=Publisher(),  # type: ignore[arg-type]
        preview_workspace=workspace,
    )
    seed = tmp_path / "attestation-cleanup-seed.mp4"
    seed.write_bytes(b"seed")

    with pytest.raises(ExceptionGroup) as failure:
        coordinator.complete(
            SimpleNamespace(reservation_id=reservation_id, status="ready"),
            _evidence(_event(), seed),
        )

    assert [type(error) for error in failure.value.exceptions] == [
        OSError,
        PreviewWorkspaceCapacityError,
    ]
    assert Ring.released == [reservation_id]
    assert (root / f"{key}.json").exists()
    staging = tuple(root.glob(".kuzet-preview-*.tmp"))
    assert len(staging) == 1
    assert staging[0].read_bytes() == b"partial"


def test_preview_workspace_expiry_cancel_restart_and_churn_stay_bounded(
    tmp_path: Path,
) -> None:
    class Clock:
        now = NOW

        def __call__(self) -> datetime:
            return self.now

    class Ring:
        def __init__(self) -> None:
            self.released: list[str] = []

        def release(self, reservation_id: str) -> int:
            self.released.append(reservation_id)
            return 1

    class Assembler:
        def assemble_preview(self, _: object, output: Path) -> object:
            output.write_bytes(b"preview")
            return SimpleNamespace(path=output)

    class Publisher:
        def __init__(self) -> None:
            self.failed: list[EvidenceInput] = []

        def mark_failed(self, evidence: EvidenceInput) -> EvidenceInput:
            self.failed.append(evidence)
            return replace(evidence, status="failed")

    clock = Clock()
    root = tmp_path / "bounded-previews"
    workspace = PreviewWorkspace(
        root,
        ttl=timedelta(seconds=10),
        max_items=2,
        max_bytes=20,
        clock=clock,
    )
    ring = Ring()
    coordinator = EvidenceCoordinator(
        ring=ring,
        assembler=Assembler(),
        publisher=Publisher(),  # type: ignore[arg-type]
        preview_workspace=workspace,
    )
    first = SimpleNamespace(reservation_id="reservation-expire", status="pending")
    second = SimpleNamespace(reservation_id="reservation-cancel", status="pending")
    coordinator.create_preview(first)
    coordinator.create_preview(second)
    assert workspace.item_count == 2
    coordinator.cancel(second.reservation_id)
    assert workspace.item_count == 1

    clock.now += timedelta(seconds=11)
    assert coordinator.sweep_expired() == ("reservation-expire",)
    assert workspace.item_count == 0
    assert set(ring.released) == {
        "reservation-cancel",
        "reservation-expire",
    }

    abandoned = SimpleNamespace(reservation_id="reservation-restart", status="pending")
    seed = tmp_path / "restart-seed.mp4"
    seed.write_bytes(b"seed")
    pending = _evidence(_event(), seed)
    coordinator.create_preview(abandoned, evidence=pending)
    restarted_ring = Ring()
    restarted_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(seconds=10),
        max_items=2,
        max_bytes=20,
        clock=clock,
    )
    restarted_publisher = Publisher()
    EvidenceCoordinator(
        ring=restarted_ring,
        assembler=Assembler(),
        publisher=restarted_publisher,  # type: ignore[arg-type]
        preview_workspace=restarted_workspace,
    )
    assert restarted_ring.released == ["reservation-restart"]
    assert restarted_workspace.item_count == 0
    assert [item.evidence_id for item in restarted_publisher.failed] == [
        pending.evidence_id
    ]

    restarted_workspace.prepare(
        "reservation-before-assembly",
        kind="preview",
        evidence=pending,
    )
    before_assembly_ring = Ring()
    before_assembly_publisher = Publisher()
    before_assembly_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(seconds=10),
        max_items=2,
        max_bytes=20,
        clock=clock,
    )
    EvidenceCoordinator(
        ring=before_assembly_ring,
        assembler=Assembler(),
        publisher=before_assembly_publisher,  # type: ignore[arg-type]
        preview_workspace=before_assembly_workspace,
    )
    assert before_assembly_ring.released == ["reservation-before-assembly"]
    assert before_assembly_publisher.failed == [pending]

    for ordinal in range(25):
        reservation_id = f"reservation-{ordinal}"
        reservation = SimpleNamespace(reservation_id=reservation_id, status="pending")
        coordinator_after_restart = EvidenceCoordinator(
            ring=Ring(),
            assembler=Assembler(),
            publisher=Publisher(),  # type: ignore[arg-type]
            preview_workspace=before_assembly_workspace,
        )
        coordinator_after_restart.create_preview(reservation)
        coordinator_after_restart.cancel(reservation_id)
    assert before_assembly_workspace.item_count == 0
    assert before_assembly_workspace.used_bytes == 0
    assert not hasattr(coordinator_after_restart, "_consumed_reservations")


def test_preview_workspace_marker_metadata_and_unknown_entries_fail_closed(
    tmp_path: Path,
) -> None:
    marker_root = tmp_path / "marker-previews"
    PreviewWorkspace(
        marker_root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    (marker_root / ".kuzet-evidence-preview-workspace.v1").write_bytes(b"forged")
    with pytest.raises(ValueError, match="marker content"):
        PreviewWorkspace(
            marker_root,
            ttl=timedelta(minutes=5),
            max_items=2,
            max_bytes=100,
            clock=lambda: NOW,
        )

    unknown_root = tmp_path / "unknown-previews"
    unknown_workspace = PreviewWorkspace(
        unknown_root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    unknown = unknown_root / "customer-owned-large.bin"
    unknown.write_bytes(b"x" * 10_000)
    with pytest.raises(PreviewWorkspaceCapacityError, match="unexpected entry"):
        unknown_workspace.prepare("reservation-1", kind="preview")
    assert unknown.stat().st_size == 10_000

    metadata_root = tmp_path / "metadata-previews"
    metadata_workspace = PreviewWorkspace(
        metadata_root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    key = metadata_workspace.path_for("reservation-1", kind="preview").name.split(".")[0]
    (metadata_root / f"{key}.json").write_bytes(b"x" * 9_000)
    with pytest.raises(
        PreviewWorkspaceCapacityError,
        match="invalid bounded metadata",
    ):
        _ = metadata_workspace.item_count

    symlink_root = tmp_path / "symlink-previews"
    symlink_workspace = PreviewWorkspace(
        symlink_root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    outside = tmp_path / "outside-metadata.json"
    outside.write_text('{"must":"remain"}', encoding="utf-8")
    symlink_key = symlink_workspace.path_for(
        "reservation-1",
        kind="preview",
    ).name.split(".")[0]
    (symlink_root / f"{symlink_key}.json").symlink_to(outside)
    with pytest.raises(
        PreviewWorkspaceCapacityError,
        match="regular owned file",
    ):
        _ = symlink_workspace.item_count
    assert outside.read_text(encoding="utf-8") == '{"must":"remain"}'


def test_preview_workspace_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    redirected_parent = tmp_path / "redirected-parent"
    redirected_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        PreviewWorkspace(
            redirected_parent / "previews",
            ttl=timedelta(minutes=5),
            max_items=2,
            max_bytes=100,
            clock=lambda: NOW,
        )

    assert not (real_parent / "previews").exists()


def test_preview_cleanup_uses_attested_descriptor_after_root_replacement(
    tmp_path: Path,
) -> None:
    root = tmp_path / "attested-previews"
    workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    reservation_id = "reservation-root-replacement"
    workspace.prepare(reservation_id, kind="preview")
    key = workspace.path_for(reservation_id, kind="preview").name.split(".")[0]
    original = tmp_path / "attested-previews-original"
    root.rename(original)
    root.mkdir(mode=0o700)
    foreign_media = root / f"{key}.preview.mp4"
    foreign_metadata = root / f"{key}.json"
    foreign_media.write_bytes(b"foreign-media")
    foreign_metadata.write_text('{"foreign":true}', encoding="utf-8")

    assert workspace.cleanup(reservation_id) == []

    assert foreign_media.read_bytes() == b"foreign-media"
    assert foreign_metadata.read_text(encoding="utf-8") == '{"foreign":true}'
    assert not (original / f"{key}.json").exists()


def test_preview_cleanup_cannot_touch_another_valid_workspace_after_swap(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first-previews"
    second_root = tmp_path / "second-previews"
    first = PreviewWorkspace(
        first_root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    second = PreviewWorkspace(
        second_root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    reservation_id = "same-reservation"
    first.prepare(reservation_id, kind="preview")
    second.prepare(reservation_id, kind="preview")
    key = first.path_for(reservation_id, kind="preview").name.split(".")[0]
    original = tmp_path / "first-previews-original"
    first_root.rename(original)
    second_root.rename(first_root)

    assert first.cleanup(reservation_id) == []

    assert (first_root / PreviewWorkspace._MARKER).read_bytes() == (
        PreviewWorkspace._MARKER_PAYLOAD
    )
    assert (first_root / f"{key}.json").exists()
    assert not (original / f"{key}.json").exists()


def test_preview_assembly_root_swap_never_writes_unmarked_replacement(
    tmp_path: Path,
) -> None:
    class Ring:
        def release(self, _: str) -> int:
            return 1

    root = tmp_path / "preview-output-root"
    original = tmp_path / "preview-output-original"

    class SwappingAssembler:
        def assemble_preview(self, _: object, output: object) -> object:
            root.rename(original)
            root.mkdir(mode=0o700)
            output.write_bytes(b"preview")  # type: ignore[attr-defined]
            return SimpleNamespace(path=output)

    coordinator = EvidenceCoordinator(
        ring=Ring(),
        assembler=SwappingAssembler(),
        publisher=SimpleNamespace(),  # type: ignore[arg-type]
        preview_workspace=PreviewWorkspace(
            root,
            ttl=timedelta(minutes=5),
            max_items=2,
            max_bytes=100,
            clock=lambda: NOW,
        ),
    )

    with pytest.raises(PreviewWorkspaceCapacityError, match="pathname"):
        coordinator.create_preview(SimpleNamespace(reservation_id="preview-swap"))

    assert tuple(root.iterdir()) == ()
    assert not tuple(original.glob("*.mp4"))
    assert not tuple(original.glob(".kuzet-preview-*.tmp"))


def test_final_assembly_root_swap_never_writes_another_valid_workspace(
    tmp_path: Path,
) -> None:
    class Ring:
        def release(self, _: str) -> int:
            return 1

    class Publisher:
        def mark_failed(self, evidence: EvidenceInput) -> EvidenceInput:
            return replace(evidence, status="failed")

    first_root = tmp_path / "final-output-first"
    second_root = tmp_path / "final-output-second"
    moved_first = tmp_path / "final-output-first-original"
    first_workspace = PreviewWorkspace(
        first_root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    second_workspace = PreviewWorkspace(
        second_root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    second_workspace.prepare("second-owned", kind="preview")
    names_before = set(os.listdir(second_workspace._root_fd))

    class SwappingAssembler:
        def assemble(self, _: object, output: object) -> object:
            first_root.rename(moved_first)
            second_root.rename(first_root)
            output.write_bytes(b"final")  # type: ignore[attr-defined]
            return SimpleNamespace(
                path=output,
                sha256=hashlib.sha256(b"final").hexdigest(),
                start_at=NOW,
                end_at=NOW + timedelta(seconds=4),
            )

    coordinator = EvidenceCoordinator(
        ring=Ring(),
        assembler=SwappingAssembler(),
        publisher=Publisher(),  # type: ignore[arg-type]
        preview_workspace=first_workspace,
    )
    seed = tmp_path / "final-swap-seed.mp4"
    seed.write_bytes(b"seed")

    with pytest.raises(PreviewWorkspaceCapacityError, match="pathname"):
        coordinator.complete(
            SimpleNamespace(reservation_id="final-swap", status="ready"),
            _evidence(_event(), seed),
        )

    assert set(os.listdir(second_workspace._root_fd)) == names_before
    assert not tuple(moved_first.glob("*.mp4"))
    assert not tuple(moved_first.glob(".kuzet-preview-*.tmp"))


def test_register_rejects_temp_basename_inode_swap_and_abort_unlinks_exact_target(
    tmp_path: Path,
) -> None:
    workspace = PreviewWorkspace(
        tmp_path / "inode-bound-previews",
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    target = workspace.prepare("inode-swap", kind="final")
    target.write_bytes(b"trusted-final")
    target_stat = os.fstat(target.descriptor)
    moved_name = f".kuzet-preview-{uuid4().hex}.tmp"
    os.rename(
        target.temporary_name,
        moved_name,
        src_dir_fd=workspace._root_fd,
        dst_dir_fd=workspace._root_fd,
    )
    replacement = os.open(
        target.temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
        dir_fd=workspace._root_fd,
    )
    os.write(replacement, b"attacker-replacement")
    os.close(replacement)

    with pytest.raises(PreviewWorkspaceCapacityError, match="inode"):
        workspace.register("inode-swap", kind="final", path=target)

    assert workspace.cleanup("inode-swap") == []
    remaining_target_inodes = {
        (entry.st_dev, entry.st_ino)
        for name in os.listdir(workspace._root_fd)
        if name.startswith(".kuzet-preview-")
        for entry in (os.stat(name, dir_fd=workspace._root_fd, follow_symlinks=False),)
    }
    assert (target_stat.st_dev, target_stat.st_ino) not in remaining_target_inodes
    assert not workspace.path_for("inode-swap", kind="final").exists()


def test_abort_cleanup_removes_preopened_assembly_temp_immediately(
    tmp_path: Path,
) -> None:
    class FailingAssembler:
        descriptor = -1

        def assemble(self, _: object, output: object) -> object:
            self.descriptor = output.descriptor  # type: ignore[attr-defined]
            output.write_bytes(b"partial")  # type: ignore[attr-defined]
            raise OSError("assembly failed")

    class Publisher:
        def mark_failed(self, evidence: EvidenceInput) -> EvidenceInput:
            return replace(evidence, status="failed")

    root = tmp_path / "abort-temp-previews"
    assembler = FailingAssembler()
    coordinator = EvidenceCoordinator(
        ring=_RecordingRing(),
        assembler=assembler,
        publisher=Publisher(),  # type: ignore[arg-type]
        preview_workspace=PreviewWorkspace(
            root,
            ttl=timedelta(minutes=5),
            max_items=2,
            max_bytes=100,
            clock=lambda: NOW,
        ),
    )
    seed = tmp_path / "abort-seed.mp4"
    seed.write_bytes(b"seed")

    with pytest.raises(OSError, match="assembly"):
        coordinator.complete(
            SimpleNamespace(reservation_id="abort-temp", status="ready"),
            _evidence(_event(), seed),
        )

    assert not tuple(root.glob(".kuzet-preview-*.tmp"))
    with pytest.raises(OSError):
        os.fstat(assembler.descriptor)


def test_ready_intent_survives_full_wal_across_restarts_until_ready_commits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    seed = tmp_path / "ready-full-wal-seed.mp4"
    seed.write_bytes(b"seed")
    pending = _evidence(event, seed)
    client = FakeS3Client()
    journal = SQLiteWALJournal(tmp_path / "ready-full.sqlite3", max_items=1)
    journal.enqueue_event(_event())
    publisher = EvidencePublisher(
        store=_s3_store(client),
        repository=repository,
        journal=journal,
    )
    original_finalize = repository.finalize_evidence

    def unavailable(*_: object, **__: object) -> object:
        raise OSError("database unavailable")

    monkeypatch.setattr(repository, "finalize_evidence", unavailable)
    root = tmp_path / "ready-full-wal-previews"
    first_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    first_ring = _RecordingRing()
    coordinator = EvidenceCoordinator(
        ring=first_ring,
        assembler=_FinalBytesAssembler(),
        publisher=publisher,
        preview_workspace=first_workspace,
    )

    with pytest.raises(JournalFullError) as first_failure:
        coordinator.complete(
            SimpleNamespace(reservation_id="ready-full-wal", status="ready"),
            pending,
        )
    assert first_failure.value.evidence_object_durable is True  # type: ignore[attr-defined]
    assert first_failure.value.ready_transition_durable is False  # type: ignore[attr-defined]
    assert first_workspace.item_count == 1
    assert first_ring.released == ["ready-full-wal"]
    assert client.objects
    first_workspace.close()

    second_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    second_ring = _RecordingRing()
    with pytest.raises(ExceptionGroup):
        EvidenceCoordinator(
            ring=second_ring,
            assembler=_FinalBytesAssembler(),
            publisher=publisher,
            preview_workspace=second_workspace,
        )
    assert second_workspace.item_count == 1
    assert second_ring.released == ["ready-full-wal"]
    second_workspace.close()

    monkeypatch.setattr(repository, "finalize_evidence", original_finalize)
    third_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    third_ring = _RecordingRing()
    EvidenceCoordinator(
        ring=third_ring,
        assembler=_FinalBytesAssembler(),
        publisher=publisher,
        preview_workspace=third_workspace,
    )

    assert repository.get_event(event.event_id).evidence_status == "ready"
    assert third_workspace.item_count == 0
    assert third_ring.released == ["ready-full-wal"]


def test_deterministic_ready_failure_keeps_tombstone_until_later_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    seed = tmp_path / "deterministic-ready-seed.mp4"
    seed.write_bytes(b"seed")
    pending = _evidence(event, seed)
    publisher = EvidencePublisher(
        store=_s3_store(FakeS3Client()),
        repository=repository,
    )
    original_finalize = repository.finalize_evidence

    def conflict(*_: object, **__: object) -> object:
        raise IdempotencyConflictError("deterministic identity conflict")

    monkeypatch.setattr(repository, "finalize_evidence", conflict)
    root = tmp_path / "deterministic-ready-previews"
    first_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    coordinator = EvidenceCoordinator(
        ring=_RecordingRing(),
        assembler=_FinalBytesAssembler(),
        publisher=publisher,
        preview_workspace=first_workspace,
    )
    with pytest.raises(IdempotencyConflictError) as failure:
        coordinator.complete(
            SimpleNamespace(reservation_id="deterministic-ready", status="ready"),
            pending,
        )
    assert failure.value.evidence_object_durable is True  # type: ignore[attr-defined]
    assert failure.value.ready_transition_durable is False  # type: ignore[attr-defined]
    assert first_workspace.item_count == 1
    first_workspace.close()

    second_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    with pytest.raises(ExceptionGroup):
        EvidenceCoordinator(
            ring=_RecordingRing(),
            assembler=_FinalBytesAssembler(),
            publisher=publisher,
            preview_workspace=second_workspace,
        )
    assert second_workspace.item_count == 1
    second_workspace.close()

    monkeypatch.setattr(repository, "finalize_evidence", original_finalize)
    third_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    EvidenceCoordinator(
        ring=_RecordingRing(),
        assembler=_FinalBytesAssembler(),
        publisher=publisher,
        preview_workspace=third_workspace,
    )
    assert repository.get_event(event.event_id).evidence_status == "ready"
    assert third_workspace.item_count == 0


def test_restart_republishes_safe_local_ready_intent_after_preupload_crash(
    tmp_path: Path,
) -> None:
    class CrashBeforeUploadPublisher:
        def publish(self, *_: object, **__: object) -> object:
            raise KeyboardInterrupt

    repository = _repository()
    event = _event()
    repository.add_event(event)
    seed = tmp_path / "preupload-crash-seed.mp4"
    seed.write_bytes(b"seed")
    pending = _evidence(event, seed)
    root = tmp_path / "preupload-crash-previews"
    first_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    coordinator = EvidenceCoordinator(
        ring=_RecordingRing(),
        assembler=_FinalBytesAssembler(),
        publisher=CrashBeforeUploadPublisher(),  # type: ignore[arg-type]
        preview_workspace=first_workspace,
    )

    with pytest.raises(KeyboardInterrupt):
        coordinator.complete(
            SimpleNamespace(reservation_id="preupload-crash", status="ready"),
            pending,
        )
    assert first_workspace.item_count == 1
    assert first_workspace.path_for("preupload-crash", kind="final").exists()
    first_workspace.close()

    client = FakeS3Client()
    second_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    ring = _RecordingRing()
    EvidenceCoordinator(
        ring=ring,
        assembler=_FinalBytesAssembler(),
        publisher=EvidencePublisher(
            store=_s3_store(client),
            repository=repository,
        ),
        preview_workspace=second_workspace,
    )

    assert client.objects
    assert repository.get_event(event.event_id).evidence_status == "ready"
    assert second_workspace.item_count == 0
    assert ring.released == ["preupload-crash"]


def test_remote_ready_identity_mismatch_fails_terminally_without_inference(
    tmp_path: Path,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    seed = tmp_path / "remote-mismatch-seed.mp4"
    seed.write_bytes(b"seed")
    pending = _evidence(event, seed)
    root = tmp_path / "remote-mismatch-previews"
    workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    reservation_id = "remote-mismatch"
    target = workspace.prepare(reservation_id, kind="final", evidence=pending)
    target.write_bytes(b"trusted-final")
    registered = workspace.register(
        reservation_id,
        kind="final",
        path=target,
        evidence=pending,
    )
    bounded = replace(
        pending,
        sha256=registered.sha256,
        start_at=NOW - timedelta(seconds=2),
        end_at=NOW + timedelta(seconds=4),
        status="pending",
    )
    workspace.persist_ready_intent(
        reservation_id,
        evidence=bounded,
        size_bytes=registered.size_bytes,
    )
    workspace.close()

    client = FakeS3Client()
    remote_key = f"pilot-evidence/{bounded.object_key}"
    wrong = b"different-remote-bytes"
    client.objects[("evidence", remote_key)] = {
        "Body": wrong,
        "ChecksumSHA256": base64.b64encode(hashlib.sha256(wrong).digest()).decode(),
        "ServerSideEncryption": "AES256",
        "LastModified": NOW,
    }
    restarted_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    EvidenceCoordinator(
        ring=_RecordingRing(),
        assembler=_FinalBytesAssembler(),
        publisher=EvidencePublisher(
            store=_s3_store(client),
            repository=repository,
        ),
        preview_workspace=restarted_workspace,
    )

    assert repository.get_event(event.event_id).evidence_status == "failed"
    assert restarted_workspace.item_count == 0
    assert client.objects[("evidence", remote_key)]["Body"] == wrong


@pytest.mark.parametrize("mismatch_location", ("remote", "local"))
def test_ready_identity_mismatch_preserves_primary_across_failed_transition_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch_location: str,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    seed = tmp_path / f"{mismatch_location}-ordered-mismatch-seed.mp4"
    seed.write_bytes(b"seed")
    pending = _evidence(event, seed)
    root = tmp_path / f"{mismatch_location}-ordered-mismatch-previews"
    reservation_id = f"{mismatch_location}-ordered-mismatch"
    workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    target = workspace.prepare(reservation_id, kind="final", evidence=pending)
    target.write_bytes(b"trusted-final")
    registered = workspace.register(
        reservation_id,
        kind="final",
        path=target,
        evidence=pending,
    )
    bounded = replace(
        pending,
        sha256=registered.sha256,
        start_at=NOW - timedelta(seconds=2),
        end_at=NOW + timedelta(seconds=4),
        status="pending",
    )
    workspace.persist_ready_intent(
        reservation_id,
        evidence=bounded,
        size_bytes=registered.size_bytes,
    )
    final_path = workspace.path_for(reservation_id, kind="final")
    client = FakeS3Client()
    remote_key = f"pilot-evidence/{bounded.object_key}"
    wrong = b"different-identity"
    if mismatch_location == "remote":
        client.objects[("evidence", remote_key)] = {
            "Body": wrong,
            "ChecksumSHA256": base64.b64encode(
                hashlib.sha256(wrong).digest()
            ).decode(),
            "ServerSideEncryption": "AES256",
            "LastModified": NOW,
        }
    else:
        final_path.write_bytes(wrong)
    workspace.close()

    original_finalize = repository.finalize_evidence

    def unavailable(*_: object, **__: object) -> object:
        raise RuntimeError("failed transition unavailable")

    monkeypatch.setattr(repository, "finalize_evidence", unavailable)
    first_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    with pytest.raises(ExceptionGroup) as first_failure:
        EvidenceCoordinator(
            ring=_RecordingRing(),
            assembler=_FinalBytesAssembler(),
            publisher=EvidencePublisher(
                store=_s3_store(client),
                repository=repository,
            ),
            preview_workspace=first_workspace,
        )

    assert [type(error) for error in first_failure.value.exceptions] == [
        ObjectIntegrityError,
        RuntimeError,
    ]
    assert first_workspace.item_count == 1
    first_workspace.close()

    monkeypatch.setattr(repository, "finalize_evidence", original_finalize)
    second_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    EvidenceCoordinator(
        ring=_RecordingRing(),
        assembler=_FinalBytesAssembler(),
        publisher=EvidencePublisher(
            store=_s3_store(client),
            repository=repository,
        ),
        preview_workspace=second_workspace,
    )

    assert repository.get_event(event.event_id).evidence_status == "failed"
    assert second_workspace.item_count == 0


def test_restart_reconciliation_keeps_identity_until_second_restart_succeeds(
    tmp_path: Path,
) -> None:
    class Ring:
        def __init__(self) -> None:
            self.released: list[str] = []

        def release(self, reservation_id: str) -> int:
            self.released.append(reservation_id)
            return 1

    class FailingPublisher:
        def mark_failed(self, _: EvidenceInput) -> EvidenceInput:
            raise RuntimeError("database and WAL unavailable")

    class RecordingPublisher:
        def __init__(self) -> None:
            self.failed: list[EvidenceInput] = []

        def mark_failed(self, evidence: EvidenceInput) -> EvidenceInput:
            self.failed.append(evidence)
            return replace(evidence, status="failed")

    root = tmp_path / "reconciliation-previews"
    seed = tmp_path / "reconciliation-seed.mp4"
    seed.write_bytes(b"seed")
    pending = _evidence(_event(), seed)
    reservation_id = "reservation-reconcile"
    first_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    output = first_workspace.prepare(
        reservation_id,
        kind="preview",
        evidence=pending,
    )
    output.write_bytes(b"preview")
    first_workspace.register(
        reservation_id,
        kind="preview",
        path=output,
        evidence=pending,
    )
    first_ring = Ring()

    with pytest.raises(ExceptionGroup) as first_failure:
        EvidenceCoordinator(
            ring=first_ring,
            assembler=SimpleNamespace(),
            publisher=FailingPublisher(),  # type: ignore[arg-type]
            preview_workspace=first_workspace,
        )

    assert isinstance(first_failure.value.exceptions[0], RuntimeError)
    assert first_ring.released == [reservation_id]
    assert first_workspace.item_count == 1
    assert not output.exists()

    second_workspace = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=100,
        clock=lambda: NOW,
    )
    second_ring = Ring()
    successful = RecordingPublisher()
    EvidenceCoordinator(
        ring=second_ring,
        assembler=SimpleNamespace(),
        publisher=successful,  # type: ignore[arg-type]
        preview_workspace=second_workspace,
    )

    assert [item.evidence_id for item in successful.failed] == [pending.evidence_id]
    assert second_ring.released == [reservation_id]
    assert second_workspace.item_count == 0


def test_cancel_and_expiry_use_persisted_evidence_by_default(tmp_path: Path) -> None:
    class Clock:
        now = NOW

        def __call__(self) -> datetime:
            return self.now

    class Ring:
        def release(self, _: str) -> int:
            return 1

    class Assembler:
        def assemble_preview(self, _: object, output: Path) -> object:
            output.write_bytes(b"preview")
            return SimpleNamespace(path=output)

    class Publisher:
        def __init__(self) -> None:
            self.failed: list[EvidenceInput] = []

        def mark_failed(self, evidence: EvidenceInput) -> EvidenceInput:
            self.failed.append(evidence)
            return replace(evidence, status="failed")

    clock = Clock()
    publisher = Publisher()
    coordinator = EvidenceCoordinator(
        ring=Ring(),
        assembler=Assembler(),
        publisher=publisher,  # type: ignore[arg-type]
        preview_workspace=PreviewWorkspace(
            tmp_path / "terminal-previews",
            ttl=timedelta(seconds=10),
            max_items=4,
            max_bytes=100,
            clock=clock,
        ),
    )
    seed = tmp_path / "terminal-seed.mp4"
    seed.write_bytes(b"seed")
    first = _evidence(_event(), seed)
    second = replace(first, evidence_id=uuid4(), object_key="events/second.mp4")
    coordinator.create_preview(
        SimpleNamespace(reservation_id="cancel-me"),
        evidence=first,
    )
    coordinator.cancel("cancel-me")
    coordinator.create_preview(
        SimpleNamespace(reservation_id="expire-me"),
        evidence=second,
    )
    clock.now += timedelta(seconds=11)

    assert coordinator.sweep_expired() == ("expire-me",)
    assert [item.evidence_id for item in publisher.failed] == [
        first.evidence_id,
        second.evidence_id,
    ]


def test_publisher_preserves_upload_error_before_failed_transition_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingStore:
        primary = ObjectPublishError("upload failed")

        def publish(self, *_: object, **__: object) -> object:
            raise self.primary

    repository = _repository()
    event = _event()
    repository.add_event(event)
    seed = tmp_path / "publisher-failure.mp4"
    seed.write_bytes(b"seed")
    evidence = _evidence(event, seed)
    journal = SQLiteWALJournal(tmp_path / "full-journal.sqlite3", max_items=1)
    journal.enqueue_event(_event())
    monkeypatch.setattr(
        repository,
        "finalize_evidence",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("database unavailable")
        ),
    )
    publisher = EvidencePublisher(
        store=FailingStore(),  # type: ignore[arg-type]
        repository=repository,
        journal=journal,
    )

    with pytest.raises(ExceptionGroup) as failure:
        publisher.publish(seed, evidence)

    assert failure.value.exceptions[0] is FailingStore.primary
    assert isinstance(failure.value.exceptions[1], JournalFullError)


def test_publisher_does_not_journal_deterministic_repository_conflicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"encoded-browser-evidence")
    evidence = _evidence(event, clip)
    journal = SQLiteWALJournal(tmp_path / "deterministic.sqlite3", max_items=10)
    publisher = EvidencePublisher(
        store=_s3_store(FakeS3Client()),
        repository=repository,
        journal=journal,
    )

    def conflict(*_: object, **__: object) -> object:
        raise IdempotencyConflictError("deterministic identity conflict")

    monkeypatch.setattr(repository, "finalize_evidence", conflict)
    with pytest.raises(IdempotencyConflictError, match="deterministic") as transition:
        publisher.publish(clip, evidence)
    assert transition.value.evidence_object_durable is True  # type: ignore[attr-defined]
    assert transition.value.ready_transition_durable is False  # type: ignore[attr-defined]
    assert journal.depth() == 0


@pytest.mark.parametrize(
    "failure",
    (
        IntegrityError("INSERT", {}, ValueError("unique constraint")),
        DataError("INSERT", {}, ValueError("invalid data")),
        ProgrammingError("INSERT", {}, ValueError("missing column")),
    ),
)
def test_publisher_never_journals_deterministic_sqlalchemy_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"encoded-browser-evidence")
    evidence = _evidence(event, clip)
    journal = SQLiteWALJournal(tmp_path / "deterministic-sql.sqlite3", max_items=10)
    publisher = EvidencePublisher(
        store=_s3_store(FakeS3Client()),
        repository=repository,
        journal=journal,
    )
    monkeypatch.setattr(
        repository,
        "finalize_evidence",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(failure),
    )

    with pytest.raises(type(failure)) as transition:
        publisher.publish(clip, evidence)
    assert transition.value.evidence_object_durable is True  # type: ignore[attr-defined]
    assert transition.value.ready_transition_durable is False  # type: ignore[attr-defined]
    assert journal.depth() == 0


def test_publisher_journals_retryable_sqlite_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"encoded-browser-evidence")
    evidence = _evidence(event, clip)
    journal = SQLiteWALJournal(tmp_path / "locked-sql.sqlite3", max_items=10)
    publisher = EvidencePublisher(
        store=_s3_store(FakeS3Client()),
        repository=repository,
        journal=journal,
    )
    monkeypatch.setattr(
        repository,
        "finalize_evidence",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OperationalError(
                "UPDATE evidence",
                {},
                sqlite3.OperationalError("database is locked"),
            )
        ),
    )

    assert publisher.publish(clip, evidence).status == "ready"
    assert journal.depth() == 1


def test_production_builder_uses_validated_site_storage_policy_and_injected_credentials(
    tmp_path: Path,
) -> None:
    repository = _repository()
    journal = SQLiteWALJournal(tmp_path / "delivery.sqlite3", max_items=10)
    ring = EncodedFragmentRing(
        tmp_path / "spool",
        ring_seconds=15,
        max_camera_bytes=1_000,
        max_spool_bytes=2_000,
    )
    site = SimpleNamespace(
        storage=SimpleNamespace(
            endpoint="https://objects.example.test/",
            bucket="evidence",
            country_code="KZ",
            evidence_prefix="configured-evidence",
            max_evidence_object_bytes=123_456,
            server_side_encryption="AES256",
            kms_key_id=None,
        )
    )

    services = build_s3_evidence_delivery(
        site=site,  # type: ignore[arg-type]
        client=FakeS3Client(),
        repository=repository,
        journal=journal,
        ring=ring,
        max_nvenc_jobs=1,
        codec_tool=SimpleNamespace(nvenc_available=False),  # type: ignore[arg-type]
        media_probe=SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert services.store.evidence_prefix == "configured-evidence"
    assert services.store.max_object_bytes == 123_456
    assert services.coordinator._ring is ring
    assert services.replay_worker.status.depth == 0


def test_restart_reconciles_hashless_pending_intent_without_material_evidence_row(
    tmp_path: Path,
) -> None:
    repository = _repository()
    event = _event().model_copy(update={"evidence_status": "unavailable"})
    repository.add_event(event)
    intent = EvidenceIntent(
        schema_version="evidence-intent.v1",
        evidence_id=uuid4(),
        event_id=event.event_id,
        object_key=f"events/{event.event_id}.mp4",
        codec="h264",
        start_at=NOW - timedelta(seconds=2),
        end_at=NOW + timedelta(seconds=2),
        source_reference="nvr://camera/01",
    )
    root = tmp_path / "intent-restart"
    first = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    output = first.prepare("reservation-intent", kind="preview", evidence=intent)
    output.write_bytes(b"preview")
    first.register(
        "reservation-intent",
        kind="preview",
        path=output,
        evidence=intent,
    )
    metadata = next(root.glob("*.json")).read_text()
    assert '"schema_version":"evidence-intent.v1"' in metadata
    assert "sha256" not in metadata
    first.close()

    ring = _RecordingRing()
    second = PreviewWorkspace(
        root,
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=1_000,
        clock=lambda: NOW,
    )
    EvidenceCoordinator(
        ring=ring,
        assembler=SimpleNamespace(),
        publisher=EvidencePublisher(
            store=SimpleNamespace(),  # type: ignore[arg-type]
            repository=repository,
        ),
        preview_workspace=second,
    )

    assert repository.get_event(event.event_id).evidence_status == "failed"
    with repository.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceModel)) == 0
    assert ring.released == ["reservation-intent"]
    assert second.item_count == 0
