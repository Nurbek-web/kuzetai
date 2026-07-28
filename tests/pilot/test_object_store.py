from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import Base, EvidenceModel
from protector.pilot.storage.object_store import (
    EncryptedLocalObjectStore,
    EvidencePublisher,
    ObjectIntegrityError,
    ObjectPublishError,
    S3CompatibleObjectStore,
    validate_object_key,
)
from protector.pilot.storage.repositories import EvidenceInput, PilotRepository

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


class FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_copy_once = False

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        try:
            stored = self.objects[(Bucket, Key)]
        except KeyError as exc:
            raise KeyError(Key) from exc
        return {
            "ContentLength": len(stored["Body"]),
            "Metadata": dict(stored["Metadata"]),
        }

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        Metadata: dict[str, str],
    ) -> None:
        self.calls.append(("put", Key))
        self.objects[(Bucket, Key)] = {
            "Body": bytes(Body),
            "Metadata": dict(Metadata),
            "LastModified": NOW,
        }

    def copy_object(
        self,
        *,
        Bucket: str,
        Key: str,
        CopySource: dict[str, str],
        MetadataDirective: str,
    ) -> None:
        self.calls.append(("copy", Key))
        if self.fail_copy_once:
            self.fail_copy_once = False
            raise OSError("simulated interrupted upload")
        source = self.objects[(CopySource["Bucket"], CopySource["Key"])]
        self.objects[(Bucket, Key)] = {
            "Body": source["Body"],
            "Metadata": dict(source["Metadata"]),
            "LastModified": NOW,
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
        S3CompatibleObjectStore(
            client=client,
            endpoint="http://objects.example.test",
            bucket="evidence",
            country_code="KZ",
        )
    with pytest.raises(ValueError, match="Kazakhstan"):
        S3CompatibleObjectStore(
            client=client,
            endpoint="https://objects.example.test",
            bucket="evidence",
            country_code="US",
        )
    with pytest.raises(TypeError):
        S3CompatibleObjectStore(
            client=client,
            endpoint="https://objects.example.test",
            bucket="evidence",
            country_code="KZ",
            access_key="must-not-be-accepted",
        )


def test_s3_publish_verifies_digest_promotes_then_cleans_incomplete_key(
    tmp_path: Path,
) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    client = FakeS3Client()
    store = S3CompatibleObjectStore(
        client=client,
        endpoint="https://objects.example.test",
        bucket="evidence",
        country_code="KZ",
    )

    stored = store.publish(source, "events/camera-01/evidence.mp4", sha256=digest)

    assert stored.key == "events/camera-01/evidence.mp4"
    assert stored.sha256 == digest
    assert client.objects[("evidence", stored.key)]["Body"] == source.read_bytes()
    assert not any(key.startswith(".incomplete/") for _, key in client.objects)
    assert [operation for operation, _ in client.calls] == ["put", "copy", "delete"]


def test_s3_interrupted_upload_is_cleaned_and_retry_is_idempotent(tmp_path: Path) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    client = FakeS3Client()
    client.fail_copy_once = True
    store = S3CompatibleObjectStore(
        client=client,
        endpoint="https://objects.example.test",
        bucket="evidence",
        country_code="KZ",
    )

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
    store = S3CompatibleObjectStore(
        client=client,
        endpoint="https://objects.example.test",
        bucket="evidence",
        country_code="KZ",
    )

    with pytest.raises(ObjectIntegrityError, match="SHA-256"):
        store.publish(source, "events/camera-01/evidence.mp4", sha256="0" * 64)
    assert client.calls == []


def test_encrypted_local_volume_requires_attestation_and_publishes_atomically(
    tmp_path: Path,
) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    with pytest.raises(ValueError, match="attestation"):
        EncryptedLocalObjectStore(tmp_path / "volume", encrypted_volume_attestation="")
    store = EncryptedLocalObjectStore(
        tmp_path / "volume",
        encrypted_volume_attestation="LUKS2 volume /dev/mapper/kuzet-evidence verified 2026-07-28",
    )

    stored = store.publish(source, "events/camera-01/evidence.mp4", sha256=digest)

    assert stored.path is not None
    assert stored.path.read_bytes() == source.read_bytes()
    assert not list((tmp_path / "volume").rglob("*.part"))
    assert store.publish(source, stored.key, sha256=digest) == stored


def test_local_store_refuses_symlink_escape_and_retention_deletes_only_expired(
    tmp_path: Path,
) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    root = tmp_path / "volume"
    store = EncryptedLocalObjectStore(
        root,
        encrypted_volume_attestation="encrypted-volume-ticket-KUZET-42",
    )
    old = store.publish(source, "events/camera-01/old.mp4", sha256=digest)
    current = store.publish(source, "events/camera-01/current.mp4", sha256=digest)
    assert old.path is not None and current.path is not None
    os.utime(old.path, (NOW.timestamp() - 100, NOW.timestamp() - 100))
    os.utime(current.path, (NOW.timestamp(), NOW.timestamp()))
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "events" / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        store.publish(source, "events/linked/escape.mp4", sha256=digest)
    assert store.delete_older_than(NOW - timedelta(seconds=50)) == ("events/camera-01/old.mp4",)
    assert current.path.exists()
    assert not old.path.exists()


def test_s3_retention_deletes_expired_final_objects_not_incomplete(tmp_path: Path) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"encoded-browser-evidence")
    digest = "e539eda43d4506254c73453ab5d57b9ae99c09847fdf7451055ae9b927958306"
    client = FakeS3Client()
    store = S3CompatibleObjectStore(
        client=client,
        endpoint="https://objects.example.test",
        bucket="evidence",
        country_code="KZ",
    )
    store.publish(source, "events/camera-01/old.mp4", sha256=digest)
    client.objects[("evidence", "events/camera-01/old.mp4")]["LastModified"] = NOW - timedelta(
        days=2
    )
    client.objects[("evidence", ".incomplete/crash.part")] = {
        "Body": b"partial",
        "Metadata": {},
        "LastModified": NOW - timedelta(days=2),
    }

    assert store.delete_older_than(NOW - timedelta(days=1)) == (
        ".incomplete/crash.part",
        "events/camera-01/old.mp4",
    )
    assert ("evidence", ".incomplete/crash.part") not in client.objects


def test_local_store_removes_crash_left_incomplete_files_on_restart(tmp_path: Path) -> None:
    root = tmp_path / "volume"
    root.mkdir()
    incomplete = root / "events" / ".clip.crash.part"
    incomplete.parent.mkdir()
    incomplete.write_bytes(b"partial")

    EncryptedLocalObjectStore(
        root,
        encrypted_volume_attestation="encrypted-volume-ticket-KUZET-42",
    )

    assert not incomplete.exists()


def test_publisher_marks_failed_upload_visible_but_never_ready(tmp_path: Path) -> None:
    repository = _repository()
    event = _event()
    repository.add_event(event)
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(b"encoded-browser-evidence")
    evidence = _evidence(event, clip)
    client = FakeS3Client()
    client.fail_copy_once = True
    publisher = EvidencePublisher(
        store=S3CompatibleObjectStore(
            client=client,
            endpoint="https://objects.example.test",
            bucket="evidence",
            country_code="KZ",
        ),
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
    store = S3CompatibleObjectStore(
        client=client,
        endpoint="https://objects.example.test",
        bucket="evidence",
        country_code="KZ",
    )
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
