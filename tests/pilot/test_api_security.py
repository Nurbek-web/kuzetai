from __future__ import annotations

import asyncio
import base64
import json
import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event
from uuid import UUID, uuid4

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import select
from sqlalchemy.orm import Session

from protector.pilot.api.app import create_app
from protector.pilot.api.auth import LoginThrottle, TotpService
from protector.pilot.api.dependencies import redact_secrets
from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    AuditEntryModel,
    Base,
    NotificationOutboxModel,
    ReviewModel,
)
from protector.pilot.storage.repositories import PilotRepository

UTC = timezone.utc
NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
TOTP_KEY = base64.urlsafe_b64encode(b"t" * 32).decode()


def _lifespan_lock_worker(
    lock_path: str,
    barrier: object,
    result_connection: object,
) -> None:
    repository = PilotRepository(
        create_session_factory(create_engine("sqlite+pysqlite:///:memory:"))
    )
    try:
        app = create_app(
            repository=repository,
            session_secret="session-secret-at-least-32-characters",
            totp_encryption_key=TOTP_KEY,
            machine_token="machine-token-at-least-16",
            runtime_lock_path=lock_path,
        )
        barrier.wait(timeout=10)

        async def run_lifespan() -> None:
            async with app.router.lifespan_context(app):
                result_connection.send(("acquired", os.getpid()))
                Event().wait(timeout=30)

        asyncio.run(run_lifespan())
    except BaseException as exc:
        result_connection.send(("rejected", f"{type(exc).__name__}: {exc}"))
    finally:
        result_connection.close()


def _repository(tmp_path: Path) -> PilotRepository:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / f'{uuid4()}.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name=f"School {uuid4()}")
    repository.add_camera(
        camera_id="cam-01",
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
            source="registry artifact",
            commercial_rights=CommercialRightsRecordV1(
                schema_version="commercial-rights.v1",
                record_id="rights-1",
                terms_reference="legal record",
                commercial_use_approved=True,
            ),
            class_list=("person",),
            preprocessing="letterbox",
            analytic="person",
        )
    )
    return repository


def _event() -> CandidateEventV1:
    return CandidateEventV1(
        schema_version="candidate-event.v1",
        event_id=uuid4(),
        camera_id="cam-01",
        module="person",
        opened_at=NOW,
        last_seen_at=NOW + timedelta(seconds=1),
        peak_confidence=0.9,
        reason="zone intrusion",
        model_artifact_id="person-v1",
        gate_mode="operator",
        evidence_status="pending",
        review_status="candidate",
    )


def test_totp_seed_is_authenticated_encrypted_and_only_current_counter_matches() -> None:
    service = TotpService(encryption_key=TOTP_KEY)
    secret = service.enrol("operator").secret
    encrypted = service.encrypt_secret(secret)
    current_code = pyotp.TOTP(secret).at(NOW)
    previous_code = pyotp.TOTP(secret).at(NOW - timedelta(seconds=30))

    assert secret not in encrypted
    assert service.decrypt_secret(encrypted) == secret
    assert service.match_current_counter(encrypted, current_code, at=NOW) == int(
        NOW.timestamp() // 30
    )
    assert service.match_current_counter(encrypted, previous_code, at=NOW) is None

    tampered = f"{encrypted[:-1]}{'A' if encrypted[-1] != 'A' else 'B'}"
    with pytest.raises(ValueError, match="invalid encrypted TOTP secret"):
        service.decrypt_secret(tampered)


def test_totp_counter_advance_is_atomic_and_persists_across_repository_instances(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    totp = TotpService(encryption_key=TOTP_KEY)
    encrypted_seed = totp.encrypt_secret(totp.enrol("operator").secret)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
        totp_secret_encrypted=encrypted_seed,
    )
    counter = 123_456
    barrier = Barrier(8)

    def accept() -> bool:
        barrier.wait(timeout=5)
        return repository.accept_totp_counter(
            user_id="operator-1",
            counter=counter,
            expected_password_hash="argon2id-placeholder",
            expected_encrypted_secret=encrypted_seed,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        accepted = list(executor.map(lambda _: accept(), range(8)))

    restarted = PilotRepository(repository.session_factory)
    assert accepted.count(True) == 1
    assert (
        restarted.accept_totp_counter(
            user_id="operator-1",
            counter=counter,
            expected_password_hash="argon2id-placeholder",
            expected_encrypted_secret=encrypted_seed,
        )
        is False
    )
    assert restarted.accept_totp_counter(
        user_id="operator-1",
        counter=counter + 1,
        expected_password_hash="argon2id-placeholder",
        expected_encrypted_secret=encrypted_seed,
    )


def test_login_throttle_admission_is_atomic_per_account_and_client_context() -> None:
    throttle = LoginThrottle(
        max_attempts=3,
        client_max_attempts=20,
        window_seconds=60,
        max_entries=100,
    )
    barrier = Barrier(12)

    def admit(index: int) -> bool:
        barrier.wait(timeout=5)
        return throttle.admit_attempt("operator", f"client-{index}")

    with ThreadPoolExecutor(max_workers=12) as executor:
        admitted = list(executor.map(admit, range(12)))

    assert admitted.count(True) == 3

    per_client = LoginThrottle(
        max_attempts=20,
        client_max_attempts=2,
        window_seconds=60,
        max_entries=100,
    )
    assert per_client.admit_attempt("one", "same-client")
    assert per_client.admit_attempt("two", "same-client")
    assert not per_client.admit_attempt("three", "same-client")


def test_app_rejects_multi_worker_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _repository(tmp_path)

    with pytest.raises(ValueError, match="exactly one API worker"):
        create_app(
            repository=repository,
            session_secret="session-secret-at-least-32-characters",
            totp_encryption_key=TOTP_KEY,
            machine_token="machine-token-at-least-16",
            worker_count=2,
        )

    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    with pytest.raises(ValueError, match="exactly one API worker"):
        create_app(
            repository=repository,
            session_secret="session-secret-at-least-32-characters",
            totp_encryption_key=TOTP_KEY,
            machine_token="machine-token-at-least-16",
        )


def test_two_real_app_lifespans_admit_one_process_and_stale_exit_releases_lock(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    lock_path = str(tmp_path / "api-singleton.lock")
    pipes = [context.Pipe(duplex=False) for _ in range(2)]
    workers = [
        context.Process(
            target=_lifespan_lock_worker,
            args=(lock_path, barrier, child_connection),
        )
        for _, child_connection in pipes
    ]
    for worker in workers:
        worker.start()
    for _, child_connection in pipes:
        child_connection.close()

    results = []
    for parent_connection, _ in pipes:
        assert parent_connection.poll(15)
        results.append(parent_connection.recv())
        parent_connection.close()
    assert sorted(result[0] for result in results) == ["acquired", "rejected"]
    assert "already held" in next(result[1] for result in results if result[0] == "rejected")

    acquired_pid = next(result[1] for result in results if result[0] == "acquired")
    acquired_worker = next(worker for worker in workers if worker.pid == acquired_pid)
    acquired_worker.terminate()
    acquired_worker.join(timeout=10)
    for worker in workers:
        if worker is not acquired_worker:
            worker.join(timeout=10)
            assert worker.exitcode == 0

    repository = PilotRepository(
        create_session_factory(create_engine("sqlite+pysqlite:///:memory:"))
    )
    recovered = create_app(
        repository=repository,
        session_secret="session-secret-at-least-32-characters",
        totp_encryption_key=TOTP_KEY,
        machine_token="machine-token-at-least-16",
        runtime_lock_path=lock_path,
    )

    async def run_recovered_lifespan() -> None:
        async with recovered.router.lifespan_context(recovered):
            pass

    asyncio.run(run_recovered_lifespan())


def test_redaction_is_conservative_for_uris_headers_and_credential_like_keys() -> None:
    payload = {
        "note": "camera rtsp://admin:password@10.0.0.8/private/live failed",
        "evidence": "s3://private-bucket/events/secret.mp4",
        "Authorization": "Bearer machine-secret",
        "x-api-token": "api-secret",
        "dbCredentialValue": "database-secret",
        "object_key": "private/events/incident.mp4",
        "signedUrl": "https://object-store.example/private?signature=secret",
        "nested": {"arbitraryPasswordVariant": "password-secret"},
        "safe": "ordinary operator note",
    }

    redacted = redact_secrets(payload)

    assert redacted["note"] == "[REDACTED]"
    assert redacted["evidence"] == "[REDACTED]"
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["x-api-token"] == "[REDACTED]"
    assert redacted["dbCredentialValue"] == "[REDACTED]"
    assert redacted["object_key"] == "[REDACTED]"
    assert redacted["signedUrl"] == "[REDACTED]"
    assert redacted["nested"]["arbitraryPasswordVariant"] == "[REDACTED]"
    assert redacted["safe"] == "ordinary operator note"


def test_confirm_review_and_outbox_roll_back_together_on_outbox_failure(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    candidate = _event()
    repository.add_event(candidate)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )

    def reject_outbox(session: Session, *_: object) -> None:
        if any(isinstance(row, NotificationOutboxModel) for row in session.new):
            raise RuntimeError("injected outbox failure")

    sqlalchemy_event.listen(Session, "before_flush", reject_outbox)
    try:
        with pytest.raises(RuntimeError, match="injected outbox failure"):
            repository.review_event_and_enqueue_notification(
                event_id=candidate.event_id,
                reviewer_id="operator-1",
                target_status="confirmed",
                expected_status="candidate",
                review_idempotency_key="review-atomic",
                notification_idempotency_key="notification-atomic",
                notes=None,
                reviewed_at=NOW + timedelta(minutes=1),
            )
    finally:
        sqlalchemy_event.remove(Session, "before_flush", reject_outbox)

    assert repository.get_event(candidate.event_id).review_status == "candidate"
    with repository.session_factory() as session:
        assert list(session.scalars(select(ReviewModel))) == []
        assert list(session.scalars(select(AuditEntryModel))) == []
        assert list(session.scalars(select(NotificationOutboxModel))) == []


def test_confirm_review_and_outbox_have_one_stable_idempotency_boundary(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    candidate = _event()
    repository.add_event(candidate)
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )
    kwargs = {
        "event_id": candidate.event_id,
        "reviewer_id": "operator-1",
        "target_status": "confirmed",
        "expected_status": "candidate",
        "review_idempotency_key": "r" * 255,
        "notification_idempotency_key": "notification-stable",
        "notes": "confirmed",
        "reviewed_at": NOW + timedelta(minutes=1),
    }

    first = repository.review_event_and_enqueue_notification(**kwargs)
    replay = repository.review_event_and_enqueue_notification(**kwargs)

    assert first.review.review_id == replay.review.review_id
    assert first.outbox is not None
    assert replay.outbox is not None
    assert first.outbox.outbox_id == replay.outbox.outbox_id
    with repository.session_factory() as session:
        assert len(list(session.scalars(select(ReviewModel)))) == 1
        audit = list(session.scalars(select(AuditEntryModel)))
        assert len(audit) == 1
        assert len(audit[0].idempotency_key) <= 255
        assert len(list(session.scalars(select(NotificationOutboxModel)))) == 1


def test_request_body_limit_rejects_declared_and_streamed_oversize_before_validation(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    app = create_app(
        repository=repository,
        session_secret="session-secret-at-least-32-characters",
        totp_encryption_key=TOTP_KEY,
        machine_token="machine-token-at-least-16",
    )
    client = TestClient(app, base_url="https://testserver")
    oversized = json.dumps(
        {"username": "operator", "password": "x" * 70_000, "totp_code": "123456"}
    ).encode()

    declared = client.post(
        "/api/auth/login",
        content=oversized,
        headers={"Content-Type": "application/json", "Content-Length": str(len(oversized))},
    )

    def chunks() -> object:
        for start in range(0, len(oversized), 4_096):
            yield oversized[start : start + 4_096]

    streamed = client.post(
        "/api/auth/login",
        content=chunks(),
        headers={"Content-Type": "application/json"},
    )
    lying = client.post(
        "/api/auth/login",
        content=oversized,
        headers={"Content-Type": "application/json", "Content-Length": "10"},
    )

    assert declared.status_code == 413
    assert streamed.status_code == 413
    assert lying.status_code == 413


def test_million_character_identifiers_and_overlong_filters_are_rejected(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    app = create_app(
        repository=repository,
        session_secret="session-secret-at-least-32-characters",
        totp_encryption_key=TOTP_KEY,
        machine_token="machine-token-at-least-16",
    )
    client = TestClient(app, base_url="https://testserver")
    observation = {
        "schema_version": "observation.v1",
        "observation_id": str(uuid4()),
        "camera_id": "x" * 1_000_000,
        "stream_epoch": str(UUID("11111111-1111-1111-1111-111111111111")),
        "source_time": NOW.isoformat(),
        "timestamp_quality": "camera_rtcp",
        "monotonic_seq": 1,
        "module": "person",
        "class_name": "person",
        "confidence": 0.9,
        "bbox": [0.1, 0.1, 0.2, 0.2],
        "model_artifact_id": "person-v1",
        "sample_kind": "fresh",
        "runtime_state": "online",
        "received_at": NOW.isoformat(),
    }

    oversized_observation = client.post(
        "/api/internal/observations",
        headers={"Authorization": "Bearer machine-token-at-least-16"},
        json=observation,
    )
    bounded_but_overlong = client.post(
        "/api/internal/observations",
        headers={"Authorization": "Bearer machine-token-at-least-16"},
        json={**observation, "camera_id": "x" * 129},
    )

    assert oversized_observation.status_code == 413
    assert bounded_but_overlong.status_code == 422
