from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from protector.pilot.api.app import create_app
from protector.pilot.api.auth import PasswordService, SessionUser, TotpService
from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    AuditEntryModel,
    Base,
    CameraHealthSampleModel,
    CandidateEventModel,
    DeliveryAttemptModel,
    NotificationOutboxModel,
    ObservationModel,
    ReviewModel,
)
from protector.pilot.storage.repositories import AuditEntryInput, EvidenceInput, PilotRepository

UTC = timezone.utc
NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
MACHINE_TOKEN = "internal-runtime-token"
TOTP_KEY = base64.urlsafe_b64encode(b"e" * 32).decode()


@pytest.fixture
def api_context(tmp_path: Path) -> tuple[TestClient, PilotRepository, str]:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'api.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(
        create_session_factory(engine),
        totp_encryption_key=TOTP_KEY,
    )
    repository.add_site(site_id="site-1", name="Pilot School")
    repository.add_camera(
        camera_id="cam-01",
        site_id="site-1",
        name="North entrance",
        source_reference="rtsp://admin:camera-password@10.0.0.10/live",
        codec="h264",
        state="online",
    )
    repository.add_camera(
        camera_id="cam-02",
        site_id="site-1",
        name="South entrance",
        source_reference="rtsp://admin:other-password@10.0.0.11/live",
        codec="h265",
        state="degraded",
    )
    repository.add_model_artifact(
        ModelArtifactV1(
            schema_version="model-artifact.v1",
            artifact_id="person-v1",
            sha256="a" * 64,
            source="s3://models/secret-object-store-path/person.onnx",
            commercial_rights=CommercialRightsRecordV1(
                schema_version="commercial-rights.v1",
                record_id="rights-1",
                terms_reference="legal://rights/1",
                commercial_use_approved=True,
            ),
            class_list=("person",),
            preprocessing="letterbox 640",
            analytic="person",
        )
    )
    totp_service = TotpService(encryption_key=TOTP_KEY)
    totp_secret = totp_service.enrol("operator").secret
    repository.add_user(
        user_id="operator-1",
        username="operator",
        password_hash=PasswordService().hash("operator-password"),
        role="operator",
        totp_secret_encrypted=totp_service.encrypt_secret(totp_secret),
    )
    app = create_app(
        repository=repository,
        session_secret="session-secret-at-least-32-characters",
        totp_encryption_key=TOTP_KEY,
        machine_token=MACHINE_TOKEN,
        pilot_site_id="site-1",
    )
    client = TestClient(app, base_url="https://testserver")
    login = client.post(
        "/api/auth/login",
        json={
            "username": "operator",
            "password": "operator-password",
            "totp_code": pyotp.TOTP(totp_secret).now(),
        },
    )
    assert login.status_code == 200
    return client, repository, login.json()["csrf_token"]


def _event(
    *,
    event_id: UUID | None = None,
    camera_id: str = "cam-01",
    module: str = "person",
    gate_mode: str = "operator",
    opened_at: datetime = NOW,
    reason: str = "restricted zone intrusion",
) -> CandidateEventV1:
    return CandidateEventV1(
        schema_version="candidate-event.v1",
        event_id=event_id or uuid4(),
        camera_id=camera_id,
        module=module,
        opened_at=opened_at,
        last_seen_at=opened_at + timedelta(seconds=2),
        peak_confidence=0.93,
        reason=reason,
        model_artifact_id="person-v1",
        gate_mode=gate_mode,
        evidence_status="pending",
        review_status="candidate",
    )


def _review(
    client: TestClient,
    event: CandidateEventV1,
    csrf: str,
    *,
    idempotency_key: str,
    target_status: str = "confirmed",
    notes: str | None = "Confirmed from evidence",
) -> object:
    return client.post(
        f"/api/events/{event.event_id}/review",
        headers={
            "X-CSRF-Token": csrf,
            "Idempotency-Key": idempotency_key,
        },
        json={
            "expected_status": "candidate",
            "target_status": target_status,
            "notes": notes,
            "reviewed_at": (NOW + timedelta(minutes=1)).isoformat(),
        },
    )


def test_camera_and_event_lists_are_redacted_filtered_and_deterministically_paginated(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, _ = api_context
    first = _event(event_id=UUID("10000000-0000-0000-0000-000000000001"))
    second = _event(
        event_id=UUID("10000000-0000-0000-0000-000000000002"),
        camera_id="cam-02",
        module="fire_smoke",
    )
    repository.add_event(first)
    repository.add_event(second)

    cameras = client.get("/api/cameras", params={"state": "online", "limit": 10})
    events = client.get("/api/events", params={"module": "person", "limit": 1, "offset": 0})
    second_page = client.get("/api/events", params={"limit": 1, "offset": 1})
    detail = client.get(f"/api/events/{first.event_id}")

    assert cameras.status_code == 200
    assert [camera["camera_id"] for camera in cameras.json()["items"]] == ["cam-01"]
    assert "source_reference" not in cameras.text
    assert "camera-password" not in cameras.text
    assert [event["event_id"] for event in events.json()["items"]] == [str(first.event_id)]
    assert [event["event_id"] for event in second_page.json()["items"]] == [str(second.event_id)]
    assert detail.json()["event_id"] == str(first.event_id)
    assert client.get("/api/events", params={"limit": 101}).status_code == 422
    assert client.get("/api/events", params={"offset": 10001}).status_code == 422
    assert client.get("/api/events", params={"module": "x" * 1_024}).status_code == 422


def test_review_requires_csrf_and_idempotency_and_returns_stable_replay(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, csrf = api_context
    event = _event()
    repository.add_event(event)
    payload = {
        "expected_status": "candidate",
        "target_status": "confirmed",
        "notes": "Confirmed from evidence",
        "reviewed_at": (NOW + timedelta(minutes=1)).isoformat(),
    }

    assert (
        client.post(
            f"/api/events/{event.event_id}/review",
            headers={"Idempotency-Key": "review-1"},
            json=payload,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/events/{event.event_id}/review",
            headers={"X-CSRF-Token": csrf},
            json=payload,
        ).status_code
        == 400
    )

    first = _review(client, event, csrf, idempotency_key="review-1")
    replay = _review(client, event, csrf, idempotency_key="review-1")

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert first.json()["event"]["review_status"] == "confirmed"
    with repository.session_factory() as session:
        assert len(session.scalars(select(AuditEntryModel)).all()) == 1
        assert len(session.scalars(select(NotificationOutboxModel)).all()) == 1


def test_review_reports_idempotency_conflict_and_stale_state(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, csrf = api_context
    event = _event()
    repository.add_event(event)

    assert _review(client, event, csrf, idempotency_key="review-conflict").status_code == 200
    conflict = _review(
        client,
        event,
        csrf,
        idempotency_key="review-conflict",
        notes="different work",
    )
    stale = _review(
        client,
        event,
        csrf,
        idempotency_key="another-review",
        target_status="rejected",
    )

    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "idempotency_conflict"
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "stale_state"


def test_shadow_confirmation_is_audited_but_never_enters_notification_outbox(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, csrf = api_context
    event = _event(gate_mode="shadow")
    repository.add_event(event)

    assert _review(client, event, csrf, idempotency_key="shadow-review").status_code == 200
    with repository.session_factory() as session:
        assert len(session.scalars(select(AuditEntryModel)).all()) == 1
        assert len(session.scalars(select(NotificationOutboxModel)).all()) == 0


def test_audit_list_is_bounded_and_does_not_disclose_secrets(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, csrf = api_context
    event = _event()
    repository.add_event(event)
    assert _review(client, event, csrf, idempotency_key="audit-review").status_code == 200

    response = client.get("/api/audit", params={"entity_type": "candidate_event", "limit": 1})

    assert response.status_code == 200
    assert response.json()["items"][0]["action"] == "event.confirmed"
    assert "camera-password" not in response.text
    assert MACHINE_TOKEN not in response.text
    assert client.get("/api/audit", params={"limit": 101}).status_code == 422


def test_api_site_boundary_blocks_foreign_reads_reviews_and_audit(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, csrf = api_context
    repository.add_site(site_id="site-2", name="Foreign School")
    repository.add_camera(
        camera_id="foreign-cam",
        site_id="site-2",
        name="Foreign Camera",
        source_reference="rtsp://foreign-secret@10.0.0.99/live",
        codec="h264",
    )
    repository.add_camera(
        camera_id="disabled-history",
        site_id="site-1",
        name="Disabled historical camera",
        source_reference="rtsp://historical-secret@10.0.0.30/live",
        codec="h264",
        enabled=False,
    )
    foreign_candidate = _event(
        event_id=UUID("30000000-0000-0000-0000-000000000001"),
        camera_id="foreign-cam",
        reason="foreign candidate must stay private",
    )
    foreign_audited = _event(
        event_id=UUID("30000000-0000-0000-0000-000000000002"),
        camera_id="foreign-cam",
        reason="foreign audited event",
        opened_at=NOW + timedelta(seconds=1),
    )
    same_site_historical = _event(
        event_id=UUID("30000000-0000-0000-0000-000000000003"),
        camera_id="disabled-history",
        reason="same-site historical event",
        opened_at=NOW + timedelta(seconds=2),
    )
    repository.add_event(foreign_candidate)
    repository.add_event(foreign_audited)
    repository.add_event(same_site_historical)
    repository.review_event_and_enqueue_notification(
        event_id=foreign_audited.event_id,
        reviewer_id="operator-1",
        target_status="rejected",
        expected_status="candidate",
        review_idempotency_key="seed-foreign-audit",
        notification_idempotency_key="seed-foreign-notification",
        notes="foreign audit",
        reviewed_at=NOW + timedelta(minutes=1),
    )
    same_camera_audit = repository.append_audit(
        AuditEntryInput(
            actor_user_id="operator-1",
            action="camera.disabled",
            entity_type="camera",
            entity_id="disabled-history",
            payload={"source_reference": "rtsp://historical-secret@10.0.0.30/live"},
            idempotency_key="same-camera-audit",
            occurred_at=NOW + timedelta(minutes=2),
        )
    )
    foreign_camera_audit = repository.append_audit(
        AuditEntryInput(
            actor_user_id="operator-1",
            action="camera.created",
            entity_type="camera",
            entity_id="foreign-cam",
            payload={"source_reference": "rtsp://foreign-secret@10.0.0.99/live"},
            idempotency_key="foreign-camera-audit",
            occurred_at=NOW + timedelta(minutes=2),
        )
    )
    unknown_audit = repository.append_audit(
        AuditEntryInput(
            actor_user_id="operator-1",
            action="unknown.claimed",
            entity_type="unknown",
            entity_id="disabled-history",
            payload={"site_id": "site-1"},
            idempotency_key="unknown-camera-claim",
            occurred_at=NOW + timedelta(minutes=2),
        )
    )

    cameras = client.get("/api/cameras")
    switched_cameras = client.get("/api/cameras", params={"site_id": "site-2"})
    events = client.get("/api/events")
    foreign_filtered = client.get(
        "/api/events",
        params={"camera_id": "foreign-cam"},
    )
    foreign_detail = client.get(f"/api/events/{foreign_candidate.event_id}")
    foreign_review = _review(
        client,
        foreign_candidate,
        csrf,
        idempotency_key="blocked-foreign-review",
    )
    historical_detail = client.get(f"/api/events/{same_site_historical.event_id}")
    historical_review = _review(
        client,
        same_site_historical,
        csrf,
        idempotency_key="same-site-historical-review",
    )
    audit = client.get("/api/audit")
    camera_audit = client.get("/api/audit", params={"entity_type": "camera"})

    assert cameras.status_code == 200
    camera_ids = {row["camera_id"] for row in cameras.json()["items"]}
    assert "foreign-cam" not in camera_ids
    assert "disabled-history" in camera_ids
    assert switched_cameras.status_code == 200
    assert switched_cameras.json()["items"] == []
    assert switched_cameras.json()["total"] == 0
    assert events.status_code == 200
    event_ids = {row["event_id"] for row in events.json()["items"]}
    assert str(foreign_candidate.event_id) not in event_ids
    assert str(foreign_audited.event_id) not in event_ids
    assert str(same_site_historical.event_id) in event_ids
    assert foreign_filtered.json()["items"] == []
    assert foreign_filtered.json()["total"] == 0
    assert foreign_detail.status_code == 404
    assert foreign_detail.json() == {"detail": "event not found"}
    assert foreign_review.status_code == 404
    assert foreign_review.json() == {"detail": "event not found"}
    assert historical_detail.status_code == 200
    assert historical_review.status_code == 200
    assert historical_review.json()["event"]["review_status"] == "confirmed"
    audit_entity_ids = {row["entity_id"] for row in audit.json()["items"]}
    assert str(foreign_audited.event_id) not in audit_entity_ids
    assert str(same_site_historical.event_id) in audit_entity_ids
    audit_ids = {row["audit_id"] for row in audit.json()["items"]}
    assert same_camera_audit.audit_id in audit_ids
    assert foreign_camera_audit.audit_id not in audit_ids
    assert unknown_audit.audit_id not in audit_ids
    assert camera_audit.status_code == 200
    assert [row["audit_id"] for row in camera_audit.json()["items"]] == [
        same_camera_audit.audit_id
    ]
    assert "historical-secret" not in audit.text + camera_audit.text
    assert "foreign-secret" not in audit.text + camera_audit.text

    with repository.session_factory() as session:
        persisted_foreign = session.get(CandidateEventModel, str(foreign_candidate.event_id))
        assert persisted_foreign is not None
        assert persisted_foreign.review_status == "candidate"
        assert (
            session.query(ReviewModel)
            .filter(ReviewModel.event_id == str(foreign_candidate.event_id))
            .count()
            == 0
        )
        assert (
            session.query(AuditEntryModel)
            .filter(AuditEntryModel.entity_id == str(foreign_candidate.event_id))
            .count()
            == 0
        )
        assert (
            session.query(NotificationOutboxModel)
            .filter(NotificationOutboxModel.event_id == str(foreign_candidate.event_id))
            .count()
            == 0
        )


def test_audit_site_attribution_covers_persisted_lifecycle_relations(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, _ = api_context
    repository.add_site(site_id="site-2", name="Foreign Audit School")
    repository.add_camera(
        camera_id="foreign-audit-cam",
        site_id="site-2",
        name="Foreign Audit Camera",
        source_reference="rtsp://foreign-audit-secret@10.0.0.97/live",
        codec="h264",
    )
    same_event = _event(
        event_id=UUID("40000000-0000-0000-0000-000000000001"),
        camera_id="cam-01",
    )
    foreign_event = _event(
        event_id=UUID("40000000-0000-0000-0000-000000000002"),
        camera_id="foreign-audit-cam",
        opened_at=NOW + timedelta(seconds=1),
    )
    repository.add_event(same_event)
    repository.add_event(foreign_event)
    same_review = repository.review_event_and_enqueue_notification(
        event_id=same_event.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        expected_status="candidate",
        review_idempotency_key="same-lifecycle-review",
        notification_idempotency_key="same-lifecycle-notification",
        notes=None,
        reviewed_at=NOW + timedelta(minutes=1),
    )
    foreign_review = repository.review_event_and_enqueue_notification(
        event_id=foreign_event.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        expected_status="candidate",
        review_idempotency_key="foreign-lifecycle-review",
        notification_idempotency_key="foreign-lifecycle-notification",
        notes=None,
        reviewed_at=NOW + timedelta(minutes=1),
    )
    assert same_review.outbox is not None
    assert foreign_review.outbox is not None
    same_evidence = repository.add_evidence(
        EvidenceInput(
            evidence_id=UUID("50000000-0000-0000-0000-000000000001"),
            event_id=same_event.event_id,
            object_key="site-1/cam-01/lifecycle.mp4",
            sha256="d" * 64,
            codec="h264",
            start_at=NOW,
            end_at=NOW + timedelta(seconds=4),
            source_reference="encoded-ring://private/cam-01",
            status="ready",
        )
    )
    foreign_evidence = repository.add_evidence(
        EvidenceInput(
            evidence_id=UUID("50000000-0000-0000-0000-000000000002"),
            event_id=foreign_event.event_id,
            object_key="site-2/foreign-audit-cam/lifecycle.mp4",
            sha256="e" * 64,
            codec="h264",
            start_at=NOW,
            end_at=NOW + timedelta(seconds=4),
            source_reference="encoded-ring://private/foreign-audit-cam",
            status="ready",
        )
    )
    with repository.session_factory.begin() as session:
        same_attempt = DeliveryAttemptModel(
            delivery_attempt_id="60000000-0000-0000-0000-000000000001",
            outbox_id=same_review.outbox.outbox_id,
            attempt_number=1,
            attempted_at=NOW + timedelta(minutes=2),
            status="delivered",
        )
        foreign_attempt = DeliveryAttemptModel(
            delivery_attempt_id="60000000-0000-0000-0000-000000000002",
            outbox_id=foreign_review.outbox.outbox_id,
            attempt_number=1,
            attempted_at=NOW + timedelta(minutes=2),
            status="delivered",
        )
        session.add_all((same_attempt, foreign_attempt))

    entity_pairs = (
        ("site", "site-1", "site-2"),
        ("camera", "cam-01", "foreign-audit-cam"),
        ("candidate_event", str(same_event.event_id), str(foreign_event.event_id)),
        ("evidence", same_evidence.evidence_id, foreign_evidence.evidence_id),
        ("review", same_review.review.review_id, foreign_review.review.review_id),
        (
            "notification_outbox",
            same_review.outbox.outbox_id,
            foreign_review.outbox.outbox_id,
        ),
        (
            "delivery_attempt",
            same_attempt.delivery_attempt_id,
            foreign_attempt.delivery_attempt_id,
        ),
    )
    same_audit_ids: set[str] = set()
    foreign_audit_ids: set[str] = set()
    for entity_type, same_entity_id, foreign_entity_id in entity_pairs:
        same_audit_ids.add(
            repository.append_audit(
                AuditEntryInput(
                    actor_user_id="operator-1",
                    action="scope.test",
                    entity_type=entity_type,
                    entity_id=same_entity_id,
                    payload={},
                    idempotency_key=f"scope-same-{entity_type}",
                    occurred_at=NOW + timedelta(minutes=3),
                )
            ).audit_id
        )
        foreign_audit_ids.add(
            repository.append_audit(
                AuditEntryInput(
                    actor_user_id="operator-1",
                    action="scope.test",
                    entity_type=entity_type,
                    entity_id=foreign_entity_id,
                    payload={},
                    idempotency_key=f"scope-foreign-{entity_type}",
                    occurred_at=NOW + timedelta(minutes=3),
                )
            ).audit_id
        )
    unknown = repository.append_audit(
        AuditEntryInput(
            actor_user_id="operator-1",
            action="scope.test",
            entity_type="unknown",
            entity_id="cam-01",
            payload={"site_id": "site-1"},
            idempotency_key="scope-unknown",
            occurred_at=NOW + timedelta(minutes=3),
        )
    )

    response = client.get("/api/audit", params={"action": "scope.test", "limit": 100})

    assert response.status_code == 200
    returned_ids = {row["audit_id"] for row in response.json()["items"]}
    assert returned_ids == same_audit_ids
    assert not returned_ids.intersection(foreign_audit_ids)
    assert unknown.audit_id not in returned_ids
    assert response.json()["total"] == len(same_audit_ids)


def test_api_site_resolution_fails_missing_and_ambiguous_as_generic_503(
    api_context: tuple[TestClient, PilotRepository, str],
    tmp_path: Path,
) -> None:
    _, repository, _ = api_context

    def authenticated_client(app: object) -> TestClient:
        token, _ = app.state.pilot_context.sessions.create(
            SessionUser(user_id="operator-1", username="operator", role="operator")
        )
        result = TestClient(app, base_url="https://testserver")
        result.cookies.set("pilot_session", token)
        return result

    missing_app = create_app(
        repository=repository,
        session_secret="missing-site-session-secret-at-least-32-characters",
        totp_encryption_key=TOTP_KEY,
        machine_token=MACHINE_TOKEN,
        pilot_site_id="missing-site",
        runtime_lock_path=tmp_path / "missing.lock",
    )
    missing = authenticated_client(missing_app).get("/api/cameras")

    repository.add_site(site_id="site-2", name="Ambiguous School")
    repository.add_camera(
        camera_id="ambiguous-foreign-cam",
        site_id="site-2",
        name="Ambiguous Foreign Camera",
        source_reference="rtsp://foreign-secret@10.0.0.98/live",
        codec="h264",
    )
    ambiguous_app = create_app(
        repository=repository,
        session_secret="ambiguous-site-session-secret-at-least-32-characters",
        totp_encryption_key=TOTP_KEY,
        machine_token=MACHINE_TOKEN,
        runtime_lock_path=tmp_path / "ambiguous.lock",
    )
    ambiguous = authenticated_client(ambiguous_app).get("/api/events")

    assert missing.status_code == 503
    assert missing.json() == {"detail": "pilot site unavailable"}
    assert ambiguous.status_code == 503
    assert ambiguous.json() == {"detail": "pilot site unavailable"}


def test_event_and_audit_payloads_redact_credentials_embedded_in_text(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, csrf = api_context
    event = _event(reason="source rtsp://admin:camera-password@10.0.0.10/live unavailable")
    repository.add_event(event)
    response = _review(
        client,
        event,
        csrf,
        idempotency_key="redacted-review",
        notes="checked access_key=object-store-credential",
    )

    detail = client.get(f"/api/events/{event.event_id}")
    audit = client.get("/api/audit")

    assert response.status_code == 200
    assert "camera-password" not in response.text
    assert "camera-password" not in detail.text
    assert "object-store-credential" not in audit.text


def test_internal_ingestion_uses_machine_auth_and_rejects_cached_display_votes(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, _ = api_context
    observation = {
        "schema_version": "observation.v1",
        "observation_id": "22222222-2222-2222-2222-222222222222",
        "camera_id": "cam-01",
        "stream_epoch": "11111111-1111-1111-1111-111111111111",
        "source_time": NOW.isoformat(),
        "timestamp_quality": "camera_rtcp",
        "monotonic_seq": 1,
        "module": "person",
        "class_name": "person",
        "confidence": 0.91,
        "bbox": [0.1, 0.2, 0.5, 0.8],
        "track_id": "track-1",
        "model_artifact_id": "person-v1",
        "sample_kind": "fresh",
        "runtime_state": "online",
        "received_at": (NOW + timedelta(milliseconds=20)).isoformat(),
    }

    assert client.post("/api/internal/observations", json=observation).status_code == 401
    accepted = client.post(
        "/api/internal/observations",
        headers={"Authorization": f"Bearer {MACHINE_TOKEN}"},
        json=observation,
    )
    cached = client.post(
        "/api/internal/observations",
        headers={"Authorization": f"Bearer {MACHINE_TOKEN}"},
        json={**observation, "observation_id": str(uuid4()), "sample_kind": "cached_display"},
    )

    assert accepted.status_code == 201
    assert cached.status_code == 422
    with repository.session_factory() as session:
        assert len(session.scalars(select(ObservationModel)).all()) == 1


def test_internal_health_ingestion_is_machine_authenticated(
    api_context: tuple[TestClient, PilotRepository, str],
) -> None:
    client, repository, _ = api_context
    health = {
        "camera_id": "cam-01",
        "observed_at": NOW.isoformat(),
        "state": "degraded",
        "last_frame_at": (NOW - timedelta(seconds=2)).isoformat(),
        "reconnect_count": 2,
        "dropped_samples": 4,
        "degraded_reason": "source timeout",
    }

    response = client.post(
        "/api/internal/health",
        headers={"Authorization": f"Bearer {MACHINE_TOKEN}"},
        json=health,
    )

    assert response.status_code == 201
    assert MACHINE_TOKEN not in response.text
    with repository.session_factory() as session:
        samples = list(session.scalars(select(CameraHealthSampleModel)))
        assert len(samples) == 1
        assert samples[0].camera_id == "cam-01"
