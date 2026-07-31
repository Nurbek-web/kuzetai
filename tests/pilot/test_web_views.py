from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event

import protector.pilot.api.web as web_module
from protector.pilot.api.app import create_app
from protector.pilot.api.auth import PasswordService, SessionUser, TotpService
from protector.pilot.api.web import EvidencePreview
from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.notifications.base import EvidenceLinkSigner
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    Base,
    CameraHealthSampleModel,
    CameraModel,
    DeliveryAttemptModel,
    NotificationOutboxModel,
)
from protector.pilot.storage.repositories import EvidenceInput, PilotRepository

UTC = timezone.utc
NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
SESSION_SECRET = "web-session-signing-key-that-is-at-least-32-characters"
TOTP_KEY = base64.urlsafe_b64encode(b"w" * 32).decode()
MACHINE_TOKEN = "web-machine-token-that-is-private"
SOURCE_SECRET = "rtsp://admin:camera-password@10.0.0.20/live"
OBJECT_KEY_SECRET = "site-1/cam-01/internal-object-key.mp4"
SOURCE_REFERENCE_SECRET = "encoded-ring://private/cam-01"
EVENT_READY = UUID("10000000-0000-0000-0000-000000000001")
EVENT_SHADOW = UUID("10000000-0000-0000-0000-000000000002")
EVENT_REVIEWED = UUID("10000000-0000-0000-0000-000000000003")
EVENT_FOREIGN = UUID("10000000-0000-0000-0000-000000000004")


@dataclass
class StubEvidenceProvider:
    payload: bytes = b"safe-preview-bytes"
    media_type: str = "video/mp4"
    error: Exception | None = None
    calls: list[tuple[str, UUID, str, int]] = field(default_factory=list)

    def get_preview(
        self,
        *,
        site_id: str,
        event_id: UUID,
        actor_id: str,
        max_bytes: int,
    ) -> EvidencePreview | None:
        self.calls.append((site_id, event_id, actor_id, max_bytes))
        assert site_id == "site-1"
        assert actor_id == "viewer-1"
        assert max_bytes == 16 * 1024 * 1024
        if event_id != EVENT_READY:
            return None
        if self.error is not None:
            raise self.error
        return EvidencePreview(content=self.payload, media_type=self.media_type)


@dataclass
class WebContext:
    client: TestClient
    repository: PilotRepository
    app: object

    def authenticate(self, role: str) -> None:
        token, _ = self.app.state.pilot_context.sessions.create(
            SessionUser(user_id=f"{role}-1", username=role, role=role)
        )
        self.client.cookies.set("pilot_session", token)


def _event(
    *,
    event_id: UUID,
    camera_id: str,
    module: str,
    gate_mode: str,
    reason: str,
    evidence_status: str = "pending",
) -> CandidateEventV1:
    return CandidateEventV1(
        schema_version="candidate-event.v1",
        event_id=event_id,
        camera_id=camera_id,
        module=module,
        opened_at=NOW,
        last_seen_at=NOW + timedelta(seconds=2),
        peak_confidence=0.93,
        reason=reason,
        model_artifact_id="person-v1",
        gate_mode=gate_mode,
        evidence_status=evidence_status,
        review_status="candidate",
    )


def _make_context(
    tmp_path: Path,
    *,
    evidence_provider: object | None = None,
    include_events: bool = True,
    pilot_site_id: str | None = "site-1",
    evidence_link_signer: EvidenceLinkSigner | None = None,
    evidence_link_now: Callable[[], datetime] | None = None,
) -> WebContext:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'web.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(
        create_session_factory(engine),
        totp_encryption_key=TOTP_KEY,
    )
    repository.add_site(site_id="site-1", name="Pilot School")
    for index in range(1, 21):
        repository.add_camera(
            camera_id=f"cam-{index:02d}",
            site_id="site-1",
            name=(
                'North <script>alert("camera")</script>'
                if index == 20
                else f"Camera {index:02d}"
            ),
            source_reference=SOURCE_SECRET,
            codec="h264",
            state="starting",
        )
    repository.add_model_artifact(
        ModelArtifactV1(
            schema_version="model-artifact.v1",
            artifact_id="person-v1",
            sha256="a" * 64,
            source="s3://models/private/person.onnx",
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
    passwords = PasswordService()
    totp = TotpService(encryption_key=TOTP_KEY)
    for role in ("viewer", "operator", "admin"):
        secret = totp.enrol(role).secret
        repository.add_user(
            user_id=f"{role}-1",
            username=role,
            password_hash=passwords.hash(f"{role}-password"),
            role=role,
            totp_secret_encrypted=totp.encrypt_secret(secret),
        )

    with repository.session_factory.begin() as session:
        session.add_all(
            (
                CameraHealthSampleModel(
                    camera_id="cam-01",
                    observed_at=NOW - timedelta(minutes=2),
                    state="online",
                    last_frame_at=NOW - timedelta(minutes=2),
                    reconnect_count=1,
                    dropped_samples=2,
                ),
                CameraHealthSampleModel(
                    camera_id="cam-01",
                    observed_at=NOW,
                    state="degraded",
                    last_frame_at=NOW - timedelta(seconds=3),
                    reconnect_count=4,
                    dropped_samples=7,
                    degraded_reason='source timeout"><script>alert("health")</script>',
                ),
                CameraHealthSampleModel(
                    camera_id="cam-03",
                    observed_at=NOW,
                    state="online",
                    last_frame_at=NOW,
                    reconnect_count=0,
                    dropped_samples=0,
                ),
            )
        )

    if include_events:
        repository.add_event(
            _event(
                event_id=EVENT_READY,
                camera_id="cam-01",
                module="person",
                gate_mode="operator",
                reason='zone <img src=x onerror="alert(1)">',
                evidence_status="ready",
            )
        )
        repository.add_event(
            _event(
                event_id=EVENT_SHADOW,
                camera_id="cam-03",
                module="fire_smoke",
                gate_mode="shadow",
                reason="shadow-only fire candidate",
            )
        )
        repository.add_event(
            _event(
                event_id=EVENT_REVIEWED,
                camera_id="cam-03",
                module="person",
                gate_mode="operator",
                reason="reviewed candidate",
            )
        )
        repository.review_event_and_enqueue_notification(
            event_id=EVENT_REVIEWED,
            reviewer_id="operator-1",
            target_status="rejected",
            expected_status="candidate",
            review_idempotency_key="reviewed-event",
            notification_idempotency_key="reviewed-event-notification",
            notes='checked <script>alert("note")</script> & rejected',
            reviewed_at=NOW + timedelta(minutes=1),
        )
        repository.add_evidence(
            EvidenceInput(
                evidence_id=UUID("20000000-0000-0000-0000-000000000001"),
                event_id=EVENT_READY,
                object_key=OBJECT_KEY_SECRET,
                sha256="b" * 64,
                codec="h264",
                start_at=NOW - timedelta(seconds=2),
                end_at=NOW + timedelta(seconds=4),
                source_reference=SOURCE_REFERENCE_SECRET,
                status="ready",
            )
        )

    app = create_app(
        repository=repository,
        session_secret=SESSION_SECRET,
        totp_encryption_key=TOTP_KEY,
        machine_token=MACHINE_TOKEN,
        evidence_preview_provider=evidence_provider,
        pilot_site_id=pilot_site_id,
        evidence_link_signer=evidence_link_signer,
        evidence_link_now=evidence_link_now,
    )
    return WebContext(
        client=TestClient(app, base_url="https://testserver"),
        repository=repository,
        app=app,
    )


def _assert_html_security_headers(response: object) -> None:
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    policy = response.headers["content-security-policy"]
    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "style-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "unsafe-inline" not in policy
    assert "http:" not in policy
    assert "https:" not in policy


def test_login_is_public_but_authenticated_views_redirect_without_reflecting_return_url(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)

    login = context.client.get("/pilot/login")
    dashboard = context.client.get(
        "/pilot?next=https://evil.example/steal",
        follow_redirects=False,
    )
    detail = context.client.get(
        f"/pilot/events/{EVENT_READY}?return_to=//evil.example",
        follow_redirects=False,
    )

    assert login.status_code == 200
    assert '<form id="login-form"' in login.text
    assert 'autocomplete="username"' in login.text
    assert 'autocomplete="current-password"' in login.text
    assert 'inputmode="numeric"' in login.text
    assert 'src="/pilot/static/pilot.js"' in login.text
    assert dashboard.status_code == 303
    assert dashboard.headers["location"] == "/pilot/login"
    assert detail.status_code == 303
    assert detail.headers["location"] == "/pilot/login"
    assert "evil.example" not in dashboard.text + detail.text
    _assert_html_security_headers(login)


def test_dashboard_renders_exactly_twenty_cameras_using_each_latest_health_sample(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)
    context.authenticate("viewer")

    response = context.client.get("/pilot")

    assert response.status_code == 200
    assert response.text.count('data-camera-card="') == 20
    assert 'data-camera-card="cam-01"' in response.text
    assert 'data-health-state="degraded"' in response.text
    assert "source timeout&#34;&gt;&lt;script&gt;alert" in response.text
    assert "Last frame" in response.text
    assert "Reconnects" in response.text
    assert ">4<" in response.text
    assert "Dropped samples" in response.text
    assert ">7<" in response.text
    assert 'data-camera-card="cam-02"' in response.text
    assert "No health sample received" in response.text
    assert "&lt;script&gt;alert(&#34;camera&#34;)&lt;/script&gt;" in response.text
    assert "<script>alert" not in response.text
    assert SOURCE_SECRET not in response.text
    _assert_html_security_headers(response)


def test_dashboard_uses_only_enabled_cameras_from_the_explicit_pilot_site(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)
    context.repository.add_camera(
        camera_id="000-disabled-history",
        site_id="site-1",
        name="Disabled historical camera",
        source_reference=SOURCE_SECRET,
        codec="h264",
        enabled=False,
    )
    context.repository.add_site(site_id="site-2", name="Foreign School")
    context.repository.add_camera(
        camera_id="000-foreign",
        site_id="site-2",
        name="Foreign enabled camera",
        source_reference=SOURCE_SECRET,
        codec="h264",
    )
    context.authenticate("viewer")

    response = context.client.get("/pilot")

    assert response.status_code == 200
    assert response.text.count('data-camera-card="') == 20
    assert 'data-camera-card="cam-01"' in response.text
    assert "000-disabled-history" not in response.text
    assert "Disabled historical camera" not in response.text
    assert "000-foreign" not in response.text
    assert "Foreign enabled camera" not in response.text


@pytest.mark.parametrize("enabled_count", (19, 21))
def test_dashboard_fails_visibly_when_enabled_pilot_camera_count_is_not_twenty(
    tmp_path: Path,
    enabled_count: int,
) -> None:
    context = _make_context(tmp_path)
    if enabled_count == 19:
        with context.repository.session_factory.begin() as database_session:
            camera = database_session.get(CameraModel, "cam-20")
            assert camera is not None
            camera.enabled = False
    else:
        context.repository.add_camera(
            camera_id="cam-21",
            site_id="site-1",
            name="Camera 21",
            source_reference=SOURCE_SECRET,
            codec="h264",
        )
    context.authenticate("viewer")

    response = context.client.get("/pilot")

    assert response.status_code == 503
    assert 'data-error-state role="alert"' in response.text
    error_tag = response.text[
        response.text.rfind("<p", 0, response.text.index("data-error-state"))
        : response.text.index(">", response.text.index("data-error-state")) + 1
    ]
    assert "hidden" not in error_tag
    assert f"{enabled_count} / 20 configured" not in response.text


def test_dashboard_without_explicit_site_fails_closed_when_enabled_sites_are_ambiguous(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path, pilot_site_id=None)
    context.repository.add_site(site_id="site-2", name="Foreign School")
    context.repository.add_camera(
        camera_id="foreign-cam",
        site_id="site-2",
        name="Foreign Camera",
        source_reference=SOURCE_SECRET,
        codec="h264",
    )
    context.authenticate("viewer")

    response = context.client.get("/pilot")

    assert response.status_code == 503
    assert 'data-error-state role="alert"' in response.text
    assert "foreign-cam" not in response.text


def test_foreign_site_event_is_absent_and_detail_and_evidence_fail_closed(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path, evidence_provider=StubEvidenceProvider())
    context.repository.add_site(site_id="site-2", name="Foreign School")
    context.repository.add_camera(
        camera_id="foreign-cam",
        site_id="site-2",
        name="Foreign Camera",
        source_reference="rtsp://foreign-secret@10.0.0.99/live",
        codec="h264",
    )
    context.repository.add_event(
        _event(
            event_id=EVENT_FOREIGN,
            camera_id="foreign-cam",
            module="person",
            gate_mode="operator",
            reason="foreign-site-only reason",
            evidence_status="ready",
        )
    )
    context.repository.add_evidence(
        EvidenceInput(
            evidence_id=UUID("20000000-0000-0000-0000-000000000002"),
            event_id=EVENT_FOREIGN,
            object_key="site-2/foreign-cam/private-evidence.mp4",
            sha256="c" * 64,
            codec="h264",
            start_at=NOW - timedelta(seconds=2),
            end_at=NOW + timedelta(seconds=4),
            source_reference="encoded-ring://private/foreign-cam",
            status="ready",
        )
    )
    context.authenticate("viewer")

    dashboard = context.client.get("/pilot")
    detail = context.client.get(f"/pilot/events/{EVENT_FOREIGN}")
    preview = context.client.get(f"/pilot/evidence/{EVENT_FOREIGN}")

    assert dashboard.status_code == 200
    assert str(EVENT_FOREIGN) not in dashboard.text
    assert "foreign-site-only reason" not in dashboard.text
    assert "Foreign Camera" not in dashboard.text
    assert detail.status_code == 404
    assert "Event not found" in detail.text
    assert "foreign-site-only reason" not in detail.text
    assert preview.status_code == 404
    assert "foreign" not in preview.text.casefold()


@pytest.mark.parametrize("pilot_site_id", ("", "   ", "x" * 129))
def test_create_app_rejects_empty_or_overlong_pilot_site_identity(
    tmp_path: Path,
    pilot_site_id: str,
) -> None:
    with pytest.raises(ValueError, match="pilot site identity"):
        _make_context(tmp_path, pilot_site_id=pilot_site_id)


@pytest.mark.parametrize(
    ("role", "should_review"),
    (("viewer", False), ("operator", True), ("admin", True)),
)
def test_review_controls_are_role_and_gate_dependent(
    tmp_path: Path,
    role: str,
    should_review: bool,
) -> None:
    context = _make_context(tmp_path)
    context.authenticate(role)

    operator_event = context.client.get(f"/pilot/events/{EVENT_READY}")
    shadow_event = context.client.get(f"/pilot/events/{EVENT_SHADOW}")

    assert ('data-review-form="' in operator_event.text) is should_review
    assert ('name="target_status"' in operator_event.text) is should_review
    assert ('value="confirmed"' in operator_event.text) is should_review
    assert ('value="rejected"' in operator_event.text) is should_review
    assert 'data-review-form="' not in shadow_event.text
    assert "Shadow analytics cannot be escalated" in shadow_event.text
    assert "candidate" in operator_event.text.casefold()


def test_dashboard_filters_and_search_are_bounded_server_side_and_escaped(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)
    context.authenticate("operator")

    filtered = context.client.get(
        "/pilot",
        params={
            "q": 'shadow"><script>alert("filter")</script>',
            "module": "fire_smoke",
            "gate_mode": "shadow",
            "review_status": "candidate",
        },
    )
    matching = context.client.get("/pilot", params={"q": "shadow-only", "module": "fire_smoke"})
    oversized = context.client.get("/pilot", params={"q": "x" * 101})

    assert filtered.status_code == 200
    assert "&lt;script&gt;alert" in filtered.text
    assert "<script>alert" not in filtered.text
    assert "No events match the current filters" in filtered.text
    assert matching.status_code == 200
    assert str(EVENT_SHADOW) in matching.text
    assert str(EVENT_READY) not in matching.text
    assert 'data-gate-mode="shadow"' in matching.text
    assert 'data-module="fire_smoke"' in matching.text
    assert oversized.status_code == 422
    assert "x" * 101 not in oversized.text


def test_dashboard_has_explicit_empty_and_loading_states(tmp_path: Path) -> None:
    context = _make_context(tmp_path, include_events=False)
    context.authenticate("viewer")

    response = context.client.get("/pilot")

    assert response.status_code == 200
    assert "No candidate events have been recorded" in response.text
    assert 'data-loading-state' in response.text
    assert "Loading latest status" in response.text
    assert 'type="button" data-refresh' in response.text


def test_dashboard_query_failure_returns_visible_error_state(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    context.authenticate("viewer")
    engine = context.repository.session_factory.kw["bind"]

    def fail_camera_health_query(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context_: object,
        executemany: bool,
    ) -> None:
        del connection, cursor, parameters, context_, executemany
        if "camera_health_samples" in statement and "FROM cameras" in statement:
            raise RuntimeError("forced camera-health query failure")

    sqlalchemy_event.listen(engine, "before_cursor_execute", fail_camera_health_query)
    try:
        response = context.client.get("/pilot")
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", fail_camera_health_query)

    assert response.status_code == 503
    assert "Unable to refresh the console" in response.text
    error_tag = response.text[
        response.text.rfind("<p", 0, response.text.index("data-error-state"))
        : response.text.index(">", response.text.index("data-error-state")) + 1
    ]
    assert "hidden" not in error_tag
    assert 'data-camera-card="' not in response.text


def test_event_detail_renders_candidate_metadata_and_escaped_review_history(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path, evidence_provider=StubEvidenceProvider())
    context.authenticate("viewer")

    candidate = context.client.get(f"/pilot/events/{EVENT_READY}")
    reviewed = context.client.get(f"/pilot/events/{EVENT_REVIEWED}")

    assert candidate.status_code == 200
    assert NOW.isoformat() in candidate.text
    assert "person-v1" in candidate.text
    assert "93%" in candidate.text
    assert 'data-evidence-status="ready"' in candidate.text
    assert f'src="/pilot/evidence/{EVENT_READY}"' in candidate.text
    assert "Human confirmation required" in candidate.text
    assert reviewed.status_code == 200
    assert "operator" in reviewed.text
    assert "rejected" in reviewed.text
    assert "&lt;script&gt;alert(&#34;note&#34;)&lt;/script&gt;" in reviewed.text
    assert "<script>alert" not in reviewed.text
    assert OBJECT_KEY_SECRET not in candidate.text + reviewed.text
    assert SOURCE_REFERENCE_SECRET not in candidate.text + reviewed.text
    _assert_html_security_headers(candidate)


def test_signed_event_detail_query_still_requires_auth_and_is_event_bound_and_expiring(
    tmp_path: Path,
) -> None:
    current_time = [NOW]
    signer = EvidenceLinkSigner(
        secret=b"l" * 32,
        application_origin="https://testserver",
        ttl=timedelta(minutes=5),
    )
    context = _make_context(
        tmp_path,
        evidence_link_signer=signer,
        evidence_link_now=lambda: current_time[0],
    )
    link = signer.issue(EVENT_READY, now=NOW)

    unauthenticated = context.client.get(link, follow_redirects=False)

    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/pilot/login"

    context.authenticate("viewer")
    assert context.client.get(f"/pilot/events/{EVENT_READY}").status_code == 200
    assert context.client.get(link).status_code == 200

    wrong_event = link.replace(str(EVENT_READY), str(EVENT_SHADOW))
    rejected_event = context.client.get(wrong_event)
    assert rejected_event.status_code == 404
    assert str(EVENT_SHADOW) not in rejected_event.text
    assert "shadow-only fire candidate" not in rejected_event.text

    current_time[0] = NOW + timedelta(minutes=5)
    expired = context.client.get(link)
    assert expired.status_code == 404
    assert str(EVENT_READY) not in expired.text
    assert "zone &lt;img" not in expired.text


def test_event_detail_rejects_missing_signer_and_malformed_signed_queries(
    tmp_path: Path,
) -> None:
    signer = EvidenceLinkSigner(
        secret=b"l" * 32,
        application_origin="https://testserver",
        ttl=timedelta(minutes=5),
    )
    link = signer.issue(EVENT_READY, now=NOW)
    path, query = link.split("?", 1)
    expires_field, signature_field = query.split("&")
    malformed_links = (
        f"{path}?{expires_field}",
        f"{path}?{signature_field}",
        f"{link}&extra=1",
        f"{link[:-1]}{'x' if link[-1] != 'x' else 'y'}",
    )
    configured = _make_context(
        tmp_path,
        evidence_link_signer=signer,
        evidence_link_now=lambda: NOW,
    )
    configured.authenticate("viewer")

    for malformed_link in malformed_links:
        response = configured.client.get(malformed_link)
        assert response.status_code == 404
        assert str(EVENT_READY) not in response.text
        assert "zone &lt;img" not in response.text

    missing_signer_path = tmp_path / "missing-signer"
    missing_signer_path.mkdir()
    missing_signer = _make_context(missing_signer_path)
    missing_signer.authenticate("viewer")
    response = missing_signer.client.get(link)
    assert response.status_code == 404
    assert str(EVENT_READY) not in response.text
    assert "zone &lt;img" not in response.text
    assert "EvidenceLinkSigner" not in repr(configured.app.state.pilot_context)
    assert "evidence_link_now" not in repr(configured.app.state.pilot_context)


def test_event_detail_renders_operator_visible_dead_letter_state(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    context.repository.review_event_and_enqueue_notification(
        event_id=EVENT_READY,
        reviewer_id="operator-1",
        target_status="confirmed",
        expected_status="candidate",
        review_idempotency_key="dead-letter-review",
        notification_idempotency_key="dead-letter-notification",
        notes=None,
        reviewed_at=NOW + timedelta(minutes=1),
        expected_site_id="site-1",
    )
    with context.repository.session_factory.begin() as session:
        outbox = session.query(NotificationOutboxModel).filter_by(
            event_id=str(EVENT_READY)
        ).one()
        outbox.status = "dead_letter"
        session.add(
            DeliveryAttemptModel(
                delivery_attempt_id="40000000-0000-0000-0000-000000000001",
                outbox_id=outbox.outbox_id,
                attempt_number=3,
                attempted_at=NOW + timedelta(minutes=2),
                status="failed",
                error="notification delivery failed",
            )
        )
    context.authenticate("viewer")

    response = context.client.get(f"/pilot/events/{EVENT_READY}")

    assert response.status_code == 200
    assert 'data-notification-state="dead_letter"' in response.text
    assert "Notification delivery needs operator attention" in response.text
    assert "3 attempts" in response.text
    assert "notification delivery failed" in response.text


@pytest.mark.parametrize(
    ("event_id", "expected"),
    (
        (EVENT_SHADOW, "Evidence is still being prepared"),
        (EVENT_REVIEWED, "Evidence is still being prepared"),
    ),
)
def test_non_ready_evidence_has_an_honest_non_preview_state(
    tmp_path: Path,
    event_id: UUID,
    expected: str,
) -> None:
    context = _make_context(tmp_path)
    context.authenticate("viewer")

    response = context.client.get(f"/pilot/events/{event_id}")

    assert response.status_code == 200
    assert expected in response.text
    assert f"/pilot/evidence/{event_id}" not in response.text


def test_ready_evidence_fails_closed_without_provider_and_never_discloses_references(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)
    context.authenticate("viewer")

    detail = context.client.get(f"/pilot/events/{EVENT_READY}")
    preview = context.client.get(f"/pilot/evidence/{EVENT_READY}")

    assert "Preview is unavailable on this deployment" in detail.text
    assert preview.status_code == 404
    assert OBJECT_KEY_SECRET not in detail.text + preview.text
    assert SOURCE_REFERENCE_SECRET not in detail.text + preview.text


def test_evidence_preview_is_same_origin_authenticated_bounded_and_no_store(
    tmp_path: Path,
) -> None:
    provider = StubEvidenceProvider()
    context = _make_context(tmp_path, evidence_provider=provider)

    unauthenticated = context.client.get(
        f"/pilot/evidence/{EVENT_READY}",
        follow_redirects=False,
    )
    context.authenticate("viewer")
    response = context.client.get(f"/pilot/evidence/{EVENT_READY}")

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    assert response.content == b"safe-preview-bytes"
    assert response.headers["content-type"] == "video/mp4"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert OBJECT_KEY_SECRET not in str(response.headers) + response.text
    assert SOURCE_REFERENCE_SECRET not in str(response.headers) + response.text
    assert provider.calls == [
        ("site-1", EVENT_READY, "viewer-1", 16 * 1024 * 1024)
    ]


def test_preview_response_capacity_is_aggregate_bounded(
    tmp_path: Path,
) -> None:
    provider = StubEvidenceProvider()
    context = _make_context(tmp_path, evidence_provider=provider)
    context.authenticate("viewer")
    acquired = [
        web_module._PREVIEW_RESPONSE_SLOTS.acquire(blocking=False)
        for _ in range(web_module._MAX_CONCURRENT_PREVIEW_RESPONSES)
    ]
    assert all(acquired)
    try:
        response = context.client.get(
            f"/pilot/evidence/{EVENT_READY}",
        )
    finally:
        for _ in acquired:
            web_module._PREVIEW_RESPONSE_SLOTS.release()

    assert response.status_code == 503
    assert provider.calls == []


def test_preview_response_capacity_releases_on_client_send_failure() -> None:
    released = 0

    def release() -> None:
        nonlocal released
        released += 1

    response = web_module._CapacityBoundResponse(
        content=b"bounded",
        media_type="video/mp4",
        release_capacity=release,
    )

    async def receive() -> dict[str, object]:
        return {"type": "http.disconnect"}

    async def send(_message: dict[str, object]) -> None:
        raise RuntimeError("client disconnected")

    with pytest.raises(RuntimeError, match="client disconnected"):
        asyncio.run(
            response(
                {
                    "type": "http",
                    "http_version": "1.1",
                    "method": "GET",
                    "path": "/pilot/evidence/test",
                    "raw_path": b"/pilot/evidence/test",
                    "root_path": "",
                    "scheme": "https",
                    "query_string": b"",
                    "headers": [],
                    "client": ("127.0.0.1", 12345),
                    "server": ("localhost", 443),
                    "state": {},
                },
                receive,
                send,
            )
        )

    assert released == 1


@pytest.mark.parametrize(
    "provider",
    (
        StubEvidenceProvider(payload=b"x" * (16 * 1024 * 1024 + 1)),
        StubEvidenceProvider(media_type="text/html"),
        pytest.param(
            StubEvidenceProvider(media_type="image/jpeg"),
            id="jpeg-is-not-renderable-by-video-preview",
        ),
        StubEvidenceProvider(error=RuntimeError("s3://private/internal-object")),
    ),
)
def test_evidence_provider_failures_are_generic_and_fail_closed(
    tmp_path: Path,
    provider: StubEvidenceProvider,
) -> None:
    context = _make_context(tmp_path, evidence_provider=provider)
    context.authenticate("viewer")

    response = context.client.get(f"/pilot/evidence/{EVENT_READY}")

    assert response.status_code == 502
    assert "private/internal-object" not in response.text
    assert OBJECT_KEY_SECRET not in response.text


def test_static_assets_are_local_accessible_and_use_safe_progressive_javascript(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)

    script = context.client.get("/pilot/static/pilot.js")
    stylesheet = context.client.get("/pilot/static/pilot.css")

    assert script.status_code == 200
    assert "crypto.randomUUID()" in script.text
    assert "Idempotency-Key" in script.text
    assert "X-CSRF-Token" in script.text
    assert "textContent" in script.text
    assert "innerHTML" not in script.text
    assert "pointerdown" not in script.text
    assert "keydown" not in script.text
    assert "api/events/" in script.text
    assert stylesheet.status_code == 200
    assert "@media (max-width: 720px)" in stylesheet.text
    assert "@media (prefers-reduced-motion: reduce)" in stylesheet.text
    assert "min-height: 44px" in stylesheet.text
    assert ":focus-visible" in stylesheet.text
    assert "@import" not in stylesheet.text
    assert "url(http" not in stylesheet.text
    assert "https://" not in script.text + stylesheet.text
    assert "http://" not in script.text + stylesheet.text
    _assert_html_security_headers(script)
    _assert_html_security_headers(stylesheet)


def test_mobile_page_width_is_bounded_while_only_the_table_scrolls_horizontally(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)
    context.authenticate("viewer")

    stylesheet = context.client.get("/pilot/static/pilot.css").text
    dashboard = context.client.get(
        "/pilot",
        params={"q": "shadow-only", "module": "fire_smoke"},
    ).text
    table_markup = dashboard[dashboard.index("<table") : dashboard.index("</table>")]

    assert ".page-shell {\n  width: calc(100% - 2rem);\n  max-width: 92rem;\n  min-width: 0;" in stylesheet
    assert ".events-section {\n  min-width: 0;\n  max-width: 100%;" in stylesheet
    assert (
        ".table-scroll {\n  width: 100%;\n  max-width: 100%;\n  min-width: 0;\n"
        "  overflow-x: auto;"
    ) in stylesheet
    assert ".filter-panel > * {\n  min-width: 0;\n  max-width: 100%;" in stylesheet
    assert "@media (max-width: 720px)" in stylesheet
    assert "width: calc(100% - 1rem);" in stylesheet
    assert stylesheet.count("overflow-x: auto") == 1
    assert "overflow-x: hidden" not in stylesheet
    assert 'class="visually-hidden"' not in table_markup
    assert '<th scope="col" aria-label="Open event detail"></th>' in table_markup
    assert ".visually-hidden {" not in stylesheet


def test_authenticated_header_offers_csrf_protected_same_origin_logout(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)
    public_login = context.client.get("/pilot/login")
    context.authenticate("viewer")

    dashboard = context.client.get("/pilot")
    script = context.client.get("/pilot/static/pilot.js")

    assert "data-logout" not in public_login.text
    assert '<button class="session-logout" type="button" data-logout>' in dashboard.text
    assert "Sign out" in dashboard.text
    assert 'fetch("/api/auth/logout"' in script.text
    assert '"X-CSRF-Token": csrf' in script.text
    assert 'window.location.assign("/pilot/login")' in script.text


def test_html_has_keyboard_and_mobile_semantics_without_external_assets(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)
    context.authenticate("operator")

    dashboard = context.client.get("/pilot")
    detail = context.client.get(f"/pilot/events/{EVENT_READY}")
    combined = dashboard.text + detail.text

    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in combined
    assert '<main id="main-content"' in combined
    assert 'href="#main-content"' in combined
    assert "<table" in dashboard.text
    assert "<caption" in dashboard.text
    assert 'aria-live="polite"' in combined
    assert '<label for="event-search">' in dashboard.text
    assert 'name="target_status"' in detail.text
    assert 'value="confirmed"' in detail.text
    assert 'value="rejected"' in detail.text
    assert "cdn" not in combined.casefold()
    assert "googleapis" not in combined.casefold()
    assert "analytics" not in combined.casefold()


def test_unknown_event_renders_a_generic_not_found_page_without_internal_data(
    tmp_path: Path,
) -> None:
    context = _make_context(tmp_path)
    context.authenticate("viewer")

    response = context.client.get(
        "/pilot/events/ffffffff-ffff-ffff-ffff-ffffffffffff"
    )

    assert response.status_code == 404
    assert "Event not found" in response.text
    assert SOURCE_SECRET not in response.text
    assert OBJECT_KEY_SECRET not in response.text
    _assert_html_security_headers(response)
