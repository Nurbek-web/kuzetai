from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from uuid import UUID

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select

from protector.pilot.domain import CandidateEventV1
from protector.pilot.gates import CommercialRightsRecordV1, ModelArtifactV1
from protector.pilot.notifications.base import (
    ConfirmedEventView,
    EvidenceLinkSigner,
    InvalidSignedLink,
)
from protector.pilot.notifications.telegram import (
    NotificationConfigurationError,
    NotificationDeliveryError,
    TelegramConnector,
)
from protector.pilot.notifications.worker import (
    NotificationWorker,
    NotificationWorkerConfig,
)
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    AuditEntryModel,
    Base,
    CandidateEventModel,
    DeliveryAttemptModel,
    ModelArtifactModel,
    NotificationOutboxModel,
    SiteModel,
)
from protector.pilot.storage.repositories import PilotRepository

UTC = timezone.utc
NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
EVENT_ID = UUID("30000000-0000-0000-0000-000000000001")
SIGNING_SECRET = b"s" * 32
BOT_TOKEN = "telegram-token-must-never-escape"
SOURCE_SECRET = "rtsp://admin:camera-password@10.0.0.20/live"
OBJECT_SECRET = "private/site-1/camera-01/evidence.mp4"


@dataclass
class MutableClock:
    current: datetime = NOW

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


@dataclass
class RecordingConnector:
    response_reference: str = "message-42"
    error: Exception | None = None
    sent: list[tuple[ConfirmedEventView, str]] = field(default_factory=list)

    async def send_confirmed(
        self,
        event_view: ConfirmedEventView,
        idempotency_key: str,
    ) -> str:
        self.sent.append((event_view, idempotency_key))
        if self.error is not None:
            raise self.error
        return self.response_reference


def _artifact() -> ModelArtifactV1:
    return ModelArtifactV1(
        schema_version="model-artifact.v1",
        artifact_id="person-v1",
        sha256="a" * 64,
        source="s3://private-model-registry/person-v1.onnx",
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


def _candidate(
    *,
    event_id: UUID = EVENT_ID,
    camera_id: str = "cam-01",
    gate_mode: str = "operator",
) -> CandidateEventV1:
    return CandidateEventV1(
        schema_version="candidate-event.v1",
        event_id=event_id,
        camera_id=camera_id,
        module="restricted_zone",
        opened_at=NOW,
        last_seen_at=NOW + timedelta(seconds=2),
        peak_confidence=0.93,
        reason=f"must not notify: {SOURCE_SECRET} {OBJECT_SECRET}",
        model_artifact_id="person-v1",
        gate_mode=gate_mode,
        evidence_status="ready",
        review_status="candidate",
    )


def _repository(tmp_path: Path, *, name: str = "notifications") -> PilotRepository:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / f'{name}.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name="Pilot School")
    repository.add_camera(
        camera_id="cam-01",
        site_id="site-1",
        name="North entrance",
        source_reference=SOURCE_SECRET,
        codec="h264",
    )
    repository.add_model_artifact(_artifact())
    repository.add_user(
        user_id="operator-1",
        username="Aruzhan Operator",
        password_hash="argon2id-placeholder",
        role="operator",
    )
    return repository


def _confirm(
    repository: PilotRepository,
    *,
    event: CandidateEventV1 | None = None,
    review_key: str = "review-1",
    notification_key: str = "notify-1",
    expected_site_id: str = "site-1",
) -> UUID:
    candidate = event or _candidate()
    repository.add_event(candidate)
    result = repository.review_event_and_enqueue_notification(
        event_id=candidate.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        expected_status="candidate",
        review_idempotency_key=review_key,
        notification_idempotency_key=notification_key,
        notes=f"must stay private: {OBJECT_SECRET}",
        reviewed_at=NOW + timedelta(seconds=3),
        expected_site_id=expected_site_id,
    )
    assert result.outbox is not None
    with repository.session_factory.begin() as session:
        outbox = session.get(NotificationOutboxModel, result.outbox.outbox_id)
        assert outbox is not None
        outbox.available_at = NOW
    return candidate.event_id


def _signer() -> EvidenceLinkSigner:
    return EvidenceLinkSigner(
        secret=SIGNING_SECRET,
        application_origin="https://pilot.example.kz",
        ttl=timedelta(minutes=5),
    )


def _view(
    link: str = (
        "https://pilot.example.kz/pilot/events/"
        "30000000-0000-0000-0000-000000000001?expires=1&signature=x"
    ),
) -> ConfirmedEventView:
    return ConfirmedEventView(
        site_id="site-1",
        site_name="Pilot School",
        camera_id="cam-01",
        camera_name="North <entrance>",
        source_time=NOW,
        category="restricted_zone",
        confirming_operator="Aruzhan Operator",
        event_id=EVENT_ID,
        evidence_link=link,
    )


def test_signed_application_link_is_event_bound_expiring_and_origin_safe() -> None:
    signer = _signer()
    link = signer.issue(EVENT_ID, now=NOW)

    assert signer.verify(link, event_id=EVENT_ID, now=NOW + timedelta(minutes=4))
    assert not signer.verify(link, event_id=EVENT_ID, now=NOW + timedelta(minutes=5))
    assert urlsplit(link).path == f"/pilot/events/{EVENT_ID}"
    assert not signer.verify(
        link,
        event_id=UUID("30000000-0000-0000-0000-000000000002"),
        now=NOW,
    )
    assert not signer.verify(link, event_id=EVENT_ID, now=NOW + timedelta(minutes=6))

    parsed = urlsplit(link)
    query = parse_qs(parsed.query)
    changed_expiry = urlunsplit(
        parsed._replace(
            query=urlencode(
                {
                    "expires": str(int(query["expires"][0]) + 1),
                    "signature": query["signature"][0],
                }
            )
        )
    )
    changed_signature = urlunsplit(
        parsed._replace(
            query=urlencode(
                {
                    "expires": query["expires"][0],
                    "signature": f"x{query['signature'][0][1:]}",
                }
            )
        )
    )
    assert not signer.verify(changed_expiry, event_id=EVENT_ID, now=NOW)
    assert not signer.verify(changed_signature, event_id=EVENT_ID, now=NOW)

    with pytest.raises(ValueError, match="HTTPS"):
        EvidenceLinkSigner(
            secret=SIGNING_SECRET,
            application_origin="http://pilot.example.kz",
            ttl=timedelta(minutes=5),
        )
    with pytest.raises(ValueError, match="credentials"):
        EvidenceLinkSigner(
            secret=SIGNING_SECRET,
            application_origin="https://admin:password@pilot.example.kz",
            ttl=timedelta(minutes=5),
        )
    with pytest.raises(ValueError, match="32 bytes"):
        EvidenceLinkSigner(
            secret=b"too-short",
            application_origin="https://pilot.example.kz",
            ttl=timedelta(minutes=5),
        )
    with pytest.raises(ValueError, match="at least one second"):
        EvidenceLinkSigner(
            secret=SIGNING_SECRET,
            application_origin="https://pilot.example.kz",
            ttl=timedelta(microseconds=1),
        )
    with pytest.raises(InvalidSignedLink):
        signer.require_valid(
            "https://evil.example/pilot/events/300?expires=1&signature=x",
            event_id=EVENT_ID,
            now=NOW,
        )


@pytest.mark.parametrize(
    "application_origin",
    (
        "https://pilot.example.kz:bad",
        "https://pilot.example.kz:0",
        "https://pilot.example.kz:65536",
        "https://pilot%2eexample.kz",
        "https://pilot.example.kz%3A8443",
        "https://pilot.example.kz\\@evil.example",
        " https://pilot.example.kz",
        "https://pilot.example.kz\t",
        "https://pilot.example.kz/\n",
        "https://Pilot.Example.kz",
        "https://pilot.example.kz:443",
        "https://pilot.example.kz:08443",
        "https://pilot.example.kz.",
        "https://pilot_example.kz",
    ),
)
def test_signed_link_origin_rejects_malformed_or_noncanonical_authority(
    application_origin: str,
) -> None:
    with pytest.raises(ValueError, match="application origin"):
        EvidenceLinkSigner(
            secret=SIGNING_SECRET,
            application_origin=application_origin,
            ttl=timedelta(minutes=5),
        )


def test_signed_link_origin_accepts_canonical_hostname_with_optional_valid_port() -> None:
    signer = EvidenceLinkSigner(
        secret=SIGNING_SECRET,
        application_origin="https://pilot.example.kz:8443",
        ttl=timedelta(minutes=5),
    )

    assert signer.issue(EVENT_ID, now=NOW).startswith(
        f"https://pilot.example.kz:8443/pilot/events/{EVENT_ID}?"
    )


def test_signed_link_origin_does_not_expose_url_parser_errors() -> None:
    with pytest.raises(ValueError) as captured:
        EvidenceLinkSigner(
            secret=SIGNING_SECRET,
            application_origin="https://pilot.example.kz:not-a-port",
            ttl=timedelta(minutes=5),
        )

    assert str(captured.value) == "application origin must be a bare canonical HTTPS origin"
    assert captured.value.__cause__ is None


def test_event_view_rejects_control_and_path_injection_and_hides_signed_link() -> None:
    link = _signer().issue(EVENT_ID, now=NOW)
    view = _view(link)

    assert link not in repr(view)
    with pytest.raises(ValueError):
        replace(view, camera_name="North entrance\nForged field")
    with pytest.raises(ValueError):
        replace(
            view,
            evidence_link=(
                "https://pilot.example.kz/pilot/events/"
                "30000000-0000-0000-0000-000000000002?expires=1&signature=x"
            ),
        )


@pytest.mark.parametrize(
    ("customer_approved", "network_approved"),
    ((False, False), (True, False), (False, True)),
)
def test_telegram_requires_both_explicit_approvals_before_network_io(
    customer_approved: bool,
    network_approved: bool,
) -> None:
    requests = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(NotificationConfigurationError, match="disabled"):
                TelegramConnector(
                    customer_approved=customer_approved,
                    outbound_network_approved=network_approved,
                    bot_token=BOT_TOKEN,
                    chat_id="-100123",
                    client=client,
                )

    asyncio.run(exercise())
    assert requests == 0


def test_approved_telegram_sends_bounded_plain_text_and_returns_only_message_id() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "ok": True,
                "result": {
                    "message_id": 42,
                    "chat": {"id": "-100123"},
                    "provider_secret": "must-not-return",
                },
            },
        )

    async def exercise() -> tuple[str, str]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            connector = TelegramConnector(
                customer_approved=True,
                outbound_network_approved=True,
                bot_token=BOT_TOKEN,
                chat_id="-100123",
                client=client,
            )
            reference = await connector.send_confirmed(_view(), "stable-notification-key")
            return reference, repr(connector)

    reference, connector_repr = asyncio.run(exercise())

    assert reference == "42"
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "POST"
    assert request.url.scheme == "https"
    assert request.url.host == "api.telegram.org"
    payload = __import__("json").loads(request.content)
    assert payload["chat_id"] == "-100123"
    assert "parse_mode" not in payload
    assert len(payload["text"]) <= 3500
    assert "Pilot School" in payload["text"]
    assert "North <entrance>" in payload["text"]
    assert NOW.isoformat() in payload["text"]
    assert "restricted_zone" in payload["text"]
    assert "Aruzhan Operator" in payload["text"]
    assert str(EVENT_ID) in payload["text"]
    assert "Human confirmation" in payload["text"]
    assert "rtsp://" not in payload["text"]
    assert OBJECT_SECRET not in payload["text"]
    assert "provider_secret" not in reference
    assert BOT_TOKEN not in connector_repr


@pytest.mark.parametrize(
    "response",
    (
        httpx.Response(500, text=f"provider failed with {BOT_TOKEN}"),
        httpx.Response(200, text="not-json"),
        httpx.Response(200, json={"ok": False, "description": f"bad {BOT_TOKEN}"}),
        httpx.Response(200, json={"ok": True, "result": {}}),
    ),
)
def test_telegram_provider_failures_are_generic_and_secret_free(response: httpx.Response) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return response

    async def exercise() -> str:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            connector = TelegramConnector(
                customer_approved=True,
                outbound_network_approved=True,
                bot_token=BOT_TOKEN,
                chat_id="-100123",
                client=client,
            )
            with pytest.raises(NotificationDeliveryError) as captured:
                await connector.send_confirmed(_view(), "stable-notification-key")
            return repr(captured.value)

    rendered_error = asyncio.run(exercise())
    assert rendered_error == "NotificationDeliveryError('notification delivery failed')"
    assert BOT_TOKEN not in rendered_error


def test_telegram_transport_exception_does_not_retain_token_bearing_exception() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(f"timeout at {request.url}", request=request)

    async def exercise() -> NotificationDeliveryError:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            connector = TelegramConnector(
                customer_approved=True,
                outbound_network_approved=True,
                bot_token=BOT_TOKEN,
                chat_id="-100123",
                client=client,
            )
            with pytest.raises(NotificationDeliveryError) as captured:
                await connector.send_confirmed(_view(), "stable-notification-key")
            return captured.value

    error = asyncio.run(exercise())
    assert error.__cause__ is None
    assert error.__context__ is None
    assert BOT_TOKEN not in repr(error)


@pytest.mark.parametrize("bot_token", ("bad/token", "bad?token", "bad#token", "bad\ntoken"))
def test_telegram_rejects_path_and_control_injection_before_network(bot_token: str) -> None:
    requests = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(NotificationConfigurationError):
                TelegramConnector(
                    customer_approved=True,
                    outbound_network_approved=True,
                    bot_token=bot_token,
                    chat_id="-100123",
                    client=client,
                )

    asyncio.run(exercise())
    assert requests == 0


def test_only_confirmed_operator_review_creates_one_outbox_on_replay(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    candidate = _candidate()
    repository.add_event(candidate)

    first = repository.review_event_and_enqueue_notification(
        event_id=candidate.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        expected_status="candidate",
        review_idempotency_key="review-1",
        notification_idempotency_key="notify-1",
        notes=None,
        reviewed_at=NOW,
        expected_site_id="site-1",
    )
    replay = repository.review_event_and_enqueue_notification(
        event_id=candidate.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        expected_status="candidate",
        review_idempotency_key="review-1",
        notification_idempotency_key="notify-1",
        notes=None,
        reviewed_at=NOW,
        expected_site_id="site-1",
    )

    assert first.outbox is not None
    assert replay.outbox is not None
    assert first.outbox.outbox_id == replay.outbox.outbox_id
    with repository.session_factory() as session:
        assert len(list(session.scalars(select(NotificationOutboxModel)))) == 1

    shadow = _candidate(
        event_id=UUID("30000000-0000-0000-0000-000000000002"),
        gate_mode="shadow",
    )
    repository.add_event(shadow)
    shadow_result = repository.review_event_and_enqueue_notification(
        event_id=shadow.event_id,
        reviewer_id="operator-1",
        target_status="confirmed",
        expected_status="candidate",
        review_idempotency_key="review-shadow",
        notification_idempotency_key="notify-shadow",
        notes=None,
        reviewed_at=NOW,
        expected_site_id="site-1",
    )
    assert shadow_result.outbox is None

    for index, target in enumerate(("rejected", "expired"), start=3):
        event = _candidate(
            event_id=UUID(f"30000000-0000-0000-0000-{index:012d}"),
        )
        repository.add_event(event)
        result = repository.review_event_and_enqueue_notification(
            event_id=event.event_id,
            reviewer_id="operator-1",
            target_status=target,
            expected_status="candidate",
            review_idempotency_key=f"review-{target}",
            notification_idempotency_key=f"notify-{target}",
            notes=None,
            reviewed_at=NOW,
            expected_site_id="site-1",
        )
        assert result.outbox is None


def test_successful_worker_delivery_uses_authoritative_safe_view_and_audits(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    _confirm(repository)
    with repository.session_factory.begin() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        outbox.payload = {
            "reason": SOURCE_SECRET,
            "object_key": OBJECT_SECRET,
            "presigned_url": "https://object-store.example/private?secret=yes",
        }

    connector = RecordingConnector()
    worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(),
        now=MutableClock(),
        pilot_site_id="site-1",
    )

    assert asyncio.run(worker.run_once()) == 1
    assert len(connector.sent) == 1
    view, idempotency_key = connector.sent[0]
    assert idempotency_key == "notify-1"
    assert view.site_id == "site-1"
    assert view.site_name == "Pilot School"
    assert view.camera_id == "cam-01"
    assert view.camera_name == "North entrance"
    assert view.source_time == NOW
    assert view.category == "restricted_zone"
    assert view.confirming_operator == "Aruzhan Operator"
    assert view.event_id == EVENT_ID
    assert _signer().verify(view.evidence_link, event_id=EVENT_ID, now=NOW)
    assert SOURCE_SECRET not in repr(view)
    assert OBJECT_SECRET not in repr(view)

    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        attempt = session.scalar(select(DeliveryAttemptModel))
        audits = list(
            session.scalars(
                select(AuditEntryModel).order_by(
                    AuditEntryModel.occurred_at,
                    AuditEntryModel.audit_id,
                )
            )
        )
        assert outbox is not None
        assert outbox.status == "delivered"
        assert outbox.lease_token is None
        assert outbox.lease_expires_at is None
        assert attempt is not None
        assert attempt.attempt_number == 1
        assert attempt.status == "delivered"
        assert attempt.response_reference == "message-42"
        assert attempt.error is None
        assert [entry.action for entry in audits][-2:] == [
            "notification.delivery_started",
            "notification.delivered",
        ]
        review_audit = next(entry for entry in audits if entry.action == "event.confirmed")
        assert review_audit.payload == {
            "from_status": "candidate",
            "to_status": "confirmed",
            "notes_present": True,
            "notes_sha256": "93da9d972c245469cfea1d27050277b07374a73409c58f635e312e28be151160",
        }
        assert all(
            SOURCE_SECRET not in repr(entry.payload) and OBJECT_SECRET not in repr(entry.payload)
            for entry in audits
        )


def test_concurrent_workers_claim_once_and_expired_lease_recovers(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    _confirm(repository)
    release = asyncio.Event()
    started = asyncio.Event()

    @dataclass
    class BlockingConnector:
        calls: int = 0

        async def send_confirmed(
            self,
            event_view: ConfirmedEventView,
            idempotency_key: str,
        ) -> str:
            del event_view, idempotency_key
            self.calls += 1
            started.set()
            await release.wait()
            return "message-1"

    connector = BlockingConnector()
    clock = MutableClock()
    first = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(lease_seconds=5),
        now=clock,
        pilot_site_id="site-1",
    )
    second = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(lease_seconds=5),
        now=clock,
        pilot_site_id="site-1",
    )

    async def compete() -> tuple[int, int]:
        first_run = asyncio.create_task(first.run_once())
        await asyncio.wait_for(started.wait(), timeout=2)
        second_result = await second.run_once()
        release.set()
        return await first_run, second_result

    assert asyncio.run(compete()) == (1, 0)
    assert connector.calls == 1

    recovery_repository = _repository(tmp_path, name="lease-recovery")
    _confirm(recovery_repository)
    crashing = RecordingConnector(error=KeyboardInterrupt())
    recovery_clock = MutableClock()
    crashed_worker = NotificationWorker(
        session_factory=recovery_repository.session_factory,
        connector=crashing,
        link_signer=_signer(),
        config=NotificationWorkerConfig(lease_seconds=5),
        now=recovery_clock,
        pilot_site_id="site-1",
    )
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(crashed_worker.run_once())

    recovery_clock.advance(6)
    recovered = RecordingConnector(response_reference="message-recovered")
    recovery_worker = NotificationWorker(
        session_factory=recovery_repository.session_factory,
        connector=recovered,
        link_signer=_signer(),
        config=NotificationWorkerConfig(lease_seconds=5),
        now=recovery_clock,
        pilot_site_id="site-1",
    )
    assert asyncio.run(recovery_worker.run_once()) == 1
    with recovery_repository.session_factory() as session:
        attempts = list(
            session.scalars(
                select(DeliveryAttemptModel).order_by(DeliveryAttemptModel.attempt_number)
            )
        )
        assert [(row.attempt_number, row.status) for row in attempts] == [
            (1, "failed"),
            (2, "delivered"),
        ]
        assert attempts[0].error == "delivery lease expired"


@pytest.mark.parametrize("late_result", ["success", "failure"])
def test_callback_after_lease_expiry_cannot_finalize_before_recovery(
    tmp_path: Path,
    late_result: str,
) -> None:
    repository = _repository(tmp_path, name=f"late-{late_result}")
    _confirm(repository)
    clock = MutableClock()

    @dataclass
    class LateConnector:
        calls: int = 0

        async def send_confirmed(
            self,
            event_view: ConfirmedEventView,
            idempotency_key: str,
        ) -> str:
            del event_view, idempotency_key
            self.calls += 1
            clock.advance(6)
            if late_result == "failure":
                raise RuntimeError("late provider failure")
            return "message-after-expiry"

    late_connector = LateConnector()
    stale_worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=late_connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(batch_size=1, lease_seconds=5),
        now=clock,
        pilot_site_id="site-1",
    )

    assert asyncio.run(stale_worker.run_once()) == 1
    assert late_connector.calls == 1
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        attempts = list(session.scalars(select(DeliveryAttemptModel)))
        assert outbox is not None
        assert outbox.status == "delivering"
        assert outbox.lease_token is not None
        assert outbox.lease_expires_at is not None
        assert len(attempts) == 1
        assert attempts[0].status == "sending"
        assert attempts[0].response_reference is None
        assert attempts[0].error is None

    recovery_connector = RecordingConnector(response_reference="message-recovered")
    recovery_worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=recovery_connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(batch_size=1, lease_seconds=5),
        now=clock,
        pilot_site_id="site-1",
    )

    assert asyncio.run(recovery_worker.run_once()) == 1
    assert len(recovery_connector.sent) == 1
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        attempts = list(
            session.scalars(
                select(DeliveryAttemptModel).order_by(DeliveryAttemptModel.attempt_number)
            )
        )
        assert outbox is not None
        assert outbox.status == "delivered"
        assert [(attempt.attempt_number, attempt.status) for attempt in attempts] == [
            (1, "failed"),
            (2, "delivered"),
        ]
        assert attempts[0].error == "delivery lease expired"
        assert attempts[1].response_reference == "message-recovered"


def test_retry_backoff_is_capped_and_terminal_failure_is_sanitised(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    _confirm(repository)
    clock = MutableClock()
    connector = RecordingConnector(
        error=RuntimeError(
            f"timeout {BOT_TOKEN} {SOURCE_SECRET} https://provider/private?token=secret"
        )
    )
    worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(
            max_attempts=3,
            initial_backoff_seconds=5,
            max_backoff_seconds=8,
        ),
        now=clock,
        pilot_site_id="site-1",
    )

    assert asyncio.run(worker.run_once()) == 1
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        assert outbox.status == "pending"
        assert outbox.available_at.replace(tzinfo=UTC) == NOW + timedelta(seconds=5)

    clock.advance(4)
    assert asyncio.run(worker.run_once()) == 0
    clock.advance(1)
    assert asyncio.run(worker.run_once()) == 1
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        assert outbox.status == "pending"
        assert outbox.available_at.replace(tzinfo=UTC) == NOW + timedelta(seconds=13)

    clock.advance(8)
    assert asyncio.run(worker.run_once()) == 1
    assert asyncio.run(worker.run_once()) == 0

    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        attempts = list(
            session.scalars(
                select(DeliveryAttemptModel).order_by(DeliveryAttemptModel.attempt_number)
            )
        )
        audits = list(session.scalars(select(AuditEntryModel)))
        assert outbox is not None
        assert outbox.status == "dead_letter"
        assert outbox.lease_token is None
        assert outbox.lease_expires_at is None
        assert [attempt.attempt_number for attempt in attempts] == [1, 2, 3]
        assert all(attempt.status == "failed" for attempt in attempts)
        assert all(attempt.error == "notification delivery failed" for attempt in attempts)
        persisted = repr(attempts) + repr([(entry.action, entry.payload) for entry in audits])
        assert BOT_TOKEN not in persisted
        assert SOURCE_SECRET not in persisted
        assert "provider/private" not in persisted
        assert "notification.dead_letter" in [entry.action for entry in audits]


def test_worker_revalidates_event_before_claim_and_finalisation(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _confirm(repository)
    repository.review_event(
        event_id=EVENT_ID,
        reviewer_id="operator-1",
        target_status="escalated",
        idempotency_key="review-escalated",
        notes=None,
        reviewed_at=NOW + timedelta(seconds=4),
    )
    connector = RecordingConnector()
    worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(),
        now=MutableClock(),
        pilot_site_id="site-1",
    )

    assert asyncio.run(worker.run_once()) == 0
    assert connector.sent == []
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        assert outbox.status == "dead_letter"
        assert list(session.scalars(select(DeliveryAttemptModel))) == []

    final_repository = _repository(tmp_path, name="final-revalidation")
    _confirm(final_repository)

    @dataclass
    class MutatingConnector:
        async def send_confirmed(
            self,
            event_view: ConfirmedEventView,
            idempotency_key: str,
        ) -> str:
            del event_view, idempotency_key
            final_repository.review_event(
                event_id=EVENT_ID,
                reviewer_id="operator-1",
                target_status="escalated",
                idempotency_key="review-escalated-during-send",
                notes=None,
                reviewed_at=NOW + timedelta(seconds=4),
            )
            return "message-possibly-sent"

    final_worker = NotificationWorker(
        session_factory=final_repository.session_factory,
        connector=MutatingConnector(),
        link_signer=_signer(),
        config=NotificationWorkerConfig(),
        now=MutableClock(),
        pilot_site_id="site-1",
    )
    assert asyncio.run(final_worker.run_once()) == 1
    with final_repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        attempt = session.scalar(select(DeliveryAttemptModel))
        failed_audits = list(
            session.scalars(
                select(AuditEntryModel).where(
                    AuditEntryModel.action == "notification.delivery_failed"
                )
            )
        )
        assert outbox is not None
        assert outbox.status == "dead_letter"
        assert attempt is not None
        assert attempt.status == "failed"
        assert attempt.response_reference is None
        assert len(failed_audits) == 1
        assert failed_audits[0].entity_type == "delivery_attempt"
        assert failed_audits[0].entity_id == attempt.delivery_attempt_id
        assert failed_audits[0].payload == {
            "attempt_number": 1,
            "error": "notification delivery failed",
        }


@pytest.mark.parametrize(
    ("gate_mode", "review_status", "transition_history"),
    (
        ("disabled", "confirmed", "observation>candidate>confirmed"),
        ("shadow", "confirmed", "observation>candidate>confirmed"),
        ("operator", "observation", "observation"),
        ("operator", "candidate", "observation>candidate"),
        ("operator", "rejected", "observation>candidate>rejected"),
        ("operator", "expired", "observation>candidate>expired"),
    ),
)
def test_worker_never_claims_corrupt_ineligible_outbox(
    tmp_path: Path,
    gate_mode: str,
    review_status: str,
    transition_history: str,
) -> None:
    repository = _repository(
        tmp_path,
        name=f"ineligible-{gate_mode}-{review_status}",
    )
    _confirm(repository)
    with repository.session_factory.begin() as session:
        event = session.get(CandidateEventModel, str(EVENT_ID))
        assert event is not None
        event.gate_mode = gate_mode
        event.review_status = review_status
        event.transition_history = transition_history
    connector = RecordingConnector()
    worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(),
        now=MutableClock(),
        pilot_site_id="site-1",
    )

    assert asyncio.run(worker.run_once()) == 0
    assert connector.sent == []
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        assert outbox.status == "dead_letter"
        assert list(session.scalars(select(DeliveryAttemptModel))) == []


@pytest.mark.parametrize(
    ("artifact_analytic", "event_module"),
    (
        ("fight", "fight"),
        ("fall", "fall"),
        ("violence", "violence"),
        ("xclip", "xclip"),
        ("vit", "vit"),
        ("unknown-analytic", "unknown-analytic"),
        ("person", "fight"),
    ),
)
def test_confirmed_operator_flagged_excluded_or_mismatched_analytic_never_reaches_connector(
    tmp_path: Path,
    artifact_analytic: str,
    event_module: str,
) -> None:
    repository = _repository(
        tmp_path,
        name=f"excluded-{artifact_analytic}-{event_module}",
    )
    _confirm(repository)
    with repository.session_factory.begin() as session:
        event = session.get(CandidateEventModel, str(EVENT_ID))
        artifact = session.get(ModelArtifactModel, "person-v1")
        assert event is not None
        assert artifact is not None
        event.module = event_module
        artifact.analytic = artifact_analytic
    connector = RecordingConnector()
    worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(),
        now=MutableClock(),
        pilot_site_id="site-1",
    )

    assert asyncio.run(worker.run_once()) == 0
    assert connector.sent == []
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        assert outbox.status == "dead_letter"
        assert list(session.scalars(select(DeliveryAttemptModel))) == []


def test_worker_revalidates_persisted_analytic_policy_before_finalisation(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path, name="analytic-finalisation")
    _confirm(repository)

    @dataclass
    class MutatingAnalyticConnector:
        async def send_confirmed(
            self,
            event_view: ConfirmedEventView,
            idempotency_key: str,
        ) -> str:
            del event_view, idempotency_key
            with repository.session_factory.begin() as session:
                artifact = session.get(ModelArtifactModel, "person-v1")
                assert artifact is not None
                artifact.analytic = "fight"
            return "message-possibly-sent"

    worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=MutatingAnalyticConnector(),
        link_signer=_signer(),
        config=NotificationWorkerConfig(),
        now=MutableClock(),
        pilot_site_id="site-1",
    )

    assert asyncio.run(worker.run_once()) == 1
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        attempt = session.scalar(select(DeliveryAttemptModel))
        assert outbox is not None
        assert outbox.status == "dead_letter"
        assert attempt is not None
        assert attempt.status == "failed"
        assert attempt.response_reference is None


def test_worker_claims_only_its_authoritative_pilot_site(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    repository.add_site(site_id="site-2", name="Foreign School")
    repository.add_camera(
        camera_id="foreign-cam",
        site_id="site-2",
        name="Foreign entrance",
        source_reference="rtsp://foreign:secret@10.0.0.99/live",
        codec="h264",
    )
    foreign_event = _candidate(
        event_id=UUID("30000000-0000-0000-0000-000000000099"),
        camera_id="foreign-cam",
    )
    _confirm(
        repository,
        event=foreign_event,
        review_key="foreign-review",
        notification_key="foreign-notification",
        expected_site_id="site-2",
    )
    connector = RecordingConnector()
    worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(),
        now=MutableClock(),
        pilot_site_id="site-1",
    )

    assert asyncio.run(worker.run_once()) == 0
    assert connector.sent == []
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        assert outbox.status == "pending"
        assert list(session.scalars(select(DeliveryAttemptModel))) == []


def test_worker_respects_future_availability_and_dead_letters_invalid_safe_view(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    _confirm(repository)
    with repository.session_factory.begin() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        outbox.available_at = NOW + timedelta(minutes=1)
    connector = RecordingConnector()
    worker = NotificationWorker(
        session_factory=repository.session_factory,
        connector=connector,
        link_signer=_signer(),
        config=NotificationWorkerConfig(),
        now=MutableClock(),
        pilot_site_id="site-1",
    )

    assert asyncio.run(worker.run_once()) == 0
    assert connector.sent == []

    with repository.session_factory.begin() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        site = session.get(SiteModel, "site-1")
        assert outbox is not None
        assert site is not None
        outbox.available_at = NOW
        site.name = "Pilot School\nForged notification field"

    assert asyncio.run(worker.run_once()) == 0
    assert connector.sent == []
    with repository.session_factory() as session:
        outbox = session.scalar(select(NotificationOutboxModel))
        assert outbox is not None
        assert outbox.status == "dead_letter"
        assert list(session.scalars(select(DeliveryAttemptModel))) == []


@pytest.mark.parametrize(
    "kwargs",
    (
        {"batch_size": 0},
        {"max_attempts": 0},
        {"lease_seconds": 0},
        {"initial_backoff_seconds": 0},
        {"initial_backoff_seconds": 10, "max_backoff_seconds": 5},
    ),
)
def test_worker_configuration_is_positive_and_bounded(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        NotificationWorkerConfig(**kwargs)


def test_notification_delivery_migration_adds_claim_state_and_index(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database}")

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database}")
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("notification_outbox")}
    indexes = {index["name"] for index in inspector.get_indexes("notification_outbox")}
    with engine.connect() as connection:
        current_revision = connection.exec_driver_sql(
            "SELECT version_num FROM alembic_version"
        ).scalar_one()

    assert {"lease_token", "lease_expires_at"} <= columns
    assert "ix_notification_outbox_claim" in indexes
    assert current_revision == "0005_auth_lifecycle"
