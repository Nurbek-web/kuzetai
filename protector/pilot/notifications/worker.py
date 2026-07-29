"""Bounded, crash-recoverable notification outbox worker.

External connectors are at-least-once: a process may stop after the provider
accepts a message but before the local success transaction commits.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from protector.pilot.notifications.base import (
    ConfirmedEventView,
    EvidenceLinkSigner,
    NotificationConnector,
)
from protector.pilot.storage.db import SessionFactory
from protector.pilot.storage.models import (
    AuditEntryModel,
    CameraModel,
    CandidateEventModel,
    DeliveryAttemptModel,
    NotificationOutboxModel,
    ReviewModel,
    SiteModel,
    UserModel,
)

GENERIC_DELIVERY_ERROR = "notification delivery failed"
EXPIRED_LEASE_ERROR = "delivery lease expired"
_SAFE_PROVIDER_REFERENCE = re.compile(r"[A-Za-z0-9_.:-]{1,255}\Z")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("notification worker clock must return a UTC-aware timestamp")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class NotificationWorkerConfig:
    batch_size: int = 10
    max_attempts: int = 5
    lease_seconds: int = 30
    initial_backoff_seconds: int = 5
    max_backoff_seconds: int = 300

    def __post_init__(self) -> None:
        bounds = (
            ("batch_size", self.batch_size, 1, 100),
            ("max_attempts", self.max_attempts, 1, 20),
            ("lease_seconds", self.lease_seconds, 1, 3_600),
            ("initial_backoff_seconds", self.initial_backoff_seconds, 1, 86_400),
            ("max_backoff_seconds", self.max_backoff_seconds, 1, 86_400),
        )
        for label, value, minimum, maximum in bounds:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < minimum
                or value > maximum
            ):
                raise ValueError(f"{label} must be between {minimum} and {maximum}")
        if self.max_backoff_seconds < self.initial_backoff_seconds:
            raise ValueError("maximum backoff must not be less than initial backoff")


@dataclass(frozen=True, slots=True)
class _Authority:
    event_id: UUID
    site_id: str
    site_name: str
    camera_id: str
    camera_name: str
    source_time: datetime
    category: str
    confirming_operator: str
    confirmed_at: datetime


@dataclass(frozen=True, slots=True)
class _Claim:
    outbox_id: str
    attempt_id: str
    lease_token: str
    idempotency_key: str
    view: ConfirmedEventView


@dataclass(frozen=True, slots=True)
class _ClaimScan:
    found: bool
    claim: _Claim | None = None


class NotificationWorker:
    """Claim and deliver a finite amount of human-confirmed notification work."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        connector: NotificationConnector,
        link_signer: EvidenceLinkSigner,
        config: NotificationWorkerConfig,
        now: Callable[[], datetime],
        pilot_site_id: str,
    ) -> None:
        if not callable(now):
            raise ValueError("notification worker clock must be callable")
        if (
            not isinstance(pilot_site_id, str)
            or pilot_site_id != pilot_site_id.strip()
            or not pilot_site_id
            or len(pilot_site_id) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in pilot_site_id)
        ):
            raise ValueError("pilot site identity must contain 1 to 128 safe characters")
        self._session_factory = session_factory
        self._connector = connector
        self._link_signer = link_signer
        self._config = config
        self._now = now
        self._pilot_site_id = pilot_site_id

    async def run_once(self) -> int:
        """Attempt at most ``batch_size`` rows and return started connector calls."""
        attempted = 0
        scanned = 0
        while scanned < self._config.batch_size:
            claim_scan = self._claim_one(_require_utc(self._now()))
            if not claim_scan.found:
                break
            scanned += 1
            claim = claim_scan.claim
            if claim is None:
                continue
            attempted += 1
            await self._deliver(claim)
        return attempted

    def _begin(self, session: Session) -> None:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        else:
            session.begin()

    def _claim_one(self, now: datetime) -> _ClaimScan:
        with self._session_factory() as session:
            self._begin(session)
            try:
                eligible = or_(
                    and_(
                        NotificationOutboxModel.status == "pending",
                        NotificationOutboxModel.available_at <= now,
                    ),
                    and_(
                        NotificationOutboxModel.status == "delivering",
                        or_(
                            NotificationOutboxModel.lease_token.is_(None),
                            NotificationOutboxModel.lease_expires_at.is_(None),
                            NotificationOutboxModel.lease_expires_at <= now,
                        ),
                    ),
                )
                statement = (
                    select(NotificationOutboxModel)
                    .join(
                        CandidateEventModel,
                        CandidateEventModel.event_id == NotificationOutboxModel.event_id,
                    )
                    .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                    .where(eligible)
                    .where(CameraModel.site_id == self._pilot_site_id)
                    .order_by(
                        NotificationOutboxModel.available_at,
                        NotificationOutboxModel.created_at,
                        NotificationOutboxModel.outbox_id,
                    )
                    .limit(1)
                )
                if session.get_bind().dialect.name != "sqlite":
                    statement = statement.with_for_update(
                        skip_locked=True,
                        of=NotificationOutboxModel,
                    )
                outbox = session.scalar(statement)
                if outbox is None:
                    session.commit()
                    return _ClaimScan(found=False)

                if outbox.status == "pending" and (
                    outbox.lease_token is not None or outbox.lease_expires_at is not None
                ):
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason="notification outbox state is invalid",
                    )
                    session.commit()
                    return _ClaimScan(found=True)
                if outbox.status == "delivering" and not self._recover_expired_lease(
                    session, outbox, now=now
                ):
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason="notification delivery state is invalid",
                    )
                    session.commit()
                    return _ClaimScan(found=True)

                authority = self._load_authority(session, outbox)
                if authority is None:
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason="notification event is no longer eligible",
                    )
                    session.commit()
                    return _ClaimScan(found=True)

                attempt_number = int(
                    session.scalar(
                        select(func.max(DeliveryAttemptModel.attempt_number)).where(
                            DeliveryAttemptModel.outbox_id == outbox.outbox_id
                        )
                    )
                    or 0
                ) + 1
                if attempt_number > self._config.max_attempts:
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason="notification attempt limit reached",
                    )
                    session.commit()
                    return _ClaimScan(found=True)

                try:
                    view = ConfirmedEventView(
                        site_id=authority.site_id,
                        site_name=authority.site_name,
                        camera_id=authority.camera_id,
                        camera_name=authority.camera_name,
                        source_time=authority.source_time,
                        category=authority.category,
                        confirming_operator=authority.confirming_operator,
                        event_id=authority.event_id,
                        evidence_link=self._link_signer.issue(authority.event_id, now=now),
                    )
                except ValueError:
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason="notification event view is invalid",
                    )
                    session.commit()
                    return _ClaimScan(found=True)

                lease_token = str(uuid4())
                attempt_id = str(uuid4())
                attempt_started_at = max(
                    now,
                    authority.confirmed_at + timedelta(microseconds=1),
                )
                outbox.status = "delivering"
                outbox.lease_token = lease_token
                outbox.lease_expires_at = now + timedelta(seconds=self._config.lease_seconds)
                attempt = DeliveryAttemptModel(
                    delivery_attempt_id=attempt_id,
                    outbox_id=outbox.outbox_id,
                    attempt_number=attempt_number,
                    attempted_at=attempt_started_at,
                    status="sending",
                )
                session.add(attempt)
                self._audit(
                    session,
                    now=attempt_started_at,
                    action="notification.delivery_started",
                    entity_type="delivery_attempt",
                    entity_id=attempt_id,
                    payload={"attempt_number": attempt_number},
                    idempotency_key=f"notification:{attempt_id}:started",
                )
                idempotency_key = outbox.idempotency_key
                session.flush()
                session.commit()
                return _ClaimScan(
                    found=True,
                    claim=_Claim(
                        outbox_id=outbox.outbox_id,
                        attempt_id=attempt_id,
                        lease_token=lease_token,
                        idempotency_key=idempotency_key,
                        view=view,
                    ),
                )
            except BaseException:
                session.rollback()
                raise

    def _recover_expired_lease(
        self,
        session: Session,
        outbox: NotificationOutboxModel,
        *,
        now: datetime,
    ) -> bool:
        if (
            outbox.lease_token is None
            or outbox.lease_expires_at is None
            or _as_utc(outbox.lease_expires_at) > now
        ):
            return False
        sending = list(
            session.scalars(
                select(DeliveryAttemptModel)
                .where(
                    DeliveryAttemptModel.outbox_id == outbox.outbox_id,
                    DeliveryAttemptModel.status == "sending",
                )
                .order_by(DeliveryAttemptModel.attempt_number.desc())
                .limit(2)
            )
        )
        if len(sending) != 1:
            return False
        expired = sending[0]
        expired.status = "failed"
        expired.error = EXPIRED_LEASE_ERROR
        expired.response_reference = None
        self._audit(
            session,
            now=now,
            action="notification.delivery_failed",
            entity_type="delivery_attempt",
            entity_id=expired.delivery_attempt_id,
            payload={"attempt_number": expired.attempt_number, "error": EXPIRED_LEASE_ERROR},
            idempotency_key=f"notification:{expired.delivery_attempt_id}:failed",
        )
        outbox.status = "pending"
        outbox.lease_token = None
        outbox.lease_expires_at = None
        return True

    def _load_authority(
        self,
        session: Session,
        outbox: NotificationOutboxModel,
    ) -> _Authority | None:
        rows = list(
            session.execute(
                select(
                    CandidateEventModel,
                    CameraModel,
                    SiteModel,
                    ReviewModel,
                    UserModel,
                )
                .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                .join(SiteModel, SiteModel.site_id == CameraModel.site_id)
                .join(
                    ReviewModel,
                    and_(
                        ReviewModel.event_id == CandidateEventModel.event_id,
                        ReviewModel.from_status == "candidate",
                        ReviewModel.to_status == "confirmed",
                    ),
                )
                .join(UserModel, UserModel.user_id == ReviewModel.reviewer_id)
                .where(CandidateEventModel.event_id == outbox.event_id)
                .limit(2)
            )
        )
        if len(rows) != 1:
            return None
        event, camera, site, review, reviewer = rows[0]
        if (
            event.gate_mode != "operator"
            or event.review_status != "confirmed"
            or event.transition_history != "observation>candidate>confirmed"
            or review.event_id != event.event_id
            or reviewer.role not in ("operator", "admin")
            or not reviewer.is_active
            or site.site_id != self._pilot_site_id
            or not outbox.idempotency_key
            or len(outbox.idempotency_key) > 255
        ):
            return None
        try:
            event_id = UUID(event.event_id)
        except ValueError:
            return None
        return _Authority(
            event_id=event_id,
            site_id=site.site_id,
            site_name=site.name,
            camera_id=camera.camera_id,
            camera_name=camera.name,
            source_time=_as_utc(event.opened_at),
            category=event.module,
            confirming_operator=reviewer.username,
            confirmed_at=_as_utc(review.reviewed_at),
        )

    async def _deliver(self, claim: _Claim) -> None:
        try:
            reference = await self._connector.send_confirmed(
                claim.view,
                claim.idempotency_key,
            )
            reference = self._provider_reference(reference)
        except Exception:
            self._finalize_failure(claim, now=_require_utc(self._now()))
            return
        self._finalize_success(
            claim,
            reference=reference,
            now=_require_utc(self._now()),
        )

    @staticmethod
    def _provider_reference(value: object) -> str:
        if not isinstance(value, str) or _SAFE_PROVIDER_REFERENCE.fullmatch(value) is None:
            raise ValueError(GENERIC_DELIVERY_ERROR)
        if "://" in value:
            raise ValueError(GENERIC_DELIVERY_ERROR)
        return value

    def _finalize_success(self, claim: _Claim, *, reference: str, now: datetime) -> None:
        with self._session_factory() as session:
            self._begin(session)
            try:
                outbox = session.scalar(
                    select(NotificationOutboxModel)
                    .where(NotificationOutboxModel.outbox_id == claim.outbox_id)
                    .with_for_update()
                )
                if not self._owns_lease(outbox, claim):
                    session.rollback()
                    return
                attempt = session.get(DeliveryAttemptModel, claim.attempt_id)
                if attempt is None or attempt.status != "sending":
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason="notification delivery state is invalid",
                    )
                    session.commit()
                    return
                if self._load_authority(session, outbox) is None:
                    attempt.status = "failed"
                    attempt.error = GENERIC_DELIVERY_ERROR
                    attempt.response_reference = None
                    self._audit(
                        session,
                        now=max(
                            now,
                            _as_utc(attempt.attempted_at) + timedelta(microseconds=1),
                        ),
                        action="notification.delivery_failed",
                        entity_type="delivery_attempt",
                        entity_id=attempt.delivery_attempt_id,
                        payload={
                            "attempt_number": attempt.attempt_number,
                            "error": GENERIC_DELIVERY_ERROR,
                        },
                        idempotency_key=f"notification:{attempt.delivery_attempt_id}:failed",
                    )
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason="notification event is no longer eligible",
                    )
                    session.commit()
                    return
                attempt.status = "delivered"
                attempt.response_reference = reference
                attempt.error = None
                outbox.status = "delivered"
                outbox.lease_token = None
                outbox.lease_expires_at = None
                self._audit(
                    session,
                    now=max(
                        now,
                        _as_utc(attempt.attempted_at) + timedelta(microseconds=1),
                    ),
                    action="notification.delivered",
                    entity_type="delivery_attempt",
                    entity_id=attempt.delivery_attempt_id,
                    payload={
                        "attempt_number": attempt.attempt_number,
                        "response_reference": reference,
                    },
                    idempotency_key=f"notification:{attempt.delivery_attempt_id}:delivered",
                )
                session.commit()
            except BaseException:
                session.rollback()
                raise

    def _finalize_failure(self, claim: _Claim, *, now: datetime) -> None:
        with self._session_factory() as session:
            self._begin(session)
            try:
                outbox = session.scalar(
                    select(NotificationOutboxModel)
                    .where(NotificationOutboxModel.outbox_id == claim.outbox_id)
                    .with_for_update()
                )
                if not self._owns_lease(outbox, claim):
                    session.rollback()
                    return
                attempt = session.get(DeliveryAttemptModel, claim.attempt_id)
                if attempt is None or attempt.status != "sending":
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason="notification delivery state is invalid",
                    )
                    session.commit()
                    return
                attempt.status = "failed"
                attempt.error = GENERIC_DELIVERY_ERROR
                attempt.response_reference = None
                self._audit(
                    session,
                    now=max(
                        now,
                        _as_utc(attempt.attempted_at) + timedelta(microseconds=1),
                    ),
                    action="notification.delivery_failed",
                    entity_type="delivery_attempt",
                    entity_id=attempt.delivery_attempt_id,
                    payload={
                        "attempt_number": attempt.attempt_number,
                        "error": GENERIC_DELIVERY_ERROR,
                    },
                    idempotency_key=f"notification:{attempt.delivery_attempt_id}:failed",
                )
                if (
                    attempt.attempt_number >= self._config.max_attempts
                    or self._load_authority(session, outbox) is None
                ):
                    self._dead_letter(
                        session,
                        outbox,
                        now=now,
                        reason=GENERIC_DELIVERY_ERROR,
                    )
                else:
                    delay = min(
                        self._config.initial_backoff_seconds
                        * (2 ** (attempt.attempt_number - 1)),
                        self._config.max_backoff_seconds,
                    )
                    outbox.status = "pending"
                    outbox.available_at = now + timedelta(seconds=delay)
                    outbox.lease_token = None
                    outbox.lease_expires_at = None
                session.commit()
            except BaseException:
                session.rollback()
                raise

    @staticmethod
    def _owns_lease(outbox: NotificationOutboxModel | None, claim: _Claim) -> bool:
        return bool(
            outbox is not None
            and outbox.status == "delivering"
            and outbox.lease_token == claim.lease_token
        )

    def _dead_letter(
        self,
        session: Session,
        outbox: NotificationOutboxModel,
        *,
        now: datetime,
        reason: str,
    ) -> None:
        outbox.status = "dead_letter"
        outbox.lease_token = None
        outbox.lease_expires_at = None
        self._audit(
            session,
            now=now,
            action="notification.dead_letter",
            entity_type="notification_outbox",
            entity_id=outbox.outbox_id,
            payload={"reason": reason[:256]},
            idempotency_key=f"notification:{outbox.outbox_id}:dead_letter",
        )

    @staticmethod
    def _audit(
        session: Session,
        *,
        now: datetime,
        action: str,
        entity_type: str,
        entity_id: str,
        payload: dict[str, object],
        idempotency_key: str,
    ) -> None:
        session.add(
            AuditEntryModel(
                audit_id=str(uuid4()),
                occurred_at=now,
                actor_user_id=None,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                payload=payload,
                idempotency_key=idempotency_key,
            )
        )
