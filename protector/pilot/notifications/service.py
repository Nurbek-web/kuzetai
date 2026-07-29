"""Production notification worker process with authenticated health telemetry."""

from __future__ import annotations

import argparse
import asyncio
import base64
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import func, select

from protector.pilot.notifications.base import EvidenceLinkSigner
from protector.pilot.notifications.telegram import TelegramConnector
from protector.pilot.notifications.worker import NotificationWorker, NotificationWorkerConfig
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import (
    CameraModel,
    CandidateEventModel,
    DeliveryAttemptModel,
    NotificationOutboxModel,
)
from protector.pilot.telemetry import (
    AuthenticatedTelemetryClient,
    NotificationTelemetryPublisher,
)

_MAX_SECRET_BYTES = 16 * 1024


def _read_secret(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_SECRET_BYTES:
            raise RuntimeError("notification secret is invalid")
        value = os.read(descriptor, _MAX_SECRET_BYTES + 1).decode("utf-8").strip()
    finally:
        os.close(descriptor)
    if not value:
        raise RuntimeError("notification secret is empty")
    return value


def _enabled(value: str) -> bool:
    return value == "true"


async def _run(arguments: argparse.Namespace) -> None:
    engine = create_engine(_read_secret(arguments.database_url_secret))
    sessions = create_session_factory(engine)
    started_at = datetime.now(UTC)

    def counts() -> dict[str, int]:
        with sessions() as session:
            attempts = (
                select(DeliveryAttemptModel.status, func.count())
                .join(
                    NotificationOutboxModel,
                    NotificationOutboxModel.outbox_id == DeliveryAttemptModel.outbox_id,
                )
                .join(
                    CandidateEventModel,
                    CandidateEventModel.event_id == NotificationOutboxModel.event_id,
                )
                .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                .where(
                    CameraModel.site_id == arguments.site_id,
                    DeliveryAttemptModel.attempted_at >= started_at,
                )
                .group_by(DeliveryAttemptModel.status)
            )
            by_status = dict(session.execute(attempts).all())
            dead_letter = session.scalar(
                select(func.count())
                .select_from(NotificationOutboxModel)
                .join(
                    CandidateEventModel,
                    CandidateEventModel.event_id == NotificationOutboxModel.event_id,
                )
                .join(CameraModel, CameraModel.camera_id == CandidateEventModel.camera_id)
                .where(
                    CameraModel.site_id == arguments.site_id,
                    NotificationOutboxModel.status == "dead_letter",
                    NotificationOutboxModel.created_at >= started_at,
                )
            )
        return {
            "attempted": sum(int(value) for value in by_status.values()),
            "delivered": int(by_status.get("delivered", 0)),
            "failed": int(by_status.get("failed", 0)),
            "dead_letter": int(dead_letter or 0),
        }

    try:
        link_key = base64.b64decode(
            _read_secret(arguments.evidence_link_secret),
            altchars=b"-_",
            validate=True,
        )
        signer = EvidenceLinkSigner(
            secret=link_key,
            application_origin=arguments.public_origin,
            ttl=timedelta(seconds=arguments.link_ttl_seconds),
        )
        telemetry = NotificationTelemetryPublisher(
            client=AuthenticatedTelemetryClient(
                base_url=arguments.control_plane_url,
                machine_token=_read_secret(arguments.machine_token_secret),
            ),
            worker_session_id=f"notifications-{uuid4()}",
        )
        async with httpx.AsyncClient() as client:
            connector = TelegramConnector(
                customer_approved=_enabled(arguments.customer_approved),
                outbound_network_approved=_enabled(arguments.network_approved),
                bot_token=_read_secret(arguments.telegram_bot_token_secret),
                chat_id=_read_secret(arguments.telegram_chat_id_secret),
                client=client,
            )
            worker = NotificationWorker(
                session_factory=sessions,
                connector=connector,
                link_signer=signer,
                config=NotificationWorkerConfig(batch_size=arguments.batch_size),
                now=lambda: datetime.now(UTC),
                pilot_site_id=arguments.site_id,
            )
            previous_failed = 0
            previous_dead = 0
            while True:
                await worker.run_once()
                totals = counts()
                state = (
                    "degraded"
                    if totals["failed"] > previous_failed
                    or totals["dead_letter"] > previous_dead
                    else "healthy"
                )
                telemetry.publish(state=state, **totals)
                previous_failed = totals["failed"]
                previous_dead = totals["dead_letter"]
                await asyncio.sleep(arguments.interval_seconds)
    finally:
        engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url-secret", type=Path, required=True)
    parser.add_argument("--machine-token-secret", type=Path, required=True)
    parser.add_argument("--evidence-link-secret", type=Path, required=True)
    parser.add_argument("--telegram-bot-token-secret", type=Path, required=True)
    parser.add_argument("--telegram-chat-id-secret", type=Path, required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--public-origin", required=True)
    parser.add_argument("--control-plane-url", required=True)
    parser.add_argument("--customer-approved", choices=("true", "false"), required=True)
    parser.add_argument("--network-approved", choices=("true", "false"), required=True)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--interval-seconds", type=float, default=2.0)
    parser.add_argument("--link-ttl-seconds", type=int, default=900)
    arguments = parser.parse_args()
    if not 0.25 <= arguments.interval_seconds <= 60:
        parser.error("notification polling interval must be between 0.25 and 60 seconds")
    asyncio.run(_run(arguments))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
