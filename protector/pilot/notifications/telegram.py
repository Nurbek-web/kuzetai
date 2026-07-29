"""Explicitly approved Telegram delivery through an injected HTTP client."""

from __future__ import annotations

import re
from typing import Any

import httpx

from protector.pilot.notifications.base import ConfirmedEventView

TELEGRAM_API_ORIGIN = "https://api.telegram.org"
MAX_MESSAGE_CHARACTERS = 3500
REQUEST_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
_BOT_TOKEN = re.compile(r"[A-Za-z0-9:_-]{1,512}\Z")
_CHAT_ID = re.compile(r"(?:-?[0-9]{1,64}|@[A-Za-z0-9_]{1,64})\Z")


class NotificationConfigurationError(ValueError):
    """Notification delivery is disabled or incompletely configured."""


class NotificationDeliveryError(RuntimeError):
    """A retryable provider failure with no provider-controlled detail."""


class TelegramConnector:
    """Plain-text Telegram connector with no implicit enablement."""

    def __init__(
        self,
        *,
        customer_approved: bool,
        outbound_network_approved: bool,
        bot_token: str,
        chat_id: str,
        client: httpx.AsyncClient,
    ) -> None:
        if not customer_approved or not outbound_network_approved:
            raise NotificationConfigurationError("Telegram notification delivery is disabled")
        if (
            not isinstance(bot_token, str)
            or _BOT_TOKEN.fullmatch(bot_token) is None
        ):
            raise NotificationConfigurationError("Telegram notification configuration is invalid")
        if (
            not isinstance(chat_id, str)
            or _CHAT_ID.fullmatch(chat_id) is None
        ):
            raise NotificationConfigurationError("Telegram notification configuration is invalid")
        if not isinstance(client, httpx.AsyncClient):
            raise NotificationConfigurationError("Telegram HTTP client is required")
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._client = client

    def __repr__(self) -> str:
        return f"{type(self).__name__}(enabled=True)"

    async def send_confirmed(
        self,
        event_view: ConfirmedEventView,
        idempotency_key: str,
    ) -> str:
        if (
            not isinstance(idempotency_key, str)
            or not idempotency_key.strip()
            or len(idempotency_key) > 255
        ):
            raise NotificationDeliveryError("notification delivery failed")
        message = self._plain_text_message(event_view)
        endpoint = f"{TELEGRAM_API_ORIGIN}/bot{self._bot_token}/sendMessage"
        failed = False
        reference: str | None = None
        try:
            response = await self._client.post(
                endpoint,
                json={"chat_id": self._chat_id, "text": message},
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code < 200 or response.status_code >= 300:
                failed = True
            else:
                payload: Any = response.json()
                if isinstance(payload, dict) and payload.get("ok") is True:
                    result = payload.get("result")
                    if isinstance(result, dict):
                        message_id = result.get("message_id")
                        if (
                            not isinstance(message_id, bool)
                            and isinstance(message_id, int)
                            and message_id >= 0
                        ):
                            candidate = str(message_id)
                            if len(candidate) <= 64:
                                reference = candidate
                failed = reference is None
        except (httpx.HTTPError, TypeError, ValueError):
            failed = True
        if failed or reference is None:
            raise NotificationDeliveryError("notification delivery failed")
        return reference

    @staticmethod
    def _plain_text_message(event_view: ConfirmedEventView) -> str:
        message = "\n".join(
            (
                "Kuzet AI reviewed event",
                f"Site: {event_view.site_name} ({event_view.site_id})",
                f"Camera: {event_view.camera_name} ({event_view.camera_id})",
                f"Source time: {event_view.source_time.isoformat()}",
                f"Category: {event_view.category}",
                f"Confirmed by: {event_view.confirming_operator}",
                f"Event ID: {event_view.event_id}",
                f"Evidence: {event_view.evidence_link}",
                "Human confirmation: informational notification only; no autonomous dispatch.",
            )
        )
        if len(message) > MAX_MESSAGE_CHARACTERS:
            raise NotificationDeliveryError("notification delivery failed")
        return message
