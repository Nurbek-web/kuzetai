"""Safe notification contracts and signed application links."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from uuid import UUID

MAX_LINK_TTL = timedelta(hours=24)
MIN_LINK_TTL = timedelta(seconds=1)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be UTC-aware")
    return value.astimezone(timezone.utc)


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


@dataclass(frozen=True, slots=True)
class ConfirmedEventView:
    """The complete and deliberately narrow connector-visible event record."""

    site_id: str
    site_name: str
    camera_id: str
    camera_name: str
    source_time: datetime
    category: str
    confirming_operator: str
    event_id: UUID
    evidence_link: str = field(repr=False)

    def __post_init__(self) -> None:
        bounds = (
            ("site identity", self.site_id, 128),
            ("site name", self.site_name, 255),
            ("camera identity", self.camera_id, 128),
            ("camera name", self.camera_name, 255),
            ("category", self.category, 128),
            ("confirming operator", self.confirming_operator, 255),
            ("evidence link", self.evidence_link, 2048),
        )
        for label, value, maximum in bounds:
            if (
                not isinstance(value, str)
                or not value.strip()
                or value != value.strip()
                or len(value) > maximum
                or _contains_control(value)
            ):
                raise ValueError(f"{label} is invalid")
        parsed_link = urlsplit(self.evidence_link)
        query = parse_qs(parsed_link.query, keep_blank_values=True, strict_parsing=True)
        if (
            parsed_link.scheme != "https"
            or not parsed_link.hostname
            or parsed_link.username is not None
            or parsed_link.password is not None
            or parsed_link.path != f"/pilot/events/{self.event_id}"
            or parsed_link.fragment
            or set(query) != {"expires", "signature"}
            or any(len(values) != 1 or not values[0] for values in query.values())
            or not query["expires"][0].isascii()
            or not query["expires"][0].isdigit()
        ):
            raise ValueError("evidence link is invalid")
        object.__setattr__(self, "source_time", _as_utc(self.source_time))


class NotificationConnector(Protocol):
    """Deliver one human-confirmed event using a stable delivery identity."""

    async def send_confirmed(
        self,
        event_view: ConfirmedEventView,
        idempotency_key: str,
    ) -> str: ...


class InvalidSignedLink(ValueError):
    """A signed application link is invalid, changed, or expired."""


class EvidenceLinkSigner:
    """Issue event-bound HMAC links to the authenticated application route."""

    def __init__(
        self,
        *,
        secret: bytes,
        application_origin: str,
        ttl: timedelta,
    ) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("link signing secret must contain at least 32 bytes")
        parsed = urlsplit(application_origin)
        if parsed.scheme != "https":
            raise ValueError("application origin must use HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("application origin must not contain credentials")
        if (
            not parsed.hostname
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or _contains_control(application_origin)
            or any(character.isspace() for character in application_origin)
        ):
            raise ValueError("application origin must be a bare HTTPS origin")
        if ttl < MIN_LINK_TTL or ttl > MAX_LINK_TTL:
            raise ValueError("signed link TTL must be at least one second and at most 24 hours")
        self._secret = secret
        self._origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")
        self._ttl = ttl

    def __repr__(self) -> str:
        return f"{type(self).__name__}(application_origin={self._origin!r})"

    def issue(self, event_id: UUID, *, now: datetime) -> str:
        issued_at = _as_utc(now)
        expires = int((issued_at + self._ttl).timestamp())
        path = f"/pilot/events/{event_id}"
        signature = self._signature(event_id=event_id, expires=expires, path=path)
        return f"{self._origin}{path}?{urlencode({'expires': expires, 'signature': signature})}"

    def verify(self, link: str, *, event_id: UUID, now: datetime) -> bool:
        try:
            self._validate(link, event_id=event_id, now=now)
        except (InvalidSignedLink, TypeError, ValueError, OverflowError):
            return False
        return True

    def require_valid(self, link: str, *, event_id: UUID, now: datetime) -> None:
        try:
            self._validate(link, event_id=event_id, now=now)
        except InvalidSignedLink:
            raise
        except (TypeError, ValueError, OverflowError) as exc:
            raise InvalidSignedLink("signed application link is invalid") from exc

    def _validate(self, link: str, *, event_id: UUID, now: datetime) -> None:
        if not isinstance(link, str) or len(link) > 2048:
            raise InvalidSignedLink("signed application link is invalid")
        parsed = urlsplit(link)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")
        expected_path = f"/pilot/events/{event_id}"
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or origin != self._origin
            or parsed.path != expected_path
            or parsed.fragment
        ):
            raise InvalidSignedLink("signed application link is invalid")
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if set(query) != {"expires", "signature"} or any(len(values) != 1 for values in query.values()):
            raise InvalidSignedLink("signed application link is invalid")
        expires_text = query["expires"][0]
        if not expires_text.isascii() or not expires_text.isdigit():
            raise InvalidSignedLink("signed application link is invalid")
        expires = int(expires_text)
        if int(_as_utc(now).timestamp()) >= expires:
            raise InvalidSignedLink("signed application link has expired")
        expected = self._signature(event_id=event_id, expires=expires, path=expected_path)
        supplied = query["signature"][0]
        if not hmac.compare_digest(supplied, expected):
            raise InvalidSignedLink("signed application link is invalid")

    def _signature(self, *, event_id: UUID, expires: int, path: str) -> str:
        material = f"{event_id}\n{expires}\n{path}".encode("utf-8")
        digest = hmac.new(self._secret, material, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
