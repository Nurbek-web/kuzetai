"""Authentication primitives with opaque, signed, short-lived sessions."""

from __future__ import annotations

import base64
import binascii
import hmac
import secrets
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Literal

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from protector.pilot.totp_envelope import decode_totp_envelope, encode_totp_envelope

Role = Literal["viewer", "operator", "admin"]


@dataclass(frozen=True)
class TotpEnrolment:
    """One-time enrolment material; callers must never serialize or log this object."""

    secret: str = field(repr=False)
    provisioning_uri: str = field(repr=False)


class PasswordService:
    """Argon2id password hashing with a reusable dummy hash for unknown users."""

    def __init__(self) -> None:
        self._hasher = PasswordHasher()
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    @property
    def dummy_hash(self) -> str:
        return self._dummy_hash

    def hash(self, password: str) -> str:
        if not password:
            raise ValueError("password must not be empty")
        return self._hasher.hash(password)

    def verify(self, encoded: str, password: str) -> bool:
        try:
            return self._hasher.verify(encoded, password)
        except (InvalidHashError, VerificationError):
            return False


class TotpService:
    """TOTP provisioning plus a versioned authenticated-encryption boundary."""

    _VERSION = b"\x01"
    _NONCE_BYTES = 16
    _TAG_BYTES = 32
    _AAD = b"kuzet-ai:totp-seed:v1"

    def __init__(self, *, encryption_key: str, issuer: str = "Kuzet AI") -> None:
        self._issuer = issuer
        try:
            key = base64.b64decode(encryption_key, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("TOTP encryption key must be URL-safe base64") from exc
        if len(key) != 32:
            raise ValueError("TOTP encryption key must decode to exactly 32 bytes")
        self._encryption_key = hmac.digest(key, b"encryption", "sha256")
        self._authentication_key = hmac.digest(key, b"authentication", "sha256")

    def enrol(self, username: str) -> TotpEnrolment:
        normalized = username.strip()
        if not normalized:
            raise ValueError("username must not be empty")
        secret = pyotp.random_base32()
        uri = pyotp.TOTP(secret).provisioning_uri(name=normalized, issuer_name=self._issuer)
        return TotpEnrolment(secret=secret, provisioning_uri=uri)

    def encrypt_secret(self, secret: str) -> str:
        plaintext = secret.encode("ascii")
        nonce = secrets.token_bytes(self._NONCE_BYTES)
        ciphertext = self._xor_stream(plaintext, nonce)
        authenticated = self._VERSION + nonce + ciphertext
        tag = hmac.digest(
            self._authentication_key,
            self._AAD + authenticated,
            "sha256",
        )
        return encode_totp_envelope(authenticated + tag)

    def decrypt_secret(self, encrypted: str) -> str:
        try:
            envelope = decode_totp_envelope(encrypted)
            minimum = 1 + self._NONCE_BYTES + 1 + self._TAG_BYTES
            if len(envelope) < minimum or envelope[:1] != self._VERSION:
                raise ValueError
            authenticated = envelope[: -self._TAG_BYTES]
            provided_tag = envelope[-self._TAG_BYTES :]
            expected_tag = hmac.digest(
                self._authentication_key,
                self._AAD + authenticated,
                "sha256",
            )
            if not hmac.compare_digest(provided_tag, expected_tag):
                raise ValueError
            nonce = authenticated[1 : 1 + self._NONCE_BYTES]
            ciphertext = authenticated[1 + self._NONCE_BYTES :]
            return self._xor_stream(ciphertext, nonce).decode("ascii")
        except (UnicodeDecodeError, binascii.Error, ValueError) as exc:
            raise ValueError("invalid encrypted TOTP secret") from exc

    def match_current_counter(
        self,
        encrypted_secret: str,
        code: str,
        *,
        at: datetime | None = None,
    ) -> int | None:
        if len(code) != 6 or not code.isdigit():
            return None
        secret = self.decrypt_secret(encrypted_secret)
        checked_at = at or datetime.now(timezone.utc)
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise ValueError("TOTP verification time must be UTC-aware")
        totp = pyotp.TOTP(secret)
        if not totp.verify(code, for_time=checked_at, valid_window=0):
            return None
        return int(totp.timecode(checked_at))

    def _xor_stream(self, value: bytes, nonce: bytes) -> bytes:
        output = bytearray()
        for counter in range((len(value) + 31) // 32):
            output.extend(
                hmac.digest(
                    self._encryption_key,
                    self._AAD + nonce + counter.to_bytes(4, "big"),
                    "sha256",
                )
            )
        return bytes(left ^ right for left, right in zip(value, output, strict=False))


@dataclass(frozen=True)
class SessionUser:
    user_id: str
    username: str
    role: Role


@dataclass(frozen=True)
class ServerSession:
    session_id: str
    user: SessionUser
    csrf_token: str
    expires_at: float


class SessionManager:
    """Bounded server-side session state referenced by a signed opaque cookie."""

    cookie_name = "pilot_session"

    def __init__(
        self,
        signing_key: str,
        *,
        ttl_seconds: int = 900,
        max_sessions: int = 10_000,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("session signing key must contain at least 32 characters")
        if ttl_seconds < 1 or max_sessions < 1:
            raise ValueError("session limits must be positive")
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self._serializer = URLSafeTimedSerializer(signing_key, salt="pilot-session-v1")
        self._sessions: OrderedDict[str, ServerSession] = OrderedDict()
        self._lock = RLock()

    def create(self, user: SessionUser) -> tuple[str, ServerSession]:
        now = time.time()
        session = ServerSession(
            session_id=secrets.token_urlsafe(32),
            user=user,
            csrf_token=secrets.token_urlsafe(32),
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._purge_expired(now)
            self._sessions[session.session_id] = session
            self._sessions.move_to_end(session.session_id)
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        token = self._serializer.dumps({"sid": session.session_id})
        return token, session

    def resolve(self, token: str | None) -> ServerSession | None:
        if not token:
            return None
        try:
            payload = self._serializer.loads(token, max_age=self.ttl_seconds)
        except (BadSignature, SignatureExpired):
            return None
        session_id = payload.get("sid") if isinstance(payload, dict) else None
        if not isinstance(session_id, str):
            return None
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            session = self._sessions.get(session_id)
            if session is None or session.expires_at <= now:
                self._sessions.pop(session_id, None)
                return None
            self._sessions.move_to_end(session_id)
            return session

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        try:
            payload = self._serializer.loads(token, max_age=self.ttl_seconds)
        except (BadSignature, SignatureExpired):
            return
        session_id = payload.get("sid") if isinstance(payload, dict) else None
        if isinstance(session_id, str):
            with self._lock:
                self._sessions.pop(session_id, None)

    def _purge_expired(self, now: float) -> None:
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for session_id in expired:
            self._sessions.pop(session_id, None)


@dataclass
class _ThrottleEntry:
    failures: deque[float]
    last_seen: float


class LoginThrottle:
    """Bounded atomic single-process admission by account and client context."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        client_max_attempts: int = 50,
        window_seconds: int = 60,
        max_entries: int = 10_000,
    ) -> None:
        if max_attempts < 1 or client_max_attempts < 1 or window_seconds < 1 or max_entries < 2:
            raise ValueError("throttle limits must be positive")
        self.max_attempts = max_attempts
        self.client_max_attempts = client_max_attempts
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._entries: OrderedDict[tuple[str, str], _ThrottleEntry] = OrderedDict()
        self._lock = RLock()

    @property
    def entry_count(self) -> int:
        with self._lock:
            return len(self._entries)

    def admit_attempt(self, username: str, client_context: str) -> bool:
        """Atomically reserve one attempt, failing closed at either limit or capacity."""
        now = time.monotonic()
        keys = (
            (("account", username.strip().casefold()), self.max_attempts),
            (("client", client_context), self.client_max_attempts),
        )
        with self._lock:
            self._purge_expired(now)
            missing = sum(key not in self._entries for key, _ in keys)
            if len(self._entries) + missing > self.max_entries:
                return False
            for key, limit in keys:
                entry = self._entries.get(key)
                if entry is not None:
                    self._trim(entry, now)
                    if len(entry.failures) >= limit:
                        return False
            for key, _ in keys:
                entry = self._entries.get(key)
                if entry is None:
                    entry = _ThrottleEntry(failures=deque(), last_seen=now)
                    self._entries[key] = entry
                entry.failures.append(now)
                entry.last_seen = now
                self._entries.move_to_end(key)
            return True

    def record_success(self, username: str) -> None:
        """Clear the account bucket; client pressure remains independent."""
        with self._lock:
            self._entries.pop(("account", username.strip().casefold()), None)

    def _trim(self, entry: _ThrottleEntry, now: float) -> None:
        cutoff = now - self.window_seconds
        while entry.failures and entry.failures[0] <= cutoff:
            entry.failures.popleft()

    def _purge_expired(self, now: float) -> None:
        cutoff = now - self.window_seconds
        expired = [
            key
            for key, entry in self._entries.items()
            if not entry.failures or entry.failures[-1] <= cutoff
        ]
        for key in expired:
            self._entries.pop(key, None)


def machine_token_matches(presented: str, expected: str) -> bool:
    """Constant-time machine-token comparison kept separate from browser sessions."""

    return secrets.compare_digest(presented.encode(), expected.encode())
