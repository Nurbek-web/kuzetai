"""Authentication primitives with opaque, signed, short-lived sessions."""

from __future__ import annotations

import secrets
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Literal

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

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
    """TOTP enrolment and verification without retaining enrolment material."""

    def __init__(self, *, issuer: str = "Kuzet AI") -> None:
        self._issuer = issuer

    def enrol(self, username: str) -> TotpEnrolment:
        normalized = username.strip()
        if not normalized:
            raise ValueError("username must not be empty")
        secret = pyotp.random_base32()
        uri = pyotp.TOTP(secret).provisioning_uri(name=normalized, issuer_name=self._issuer)
        return TotpEnrolment(secret=secret, provisioning_uri=uri)

    @staticmethod
    def verify(secret: str, code: str) -> bool:
        if len(code) != 6 or not code.isdigit():
            return False
        return bool(pyotp.TOTP(secret).verify(code, valid_window=1))


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
    """Bounded single-process login throttle with a replaceable narrow interface."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        window_seconds: int = 60,
        max_entries: int = 10_000,
    ) -> None:
        if max_attempts < 1 or window_seconds < 1 or max_entries < 1:
            raise ValueError("throttle limits must be positive")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._entries: OrderedDict[tuple[str, str], _ThrottleEntry] = OrderedDict()
        self._lock = RLock()

    @property
    def entry_count(self) -> int:
        with self._lock:
            return len(self._entries)

    @staticmethod
    def _key(username: str, client_context: str) -> tuple[str, str]:
        return username.strip().casefold(), client_context

    def is_limited(self, username: str, client_context: str) -> bool:
        now = time.monotonic()
        key = self._key(username, client_context)
        with self._lock:
            self._purge_expired(now)
            entry = self._entries.get(key)
            if entry is None:
                return len(self._entries) >= self.max_entries
            self._trim(entry, now)
            if not entry.failures:
                self._entries.pop(key, None)
                return False
            entry.last_seen = now
            self._entries.move_to_end(key)
            return len(entry.failures) >= self.max_attempts

    def record_failure(self, username: str, client_context: str) -> None:
        now = time.monotonic()
        key = self._key(username, client_context)
        with self._lock:
            self._purge_expired(now)
            entry = self._entries.get(key)
            if entry is None:
                if len(self._entries) >= self.max_entries:
                    return
                entry = _ThrottleEntry(failures=deque(), last_seen=now)
                self._entries[key] = entry
            self._trim(entry, now)
            entry.failures.append(now)
            entry.last_seen = now
            self._entries.move_to_end(key)

    def reset(self, username: str, client_context: str) -> None:
        with self._lock:
            self._entries.pop(self._key(username, client_context), None)

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
