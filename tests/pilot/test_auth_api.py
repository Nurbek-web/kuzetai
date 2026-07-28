from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

from protector.pilot.api.app import create_app
from protector.pilot.api.auth import LoginThrottle, PasswordService, TotpService
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import Base
from protector.pilot.storage.repositories import PilotRepository

UTC = timezone.utc
NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
SESSION_SECRET = "test-session-signing-key-that-is-never-returned"
MACHINE_TOKEN = "test-machine-token-that-is-never-returned"


@pytest.fixture
def auth_context(tmp_path: Path) -> tuple[TestClient, PilotRepository, dict[str, str]]:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'auth.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    password_service = PasswordService()
    totp_service = TotpService()
    secrets: dict[str, str] = {}
    for username, role in (
        ("viewer", "viewer"),
        ("operator", "operator"),
        ("admin", "admin"),
    ):
        totp_secret = totp_service.enrol(username).secret
        secrets[username] = totp_secret
        repository.add_user(
            user_id=f"{role}-1",
            username=username,
            password_hash=password_service.hash("Correct horse battery staple"),
            role=role,
            totp_secret_encrypted=totp_secret,
        )
    app = create_app(
        repository=repository,
        session_secret=SESSION_SECRET,
        machine_token=MACHINE_TOKEN,
        throttle=LoginThrottle(max_attempts=3, window_seconds=60, max_entries=8),
    )
    return TestClient(app, base_url="https://testserver"), repository, secrets


def _login(
    client: TestClient,
    secrets: dict[str, str],
    username: str,
    *,
    password: str = "Correct horse battery staple",
) -> object:
    return client.post(
        "/api/auth/login",
        json={
            "username": username,
            "password": password,
            "totp_code": pyotp.TOTP(secrets[username]).now(),
        },
    )


def test_password_hashing_uses_argon2_and_totp_enrolment_verifies() -> None:
    passwords = PasswordService()
    encoded = passwords.hash("secret password")
    totp = TotpService()
    enrolment = totp.enrol("operator")

    assert encoded.startswith("$argon2id$")
    assert "secret password" not in encoded
    assert passwords.verify(encoded, "secret password")
    assert not passwords.verify(encoded, "wrong password")
    assert "operator" in enrolment.provisioning_uri
    assert totp.verify(enrolment.secret, pyotp.TOTP(enrolment.secret).now())
    assert enrolment.secret not in repr(enrolment)


def test_login_requires_password_and_totp_and_sets_a_hardened_opaque_cookie(
    auth_context: tuple[TestClient, PilotRepository, dict[str, str]],
) -> None:
    client, _, secrets = auth_context

    bad_totp = client.post(
        "/api/auth/login",
        json={
            "username": "operator",
            "password": "Correct horse battery staple",
            "totp_code": "000000",
        },
    )
    response = _login(client, secrets, "operator")

    assert bad_totp.status_code == 401
    assert response.status_code == 200
    assert response.json()["user"] == {
        "user_id": "operator-1",
        "username": "operator",
        "role": "operator",
    }
    serialized = response.text
    assert secrets["operator"] not in serialized
    assert SESSION_SECRET not in serialized
    assert MACHINE_TOKEN not in serialized
    set_cookie = response.headers["set-cookie"].lower()
    assert "pilot_session=" in set_cookie
    assert "secure" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "max-age=900" in set_cookie
    assert "operator-1" not in set_cookie
    assert secrets["operator"].lower() not in set_cookie
    assert MACHINE_TOKEN not in repr(client.app.state.pilot_context)


def test_successful_login_rotates_session_and_logout_requires_csrf(
    auth_context: tuple[TestClient, PilotRepository, dict[str, str]],
) -> None:
    client, _, secrets = auth_context
    first = _login(client, secrets, "operator")
    first_cookie = client.cookies.get("pilot_session")
    csrf = first.json()["csrf_token"]

    second = _login(client, secrets, "operator")
    second_cookie = client.cookies.get("pilot_session")

    assert first_cookie != second_cookie
    assert client.post("/api/auth/logout").status_code == 403
    assert client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": second.json()["csrf_token"]},
    ).status_code == 204
    assert client.get("/api/cameras").status_code == 401

    client.cookies.set("pilot_session", first_cookie)
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 401


def test_login_throttle_is_bounded_and_does_not_trust_forwarded_headers(
    auth_context: tuple[TestClient, PilotRepository, dict[str, str]],
) -> None:
    client, _, secrets = auth_context
    payload = {
        "username": " OPERATOR ",
        "password": "wrong",
        "totp_code": pyotp.TOTP(secrets["operator"]).now(),
    }

    for attempt in range(3):
        response = client.post(
            "/api/auth/login",
            json=payload,
            headers={"X-Forwarded-For": f"198.51.100.{attempt}"},
        )
        assert response.status_code == 401

    assert client.post("/api/auth/login", json=payload).status_code == 429

    throttle = LoginThrottle(max_attempts=1, window_seconds=60, max_entries=2)
    for index in range(10):
        throttle.record_failure(f"user-{index}", "client")
    assert throttle.entry_count == 2
    assert throttle.is_limited("new-user-during-capacity-pressure", "client")


def test_login_validation_errors_do_not_echo_passwords(
    auth_context: tuple[TestClient, PilotRepository, dict[str, str]],
) -> None:
    client, _, _ = auth_context
    disclosed_password = "highly-sensitive-" + ("x" * 1_100)

    response = client.post(
        "/api/auth/login",
        json={
            "username": "operator",
            "password": disclosed_password,
            "totp_code": "123456",
        },
    )

    assert response.status_code == 422
    assert disclosed_password not in response.text


def test_viewer_cannot_review_and_browser_session_cannot_ingest_internal_data(
    auth_context: tuple[TestClient, PilotRepository, dict[str, str]],
) -> None:
    client, _, secrets = auth_context
    login = _login(client, secrets, "viewer")

    review = client.post(
        "/api/events/11111111-1111-1111-1111-111111111111/review",
        headers={
            "X-CSRF-Token": login.json()["csrf_token"],
            "Idempotency-Key": "viewer-review",
        },
        json={
            "expected_status": "candidate",
            "target_status": "confirmed",
            "notes": None,
            "reviewed_at": NOW.isoformat(),
        },
    )

    assert review.status_code == 403
    assert client.post("/api/internal/observations", json={}).status_code == 401
