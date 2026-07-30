from __future__ import annotations

import base64
import json
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from protector.pilot.api.app import create_app
from protector.pilot.api.auth import PasswordService, TotpService
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import AuditEntryModel, Base, UserModel
from protector.pilot.storage.repositories import PilotRepository

SESSION_SECRET = "auth-lifecycle-session-signing-key-long-enough"
MACHINE_TOKEN = "auth-lifecycle-machine-token"
PASSWORD = "Correct horse battery staple"
TOTP_KEY = base64.urlsafe_b64encode(b"a" * 32).decode()


@pytest.fixture
def lifecycle_context(
    tmp_path: Path,
) -> tuple[object, PilotRepository, dict[str, str]]:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'auth-lifecycle-api.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(
        create_session_factory(engine),
        totp_encryption_key=TOTP_KEY,
    )
    repository.add_site(site_id="site-1", name="School 1")
    passwords = PasswordService()
    totp = TotpService(encryption_key=TOTP_KEY)
    secrets: dict[str, str] = {}
    for user_id, username, role in (
        ("admin-1", "Admin", "admin"),
        ("operator-1", "Operator", "operator"),
        ("viewer-1", "Straße", "viewer"),
    ):
        secret = totp.enrol(username).secret
        secrets[user_id] = secret
        repository.add_user(
            user_id=user_id,
            username=username,
            password_hash=passwords.hash(PASSWORD),
            role=role,
            totp_secret_encrypted=totp.encrypt_secret(secret),
        )
    app = create_app(
        repository=repository,
        session_secret=SESSION_SECRET,
        totp_encryption_key=TOTP_KEY,
        machine_token=MACHINE_TOKEN,
        pilot_site_id="site-1",
    )
    return app, repository, secrets


def _client(app: object) -> TestClient:
    return TestClient(app, base_url="https://testserver")


def _login(
    client: TestClient,
    *,
    username: str,
    secret: str,
    password: str = PASSWORD,
) -> dict[str, object]:
    response = client.post(
        "/api/auth/login",
        json={
            "username": username,
            "password": password,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_login_uses_durable_nfkc_casefold_identity(
    lifecycle_context: tuple[object, PilotRepository, dict[str, str]],
) -> None:
    app, _, secrets = lifecycle_context
    client = _client(app)

    payload = _login(
        client,
        username="  ＳＴＲＡＳＳＥ  ",
        secret=secrets["viewer-1"],
    )

    assert payload["user"] == {
        "user_id": "viewer-1",
        "username": "Straße",
        "role": "viewer",
    }


def test_admin_can_list_and_create_users_without_credential_disclosure(
    lifecycle_context: tuple[object, PilotRepository, dict[str, str]],
) -> None:
    app, repository, secrets = lifecycle_context
    client = _client(app)
    login = _login(client, username="admin", secret=secrets["admin-1"])

    listed = client.get("/api/auth/users")
    created = client.post(
        "/api/auth/users",
        headers={"X-CSRF-Token": str(login["csrf_token"])},
        json={
            "username": "  Ｎew User  ",
            "password": "new-user-password",
            "role": "viewer",
        },
    )

    assert listed.status_code == 200
    assert listed.json()["total"] == 3
    serialized_list = listed.text.casefold()
    assert "password_hash" not in serialized_list
    assert "totp_secret" not in serialized_list
    assert created.status_code == 201
    body = created.json()
    assert body["user"]["username"] == "New User"
    assert body["user"]["auth_generation"] == 1
    assert set(body["totp_enrolment"]) == {"secret", "provisioning_uri"}
    assert body["totp_enrolment"]["secret"] in body["totp_enrolment"]["provisioning_uri"]

    with repository.session_factory() as session:
        stored = session.get(UserModel, body["user"]["user_id"])
        audit = session.scalar(
            select(AuditEntryModel).where(AuditEntryModel.entity_id == body["user"]["user_id"])
        )
    assert stored is not None
    assert stored.normalized_username == "new user"
    assert audit is not None
    assert audit.site_id == "site-1"
    serialized_audit = json.dumps(audit.payload, sort_keys=True)
    assert "new-user-password" not in serialized_audit
    assert body["totp_enrolment"]["secret"] not in serialized_audit

    visible_audit = client.get(
        "/api/audit",
        params={"entity_type": "user", "entity_id": body["user"]["user_id"]},
    )
    assert visible_audit.status_code == 200
    assert visible_audit.json()["total"] == 1


@pytest.mark.parametrize(
    ("method", "path", "body"),
    (
        ("get", "/api/auth/users", None),
        (
            "post",
            "/api/auth/users",
            {"username": "forbidden", "password": "password", "role": "viewer"},
        ),
        (
            "put",
            "/api/auth/users/viewer-1/role",
            {"role": "operator", "expected_auth_generation": 1},
        ),
        (
            "put",
            "/api/auth/users/viewer-1/active",
            {"is_active": False, "expected_auth_generation": 1},
        ),
        (
            "put",
            "/api/auth/users/viewer-1/password",
            {"password": "replacement", "expected_auth_generation": 1},
        ),
        (
            "post",
            "/api/auth/users/viewer-1/totp-reset",
            {"expected_auth_generation": 1},
        ),
        (
            "post",
            "/api/auth/users/viewer-1/sessions/revoke",
            {"expected_auth_generation": 1},
        ),
    ),
)
def test_every_user_lifecycle_operation_is_admin_only(
    lifecycle_context: tuple[object, PilotRepository, dict[str, str]],
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    app, _, secrets = lifecycle_context
    client = _client(app)
    login = _login(client, username="operator", secret=secrets["operator-1"])

    response = client.request(
        method,
        path,
        headers={"X-CSRF-Token": str(login["csrf_token"])},
        json=body,
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "body"),
    (
        (
            "put",
            "/api/auth/users/viewer-1/role",
            {"role": "operator", "expected_auth_generation": 1},
        ),
        (
            "put",
            "/api/auth/users/viewer-1/active",
            {"is_active": False, "expected_auth_generation": 1},
        ),
        (
            "put",
            "/api/auth/users/viewer-1/password",
            {"password": "replacement", "expected_auth_generation": 1},
        ),
        (
            "post",
            "/api/auth/users/viewer-1/totp-reset",
            {"expected_auth_generation": 1},
        ),
        (
            "post",
            "/api/auth/users/viewer-1/sessions/revoke",
            {"expected_auth_generation": 1},
        ),
    ),
)
def test_each_user_mutation_immediately_invalidates_existing_sessions(
    lifecycle_context: tuple[object, PilotRepository, dict[str, str]],
    method: str,
    path: str,
    body: dict[str, object],
) -> None:
    app, repository, secrets = lifecycle_context
    target_client = _client(app)
    _login(
        target_client,
        username="ＳＴＲＡＳＳＥ",
        secret=secrets["viewer-1"],
    )
    assert target_client.get("/api/events").status_code == 200
    admin_client = _client(app)
    admin_login = _login(
        admin_client,
        username="admin",
        secret=secrets["admin-1"],
    )

    changed = admin_client.request(
        method,
        path,
        headers={"X-CSRF-Token": str(admin_login["csrf_token"])},
        json=body,
    )

    assert changed.status_code == 200, changed.text
    assert changed.json()["user"]["auth_generation"] == 2
    assert target_client.get("/api/events").status_code == 401
    with repository.session_factory() as session:
        stored = session.get(UserModel, "viewer-1")
        assert stored is not None
        assert stored.auth_generation == 2


def test_last_active_admin_protection_and_stale_generation_map_to_conflict(
    lifecycle_context: tuple[object, PilotRepository, dict[str, str]],
) -> None:
    app, repository, secrets = lifecycle_context
    client = _client(app)
    login = _login(client, username="admin", secret=secrets["admin-1"])
    headers = {"X-CSRF-Token": str(login["csrf_token"])}

    last_admin = client.put(
        "/api/auth/users/admin-1/active",
        headers=headers,
        json={"is_active": False, "expected_auth_generation": 1},
    )
    stale = client.put(
        "/api/auth/users/viewer-1/role",
        headers=headers,
        json={"role": "operator", "expected_auth_generation": 99},
    )

    assert last_admin.status_code == 409
    assert last_admin.json()["detail"]["code"] == "last_active_admin"
    assert stale.status_code == 409
    assert stale.json()["detail"] == {
        "code": "stale_auth_generation",
        "expected": 99,
        "actual": 1,
    }
    with repository.session_factory() as session:
        admin = session.get(UserModel, "admin-1")
        assert admin is not None
        assert (admin.is_active, admin.auth_generation) == (True, 1)


def test_bootstrap_is_not_exposed_as_an_unauthenticated_api(
    lifecycle_context: tuple[object, PilotRepository, dict[str, str]],
) -> None:
    app, _, _ = lifecycle_context
    response = _client(app).post(
        "/api/auth/bootstrap",
        json={"username": "admin", "password": "default"},
    )
    assert response.status_code == 404
