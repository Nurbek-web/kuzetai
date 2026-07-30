from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier

import pytest
from sqlalchemy import event, func, select

from protector.pilot.api import auth
from protector.pilot.api.auth import PasswordService, TotpService
from protector.pilot.storage import repositories
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import AuditEntryModel, Base, UserModel
from protector.pilot.storage.repositories import PilotRepository

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
TOTP_KEY = base64.urlsafe_b64encode(b"l" * 32).decode()


def _repository(tmp_path: Path, name: str = "auth-lifecycle.db") -> PilotRepository:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / name}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(
        create_session_factory(engine),
        totp_encryption_key=TOTP_KEY,
    )
    repository.add_site(site_id="site-1", name="School 1")
    return repository


def _encrypted_totp(username: str) -> tuple[str, str]:
    service = TotpService(encryption_key=TOTP_KEY)
    secret = service.enrol(username).secret
    return secret, service.encrypt_secret(secret)


def _seed_user(
    repository: PilotRepository,
    *,
    user_id: str,
    username: str,
    role: str,
    is_active: bool = True,
) -> None:
    _, encrypted = _encrypted_totp(username)
    repository.add_user(
        user_id=user_id,
        username=username,
        password_hash=PasswordService().hash(f"password-{user_id}"),
        role=role,
        totp_secret_encrypted=encrypted,
        is_active=is_active,
    )


def test_username_identity_uses_nfkc_then_casefold() -> None:
    assert auth.normalize_username("  Ｓｔｒａßｅ  ") == "strasse"
    assert auth.normalize_username("KUZET") == "kuzet"
    with pytest.raises(ValueError, match="username"):
        auth.normalize_username(" \u3000 ")


def test_concurrent_first_admin_bootstrap_is_zero_user_only_and_site_audited(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    password_hash = PasswordService().hash("bootstrap-password")
    secrets = [_encrypted_totp(f"admin-{index}")[1] for index in range(2)]
    barrier = Barrier(2)

    def bootstrap(index: int) -> object:
        barrier.wait(timeout=5)
        try:
            return repository.bootstrap_first_admin(
                user_id=f"admin-{index}",
                username=f"Admin {index}",
                password_hash=password_hash,
                totp_secret_encrypted=secrets[index],
                occurred_at=NOW,
            )
        except repositories.BootstrapAlreadyCompletedError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(bootstrap, range(2)))

    assert sum(isinstance(result, UserModel) for result in results) == 1
    assert (
        sum(isinstance(result, repositories.BootstrapAlreadyCompletedError) for result in results)
        == 1
    )
    with repository.session_factory() as session:
        users = list(session.scalars(select(UserModel)))
        audits = list(session.scalars(select(AuditEntryModel)))
    assert len(users) == 1
    assert users[0].role == "admin"
    assert users[0].is_active is True
    assert users[0].auth_generation == 1
    assert users[0].normalized_username in {"admin 0", "admin 1"}
    assert [(entry.site_id, entry.action) for entry in audits] == [
        ("site-1", "auth.first_admin_bootstrapped")
    ]
    serialized_audit = json.dumps(audits[0].payload, sort_keys=True)
    assert password_hash not in serialized_audit
    assert all(secret not in serialized_audit for secret in secrets)


def test_bootstrap_requires_exactly_one_site_and_leaves_no_partial_user(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    repository.add_site(site_id="site-2", name="School 2")
    _, encrypted = _encrypted_totp("admin")

    with pytest.raises(repositories.SoleSiteRequiredError):
        repository.bootstrap_first_admin(
            user_id="admin-1",
            username="admin",
            password_hash=PasswordService().hash("bootstrap-password"),
            totp_secret_encrypted=encrypted,
            occurred_at=NOW,
        )

    with repository.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(UserModel)) == 0
        assert session.scalar(select(func.count()).select_from(AuditEntryModel)) == 0


def test_lifecycle_mutations_increment_generation_and_emit_redacted_atomic_audit(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    _seed_user(repository, user_id="admin-1", username="admin", role="admin")
    _, first_totp = _encrypted_totp("viewer")
    created = repository.create_user(
        actor_user_id="admin-1",
        user_id="viewer-1",
        username="  Ｖiewer  ",
        password_hash=PasswordService().hash("viewer-original"),
        role="viewer",
        totp_secret_encrypted=first_totp,
        occurred_at=NOW,
    )
    assert created.auth_generation == 1
    assert created.username == "Viewer"
    assert created.normalized_username == "viewer"

    role_changed = repository.set_user_role(
        actor_user_id="admin-1",
        user_id="viewer-1",
        role="operator",
        expected_auth_generation=1,
        occurred_at=NOW,
    )
    deactivated = repository.set_user_active(
        actor_user_id="admin-1",
        user_id="viewer-1",
        is_active=False,
        expected_auth_generation=2,
        occurred_at=NOW,
    )
    new_password_hash = PasswordService().hash("viewer-replacement")
    password_changed = repository.set_user_password(
        actor_user_id="admin-1",
        user_id="viewer-1",
        password_hash=new_password_hash,
        expected_auth_generation=3,
        occurred_at=NOW,
    )
    new_totp_secret, new_totp = _encrypted_totp("viewer")
    totp_changed = repository.reset_user_totp(
        actor_user_id="admin-1",
        user_id="viewer-1",
        totp_secret_encrypted=new_totp,
        expected_auth_generation=4,
        occurred_at=NOW,
    )
    revoked = repository.revoke_user_sessions(
        actor_user_id="admin-1",
        user_id="viewer-1",
        expected_auth_generation=5,
        occurred_at=NOW,
    )

    assert [
        role_changed.auth_generation,
        deactivated.auth_generation,
        password_changed.auth_generation,
        totp_changed.auth_generation,
        revoked.auth_generation,
    ] == [2, 3, 4, 5, 6]
    with repository.session_factory() as session:
        stored = session.get(UserModel, "viewer-1")
        audits = list(
            session.scalars(
                select(AuditEntryModel)
                .where(AuditEntryModel.entity_id == "viewer-1")
                .order_by(AuditEntryModel.audit_id)
            )
        )
    assert stored is not None
    assert stored.password_hash == new_password_hash
    assert stored.totp_secret_encrypted == new_totp
    assert stored.totp_last_accepted_counter is None
    assert stored.auth_generation == 6
    assert {entry.site_id for entry in audits} == {"site-1"}
    assert {entry.action for entry in audits} == {
        "auth.user.created",
        "auth.user.role_changed",
        "auth.user.active_changed",
        "auth.user.password_changed",
        "auth.user.totp_reset",
        "auth.user.sessions_revoked",
    }
    serialized_audit = json.dumps([entry.payload for entry in audits], sort_keys=True)
    for credential in (new_password_hash, first_totp, new_totp, new_totp_secret):
        assert credential not in serialized_audit


def test_stale_generation_rolls_back_without_audit(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _seed_user(repository, user_id="admin-1", username="admin", role="admin")
    _seed_user(repository, user_id="viewer-1", username="viewer", role="viewer")

    with pytest.raises(repositories.StaleAuthGenerationError) as exc_info:
        repository.set_user_role(
            actor_user_id="admin-1",
            user_id="viewer-1",
            role="operator",
            expected_auth_generation=99,
            occurred_at=NOW,
        )

    assert (exc_info.value.expected, exc_info.value.actual) == (99, 1)
    with repository.session_factory() as session:
        user = session.get(UserModel, "viewer-1")
        assert user is not None
        assert (user.role, user.auth_generation) == ("viewer", 1)
        assert session.scalar(select(func.count()).select_from(AuditEntryModel)) == 0


def test_audit_insert_failure_rolls_back_credential_mutation(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _seed_user(repository, user_id="admin-1", username="admin", role="admin")
    _seed_user(repository, user_id="viewer-1", username="viewer", role="viewer")
    with repository.session_factory() as session:
        original = session.get(UserModel, "viewer-1")
        assert original is not None
        original_hash = original.password_hash

    def reject_audit(*_: object) -> None:
        raise RuntimeError("injected audit failure")

    event.listen(AuditEntryModel, "before_insert", reject_audit)
    try:
        with pytest.raises(RuntimeError, match="injected audit failure"):
            repository.set_user_password(
                actor_user_id="admin-1",
                user_id="viewer-1",
                password_hash=PasswordService().hash("replacement"),
                expected_auth_generation=1,
                occurred_at=NOW,
            )
    finally:
        event.remove(AuditEntryModel, "before_insert", reject_audit)

    with repository.session_factory() as session:
        user = session.get(UserModel, "viewer-1")
        assert user is not None
        assert (user.password_hash, user.auth_generation) == (original_hash, 1)
        assert session.scalar(select(func.count()).select_from(AuditEntryModel)) == 0


def test_concurrent_admin_deactivation_cannot_remove_last_active_admin(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    _seed_user(repository, user_id="admin-1", username="admin-one", role="admin")
    _seed_user(repository, user_id="admin-2", username="admin-two", role="admin")
    barrier = Barrier(2)

    def deactivate(user_id: str) -> object:
        barrier.wait(timeout=5)
        try:
            return repository.set_user_active(
                actor_user_id="admin-1",
                user_id=user_id,
                is_active=False,
                expected_auth_generation=1,
                occurred_at=NOW,
            )
        except repositories.LastActiveAdminError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(deactivate, ("admin-1", "admin-2")))

    assert sum(isinstance(result, UserModel) for result in results) == 1
    assert sum(isinstance(result, repositories.LastActiveAdminError) for result in results) == 1
    with repository.session_factory() as session:
        active_admins = session.scalar(
            select(func.count())
            .select_from(UserModel)
            .where(UserModel.role == "admin", UserModel.is_active.is_(True))
        )
        audit_count = session.scalar(select(func.count()).select_from(AuditEntryModel))
    assert active_admins == 1
    assert audit_count == 1
