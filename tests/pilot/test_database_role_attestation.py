from __future__ import annotations

from types import SimpleNamespace

import pytest

from protector.pilot.storage.db import (
    DatabaseRoleAttestationError,
    require_dbapi_database_role,
    require_sqlalchemy_database_role,
)


class _SqlAlchemyEngine:
    def __init__(self, row: object) -> None:
        self.row = row
        self.query: str | None = None

    def connect(self):
        engine = self

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def exec_driver_sql(self, query: str):
                engine.query = query
                return SimpleNamespace(fetchone=lambda: engine.row)

        return Connection()


class _DbapiConnection:
    def __init__(self, row: object) -> None:
        self.row = row
        self.query: str | None = None

    def execute(self, query: str):
        self.query = query
        return SimpleNamespace(fetchone=lambda: self.row)


def test_database_role_attestation_accepts_only_both_exact_identities() -> None:
    engine = _SqlAlchemyEngine(("kuzet_api", "kuzet_api"))
    connection = _DbapiConnection(
        ("kuzet_retention", "kuzet_retention")
    )

    require_sqlalchemy_database_role(
        engine,
        expected_role="kuzet_api",
    )
    require_dbapi_database_role(
        connection,
        expected_role="kuzet_retention",
    )

    assert engine.query == "SELECT session_user, current_user"
    assert connection.query == "SELECT session_user, current_user"


@pytest.mark.parametrize(
    "row",
    (
        None,
        ("kuzet_owner", "kuzet_owner"),
        ("kuzet_api", "kuzet_owner"),
        ("kuzet_migrator", "kuzet_api"),
        ("kuzet_api",),
    ),
)
def test_database_role_attestation_rejects_substitution_and_set_role(
    row: object,
) -> None:
    with pytest.raises(DatabaseRoleAttestationError):
        require_sqlalchemy_database_role(
            _SqlAlchemyEngine(row),
            expected_role="kuzet_api",
        )


def test_database_role_attestation_rejects_unknown_expected_role() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        require_dbapi_database_role(
            _DbapiConnection(("owner", "owner")),
            expected_role="owner",
        )
