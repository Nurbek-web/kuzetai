"""SQLAlchemy engine and session construction for PostgreSQL and local tests."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, event
from sqlalchemy import create_engine as sqlalchemy_create_engine
from sqlalchemy.orm import Session, sessionmaker

SessionFactory = sessionmaker[Session]
_PRODUCTION_DATABASE_ROLES = frozenset(
    {
        "kuzet_api",
        "kuzet_runtime",
        "kuzet_retention",
    }
)
_ROLE_QUERY = "SELECT session_user, current_user"


class DatabaseRoleAttestationError(RuntimeError):
    """A production connection does not use its exact restricted login role."""


def _require_database_role_row(
    row: object,
    *,
    expected_role: str,
) -> None:
    if expected_role not in _PRODUCTION_DATABASE_ROLES:
        raise ValueError("unsupported production database role")
    try:
        identities = tuple(row) if row is not None else ()
    except TypeError:
        identities = ()
    if identities != (expected_role, expected_role):
        raise DatabaseRoleAttestationError(
            "production database connection role identity is invalid"
        )


def require_sqlalchemy_database_role(
    engine: object,
    *,
    expected_role: str,
) -> None:
    """Attest one SQLAlchemy connection before any production domain access."""

    if expected_role not in _PRODUCTION_DATABASE_ROLES:
        raise ValueError("unsupported production database role")
    try:
        with engine.connect() as connection:  # type: ignore[attr-defined]
            row = connection.exec_driver_sql(_ROLE_QUERY).fetchone()
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise DatabaseRoleAttestationError(
            "production database role could not be verified"
        ) from exc
    _require_database_role_row(row, expected_role=expected_role)


def require_dbapi_database_role(
    connection: object,
    *,
    expected_role: str,
) -> None:
    """Attest one DBAPI connection before locks or production domain access."""

    if expected_role not in _PRODUCTION_DATABASE_ROLES:
        raise ValueError("unsupported production database role")
    try:
        row = connection.execute(_ROLE_QUERY).fetchone()  # type: ignore[attr-defined]
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise DatabaseRoleAttestationError(
            "production database role could not be verified"
        ) from exc
    _require_database_role_row(row, expected_role=expected_role)


def create_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Create a PostgreSQL-oriented engine with SQLite portability for tests."""
    engine = sqlalchemy_create_engine(database_url, echo=echo, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return engine


def create_session_factory(engine: Engine) -> SessionFactory:
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def transactional_session(factory: SessionFactory) -> Iterator[Session]:
    """Commit as one unit, rolling back automatically on any failure."""
    with factory.begin() as session:
        yield session
