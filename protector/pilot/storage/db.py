"""SQLAlchemy engine and session construction for PostgreSQL and local tests."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, event
from sqlalchemy import create_engine as sqlalchemy_create_engine
from sqlalchemy.orm import Session, sessionmaker

SessionFactory = sessionmaker[Session]


def create_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Create a PostgreSQL-oriented engine with SQLite portability for tests."""
    engine = sqlalchemy_create_engine(database_url, echo=echo, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def create_session_factory(engine: Engine) -> SessionFactory:
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def transactional_session(factory: SessionFactory) -> Iterator[Session]:
    """Commit as one unit, rolling back automatically on any failure."""
    with factory.begin() as session:
        yield session
