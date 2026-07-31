from __future__ import annotations

import inspect
from types import SimpleNamespace
from uuid import UUID

import pytest

from protector.pilot.runtime.production_main import (
    ProductionRuntimeError,
    _preview_context,
    _require_database_role,
    _run_operational_loop,
    _shutdown_production_components,
)
from protector.pilot.runtime import production_main


class _Runtime:
    def __init__(
        self,
        log: list[object],
        *,
        failed_reason: str | None = None,
        stop_error: BaseException | None = None,
    ) -> None:
        self.log = log
        self.failed_reason = failed_reason
        self.stop_error = stop_error

    def stop(self, *, preserve_observations: bool) -> None:
        self.log.append(("graph-stop", preserve_observations))
        if self.stop_error is not None:
            raise self.stop_error

    def finish_observation_drain(self) -> None:
        self.log.append("observation-drain-finished")


class _Pipeline:
    def __init__(self, log: list[object]) -> None:
        self.log = log

    def close(self) -> None:
        self.log.append("event-pipeline-close")


class _Closable:
    def __init__(self, log: list[object], label: str) -> None:
        self.log = log
        self.label = label

    def close(self) -> None:
        self.log.append(self.label)

    def dispose(self) -> None:
        self.log.append(self.label)


class _DatabaseRoleEngine:
    def __init__(self, session_user: str, current_user: str) -> None:
        self.row = (session_user, current_user)
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


def test_runtime_database_connection_requires_exact_restricted_role() -> None:
    engine = _DatabaseRoleEngine("kuzet_runtime", "kuzet_runtime")

    _require_database_role(engine)

    assert engine.query == "SELECT session_user, current_user"


@pytest.mark.parametrize(
    ("session_user", "current_user"),
    (
        ("kuzet_owner", "kuzet_owner"),
        ("kuzet_runtime", "kuzet_owner"),
        ("kuzet_migrator", "kuzet_runtime"),
    ),
)
def test_runtime_database_connection_rejects_privileged_or_set_roles(
    session_user: str,
    current_user: str,
) -> None:
    with pytest.raises(
        ProductionRuntimeError,
        match="restricted runtime role",
    ):
        _require_database_role(
            _DatabaseRoleEngine(session_user, current_user)
        )


def test_shutdown_quiesces_graph_before_worker_and_durable_dependencies() -> None:
    log: list[object] = []

    _shutdown_production_components(
        runtime=_Runtime(log),  # type: ignore[arg-type]
        pipeline=_Pipeline(log),  # type: ignore[arg-type]
        worker=SimpleNamespace(thread_alive=False),
        object_client=_Closable(log, "object-client-close"),
        engine=_Closable(log, "database-engine-dispose"),
    )

    assert log == [
        ("graph-stop", True),
        "event-pipeline-close",
        "observation-drain-finished",
        "object-client-close",
        "database-engine-dispose",
    ]


def test_shutdown_retains_dependencies_if_event_thread_is_still_alive() -> None:
    log: list[object] = []

    with pytest.raises(
        ProductionRuntimeError,
        match="still owns durable dependencies",
    ):
        _shutdown_production_components(
            runtime=_Runtime(log),  # type: ignore[arg-type]
            pipeline=_Pipeline(log),  # type: ignore[arg-type]
            worker=SimpleNamespace(thread_alive=True),
            object_client=_Closable(log, "object-client-close"),
            engine=_Closable(log, "database-engine-dispose"),
        )

    assert log == [
        ("graph-stop", True),
        "event-pipeline-close",
    ]


def test_shutdown_retains_every_dependency_when_graph_null_is_unverified() -> None:
    log: list[object] = []

    with pytest.raises(RuntimeError, match="NULL transition failed"):
        _shutdown_production_components(
            runtime=_Runtime(  # type: ignore[arg-type]
                log,
                stop_error=RuntimeError("NULL transition failed"),
            ),
            pipeline=_Pipeline(log),  # type: ignore[arg-type]
            worker=SimpleNamespace(thread_alive=False),
            object_client=_Closable(log, "object-client-close"),
            engine=_Closable(log, "database-engine-dispose"),
        )

    assert log == [("graph-stop", True)]


def test_active_ruleset_manifest_bindings_precede_external_runtime_resources() -> None:
    source = inspect.getsource(production_main.main)
    configuration = source.index("load_runtime_configuration(")

    for exact_binding in (
        "expected_runtime_manifest_sha256",
        "expected_frozen_workload_sha256",
        "expected_engine_sha256",
    ):
        assert exact_binding in source[configuration:]
    for external_resource in (
        "_build_s3_client(",
        "build_production_event_pipeline(",
        "_load_nvidia_bindings(",
    ):
        assert configuration < source.index(external_resource)


def test_preview_context_uses_exact_event_evidence_and_source_epoch() -> None:
    calls: list[dict[str, object]] = []

    class Repository:
        def get_preview_object_context(self, **kwargs: object) -> object:
            calls.append(kwargs)
            return "authority-derived"

    event_id = UUID("11111111-1111-1111-1111-111111111111")
    evidence_id = UUID("22222222-2222-2222-2222-222222222222")
    source_epoch = UUID("33333333-3333-3333-3333-333333333333")

    result = _preview_context(
        Repository(),
        site_id="site-1",
        reservation=SimpleNamespace(stream_epoch=source_epoch),
        evidence=SimpleNamespace(
            event_id=event_id,
            evidence_id=evidence_id,
        ),
    )

    assert result == "authority-derived"
    assert calls == [
        {
            "site_id": "site-1",
            "event_id": event_id,
            "evidence_id": evidence_id,
            "source_epoch": source_epoch,
        }
    ]


def test_operational_loop_quits_and_fails_on_event_worker_failure() -> None:
    calls: list[str] = []

    class Loop:
        def run(self) -> None:
            calls.append("run")

        def quit(self) -> None:
            calls.append("quit")

    class Glib:
        def timeout_add(self, _: int, callback: object) -> None:
            assert callable(callback)
            assert callback() is False

    class Signals:
        SIGTERM = 15
        SIGINT = 2

        @staticmethod
        def getsignal(signum: int) -> str:
            return f"prior-{signum}"

        @staticmethod
        def signal(signum: int, handler: object) -> None:
            calls.append(f"signal-{signum}-{handler}")

    result = _run_operational_loop(
        runtime=_Runtime(calls),  # type: ignore[arg-type]
        worker=SimpleNamespace(
            status=SimpleNamespace(failed=True),
        ),
        loop=Loop(),
        glib=Glib(),
        signal_module=Signals,
    )

    assert result == 1
    assert "quit" in calls
    assert "run" not in calls
