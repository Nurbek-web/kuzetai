from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import update

from protector.pilot.domain import _issue_runtime_writer_receipt
from protector.pilot.runtime.production_repository import (
    PostgresRuntimeMutationGateway,
    RuntimeBoundPilotRepository,
    RuntimePersistenceError,
    bind_runtime_repository,
    claim_runtime_writer,
    load_runtime_configuration,
)
from protector.pilot.storage.journal import JournalItem
from protector.pilot.storage.models import (
    CameraRuleRevisionModel,
    SiteConfigRevisionModel,
)
from protector.pilot.storage.repositories import EvidenceInput
from tests.pilot.test_event_provenance_repository import (
    configured_repository as _configured_repository_fixture,  # noqa: F401
)


NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
EVENT_ID = UUID("10000000-0000-0000-0000-000000000001")
EVIDENCE_ID = UUID("20000000-0000-0000-0000-000000000002")
RUNTIME_BINDINGS = {
    "expected_frozen_workload_sha256": "b" * 64,
    "expected_engine_sha256": "c" * 64,
    "expected_runtime_manifest_sha256": "d" * 64,
}


@pytest.fixture
def configured_repository(_configured_repository_fixture):  # noqa: F811
    return _configured_repository_fixture


def _writer(session: str = "runtime-1"):
    return _issue_runtime_writer_receipt(
        site_id="site-1",
        runtime_session_id=session,
        runtime_writer_generation=3,
        configuration_activation_generation=2,
        config_revision_id="config-1",
        site_config_sha256="a" * 64,
        ruleset_revision_id="rules-1",
        ruleset_sha256="b" * 64,
        rule_revision_digests={"rule-1": "c" * 64},
        issued_at=NOW,
    )


def _evidence(status: str = "ready") -> EvidenceInput:
    return EvidenceInput(
        evidence_id=EVIDENCE_ID,
        event_id=EVENT_ID,
        object_key=f"events/{EVENT_ID}.mp4",
        sha256="d" * 64,
        codec="h264",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=4),
        source_reference="nvr://site-1/camera-01",
        status=status,  # type: ignore[arg-type]
    )


class _Delegate:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def get_event(self, event_id: UUID, **_: object) -> object:
        self.calls.append(("get_event", event_id))
        return "event"

    def store_provenanced_event(self, envelope: object, **_: object) -> object:
        self.calls.append(("store", envelope))
        return "persisted"

    def prepare_preview_publication(self, **kwargs: object) -> object:
        self.calls.append(("prepare_preview", kwargs))
        return "intent"

    def finalize_preview_receipt(self, **kwargs: object) -> None:
        self.calls.append(("finalize_preview", kwargs))

    def get_preview_object_context(self, **kwargs: object) -> object:
        self.calls.append(("preview_context", kwargs))
        return "context"


class _Gateway:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def activate_camera_epoch(self, **kwargs: object) -> object:
        self.calls.append(("epoch", kwargs))
        return "epoch-receipt"

    def get_event(self, **kwargs: object) -> object:
        self.calls.append(("get_event", kwargs))
        return "event"

    def store_provenanced_event(self, **kwargs: object) -> object:
        self.calls.append(("store", kwargs))
        return "persisted"

    def set_candidate_evidence_status(self, **kwargs: object) -> object:
        self.calls.append(("candidate", kwargs))
        return "event"

    def finalize_evidence(self, **kwargs: object) -> object:
        self.calls.append(("evidence", kwargs))
        return kwargs["evidence"]


class _PostgresClaimSession:
    def __init__(
        self,
        state: dict[str, object],
        calls: list[tuple[str, dict[str, object]]],
    ) -> None:
        self._state = state
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def scalar(self, statement: object, parameters: dict[str, object]):
        sql = str(statement)
        self._calls.append((sql, parameters))
        if "pilot_get_runtime_claim_state" in sql:
            return self._state
        canonical = parameters["receipt"]
        assert isinstance(canonical, str)
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert parameters["receipt_sha256"] == expected
        return expected


class _PostgresClaimSessions:
    def __init__(self, state: dict[str, object]) -> None:
        self.state = state
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __call__(self) -> _PostgresClaimSession:
        return _PostgresClaimSession(self.state, self.calls)

    def begin(self) -> _PostgresClaimSession:
        return _PostgresClaimSession(self.state, self.calls)


class _PostgresClaimRepository:
    def __init__(self, state: dict[str, object]) -> None:
        self.session_factory = _PostgresClaimSessions(state)


class _NeverSessions:
    def begin(self):
        raise AssertionError("invalid runtime material reached PostgreSQL")


def test_runtime_bound_repository_routes_only_bounded_mutations() -> None:
    delegate = _Delegate()
    gateway = _Gateway()
    writer = _writer()
    repository = RuntimeBoundPilotRepository(
        repository=delegate,
        writer_receipt=writer,
        mutation_gateway=gateway,
    )
    evidence = _evidence()

    assert repository.get_event(EVENT_ID) == "event"
    assert (
        repository.store_provenanced_event("envelope", receipt=writer)
        == "persisted"
    )
    assert repository.mark_candidate_evidence_pending(EVENT_ID) == "event"
    assert repository.mark_candidate_evidence_failed(EVENT_ID) == "event"
    assert repository.finalize_evidence(evidence, status="ready") == evidence
    assert repository.activate_camera_epoch(
        camera_id="camera-01",
        source_epoch=UUID("30000000-0000-0000-0000-000000000003"),
        expected_source_epoch=None,
        activated_at=NOW,
    ) == "epoch-receipt"

    assert [name for name, _ in gateway.calls] == [
        "get_event",
        "store",
        "candidate",
        "candidate",
        "evidence",
        "epoch",
    ]
    assert delegate.calls == []


def test_runtime_journal_accepts_only_terminal_evidence_work() -> None:
    gateway = _Gateway()
    repository = RuntimeBoundPilotRepository(
        repository=_Delegate(),
        writer_receipt=_writer(),
        mutation_gateway=gateway,
    )
    evidence = _evidence()
    payload = {
        "schema_version": "evidence-work.v1",
        "evidence_id": str(evidence.evidence_id),
        "event_id": str(evidence.event_id),
        "object_key": evidence.object_key,
        "sha256": evidence.sha256,
        "codec": evidence.codec,
        "start_at": evidence.start_at.isoformat(),
        "end_at": evidence.end_at.isoformat(),
        "source_reference": evidence.source_reference,
        "status": evidence.status,
    }

    repository.persist_journal_item(
        JournalItem(
            item_id=1,
            kind="evidence",
            schema_version="evidence-work.v1",
            idempotency_key="evidence-1",
            payload=payload,
            created_at=NOW,
        )
    )
    assert gateway.calls[0][0] == "evidence"

    with pytest.raises(RuntimePersistenceError, match="candidate replay"):
        repository.persist_journal_item(
            JournalItem(
                item_id=2,
                kind="candidate_event",
                schema_version="candidate-event.v1",
                idempotency_key="legacy-candidate",
                payload={"schema_version": "candidate-event.v1"},
                created_at=NOW,
            )
        )


def test_runtime_bound_repository_rejects_a_different_writer_capability() -> None:
    delegate = _Delegate()
    repository = RuntimeBoundPilotRepository(
        repository=delegate,
        writer_receipt=_writer(),
        mutation_gateway=_Gateway(),
    )

    with pytest.raises(RuntimePersistenceError, match="writer authority"):
        repository.store_provenanced_event(
            object(),
            receipt=_writer("runtime-2"),
        )

    assert delegate.calls == []


def test_postgres_claim_issues_only_the_exact_locked_state_receipt() -> None:
    state = {
        "schema_version": "runtime-claim-state.v1",
        "site_id": "site-1",
        "activation_generation": 2,
        "config_revision_id": "config-1",
        "site_config_sha256": "a" * 64,
        "ruleset_revision_id": "rules-1",
        "ruleset_sha256": "b" * 64,
        "rule_revision_digests": {"rule-1": "c" * 64},
        "current_runtime_session_id": "runtime-previous",
        "current_writer_generation": 3,
        "writer_configuration_activation_generation": 2,
        "writer_issued_at": NOW - timedelta(hours=1),
    }
    repository = _PostgresClaimRepository(state)

    receipt = claim_runtime_writer(
        repository,  # type: ignore[arg-type]
        "site-1",
        "runtime-next",
        NOW,
        expected_writer_generation=3,
        dialect_name="postgresql",
    )

    assert receipt.runtime_writer_generation == 4
    assert receipt.configuration_activation_generation == 2
    assert receipt.rule_revision_digests == {"rule-1": "c" * 64}
    calls = repository.session_factory.calls
    assert len(calls) == 2
    assert "pilot_get_runtime_claim_state" in calls[0][0]
    assert "pilot_claim_runtime_writer" in calls[1][0]
    canonical = calls[1][1]["receipt"]
    assert isinstance(canonical, str)
    assert json.loads(canonical) == receipt.model_dump(mode="json")
    assert calls[1][1]["receipt_sha256"] == receipt.authority_sha256


def test_postgres_gateway_rejects_naive_times_before_mutation() -> None:
    gateway = PostgresRuntimeMutationGateway(
        repository=object(),  # type: ignore[arg-type]
        sessions=_NeverSessions(),  # type: ignore[arg-type]
    )
    writer = _writer()

    with pytest.raises(RuntimePersistenceError, match="timezone-aware"):
        gateway.activate_camera_epoch(
            receipt=writer,
            camera_id="camera-01",
            source_epoch=UUID(
                "30000000-0000-0000-0000-000000000003"
            ),
            expected_source_epoch=None,
            activated_at=NOW.replace(tzinfo=None),
        )

    with pytest.raises(RuntimePersistenceError, match="timezone-aware"):
        gateway.finalize_evidence(
            receipt=writer,
            evidence=replace(
                _evidence(),
                start_at=NOW.replace(tzinfo=None),
            ),
            status="ready",
        )


def test_sqlite_claim_and_runtime_projection_are_bound_to_exact_receipt(
    configured_repository,
) -> None:
    repository, _ = configured_repository
    receipt = claim_runtime_writer(
        repository,
        "site-1",
        "production-runtime-1",
        NOW,
        dialect_name="sqlite",
    )

    site, rules = load_runtime_configuration(
        repository,
        receipt,
        dialect_name="sqlite",
        **RUNTIME_BINDINGS,
    )
    bound = bind_runtime_repository(
        repository=repository,
        writer_receipt=receipt,
        dialect_name="sqlite",
    )

    assert site.ready_to_start.feeds[0].camera_id == "camera-01"
    assert tuple(
        (rule.camera_id, rule.module, rule.rule_id)
        for rule in rules
    ) == (("camera-01", "weapon", "camera-01-weapon"),)
    assert rules[0].rule_revision_sha256 == receipt.rule_revision_sha256(
        "camera-01-weapon"
    )
    assert bound.writer_receipt is receipt


def test_runtime_projection_recomputes_site_config_digest(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    receipt = claim_runtime_writer(
        repository=repository,
        site_id="site-1",
        runtime_session_id="production-runtime-1",
        issued_at=NOW,
        expected_writer_generation=activation.runtime_writer_generation,
        dialect_name="sqlite",
    )
    with repository.session_factory.begin() as session:
        session.connection().exec_driver_sql(
            "DROP TRIGGER trg_site_config_revisions_update_immutable"
        )
        config = session.get(SiteConfigRevisionModel, "site-config-1")
        assert config is not None
        changed = dict(config.canonical_config)
        ready = dict(changed["ready_to_start"])
        ready["ntp_source"] = "untrusted.example"
        changed["ready_to_start"] = ready
        session.execute(
            update(SiteConfigRevisionModel)
            .where(
                SiteConfigRevisionModel.config_revision_id
                == "site-config-1"
            )
            .values(canonical_config=changed)
        )

    with pytest.raises(
        RuntimePersistenceError,
        match="site configuration digest",
    ):
        load_runtime_configuration(
            repository,
            receipt,
            dialect_name="sqlite",
            **RUNTIME_BINDINGS,
        )


def test_runtime_projection_rejects_rule_digest_drift(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    receipt = claim_runtime_writer(
        repository=repository,
        site_id="site-1",
        runtime_session_id="production-runtime-1",
        issued_at=NOW,
        expected_writer_generation=activation.runtime_writer_generation,
        dialect_name="sqlite",
    )
    with repository.session_factory.begin() as session:
        session.connection().exec_driver_sql(
            "DROP TRIGGER trg_camera_rule_revisions_update_immutable"
        )
        session.execute(
            update(CameraRuleRevisionModel)
            .where(
                CameraRuleRevisionModel.ruleset_revision_id == "ruleset-1",
                CameraRuleRevisionModel.rule_id == "camera-01-weapon",
            )
            .values(rule_revision_sha256="f" * 64)
        )

    with pytest.raises(RuntimePersistenceError, match="rule digest"):
        load_runtime_configuration(
            repository,
            receipt,
            dialect_name="sqlite",
            **RUNTIME_BINDINGS,
        )


def test_runtime_projection_rejects_rule_spec_module_drift(
    configured_repository,
) -> None:
    repository, activation = configured_repository
    receipt = claim_runtime_writer(
        repository=repository,
        site_id="site-1",
        runtime_session_id="production-runtime-1",
        issued_at=NOW,
        expected_writer_generation=activation.runtime_writer_generation,
        dialect_name="sqlite",
    )
    with repository.session_factory.begin() as session:
        session.connection().exec_driver_sql(
            "DROP TRIGGER trg_camera_rule_revisions_update_immutable"
        )
        session.execute(
            update(CameraRuleRevisionModel)
            .where(
                CameraRuleRevisionModel.ruleset_revision_id == "ruleset-1",
                CameraRuleRevisionModel.rule_id == "camera-01-weapon",
            )
            .values(
                rule_spec={
                    "kind": "zone",
                    "mode": "intrusion",
                    "polygon": ((0.0, 0.0), (1.0, 0.0), (0.0, 1.0)),
                    "loiter_seconds": 0.0,
                    "reason": "corrupted rule kind",
                    "merge_window_seconds": 0.0,
                    "cooldown_seconds": 0.0,
                }
            )
        )

    with pytest.raises(RuntimePersistenceError, match="rule spec"):
        load_runtime_configuration(
            repository,
            receipt,
            dialect_name="sqlite",
            **RUNTIME_BINDINGS,
        )


@pytest.mark.parametrize(
    "changed_binding",
    (
        "expected_frozen_workload_sha256",
        "expected_engine_sha256",
        "expected_runtime_manifest_sha256",
    ),
)
def test_runtime_projection_rejects_mounted_manifest_binding_drift(
    configured_repository,
    changed_binding: str,
) -> None:
    repository, activation = configured_repository
    receipt = claim_runtime_writer(
        repository=repository,
        site_id="site-1",
        runtime_session_id="production-runtime-1",
        issued_at=NOW,
        expected_writer_generation=activation.runtime_writer_generation,
        dialect_name="sqlite",
    )
    expected = dict(RUNTIME_BINDINGS)
    expected[changed_binding] = "e" * 64

    with pytest.raises(
        RuntimePersistenceError,
        match="mounted runtime manifest",
    ):
        load_runtime_configuration(
            repository,
            receipt,
            dialect_name="sqlite",
            **expected,
        )
