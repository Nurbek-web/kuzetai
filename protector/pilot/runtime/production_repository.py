"""Writer-bound production persistence without broad runtime table privileges."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Literal, Protocol
from uuid import UUID

from sqlalchemy import select, text

from protector.pilot.config import SiteConfig
from protector.pilot.domain import (
    CameraEpochActivationReceiptV1,
    CandidateEventV1,
    PersistedCandidateEventV2,
    ProvenancedCandidateEventV2,
    RuntimeWriterReceiptV1,
    _issue_runtime_writer_receipt,
)
from protector.pilot.gates import site_config_sha256
from protector.pilot.rules import (
    CompiledCameraRuleV1,
    LineRuleSpecV1,
    ModuleRuleSpecV1,
    ZoneRuleSpecV1,
)
from protector.pilot.storage.db import SessionFactory
from protector.pilot.storage.journal import (
    JournalItem,
    validate_journal_work,
)
from protector.pilot.storage.models import (
    ActivePilotConfigurationModel,
    CameraRuleRevisionModel,
    CameraRulesetRevisionModel,
    RuntimeWriterAuthorityModel,
    RuntimeWriterSessionModel,
    SiteConfigRevisionModel,
)
from protector.pilot.storage.repositories import (
    EvidenceInput,
    EvidenceIntent,
    PilotRepository,
)


class RuntimePersistenceError(RuntimeError):
    """A production mutation escaped its exact writer or SQL-function boundary."""


class RuntimeMutationGateway(Protocol):
    """Only the mutations the production video runtime is allowed to perform."""

    def activate_camera_epoch(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        camera_id: str,
        source_epoch: UUID,
        expected_source_epoch: UUID | None,
        activated_at: datetime,
    ) -> CameraEpochActivationReceiptV1: ...

    def get_event(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        event_id: UUID,
    ) -> CandidateEventV1: ...

    def store_provenanced_event(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        envelope: ProvenancedCandidateEventV2,
    ) -> PersistedCandidateEventV2: ...

    def set_candidate_evidence_status(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        event_id: UUID,
        target: Literal["pending", "failed"],
    ) -> Any: ...

    def finalize_evidence(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        evidence: EvidenceInput,
        status: Literal["ready", "failed"],
    ) -> Any: ...


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_DIGEST = re.compile(r"[a-f0-9]{64}")
_SUPPORTED_MODULES = frozenset(
    {
        "person",
        "restricted_zone",
        "intrusion",
        "loitering",
        "line_crossing",
        "fire_smoke",
        "weapon",
        "fight",
        "fall",
        "violence",
        "xclip",
        "vit",
    }
)


def _mapping(value: object, *, label: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise RuntimePersistenceError(
                f"{label} function returned invalid JSON"
            ) from exc
    if not isinstance(value, Mapping):
        raise RuntimePersistenceError(
            f"{label} function returned a non-object"
        )
    return dict(value)


def _exact_keys(
    value: Mapping[str, Any],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if set(value) != expected:
        raise RuntimePersistenceError(
            f"{label} fields do not match the immutable projection"
        )


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RuntimePersistenceError(f"{label} is not a canonical identifier")
    return value


def _nonempty(
    value: object,
    *,
    label: str,
    maximum: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise RuntimePersistenceError(f"{label} is not canonical text")
    return value


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RuntimePersistenceError(f"{label} is not a canonical digest")
    return value


def _positive_integer(value: object, *, label: str) -> int:
    if type(value) is not int or value < 1:
        raise RuntimePersistenceError(f"{label} must be a positive integer")
    return value


def _utc_datetime(value: object, *, label: str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuntimePersistenceError(
                f"{label} is not an ISO timestamp"
            ) from exc
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise RuntimePersistenceError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _dialect_name(
    repository: PilotRepository,
    selected: str | None,
) -> str:
    if selected is not None:
        return selected
    with repository.session_factory() as session:
        return session.get_bind().dialect.name


def _evidence_payload(
    evidence: EvidenceInput,
    *,
    status: Literal["ready", "failed"],
) -> dict[str, object]:
    return {
        "schema_version": "evidence-work.v1",
        "evidence_id": str(evidence.evidence_id),
        "event_id": str(evidence.event_id),
        "object_key": evidence.object_key,
        "sha256": evidence.sha256,
        "codec": evidence.codec,
        "start_at": evidence.start_at.isoformat(),
        "end_at": evidence.end_at.isoformat(),
        "source_reference": evidence.source_reference,
        "status": status,
    }


class RepositoryRuntimeMutationGateway:
    """Portable test/replay gateway using the repository's ordinary transactions."""

    __slots__ = ("_repository",)

    def __init__(self, repository: PilotRepository) -> None:
        self._repository = repository

    def get_event(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        event_id: UUID,
    ) -> CandidateEventV1:
        return self._repository.get_event(
            event_id,
            expected_site_id=receipt.site_id,
        )

    def store_provenanced_event(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        envelope: ProvenancedCandidateEventV2,
    ) -> PersistedCandidateEventV2:
        return self._repository.store_provenanced_event(
            envelope,
            receipt=receipt,
        )

    def activate_camera_epoch(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        camera_id: str,
        source_epoch: UUID,
        expected_source_epoch: UUID | None,
        activated_at: datetime,
    ) -> CameraEpochActivationReceiptV1:
        return self._repository.activate_camera_epoch(
            receipt=receipt,
            camera_id=camera_id,
            source_epoch=source_epoch,
            expected_source_epoch=expected_source_epoch,
            activated_at=activated_at,
        )

    def set_candidate_evidence_status(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        event_id: UUID,
        target: Literal["pending", "failed"],
    ) -> Any:
        del receipt
        if target == "pending":
            return self._repository.mark_candidate_evidence_pending(event_id)
        return self._repository.mark_candidate_evidence_failed(event_id)

    def finalize_evidence(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        evidence: EvidenceInput,
        status: Literal["ready", "failed"],
    ) -> Any:
        del receipt
        return self._repository.finalize_evidence(
            evidence,
            status=status,
        )


class PostgresRuntimeMutationGateway:
    """Invoke only security-definer runtime functions on PostgreSQL."""

    __slots__ = ("_repository", "_sessions")

    def __init__(
        self,
        *,
        repository: PilotRepository,
        sessions: SessionFactory,
    ) -> None:
        self._repository = repository
        self._sessions = sessions

    def get_event(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        event_id: UUID,
    ) -> CandidateEventV1:
        with self._sessions() as session:
            payload = session.scalar(
                text(
                    """
                    SELECT public.pilot_get_runtime_event(
                        :receipt,
                        :receipt_sha256,
                        CAST(:event_id AS uuid)
                    )
                    """
                ),
                {
                    "receipt": _canonical_json(
                        receipt.model_dump(mode="json")
                    ),
                    "receipt_sha256": receipt.authority_sha256,
                    "event_id": str(event_id),
                },
            )
        try:
            return CandidateEventV1.model_validate(
                _mapping(payload, label="runtime event")
            )
        except (TypeError, ValueError) as exc:
            raise RuntimePersistenceError(
                "runtime event function returned an invalid candidate"
            ) from exc

    def store_provenanced_event(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        envelope: ProvenancedCandidateEventV2,
    ) -> PersistedCandidateEventV2:
        if type(envelope) is not ProvenancedCandidateEventV2:
            raise TypeError(
                "runtime candidate write requires an exact provenance envelope"
            )
        provenance = envelope.provenance
        if (
            provenance.site_id != receipt.site_id
            or provenance.runtime_session_id != receipt.runtime_session_id
            or provenance.runtime_writer_generation
            != receipt.runtime_writer_generation
            or provenance.configuration_activation_generation
            != receipt.configuration_activation_generation
            or provenance.site_config_sha256 != receipt.site_config_sha256
            or provenance.ruleset_sha256 != receipt.ruleset_sha256
            or provenance.rule_revision_sha256
            != receipt.rule_revision_sha256(provenance.rule_id)
        ):
            raise RuntimePersistenceError(
                "candidate provenance escaped its writer receipt"
            )
        candidate_payload = envelope.event.model_dump(
            mode="json",
            exclude={"dedupe_key"},
        )
        candidate_payload["dedupe_key"] = envelope.event.dedupe_key
        provenance_payload = provenance.model_dump(mode="json")
        provenance_payload.update(
            {
                "ruleset_revision_id": receipt.ruleset_revision_id,
                "body_sha256": envelope.body_sha256,
                "body_canonical_json": envelope.canonical_body_json,
            }
        )
        with self._sessions.begin() as session:
            accepted_event_id = session.scalar(
                text(
                    """
                    SELECT public.pilot_ingest_candidate(
                        CAST(:candidate AS jsonb),
                        CAST(:provenance AS jsonb)
                    )
                    """
                ),
                {
                    "candidate": _canonical_json(candidate_payload),
                    "provenance": _canonical_json(provenance_payload),
                },
            )
            if accepted_event_id != str(envelope.event.event_id):
                raise RuntimePersistenceError(
                    "candidate ingest function returned a different identity"
                )
        return PersistedCandidateEventV2(
            event=envelope.event,
            provenance=provenance,
        )

    def activate_camera_epoch(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        camera_id: str,
        source_epoch: UUID,
        expected_source_epoch: UUID | None,
        activated_at: datetime,
    ) -> CameraEpochActivationReceiptV1:
        _identifier(camera_id, label="camera epoch camera")
        if type(source_epoch) is not UUID or (
            expected_source_epoch is not None
            and type(expected_source_epoch) is not UUID
        ):
            raise TypeError("camera epoch identities must be exact UUIDs")
        activated_at = _utc_datetime(
            activated_at,
            label="camera epoch activation",
        )
        with self._sessions.begin() as session:
            accepted = session.scalar(
                text(
                    """
                    SELECT public.pilot_activate_runtime_camera_epoch(
                        :receipt,
                        :receipt_sha256,
                        :camera_id,
                        CAST(:source_epoch AS uuid),
                        CAST(:expected_source_epoch AS uuid),
                        :activated_at
                    )
                    """
                ),
                {
                    "receipt": _canonical_json(
                        receipt.model_dump(mode="json")
                    ),
                    "receipt_sha256": receipt.authority_sha256,
                    "camera_id": camera_id,
                    "source_epoch": str(source_epoch),
                    "expected_source_epoch": (
                        None
                        if expected_source_epoch is None
                        else str(expected_source_epoch)
                    ),
                    "activated_at": activated_at,
                },
            )
            if accepted is not True:
                raise RuntimePersistenceError(
                    "camera epoch function did not confirm its mutation"
                )
        return CameraEpochActivationReceiptV1(
            site_id=receipt.site_id,
            camera_id=camera_id,
            source_epoch=source_epoch,
            previous_source_epoch=expected_source_epoch,
            runtime_session_id=receipt.runtime_session_id,
            runtime_writer_generation=(
                receipt.runtime_writer_generation
            ),
            configuration_activation_generation=(
                receipt.configuration_activation_generation
            ),
            activated_at=activated_at,
        )

    def set_candidate_evidence_status(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        event_id: UUID,
        target: Literal["pending", "failed"],
    ) -> Any:
        with self._sessions.begin() as session:
            payload = session.scalar(
                text(
                    """
                    SELECT public.pilot_set_runtime_candidate_evidence_status(
                        :receipt,
                        :receipt_sha256,
                        CAST(:event_id AS uuid),
                        :target
                    )
                    """
                ),
                {
                    "receipt": _canonical_json(
                        receipt.model_dump(mode="json")
                    ),
                    "receipt_sha256": receipt.authority_sha256,
                    "event_id": str(event_id),
                    "target": target,
                },
            )
        try:
            return CandidateEventV1.model_validate(
                _mapping(payload, label="candidate evidence")
            )
        except (TypeError, ValueError) as exc:
            raise RuntimePersistenceError(
                "candidate evidence function returned an invalid candidate"
            ) from exc

    def finalize_evidence(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        evidence: EvidenceInput,
        status: Literal["ready", "failed"],
    ) -> EvidenceInput:
        if type(evidence) is not EvidenceInput:
            raise TypeError("terminal evidence requires an exact input")
        if status not in ("ready", "failed"):
            raise RuntimePersistenceError(
                "terminal evidence status is invalid"
            )
        if type(evidence.evidence_id) is not UUID or type(
            evidence.event_id
        ) is not UUID:
            raise TypeError("terminal evidence identities must be exact UUIDs")
        if evidence.object_key != f"events/{evidence.event_id}.mp4":
            raise RuntimePersistenceError(
                "terminal evidence object key escaped its event"
            )
        _digest(evidence.sha256, label="terminal evidence digest")
        _nonempty(
            evidence.source_reference,
            label="terminal evidence source",
            maximum=2048,
        )
        start_at = _utc_datetime(
            evidence.start_at,
            label="terminal evidence start",
        )
        end_at = _utc_datetime(
            evidence.end_at,
            label="terminal evidence end",
        )
        normalized = replace(
            evidence,
            start_at=start_at,
            end_at=end_at,
        )
        with self._sessions.begin() as session:
            accepted = session.scalar(
                text(
                    """
                    SELECT public.pilot_finalize_runtime_evidence(
                        :receipt,
                        :receipt_sha256,
                        CAST(:evidence AS jsonb)
                    )
                    """
                ),
                {
                    "receipt": _canonical_json(
                        receipt.model_dump(mode="json")
                    ),
                    "receipt_sha256": receipt.authority_sha256,
                    "evidence": _canonical_json(
                        _evidence_payload(normalized, status=status)
                    ),
                },
            )
            if accepted is not True:
                raise RuntimePersistenceError(
                    "evidence function did not confirm its mutation"
                )
        return replace(normalized, status=status)


class RuntimeBoundPilotRepository:
    """Bind every runtime-side mutation to one opaque writer capability."""

    __slots__ = ("_gateway", "_repository", "_writer_receipt")

    def __init__(
        self,
        *,
        repository: Any,
        writer_receipt: RuntimeWriterReceiptV1,
        mutation_gateway: RuntimeMutationGateway,
    ) -> None:
        if type(writer_receipt) is not RuntimeWriterReceiptV1:
            raise TypeError(
                "production repository requires a runtime writer receipt"
            )
        required_repository_methods = (
            "get_event",
            "store_provenanced_event",
            "prepare_preview_publication",
            "finalize_preview_receipt",
            "get_preview_object_context",
        )
        if any(
            not callable(getattr(repository, method, None))
            for method in required_repository_methods
        ):
            raise TypeError("production repository delegate is incomplete")
        required_gateway_methods = (
            "activate_camera_epoch",
            "get_event",
            "store_provenanced_event",
            "set_candidate_evidence_status",
            "finalize_evidence",
        )
        if any(
            not callable(getattr(mutation_gateway, method, None))
            for method in required_gateway_methods
        ):
            raise TypeError("production mutation gateway is incomplete")
        self._repository = repository
        self._writer_receipt = writer_receipt
        self._gateway = mutation_gateway

    @property
    def writer_receipt(self) -> RuntimeWriterReceiptV1:
        return self._writer_receipt

    def get_event(
        self,
        event_id: UUID,
        *,
        expected_site_id: str | None = None,
    ) -> Any:
        site_id = (
            self._writer_receipt.site_id
            if expected_site_id is None
            else expected_site_id
        )
        if site_id != self._writer_receipt.site_id:
            raise RuntimePersistenceError(
                "runtime event read escaped its writer site"
            )
        return self._gateway.get_event(
            receipt=self._writer_receipt,
            event_id=event_id,
        )

    def store_provenanced_event(
        self,
        envelope: Any,
        *,
        receipt: RuntimeWriterReceiptV1,
    ) -> Any:
        if receipt is not self._writer_receipt:
            raise RuntimePersistenceError(
                "candidate write used different writer authority"
            )
        return self._gateway.store_provenanced_event(
            receipt=receipt,
            envelope=envelope,
        )

    def activate_camera_epoch(
        self,
        *,
        receipt: RuntimeWriterReceiptV1 | None = None,
        camera_id: str,
        source_epoch: UUID,
        expected_source_epoch: UUID | None,
        activated_at: datetime,
    ) -> CameraEpochActivationReceiptV1:
        selected = self._writer_receipt if receipt is None else receipt
        if selected is not self._writer_receipt:
            raise RuntimePersistenceError(
                "camera epoch used different writer authority"
            )
        return self._gateway.activate_camera_epoch(
            receipt=selected,
            camera_id=camera_id,
            source_epoch=source_epoch,
            expected_source_epoch=expected_source_epoch,
            activated_at=activated_at,
        )

    def mark_candidate_evidence_pending(self, event_id: UUID) -> Any:
        return self._gateway.set_candidate_evidence_status(
            receipt=self._writer_receipt,
            event_id=event_id,
            target="pending",
        )

    def mark_candidate_evidence_failed(self, event_id: UUID) -> Any:
        return self._gateway.set_candidate_evidence_status(
            receipt=self._writer_receipt,
            event_id=event_id,
            target="failed",
        )

    def finalize_evidence(
        self,
        evidence: EvidenceInput,
        *,
        status: Literal["ready", "failed"],
    ) -> Any:
        return self._gateway.finalize_evidence(
            receipt=self._writer_receipt,
            evidence=evidence,
            status=status,
        )

    def persist_journal_item(self, item: JournalItem) -> None:
        if type(item) is not JournalItem:
            raise TypeError("runtime journal persistence requires an exact item")
        validate_journal_work(
            item.kind,
            item.schema_version,
            item.payload,
        )
        if item.kind in (
            "candidate_event",
            "provenanced_candidate_event",
        ):
            raise RuntimePersistenceError(
                "runtime candidate replay must use the provenance authority"
            )
        if item.kind == "evidence":
            evidence = EvidenceInput.from_payload(item.payload)
            if evidence.status not in ("ready", "failed"):
                raise RuntimePersistenceError(
                    "runtime evidence journal must be terminal"
                )
            self.finalize_evidence(
                evidence,
                status=evidence.status,
            )
            return
        intent = EvidenceIntent.from_payload(item.payload)
        if intent.status != "failed":
            raise RuntimePersistenceError(
                "runtime evidence intent journal must be failed"
            )
        self.mark_candidate_evidence_failed(intent.event_id)

    def get_preview_object_context(self, **kwargs: Any) -> Any:
        return self._repository.get_preview_object_context(**kwargs)

    def prepare_preview_publication(self, **kwargs: Any) -> Any:
        return self._repository.prepare_preview_publication(**kwargs)

    def finalize_preview_receipt(self, **kwargs: Any) -> None:
        self._repository.finalize_preview_receipt(**kwargs)


_ACTIVE_FIELDS = (
    "site_id",
    "activation_generation",
    "config_revision_id",
    "ruleset_revision_id",
    "activated_by",
    "activated_at",
)
_WRITER_FIELDS = (
    "site_id",
    "runtime_session_id",
    "writer_generation",
    "configuration_activation_generation",
    "issued_at",
)
_WRITER_SESSION_FIELDS = (
    "runtime_session_id",
    "site_id",
    "writer_generation",
    "configuration_activation_generation",
    "issued_at",
    "receipt_sha256",
)
_CONFIG_FIELDS = (
    "config_revision_id",
    "schema_version",
    "site_id",
    "revision",
    "config_sha256",
    "artifact_sha256",
    "signature_sha256",
    "signing_key_spki_sha256",
    "reviewed_by",
    "reviewed_at",
    "review_reference",
    "canonical_config",
    "created_at",
)
_RULESET_FIELDS = (
    "ruleset_revision_id",
    "schema_version",
    "ruleset_id",
    "revision",
    "site_id",
    "config_revision_id",
    "site_config_sha256",
    "frozen_workload_sha256",
    "engine_sha256",
    "runtime_manifest_sha256",
    "ruleset_sha256",
    "artifact_sha256",
    "signature_sha256",
    "signing_key_spki_sha256",
    "reviewed_by",
    "reviewed_at",
    "review_reference",
    "created_at",
)
_RULE_FIELDS = (
    "ruleset_revision_id",
    "rule_id",
    "schema_version",
    "revision",
    "site_id",
    "camera_id",
    "module",
    "enabled",
    "model_artifact_id",
    "model_decision_sha256",
    "gate_mode",
    "minimum_confidence",
    "minimum_votes",
    "sample_count",
    "window_seconds",
    "evidence_seconds",
    "rule_spec",
    "rule_revision_sha256",
    "created_at",
)


def _row_payload(row: object, fields: tuple[str, ...]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for field in fields:
        value = getattr(row, field)
        if isinstance(value, datetime) and value.tzinfo is None:
            # SQLite drops the declared timezone marker. All repository
            # timestamps are stored as UTC; restore that marker only on this
            # portable test/replay projection before strict validation.
            value = value.replace(tzinfo=timezone.utc)
        payload[field] = value
    return payload


def _sqlite_runtime_projection(
    repository: PilotRepository,
    receipt: RuntimeWriterReceiptV1,
) -> dict[str, Any]:
    session = repository.session_factory()
    try:
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        active = session.get(
            ActivePilotConfigurationModel,
            receipt.site_id,
        )
        writer = session.get(
            RuntimeWriterAuthorityModel,
            receipt.site_id,
        )
        writer_session = session.get(
            RuntimeWriterSessionModel,
            receipt.runtime_session_id,
        )
        config = (
            None
            if active is None
            else session.get(
                SiteConfigRevisionModel,
                active.config_revision_id,
            )
        )
        ruleset = (
            None
            if active is None
            else session.get(
                CameraRulesetRevisionModel,
                active.ruleset_revision_id,
            )
        )
        rules = (
            []
            if active is None
            else list(
                session.scalars(
                    select(CameraRuleRevisionModel)
                    .where(
                        CameraRuleRevisionModel.ruleset_revision_id
                        == active.ruleset_revision_id
                    )
                    .order_by(
                        CameraRuleRevisionModel.camera_id,
                        CameraRuleRevisionModel.module,
                        CameraRuleRevisionModel.rule_id,
                        CameraRuleRevisionModel.revision,
                    )
                )
            )
        )
        if any(
            row is None
            for row in (
                active,
                writer,
                writer_session,
                config,
                ruleset,
            )
        ):
            raise RuntimePersistenceError(
                "active runtime configuration is incomplete"
            )
        assert active is not None
        assert writer is not None
        assert writer_session is not None
        assert config is not None
        assert ruleset is not None
        payload = {
            "schema_version": "runtime-configuration-projection.v1",
            "active": _row_payload(active, _ACTIVE_FIELDS),
            "writer": _row_payload(writer, _WRITER_FIELDS),
            "writer_session": _row_payload(
                writer_session,
                _WRITER_SESSION_FIELDS,
            ),
            "config": _row_payload(config, _CONFIG_FIELDS),
            "ruleset": _row_payload(ruleset, _RULESET_FIELDS),
            "rules": [
                _row_payload(rule, _RULE_FIELDS)
                for rule in rules
            ],
        }
        session.commit()
        return payload
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def _validate_runtime_projection(
    payload: object,
    receipt: RuntimeWriterReceiptV1,
    *,
    expected_frozen_workload_sha256: str,
    expected_engine_sha256: str,
    expected_runtime_manifest_sha256: str,
) -> tuple[SiteConfig, tuple[CompiledCameraRuleV1, ...]]:
    projection = _mapping(payload, label="runtime configuration")
    _exact_keys(
        projection,
        frozenset(
            {
                "schema_version",
                "active",
                "writer",
                "writer_session",
                "config",
                "ruleset",
                "rules",
            }
        ),
        label="runtime configuration",
    )
    if (
        projection["schema_version"]
        != "runtime-configuration-projection.v1"
    ):
        raise RuntimePersistenceError(
            "runtime configuration projection schema is unsupported"
        )

    active = _mapping(projection["active"], label="active configuration")
    writer = _mapping(projection["writer"], label="runtime writer")
    writer_session = _mapping(
        projection["writer_session"],
        label="runtime writer history",
    )
    config = _mapping(projection["config"], label="site configuration")
    ruleset = _mapping(projection["ruleset"], label="camera ruleset")
    _exact_keys(
        active,
        frozenset(_ACTIVE_FIELDS),
        label="active configuration",
    )
    _exact_keys(
        writer,
        frozenset(_WRITER_FIELDS),
        label="runtime writer",
    )
    _exact_keys(
        writer_session,
        frozenset(_WRITER_SESSION_FIELDS),
        label="runtime writer history",
    )
    _exact_keys(
        config,
        frozenset(_CONFIG_FIELDS),
        label="site configuration",
    )
    _exact_keys(
        ruleset,
        frozenset(_RULESET_FIELDS),
        label="camera ruleset",
    )

    active_site = _identifier(active["site_id"], label="active site")
    active_generation = _positive_integer(
        active["activation_generation"],
        label="active generation",
    )
    active_config_id = _identifier(
        active["config_revision_id"],
        label="active config revision",
    )
    active_ruleset_id = _identifier(
        active["ruleset_revision_id"],
        label="active ruleset revision",
    )
    _identifier(active["activated_by"], label="configuration activator")
    _utc_datetime(active["activated_at"], label="configuration activation")
    if (
        active_site != receipt.site_id
        or active_generation
        != receipt.configuration_activation_generation
        or active_config_id != receipt.config_revision_id
        or active_ruleset_id != receipt.ruleset_revision_id
    ):
        raise RuntimePersistenceError(
            "active configuration escaped the writer receipt"
        )

    if (
        _identifier(writer["site_id"], label="writer site")
        != receipt.site_id
        or _identifier(
            writer["runtime_session_id"],
            label="writer session",
        )
        != receipt.runtime_session_id
        or _positive_integer(
            writer["writer_generation"],
            label="writer generation",
        )
        != receipt.runtime_writer_generation
        or _positive_integer(
            writer["configuration_activation_generation"],
            label="writer activation generation",
        )
        != receipt.configuration_activation_generation
        or _utc_datetime(
            writer["issued_at"],
            label="writer issue time",
        )
        != receipt.issued_at
    ):
        raise RuntimePersistenceError(
            "current runtime writer does not match its receipt"
        )

    if (
        _identifier(
            writer_session["runtime_session_id"],
            label="writer history session",
        )
        != receipt.runtime_session_id
        or _identifier(
            writer_session["site_id"],
            label="writer history site",
        )
        != receipt.site_id
        or _positive_integer(
            writer_session["writer_generation"],
            label="writer history generation",
        )
        != receipt.runtime_writer_generation
        or _positive_integer(
            writer_session["configuration_activation_generation"],
            label="writer history activation",
        )
        != receipt.configuration_activation_generation
        or _utc_datetime(
            writer_session["issued_at"],
            label="writer history issue time",
        )
        != receipt.issued_at
        or _digest(
            writer_session["receipt_sha256"],
            label="writer history receipt",
        )
        != receipt.authority_sha256
    ):
        raise RuntimePersistenceError(
            "runtime writer history does not match its receipt"
        )

    if (
        config["schema_version"] != "reviewed-site-config.v1"
        or _identifier(
            config["config_revision_id"],
            label="site config revision",
        )
        != receipt.config_revision_id
        or _identifier(config["site_id"], label="site config site")
        != receipt.site_id
        or _positive_integer(
            config["revision"],
            label="site config revision number",
        )
        < 1
        or _digest(
            config["config_sha256"],
            label="site configuration digest",
        )
        != receipt.site_config_sha256
    ):
        raise RuntimePersistenceError(
            "site configuration metadata escaped the writer receipt"
        )
    for field in (
        "artifact_sha256",
        "signature_sha256",
        "signing_key_spki_sha256",
    ):
        _digest(config[field], label=f"site config {field}")
    _nonempty(
        config["reviewed_by"],
        label="site config reviewer",
        maximum=255,
    )
    _utc_datetime(config["reviewed_at"], label="site config review time")
    _nonempty(
        config["review_reference"],
        label="site config review reference",
        maximum=2048,
    )
    _utc_datetime(config["created_at"], label="site config creation time")
    try:
        site = SiteConfig.model_validate(config["canonical_config"])
    except (TypeError, ValueError) as exc:
        raise RuntimePersistenceError(
            "canonical site configuration is invalid"
        ) from exc
    if site_config_sha256(site) != receipt.site_config_sha256:
        raise RuntimePersistenceError(
            "canonical site configuration digest does not match authority"
        )

    if (
        ruleset["schema_version"] != "reviewed-camera-ruleset.v1"
        or _identifier(
            ruleset["ruleset_revision_id"],
            label="ruleset revision",
        )
        != receipt.ruleset_revision_id
        or _identifier(ruleset["site_id"], label="ruleset site")
        != receipt.site_id
        or _identifier(
            ruleset["config_revision_id"],
            label="ruleset config revision",
        )
        != receipt.config_revision_id
        or _digest(
            ruleset["site_config_sha256"],
            label="ruleset site config digest",
        )
        != receipt.site_config_sha256
        or _digest(
            ruleset["ruleset_sha256"],
            label="ruleset digest",
        )
        != receipt.ruleset_sha256
    ):
        raise RuntimePersistenceError(
            "camera ruleset metadata escaped the writer receipt"
        )
    _identifier(ruleset["ruleset_id"], label="ruleset identity")
    _positive_integer(ruleset["revision"], label="ruleset revision number")
    reviewed_runtime_bindings = {}
    for field in (
        "frozen_workload_sha256",
        "engine_sha256",
        "runtime_manifest_sha256",
        "artifact_sha256",
        "signature_sha256",
        "signing_key_spki_sha256",
    ):
        reviewed_runtime_bindings[field] = _digest(
            ruleset[field],
            label=f"ruleset {field}",
        )
    if (
        reviewed_runtime_bindings["frozen_workload_sha256"]
        != expected_frozen_workload_sha256
        or reviewed_runtime_bindings["engine_sha256"]
        != expected_engine_sha256
        or reviewed_runtime_bindings["runtime_manifest_sha256"]
        != expected_runtime_manifest_sha256
    ):
        raise RuntimePersistenceError(
            "active camera ruleset does not match the mounted runtime manifest"
        )
    _nonempty(
        ruleset["reviewed_by"],
        label="ruleset reviewer",
        maximum=255,
    )
    _utc_datetime(ruleset["reviewed_at"], label="ruleset review time")
    _nonempty(
        ruleset["review_reference"],
        label="ruleset review reference",
        maximum=2048,
    )
    _utc_datetime(ruleset["created_at"], label="ruleset creation time")

    rule_values = projection["rules"]
    if (
        not isinstance(rule_values, list)
        or not 1 <= len(rule_values) <= 512
    ):
        raise RuntimePersistenceError(
            "runtime rule projection must contain 1..512 rules"
        )
    feeds = {
        feed.camera_id: feed
        for feed in site.ready_to_start.feeds
    }
    compiled: list[CompiledCameraRuleV1] = []
    persisted_digests: dict[str, str] = {}
    camera_modules: set[tuple[str, str]] = set()
    for index, raw_rule in enumerate(rule_values):
        rule = _mapping(raw_rule, label=f"camera rule {index}")
        _exact_keys(
            rule,
            frozenset(_RULE_FIELDS),
            label=f"camera rule {index}",
        )
        rule_id = _identifier(rule["rule_id"], label="rule identity")
        camera_id = _identifier(rule["camera_id"], label="rule camera")
        module = _nonempty(
            rule["module"],
            label="rule module",
            maximum=128,
        )
        if module not in _SUPPORTED_MODULES:
            raise RuntimePersistenceError(
                "runtime rule module is outside the controlled pilot"
            )
        if (
            _identifier(
                rule["ruleset_revision_id"],
                label="rule ruleset revision",
            )
            != receipt.ruleset_revision_id
            or rule["schema_version"] != "camera-rule.v1"
            or _identifier(rule["site_id"], label="rule site")
            != receipt.site_id
            or camera_id not in feeds
        ):
            raise RuntimePersistenceError(
                "camera rule escaped its active site or ruleset"
            )
        revision = _positive_integer(
            rule["revision"],
            label="rule revision",
        )
        if type(rule["enabled"]) is not bool:
            raise RuntimePersistenceError(
                "camera rule enabled flag is not strict"
            )
        model_artifact_id = _nonempty(
            rule["model_artifact_id"],
            label="rule model artifact",
            maximum=255,
        )
        model_decision_sha256 = _digest(
            rule["model_decision_sha256"],
            label="rule model decision",
        )
        gate_mode = rule["gate_mode"]
        if gate_mode not in ("disabled", "shadow", "operator"):
            raise RuntimePersistenceError("camera rule gate mode is invalid")
        if (
            module in {"fight", "fall", "violence", "xclip", "vit"}
            and gate_mode == "operator"
        ):
            raise RuntimePersistenceError(
                "heavy verifier rule escaped shadow-only policy"
            )
        minimum_confidence = rule["minimum_confidence"]
        window_seconds = rule["window_seconds"]
        if (
            isinstance(minimum_confidence, bool)
            or not isinstance(minimum_confidence, (int, float))
            or not math.isfinite(minimum_confidence)
            or not 0.0 <= float(minimum_confidence) <= 1.0
            or isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not math.isfinite(window_seconds)
            or not 0.0 < float(window_seconds) <= 60.0
        ):
            raise RuntimePersistenceError(
                "camera rule numeric bounds are invalid"
            )
        minimum_votes = _positive_integer(
            rule["minimum_votes"],
            label="rule minimum votes",
        )
        sample_count = _positive_integer(
            rule["sample_count"],
            label="rule sample count",
        )
        evidence_seconds = _positive_integer(
            rule["evidence_seconds"],
            label="rule evidence seconds",
        )
        if (
            minimum_votes > 64
            or sample_count > 64
            or sample_count < minimum_votes
            or not 4 <= evidence_seconds <= 10
        ):
            raise RuntimePersistenceError(
                "camera rule vote or evidence bounds are invalid"
            )
        rule_digest = _digest(
            rule["rule_revision_sha256"],
            label="rule digest",
        )
        if (
            receipt.rule_revision_digests.get(rule_id)
            != rule_digest
        ):
            raise RuntimePersistenceError(
                "persisted rule digest does not match writer authority"
            )
        _utc_datetime(rule["created_at"], label="rule creation time")
        schedule_module = (
            "person"
            if module
            in {
                "restricted_zone",
                "intrusion",
                "loitering",
                "line_crossing",
            }
            else module
        )
        if (
            rule["enabled"]
            and (
                feeds[camera_id].analytics_hz.get(schedule_module) is None
                or feeds[camera_id].analytics_hz[schedule_module] <= 0.0
            )
        ):
            raise RuntimePersistenceError(
                "enabled rule is absent from the reviewed camera schedule"
            )
        if rule_id in persisted_digests or (
            camera_id,
            module,
        ) in camera_modules:
            raise RuntimePersistenceError(
                "runtime rule projection contains duplicate authority"
            )
        try:
            compiled_rule = CompiledCameraRuleV1(
                rule_id=rule_id,
                revision=revision,
                site_id=receipt.site_id,
                camera_id=camera_id,
                module=module,
                enabled=rule["enabled"],
                model_artifact_id=model_artifact_id,
                model_decision_sha256=model_decision_sha256,
                gate_mode=gate_mode,
                minimum_confidence=float(minimum_confidence),
                minimum_votes=minimum_votes,
                sample_count=sample_count,
                window_seconds=float(window_seconds),
                evidence_seconds=evidence_seconds,
                spec=rule["rule_spec"],
                rule_revision_sha256=rule_digest,
            )
        except (TypeError, ValueError) as exc:
            raise RuntimePersistenceError(
                "persisted compiled rule projection is invalid"
            ) from exc
        if module in {
            "restricted_zone",
            "intrusion",
            "loitering",
        }:
            expected_mode = (
                "loitering" if module == "loitering" else "intrusion"
            )
            if (
                not isinstance(compiled_rule.spec, ZoneRuleSpecV1)
                or compiled_rule.spec.mode != expected_mode
            ):
                raise RuntimePersistenceError(
                    "persisted rule spec does not match its zone module"
                )
        elif module == "line_crossing":
            if (
                not isinstance(compiled_rule.spec, LineRuleSpecV1)
                or minimum_votes != 1
                or sample_count != 1
            ):
                raise RuntimePersistenceError(
                    "persisted rule spec does not match its line module"
                )
        elif not isinstance(compiled_rule.spec, ModuleRuleSpecV1):
            raise RuntimePersistenceError(
                "persisted rule spec does not match its analytic module"
            )
        persisted_digests[rule_id] = rule_digest
        camera_modules.add((camera_id, module))
        compiled.append(compiled_rule)
    if persisted_digests != dict(receipt.rule_revision_digests):
        raise RuntimePersistenceError(
            "runtime rule membership does not match writer authority"
        )
    compiled.sort(
        key=lambda rule: (
            rule.camera_id,
            rule.module,
            rule.rule_id,
            rule.revision,
        )
    )
    return site, tuple(compiled)


def _receipt_from_claim_state(
    payload: object,
    *,
    site_id: str,
    runtime_session_id: str,
    issued_at: datetime,
    expected_writer_generation: int | None,
) -> RuntimeWriterReceiptV1:
    state = _mapping(payload, label="runtime claim state")
    _exact_keys(
        state,
        frozenset(
            {
                "schema_version",
                "site_id",
                "activation_generation",
                "config_revision_id",
                "site_config_sha256",
                "ruleset_revision_id",
                "ruleset_sha256",
                "rule_revision_digests",
                "current_runtime_session_id",
                "current_writer_generation",
                "writer_configuration_activation_generation",
                "writer_issued_at",
            }
        ),
        label="runtime claim state",
    )
    if state["schema_version"] != "runtime-claim-state.v1":
        raise RuntimePersistenceError(
            "runtime claim state schema is unsupported"
        )
    active_generation = _positive_integer(
        state["activation_generation"],
        label="claim activation generation",
    )
    current_generation = _positive_integer(
        state["current_writer_generation"],
        label="claim writer generation",
    )
    if (
        _identifier(state["site_id"], label="claim site") != site_id
        or _positive_integer(
            state["writer_configuration_activation_generation"],
            label="claim writer activation",
        )
        != active_generation
    ):
        raise RuntimePersistenceError(
            "runtime claim state has inconsistent authority"
        )
    if (
        expected_writer_generation is not None
        and expected_writer_generation != current_generation
    ):
        raise RuntimePersistenceError(
            "runtime claim expected a different writer generation"
        )
    current_session = state["current_runtime_session_id"]
    if current_session is not None:
        current_session = _identifier(
            current_session,
            label="current writer session",
        )
    current_issued_at = _utc_datetime(
        state["writer_issued_at"],
        label="current writer issue time",
    )
    if issued_at < current_issued_at:
        raise RuntimePersistenceError(
            "runtime writer issue time cannot regress"
        )
    if (
        current_session == runtime_session_id
        and issued_at != current_issued_at
    ):
        raise RuntimePersistenceError(
            "runtime writer replay changed its issue time"
        )
    predicted_generation = current_generation + int(
        current_session is not None
        and current_session != runtime_session_id
    )
    raw_rule_digests = state["rule_revision_digests"]
    if (
        not isinstance(raw_rule_digests, Mapping)
        or not 1 <= len(raw_rule_digests) <= 512
    ):
        raise RuntimePersistenceError(
            "runtime claim rule authority is incomplete"
        )
    rule_digests = {
        _identifier(rule_id, label="claim rule identity"): _digest(
            digest,
            label="claim rule digest",
        )
        for rule_id, digest in raw_rule_digests.items()
    }
    return _issue_runtime_writer_receipt(
        site_id=site_id,
        runtime_session_id=runtime_session_id,
        runtime_writer_generation=predicted_generation,
        configuration_activation_generation=active_generation,
        config_revision_id=_identifier(
            state["config_revision_id"],
            label="claim config revision",
        ),
        site_config_sha256=_digest(
            state["site_config_sha256"],
            label="claim site configuration",
        ),
        ruleset_revision_id=_identifier(
            state["ruleset_revision_id"],
            label="claim ruleset revision",
        ),
        ruleset_sha256=_digest(
            state["ruleset_sha256"],
            label="claim ruleset",
        ),
        rule_revision_digests=rule_digests,
        issued_at=issued_at,
    )


def claim_runtime_writer(
    repository: PilotRepository,
    site_id: str,
    runtime_session_id: str,
    issued_at: datetime,
    expected_writer_generation: int | None = None,
    *,
    dialect_name: str | None = None,
) -> RuntimeWriterReceiptV1:
    """Atomically claim one exact active configuration for one runtime session."""

    _identifier(site_id, label="runtime site")
    _identifier(runtime_session_id, label="runtime session")
    issued_at = _utc_datetime(issued_at, label="runtime writer issue time")
    if (
        expected_writer_generation is not None
        and (
            type(expected_writer_generation) is not int
            or expected_writer_generation < 1
        )
    ):
        raise ValueError(
            "expected runtime writer generation must be a positive integer"
        )
    dialect = _dialect_name(repository, dialect_name)
    if dialect == "sqlite":
        selected_generation = expected_writer_generation
        if selected_generation is None:
            with repository.session_factory() as session:
                writer = session.get(
                    RuntimeWriterAuthorityModel,
                    site_id,
                )
                if writer is None:
                    raise RuntimePersistenceError(
                        "active configuration has no writer fence"
                    )
                selected_generation = writer.writer_generation
        return repository.issue_runtime_writer_receipt(
            site_id=site_id,
            runtime_session_id=runtime_session_id,
            issued_at=issued_at,
            expected_writer_generation=selected_generation,
        )
    if dialect != "postgresql":
        raise RuntimePersistenceError(
            "production persistence dialect is unsupported"
        )

    with repository.session_factory() as session:
        claim_state = session.scalar(
            text(
                """
                SELECT public.pilot_get_runtime_claim_state(:site_id)
                """
            ),
            {"site_id": site_id},
        )
    receipt = _receipt_from_claim_state(
        claim_state,
        site_id=site_id,
        runtime_session_id=runtime_session_id,
        issued_at=issued_at,
        expected_writer_generation=expected_writer_generation,
    )
    canonical_receipt = _canonical_json(receipt.model_dump(mode="json"))
    with repository.session_factory.begin() as session:
        accepted_digest = session.scalar(
            text(
                """
                SELECT public.pilot_claim_runtime_writer(
                    :receipt,
                    :receipt_sha256
                )
                """
            ),
            {
                "receipt": canonical_receipt,
                "receipt_sha256": receipt.authority_sha256,
            },
        )
        if accepted_digest != receipt.authority_sha256:
            raise RuntimePersistenceError(
                "runtime writer claim did not return its exact authority"
            )
    return receipt


def load_runtime_configuration(
    repository: PilotRepository,
    receipt: RuntimeWriterReceiptV1,
    *,
    expected_frozen_workload_sha256: str,
    expected_engine_sha256: str,
    expected_runtime_manifest_sha256: str,
    dialect_name: str | None = None,
) -> tuple[SiteConfig, tuple[CompiledCameraRuleV1, ...]]:
    """Load a validated compiled projection bound to one current writer receipt."""

    if type(receipt) is not RuntimeWriterReceiptV1:
        raise TypeError(
            "runtime configuration requires a repository-issued receipt"
        )
    expected_frozen_workload_sha256 = _digest(
        expected_frozen_workload_sha256,
        label="mounted runtime frozen workload",
    )
    expected_engine_sha256 = _digest(
        expected_engine_sha256,
        label="mounted runtime engine",
    )
    expected_runtime_manifest_sha256 = _digest(
        expected_runtime_manifest_sha256,
        label="mounted runtime manifest",
    )
    dialect = _dialect_name(repository, dialect_name)
    if dialect == "sqlite":
        payload = _sqlite_runtime_projection(repository, receipt)
    elif dialect == "postgresql":
        with repository.session_factory() as session:
            payload = session.scalar(
                text(
                    """
                    SELECT public.pilot_get_runtime_configuration(
                        :receipt,
                        :receipt_sha256
                    )
                    """
                ),
                {
                    "receipt": _canonical_json(
                        receipt.model_dump(mode="json")
                    ),
                    "receipt_sha256": receipt.authority_sha256,
                },
            )
    else:
        raise RuntimePersistenceError(
            "production persistence dialect is unsupported"
        )
    return _validate_runtime_projection(
        payload,
        receipt,
        expected_frozen_workload_sha256=(
            expected_frozen_workload_sha256
        ),
        expected_engine_sha256=expected_engine_sha256,
        expected_runtime_manifest_sha256=(
            expected_runtime_manifest_sha256
        ),
    )


def bind_runtime_repository(
    *,
    repository: PilotRepository,
    writer_receipt: RuntimeWriterReceiptV1,
    dialect_name: str | None = None,
) -> RuntimeBoundPilotRepository:
    """Select the security-definer PostgreSQL path or portable test path."""

    dialect_name = _dialect_name(repository, dialect_name)
    gateway: RuntimeMutationGateway
    if dialect_name == "postgresql":
        gateway = PostgresRuntimeMutationGateway(
            repository=repository,
            sessions=repository.session_factory,
        )
    elif dialect_name == "sqlite":
        gateway = RepositoryRuntimeMutationGateway(repository)
    else:
        raise RuntimePersistenceError(
            "production persistence dialect is unsupported"
        )
    return RuntimeBoundPilotRepository(
        repository=repository,
        writer_receipt=writer_receipt,
        mutation_gateway=gateway,
    )


__all__ = (
    "PostgresRuntimeMutationGateway",
    "RepositoryRuntimeMutationGateway",
    "RuntimeBoundPilotRepository",
    "RuntimePersistenceError",
    "bind_runtime_repository",
    "claim_runtime_writer",
    "load_runtime_configuration",
)
