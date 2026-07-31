"""Runtime-only authority for provenance-bound candidate journal writes."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Literal, Protocol

from protector.pilot.domain import (
    CameraEpochActivationReceiptV1,
    CandidateEventProvenanceV1,
    PersistedCandidateEventV2,
    ProvenancedCandidateEventV2,
    RuntimeWriterReceiptV1,
)
from protector.pilot.runtime.event_engine import CandidateTrigger
from protector.pilot.storage.journal import JournalItem, validate_journal_work

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class RuntimeCandidateAuthorityError(RuntimeError):
    """Candidate issuance or replay did not match current runtime authority."""


def _identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _digest(value: str, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class ProvenanceRuleBinding:
    """One enabled reviewed rule projected into the runtime event engine."""

    rule_id: str
    revision: int
    rule_revision_sha256: str
    camera_id: str
    module: str
    model_artifact_id: str
    model_gate_decision_sha256: str
    gate_mode: Literal["shadow", "operator"]

    def __post_init__(self) -> None:
        _identifier(self.rule_id, label="rule_id")
        _identifier(self.camera_id, label="camera_id")
        _identifier(self.module, label="module")
        _identifier(self.model_artifact_id, label="model_artifact_id")
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 1
        ):
            raise ValueError("rule revision must be a positive integer")
        _digest(
            self.rule_revision_sha256,
            label="rule_revision_sha256",
        )
        _digest(
            self.model_gate_decision_sha256,
            label="model_gate_decision_sha256",
        )
        if self.gate_mode not in ("shadow", "operator"):
            raise ValueError("runtime candidate rules must be shadow or operator")


class RuntimeCandidateAuthority:
    """Bind triggers to the current writer, reviewed rule, and camera epoch."""

    __slots__ = (
        "_epochs",
        "_lock",
        "_rules",
        "_writer_receipt",
    )

    def __init__(
        self,
        *,
        writer_receipt: RuntimeWriterReceiptV1,
        rule_bindings: tuple[ProvenanceRuleBinding, ...],
    ) -> None:
        if type(writer_receipt) is not RuntimeWriterReceiptV1:
            raise TypeError("runtime candidate authority requires a writer receipt")
        if not rule_bindings or len(rule_bindings) > 512:
            raise ValueError("runtime candidate authority requires 1..512 rules")
        if any(type(binding) is not ProvenanceRuleBinding for binding in rule_bindings):
            raise TypeError("runtime rule bindings must be exact validated contracts")
        by_rule = {binding.rule_id: binding for binding in rule_bindings}
        if len(by_rule) != len(rule_bindings):
            raise ValueError("runtime rule identities must be unique")
        for binding in rule_bindings:
            if (
                writer_receipt.rule_revision_sha256(binding.rule_id)
                != binding.rule_revision_sha256
            ):
                raise ValueError(
                    "runtime rule binding differs from the writer receipt"
                )
        self._writer_receipt = writer_receipt
        self._rules = by_rule
        self._epochs: dict[str, CameraEpochActivationReceiptV1] = {}
        self._lock = threading.RLock()

    def __copy__(self) -> object:
        raise TypeError("runtime candidate authority cannot be copied")

    def __deepcopy__(self, _: object) -> object:
        raise TypeError("runtime candidate authority cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("runtime candidate authority cannot be serialized")

    def __reduce_ex__(self, _: int) -> object:
        raise TypeError("runtime candidate authority cannot be serialized")

    @property
    def writer_receipt(self) -> RuntimeWriterReceiptV1:
        return self._writer_receipt

    @property
    def active_camera_count(self) -> int:
        with self._lock:
            return len(self._epochs)

    def activate_camera_epoch(
        self,
        receipt: CameraEpochActivationReceiptV1,
    ) -> None:
        """Install only a repository-issued epoch that causally replaces current."""

        if type(receipt) is not CameraEpochActivationReceiptV1:
            raise TypeError("camera epoch activation requires an exact receipt")
        writer = self._writer_receipt
        if (
            receipt.site_id != writer.site_id
            or receipt.runtime_session_id != writer.runtime_session_id
            or receipt.runtime_writer_generation
            != writer.runtime_writer_generation
            or receipt.configuration_activation_generation
            != writer.configuration_activation_generation
            or receipt.activated_at < writer.issued_at
        ):
            raise RuntimeCandidateAuthorityError(
                "camera epoch does not belong to the current writer"
            )
        if not any(
            binding.camera_id == receipt.camera_id
            for binding in self._rules.values()
        ):
            raise RuntimeCandidateAuthorityError(
                "camera epoch has no enabled reviewed runtime rule"
            )
        with self._lock:
            current = self._epochs.get(receipt.camera_id)
            expected_previous = (
                None if current is None else current.source_epoch
            )
            if receipt.previous_source_epoch != expected_previous:
                raise RuntimeCandidateAuthorityError(
                    "camera epoch did not causally replace the current epoch"
                )
            if current is not None and current.source_epoch == receipt.source_epoch:
                raise RuntimeCandidateAuthorityError(
                    "camera source epoch cannot be reactivated"
                )
            self._epochs[receipt.camera_id] = receipt

    def build_envelope(
        self,
        trigger: CandidateTrigger,
    ) -> ProvenancedCandidateEventV2:
        """Issue one envelope only from an active camera epoch and reviewed rule."""

        if type(trigger) is not CandidateTrigger:
            raise TypeError("candidate envelope requires an exact engine trigger")
        try:
            binding = self._rules[trigger.rule_id]
        except KeyError as exc:
            raise RuntimeCandidateAuthorityError(
                "candidate rule is not authorized by the current writer"
            ) from exc
        event = trigger.event
        if (
            event.camera_id != binding.camera_id
            or event.module != binding.module
            or event.model_artifact_id != binding.model_artifact_id
            or event.gate_mode != binding.gate_mode
            or event.evidence_status != "pending"
            or event.review_status != "candidate"
            or event.transition_history != ("observation", "candidate")
        ):
            raise RuntimeCandidateAuthorityError(
                "candidate differs from its reviewed runtime rule"
            )
        with self._lock:
            epoch = self._epochs.get(event.camera_id)
        if epoch is None or epoch.source_epoch != trigger.stream_epoch:
            raise RuntimeCandidateAuthorityError(
                "candidate source epoch is not current for its camera"
            )
        writer = self._writer_receipt
        return ProvenancedCandidateEventV2(
            event=event,
            provenance=CandidateEventProvenanceV1(
                site_id=writer.site_id,
                runtime_session_id=writer.runtime_session_id,
                runtime_writer_generation=writer.runtime_writer_generation,
                configuration_activation_generation=(
                    writer.configuration_activation_generation
                ),
                source_epoch=trigger.stream_epoch,
                rule_id=binding.rule_id,
                rule_revision=binding.revision,
                rule_revision_sha256=binding.rule_revision_sha256,
                ruleset_sha256=writer.ruleset_sha256,
                site_config_sha256=writer.site_config_sha256,
                model_gate_decision_sha256=(
                    binding.model_gate_decision_sha256
                ),
                gate_mode=binding.gate_mode,
            ),
        )


class ProvenancedEventRepository(Protocol):
    def store_provenanced_event(
        self,
        envelope: ProvenancedCandidateEventV2,
        *,
        receipt: RuntimeWriterReceiptV1,
    ) -> PersistedCandidateEventV2: ...

    def persist_journal_item(self, item: JournalItem) -> None: ...


class RuntimeJournalProcessor:
    """Replay V2 candidates with one opaque writer capability; reject legacy writes."""

    __slots__ = ("_repository", "_writer_receipt")

    def __init__(
        self,
        *,
        repository: ProvenancedEventRepository,
        writer_receipt: RuntimeWriterReceiptV1,
    ) -> None:
        if type(writer_receipt) is not RuntimeWriterReceiptV1:
            raise TypeError("runtime replay requires a writer receipt")
        if not callable(getattr(repository, "store_provenanced_event", None)):
            raise TypeError("runtime replay repository is invalid")
        if not callable(getattr(repository, "persist_journal_item", None)):
            raise TypeError("runtime replay repository is invalid")
        self._repository = repository
        self._writer_receipt = writer_receipt

    def __copy__(self) -> object:
        raise TypeError("runtime journal processor cannot be copied")

    def __deepcopy__(self, _: object) -> object:
        raise TypeError("runtime journal processor cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("runtime journal processor cannot be serialized")

    def __reduce_ex__(self, _: int) -> object:
        raise TypeError("runtime journal processor cannot be serialized")

    def __call__(self, item: JournalItem) -> None:
        if type(item) is not JournalItem:
            raise TypeError("runtime replay requires an exact journal item")
        validate_journal_work(item.kind, item.schema_version, item.payload)
        if item.kind == "provenanced_candidate_event":
            envelope = ProvenancedCandidateEventV2.model_validate(item.payload)
            self._repository.store_provenanced_event(
                envelope,
                receipt=self._writer_receipt,
            )
            return
        if item.kind == "candidate_event":
            raise RuntimeCandidateAuthorityError(
                "production runtime cannot replay legacy candidate writes"
            )
        self._repository.persist_journal_item(item)
