"""Private C2 target authority and V2-run binding for additive acceptance V3."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import stat
import threading
import weakref
from pathlib import Path
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from protector.pilot.acceptance import ExecutionBindingV2
from protector.pilot.acceptance_authority import (
    AcceptanceRunSigner,
    AcceptanceAuthorityTrustContextV2,
    _require_authority_trust_context,
)
from protector.pilot.acceptance_channel import (
    _peek_channel_receipt,
    _require_channel_receipt,
)
from protector.pilot.acceptance_proof import (
    AcceptanceFinalEnvelopeV2,
    VerifiedAcceptanceJournalProofV2,
    verify_acceptance_journal_proof,
)
from protector.pilot.acceptance_source_profile import (
    VerifiedTargetSourceProfileAttestationV2,
    _require_verified_target_source_profile_attestation,
)
from protector.pilot.acceptance_target_controller import (
    _peek_controller_runtime_authority,
    _require_controller_runtime_authority,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.acceptance_transaction import (
    C2_CAPABILITY_TRANSACTION_LOCK,
)
from protector.pilot.acceptance_work import (
    _peek_verified_target_work,
    _require_verified_target_work,
)
from protector.pilot.config import FrozenModel
from protector.pilot.trusted_artifacts import verify_ed25519_payload

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeId = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$"),
]
_EXACT_RUNTIME_EPOCHS = 2
TARGET_RUNTIME_RESTART_CONTINUATION_AUTHORIZING = False


def _require_target_runtime_restart_continuation_authority() -> None:
    if TARGET_RUNTIME_RESTART_CONTINUATION_AUTHORIZING is not False:
        raise AssertionError(
            "runtime restart continuation flag cannot substitute for authority"
        )
    raise RuntimeError(
        "retained V3 runtime restart is non-authorizing: canonical +40s "
        "restart requires a fresh controller-owned launch request, nonce, "
        "channel, execution transition, asynchronous prewarm/work "
        "completion, and final C2 continuation binding"
    )


class _StrictFrozenModel(FrozenModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _aggregate(
    epochs: tuple[TargetEpochEvidenceV3, ...],
    field: str,
) -> str:
    return _sha(
        {
            "schema_version": "target-epoch-digest-list.v3",
            "field": field,
            "values": [getattr(epoch, field) for epoch in epochs],
        }
    )


class TargetEpochEvidenceV3(_StrictFrozenModel):
    """One controller/child epoch after native prewarm and real scheduled work."""

    schema_version: Literal["target-epoch-evidence.v3"]
    collector_id: SafeId
    site_id: SafeId
    campaign_id: SafeId
    gate: Literal["8h", "72h"]
    runtime_epoch: Annotated[int, Field(ge=1, le=2**63 - 1)]
    runtime_epoch_started_generation: Annotated[int, Field(ge=1, le=2**63 - 1)]
    launch_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    container_id: Digest
    launch_request_sha256: Digest
    runtime_identity_sha256: Digest
    gpu_inventory_sha256: Digest
    source_profile_sha256: Digest
    native_prewarm_sha256: Digest
    unique_work_plan_sha256: Digest
    unique_work_sha256: Digest
    completion_sha256: Digest
    runtime_epoch_started_monotonic_ns: Annotated[int, Field(ge=0, le=2**63 - 1)]
    identity_observed_monotonic_ns: Annotated[int, Field(ge=1, le=2**63 - 1)]
    prewarm_ready_at_monotonic_ns: Annotated[int, Field(ge=1, le=2**63 - 1)]
    measurement_started_monotonic_ns: Annotated[int, Field(ge=1, le=2**63 - 1)]
    measurement_completed_monotonic_ns: Annotated[int, Field(ge=1, le=2**63 - 1)]
    disposition: Literal["restart", "authorize"]
    analytics_publication_enabled_during_gate: Literal[False] = False

    @model_validator(mode="after")
    def ordered_epoch_window(self) -> TargetEpochEvidenceV3:
        if (
            self.runtime_epoch != self.runtime_epoch_started_generation
            or self.identity_observed_monotonic_ns
            < self.runtime_epoch_started_monotonic_ns
            or self.identity_observed_monotonic_ns
            - self.runtime_epoch_started_monotonic_ns
            > 3_000_000_000
            or self.prewarm_ready_at_monotonic_ns
            < self.identity_observed_monotonic_ns
            or self.measurement_started_monotonic_ns
            < self.prewarm_ready_at_monotonic_ns
            or self.measurement_completed_monotonic_ns
            - self.measurement_started_monotonic_ns
            != 60_000_000_000
        ):
            raise ValueError("target epoch prewarm/work ordering differs")
        return self

    @property
    def epoch_sha256(self) -> str:
        return _sha(self)


class TargetC2EvidenceV3(_StrictFrozenModel):
    schema_version: Literal["target-c2-evidence.v3"]
    collector_id: SafeId
    site_id: SafeId
    campaign_id: SafeId
    gate: Literal["8h", "72h"]
    epochs: Annotated[
        tuple[TargetEpochEvidenceV3, ...],
        Field(min_length=_EXACT_RUNTIME_EPOCHS, max_length=_EXACT_RUNTIME_EPOCHS),
    ]

    @field_validator("epochs", mode="before")
    @classmethod
    def epochs_are_strict(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            raise TypeError("target C2 epochs must be one finite sequence")
        return tuple(TargetEpochEvidenceV3.model_validate(item) for item in value)

    @model_validator(mode="after")
    def exact_restart_chain(self) -> TargetC2EvidenceV3:
        if (
            any(
                (
                    epoch.collector_id,
                    epoch.site_id,
                    epoch.campaign_id,
                    epoch.gate,
                )
                != (
                    self.collector_id,
                    self.site_id,
                    self.campaign_id,
                    self.gate,
                )
                for epoch in self.epochs
            )
            or tuple(epoch.runtime_epoch for epoch in self.epochs)
            != tuple(
                range(
                    self.epochs[0].runtime_epoch,
                    self.epochs[0].runtime_epoch + len(self.epochs),
                )
            )
            or tuple(epoch.runtime_epoch_started_generation for epoch in self.epochs)
            != tuple(epoch.runtime_epoch for epoch in self.epochs)
            or any(epoch.disposition != "restart" for epoch in self.epochs[:-1])
            or self.epochs[-1].disposition != "authorize"
            or len({epoch.launch_nonce for epoch in self.epochs}) != len(self.epochs)
            or len({epoch.container_id for epoch in self.epochs}) != len(self.epochs)
            or len({epoch.runtime_identity_sha256 for epoch in self.epochs})
            != len(self.epochs)
        ):
            raise ValueError(
                "target C2 requires ordered new-container restart epochs and one final authorization"
            )
        return self

    @property
    def evidence_sha256(self) -> str:
        return _sha(self)


class TargetExecutionTransitionEntryV3(_StrictFrozenModel):
    """One immutable step in the retained-runtime replacement journal."""

    schema_version: Literal["target-execution-transition-entry.v3"]
    sequence: Annotated[int, Field(ge=1, le=3)]
    phase: Literal["requested", "runtime_observed", "authorized"]
    collector_id: SafeId
    site_id: SafeId
    campaign_id: SafeId
    gate: Literal["8h", "72h"]
    runtime_restart_fault_id: SafeId
    base_c2_evidence_sha256: Digest
    previous_epoch_sha256: Digest
    previous_execution_binding_sha256: Digest
    previous_runtime_identity_sha256: Digest
    continuation_launch_request_sha256: Digest
    continuation_launch_nonce: Annotated[
        str,
        Field(pattern=r"^[0-9a-f]{32}$"),
    ]
    continuation_runtime_epoch: Annotated[
        int,
        Field(ge=1, le=2**63 - 1),
    ]
    continuation_execution_binding_sha256: Digest | None = None
    continuation_runtime_identity_sha256: Digest | None = None
    continuation_runtime_boot_id: (
        Annotated[str, Field(min_length=1, max_length=128)] | None
    ) = None
    v2_compatibility_runtime_boot_id: (
        Annotated[str, Field(min_length=1, max_length=128)] | None
    ) = None
    source_profile_sha256: Digest | None = None
    native_prewarm_sha256: Digest | None = None
    unique_work_plan_sha256: Digest | None = None
    unique_work_sha256: Digest | None = None
    completion_sha256: Digest | None = None
    previous_entry_sha256: Digest
    recorded_monotonic_ns: Annotated[int, Field(ge=1, le=2**63 - 1)]

    @model_validator(mode="after")
    def exact_phase_projection(
        self,
    ) -> TargetExecutionTransitionEntryV3:
        runtime_fields = (
            self.continuation_execution_binding_sha256,
            self.continuation_runtime_identity_sha256,
            self.continuation_runtime_boot_id,
            self.v2_compatibility_runtime_boot_id,
        )
        work_fields = (
            self.source_profile_sha256,
            self.native_prewarm_sha256,
            self.unique_work_plan_sha256,
            self.unique_work_sha256,
            self.completion_sha256,
        )
        expected = (
            (1, "requested"),
            (2, "runtime_observed"),
            (3, "authorized"),
        )[self.sequence - 1]
        if (
            (self.sequence, self.phase) != expected
            or (
                self.phase == "requested"
                and (
                    any(value is not None for value in runtime_fields)
                    or any(value is not None for value in work_fields)
                    or self.previous_entry_sha256 != "0" * 64
                )
            )
            or (
                self.phase == "runtime_observed"
                and (
                    any(value is None for value in runtime_fields)
                    or any(value is not None for value in work_fields)
                    or self.previous_entry_sha256 == "0" * 64
                )
            )
            or (
                self.phase == "authorized"
                and (
                    any(value is None for value in runtime_fields)
                    or any(value is None for value in work_fields)
                    or self.previous_entry_sha256 == "0" * 64
                )
            )
        ):
            raise ValueError(
                "execution transition entry differs from its exact phase"
            )
        return self

    @property
    def entry_sha256(self) -> str:
        return _sha(self)


class TargetExecutionTransitionJournalV3(_StrictFrozenModel):
    """Exact bounded append-only chain for one runtime replacement."""

    schema_version: Literal["target-execution-transition-journal.v3"]
    entries: Annotated[
        tuple[TargetExecutionTransitionEntryV3, ...],
        Field(min_length=3, max_length=3),
    ]

    @field_validator("entries", mode="before")
    @classmethod
    def entries_are_strict(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            raise TypeError(
                "execution transition journal must be one finite sequence"
            )
        return tuple(
            TargetExecutionTransitionEntryV3.model_validate(item)
            for item in value
        )

    @model_validator(mode="after")
    def exact_append_chain(self) -> TargetExecutionTransitionJournalV3:
        first = self.entries[0]
        common = (
            first.collector_id,
            first.site_id,
            first.campaign_id,
            first.gate,
            first.runtime_restart_fault_id,
            first.base_c2_evidence_sha256,
            first.previous_epoch_sha256,
            first.previous_execution_binding_sha256,
            first.previous_runtime_identity_sha256,
            first.continuation_launch_request_sha256,
            first.continuation_launch_nonce,
            first.continuation_runtime_epoch,
        )
        if (
            tuple(entry.sequence for entry in self.entries) != (1, 2, 3)
            or tuple(entry.phase for entry in self.entries)
            != ("requested", "runtime_observed", "authorized")
            or any(
                (
                    entry.collector_id,
                    entry.site_id,
                    entry.campaign_id,
                    entry.gate,
                    entry.runtime_restart_fault_id,
                    entry.base_c2_evidence_sha256,
                    entry.previous_epoch_sha256,
                    entry.previous_execution_binding_sha256,
                    entry.previous_runtime_identity_sha256,
                    entry.continuation_launch_request_sha256,
                    entry.continuation_launch_nonce,
                    entry.continuation_runtime_epoch,
                )
                != common
                for entry in self.entries
            )
            or self.entries[1].previous_entry_sha256
            != self.entries[0].entry_sha256
            or self.entries[2].previous_entry_sha256
            != self.entries[1].entry_sha256
            or not (
                self.entries[0].recorded_monotonic_ns
                < self.entries[1].recorded_monotonic_ns
                < self.entries[2].recorded_monotonic_ns
            )
            or any(
                getattr(self.entries[1], field)
                != getattr(self.entries[2], field)
                for field in (
                    "continuation_execution_binding_sha256",
                    "continuation_runtime_identity_sha256",
                    "continuation_runtime_boot_id",
                    "v2_compatibility_runtime_boot_id",
                )
            )
        ):
            raise ValueError(
                "execution transition journal is not one exact append chain"
            )
        return self

    @property
    def journal_root_sha256(self) -> str:
        return _sha(
            {
                "schema_version": "target-execution-transition-root.v3",
                "entry_sha256": [
                    entry.entry_sha256 for entry in self.entries
                ],
            }
        )


class TargetC2ContinuationEvidenceV3(_StrictFrozenModel):
    """Additive third epoch bound to the canonical V2 runtime restart."""

    schema_version: Literal["target-c2-continuation-evidence.v3"]
    base_c2: TargetC2EvidenceV3
    runtime_restart_fault_id: SafeId
    injected_monotonic_offset_seconds: Literal[40.0]
    recovered_monotonic_offset_seconds: Literal[43.0]
    previous_execution: ExecutionBindingV2
    continuation_execution: ExecutionBindingV2
    continuation_epoch: TargetEpochEvidenceV3
    continuation_runtime_boot_id: Annotated[
        str,
        Field(min_length=1, max_length=128),
    ]
    v2_compatibility_runtime_boot_id: Annotated[
        str,
        Field(min_length=1, max_length=128),
    ]
    transition_journal: TargetExecutionTransitionJournalV3

    @model_validator(mode="after")
    def exact_cross_binding(self) -> TargetC2ContinuationEvidenceV3:
        prior = self.base_c2.epochs[-1]
        epoch = self.continuation_epoch
        final_entry = self.transition_journal.entries[-1]
        if (
            epoch.collector_id != self.base_c2.collector_id
            or epoch.site_id != self.base_c2.site_id
            or epoch.campaign_id != self.base_c2.campaign_id
            or epoch.gate != self.base_c2.gate
            or epoch.runtime_epoch != prior.runtime_epoch + 1
            or epoch.runtime_epoch_started_generation
            != epoch.runtime_epoch
            or epoch.disposition != "authorize"
            or epoch.launch_nonce == prior.launch_nonce
            or epoch.container_id == prior.container_id
            or epoch.runtime_identity_sha256
            == prior.runtime_identity_sha256
            or self.previous_execution.launch_nonce != prior.launch_nonce
            or self.previous_execution.container_id != prior.container_id
            or self.continuation_execution.launch_nonce
            != epoch.launch_nonce
            or self.continuation_execution.container_id
            != epoch.container_id
            or self.continuation_runtime_boot_id
            != f"container:{epoch.container_id}"
            or not self.v2_compatibility_runtime_boot_id.startswith(
                f"{self.previous_execution.launch_nonce}."
            )
            or self.v2_compatibility_runtime_boot_id
            != (
                f"{self.previous_execution.launch_nonce}.container-"
                f"{epoch.container_id[:32]}"
            )
            or self.continuation_runtime_boot_id
            == self.v2_compatibility_runtime_boot_id
            or final_entry.collector_id != self.base_c2.collector_id
            or final_entry.site_id != self.base_c2.site_id
            or final_entry.campaign_id != self.base_c2.campaign_id
            or final_entry.gate != self.base_c2.gate
            or final_entry.runtime_restart_fault_id
            != self.runtime_restart_fault_id
            or final_entry.base_c2_evidence_sha256
            != self.base_c2.evidence_sha256
            or final_entry.previous_epoch_sha256 != prior.epoch_sha256
            or final_entry.previous_execution_binding_sha256
            != self.previous_execution.binding_sha256
            or final_entry.previous_runtime_identity_sha256
            != prior.runtime_identity_sha256
            or final_entry.continuation_launch_request_sha256
            != epoch.launch_request_sha256
            or final_entry.continuation_launch_nonce != epoch.launch_nonce
            or final_entry.continuation_runtime_epoch
            != epoch.runtime_epoch
            or final_entry.continuation_execution_binding_sha256
            != self.continuation_execution.binding_sha256
            or final_entry.continuation_runtime_identity_sha256
            != epoch.runtime_identity_sha256
            or final_entry.continuation_runtime_boot_id
            != self.continuation_runtime_boot_id
            or final_entry.v2_compatibility_runtime_boot_id
            != self.v2_compatibility_runtime_boot_id
            or final_entry.source_profile_sha256
            != epoch.source_profile_sha256
            or final_entry.native_prewarm_sha256
            != epoch.native_prewarm_sha256
            or final_entry.unique_work_plan_sha256
            != epoch.unique_work_plan_sha256
            or final_entry.unique_work_sha256
            != epoch.unique_work_sha256
            or final_entry.completion_sha256
            != epoch.completion_sha256
        ):
            raise ValueError(
                "target C2 continuation does not bind the fresh runtime "
                "to its V2 restart transition"
            )
        return self

    @property
    def evidence_sha256(self) -> str:
        return _sha(self)


class TargetAuthorityBindingV3(_StrictFrozenModel):
    """Serializable graph whose authority comes only from a verified signature."""

    schema_version: Literal["target-authority-binding.v3"]
    authorized: Literal[True]
    collector_id: SafeId
    site_id: SafeId
    campaign_id: SafeId
    gate: Literal["8h", "72h"]
    epochs: Annotated[
        tuple[TargetEpochEvidenceV3, ...],
        Field(min_length=_EXACT_RUNTIME_EPOCHS, max_length=_EXACT_RUNTIME_EPOCHS),
    ]
    runtime_identity_sha256: Digest
    gpu_inventory_sha256: Digest
    source_profile_sha256: Digest
    native_prewarm_sha256: Digest
    unique_work_sha256: Digest
    completion_sha256: Digest
    c2_evidence_sha256: Digest
    epoch_chain_sha256: Digest
    c2_continuation: TargetC2ContinuationEvidenceV3 | None = None
    c2_continuation_sha256: Digest | None = None
    execution_transition_journal_root_sha256: Digest | None = None
    journal_proof_sha256: Digest
    v2_run_record_sha256: Digest
    v2_run_attestation_sha256: Digest
    v2_journal_root_sha256: Digest
    authority_receipt_sha256: Digest
    cross_artifact_root_sha256: Digest

    @field_validator("epochs", mode="before")
    @classmethod
    def epochs_are_strict(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            raise TypeError("target authority epochs must be one finite sequence")
        return tuple(TargetEpochEvidenceV3.model_validate(item) for item in value)

    @model_validator(mode="after")
    def complete_binding(self) -> TargetAuthorityBindingV3:
        c2 = TargetC2EvidenceV3(
            schema_version="target-c2-evidence.v3",
            collector_id=self.collector_id,
            site_id=self.site_id,
            campaign_id=self.campaign_id,
            gate=self.gate,
            epochs=self.epochs,
        )
        continuation_values = (
            self.c2_continuation,
            self.c2_continuation_sha256,
            self.execution_transition_journal_root_sha256,
        )
        if any(value is None for value in continuation_values) and any(
            value is not None for value in continuation_values
        ):
            raise ValueError(
                "target authority continuation must be wholly present or absent"
            )
        if (
            self.c2_continuation is not None
            and (
                self.c2_continuation.base_c2 != c2
                or self.c2_continuation_sha256
                != self.c2_continuation.evidence_sha256
                or self.execution_transition_journal_root_sha256
                != self.c2_continuation.transition_journal.journal_root_sha256
            )
        ):
            raise ValueError(
                "target authority continuation differs from base C2"
            )
        receipt_projection: dict[str, object] = {
            "schema_version": "target-authority-receipt.v3",
            "c2_evidence_sha256": c2.evidence_sha256,
            "v2_run_record_sha256": self.v2_run_record_sha256,
            "v2_run_attestation_sha256": self.v2_run_attestation_sha256,
            "v2_journal_proof_sha256": self.journal_proof_sha256,
            "v2_journal_root_sha256": self.v2_journal_root_sha256,
        }
        if self.c2_continuation is not None:
            receipt_projection.update(
                {
                    "c2_continuation_sha256": (
                        self.c2_continuation.evidence_sha256
                    ),
                    "execution_transition_journal_root_sha256": (
                        self.c2_continuation.transition_journal
                        .journal_root_sha256
                    ),
                }
            )
        expected_receipt = _sha(receipt_projection)
        expected_epoch_chain = _sha(
            {
                "schema_version": "target-epoch-chain.v3",
                "epoch_sha256": [epoch.epoch_sha256 for epoch in self.epochs],
            }
        )
        cross_projection: dict[str, object] = {
            "schema_version": "target-v2-cross-artifact-root.v3",
            "c2_evidence_sha256": c2.evidence_sha256,
            "epoch_chain_sha256": expected_epoch_chain,
            "runtime_identity_sha256": self.runtime_identity_sha256,
            "gpu_inventory_sha256": self.gpu_inventory_sha256,
            "source_profile_sha256": self.source_profile_sha256,
            "native_prewarm_sha256": self.native_prewarm_sha256,
            "unique_work_sha256": self.unique_work_sha256,
            "completion_sha256": self.completion_sha256,
            "v2_run_record_sha256": self.v2_run_record_sha256,
            "v2_run_attestation_sha256": self.v2_run_attestation_sha256,
            "v2_journal_proof_sha256": self.journal_proof_sha256,
            "v2_journal_root_sha256": self.v2_journal_root_sha256,
            "authority_receipt_sha256": expected_receipt,
        }
        if self.c2_continuation is not None:
            cross_projection.update(
                {
                    "c2_continuation_sha256": (
                        self.c2_continuation.evidence_sha256
                    ),
                    "execution_transition_journal_root_sha256": (
                        self.c2_continuation.transition_journal
                        .journal_root_sha256
                    ),
                    "continuation_execution_binding_sha256": (
                        self.c2_continuation.continuation_execution
                        .binding_sha256
                    ),
                    "v2_compatibility_runtime_boot_id": (
                        self.c2_continuation
                        .v2_compatibility_runtime_boot_id
                    ),
                }
            )
        expected_cross_root = _sha(cross_projection)
        if (
            self.c2_evidence_sha256 != c2.evidence_sha256
            or self.epoch_chain_sha256 != expected_epoch_chain
            or self.runtime_identity_sha256
            != _aggregate(self.epochs, "runtime_identity_sha256")
            or self.gpu_inventory_sha256 != _aggregate(self.epochs, "gpu_inventory_sha256")
            or self.source_profile_sha256 != _aggregate(self.epochs, "source_profile_sha256")
            or self.native_prewarm_sha256 != _aggregate(self.epochs, "native_prewarm_sha256")
            or self.unique_work_sha256 != _aggregate(self.epochs, "unique_work_sha256")
            or self.completion_sha256 != _aggregate(self.epochs, "completion_sha256")
            or self.authority_receipt_sha256 != expected_receipt
            or self.cross_artifact_root_sha256 != expected_cross_root
        ):
            raise ValueError("target authority does not digest every verified epoch and V2 run")
        return self


class SignedTargetAuthorityBindingV3(_StrictFrozenModel):
    """Durable controller/C2 receipt signed by the pinned run role."""

    schema_version: Literal["signed-target-authority-binding.v3"]
    binding: TargetAuthorityBindingV3
    public_key_spki_sha256: Digest
    signature_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


def verify_signed_target_authority_v3(
    signed: SignedTargetAuthorityBindingV3,
    *,
    trust_context: AcceptanceAuthorityTrustContextV2,
) -> TargetAuthorityBindingV3:
    if type(signed) is not SignedTargetAuthorityBindingV3:
        raise TypeError("exact signed target authority binding is required")
    checked = SignedTargetAuthorityBindingV3.model_validate(
        signed.model_dump(mode="python")
    )
    context = _require_authority_trust_context(trust_context)
    try:
        signature = bytes.fromhex(checked.signature_hex)
    except ValueError:
        raise ValueError("signed target authority signature is invalid") from None
    fingerprint = verify_ed25519_payload(
        payload=canonical_json_bytes(checked.binding),
        signature=signature,
        trusted_public_key=context.trust.role_public_keys.run,
        label="signed target authority binding",
    )
    if (
        fingerprint != checked.public_key_spki_sha256
        or fingerprint != context.trust.policy.roles.run_spki_sha256
        or checked.binding.site_id != context.configured_site_id
        or checked.binding.campaign_id != context.configured_campaign_id
        or checked.binding.gate != context.configured_gate
    ):
        raise ValueError("signed target authority differs from pinned controller trust")
    return checked.binding


def require_target_authority_continuation_v3(
    candidate: TargetAuthorityBindingV3,
) -> TargetAuthorityBindingV3:
    """Promote only a signed binding with the canonical third-epoch restart."""

    if type(candidate) is not TargetAuthorityBindingV3:
        raise TypeError("exact target authority binding is required")
    checked = TargetAuthorityBindingV3.model_validate(
        candidate.model_dump(mode="python")
    )
    continuation = checked.c2_continuation
    if (
        continuation is None
        or checked.c2_continuation_sha256
        != continuation.evidence_sha256
        or checked.execution_transition_journal_root_sha256
        != continuation.transition_journal.journal_root_sha256
    ):
        raise ValueError(
            "target authority requires the signed runtime restart continuation"
        )
    return checked


def _make_c2_capability_tools():
    c2_issuer = object()
    key = secrets.token_bytes(32)

    class _VerifiedC2:
        __slots__ = ("__consumed", "__evidence_bytes", "__lock", "__receipt")

        def __init__(self, *, token: object, evidence: TargetC2EvidenceV3) -> None:
            if token is not c2_issuer:
                raise TypeError("verified C2 capability requires its private issuer")
            self.__evidence_bytes = canonical_json_bytes(evidence)
            self.__receipt = hmac.digest(key, b"c2:" + self.__evidence_bytes, "sha256")
            self.__consumed = False
            self.__lock = threading.Lock()

        def __copy__(self) -> None:
            raise TypeError("verified C2 capability cannot be copied or serialized")

        def __deepcopy__(self, _memo: object) -> None:
            raise TypeError("verified C2 capability cannot be copied or serialized")

        def __reduce_ex__(self, _protocol: int) -> None:
            raise TypeError("verified C2 capability cannot be copied or serialized")

    def issue_c2(evidence: TargetC2EvidenceV3) -> object:
        return _VerifiedC2(token=c2_issuer, evidence=evidence)

    def inspect_c2(
        candidate: object,
        *,
        consume: bool,
    ) -> TargetC2EvidenceV3:
        if type(candidate) is not _VerifiedC2:
            raise TypeError("verified C2 capability is required")
        with candidate._VerifiedC2__lock:
            if candidate._VerifiedC2__consumed:
                raise RuntimeError("verified C2 capability was already consumed")
            payload = candidate._VerifiedC2__evidence_bytes
            receipt = candidate._VerifiedC2__receipt
            if (
                type(payload) is not bytes
                or type(receipt) is not bytes
                or not hmac.compare_digest(
                    receipt,
                    hmac.digest(key, b"c2:" + payload, "sha256"),
                )
            ):
                raise ValueError("verified C2 capability provenance is invalid")
            evidence = TargetC2EvidenceV3.model_validate_json(payload, strict=True)
            if consume:
                candidate._VerifiedC2__consumed = True
            return evidence

    def peek_c2(candidate: object) -> TargetC2EvidenceV3:
        return inspect_c2(candidate, consume=False)

    def consume_c2(candidate: object) -> TargetC2EvidenceV3:
        return inspect_c2(candidate, consume=True)

    return issue_c2, peek_c2, consume_c2


(
    _issue_c2_capability,
    _peek_c2_capability,
    _consume_c2_capability,
) = _make_c2_capability_tools()


def _make_transition_capability_tools():
    journal_issuer = object()
    continuation_issuer = object()
    key = secrets.token_bytes(32)

    class _VerifiedTransitionJournal:
        __slots__ = ("__consumed", "__lock", "__payload", "__receipt")

        def __init__(
            self,
            *,
            token: object,
            journal: TargetExecutionTransitionJournalV3,
        ) -> None:
            if token is not journal_issuer:
                raise TypeError(
                    "transition journal capability requires its private issuer"
                )
            self.__payload = canonical_json_bytes(journal)
            self.__receipt = hmac.digest(
                key,
                b"transition-journal:" + self.__payload,
                "sha256",
            )
            self.__consumed = False
            self.__lock = threading.Lock()

        def __copy__(self) -> None:
            raise TypeError(
                "transition journal capability cannot be copied or serialized"
            )

        def __deepcopy__(self, _memo: object) -> None:
            raise TypeError(
                "transition journal capability cannot be copied or serialized"
            )

        def __reduce_ex__(self, _protocol: int) -> None:
            raise TypeError(
                "transition journal capability cannot be copied or serialized"
            )

    class _VerifiedContinuation:
        __slots__ = ("__consumed", "__lock", "__payload", "__receipt")

        def __init__(
            self,
            *,
            token: object,
            evidence: TargetC2ContinuationEvidenceV3,
        ) -> None:
            if token is not continuation_issuer:
                raise TypeError(
                    "C2 continuation capability requires its private issuer"
                )
            self.__payload = canonical_json_bytes(evidence)
            self.__receipt = hmac.digest(
                key,
                b"c2-continuation:" + self.__payload,
                "sha256",
            )
            self.__consumed = False
            self.__lock = threading.Lock()

        def __copy__(self) -> None:
            raise TypeError(
                "C2 continuation capability cannot be copied or serialized"
            )

        def __deepcopy__(self, _memo: object) -> None:
            raise TypeError(
                "C2 continuation capability cannot be copied or serialized"
            )

        def __reduce_ex__(self, _protocol: int) -> None:
            raise TypeError(
                "C2 continuation capability cannot be copied or serialized"
            )

    def issue_journal(
        journal: TargetExecutionTransitionJournalV3,
    ) -> object:
        return _VerifiedTransitionJournal(
            token=journal_issuer,
            journal=journal,
        )

    def inspect_journal(
        candidate: object,
        *,
        consume: bool,
    ) -> TargetExecutionTransitionJournalV3:
        if type(candidate) is not _VerifiedTransitionJournal:
            raise TypeError(
                "verified execution transition journal is required"
            )
        with candidate._VerifiedTransitionJournal__lock:
            if candidate._VerifiedTransitionJournal__consumed:
                raise RuntimeError(
                    "execution transition journal was already consumed"
                )
            payload = candidate._VerifiedTransitionJournal__payload
            receipt = candidate._VerifiedTransitionJournal__receipt
            if (
                type(payload) is not bytes
                or type(receipt) is not bytes
                or not hmac.compare_digest(
                    receipt,
                    hmac.digest(
                        key,
                        b"transition-journal:" + payload,
                        "sha256",
                    ),
                )
            ):
                raise ValueError(
                    "execution transition journal provenance is invalid"
                )
            journal = TargetExecutionTransitionJournalV3.model_validate_json(
                payload,
                strict=True,
            )
            if consume:
                candidate._VerifiedTransitionJournal__consumed = True
            return journal

    def issue_continuation(
        evidence: TargetC2ContinuationEvidenceV3,
    ) -> object:
        return _VerifiedContinuation(
            token=continuation_issuer,
            evidence=evidence,
        )

    def inspect_continuation(
        candidate: object,
        *,
        consume: bool,
    ) -> TargetC2ContinuationEvidenceV3:
        if type(candidate) is not _VerifiedContinuation:
            raise TypeError("verified C2 continuation capability is required")
        with candidate._VerifiedContinuation__lock:
            if candidate._VerifiedContinuation__consumed:
                raise RuntimeError(
                    "verified C2 continuation was already consumed"
                )
            payload = candidate._VerifiedContinuation__payload
            receipt = candidate._VerifiedContinuation__receipt
            if (
                type(payload) is not bytes
                or type(receipt) is not bytes
                or not hmac.compare_digest(
                    receipt,
                    hmac.digest(
                        key,
                        b"c2-continuation:" + payload,
                        "sha256",
                    ),
                )
            ):
                raise ValueError(
                    "verified C2 continuation provenance is invalid"
                )
            evidence = TargetC2ContinuationEvidenceV3.model_validate_json(
                payload,
                strict=True,
            )
            if consume:
                candidate._VerifiedContinuation__consumed = True
            return evidence

    return (
        issue_journal,
        lambda candidate: inspect_journal(candidate, consume=False),
        lambda candidate: inspect_journal(candidate, consume=True),
        issue_continuation,
        lambda candidate: inspect_continuation(candidate, consume=False),
        lambda candidate: inspect_continuation(candidate, consume=True),
    )


(
    _issue_transition_journal_capability,
    _peek_transition_journal_capability,
    _consume_transition_journal_capability,
    _issue_continuation_capability,
    _peek_continuation_capability,
    _consume_continuation_capability,
) = _make_transition_capability_tools()


def _require_continuation_capability(
    candidate: object,
) -> TargetC2ContinuationEvidenceV3:
    """Require private continuation provenance without consuming it."""

    return _peek_continuation_capability(candidate)


class SQLiteTargetExecutionTransitionJournalV3:
    """Durable insert-only journal for one exact retained-runtime transition."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("execution transition journal path is unsafe")
        try:
            parent = path.parent.resolve(strict=True)
            metadata = parent.stat()
        except OSError as exc:
            raise ValueError(
                "execution transition journal root is unavailable"
            ) from exc
        if (
            parent != path.parent
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError(
                "execution transition journal root must be private "
                "and runner-owned"
            )
        self.path = path
        self._root_identity = (metadata.st_dev, metadata.st_ino)
        self._database_identity: tuple[int, int] | None = None
        self._lock = threading.RLock()
        previous_umask = os.umask(0o077)
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS target_execution_transitions (
                        collector_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 3),
                        entry_sha256 TEXT NOT NULL,
                        entry_json TEXT NOT NULL,
                        PRIMARY KEY (collector_id, sequence),
                        UNIQUE (entry_sha256)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS
                    target_execution_transition_seals (
                        collector_id TEXT PRIMARY KEY,
                        journal_root_sha256 TEXT NOT NULL UNIQUE
                            CHECK (
                                length(journal_root_sha256) = 64
                                AND journal_root_sha256
                                    NOT GLOB '*[^0-9a-f]*'
                            )
                    )
                    """
                )
        finally:
            os.umask(previous_umask)
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        metadata = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (metadata.st_dev, metadata.st_ino)
            != self._root_identity
        ):
            raise RuntimeError(
                "execution transition journal root identity changed"
            )
        try:
            current = self.path.lstat()
        except FileNotFoundError:
            current = None
        if current is not None:
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.geteuid()
                or current.st_nlink != 1
                or current.st_mode & 0o077
            ):
                raise RuntimeError(
                    "execution transition journal file is unsafe"
                )
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            opened = self.path.lstat()
        except OSError:
            connection.close()
            raise RuntimeError(
                "execution transition journal file is unavailable"
            ) from None
        opened_identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_mode & 0o077
            or (
                current is not None
                and opened_identity != (current.st_dev, current.st_ino)
            )
            or (
                self._database_identity is not None
                and opened_identity != self._database_identity
            )
        ):
            connection.close()
            raise RuntimeError(
                "execution transition journal file identity changed"
            )
        if self._database_identity is None:
            self._database_identity = opened_identity
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @staticmethod
    def _encoded(
        entry: TargetExecutionTransitionEntryV3,
    ) -> tuple[str, str]:
        encoded = canonical_json_bytes(entry)
        if len(encoded) > 64 * 1024:
            raise ValueError("execution transition entry is unbounded")
        return encoded.decode("utf-8"), hashlib.sha256(encoded).hexdigest()

    def append(
        self,
        entry: TargetExecutionTransitionEntryV3,
    ) -> TargetExecutionTransitionEntryV3:
        if type(entry) is not TargetExecutionTransitionEntryV3:
            raise TypeError("exact execution transition entry is required")
        checked = TargetExecutionTransitionEntryV3.model_validate(
            entry.model_dump(mode="python")
        )
        encoded, digest = self._encoded(checked)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            sealed = connection.execute(
                "SELECT journal_root_sha256 "
                "FROM target_execution_transition_seals "
                "WHERE collector_id = ?",
                (checked.collector_id,),
            ).fetchone()
            if sealed is not None:
                raise RuntimeError(
                    "execution transition journal is already sealed"
                )
            rows = connection.execute(
                "SELECT sequence, entry_sha256, entry_json "
                "FROM target_execution_transitions "
                "WHERE collector_id = ? ORDER BY sequence",
                (checked.collector_id,),
            ).fetchall()
            if len(rows) >= checked.sequence:
                row = rows[checked.sequence - 1]
                if (
                    row["sequence"] != checked.sequence
                    or row["entry_sha256"] != digest
                    or row["entry_json"] != encoded
                ):
                    raise RuntimeError(
                        "execution transition append retry changed"
                    )
                return checked
            if (
                len(rows) != checked.sequence - 1
                or (
                    rows
                    and checked.previous_entry_sha256
                    != rows[-1]["entry_sha256"]
                )
                or (
                    not rows
                    and checked.previous_entry_sha256 != "0" * 64
                )
            ):
                raise RuntimeError(
                    "execution transition append is out of order"
                )
            connection.execute(
                "INSERT INTO target_execution_transitions "
                "(collector_id, sequence, entry_sha256, entry_json) "
                "VALUES (?, ?, ?, ?)",
                (
                    checked.collector_id,
                    checked.sequence,
                    digest,
                    encoded,
                ),
            )
            page_count = int(
                connection.execute("PRAGMA page_count").fetchone()[0]
            )
            page_size = int(
                connection.execute("PRAGMA page_size").fetchone()[0]
            )
            if page_count * page_size > 1024 * 1024 * 1024:
                raise RuntimeError(
                    "execution transition journal byte bound reached"
                )
        return checked

    def finalize(
        self,
        collector_id: str,
    ) -> tuple[TargetExecutionTransitionJournalV3, object]:
        if (
            type(collector_id) is not str
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}",
                collector_id,
            )
            is None
        ):
            raise ValueError(
                "execution transition collector identity is invalid"
            )
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            sealed = connection.execute(
                "SELECT journal_root_sha256 "
                "FROM target_execution_transition_seals "
                "WHERE collector_id = ?",
                (collector_id,),
            ).fetchone()
            if sealed is not None:
                raise RuntimeError(
                    "execution transition journal finalization was replayed"
                )
            rows = connection.execute(
                "SELECT sequence, entry_sha256, entry_json "
                "FROM target_execution_transitions "
                "WHERE collector_id = ? ORDER BY sequence",
                (collector_id,),
            ).fetchall()
            if len(rows) != 3 or tuple(
                int(row["sequence"]) for row in rows
            ) != (1, 2, 3):
                raise RuntimeError(
                    "execution transition journal is incomplete"
                )
            entries: list[TargetExecutionTransitionEntryV3] = []
            for row in rows:
                try:
                    entry = (
                        TargetExecutionTransitionEntryV3.model_validate_json(
                            row["entry_json"],
                            strict=True,
                        )
                    )
                    encoded, digest = self._encoded(entry)
                except (TypeError, ValueError) as exc:
                    raise RuntimeError(
                        "execution transition journal was tampered"
                    ) from exc
                if (
                    entry.collector_id != collector_id
                    or entry.sequence != int(row["sequence"])
                    or encoded != row["entry_json"]
                    or digest != row["entry_sha256"]
                ):
                    raise RuntimeError(
                        "execution transition journal digest was tampered"
                    )
                entries.append(entry)
            try:
                journal = TargetExecutionTransitionJournalV3(
                    schema_version=(
                        "target-execution-transition-journal.v3"
                    ),
                    entries=tuple(entries),
                )
            except ValueError as exc:
                raise RuntimeError(
                    "execution transition journal chain was tampered"
                ) from exc
            connection.execute(
                "INSERT INTO target_execution_transition_seals "
                "(collector_id, journal_root_sha256) VALUES (?, ?)",
                (collector_id, journal.journal_root_sha256),
            )
        return journal, _issue_transition_journal_capability(journal)


def _execution_binding_from_runtime_identity(
    identity: object,
) -> ExecutionBindingV2:
    request = identity.launch_request
    return ExecutionBindingV2(
        schema_version="acceptance-execution-binding.v2",
        launch_attestation_sha256=request.launch.attestation_sha256,
        launch_nonce=request.launch_nonce,
        container_id=identity.container_id,
        container_config_sha256=identity.container_config_sha256,
        runtime_image_id_sha256=identity.runtime_image_id_sha256,
        acceptance_adapter_sha256=(
            request.launch.acceptance_adapter_sha256
        ),
        acceptance_adapter_policy_sha256=(
            request.launch.acceptance_adapter_policy_sha256
        ),
        acceptance_observer_sha256=(
            request.launch.acceptance_observer_sha256
        ),
        acceptance_observer_policy_sha256=(
            request.launch.acceptance_observer_policy_sha256
        ),
        control_network_id=identity.control_network_id,
        control_network_config_sha256=(
            identity.control_network_config_sha256
        ),
        camera_network_id=identity.camera_network_id,
        camera_network_config_sha256=(
            identity.camera_network_config_sha256
        ),
        observed_gpu_inventory_sha256=(
            identity.observed_gpu_inventory.launch_compatibility_sha256
        ),
    )


def authorize_target_c2_continuation_v3(
    *,
    c2_capability: object,
    previous_execution: ExecutionBindingV2,
    runtime_capability: object,
    channel_receipt: object,
    verified_work: object,
    verified_source_profile: VerifiedTargetSourceProfileAttestationV2,
    transition_journal_capability: object,
    runtime_restart_fault_id: str,
) -> tuple[TargetC2ContinuationEvidenceV3, object]:
    """Consume fresh third-epoch capabilities into one private continuation."""

    with C2_CAPABILITY_TRANSACTION_LOCK:
        c2 = _peek_c2_capability(c2_capability)
        journal = _peek_transition_journal_capability(
            transition_journal_capability
        )
        runtime, identity = _peek_controller_runtime_authority(
            runtime_capability
        )
        result, ack = _peek_channel_receipt(channel_receipt)
        plan, projection = _peek_verified_target_work(verified_work)
        source_profile = (
            _require_verified_target_source_profile_attestation(
                verified_source_profile
            )
        )
        prior = c2.epochs[-1]
        request = identity.launch_request
        continuation_execution = _execution_binding_from_runtime_identity(
            identity
        )
        if type(previous_execution) is not ExecutionBindingV2:
            raise TypeError(
                "exact previous V2 execution binding is required"
            )
        checked_previous = ExecutionBindingV2.model_validate(
            previous_execution.model_dump(mode="python")
        )
        if (
            checked_previous.launch_nonce != prior.launch_nonce
            or checked_previous.container_id != prior.container_id
            or request.runtime_epoch != prior.runtime_epoch + 1
            or request.runtime_epoch_started_generation
            != request.runtime_epoch
            or request.launch.site_id != c2.site_id
            or request.campaign_id != c2.campaign_id
            or request.gate != c2.gate
            or request.launch_nonce == prior.launch_nonce
            or identity.container_id == prior.container_id
            or identity.identity_sha256
            == prior.runtime_identity_sha256
            or result.collector_id != c2.collector_id
            or result.launch_request_sha256 != request.request_sha256
            or result.runtime_identity_sha256
            != identity.identity_sha256
            or result.unique_work_projection != projection
            or ack.collector_id != c2.collector_id
            or ack.channel_nonce != request.launch_nonce
            or ack.result_sha256 != result.result_sha256
            or ack.action != "authorize"
            or plan.plan_sha256 != projection.plan_sha256
            or source_profile.launch_request_sha256
            != request.request_sha256
            or source_profile.source_identity_commitments
            != tuple(
                item.source_identity_commitment
                for item in request.source_bindings
            )
            or result.verified_source_profile_sha256
            != verified_source_profile.verified_binding_sha256
            or journal.entries[-1].runtime_restart_fault_id
            != runtime_restart_fault_id
        ):
            raise ValueError(
                "target continuation differs from "
                "controller/source/work authority"
            )
        epoch = TargetEpochEvidenceV3(
            schema_version="target-epoch-evidence.v3",
            collector_id=c2.collector_id,
            site_id=c2.site_id,
            campaign_id=c2.campaign_id,
            gate=c2.gate,
            runtime_epoch=request.runtime_epoch,
            runtime_epoch_started_generation=(
                request.runtime_epoch_started_generation
            ),
            launch_nonce=request.launch_nonce,
            container_id=identity.container_id,
            launch_request_sha256=request.request_sha256,
            runtime_identity_sha256=identity.identity_sha256,
            gpu_inventory_sha256=(
                identity.observed_gpu_inventory.inventory_sha256
            ),
            source_profile_sha256=(
                verified_source_profile.verified_binding_sha256
            ),
            native_prewarm_sha256=(
                result.native_prewarm.projection_sha256
            ),
            unique_work_plan_sha256=plan.plan_sha256,
            unique_work_sha256=projection.projection_sha256,
            completion_sha256=projection.completed_work_ledger_sha256,
            runtime_epoch_started_monotonic_ns=(
                identity.runtime_epoch_started_monotonic_ns
            ),
            identity_observed_monotonic_ns=(
                identity.identity_observed_monotonic_ns
            ),
            prewarm_ready_at_monotonic_ns=(
                result.native_prewarm.ready_at_monotonic_ns
            ),
            measurement_started_monotonic_ns=(
                projection.measurement_started_monotonic_ns
            ),
            measurement_completed_monotonic_ns=(
                projection.measurement_completed_monotonic_ns
            ),
            disposition="authorize",
            analytics_publication_enabled_during_gate=False,
        )
        final_entry = journal.entries[-1]
        evidence = TargetC2ContinuationEvidenceV3(
            schema_version="target-c2-continuation-evidence.v3",
            base_c2=c2,
            runtime_restart_fault_id=runtime_restart_fault_id,
            injected_monotonic_offset_seconds=40.0,
            recovered_monotonic_offset_seconds=43.0,
            previous_execution=checked_previous,
            continuation_execution=continuation_execution,
            continuation_epoch=epoch,
            continuation_runtime_boot_id=identity.runtime_boot_id,
            v2_compatibility_runtime_boot_id=(
                final_entry.v2_compatibility_runtime_boot_id
            ),
            transition_journal=journal,
        )
        committed_runtime, committed_identity = (
            _require_controller_runtime_authority(runtime_capability)
        )
        committed_result, committed_ack = _require_channel_receipt(
            channel_receipt
        )
        committed_plan, committed_projection = (
            _require_verified_target_work(verified_work)
        )
        committed_journal = _consume_transition_journal_capability(
            transition_journal_capability
        )
        if (
            committed_runtime is not runtime
            or committed_identity != identity
            or committed_result != result
            or committed_ack != ack
            or committed_plan != plan
            or committed_projection != projection
            or committed_journal != journal
        ):
            raise RuntimeError(
                "target continuation capability changed during commit"
            )
        return evidence, _issue_continuation_capability(evidence)


def _make_target_c2_authority_type() -> type:
    """Keep authority state outside caller-reachable object attributes."""

    class _AuthorityState:
        __slots__ = (
            "campaign_id",
            "collector_id",
            "epochs",
            "finalized",
            "gate",
            "lock",
            "site_id",
        )

        def __init__(
            self,
            *,
            collector_id: str,
            site_id: str,
            campaign_id: str,
            gate: Literal["8h", "72h"],
        ) -> None:
            self.collector_id = collector_id
            self.site_id = site_id
            self.campaign_id = campaign_id
            self.gate = gate
            self.epochs: list[TargetEpochEvidenceV3] = []
            self.finalized = False
            self.lock = threading.RLock()

    states: weakref.WeakKeyDictionary[object, _AuthorityState] = (
        weakref.WeakKeyDictionary()
    )
    states_lock = threading.Lock()

    def state_for(candidate: object) -> _AuthorityState:
        with states_lock:
            try:
                return states[candidate]
            except KeyError:
                raise TypeError(
                    "target C2 authority provenance is invalid"
                ) from None

    class _TargetC2AuthorityV3:
        """Consume private runtime/channel/work capabilities in exact epoch order."""

        __slots__ = ("__weakref__",)

        def __init__(
            self,
            *,
            collector_id: str,
            site_id: str,
            campaign_id: str,
            gate: Literal["8h", "72h"],
        ) -> None:
            if not all(
                type(value) is str and value
                for value in (collector_id, site_id, campaign_id)
            ):
                raise ValueError("target C2 identities are invalid")
            if gate not in {"8h", "72h"}:
                raise ValueError("target C2 gate is invalid")
            state = _AuthorityState(
                collector_id=collector_id,
                site_id=site_id,
                campaign_id=campaign_id,
                gate=gate,
            )
            with states_lock:
                states[self] = state

        def __copy__(self) -> None:
            raise TypeError("target C2 authority cannot be copied or serialized")

        def __deepcopy__(self, _memo: object) -> None:
            raise TypeError("target C2 authority cannot be copied or serialized")

        def __reduce_ex__(self, _protocol: int) -> None:
            raise TypeError("target C2 authority cannot be copied or serialized")

        def add_epoch(
            self,
            candidate: TargetEpochEvidenceV3 | None = None,
            *,
            runtime_capability: object,
            channel_receipt: object,
            verified_work: object,
            verified_source_profile: (
                VerifiedTargetSourceProfileAttestationV2 | None
            ) = None,
            disposition: Literal["restart", "authorize"] = "restart",
        ) -> TargetEpochEvidenceV3:
            state = state_for(self)
            with state.lock, C2_CAPABILITY_TRANSACTION_LOCK:
                del candidate
                if state.finalized:
                    raise RuntimeError(
                        "target C2 authority is already finalized"
                    )
                if len(state.epochs) >= _EXACT_RUNTIME_EPOCHS:
                    raise RuntimeError("target C2 epoch bound is exhausted")
                runtime, identity = _peek_controller_runtime_authority(
                    runtime_capability
                )
                result, ack = _peek_channel_receipt(channel_receipt)
                plan, projection = _peek_verified_target_work(verified_work)
                if verified_source_profile is None:
                    raise TypeError(
                        "verified source profile capability is required"
                    )
                source_profile = (
                    _require_verified_target_source_profile_attestation(
                        verified_source_profile
                    )
                )
                request = identity.launch_request
                expected_epoch = (
                    request.runtime_epoch
                    if not state.epochs
                    else state.epochs[-1].runtime_epoch + 1
                )
                if (
                    request.runtime_epoch != expected_epoch
                    or request.runtime_epoch_started_generation
                    != request.runtime_epoch
                    or request.launch.site_id != state.site_id
                    or request.campaign_id != state.campaign_id
                    or request.gate != state.gate
                    or result.collector_id != state.collector_id
                    or result.launch_request_sha256 != request.request_sha256
                    or result.runtime_identity_sha256
                    != identity.identity_sha256
                    or result.native_prewarm
                    != result.native_prewarm.model_validate(
                        result.native_prewarm
                    )
                    or result.unique_work_projection != projection
                    or ack.collector_id != state.collector_id
                    or ack.channel_nonce != request.launch_nonce
                    or ack.result_sha256 != result.result_sha256
                    or ack.action != disposition
                    or plan.plan_sha256 != projection.plan_sha256
                    or source_profile.launch_request_sha256
                    != request.request_sha256
                    or source_profile.source_identity_commitments
                    != tuple(
                        item.source_identity_commitment
                        for item in request.source_bindings
                    )
                    or result.verified_source_profile_sha256
                    != verified_source_profile.verified_binding_sha256
                    or disposition not in {"restart", "authorize"}
                    or (
                        state.epochs
                        and state.epochs[-1].disposition != "restart"
                    )
                    or disposition
                    != (
                        "restart"
                        if len(state.epochs) == 0
                        else "authorize"
                    )
                ):
                    raise ValueError(
                        "target C2 epoch differs from "
                        "controller/source/work authority"
                    )
                source_profile_sha256 = (
                    verified_source_profile.verified_binding_sha256
                )
                epoch = TargetEpochEvidenceV3(
                    schema_version="target-epoch-evidence.v3",
                    collector_id=state.collector_id,
                    site_id=state.site_id,
                    campaign_id=state.campaign_id,
                    gate=state.gate,
                    runtime_epoch=request.runtime_epoch,
                    runtime_epoch_started_generation=(
                        request.runtime_epoch_started_generation
                    ),
                    launch_nonce=request.launch_nonce,
                    container_id=identity.container_id,
                    launch_request_sha256=request.request_sha256,
                    runtime_identity_sha256=identity.identity_sha256,
                    gpu_inventory_sha256=(
                        identity.observed_gpu_inventory.inventory_sha256
                    ),
                    source_profile_sha256=source_profile_sha256,
                    native_prewarm_sha256=(
                        result.native_prewarm.projection_sha256
                    ),
                    unique_work_plan_sha256=plan.plan_sha256,
                    unique_work_sha256=projection.projection_sha256,
                    completion_sha256=(
                        projection.completed_work_ledger_sha256
                    ),
                    runtime_epoch_started_monotonic_ns=(
                        identity.runtime_epoch_started_monotonic_ns
                    ),
                    identity_observed_monotonic_ns=(
                        identity.identity_observed_monotonic_ns
                    ),
                    prewarm_ready_at_monotonic_ns=(
                        result.native_prewarm.ready_at_monotonic_ns
                    ),
                    measurement_started_monotonic_ns=(
                        projection.measurement_started_monotonic_ns
                    ),
                    measurement_completed_monotonic_ns=(
                        projection.measurement_completed_monotonic_ns
                    ),
                    disposition=disposition,
                    analytics_publication_enabled_during_gate=False,
                )
                if any(
                    previous.container_id == epoch.container_id
                    or previous.launch_nonce == epoch.launch_nonce
                    or previous.runtime_identity_sha256
                    == epoch.runtime_identity_sha256
                    for previous in state.epochs
                ):
                    raise ValueError(
                        "target C2 restart reused a container, nonce, "
                        "or runtime identity"
                    )
                if disposition == "restart":
                    runtime.cleanup()
                committed_runtime, committed_identity = (
                    _require_controller_runtime_authority(runtime_capability)
                )
                committed_result, committed_ack = _require_channel_receipt(
                    channel_receipt
                )
                committed_plan, committed_projection = (
                    _require_verified_target_work(verified_work)
                )
                if (
                    committed_runtime is not runtime
                    or committed_identity != identity
                    or committed_result != result
                    or committed_ack != ack
                    or committed_plan != plan
                    or committed_projection != projection
                ):
                    raise RuntimeError(
                        "target C2 capability changed during commit"
                    )
                state.epochs.append(epoch)
                return epoch

        def finalize(self) -> tuple[TargetC2EvidenceV3, object]:
            state = state_for(self)
            with state.lock, C2_CAPABILITY_TRANSACTION_LOCK:
                if state.finalized:
                    raise RuntimeError(
                        "target C2 authority is already finalized"
                    )
                if len(state.epochs) != _EXACT_RUNTIME_EPOCHS:
                    raise RuntimeError(
                        "target C2 requires a completed restart "
                        "and final authorized epoch"
                    )
                try:
                    evidence = TargetC2EvidenceV3(
                        schema_version="target-c2-evidence.v3",
                        collector_id=state.collector_id,
                        site_id=state.site_id,
                        campaign_id=state.campaign_id,
                        gate=state.gate,
                        epochs=tuple(state.epochs),
                    )
                except ValueError:
                    raise RuntimeError(
                        "target C2 requires a completed restart "
                        "and final authorized epoch"
                    ) from None
                state.finalized = True
                return evidence, _issue_c2_capability(evidence)

    _TargetC2AuthorityV3.__name__ = "TargetC2AuthorityV3"
    _TargetC2AuthorityV3.__qualname__ = "TargetC2AuthorityV3"
    return _TargetC2AuthorityV3


TargetC2AuthorityV3 = _make_target_c2_authority_type()


def bind_target_authority_v3(
    *,
    c2_capability: object,
    continuation_capability: object,
    trust_context: AcceptanceAuthorityTrustContextV2,
    signer: AcceptanceRunSigner,
    final_envelope: AcceptanceFinalEnvelopeV2,
    journal_proof_path: Path,
) -> tuple[
    SignedTargetAuthorityBindingV3,
    VerifiedAcceptanceJournalProofV2,
]:
    """Atomically reserve C2 until durable signing succeeds or rolls back."""

    with C2_CAPABILITY_TRANSACTION_LOCK:
        continuation = _require_continuation_capability(
            continuation_capability
        )
        if continuation.base_c2 != _peek_c2_capability(c2_capability):
            raise ValueError(
                "target C2 continuation differs from its base C2 capability"
            )
        return _bind_target_authority_v3_locked(
            c2_capability=c2_capability,
            continuation_capability=continuation_capability,
            trust_context=trust_context,
            signer=signer,
            final_envelope=final_envelope,
            journal_proof_path=journal_proof_path,
        )


def _bind_target_authority_v3_locked(
    *,
    c2_capability: object,
    continuation_capability: object | None,
    trust_context: AcceptanceAuthorityTrustContextV2,
    signer: AcceptanceRunSigner,
    final_envelope: AcceptanceFinalEnvelopeV2,
    journal_proof_path: Path,
) -> tuple[
    SignedTargetAuthorityBindingV3,
    VerifiedAcceptanceJournalProofV2,
]:
    """Bind private C2 to one signature-verified, replayed V2 run and proof."""

    c2 = _peek_c2_capability(c2_capability)
    continuation = (
        None
        if continuation_capability is None
        else _peek_continuation_capability(continuation_capability)
    )
    if continuation is not None and continuation.base_c2 != c2:
        raise ValueError(
            "target C2 continuation differs from its base C2 capability"
        )
    context = _require_authority_trust_context(trust_context)
    if type(final_envelope) is not AcceptanceFinalEnvelopeV2:
        raise TypeError("target authority requires the exact V2 final envelope")
    envelope = AcceptanceFinalEnvelopeV2.model_validate(
        final_envelope.model_dump(mode="python")
    )
    record = envelope.record
    attestation = envelope.attestation
    try:
        signature = bytes.fromhex(envelope.signature_hex)
    except ValueError:
        raise ValueError("target V2 run signature is invalid") from None
    attestation_payload = canonical_json_bytes(attestation)
    fingerprint = verify_ed25519_payload(
        payload=attestation_payload,
        signature=signature,
        trusted_public_key=context.trust.role_public_keys.run,
        label="target run attestation",
    )
    record_sha256 = _sha(record)
    attestation_sha256 = _sha(attestation)
    if (
        c2.site_id != context.configured_site_id
        or c2.campaign_id != context.configured_campaign_id
        or c2.gate != context.configured_gate
        or c2.collector_id != record.run_id
        or record.environment != "target"
        or record.site_id != c2.site_id
        or record.gate != c2.gate
        or record.manifest_sha256 != context.trust.manifest.manifest_sha256
        or attestation.collector_id != c2.collector_id
        or attestation.site_id != c2.site_id
        or attestation.gate != c2.gate
        or attestation.run_record_sha256 != record_sha256
        or attestation.public_key_spki_sha256 != fingerprint
        or fingerprint != context.trust.policy.roles.run_spki_sha256
    ):
        raise ValueError("target V2 run differs from verified C2 and trust")
    if continuation is not None:
        restart_faults = tuple(
            fault
            for fault in record.faults
            if fault.kind == "runtime_restart"
        )
        restart_traces = tuple(
            trace
            for trace in record.fault_traces
            if trace.fault_id
            == continuation.runtime_restart_fault_id
        )
        recovered = tuple(
            trace
            for trace in restart_traces
            if trace.phase == "recovered"
        )
        degraded = tuple(
            trace
            for trace in restart_traces
            if trace.phase == "degraded"
        )
        if (
            record.execution != continuation.previous_execution
            or len(restart_faults) != 1
            or restart_faults[0].fault_id
            != continuation.runtime_restart_fault_id
            or len(restart_traces) != 2
            or len(degraded) != 1
            or len(recovered) != 1
            or degraded[0].runtime_boot_id
            == recovered[0].runtime_boot_id
            or recovered[0].runtime_boot_id
            != continuation.v2_compatibility_runtime_boot_id
            or continuation.v2_compatibility_runtime_boot_id
            not in record.runtime_boot_ids
        ):
            raise ValueError(
                "target V2 runtime restart differs from the C2 continuation"
            )
    proof = verify_acceptance_journal_proof(
        journal_proof_path,
        expected_attestation=attestation,
        expected_run_record=record,
    )
    if (
        signer is None
        or not callable(getattr(signer, "sign", None))
        or signer.public_key_spki_sha256
        != context.trust.policy.roles.run_spki_sha256
    ):
        raise ValueError("target authority signer differs from pinned run role")
    receipt_projection: dict[str, object] = {
        "schema_version": "target-authority-receipt.v3",
        "c2_evidence_sha256": c2.evidence_sha256,
        "v2_run_record_sha256": record_sha256,
        "v2_run_attestation_sha256": attestation_sha256,
        "v2_journal_proof_sha256": proof.proof_sha256,
        "v2_journal_root_sha256": proof.trailer.journal_final_root_sha256,
    }
    if continuation is not None:
        receipt_projection.update(
            {
                "c2_continuation_sha256": continuation.evidence_sha256,
                "execution_transition_journal_root_sha256": (
                    continuation.transition_journal.journal_root_sha256
                ),
            }
        )
    receipt_sha256 = _sha(receipt_projection)
    epoch_chain_sha256 = _sha(
        {
            "schema_version": "target-epoch-chain.v3",
            "epoch_sha256": [
                epoch.epoch_sha256 for epoch in c2.epochs
            ],
        }
    )
    cross_projection: dict[str, object] = {
        "schema_version": "target-v2-cross-artifact-root.v3",
        "c2_evidence_sha256": c2.evidence_sha256,
        "epoch_chain_sha256": epoch_chain_sha256,
        "runtime_identity_sha256": _aggregate(
            c2.epochs,
            "runtime_identity_sha256",
        ),
        "gpu_inventory_sha256": _aggregate(
            c2.epochs,
            "gpu_inventory_sha256",
        ),
        "source_profile_sha256": _aggregate(
            c2.epochs,
            "source_profile_sha256",
        ),
        "native_prewarm_sha256": _aggregate(
            c2.epochs,
            "native_prewarm_sha256",
        ),
        "unique_work_sha256": _aggregate(
            c2.epochs,
            "unique_work_sha256",
        ),
        "completion_sha256": _aggregate(
            c2.epochs,
            "completion_sha256",
        ),
        "v2_run_record_sha256": record_sha256,
        "v2_run_attestation_sha256": attestation_sha256,
        "v2_journal_proof_sha256": proof.proof_sha256,
        "v2_journal_root_sha256": (
            proof.trailer.journal_final_root_sha256
        ),
        "authority_receipt_sha256": receipt_sha256,
    }
    if continuation is not None:
        cross_projection.update(
            {
                "c2_continuation_sha256": continuation.evidence_sha256,
                "execution_transition_journal_root_sha256": (
                    continuation.transition_journal.journal_root_sha256
                ),
                "continuation_execution_binding_sha256": (
                    continuation.continuation_execution.binding_sha256
                ),
                "v2_compatibility_runtime_boot_id": (
                    continuation.v2_compatibility_runtime_boot_id
                ),
            }
        )
    binding = TargetAuthorityBindingV3(
        schema_version="target-authority-binding.v3",
        authorized=True,
        collector_id=c2.collector_id,
        site_id=c2.site_id,
        campaign_id=c2.campaign_id,
        gate=c2.gate,
        epochs=c2.epochs,
        runtime_identity_sha256=_aggregate(c2.epochs, "runtime_identity_sha256"),
        gpu_inventory_sha256=_aggregate(c2.epochs, "gpu_inventory_sha256"),
        source_profile_sha256=_aggregate(c2.epochs, "source_profile_sha256"),
        native_prewarm_sha256=_aggregate(c2.epochs, "native_prewarm_sha256"),
        unique_work_sha256=_aggregate(c2.epochs, "unique_work_sha256"),
        completion_sha256=_aggregate(c2.epochs, "completion_sha256"),
        c2_evidence_sha256=c2.evidence_sha256,
        epoch_chain_sha256=epoch_chain_sha256,
        c2_continuation=continuation,
        c2_continuation_sha256=(
            None if continuation is None else continuation.evidence_sha256
        ),
        execution_transition_journal_root_sha256=(
            None
            if continuation is None
            else continuation.transition_journal.journal_root_sha256
        ),
        journal_proof_sha256=proof.proof_sha256,
        v2_run_record_sha256=record_sha256,
        v2_run_attestation_sha256=attestation_sha256,
        v2_journal_root_sha256=proof.trailer.journal_final_root_sha256,
        authority_receipt_sha256=receipt_sha256,
        cross_artifact_root_sha256=_sha(cross_projection),
    )
    signed_bytes = signer.sign(canonical_json_bytes(binding))
    if type(signed_bytes) is not bytes or len(signed_bytes) != 64:
        raise RuntimeError("target authority signer returned an invalid signature")
    signed = SignedTargetAuthorityBindingV3(
        schema_version="signed-target-authority-binding.v3",
        binding=binding,
        public_key_spki_sha256=signer.public_key_spki_sha256,
        signature_hex=signed_bytes.hex(),
    )
    if continuation is not None:
        consumed_continuation = _consume_continuation_capability(
            continuation_capability
        )
        if consumed_continuation != continuation:
            raise RuntimeError(
                "target C2 continuation changed during durable signing"
            )
    consumed = _consume_c2_capability(c2_capability)
    if consumed != c2:
        raise RuntimeError("target C2 capability changed during durable signing")
    return signed, proof


__all__ = (
    "TargetAuthorityBindingV3",
    "TargetC2AuthorityV3",
    "TargetC2EvidenceV3",
    "TargetEpochEvidenceV3",
    "SignedTargetAuthorityBindingV3",
    "bind_target_authority_v3",
    "require_target_authority_continuation_v3",
    "verify_signed_target_authority_v3",
)
