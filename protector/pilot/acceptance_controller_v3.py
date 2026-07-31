"""Collector-bound V3 orchestration owned entirely by the controller."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import ConfigDict, Field, model_validator

from protector.pilot.acceptance import (
    AcceptanceManifestV2,
    AcceptanceRunRecordV2,
    ConditionalGateAttestationV2,
)
from protector.pilot.acceptance_authority_v3 import (
    AcceptanceAuthorityV3,
    AcceptanceRunStateV3,
    SignedAcceptancePassAttestationV3,
)
from protector.pilot.acceptance_authority import (
    AcceptanceAuthorityTrustContextV2,
    _require_authority_trust_context,
)
from protector.pilot.acceptance_c2 import (
    SignedTargetAuthorityBindingV3,
    require_target_authority_continuation_v3,
    verify_signed_target_authority_v3,
)
from protector.pilot.acceptance_operational import (
    AcceptanceLimitsV1,
    AuthoritativeRepositoryBoundaryV1,
    OperationalAcceptanceEvidenceV1,
)
from protector.pilot.acceptance_proof import AcceptanceFinalEnvelopeV2
from protector.pilot.acceptance_proof_v3 import (
    AcceptanceProofStoreV3,
    build_acceptance_journal_proof_v3,
)
from protector.pilot.acceptance_snapshot import (
    AcceptanceAuthoritySnapshotStoreV3,
    AcceptanceAuthoritySnapshotV3,
    build_acceptance_authority_snapshot_v3,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.config import FrozenModel
from protector.pilot.trusted_artifacts import verify_ed25519_payload

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeId = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$"),
]


@dataclass(frozen=True)
class AcceptanceEvidenceCaptureV3:
    """One transactionally captured provider result, never an API body."""

    collector_id: str
    campaign_id: str
    offline_root_spki_sha256: str
    policy_id: str
    policy_sha256: str
    manifest_payload_sha256: str
    controller_image_sha256: str
    controller_code_sha256: str
    signed_target_authority: SignedTargetAuthorityBindingV3
    manifest: AcceptanceManifestV2
    run_record: AcceptanceRunRecordV2
    operational_limits: AcceptanceLimitsV1
    operational_evidence: OperationalAcceptanceEvidenceV1
    repository_boundary: AuthoritativeRepositoryBoundaryV1
    conditional_gate_decisions: tuple[ConditionalGateAttestationV2, ...]
    final_envelope_v2: AcceptanceFinalEnvelopeV2
    journal_proof_v2_path: Path


@dataclass(frozen=True)
class DurableV2EvidenceV3:
    final_envelope: AcceptanceFinalEnvelopeV2
    journal_proof_path: Path


class AcceptanceEvidenceProviderV3(Protocol):
    """Controller-owned repository/provider composition, not an HTTP seam."""

    def capture_for_snapshot(self, collector_id: str) -> AcceptanceEvidenceCaptureV3: ...

    def load_durable_v2_evidence(self, collector_id: str) -> DurableV2EvidenceV3: ...

    def readiness_probe(self) -> None: ...


class AcceptanceControllerResultV3(FrozenModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["acceptance-controller-result.v3"]
    collector_id: SafeId
    state: Literal["ATTESTED"]
    snapshot_sha256: Digest
    evaluation_sha256: Digest
    final_decision_sha256: Digest
    proof_sha256: Digest
    accepted: bool
    pass_attestation: SignedAcceptancePassAttestationV3 | None

    @model_validator(mode="after")
    def pass_attestation_is_the_only_acceptance_claim(
        self,
    ) -> AcceptanceControllerResultV3:
        if self.accepted != (self.pass_attestation is not None):
            raise ValueError("accepted status requires exactly one pass attestation")
        if self.pass_attestation is not None:
            payload = self.pass_attestation.payload
            if (
                payload.collector_id != self.collector_id
                or payload.snapshot_sha256 != self.snapshot_sha256
                or payload.evaluation_sha256 != self.evaluation_sha256
                or payload.final_decision_sha256 != self.final_decision_sha256
                or payload.proof_sha256 != self.proof_sha256
            ):
                raise ValueError("pass attestation differs from controller result")
        return self


def _exact_capture(
    value: object,
    *,
    collector_id: str,
) -> AcceptanceEvidenceCaptureV3:
    if type(value) is not AcceptanceEvidenceCaptureV3:
        raise TypeError("acceptance provider returned the wrong exact capture type")
    if (
        value.collector_id != collector_id
        or not value.journal_proof_v2_path.is_absolute()
        or value.run_record.run_id != collector_id
        or value.final_envelope_v2.record != value.run_record
        or value.repository_boundary.site_id != value.run_record.site_id
        or value.repository_boundary.manifest_sha256
        != value.run_record.manifest_sha256
    ):
        raise ValueError("acceptance provider capture binding differs")
    return value


class CollectorBoundAcceptanceControllerV3:
    """Own capture, immutable publication, evaluation, proof, and attestation."""

    def __init__(
        self,
        *,
        provider: AcceptanceEvidenceProviderV3,
        snapshot_store: AcceptanceAuthoritySnapshotStoreV3,
        authority: AcceptanceAuthorityV3,
        proof_store: AcceptanceProofStoreV3,
        trust_context: AcceptanceAuthorityTrustContextV2,
    ) -> None:
        if (
            provider is None
            or type(snapshot_store) is not AcceptanceAuthoritySnapshotStoreV3
            or type(authority) is not AcceptanceAuthorityV3
            or type(proof_store) is not AcceptanceProofStoreV3
        ):
            raise TypeError("V3 controller requires exact owned authority stores")
        self._provider = provider
        self._snapshot_store = snapshot_store
        self._authority = authority
        self._proof_store = proof_store
        self._trust_context = _require_authority_trust_context(trust_context)

    def _require_continued_snapshot(
        self,
        snapshot: AcceptanceAuthoritySnapshotV3,
    ) -> AcceptanceAuthoritySnapshotV3:
        require_target_authority_continuation_v3(
            verify_signed_target_authority_v3(
                snapshot.signed_target_authority,
                trust_context=self._trust_context,
            )
        )
        return snapshot

    def _snapshot(self, collector_id: str) -> AcceptanceAuthoritySnapshotV3:
        current = self._authority.state_store.begin(collector_id)
        if current.snapshot_sha256 is not None:
            return self._require_continued_snapshot(
                self._snapshot_store.load_exact(
                    collector_id,
                    current.snapshot_sha256,
                )
            )
        recovered = self._snapshot_store.recover_existing(collector_id)
        if recovered is not None:
            recovered = self._require_continued_snapshot(recovered)
            self._authority.state_store.commit_snapshot(recovered)
            return recovered
        capture = _exact_capture(
            self._provider.capture_for_snapshot(collector_id),
            collector_id=collector_id,
        )
        snapshot = build_acceptance_authority_snapshot_v3(
            collector_id=capture.collector_id,
            campaign_id=capture.campaign_id,
            offline_root_spki_sha256=capture.offline_root_spki_sha256,
            policy_id=capture.policy_id,
            policy_sha256=capture.policy_sha256,
            manifest_payload_sha256=capture.manifest_payload_sha256,
            controller_image_sha256=capture.controller_image_sha256,
            controller_code_sha256=capture.controller_code_sha256,
            signed_target_authority=capture.signed_target_authority,
            trust_context=self._trust_context,
            manifest=capture.manifest,
            run_record=capture.run_record,
            operational_limits=capture.operational_limits,
            operational_evidence=capture.operational_evidence,
            repository_boundary=capture.repository_boundary,
            conditional_gate_decisions=capture.conditional_gate_decisions,
        )
        published = self._snapshot_store.publish(snapshot)
        if published.sha256 != snapshot.snapshot_sha256:
            raise RuntimeError("published snapshot digest differs from observed bytes")
        self._authority.state_store.commit_snapshot(snapshot)
        return self._require_continued_snapshot(snapshot)

    def finalize_collector(self, collector_id: str) -> dict[str, object]:
        """Finalize one durable collector; no caller evidence or paths are accepted."""

        snapshot = self._snapshot(collector_id)
        finalization = self._authority.evaluate_and_finalize(snapshot)
        current = self._authority.state_store.load(collector_id)
        if current.state is AcceptanceRunStateV3.FINALIZED:
            durable = self._provider.load_durable_v2_evidence(collector_id)
            if type(durable) is not DurableV2EvidenceV3:
                raise TypeError("acceptance provider returned invalid durable V2 evidence")
            if (
                durable.final_envelope.record != snapshot.run_record
                or not durable.journal_proof_path.is_absolute()
            ):
                raise ValueError("durable V2 evidence differs from authority snapshot")
            proof = build_acceptance_journal_proof_v3(
                v2_journal_proof_path=durable.journal_proof_path,
                v2_final_envelope=durable.final_envelope,
                snapshot_sha256=snapshot.snapshot_sha256,
                standard_evaluation_sha256=(
                    finalization.evaluation.standard.outcome_sha256
                ),
                operational_evaluation_sha256=(
                    finalization.evaluation.operational.outcome_sha256
                ),
                final_decision_sha256=finalization.decision.decision_sha256,
            )
            published = self._proof_store.publish(
                collector_id=collector_id,
                proof=proof,
            )
            current = self._authority.mark_proof_published(
                collector_id,
                published.sha256,
            )
        if current.state is AcceptanceRunStateV3.PROOF_PUBLISHED:
            pass_attestation = self._authority.attest(collector_id)
        elif current.state is AcceptanceRunStateV3.ATTESTED:
            pass_attestation = current.pass_attestation
        else:
            raise RuntimeError("V3 controller did not reach proof publication")
        if pass_attestation is not None:
            try:
                signature = bytes.fromhex(pass_attestation.signature_hex)
            except ValueError:
                raise ValueError("acceptance pass signature is invalid") from None
            fingerprint = verify_ed25519_payload(
                payload=canonical_json_bytes(pass_attestation.payload),
                signature=signature,
                trusted_public_key=self._trust_context.trust.role_public_keys.run,
                label="acceptance pass attestation",
            )
            if fingerprint != self._trust_context.trust.policy.roles.run_spki_sha256:
                raise ValueError("acceptance pass signer differs from pinned run role")
        completed = self._authority.state_store.load(collector_id)
        if (
            completed.state is not AcceptanceRunStateV3.ATTESTED
            or completed.snapshot_sha256 is None
            or completed.evaluation is None
            or completed.decision is None
            or completed.proof_sha256 is None
            or completed.accepted is None
        ):
            raise RuntimeError("V3 controller durable completion is incomplete")
        result = AcceptanceControllerResultV3(
            schema_version="acceptance-controller-result.v3",
            collector_id=collector_id,
            state="ATTESTED",
            snapshot_sha256=completed.snapshot_sha256,
            evaluation_sha256=completed.evaluation.evaluation_sha256,
            final_decision_sha256=completed.decision.decision_sha256,
            proof_sha256=completed.proof_sha256,
            accepted=completed.accepted,
            pass_attestation=pass_attestation,
        )
        return result.model_dump(mode="json")

    def readiness_probe(self) -> None:
        self._provider.readiness_probe()
