#!/usr/bin/env python3
"""Validate an observed run and emit an externally signed acceptance report."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from protector.pilot import acceptance as acceptance_contracts  # noqa: E402
from protector.pilot.acceptance import (  # noqa: E402
    MAX_ACCEPTANCE_RECORD_BYTES,
    AcceptanceManifestV2,
    AcceptanceReportV2,
    AcceptanceRunRecordV2,
    AcceptanceVerificationV2,
    SignedAcceptanceEnvelopeV2,
    capture_verified_signed_report_v2,
    evaluate_acceptance,
    load_conditional_gate_decisions,
    verify_signed_report,  # noqa: F401 - retained as a V2 no-call tripwire
    write_signed_report,
)
from protector.pilot.acceptance_proof import (  # noqa: E402
    TargetRunAttestationV2,
    verify_acceptance_journal_proof,
)
from protector.pilot.acceptance_trust import (  # noqa: E402
    MAX_ACCEPTANCE_ATTESTATION_BYTES,
    MAX_ACCEPTANCE_CAPACITY_BYTES,
    MAX_SIGNATURE_BYTES,
    AcceptanceRolePublicKeyPathsV2,
    VerifiedAcceptanceTrustV2,
    load_canonical_json_bytes,
    load_restricted_yaml_bytes,
    verify_acceptance_trust_chain,
    verify_historical_acceptance_trust,
)
from protector.pilot.gates import MeasuredCapacityReportV1  # noqa: E402
from protector.pilot.trusted_artifacts import (  # noqa: E402
    CapturedRegularArtifact,
    capture_regular_bounded,
    ed25519_public_key_spki_sha256,
    read_regular_bounded,
    verify_ed25519_payload,
)

_V2_REQUIRED_VERIFY_ARGUMENTS = (
    "acceptance_site_id",
    "acceptance_campaign_id",
    "acceptance_gate",
    "acceptance_offline_root_spki_sha256",
    "acceptance_offline_root_public_key",
    "acceptance_trust_policy",
    "acceptance_trust_policy_signature",
    "acceptance_manifest_role_public_key",
    "acceptance_capacity_role_public_key",
    "acceptance_run_role_public_key",
    "acceptance_report_role_public_key",
    "acceptance_conditional_role_public_key",
    "manifest",
    "manifest_signature",
    "run_record",
    "run_attestation",
    "run_signature",
    "journal_proof",
    "measured_capacity_report",
    "measured_capacity_signature",
)


def _add_trust_arguments(
    parser: argparse.ArgumentParser,
    *,
    required: bool = True,
) -> None:
    parser.add_argument("--acceptance-site-id", required=required)
    parser.add_argument("--acceptance-campaign-id", required=required)
    parser.add_argument(
        "--acceptance-gate",
        choices=("8h", "72h"),
        required=required,
    )
    parser.add_argument(
        "--acceptance-offline-root-spki-sha256",
        required=required,
    )
    parser.add_argument(
        "--acceptance-offline-root-public-key",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--acceptance-trust-policy",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--acceptance-trust-policy-signature",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--acceptance-manifest-role-public-key",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--acceptance-capacity-role-public-key",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--acceptance-run-role-public-key",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--acceptance-report-role-public-key",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--acceptance-conditional-role-public-key",
        type=Path,
        required=required,
    )
    parser.add_argument("--manifest", type=Path, required=required)
    parser.add_argument("--manifest-signature", type=Path, required=required)


def _add_evidence_arguments(
    parser: argparse.ArgumentParser,
    *,
    required: bool = True,
) -> None:
    parser.add_argument("--run-record", type=Path, required=required)
    parser.add_argument("--run-attestation", type=Path, required=required)
    parser.add_argument("--run-signature", type=Path, required=required)
    parser.add_argument("--journal-proof", type=Path, required=required)
    parser.add_argument(
        "--measured-capacity-report",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--measured-capacity-signature",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--conditional-gate-decision",
        type=Path,
        action="append",
        default=[],
        help=(
            "Bounded signed conditional-gate-attestation.v2 JSON; repeat per conditional module."
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    _add_trust_arguments(generate)
    _add_evidence_arguments(generate)
    generate.add_argument("--out-dir", type=Path, required=True)
    generate.add_argument("--private-key", type=Path, required=True)
    generate.add_argument("--public-key", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    _add_trust_arguments(verify, required=False)
    _add_evidence_arguments(verify, required=False)
    verify.add_argument("--metadata", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    return parser


@dataclass(frozen=True)
class _VerifiedReportInputs:
    trust: VerifiedAcceptanceTrustV2
    manifest: AcceptanceManifestV2
    run: AcceptanceRunRecordV2
    run_signature_sha256: str
    decisions: tuple[object, ...]
    expected_report: AcceptanceReportV2


def _verification_schema_version(
    captured_metadata: CapturedRegularArtifact,
) -> str | None:
    metadata = json.loads(captured_metadata.payload)
    if not isinstance(metadata, dict):
        return None
    schema_version = metadata.get("schema_version")
    return schema_version if isinstance(schema_version, str) else None


def _v2_arguments_present(arguments: argparse.Namespace) -> bool:
    return any(
        getattr(arguments, name) is not None
        for name in _V2_REQUIRED_VERIFY_ARGUMENTS
    ) or bool(arguments.conditional_gate_decision)


def _require_v2_arguments(arguments: argparse.Namespace) -> None:
    missing = tuple(
        f"--{name.replace('_', '-')}"
        for name in _V2_REQUIRED_VERIFY_ARGUMENTS
        if getattr(arguments, name) is None
    )
    if missing:
        raise ValueError(
            "V2 verification requires rooted inputs: " + ", ".join(missing)
        )


def _verified_report_inputs(
    arguments: argparse.Namespace,
    *,
    report_public_key_payload: bytes | None = None,
) -> _VerifiedReportInputs:
    trust = verify_acceptance_trust_chain(
        expected_offline_root_spki_sha256=(arguments.acceptance_offline_root_spki_sha256),
        root_public_key_path=arguments.acceptance_offline_root_public_key,
        policy_path=arguments.acceptance_trust_policy,
        policy_signature_path=arguments.acceptance_trust_policy_signature,
        role_public_key_paths=AcceptanceRolePublicKeyPathsV2(
            manifest=arguments.acceptance_manifest_role_public_key,
            capacity=arguments.acceptance_capacity_role_public_key,
            run=arguments.acceptance_run_role_public_key,
            report=arguments.acceptance_report_role_public_key,
            conditional=arguments.acceptance_conditional_role_public_key,
        ),
        manifest_path=arguments.manifest,
        manifest_signature_path=arguments.manifest_signature,
    )
    manifest = trust.manifest
    run_payload = read_regular_bounded(
        arguments.run_record,
        max_bytes=MAX_ACCEPTANCE_RECORD_BYTES,
        label="acceptance run record",
    )
    run = load_canonical_json_bytes(
        run_payload,
        AcceptanceRunRecordV2,
        max_bytes=MAX_ACCEPTANCE_RECORD_BYTES,
        label="acceptance run record",
    )
    if (
        arguments.acceptance_site_id != trust.policy.site_id
        or arguments.acceptance_campaign_id != trust.policy.campaign_id
        or arguments.acceptance_gate not in trust.policy.allowed_gates
        or run.site_id != arguments.acceptance_site_id
        or run.gate != arguments.acceptance_gate
        or run.environment != "target"
        or run.manifest_sha256 != manifest.manifest_sha256
        or run.launch != manifest.launch
        or run.execution is None
    ):
        raise ValueError("acceptance report trust context differs from run evidence")
    verify_historical_acceptance_trust(
        trust,
        expected_site_id=arguments.acceptance_site_id,
        expected_campaign_id=arguments.acceptance_campaign_id,
        expected_gate=arguments.acceptance_gate,
        execution_started_at=run.started_at,
        verified_at=run.ended_at.astimezone(timezone.utc),
    )

    run_attestation_payload = read_regular_bounded(
        arguments.run_attestation,
        max_bytes=MAX_ACCEPTANCE_ATTESTATION_BYTES,
        label="target run attestation",
    )
    run_attestation = load_canonical_json_bytes(
        run_attestation_payload,
        TargetRunAttestationV2,
        max_bytes=MAX_ACCEPTANCE_ATTESTATION_BYTES,
        label="target run attestation",
    )
    run_signature = read_regular_bounded(
        arguments.run_signature,
        max_bytes=MAX_SIGNATURE_BYTES,
        label="target run attestation signature",
    )
    run_key_hash = verify_ed25519_payload(
        payload=run_attestation_payload,
        signature=run_signature,
        trusted_public_key=trust.role_public_keys.run,
        label="target run attestation",
    )
    if (
        run_key_hash != trust.policy.roles.run_spki_sha256
        or run_attestation.public_key_spki_sha256 != run_key_hash
        or run_attestation.offline_root_spki_sha256 != trust.root_spki_sha256
        or run_attestation.policy_id != trust.policy.policy_id
        or run_attestation.policy_sha256 != trust.policy_sha256
        or run_attestation.campaign_id != trust.policy.campaign_id
        or run_attestation.manifest_payload_sha256 != trust.manifest_payload_sha256
        or run_attestation.run_record_sha256 != hashlib.sha256(run_payload).hexdigest()
        or run_attestation.collector_id != run.run_id
        or run_attestation.site_id != run.site_id
        or run_attestation.manifest_sha256 != run.manifest_sha256
        or run_attestation.gate != run.gate
        or run_attestation.launch_attestation_sha256 != run.launch.attestation_sha256
        or run_attestation.execution_binding_sha256 != run.execution.binding_sha256
        or (
            run.authority_journal_root_sha256 is not None
            and run_attestation.journal_root_sha256 != run.authority_journal_root_sha256
        )
        or (
            run.authority_journal_entry_count is not None
            and run_attestation.journal_entry_count != run.authority_journal_entry_count
        )
        or (
            run.authority_public_key_spki_sha256 is not None
            and run_attestation.public_key_spki_sha256 != run.authority_public_key_spki_sha256
        )
    ):
        raise ValueError("controller target-run attestation differs from run evidence")
    verify_acceptance_journal_proof(
        arguments.journal_proof,
        expected_attestation=run_attestation,
        expected_run_record=run,
    )

    capacity_payload = read_regular_bounded(
        arguments.measured_capacity_report,
        max_bytes=MAX_ACCEPTANCE_CAPACITY_BYTES,
        label="measured capacity report",
    )
    capacity_signature = read_regular_bounded(
        arguments.measured_capacity_signature,
        max_bytes=MAX_SIGNATURE_BYTES,
        label="measured capacity report signature",
    )
    capacity_key_hash = verify_ed25519_payload(
        payload=capacity_payload,
        signature=capacity_signature,
        trusted_public_key=trust.role_public_keys.capacity,
        label="measured capacity report",
    )
    capacity = MeasuredCapacityReportV1.model_validate(
        load_restricted_yaml_bytes(
            capacity_payload,
            max_bytes=MAX_ACCEPTANCE_CAPACITY_BYTES,
            label="measured capacity report",
        )
    )
    if (
        hashlib.sha256(capacity_payload).hexdigest()
        != manifest.launch.measured_capacity_file_sha256
        or hashlib.sha256(capacity_signature).hexdigest()
        != manifest.launch.capacity_signature_sha256
        or capacity_key_hash != trust.policy.roles.capacity_spki_sha256
        or capacity_key_hash != manifest.launch.capacity_trust_key_spki_sha256
        or capacity.site_id != manifest.site_id
        or capacity.artifact_sha256 != manifest.launch.artifact_sha256
        or capacity.registry_entry_sha256 != manifest.launch.registry_entry_sha256
        or capacity.engine_sha256 != manifest.launch.engine_sha256
        or capacity.gpu_inventory_sha256 != manifest.launch.gpu_inventory_sha256
        or capacity.runtime_image_id_sha256 != manifest.launch.runtime_image_id_sha256
        or capacity.runtime_image_config_sha256 != manifest.launch.runtime_image_config_sha256
        or capacity.runtime_code_sha256 != manifest.launch.runtime_code_sha256
        or capacity.mount_contract_sha256 != manifest.launch.mount_contract_sha256
    ):
        raise ValueError("measured capacity evidence differs from signed launch")

    report_public_key = report_public_key_payload
    if report_public_key is None:
        report_public_key = read_regular_bounded(
            arguments.public_key,
            max_bytes=64 * 1024,
            label="acceptance report public key",
        )
    if ed25519_public_key_spki_sha256(report_public_key) != trust.policy.roles.report_spki_sha256:
        raise ValueError("report public key differs from the policy-pinned report role")

    decisions: tuple[object, ...] = ()
    if arguments.conditional_gate_decision:
        with tempfile.TemporaryDirectory(prefix="kuzet-conditional-key-") as temporary:
            conditional_key = Path(temporary) / "conditional.public.pem"
            conditional_key.write_bytes(trust.role_public_keys.conditional)
            conditional_key.chmod(0o600)
            decisions = load_conditional_gate_decisions(
                arguments.conditional_gate_decision,
                trusted_public_key=conditional_key,
            )
    expected_report = evaluate_acceptance(
        manifest,
        run,
        verified_gate_decisions=decisions,
    ).model_copy(
        update={
            "manifest_signature_sha256": trust.manifest_signature_sha256,
            "manifest_trust_key_spki_sha256": trust.policy.roles.manifest_spki_sha256,
            "run_signature_sha256": hashlib.sha256(run_signature).hexdigest(),
            "run_trust_key_spki_sha256": run_key_hash,
        }
    )
    return _VerifiedReportInputs(
        trust=trust,
        manifest=manifest,
        run=run,
        run_signature_sha256=hashlib.sha256(run_signature).hexdigest(),
        decisions=decisions,
        expected_report=expected_report,
    )


def _load_signed_report(metadata_path: Path) -> AcceptanceReportV2:
    metadata = AcceptanceVerificationV2.model_validate_json(
        read_regular_bounded(
            metadata_path,
            max_bytes=64 * 1024,
            label="acceptance report verification metadata",
        )
    )
    if metadata.schema_version != "acceptance-verification.v2":
        raise ValueError("acceptance report verification metadata is invalid")
    envelope = SignedAcceptanceEnvelopeV2.model_validate_json(
        read_regular_bounded(
            metadata_path.parent / metadata.signed_file,
            max_bytes=8 * 1024 * 1024,
            label="signed acceptance report",
        )
    )
    if envelope.schema_version != "signed-acceptance-envelope.v2":
        raise ValueError("signed acceptance report envelope is invalid")
    return envelope.report


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "verify":
            captured_metadata = capture_regular_bounded(
                arguments.metadata,
                max_bytes=64 * 1024,
                label="acceptance report verification metadata",
            )
            schema_version = _verification_schema_version(captured_metadata)
            if schema_version == "acceptance-verification.v1":
                if _v2_arguments_present(arguments):
                    raise ValueError(
                        "V1 verification does not accept V2 rooted inputs"
                    )
                return (
                    0
                    if acceptance_contracts.verify_signed_report_v1(
                        arguments.metadata,
                        public_key=arguments.public_key,
                    )
                    else 2
                )
            if schema_version != "acceptance-verification.v2":
                raise ValueError(
                    "acceptance report verification metadata schema is unsupported"
                )
            _require_v2_arguments(arguments)
            signed_bundle = capture_verified_signed_report_v2(
                arguments.metadata,
                public_key=arguments.public_key,
                captured_metadata=captured_metadata,
            )
            verified = _verified_report_inputs(
                arguments,
                report_public_key_payload=signed_bundle.public_key_payload,
            )
            if signed_bundle.report != verified.expected_report:
                raise ValueError(
                    "signed acceptance report differs from reevaluated evidence"
                )
            return 0
        verified = _verified_report_inputs(arguments)
        write_signed_report(
            verified.expected_report,
            output_dir=arguments.out_dir,
            private_key=arguments.private_key,
            public_key=arguments.public_key,
        )
        return 0 if verified.expected_report.passed else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"acceptance report refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
