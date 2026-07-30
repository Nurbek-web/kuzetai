from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
from argparse import Namespace
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import get_args

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from protector.pilot import acceptance, acceptance_authority, acceptance_trust
from protector.pilot.acceptance import build_canonical_fault_schedule
from protector.pilot.acceptance_authority import (
    AcceptanceAuthority,
    AcceptanceFaultAckRequestV2,
    AcceptanceFaultPrepareRequestV2,
    AcceptanceFinalizeRequestV2,
    AcceptanceProofRequestV2,
    AcceptanceSampleRequestV2,
    AcceptanceStartRequestV2,
    AcceptanceStartResponseV2,
    FaultEffectExecutionRequestV2,
    FaultEffectReceiptV2,
)
from protector.pilot.acceptance_proof import (
    AcceptanceFinalEnvelopeV2,
    AcceptanceJournalProofEntryV2,
)
from protector.pilot.api import acceptance_controller
from protector.pilot.api.acceptance_controller import (
    create_acceptance_controller_app,
)
from protector.pilot.trusted_artifacts import (
    CapturedRegularArtifact,
    VerifiedDetachedArtifact,
    capture_regular_bounded,
    ed25519_public_key_spki_sha256,
)
from scripts.pilot import acceptance_report as acceptance_report_cli
from scripts.pilot.replay_20 import (
    AuthenticatedTargetCollector,
    SQLiteTargetCollectorJournal,
    run_target,
)
from tests.pilot.acceptance_trust_helpers import (
    verified_trust_bundle,
)
from tests.pilot.test_acceptance_authority import (
    _binding,
    _execution,
    _workloads,
)
from tests.pilot.test_acceptance_report import _manifest, _run

FIXTURE_ROOT = (
    Path(__file__).parent
    / "fixtures"
    / "acceptance_v1_400fe18"
)
UTC = timezone.utc


def _cli_tripwire(
    name: str,
    calls: list[str],
):
    def fail(*_args: object, **_kwargs: object) -> object:
        calls.append(name)
        raise AssertionError(f"{name} must not be invoked")

    return fail


def _install_v2_cli_effect_tripwires(
    monkeypatch: pytest.MonkeyPatch,
    calls: list[str],
) -> None:
    for name in (
        "_verified_report_inputs",
        "_load_signed_report",
        "verify_acceptance_trust_chain",
        "verify_historical_acceptance_trust",
        "verify_acceptance_journal_proof",
        "load_canonical_json_bytes",
        "load_restricted_yaml_bytes",
        "verify_ed25519_payload",
        "load_conditional_gate_decisions",
        "evaluate_acceptance",
    ):
        monkeypatch.setattr(
            acceptance_report_cli,
            name,
            _cli_tripwire(name, calls),
        )
    monkeypatch.setattr(
        acceptance_report_cli,
        "capture_verified_signed_report_v2",
        _cli_tripwire("capture-v2-report", calls),
        raising=False,
    )
    monkeypatch.setattr(
        acceptance_report_cli.tempfile,
        "TemporaryDirectory",
        _cli_tripwire("temporary-key-directory", calls),
    )


def _signed_v2_report_bundle(
    tmp_path: Path,
    *,
    report: acceptance.AcceptanceReportV2 | None = None,
    name: str = "signed",
) -> tuple[
    acceptance.AcceptanceReportV2,
    acceptance.SignedReportPathsV2,
    Path,
    Path,
]:
    root = tmp_path / name
    root.mkdir()
    private_key = root / "report.private.pem"
    public_key = root / "report.public.pem"
    subprocess.run(
        (
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(private_key),
        ),
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        (
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ),
        check=True,
        capture_output=True,
        timeout=30,
    )
    if report is None:
        manifest_root = root / "manifest"
        manifest_root.mkdir()
        manifest = _manifest(manifest_root)
        report = acceptance.evaluate_acceptance(manifest, _run(manifest))
    paths = acceptance.write_signed_report(
        report,
        output_dir=root / "bundle",
        private_key=private_key,
        public_key=public_key,
    )
    return report, paths, private_key, public_key


def _complete_v2_verify_arguments(
    tmp_path: Path,
    *,
    metadata: Path,
    public_key: Path,
) -> list[str]:
    rooted_path = tmp_path / "rooted-input"
    return [
        "verify",
        "--acceptance-site-id",
        "school-01",
        "--acceptance-campaign-id",
        "campaign-2026-001",
        "--acceptance-gate",
        "8h",
        "--acceptance-offline-root-spki-sha256",
        "a" * 64,
        "--acceptance-offline-root-public-key",
        str(rooted_path),
        "--acceptance-trust-policy",
        str(rooted_path),
        "--acceptance-trust-policy-signature",
        str(rooted_path),
        "--acceptance-manifest-role-public-key",
        str(rooted_path),
        "--acceptance-capacity-role-public-key",
        str(rooted_path),
        "--acceptance-run-role-public-key",
        str(rooted_path),
        "--acceptance-report-role-public-key",
        str(rooted_path),
        "--acceptance-conditional-role-public-key",
        str(rooted_path),
        "--manifest",
        str(rooted_path),
        "--manifest-signature",
        str(rooted_path),
        "--run-record",
        str(rooted_path),
        "--run-attestation",
        str(rooted_path),
        "--run-signature",
        str(rooted_path),
        "--journal-proof",
        str(rooted_path),
        "--measured-capacity-report",
        str(rooted_path),
        "--measured-capacity-signature",
        str(rooted_path),
        "--metadata",
        str(metadata),
        "--public-key",
        str(public_key),
    ]


def _control_payloads(tmp_path: Path) -> dict[str, dict[str, object]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    manifest = _manifest(tmp_path)
    schedule = build_canonical_fault_schedule(
        tuple(source.camera_id for source in manifest.sources)
    )
    binding = _binding(
        collector_id="collector-v2-boundary",
        manifest_sha256=manifest.manifest_sha256,
        launch=manifest.launch,
        schedule=schedule,
    )
    execution = _execution(manifest.launch)
    fault = schedule[0]
    command_id = "command-" + "a" * 64
    effect_started_at = datetime(2026, 7, 30, tzinfo=UTC)
    effect_completed_at = datetime(2026, 7, 30, 0, 0, 1, tzinfo=UTC)
    receipt = FaultEffectReceiptV2(
        schema_version="acceptance-fault-effect-receipt.v2",
        command_id=command_id,
        fault_id=fault.fault_id,
        phase="inject",
        target=fault.target,
        execution_binding_sha256=execution.binding_sha256,
        executor_sha256="1" * 64,
        executor_policy_sha256="2" * 64,
        pre_state="ready",
        post_state="degraded",
        pre_runtime_boot_id="runtime-boot-a",
        post_runtime_boot_id="runtime-boot-a",
        pre_api_boot_id="api-boot-a",
        post_api_boot_id="api-boot-a",
        effect_started_at=effect_started_at,
        effect_completed_at=effect_completed_at,
        effect_proof_sha256="3" * 64,
        outcome="ensured",
    )
    return {
        "start": AcceptanceStartRequestV2(
            schema_version="acceptance-collector-start.v2",
            **binding,
            sample_interval_seconds=60,
            camera_ids=tuple(source.camera_id for source in manifest.sources),
            workloads=_workloads(manifest),
            launch=manifest.launch,
            execution=execution,
            fault_schedule=schedule,
        ).model_dump(mode="json"),
        "sample": AcceptanceSampleRequestV2(
            schema_version="acceptance-collector-sample.v2",
            **binding,
            process_healthy=True,
            scheduled_monotonic_offset_seconds=0,
        ).model_dump(mode="json"),
        "prepare_inject": AcceptanceFaultPrepareRequestV2(
            schema_version="acceptance-fault-prepare.v2",
            **binding,
            fault=fault,
            phase="inject",
            commanded_monotonic_offset_seconds=fault.offset_seconds,
        ).model_dump(mode="json"),
        "prepare_recover": AcceptanceFaultPrepareRequestV2(
            schema_version="acceptance-fault-prepare.v2",
            **binding,
            fault=fault,
            phase="recover",
            commanded_monotonic_offset_seconds=(
                fault.offset_seconds + fault.duration_seconds
            ),
        ).model_dump(mode="json"),
        "ack_inject": AcceptanceFaultAckRequestV2(
            schema_version="acceptance-fault-ack.v2",
            **binding,
            fault_id=fault.fault_id,
            phase="inject",
            command_id=command_id,
            receipt=receipt,
        ).model_dump(mode="json"),
        "finalize": AcceptanceFinalizeRequestV2(
            schema_version="acceptance-collector-finalize.v2",
            **binding,
        ).model_dump(mode="json"),
        "proof": AcceptanceProofRequestV2(
            schema_version="acceptance-proof-request.v2",
            **binding,
        ).model_dump(mode="json"),
        "effect_inject": FaultEffectExecutionRequestV2(
            schema_version="acceptance-fault-effect-execution.v2",
            collector_id=str(binding["collector_id"]),
            launch_attestation_sha256=manifest.launch.attestation_sha256,
            execution_binding_sha256=execution.binding_sha256,
            fault=fault,
            phase="inject",
            command_id=command_id,
            commanded_monotonic_offset_seconds=fault.offset_seconds,
        ).model_dump(mode="json"),
        "effect_recover": FaultEffectExecutionRequestV2(
            schema_version="acceptance-fault-effect-execution.v2",
            collector_id=str(binding["collector_id"]),
            launch_attestation_sha256=manifest.launch.attestation_sha256,
            execution_binding_sha256=execution.binding_sha256,
            fault=fault,
            phase="recover",
            command_id="command-" + "b" * 64,
            commanded_monotonic_offset_seconds=(
                fault.offset_seconds + fault.duration_seconds
            ),
        ).model_dump(mode="json"),
    }


def _literal_value(model: type[object], field: str) -> str:
    values = get_args(model.model_fields[field].annotation)  # type: ignore[attr-defined]
    assert len(values) == 1
    return values[0]


def _resign_ed25519(
    *,
    private_key: Path,
    payload: Path,
    signature: Path,
) -> None:
    subprocess.run(
        (
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(payload),
            "-out",
            str(signature),
        ),
        check=True,
        capture_output=True,
        timeout=30,
    )


def test_live_acceptance_family_is_explicit_v2_without_v1_aliases() -> None:
    expected_v2 = {
        "ScheduledFaultV2",
        "LocalFixtureSourceV2",
        "TargetSecretSourceV2",
        "SourceManifestV2",
        "ModuleDispositionV2",
        "LaunchAttestationV2",
        "ExecutionBindingV2",
        "AcceptanceManifestV2",
        "ConditionalGateAttestationV2",
        "CameraRunRecordV2",
        "AcceptanceRunRecordV2",
        "AcceptanceReportV2",
        "SignedAcceptanceEnvelopeV2",
        "AcceptanceVerificationV2",
    }
    forbidden_v1 = {
        name.removesuffix("V2") + "V1"
        for name in expected_v2
        if name.endswith("V2")
    }

    assert expected_v2 <= set(vars(acceptance))
    assert not forbidden_v1 & set(vars(acceptance))


def test_live_core_schema_tags_are_exact_v2() -> None:
    assert _literal_value(acceptance.LaunchAttestationV2, "schema_version") == (
        "acceptance-launch-attestation.v2"
    )
    assert _literal_value(acceptance.ExecutionBindingV2, "schema_version") == (
        "acceptance-execution-binding.v2"
    )
    assert _literal_value(acceptance.AcceptanceManifestV2, "schema_version") == (
        "acceptance-manifest.v2"
    )
    assert _literal_value(
        acceptance.ConditionalGateAttestationV2,
        "schema_version",
    ) == "conditional-gate-attestation.v2"
    assert _literal_value(acceptance.AcceptanceRunRecordV2, "schema_version") == (
        "acceptance-run-record.v2"
    )
    assert _literal_value(acceptance.AcceptanceReportV2, "schema_version") == (
        "acceptance-report.v2"
    )
    assert _literal_value(
        acceptance.SignedAcceptanceEnvelopeV2,
        "schema_version",
    ) == "signed-acceptance-envelope.v2"
    assert _literal_value(
        acceptance.AcceptanceVerificationV2,
        "schema_version",
    ) == "acceptance-verification.v2"


def test_live_trust_authority_and_proof_schemas_are_exact_v2() -> None:
    expected = (
        (acceptance_trust.AcceptanceRolePinsV2, "acceptance-role-pins.v2"),
        (
            acceptance_trust.AcceptanceTrustPolicyV2,
            "acceptance-trust-policy.v2",
        ),
        (
            acceptance_authority.AcceptanceTrustBindingV2,
            "acceptance-trust-binding.v2",
        ),
        (
            acceptance_authority.AcceptanceStartRequestV2,
            "acceptance-collector-start.v2",
        ),
        (
            acceptance_authority.AcceptanceSampleRequestV2,
            "acceptance-collector-sample.v2",
        ),
        (
            acceptance_authority.AcceptanceFaultPrepareRequestV2,
            "acceptance-fault-prepare.v2",
        ),
        (
            acceptance_authority.AcceptanceFaultAckRequestV2,
            "acceptance-fault-ack.v2",
        ),
        (
            acceptance_authority.AcceptanceFinalizeRequestV2,
            "acceptance-collector-finalize.v2",
        ),
        (
            acceptance_authority.AcceptanceProofRequestV2,
            "acceptance-proof-request.v2",
        ),
        (
            acceptance_authority.FaultEffectExecutionRequestV2,
            "acceptance-fault-effect-execution.v2",
        ),
        (
            acceptance_authority.FaultEffectReceiptV2,
            "acceptance-fault-effect-receipt.v2",
        ),
        (
            acceptance_authority.TargetRunAttestationV2,
            "target-run-attestation.v2",
        ),
        (AcceptanceFinalEnvelopeV2, "acceptance-final-envelope.v2"),
    )
    for model, schema in expected:
        assert _literal_value(model, "schema_version") == schema


def test_signed_v2_envelope_and_metadata_reject_coercion() -> None:
    report = acceptance.AcceptanceReportV2.model_construct()
    with pytest.raises(ValidationError):
        acceptance.SignedAcceptanceEnvelopeV2.model_validate(
            {
                "schema_version": "signed-acceptance-envelope.v2",
                "report": report,
                "html_sha256": b"0" * 64,
            }
        )
    with pytest.raises(ValidationError):
        acceptance.AcceptanceVerificationV2.model_validate(
            {
                "schema_version": "acceptance-verification.v2",
                "algorithm": b"Ed25519",
                "signed_file": "acceptance-report.json",
                "signature_file": "acceptance-report.sig",
                "html_file": "acceptance-report.html",
                "signed_sha256": "0" * 64,
                "html_sha256": "1" * 64,
                "public_key_spki_sha256": "2" * 64,
                "capacity_signature_sha256": "3" * 64,
                "capacity_trust_key_spki_sha256": "4" * 64,
            }
        )


def test_spki_identities_are_named_as_spki() -> None:
    assert "run_authority_public_key_spki_sha256" in (
        acceptance.LaunchAttestationV2.model_fields
    )
    assert "capacity_trust_key_spki_sha256" in (
        acceptance.LaunchAttestationV2.model_fields
    )
    assert "gate_trust_key_spki_sha256" in (
        acceptance.ModuleDispositionV2.model_fields
    )
    assert "public_key_spki_sha256" in (
        acceptance.ConditionalGateAttestationV2.model_fields
    )
    assert "authority_public_key_spki_sha256" in (
        acceptance.AcceptanceRunRecordV2.model_fields
    )
    assert "manifest_trust_key_spki_sha256" in (
        acceptance.AcceptanceReportV2.model_fields
    )
    assert "run_trust_key_spki_sha256" in (
        acceptance.AcceptanceReportV2.model_fields
    )
    assert "public_key_spki_sha256" in (
        acceptance.AcceptanceVerificationV2.model_fields
    )
    assert "trust_key_spki_sha256" in VerifiedDetachedArtifact.__dataclass_fields__
    assert "trust_key_sha256" not in VerifiedDetachedArtifact.__dataclass_fields__


def test_live_authority_has_no_historical_target_attestation() -> None:
    assert "TargetRunAttestationV1" not in vars(acceptance_authority)
    assert "TargetRunAttestationV2" in vars(acceptance_authority)


@pytest.mark.parametrize("metadata", [{}, {"schema_version": "unknown.v9"}])
def test_dispatcher_unknown_or_missing_schema_invokes_neither_verifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    metadata: dict[str, object],
) -> None:
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    public_key = tmp_path / "public.pem"
    public_key.write_text("not consulted", encoding="utf-8")
    calls: list[str] = []

    monkeypatch.setattr(
        acceptance,
        "verify_signed_report_v1",
        lambda *_args, **_kwargs: calls.append("v1") or True,
    )
    monkeypatch.setattr(
        acceptance,
        "verify_signed_report_v2",
        lambda *_args, **_kwargs: calls.append("v2") or True,
    )

    assert not acceptance.verify_signed_report(
        metadata_path,
        public_key=public_key,
    )
    assert calls == []


def test_dispatcher_never_falls_back_from_failed_v2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(
        '{"schema_version":"acceptance-verification.v2"}',
        encoding="utf-8",
    )
    public_key = tmp_path / "public.pem"
    public_key.write_text("not consulted", encoding="utf-8")
    calls: list[str] = []

    monkeypatch.setattr(
        acceptance,
        "verify_signed_report_v1",
        lambda *_args, **_kwargs: calls.append("v1") or True,
    )
    monkeypatch.setattr(
        acceptance,
        "verify_signed_report_v2",
        lambda *_args, **_kwargs: calls.append("v2") or False,
    )

    assert not acceptance.verify_signed_report(
        metadata_path,
        public_key=public_key,
    )
    assert calls == ["v2"]


def test_frozen_400fe18_v1_fixture_verifies_read_only() -> None:
    from protector.pilot.acceptance_legacy_v1 import verify_signed_report_v1

    assert verify_signed_report_v1(
        FIXTURE_ROOT / "acceptance-verification.json",
        public_key=FIXTURE_ROOT / "public-key.pem",
    )


def test_report_cli_process_verifies_exact_v1_fixture_without_v2_arguments() -> None:
    script = Path(__file__).parents[2] / "scripts" / "pilot" / "acceptance_report.py"

    completed = subprocess.run(
        (
            sys.executable,
            str(script),
            "verify",
            "--metadata",
            str(FIXTURE_ROOT / "acceptance-verification.json"),
            "--public-key",
            str(FIXTURE_ROOT / "public-key.pem"),
        ),
        cwd=script.parents[2],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""


def test_report_cli_v1_invokes_only_read_only_legacy_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    verify_v1 = acceptance.verify_signed_report_v1

    def counted_v1(*args: object, **kwargs: object) -> bool:
        calls.append("v1-verifier")
        return verify_v1(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(acceptance, "verify_signed_report_v1", counted_v1)
    monkeypatch.setattr(
        acceptance,
        "verify_signed_report_v2",
        _cli_tripwire("v2-verifier", calls),
    )
    _install_v2_cli_effect_tripwires(monkeypatch, calls)

    assert (
        acceptance_report_cli.main(
            [
                "verify",
                "--metadata",
                str(FIXTURE_ROOT / "acceptance-verification.json"),
                "--public-key",
                str(FIXTURE_ROOT / "public-key.pem"),
            ]
        )
        == 0
    )
    assert calls == ["v1-verifier"]


@pytest.mark.parametrize(
    "metadata_payload",
    [
        b"{",
        b"[]",
        b"{}",
        b'{"schema_version":"unknown.v9"}',
    ],
)
def test_report_cli_unknown_or_malformed_schema_invokes_no_verifier_or_v2_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    metadata_payload: bytes,
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(metadata_payload)
    public_key = tmp_path / "public.pem"
    public_key.write_text("not consulted", encoding="utf-8")
    calls: list[str] = []
    _install_v2_cli_effect_tripwires(monkeypatch, calls)
    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report",
        _cli_tripwire("report-verifier-dispatch", calls),
    )

    assert (
        acceptance_report_cli.main(
            [
                "verify",
                "--metadata",
                str(metadata),
                "--public-key",
                str(public_key),
            ]
        )
        == 2
    )
    assert calls == []


def test_report_cli_mutated_v1_fails_without_v2_effects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    copied = tmp_path / "fixture"
    shutil.copytree(FIXTURE_ROOT, copied)
    signed_report = copied / "acceptance-report.json"
    signed_report.write_bytes(signed_report.read_bytes() + b"\n")
    calls: list[str] = []
    verify_v1 = acceptance.verify_signed_report_v1

    def counted_v1(*args: object, **kwargs: object) -> bool:
        calls.append("v1-verifier")
        return verify_v1(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(acceptance, "verify_signed_report_v1", counted_v1)
    monkeypatch.setattr(
        acceptance,
        "verify_signed_report_v2",
        _cli_tripwire("v2-verifier", calls),
    )
    _install_v2_cli_effect_tripwires(monkeypatch, calls)

    assert (
        acceptance_report_cli.main(
            [
                "verify",
                "--metadata",
                str(copied / "acceptance-verification.json"),
                "--public-key",
                str(copied / "public-key.pem"),
            ]
        )
        == 2
    )
    assert calls == ["v1-verifier"]


def test_report_cli_rejects_v1_with_v2_only_arguments_before_any_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    _install_v2_cli_effect_tripwires(monkeypatch, calls)
    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report",
        _cli_tripwire("report-verifier-dispatch", calls),
    )

    assert (
        acceptance_report_cli.main(
            [
                "verify",
                "--metadata",
                str(FIXTURE_ROOT / "acceptance-verification.json"),
                "--public-key",
                str(FIXTURE_ROOT / "public-key.pem"),
                "--acceptance-site-id",
                "must-not-be-consulted",
            ]
        )
        == 2
    )
    assert calls == []


def test_report_cli_v2_missing_rooted_inputs_fails_before_verifier_or_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        '{"schema_version":"acceptance-verification.v2"}',
        encoding="utf-8",
    )
    public_key = tmp_path / "public.pem"
    public_key.write_text("not consulted", encoding="utf-8")
    calls: list[str] = []
    _install_v2_cli_effect_tripwires(monkeypatch, calls)
    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report",
        _cli_tripwire("report-verifier-dispatch", calls),
    )

    assert (
        acceptance_report_cli.main(
            [
                "verify",
                "--metadata",
                str(metadata),
                "--public-key",
                str(public_key),
            ]
        )
        == 2
    )
    assert calls == []


def test_report_cli_metadata_capture_cannot_redispatch_v1_as_v2_without_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _report, paths, _private_key, public_key = _signed_v2_report_bundle(
        tmp_path,
        name="metadata-swap",
    )
    v2_metadata_payload = paths.metadata.read_bytes()
    v1_metadata_payload = (
        FIXTURE_ROOT / "acceptance-verification.json"
    ).read_bytes()
    paths.metadata.write_bytes(v1_metadata_payload)
    original_capture = acceptance_report_cli.capture_regular_bounded
    swaps: list[str] = []
    calls: list[str] = []

    def capture_then_swap(
        path: Path,
        *,
        max_bytes: int,
        label: str,
    ) -> CapturedRegularArtifact:
        captured = original_capture(
            path,
            max_bytes=max_bytes,
            label=label,
        )
        if path == paths.metadata and not swaps:
            assert captured.payload == v1_metadata_payload
            paths.metadata.write_bytes(v2_metadata_payload)
            swaps.append("metadata")
        return captured

    _install_v2_cli_effect_tripwires(monkeypatch, calls)
    monkeypatch.setattr(
        acceptance_report_cli,
        "capture_regular_bounded",
        capture_then_swap,
    )
    original_generic_verifier = acceptance_report_cli.verify_signed_report

    def counted_generic_verifier(*args: object, **kwargs: object) -> bool:
        calls.append("generic-report-verifier")
        return original_generic_verifier(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report",
        counted_generic_verifier,
    )

    assert (
        acceptance_report_cli.main(
            [
                "verify",
                "--metadata",
                str(paths.metadata),
                "--public-key",
                str(public_key),
            ]
        )
        == 2
    )
    assert swaps == ["metadata"]
    assert calls == []


def test_report_cli_does_not_reread_signed_report_after_verification(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected_report, expected_paths, private_key, public_key = (
        _signed_v2_report_bundle(tmp_path, name="signed-report-race")
    )
    first_report = expected_report.model_copy(
        update={"reasons": (*expected_report.reasons, "first captured report")}
    )
    first_paths = acceptance.write_signed_report(
        first_report,
        output_dir=tmp_path / "signed-report-race" / "first",
        private_key=private_key,
        public_key=public_key,
    )
    original_capture = acceptance_report_cli.capture_verified_signed_report_v2
    swaps: list[str] = []
    calls: list[str] = []

    def capture_then_swap(
        *args: object,
        **kwargs: object,
    ) -> acceptance.VerifiedSignedReportV2:
        bundle = original_capture(*args, **kwargs)  # type: ignore[arg-type]
        calls.append("capture-v2-report")
        assert bundle.report == first_report
        if not swaps:
            first_paths.report_json.write_bytes(
                expected_paths.report_json.read_bytes()
            )
            swaps.append("signed-report")
        return bundle

    def rooted_inputs(
        _arguments: Namespace,
        *,
        report_public_key_payload: bytes,
    ) -> SimpleNamespace:
        calls.append("rooted-inputs")
        assert report_public_key_payload == public_key.read_bytes()
        return SimpleNamespace(expected_report=expected_report)

    monkeypatch.setattr(
        acceptance_report_cli,
        "_verified_report_inputs",
        rooted_inputs,
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "capture_verified_signed_report_v2",
        capture_then_swap,
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report",
        _cli_tripwire("generic-report-verifier", calls),
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "_load_signed_report",
        _cli_tripwire("signed-report-reread", calls),
    )

    assert (
        acceptance_report_cli.main(
            _complete_v2_verify_arguments(
                tmp_path,
                metadata=first_paths.metadata,
                public_key=public_key,
            )
        )
        == 2
    )
    assert swaps == ["signed-report"]
    assert calls == ["capture-v2-report", "rooted-inputs"]


def test_report_cli_public_key_capture_cannot_change_after_policy_pinning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, paths, _private_key, signing_public_key = (
        _signed_v2_report_bundle(tmp_path, name="public-key-race")
    )
    other_root = tmp_path / "other-key"
    other_root.mkdir()
    other_private = other_root / "other.private.pem"
    other_public = other_root / "other.public.pem"
    subprocess.run(
        (
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(other_private),
        ),
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        (
            "openssl",
            "pkey",
            "-in",
            str(other_private),
            "-pubout",
            "-out",
            str(other_public),
        ),
        check=True,
        capture_output=True,
        timeout=30,
    )
    active_public_key = tmp_path / "active-report.public.pem"
    signing_public_key_payload = signing_public_key.read_bytes()
    other_public_key_payload = other_public.read_bytes()
    active_public_key.write_bytes(signing_public_key_payload)
    original_capture = acceptance_report_cli.capture_verified_signed_report_v2
    swaps: list[str] = []
    calls: list[str] = []

    def capture_then_swap(
        *args: object,
        **kwargs: object,
    ) -> acceptance.VerifiedSignedReportV2:
        bundle = original_capture(*args, **kwargs)  # type: ignore[arg-type]
        calls.append("capture-v2-report")
        assert bundle.public_key_payload == signing_public_key_payload
        if not swaps:
            active_public_key.write_bytes(other_public_key_payload)
            swaps.append("public-key")
        return bundle

    def rooted_inputs(
        _arguments: Namespace,
        *,
        report_public_key_payload: bytes,
    ) -> SimpleNamespace:
        calls.append("rooted-inputs")
        assert report_public_key_payload == signing_public_key_payload
        assert active_public_key.read_bytes() == other_public_key_payload
        return SimpleNamespace(expected_report=report)

    monkeypatch.setattr(
        acceptance_report_cli,
        "_verified_report_inputs",
        rooted_inputs,
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "capture_verified_signed_report_v2",
        capture_then_swap,
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report",
        _cli_tripwire("generic-report-verifier", calls),
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "_load_signed_report",
        _cli_tripwire("signed-report-reread", calls),
    )

    assert (
        acceptance_report_cli.main(
            _complete_v2_verify_arguments(
                tmp_path,
                metadata=paths.metadata,
                public_key=active_public_key,
            )
        )
        == 0
    )
    assert swaps == ["public-key"]
    assert calls == ["capture-v2-report", "rooted-inputs"]


def test_capture_verified_v2_bundle_reuses_metadata_and_returns_exact_payloads(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, paths, _private_key, public_key = _signed_v2_report_bundle(
        tmp_path,
        name="exact-captured-bundle",
    )
    captured_metadata = capture_regular_bounded(
        paths.metadata,
        max_bytes=64 * 1024,
        label="acceptance report verification metadata",
    )
    assert isinstance(captured_metadata, CapturedRegularArtifact)
    original_capture = capture_regular_bounded

    def capture_without_metadata_reread(
        path: Path,
        *,
        max_bytes: int,
        label: str,
    ) -> CapturedRegularArtifact:
        if path == paths.metadata:
            raise AssertionError("metadata capture must be reused")
        return original_capture(
            path,
            max_bytes=max_bytes,
            label=label,
        )

    monkeypatch.setattr(
        acceptance,
        "capture_regular_bounded",
        capture_without_metadata_reread,
        raising=False,
    )
    bundle = acceptance.capture_verified_signed_report_v2(
        paths.metadata,
        public_key=public_key,
        captured_metadata=captured_metadata,
    )

    assert type(bundle) is acceptance.VerifiedSignedReportV2
    assert bundle.report == report
    assert bundle.public_key_payload == public_key.read_bytes()
    with pytest.raises(FrozenInstanceError):
        bundle.public_key_payload = b"replacement"  # type: ignore[misc]


def test_report_cli_uses_verified_bundle_report_and_key_without_load_reread(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, _paths, _private_key, public_key = _signed_v2_report_bundle(
        tmp_path,
        name="cli-bundle",
    )
    metadata = tmp_path / "cli-bundle-metadata.json"
    metadata_payload = b'{"schema_version":"acceptance-verification.v2"}'
    metadata.write_bytes(metadata_payload)
    captured_public_key = b"captured report public key bytes"
    calls: list[str] = []

    def captured_bundle(
        metadata_path: Path,
        *,
        public_key: Path,
        captured_metadata: CapturedRegularArtifact,
    ) -> SimpleNamespace:
        calls.append("capture-bundle")
        assert metadata_path == metadata
        assert public_key == public_key_path
        assert captured_metadata.payload == metadata_payload
        return SimpleNamespace(
            report=report,
            public_key_payload=captured_public_key,
        )

    def rooted_inputs(
        _arguments: Namespace,
        *,
        report_public_key_payload: bytes,
    ) -> SimpleNamespace:
        calls.append("rooted-inputs")
        assert report_public_key_payload == captured_public_key
        return SimpleNamespace(expected_report=report)

    public_key_path = public_key
    monkeypatch.setattr(
        acceptance_report_cli,
        "capture_verified_signed_report_v2",
        captured_bundle,
        raising=False,
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "_verified_report_inputs",
        rooted_inputs,
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report",
        _cli_tripwire("generic-report-verifier", calls),
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "_load_signed_report",
        _cli_tripwire("signed-report-reread", calls),
    )

    assert (
        acceptance_report_cli.main(
            _complete_v2_verify_arguments(
                tmp_path,
                metadata=metadata,
                public_key=public_key,
            )
        )
        == 0
    )
    assert calls == ["capture-bundle", "rooted-inputs"]


def test_report_cli_failed_v2_capture_never_falls_back_or_reaches_rooted_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    metadata = tmp_path / "failed-v2-metadata.json"
    metadata.write_bytes(
        b'{"schema_version":"acceptance-verification.v2"}'
    )
    public_key = tmp_path / "failed-v2-public.pem"
    public_key.write_bytes(b"not a key")
    calls: list[str] = []

    def failed_capture(*_args: object, **_kwargs: object) -> object:
        calls.append("capture-v2")
        raise ValueError("V2 report capture failed")

    monkeypatch.setattr(
        acceptance_report_cli,
        "capture_verified_signed_report_v2",
        failed_capture,
        raising=False,
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "_verified_report_inputs",
        lambda *_args, **_kwargs: (
            calls.append("rooted-inputs")
            or SimpleNamespace(expected_report=object())
        ),
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report",
        lambda *_args, **_kwargs: calls.append("generic-verifier") or False,
    )
    monkeypatch.setattr(
        acceptance_report_cli,
        "verify_signed_report_v1",
        _cli_tripwire("legacy-verifier", calls),
        raising=False,
    )

    assert (
        acceptance_report_cli.main(
            _complete_v2_verify_arguments(
                tmp_path,
                metadata=metadata,
                public_key=public_key,
            )
        )
        == 2
    )
    assert calls == ["capture-v2"]


@pytest.mark.parametrize(
    "filename",
    [
        "acceptance-report.json",
        "acceptance-report.html",
        "acceptance-report.sig",
        "public-key.pem",
    ],
)
def test_frozen_400fe18_v1_fixture_rejects_each_artifact_mutation(
    tmp_path: Path,
    filename: str,
) -> None:
    from protector.pilot.acceptance_legacy_v1 import verify_signed_report_v1

    copied = tmp_path / "fixture"
    shutil.copytree(FIXTURE_ROOT, copied)
    target = copied / filename
    target.write_bytes(target.read_bytes() + b"\n")

    assert not verify_signed_report_v1(
        copied / "acceptance-verification.json",
        public_key=copied / "public-key.pem",
    )


def test_legacy_v1_raw_pem_identity_differs_but_v2_spki_identity_is_stable() -> None:
    public_key = (FIXTURE_ROOT / "public-key.pem").read_bytes()
    reformatted = b"\n" + public_key.replace(b"\n", b"\r\n") + b"\n"

    assert hashlib.sha256(public_key).hexdigest() != hashlib.sha256(reformatted).hexdigest()
    assert ed25519_public_key_spki_sha256(public_key) == (
        ed25519_public_key_spki_sha256(reformatted)
    )


def test_legacy_v1_preserves_historical_unchecked_envelope_schema_quirk(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from protector.pilot import acceptance_legacy_v1

    copied = tmp_path / "fixture"
    shutil.copytree(FIXTURE_ROOT, copied)
    signed_path = copied / "acceptance-report.json"
    envelope = json.loads(signed_path.read_bytes())
    envelope["schema_version"] = "historical-quirk-is-not-dispatched-here"
    signed_payload = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    signed_path.write_bytes(signed_payload)
    metadata_path = copied / "acceptance-verification.json"
    metadata = json.loads(metadata_path.read_bytes())
    metadata["signed_sha256"] = hashlib.sha256(signed_payload).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    monkeypatch.setattr(
        acceptance_legacy_v1.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
    )

    assert acceptance_legacy_v1.verify_signed_report_v1(
        metadata_path,
        public_key=copied / "public-key.pem",
    )


def test_legacy_module_exposes_verification_only() -> None:
    from protector.pilot import acceptance_legacy_v1

    forbidden = {
        "write_signed_report",
        "evaluate_acceptance",
        "load_acceptance_manifest",
        "load_run_record",
        "authorize_acceptance_execution",
        "ExecutionTrustGrantV1",
    }
    assert not forbidden & set(vars(acceptance_legacy_v1))


def test_no_private_key_is_retained_in_golden_fixture() -> None:
    files = tuple(path for path in FIXTURE_ROOT.rglob("*") if path.is_file())
    assert files
    assert all("private" not in path.name.lower() for path in files)
    assert all(b"PRIVATE KEY" not in path.read_bytes() for path in files)


def test_controller_rejects_every_legacy_operation_before_authority_effects(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class AuthoritySpy:
        def start(self, _payload: dict[str, object]) -> dict[str, object]:
            calls.append("start")
            return {}

        def sample(self, _payload: dict[str, object]) -> dict[str, object]:
            calls.append("sample")
            return {}

        def prepare_fault(self, _payload: dict[str, object]) -> dict[str, object]:
            calls.append("prepare_fault")
            return {}

        def acknowledge_fault(self, _payload: dict[str, object]) -> dict[str, object]:
            calls.append("acknowledge_fault")
            return {}

        def finalize(self, _payload: dict[str, object]) -> dict[str, object]:
            calls.append("finalize")
            return {}

        def proof_metadata(self, _payload: dict[str, object]) -> tuple[object, object]:
            calls.append("proof")
            return object(), ()

    token = "controller-version-integrity-token"
    app = create_acceptance_controller_app(
        authority=AuthoritySpy(),
        controller_token=token,
        runtime_lock_path=tmp_path / "controller.lock",
    )
    client = TestClient(app)
    payloads = _control_payloads(tmp_path)
    cases = (
        ("/api/internal/acceptance/start", payloads["start"]),
        ("/api/internal/acceptance/sample", payloads["sample"]),
        ("/api/internal/acceptance/fault/prepare", payloads["prepare_inject"]),
        ("/api/internal/acceptance/fault/prepare", payloads["prepare_recover"]),
        ("/api/internal/acceptance/fault/ack", payloads["ack_inject"]),
        ("/api/internal/acceptance/finalize", payloads["finalize"]),
        ("/api/internal/acceptance/proof", payloads["proof"]),
    )
    for path, current in cases:
        legacy = {**current, "schema_version": str(current["schema_version"]).replace(".v2", ".v1")}
        response = client.post(
            path,
            headers={"Authorization": f"Bearer {token}"},
            json=legacy,
        )
        assert response.status_code == 422, (path, response.text)
    assert calls == []


def test_authority_rejects_every_legacy_operation_before_dependencies(
    tmp_path: Path,
) -> None:
    class Tripwire:
        def __getattribute__(self, name: str) -> object:
            raise AssertionError(f"authority dependency was touched: {name}")

    authority = object.__new__(AcceptanceAuthority)
    authority.journal = Tripwire()
    authority.adapter = Tripwire()
    authority.signer = Tripwire()
    authority.proof_store = Tripwire()
    authority.trust_context = Tripwire()
    payloads = _control_payloads(tmp_path)
    cases = (
        ("start", payloads["start"]),
        ("sample", payloads["sample"]),
        ("prepare_fault", payloads["prepare_inject"]),
        ("prepare_fault", payloads["prepare_recover"]),
        ("acknowledge_fault", payloads["ack_inject"]),
        ("finalize", payloads["finalize"]),
        ("proof_metadata", payloads["proof"]),
    )
    for method_name, current in cases:
        legacy = {**current, "schema_version": str(current["schema_version"]).replace(".v2", ".v1")}
        with pytest.raises(ValidationError):
            getattr(authority, method_name)(legacy)


@pytest.mark.parametrize("phase", ["inject", "recover"])
def test_fault_effect_journal_rejects_legacy_request_before_write(
    tmp_path: Path,
    phase: str,
) -> None:
    root = tmp_path / f"collector-{phase}"
    root.mkdir(mode=0o700)
    journal = SQLiteTargetCollectorJournal(root / "state.sqlite3")
    payload = _control_payloads(tmp_path / phase)[f"effect_{phase}"]
    legacy = {**payload, "schema_version": "acceptance-fault-effect-execution.v1"}

    with pytest.raises(ValidationError):
        journal.prepare_effect(str(payload["command_id"]), request=legacy)

    assert journal.effect(str(payload["command_id"])) is None


def test_cached_completed_response_is_reparsed_before_network_or_completion(
    tmp_path: Path,
) -> None:
    payload = _control_payloads(tmp_path)["start"]
    cached = {
        "schema_version": "acceptance-collector-start-response.v1",
        **{
            field: payload[field]
            for field in acceptance_authority.CollectorBindingV2.model_fields
            if field in payload
        },
    }
    calls: list[str] = []

    class CachedJournal:
        def stage(
            self,
            _operation_key: str,
            request: dict[str, object],
        ) -> dict[str, object]:
            return request

        def response(self, _operation_key: str) -> dict[str, object]:
            return cached

        def complete(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            calls.append("complete")
            return {}

    collector = object.__new__(AuthenticatedTargetCollector)
    collector._operation_lock = threading.RLock()
    collector._journal = CachedJournal()
    collector._post = lambda *_args, **_kwargs: calls.append("network") or {}

    with pytest.raises(ValidationError):
        collector._durable_post(
            operation_key="start",
            path="/api/internal/acceptance/start",
            payload=payload,
            limit=64 * 1024,
            response_model=AcceptanceStartResponseV2,
        )
    assert calls == []


def test_cached_fault_effect_request_is_reparsed_as_exact_v2(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cached-effect"
    root.mkdir(mode=0o700)
    journal = SQLiteTargetCollectorJournal(root / "state.sqlite3")
    payload = _control_payloads(tmp_path / "effect-fixture")["effect_inject"]
    command_id = str(payload["command_id"])
    journal.prepare_effect(command_id, request=payload)
    legacy = json.dumps(
        {
            **payload,
            "schema_version": "acceptance-fault-effect-execution.v1",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE executor_receipts SET request_json = ?, request_sha256 = ? "
            "WHERE command_id = ?",
            (
                legacy,
                hashlib.sha256(legacy.encode()).hexdigest(),
                command_id,
            ),
        )

    with pytest.raises(ValidationError):
        journal.effect(command_id)


@pytest.mark.parametrize(
    ("kind", "schema"),
    tuple(acceptance_authority._DURABLE_ENTRY_SCHEMAS.items()),
)
def test_cached_authority_journal_entry_requires_operation_specific_v2(
    kind: str,
    schema: str,
) -> None:
    legacy = json.dumps(
        {"schema_version": schema.replace(".v2", ".v1")},
        sort_keys=True,
        separators=(",", ":"),
    )
    with pytest.raises(RuntimeError, match="schema"):
        acceptance_authority._decode_durable_entry(kind, legacy)


def test_authority_journal_rejects_legacy_schema_before_append(
    tmp_path: Path,
) -> None:
    journal = acceptance_authority.SQLiteAcceptanceAuthorityJournal(
        tmp_path / "authority.sqlite3"
    )
    with pytest.raises(ValueError, match="schema"):
        journal.append(
            collector_id="collector-v2-boundary",
            kind="start",
            identity="start",
            payload={"schema_version": "acceptance-collector-start.v1"},
            created_at=datetime(2026, 7, 30, tzinfo=UTC),
        )
    assert journal.entry_count("collector-v2-boundary") == 0


def test_bare_target_run_record_is_not_a_completed_final_envelope(
    tmp_path: Path,
) -> None:
    record = _run(_manifest(tmp_path), hours=8).model_copy(update={"gate": "8h"})
    with pytest.raises(ValidationError):
        AcceptanceFinalEnvelopeV2.model_validate(record.model_dump(mode="json"))


def test_unsigned_authority_has_no_bare_final_record_fallback(
    tmp_path: Path,
) -> None:
    payload = _control_payloads(tmp_path)["finalize"]
    request = AcceptanceFinalizeRequestV2.model_validate(payload)
    record_root = tmp_path / "record"
    record_root.mkdir()
    record = _run(_manifest(record_root), hours=8).model_copy(
        update={"gate": "8h"}
    )
    authority = object.__new__(AcceptanceAuthority)
    authority.signer = None
    authority.proof_store = SimpleNamespace(
        publish_chunks=lambda *_args, **_kwargs: pytest.fail("proof store touched")
    )

    with pytest.raises(RuntimeError, match="signer"):
        authority._attested_final_response(request=request, record=record)


def test_proof_export_rejects_legacy_header_before_proof_store_effect() -> None:
    calls: list[str] = []

    class ProofStoreSpy:
        def publish_chunks(self, *_args: object, **_kwargs: object) -> object:
            calls.append("publish")
            return object()

    journal = object.__new__(acceptance_authority.SQLiteAcceptanceAuthorityJournal)
    legacy_header = SimpleNamespace(
        schema_version="acceptance-journal-proof-header.v1",
        collector_id="collector-v2-boundary",
    )
    with pytest.raises(ValueError, match="exact V2"):
        journal.export_proof(
            collector_id="collector-v2-boundary",
            header=legacy_header,  # type: ignore[arg-type]
            run_record_sha256="0" * 64,
            proof_store=ProofStoreSpy(),  # type: ignore[arg-type]
        )
    assert calls == []


def test_proof_entry_rejects_legacy_operation_payload() -> None:
    with pytest.raises(ValidationError, match="payload"):
        AcceptanceJournalProofEntryV2(
            schema_version="acceptance-journal-proof-entry.v2",
            ordinal=1,
            collector_id="collector-v2-boundary",
            kind="start",
            identity="start",
            payload={"schema_version": "acceptance-collector-start.v1"},
            created_at="2026-07-30T00:00:00+00:00",
            previous_entry_sha256="",
            entry_sha256="0" * 64,
        )


def test_report_writer_rejects_legacy_report_before_key_or_output_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from protector.pilot.acceptance_legacy_v1 import AcceptanceReportV1

    envelope = json.loads(
        (FIXTURE_ROOT / "acceptance-report.json").read_bytes()
    )
    legacy_report = AcceptanceReportV1.model_validate(envelope["report"])
    calls: list[str] = []

    def key_read_tripwire(*_args: object, **_kwargs: object) -> bytes:
        calls.append("key-read")
        raise AssertionError("signing key was read")

    monkeypatch.setattr(
        acceptance,
        "_read_regular_bounded_with_metadata",
        key_read_tripwire,
    )
    monkeypatch.setattr(
        acceptance,
        "_read_regular_bounded",
        key_read_tripwire,
    )
    output_dir = tmp_path / "out"
    with pytest.raises(ValueError, match="exact V2"):
        acceptance.write_signed_report(
            legacy_report,  # type: ignore[arg-type]
            output_dir=output_dir,
            private_key=tmp_path / "private.pem",
            public_key=tmp_path / "public.pem",
        )
    assert calls == []
    assert not output_dir.exists()


def test_report_cli_refuses_legacy_signed_metadata() -> None:
    with pytest.raises(ValidationError):
        acceptance_report_cli._load_signed_report(
            FIXTURE_ROOT / "acceptance-verification.json"
        )


def test_target_boot_rejects_signed_legacy_manifest_before_process_or_state(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    bundle = verified_trust_bundle(tmp_path, manifest)
    legacy_manifest = json.loads(bundle.manifest.read_bytes())
    legacy_manifest["schema_version"] = "acceptance-manifest.v1"
    manifest_payload = acceptance_trust.canonical_json_bytes(legacy_manifest)
    bundle.manifest.write_bytes(manifest_payload)
    _resign_ed25519(
        private_key=bundle.manifest.parent / "manifest.private.pem",
        payload=bundle.manifest,
        signature=bundle.manifest_signature,
    )
    policy = json.loads(bundle.policy.read_bytes())
    policy["manifest_payload_sha256"] = hashlib.sha256(manifest_payload).hexdigest()
    bundle.policy.write_bytes(acceptance_trust.canonical_json_bytes(policy))
    _resign_ed25519(
        private_key=bundle.policy.parent / "root.private.pem",
        payload=bundle.policy,
        signature=bundle.policy_signature,
    )
    collector_state = tmp_path / "runner-state" / "collector.sqlite3"
    arguments = Namespace(
        duration_seconds=28_800,
        acceptance_gate="8h",
        stop_grace_seconds=30,
        collector_interval_seconds=60,
        acceptance_offline_root_public_key=bundle.root_public_key,
        acceptance_trust_policy=bundle.policy,
        acceptance_trust_policy_signature=bundle.policy_signature,
        acceptance_manifest_role_public_key=bundle.role_public_keys.manifest,
        acceptance_capacity_role_public_key=bundle.role_public_keys.capacity,
        acceptance_run_role_public_key=bundle.role_public_keys.run,
        acceptance_report_role_public_key=bundle.role_public_keys.report,
        acceptance_conditional_role_public_key=(
            bundle.role_public_keys.conditional
        ),
        manifest=bundle.manifest,
        manifest_signature=bundle.manifest_signature,
        acceptance_site_id=manifest.site_id,
        acceptance_campaign_id=bundle.trust.policy.campaign_id,
        acceptance_offline_root_spki_sha256=(
            bundle.expected_offline_root_spki_sha256
        ),
        collector_state=collector_state,
    )
    process_calls: list[str] = []

    with pytest.raises(ValueError, match="manifest|schema"):
        run_target(
            arguments,
            process_factory=lambda *_args, **_kwargs: (
                process_calls.append("process") or object()
            ),
        )

    assert process_calls == []
    assert not collector_state.exists()
    assert not collector_state.with_name(
        f"{collector_state.name}.campaign.lock"
    ).exists()


def test_production_authority_rejects_signed_legacy_policy_before_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    bundle = verified_trust_bundle(tmp_path, manifest)
    legacy_policy = json.loads(bundle.policy.read_bytes())
    legacy_policy["schema_version"] = "acceptance-trust-policy.v1"
    bundle.policy.write_bytes(
        acceptance_trust.canonical_json_bytes(legacy_policy)
    )
    _resign_ed25519(
        private_key=bundle.policy.parent / "root.private.pem",
        payload=bundle.policy,
        signature=bundle.policy_signature,
    )
    for name in tuple(os.environ):
        if name.startswith("PILOT_ACCEPTANCE_"):
            monkeypatch.delenv(name, raising=False)
    journal_path = tmp_path / "production" / "authority.sqlite3"
    proof_root = tmp_path / "production-proofs"
    monkeypatch.setenv("PILOT_SITE_ID", manifest.site_id)
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_CAMPAIGN_ID",
        bundle.trust.policy.campaign_id,
    )
    monkeypatch.setenv("PILOT_ACCEPTANCE_GATE", "8h")
    monkeypatch.setenv(
        "PILOT_ACCEPTANCE_OFFLINE_ROOT_SPKI_SHA256",
        bundle.expected_offline_root_spki_sha256,
    )
    monkeypatch.setenv("PILOT_ACCEPTANCE_JOURNAL_PATH", str(journal_path))
    monkeypatch.setenv("PILOT_ACCEPTANCE_PROOF_DIR", str(proof_root))
    monkeypatch.setattr(
        acceptance_controller,
        "_PROTECTED_NAMESPACE_RUNTIME_UID",
        os.geteuid(),
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_PROTECTED_NAMESPACE_RUNTIME_GID",
        os.getegid(),
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_OFFLINE_ROOT_PUBLIC_KEY_PATH",
        bundle.root_public_key,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_TRUST_POLICY_PATH",
        bundle.policy,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_TRUST_POLICY_SIGNATURE_PATH",
        bundle.policy_signature,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_ROLE_PUBLIC_KEY_PATHS",
        bundle.role_public_keys,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_ACCEPTANCE_MANIFEST_PATH",
        bundle.manifest,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_ACCEPTANCE_MANIFEST_SIGNATURE_PATH",
        bundle.manifest_signature,
    )
    resource_calls: list[str] = []

    def signer_tripwire(*_args: object, **_kwargs: object) -> object:
        resource_calls.append("signer")
        return object()

    def authority_tripwire(*_args: object, **_kwargs: object) -> object:
        resource_calls.append("authority")
        return object()

    monkeypatch.setattr(
        acceptance_controller,
        "OpenSSLAcceptanceRunSigner",
        signer_tripwire,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_compose_acceptance_authority",
        authority_tripwire,
    )

    with pytest.raises(RuntimeError, match="offline-root trust"):
        acceptance_controller.build_production_acceptance_authority()

    assert resource_calls == []
    assert not journal_path.exists()
    assert not proof_root.exists()
