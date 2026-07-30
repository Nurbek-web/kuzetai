from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from protector.pilot.acceptance_authority import (
    build_acceptance_trust_binding,
    build_authority_trust_context,
)
from protector.pilot.acceptance_source_profile import (
    AttestedSourceProfileExpectationV2,
    TargetSourceProfileAttestationV2,
    capture_verified_target_source_profile_attestation,
)
from protector.pilot.acceptance_target import (
    ObservedGpuDeviceV2,
    ObservedGpuInventoryV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
    TargetSourceBindingV2,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.runtime.source_profile import (
    Ed25519SourceProfileProofSigner,
    SourceProfileExpectation,
)
from protector.pilot.trusted_artifacts import ed25519_public_key_spki_sha256
from tests.pilot.acceptance_trust_helpers import verified_trust_bundle
from tests.pilot.test_acceptance_report import _manifest

COMMITMENT_KEY = hashlib.sha256(b"target-source-profile-commitment").digest()
MILESTONE_KEY = hashlib.sha256(b"target-source-profile-milestones").digest()
PROOF_SEED = hashlib.sha256(b"target-source-profile-proof").digest()
PROOF_KEY_ID = "source-proof-2026-07"
MILESTONE_KEY_ID = "source-milestones-2026-07"


def _resolved_sources() -> tuple[str, ...]:
    return tuple(
        f"rtsp://operator:camera-secret-{index}@10.20.0.{index + 10}/live?token={index}"
        for index in range(20)
    )


def _expectations(
    *,
    site_id: str,
) -> tuple[SourceProfileExpectation, ...]:
    return tuple(
        SourceProfileExpectation.signed(
            site_id=site_id,
            camera_id=f"camera-{index:02}",
            source_index=index,
            resolved_url=resolved_url,
            commitment_key=COMMITMENT_KEY,
            codec="h264",
            width=1920,
            height=1080,
            fps_min=25.0,
            fps_max=25.0,
            bitrate_kbps_min=4096,
            bitrate_kbps_max=4096,
            max_timestamp_gap_ns=2_000_000_000,
            max_timestamp_skew_ns=500_000_000,
            stale_after_ns=5_000_000_000,
        )
        for index, resolved_url in enumerate(_resolved_sources())
    )


def _inventory(request_launch) -> ObservedGpuInventoryV2:
    return ObservedGpuInventoryV2(
        schema_version="observed-gpu-inventory.v2",
        devices=(
            ObservedGpuDeviceV2(
                uuid=request_launch.gpu_device_ids[0],
                product_name=request_launch.gpu_product_name,
                pci_bus_id=request_launch.gpu_pci_bus_id,
                total_vram_bytes=request_launch.gpu_total_vram_bytes,
                compute_capability=request_launch.gpu_compute_capability,
                mig_mode=request_launch.gpu_mig_mode,
            ),
        ),
        nvidia_driver_version=request_launch.nvidia_driver_version,
        cuda_driver_version=request_launch.cuda_driver_version,
        cuda_runtime_version=request_launch.cuda_runtime_version,
        nvidia_container_toolkit_version=(request_launch.nvidia_container_toolkit_version),
    )


def _request_and_identity(
    context,
    expectations: tuple[SourceProfileExpectation, ...],
    *,
    runtime_epoch: int = 1,
    runtime_epoch_started_monotonic_ns: int = 1_000_000_000,
) -> tuple[TargetRuntimeLaunchRequestV2, TargetRuntimeIdentityV2]:
    trust_binding_sha256 = hashlib.sha256(
        canonical_json_bytes(build_acceptance_trust_binding(context.trust))
    ).hexdigest()
    bindings = tuple(
        TargetSourceBindingV2(
            camera_id=expectation.camera_id,
            source_index=expectation.source_index,
            source_identity_commitment=expectation.source_identity_commitment,
        )
        for expectation in expectations
    )
    request = TargetRuntimeLaunchRequestV2(
        schema_version="target-runtime-launch-request.v2",
        campaign_id=context.configured_campaign_id,
        gate=context.configured_gate,
        launch_nonce=f"{runtime_epoch:032x}",
        manifest_sha256=context.binding.manifest_payload_sha256,
        acceptance_trust_binding_sha256=trust_binding_sha256,
        module_gate_bindings_sha256="4" * 64,
        controller_image_id_sha256="5" * 64,
        controller_image_config_sha256="6" * 64,
        controller_code_sha256="7" * 64,
        runtime_epoch=runtime_epoch,
        runtime_epoch_started_generation=runtime_epoch,
        launch=context.launch,
        source_bindings=bindings,
    )
    inventory = _inventory(request.launch)
    identity = TargetRuntimeIdentityV2(
        schema_version="target-runtime-identity.v2",
        launch_request=request,
        process_id=f"docker:{runtime_epoch:064x}",
        runtime_boot_id=f"container:{runtime_epoch:064x}",
        container_id=f"{runtime_epoch:064x}",
        container_config_sha256="9" * 64,
        runtime_image_id_sha256=request.launch.runtime_image_id_sha256,
        runtime_image_config_sha256=request.launch.runtime_image_config_sha256,
        runtime_code_sha256=request.launch.runtime_code_sha256,
        mount_contract_sha256=request.launch.mount_contract_sha256,
        controller_image_id_sha256=request.controller_image_id_sha256,
        controller_image_config_sha256=request.controller_image_config_sha256,
        controller_code_sha256=request.controller_code_sha256,
        control_network_id=request.launch.expected_control_network_id,
        control_network_config_sha256=(request.launch.expected_control_network_config_sha256),
        camera_network_id=request.launch.expected_camera_network_id,
        camera_network_config_sha256=(request.launch.expected_camera_network_config_sha256),
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=request.runtime_epoch_started_generation,
        runtime_epoch_started_monotonic_ns=runtime_epoch_started_monotonic_ns,
        identity_observed_monotonic_ns=runtime_epoch_started_monotonic_ns + 1,
        observed_gpu_inventory=inventory,
        source_bindings=request.source_bindings,
    )
    return request, identity


def _attestation(
    context,
    request: TargetRuntimeLaunchRequestV2,
    expectations: tuple[SourceProfileExpectation, ...],
    proof_signer: Ed25519SourceProfileProofSigner,
) -> TargetSourceProfileAttestationV2:
    return TargetSourceProfileAttestationV2(
        schema_version="target-source-profile-attestation.v2",
        site_id=context.configured_site_id,
        campaign_id=context.configured_campaign_id,
        gate=context.configured_gate,
        manifest_sha256=context.binding.manifest_payload_sha256,
        manifest_signature_sha256=context.trust.manifest_signature_sha256,
        manifest_role_spki_sha256=(context.trust.policy.roles.manifest_spki_sha256),
        acceptance_trust_binding_sha256=(request.acceptance_trust_binding_sha256),
        launch_attestation_sha256=context.launch.attestation_sha256,
        launch_request_sha256=request.request_sha256,
        source_profiles_sha256=context.launch.source_profiles_sha256,
        source_profile_proof_key_id=PROOF_KEY_ID,
        source_profile_proof_public_key_spki_sha256=(
            ed25519_public_key_spki_sha256(proof_signer.public_key)
        ),
        milestone_authenticator_key_id=MILESTONE_KEY_ID,
        expectations=tuple(
            AttestedSourceProfileExpectationV2.model_validate(expectation.to_dict())
            for expectation in expectations
        ),
        source_identity_commitments=tuple(
            expectation.source_identity_commitment for expectation in expectations
        ),
        authorizing=False,
    )


def _verified_fixture(tmp_path: Path, *, runtime_epoch: int = 1):
    manifest_root = tmp_path / "manifest-inputs"
    manifest_root.mkdir()
    manifest = _manifest(manifest_root)
    bundle = verified_trust_bundle(
        manifest_root,
        manifest,
        allowed_gates=("8h", "72h"),
    )
    context = build_authority_trust_context(
        trust=bundle.trust,
        configured_site_id=manifest.site_id,
        configured_campaign_id=bundle.trust.policy.campaign_id,
        configured_gate="8h",
    )
    expectations = _expectations(site_id=manifest.site_id)
    request, identity = _request_and_identity(
        context,
        expectations,
        runtime_epoch=runtime_epoch,
        runtime_epoch_started_monotonic_ns=runtime_epoch * 1_000_000_000,
    )
    proof_signer = Ed25519SourceProfileProofSigner(
        key_id=PROOF_KEY_ID,
        signing_seed=PROOF_SEED,
    )
    attestation = _attestation(context, request, expectations, proof_signer)
    profile_path = tmp_path / "target-source-profile-attestation.json"
    signature_path = tmp_path / "target-source-profile-attestation.sig"
    profile_path.write_bytes(canonical_json_bytes(attestation))
    profile_path.chmod(0o600)
    subprocess.run(
        (
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(bundle.manifest.parent / "manifest.private.pem"),
            "-in",
            str(profile_path),
            "-out",
            str(signature_path),
        ),
        check=True,
        capture_output=True,
    )
    signature_path.chmod(0o600)
    verified = capture_verified_target_source_profile_attestation(
        context=context,
        launch_request=request,
        attestation_path=profile_path,
        signature_path=signature_path,
    )
    return (
        context,
        request,
        identity,
        expectations,
        proof_signer,
        verified,
        profile_path,
        signature_path,
        bundle,
    )


def test_manifest_role_signed_source_profile_is_exact_20_and_secret_free(
    tmp_path: Path,
) -> None:
    (
        context,
        request,
        _identity,
        expectations,
        _signer,
        verified,
        profile_path,
        _signature_path,
        _bundle,
    ) = _verified_fixture(tmp_path)

    assert verified.attestation.expectations == tuple(
        AttestedSourceProfileExpectationV2.model_validate(item.to_dict()) for item in expectations
    )
    assert verified.attestation.source_identity_commitments == tuple(
        binding.source_identity_commitment for binding in request.source_bindings
    )
    assert verified.attestation.manifest_sha256 == (context.binding.manifest_payload_sha256)
    payload = profile_path.read_bytes()
    assert b"rtsp://" not in payload
    assert b"camera-secret" not in payload
    assert COMMITMENT_KEY not in payload
    assert MILESTONE_KEY not in payload
    assert PROOF_SEED not in payload
    assert verified.attestation.authorizing is False


def test_attestation_rejects_reordered_or_caller_substituted_commitments(
    tmp_path: Path,
) -> None:
    context, request, _, expectations, signer, _, _, _, _ = _verified_fixture(tmp_path)
    attestation = _attestation(context, request, expectations, signer)

    with pytest.raises(ValidationError, match="ordered|commitment|source"):
        TargetSourceProfileAttestationV2.model_validate(
            {
                **attestation.model_dump(mode="python"),
                "expectations": (
                    attestation.expectations[1],
                    attestation.expectations[0],
                    *attestation.expectations[2:],
                ),
            }
        )
    forged = attestation.model_copy(
        update={
            "source_identity_commitments": (
                "f" * 64,
                *attestation.source_identity_commitments[1:],
            )
        }
    )
    path = tmp_path / "forged.json"
    signature = tmp_path / "forged.sig"
    path.write_bytes(canonical_json_bytes(forged))
    path.chmod(0o600)
    signature.write_bytes(b"x" * 64)
    signature.chmod(0o600)
    with pytest.raises(ValueError, match="signature|commitment|source"):
        capture_verified_target_source_profile_attestation(
            context=context,
            launch_request=request,
            attestation_path=path,
            signature_path=signature,
        )


def test_capture_fails_closed_on_manifest_or_request_drift(tmp_path: Path) -> None:
    context, request, _, expectations, signer, _, _, _, bundle = _verified_fixture(tmp_path)
    attestation = _attestation(context, request, expectations, signer)
    drifted = attestation.model_copy(update={"launch_request_sha256": "f" * 64})
    path = tmp_path / "drifted.json"
    signature = tmp_path / "drifted.sig"
    path.write_bytes(canonical_json_bytes(drifted))
    path.chmod(0o600)
    private_key = bundle.manifest.parent / "manifest.private.pem"
    subprocess.run(
        (
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(path),
            "-out",
            str(signature),
        ),
        check=True,
        capture_output=True,
    )
    signature.chmod(0o600)

    with pytest.raises(ValueError, match="request|launch|binding"):
        capture_verified_target_source_profile_attestation(
            context=context,
            launch_request=request,
            attestation_path=path,
            signature_path=signature,
        )
