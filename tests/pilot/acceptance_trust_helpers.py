from __future__ import annotations

import hashlib
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from protector.pilot.acceptance import AcceptanceManifestV2
from protector.pilot.acceptance_authority import (
    AcceptanceAuthorityTrustContextV2,
    build_authority_trust_context,
)
from protector.pilot.acceptance_trust import (
    AcceptanceGate,
    AcceptanceRolePinsV2,
    AcceptanceRolePublicKeyPathsV2,
    AcceptanceTrustPolicyV2,
    VerifiedAcceptanceTrustV2,
    canonical_json_bytes,
    verify_acceptance_trust_chain,
)
from protector.pilot.trusted_artifacts import (
    ed25519_public_key_spki_sha256,
)

UTC = timezone.utc
START = datetime(2026, 7, 30, tzinfo=UTC)


@dataclass(frozen=True)
class VerifiedAcceptanceTrustBundle:
    trust: VerifiedAcceptanceTrustV2
    expected_offline_root_spki_sha256: str
    root_public_key: Path
    policy: Path
    policy_signature: Path
    role_public_keys: AcceptanceRolePublicKeyPathsV2
    manifest: Path
    manifest_signature: Path


def _run_openssl(arguments: list[str]) -> bytes:
    return subprocess.run(
        ["openssl", *arguments],
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout


def _secure_write(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def _generate_ed25519_keypair(
    root: Path,
    role: str,
) -> tuple[Path, Path]:
    private = root / f"{role}.private.pem"
    public = root / f"{role}.public.pem"
    _run_openssl(
        ["genpkey", "-algorithm", "ED25519", "-out", str(private)]
    )
    private.chmod(0o600)
    _run_openssl(
        ["pkey", "-in", str(private), "-pubout", "-out", str(public)]
    )
    public.chmod(0o600)
    return private, public


def _sign(
    *,
    private_key: Path,
    payload_path: Path,
    signature_path: Path,
) -> Path:
    _run_openssl(
        [
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(payload_path),
            "-out",
            str(signature_path),
        ]
    )
    signature_path.chmod(0o600)
    return signature_path


def verified_trust_bundle(
    artifact_root: Path,
    manifest: AcceptanceManifestV2,
    *,
    policy_id: str = "policy-2026-001",
    campaign_id: str = "campaign-2026-001",
    valid_from: datetime = START - timedelta(hours=1),
    valid_until: datetime = START + timedelta(hours=9),
    allowed_gates: tuple[AcceptanceGate, ...] = ("8h",),
) -> VerifiedAcceptanceTrustBundle:
    """Build and verify a real offline-root chain around a fixture manifest."""
    trust_root = Path(
        tempfile.mkdtemp(
            prefix="acceptance-trust-",
            dir=artifact_root,
        )
    )
    trust_root.chmod(0o700)
    root_private, root_public = _generate_ed25519_keypair(
        trust_root,
        "root",
    )
    manifest_private, manifest_public = _generate_ed25519_keypair(
        trust_root,
        "manifest",
    )
    _, report_public = _generate_ed25519_keypair(trust_root, "report")
    _, conditional_public = _generate_ed25519_keypair(
        trust_root,
        "conditional",
    )
    capacity_public = _secure_write(
        trust_root / "capacity.public.pem",
        (artifact_root / "capacity-authority-public.pem").read_bytes(),
    )
    run_public = _secure_write(
        trust_root / "run.public.pem",
        (artifact_root / "target-run-authority.pem").read_bytes(),
    )
    role_paths = AcceptanceRolePublicKeyPathsV2(
        manifest=manifest_public,
        capacity=capacity_public,
        run=run_public,
        report=report_public,
        conditional=conditional_public,
    )
    role_pins = AcceptanceRolePinsV2(
        schema_version="acceptance-role-pins.v2",
        manifest_spki_sha256=ed25519_public_key_spki_sha256(
            manifest_public.read_bytes()
        ),
        capacity_spki_sha256=ed25519_public_key_spki_sha256(
            capacity_public.read_bytes()
        ),
        run_spki_sha256=ed25519_public_key_spki_sha256(
            run_public.read_bytes()
        ),
        report_spki_sha256=ed25519_public_key_spki_sha256(
            report_public.read_bytes()
        ),
        conditional_spki_sha256=ed25519_public_key_spki_sha256(
            conditional_public.read_bytes()
        ),
    )
    manifest_payload = canonical_json_bytes(manifest)
    manifest_path = _secure_write(
        trust_root / "acceptance-manifest.json",
        manifest_payload,
    )
    manifest_signature = _sign(
        private_key=manifest_private,
        payload_path=manifest_path,
        signature_path=trust_root / "acceptance-manifest.sig",
    )
    root_spki_sha256 = ed25519_public_key_spki_sha256(
        root_public.read_bytes()
    )
    policy = AcceptanceTrustPolicyV2(
        schema_version="acceptance-trust-policy.v2",
        policy_id=policy_id,
        campaign_id=campaign_id,
        site_id=manifest.site_id,
        signature_algorithm="Ed25519",
        root_spki_sha256=root_spki_sha256,
        valid_from=valid_from,
        valid_until=valid_until,
        allowed_gates=allowed_gates,
        manifest_payload_sha256=hashlib.sha256(
            manifest_payload
        ).hexdigest(),
        roles=role_pins,
    )
    policy_path = _secure_write(
        trust_root / "acceptance-trust-policy.json",
        canonical_json_bytes(policy),
    )
    policy_signature = _sign(
        private_key=root_private,
        payload_path=policy_path,
        signature_path=trust_root / "acceptance-trust-policy.sig",
    )
    trust = verify_acceptance_trust_chain(
        expected_offline_root_spki_sha256=root_spki_sha256,
        root_public_key_path=root_public,
        policy_path=policy_path,
        policy_signature_path=policy_signature,
        role_public_key_paths=role_paths,
        manifest_path=manifest_path,
        manifest_signature_path=manifest_signature,
    )
    return VerifiedAcceptanceTrustBundle(
        trust=trust,
        expected_offline_root_spki_sha256=root_spki_sha256,
        root_public_key=root_public,
        policy=policy_path,
        policy_signature=policy_signature,
        role_public_keys=role_paths,
        manifest=manifest_path,
        manifest_signature=manifest_signature,
    )


def verified_trust(
    artifact_root: Path,
    manifest: AcceptanceManifestV2,
    *,
    policy_id: str = "policy-2026-001",
    campaign_id: str = "campaign-2026-001",
    valid_from: datetime = START - timedelta(hours=1),
    valid_until: datetime = START + timedelta(hours=9),
    allowed_gates: tuple[AcceptanceGate, ...] = ("8h",),
) -> VerifiedAcceptanceTrustV2:
    return verified_trust_bundle(
        artifact_root,
        manifest,
        policy_id=policy_id,
        campaign_id=campaign_id,
        valid_from=valid_from,
        valid_until=valid_until,
        allowed_gates=allowed_gates,
    ).trust


def authority_trust_context(
    artifact_root: Path,
    manifest: AcceptanceManifestV2,
    **trust_updates: object,
) -> AcceptanceAuthorityTrustContextV2:
    trust = verified_trust(
        artifact_root,
        manifest,
        **trust_updates,
    )
    return build_authority_trust_context(
        trust=trust,
        configured_site_id=manifest.site_id,
        configured_campaign_id=trust.policy.campaign_id,
        configured_gate="8h",
    )
