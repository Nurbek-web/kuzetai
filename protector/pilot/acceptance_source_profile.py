"""Manifest-role-signed exact-source profiles for target acceptance."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from protector.pilot.acceptance_authority import (
    AcceptanceAuthorityTrustContextV2,
    _require_authority_trust_context,
    build_acceptance_trust_binding,
)
from protector.pilot.acceptance_target import TargetRuntimeLaunchRequestV2
from protector.pilot.acceptance_trust import (
    AcceptanceGate,
    canonical_json_bytes,
    load_canonical_json_bytes,
)
from protector.pilot.config import FrozenModel
from protector.pilot.runtime.source_profile import SourceProfileExpectation
from protector.pilot.trusted_artifacts import (
    capture_regular_bounded,
    ed25519_public_key_spki_sha256,
    verify_ed25519_payload,
)

MAX_TARGET_SOURCE_PROFILE_ATTESTATION_BYTES = 512 * 1024
MAX_TARGET_SOURCE_PROFILE_SIGNATURE_BYTES = 1024
_CAMERA_COUNT = 20
_PROVENANCE_KEY = secrets.token_bytes(32)
_Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_SafeIdentifier = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
]


class _StrictFrozenModel(FrozenModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class AttestedSourceProfileExpectationV2(_StrictFrozenModel):
    """Credential-free wire form of one tracker expectation."""

    camera_id: _SafeIdentifier
    source_index: Annotated[int, Field(ge=0, lt=_CAMERA_COUNT)]
    source_identity_commitment: _Digest
    codec: Literal["h264", "h265"]
    width: Annotated[int, Field(ge=320, le=16_384)]
    height: Annotated[int, Field(ge=240, le=8_640)]
    fps_min: Annotated[float, Field(ge=1, le=240)]
    fps_max: Annotated[float, Field(ge=1, le=240)]
    bitrate_kbps_min: Annotated[int, Field(ge=1, le=1_000_000)]
    bitrate_kbps_max: Annotated[int, Field(ge=1, le=1_000_000)]
    max_timestamp_gap_ns: Annotated[
        int,
        Field(ge=1, le=120_000_000_000),
    ]
    max_timestamp_skew_ns: Annotated[
        int,
        Field(ge=0, le=60_000_000_000),
    ]
    stale_after_ns: Annotated[
        int,
        Field(ge=1, le=300_000_000_000),
    ]
    signature: _Digest

    @model_validator(mode="after")
    def ranges_are_ordered(self) -> AttestedSourceProfileExpectationV2:
        if self.fps_min > self.fps_max or self.bitrate_kbps_min > self.bitrate_kbps_max:
            raise ValueError("source profile expectation ranges must be ordered")
        return self

    def to_tracker_expectation(self) -> SourceProfileExpectation:
        return SourceProfileExpectation(**self.model_dump(mode="python"))


class TargetSourceProfileAttestationV2(_StrictFrozenModel):
    """Signed public profile binding; it contains commitments, never source secrets."""

    schema_version: Literal["target-source-profile-attestation.v2"]
    site_id: _SafeIdentifier
    campaign_id: _SafeIdentifier
    gate: AcceptanceGate
    manifest_sha256: _Digest
    manifest_signature_sha256: _Digest
    manifest_role_spki_sha256: _Digest
    acceptance_trust_binding_sha256: _Digest
    launch_attestation_sha256: _Digest
    launch_request_sha256: _Digest
    source_profiles_sha256: _Digest
    source_profile_proof_key_id: _SafeIdentifier
    source_profile_proof_public_key_spki_sha256: _Digest
    milestone_authenticator_key_id: _SafeIdentifier
    expectations: Annotated[
        tuple[AttestedSourceProfileExpectationV2, ...],
        Field(min_length=_CAMERA_COUNT, max_length=_CAMERA_COUNT),
    ]
    source_identity_commitments: Annotated[
        tuple[_Digest, ...],
        Field(min_length=_CAMERA_COUNT, max_length=_CAMERA_COUNT),
    ]
    authorizing: Literal[False] = False

    @field_validator("expectations", mode="before")
    @classmethod
    def expectations_are_one_finite_sequence(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            raise TypeError("source profile expectations must be one finite sequence")
        return tuple(AttestedSourceProfileExpectationV2.model_validate(item) for item in value)

    @field_validator("source_identity_commitments", mode="before")
    @classmethod
    def commitments_are_one_finite_sequence(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            raise TypeError("source identity commitments must be one finite sequence")
        return tuple(value)

    @model_validator(mode="after")
    def exact_ordered_twenty_are_bound(self) -> TargetSourceProfileAttestationV2:
        indices = tuple(item.source_index for item in self.expectations)
        camera_ids = tuple(item.camera_id for item in self.expectations)
        commitments = tuple(item.source_identity_commitment for item in self.expectations)
        if (
            indices != tuple(range(_CAMERA_COUNT))
            or len(set(camera_ids)) != _CAMERA_COUNT
            or len(set(commitments)) != _CAMERA_COUNT
            or commitments != self.source_identity_commitments
        ):
            raise ValueError("source profile attestation requires exact ordered 20 unique sources")
        return self

    @property
    def attestation_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


class TransmittedTargetSourceProfileV2(_StrictFrozenModel):
    """Exact signed bytes and manifest key independently verified by the child."""

    schema_version: Literal["transmitted-target-source-profile.v2"]
    attestation: TargetSourceProfileAttestationV2
    signature_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
    manifest_public_key_pem_base64: Annotated[
        str,
        Field(min_length=1, max_length=2048),
    ]
    attestation_payload_sha256: _Digest
    signature_sha256: _Digest
    manifest_role_spki_sha256: _Digest
    verified_binding_sha256: _Digest

    @model_validator(mode="after")
    def exact_signed_graph(self) -> TransmittedTargetSourceProfileV2:
        payload = canonical_json_bytes(self.attestation)
        try:
            signature = bytes.fromhex(self.signature_hex)
            public_key = base64.b64decode(
                self.manifest_public_key_pem_base64,
                validate=True,
            )
        except ValueError:
            raise ValueError("transmitted source profile encoding is invalid") from None
        manifest_spki = ed25519_public_key_spki_sha256(public_key)
        expected_binding = hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema_version": "verified-target-source-profile-binding.v2",
                    "attestation_payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "signature_sha256": hashlib.sha256(signature).hexdigest(),
                    "manifest_role_spki_sha256": manifest_spki,
                    "launch_request_sha256": self.attestation.launch_request_sha256,
                }
            )
        ).hexdigest()
        if (
            len(signature) != 64
            or not 1 <= len(public_key) <= 1024
            or self.attestation_payload_sha256
            != hashlib.sha256(payload).hexdigest()
            or self.signature_sha256 != hashlib.sha256(signature).hexdigest()
            or self.manifest_role_spki_sha256 != manifest_spki
            or self.attestation.manifest_role_spki_sha256 != manifest_spki
            or self.verified_binding_sha256 != expected_binding
        ):
            raise ValueError("transmitted source profile digest graph differs")
        verified_spki = verify_ed25519_payload(
            payload=payload,
            signature=signature,
            trusted_public_key=public_key,
            label="transmitted target source profile",
        )
        if verified_spki != manifest_spki:
            raise ValueError("transmitted source profile used the wrong manifest role")
        return self


class VerifiedTargetSourceProfileAttestationV2:
    """Process-local proof that exact captured bytes passed the manifest-role check."""

    __slots__ = (
        "_attestation",
        "_attestation_payload_sha256",
        "_manifest_public_key",
        "_manifest_role_spki_sha256",
        "_provenance",
        "_signature",
        "_signature_sha256",
        "_verified_binding_sha256",
    )

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del _args, _kwargs
        raise TypeError("verified source profile attestations come only from capture")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("verified source profile attestations are immutable")

    def __copy__(self) -> None:
        raise TypeError("verified source profile attestations cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("verified source profile attestations cannot be copied")

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        raise TypeError("verified source profile attestations cannot be serialized")

    @property
    def attestation(self) -> TargetSourceProfileAttestationV2:
        return TargetSourceProfileAttestationV2.model_validate(
            self._attestation.model_dump(mode="python")
        )

    @property
    def attestation_payload_sha256(self) -> str:
        return self._attestation_payload_sha256

    @property
    def signature_sha256(self) -> str:
        return self._signature_sha256

    @property
    def verified_binding_sha256(self) -> str:
        return self._verified_binding_sha256


def _provenance(
    *,
    attestation: TargetSourceProfileAttestationV2,
    attestation_payload_sha256: str,
    signature_sha256: str,
    manifest_role_spki_sha256: str,
) -> bytes:
    return hmac.digest(
        _PROVENANCE_KEY,
        canonical_json_bytes(
            {
                "attestation": attestation.model_dump(mode="json"),
                "attestation_payload_sha256": attestation_payload_sha256,
                "manifest_role_spki_sha256": manifest_role_spki_sha256,
                "signature_sha256": signature_sha256,
            }
        ),
        "sha256",
    )


def _mint_verified(
    *,
    attestation: TargetSourceProfileAttestationV2,
    attestation_payload_sha256: str,
    signature_sha256: str,
    manifest_role_spki_sha256: str,
    signature: bytes,
    manifest_public_key: bytes,
) -> VerifiedTargetSourceProfileAttestationV2:
    verified = object.__new__(VerifiedTargetSourceProfileAttestationV2)
    object.__setattr__(verified, "_attestation", attestation)
    object.__setattr__(
        verified,
        "_attestation_payload_sha256",
        attestation_payload_sha256,
    )
    object.__setattr__(verified, "_signature_sha256", signature_sha256)
    object.__setattr__(verified, "_signature", bytes(signature))
    object.__setattr__(
        verified,
        "_manifest_public_key",
        bytes(manifest_public_key),
    )
    object.__setattr__(
        verified,
        "_manifest_role_spki_sha256",
        manifest_role_spki_sha256,
    )
    object.__setattr__(
        verified,
        "_provenance",
        _provenance(
            attestation=attestation,
            attestation_payload_sha256=attestation_payload_sha256,
            signature_sha256=signature_sha256,
            manifest_role_spki_sha256=manifest_role_spki_sha256,
        ),
    )
    object.__setattr__(
        verified,
        "_verified_binding_sha256",
        hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema_version": "verified-target-source-profile-binding.v2",
                    "attestation_payload_sha256": attestation_payload_sha256,
                    "signature_sha256": signature_sha256,
                    "manifest_role_spki_sha256": manifest_role_spki_sha256,
                    "launch_request_sha256": attestation.launch_request_sha256,
                }
            )
        ).hexdigest(),
    )
    return verified


def _require_verified_target_source_profile_attestation(
    verified: VerifiedTargetSourceProfileAttestationV2,
) -> TargetSourceProfileAttestationV2:
    if type(verified) is not VerifiedTargetSourceProfileAttestationV2:
        raise ValueError("source profile attestation provenance is invalid")
    try:
        expected = _provenance(
            attestation=verified._attestation,
            attestation_payload_sha256=(verified._attestation_payload_sha256),
            signature_sha256=verified._signature_sha256,
            manifest_role_spki_sha256=(verified._manifest_role_spki_sha256),
        )
        actual = verified._provenance
        actual_binding = verified._verified_binding_sha256
        expected_binding = hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema_version": (
                        "verified-target-source-profile-binding.v2"
                    ),
                    "attestation_payload_sha256": (
                        verified._attestation_payload_sha256
                    ),
                    "signature_sha256": verified._signature_sha256,
                    "manifest_role_spki_sha256": (
                        verified._manifest_role_spki_sha256
                    ),
                    "launch_request_sha256": (
                        verified._attestation.launch_request_sha256
                    ),
                }
            )
        ).hexdigest()
    except (AttributeError, TypeError, ValueError):
        raise ValueError("source profile attestation provenance is invalid") from None
    if (
        type(actual) is not bytes
        or len(actual) != hashlib.sha256().digest_size
        or not hmac.compare_digest(actual, expected)
        or type(actual_binding) is not str
        or not hmac.compare_digest(
            actual_binding,
            expected_binding,
        )
        or type(verified._signature) is not bytes
        or len(verified._signature) != 64
        or type(verified._manifest_public_key) is not bytes
        or ed25519_public_key_spki_sha256(verified._manifest_public_key)
        != verified._manifest_role_spki_sha256
        or hashlib.sha256(verified._signature).hexdigest()
        != verified._signature_sha256
    ):
        raise ValueError("source profile attestation provenance is invalid")
    return TargetSourceProfileAttestationV2.model_validate(
        verified._attestation.model_dump(mode="python")
    )


def export_verified_target_source_profile(
    verified: VerifiedTargetSourceProfileAttestationV2,
) -> TransmittedTargetSourceProfileV2:
    """Export only the signed public profile material, never a local capability."""

    attestation = _require_verified_target_source_profile_attestation(verified)
    return TransmittedTargetSourceProfileV2(
        schema_version="transmitted-target-source-profile.v2",
        attestation=attestation,
        signature_hex=verified._signature.hex(),
        manifest_public_key_pem_base64=base64.b64encode(
            verified._manifest_public_key
        ).decode("ascii"),
        attestation_payload_sha256=verified.attestation_payload_sha256,
        signature_sha256=verified.signature_sha256,
        manifest_role_spki_sha256=verified._manifest_role_spki_sha256,
        verified_binding_sha256=verified.verified_binding_sha256,
    )


def verify_transmitted_target_source_profile(
    transmitted: TransmittedTargetSourceProfileV2,
    *,
    launch_request: TargetRuntimeLaunchRequestV2,
) -> VerifiedTargetSourceProfileAttestationV2:
    """Independently verify the signed wire profile inside the child process."""

    if type(transmitted) is not TransmittedTargetSourceProfileV2:
        raise TypeError("exact transmitted source profile is required")
    if type(launch_request) is not TargetRuntimeLaunchRequestV2:
        raise TypeError("exact target launch request is required")
    checked = TransmittedTargetSourceProfileV2.model_validate(
        transmitted.model_dump(mode="python")
    )
    request = TargetRuntimeLaunchRequestV2.model_validate(
        launch_request.model_dump(mode="python")
    )
    attestation = checked.attestation
    if (
        attestation.launch_request_sha256 != request.request_sha256
        or attestation.site_id != request.launch.site_id
        or attestation.campaign_id != request.campaign_id
        or attestation.gate != request.gate
        or attestation.source_identity_commitments
        != tuple(
            binding.source_identity_commitment
            for binding in request.source_bindings
        )
    ):
        raise ValueError("transmitted source profile differs from the exact launch")
    signature = bytes.fromhex(checked.signature_hex)
    public_key = base64.b64decode(
        checked.manifest_public_key_pem_base64,
        validate=True,
    )
    return _mint_verified(
        attestation=attestation,
        attestation_payload_sha256=checked.attestation_payload_sha256,
        signature_sha256=checked.signature_sha256,
        manifest_role_spki_sha256=checked.manifest_role_spki_sha256,
        signature=signature,
        manifest_public_key=public_key,
    )


def _validate_manifest_profile_bindings(
    *,
    context: AcceptanceAuthorityTrustContextV2,
    request: TargetRuntimeLaunchRequestV2,
    attestation: TargetSourceProfileAttestationV2,
) -> None:
    binding_sha256 = hashlib.sha256(
        canonical_json_bytes(build_acceptance_trust_binding(context.trust))
    ).hexdigest()
    if (
        request.launch != context.launch
        or request.manifest_sha256 != context.binding.manifest_payload_sha256
        or request.campaign_id != context.configured_campaign_id
        or request.gate != context.configured_gate
        or request.acceptance_trust_binding_sha256 != binding_sha256
        or attestation.site_id != context.configured_site_id
        or attestation.campaign_id != context.configured_campaign_id
        or attestation.gate != context.configured_gate
        or attestation.manifest_sha256 != context.binding.manifest_payload_sha256
        or attestation.manifest_signature_sha256 != context.trust.manifest_signature_sha256
        or attestation.manifest_role_spki_sha256 != context.trust.policy.roles.manifest_spki_sha256
        or attestation.acceptance_trust_binding_sha256 != binding_sha256
        or attestation.launch_attestation_sha256 != context.launch.attestation_sha256
        or attestation.launch_request_sha256 != request.request_sha256
        or attestation.source_profiles_sha256 != context.launch.source_profiles_sha256
    ):
        raise ValueError(
            "source profile attestation differs from manifest, launch, or request binding"
        )

    expected_bindings = tuple(
        (
            item.camera_id,
            item.source_index,
            item.source_identity_commitment,
        )
        for item in attestation.expectations
    )
    request_bindings = tuple(
        (
            item.camera_id,
            item.source_index,
            item.source_identity_commitment,
        )
        for item in request.source_bindings
    )
    if expected_bindings != request_bindings:
        raise ValueError("source profile commitments differ from the exact launch request")

    for workload, expectation in zip(
        context.workloads,
        attestation.expectations,
        strict=True,
    ):
        if (
            workload.camera_id != expectation.camera_id
            or workload.source_index != expectation.source_index
            or workload.codec != expectation.codec
            or workload.width != expectation.width
            or workload.height != expectation.height
            or not expectation.fps_min <= workload.fps <= expectation.fps_max
            or not expectation.bitrate_kbps_min
            <= workload.bitrate_kbps
            <= expectation.bitrate_kbps_max
        ):
            raise ValueError("source profile expectation differs from the signed manifest workload")


def capture_verified_target_source_profile_attestation(
    *,
    context: AcceptanceAuthorityTrustContextV2,
    launch_request: TargetRuntimeLaunchRequestV2,
    attestation_path,
    signature_path,
) -> VerifiedTargetSourceProfileAttestationV2:
    """Capture once and verify one source-profile attestation with the manifest role."""

    checked_context = _require_authority_trust_context(context)
    if type(launch_request) is not TargetRuntimeLaunchRequestV2:
        raise TypeError("source profile verification requires the exact launch request")
    request = TargetRuntimeLaunchRequestV2.model_validate(launch_request)
    captured_attestation = capture_regular_bounded(
        attestation_path,
        max_bytes=MAX_TARGET_SOURCE_PROFILE_ATTESTATION_BYTES,
        label="target source profile attestation",
    )
    captured_signature = capture_regular_bounded(
        signature_path,
        max_bytes=MAX_TARGET_SOURCE_PROFILE_SIGNATURE_BYTES,
        label="target source profile attestation signature",
    )
    attestation = load_canonical_json_bytes(
        captured_attestation.payload,
        TargetSourceProfileAttestationV2,
        max_bytes=MAX_TARGET_SOURCE_PROFILE_ATTESTATION_BYTES,
        label="target source profile attestation",
    )
    manifest_public_key = checked_context.trust.role_public_keys.manifest
    manifest_spki = ed25519_public_key_spki_sha256(manifest_public_key)
    if manifest_spki != checked_context.trust.policy.roles.manifest_spki_sha256:
        raise ValueError("manifest role key differs from the verified trust policy")
    verified_spki = verify_ed25519_payload(
        payload=captured_attestation.payload,
        signature=captured_signature.payload,
        trusted_public_key=manifest_public_key,
        label="target source profile attestation",
    )
    if verified_spki != manifest_spki:
        raise ValueError("source profile attestation signature used the wrong role")
    _validate_manifest_profile_bindings(
        context=checked_context,
        request=request,
        attestation=attestation,
    )
    return _mint_verified(
        attestation=attestation,
        attestation_payload_sha256=hashlib.sha256(captured_attestation.payload).hexdigest(),
        signature_sha256=hashlib.sha256(captured_signature.payload).hexdigest(),
        manifest_role_spki_sha256=manifest_spki,
        signature=captured_signature.payload,
        manifest_public_key=manifest_public_key,
    )


__all__ = (
    "AttestedSourceProfileExpectationV2",
    "MAX_TARGET_SOURCE_PROFILE_ATTESTATION_BYTES",
    "MAX_TARGET_SOURCE_PROFILE_SIGNATURE_BYTES",
    "TargetSourceProfileAttestationV2",
    "TransmittedTargetSourceProfileV2",
    "VerifiedTargetSourceProfileAttestationV2",
    "capture_verified_target_source_profile_attestation",
    "export_verified_target_source_profile",
    "verify_transmitted_target_source_profile",
)
