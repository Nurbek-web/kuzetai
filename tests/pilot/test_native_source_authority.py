from __future__ import annotations

import copy
import pickle
from pathlib import Path

import pytest

from protector.pilot.acceptance_target import TargetNativePrewarmProjectionV2
from protector.pilot.runtime.native_acceptance import (
    load_native_prewarm_projection,
)
from protector.pilot.runtime.native_source_authority import (
    NativeExact20SourceAuthorityV2,
    NativeSourceSecretsV2,
)
from protector.pilot.runtime.source_probe import SourceProbeLease
from tests.pilot.test_acceptance_source_profile import (
    COMMITMENT_KEY,
    MILESTONE_KEY,
    _resolved_sources,
    _verified_fixture,
)

SOURCE_TIMESTAMP_BASE_NS = 900_000_000_000
SOURCE_NTP_BASE_NS = 1_800_000_000_000_000_000


def _drive_real_native_prewarm(
    leases: tuple[SourceProbeLease, ...],
    *,
    epoch_started_monotonic_ns: int,
) -> None:
    for lease in leases:
        assert lease.observe_rtp_caps("h264", epoch_started_monotonic_ns)
        assert lease.observe_decoder_caps(
            1920,
            1080,
            25,
            1,
            epoch_started_monotonic_ns,
        )
    for sample in range(752):
        elapsed_ns = sample * 80_000_000
        observed_ns = epoch_started_monotonic_ns + elapsed_ns
        for lease in leases:
            pts_ns = sample + 1
            assert lease.observe_parser_buffer(
                40_960,
                SOURCE_TIMESTAMP_BASE_NS + elapsed_ns,
                pts_ns,
                observed_ns,
            )
            assert lease.observe_decoded_buffer(pts_ns, observed_ns)
            assert lease.observe_nvds_ntp(
                pts_ns,
                SOURCE_NTP_BASE_NS + elapsed_ns,
                observed_ns,
            )


def _authority(tmp_path: Path, *, runtime_epoch: int = 1):
    (
        _context,
        request,
        identity,
        _expectations,
        proof_signer,
        verified,
        _profile_path,
        _signature_path,
        _bundle,
    ) = _verified_fixture(tmp_path, runtime_epoch=runtime_epoch)
    secrets = NativeSourceSecretsV2(
        resolved_sources=_resolved_sources(),
        commitment_key=COMMITMENT_KEY,
        milestone_authenticator_key=MILESTONE_KEY,
        proof_signer=proof_signer,
    )
    output = tmp_path / f"native-source-prewarm-{runtime_epoch}.json"
    authority = NativeExact20SourceAuthorityV2(
        verified_attestation=verified,
        launch_request=request,
        runtime_identity=identity,
        secrets=secrets,
        projection_path=output,
        bridge_capacity=8,
        monotonic_ns=lambda: identity.runtime_epoch_started_monotonic_ns,
    )
    return authority, request, identity, output, secrets


def test_child_owns_real_exact20_tracker_bridges_receipt_and_projection(
    tmp_path: Path,
) -> None:
    authority, request, identity, output, secrets = _authority(tmp_path)
    leases = tuple(
        authority.acquire(binding.camera_id, binding.source_index)
        for binding in request.source_bindings
    )
    assert all(type(lease) is SourceProbeLease for lease in leases)
    assert len({id(lease) for lease in leases}) == 20
    assert len({id(lease._bridge) for lease in leases}) == 20  # noqa: SLF001

    _drive_real_native_prewarm(
        leases,
        epoch_started_monotonic_ns=(identity.runtime_epoch_started_monotonic_ns),
    )
    projection = authority.publish_native_prewarm()

    assert type(projection) is TargetNativePrewarmProjectionV2
    assert projection.authorizing is False
    assert projection.runtime_epoch == request.runtime_epoch
    assert projection.runtime_epoch_started_generation == (request.runtime_epoch_started_generation)
    assert projection.prewarm_duration_seconds == 60.08
    assert (
        load_native_prewarm_projection(
            output,
            launch_request=request,
            runtime_identity=identity,
        )
        == projection
    )
    payload = output.read_bytes()
    assert b"rtsp://" not in payload
    assert b"camera-secret" not in payload
    assert COMMITMENT_KEY not in payload
    assert MILESTONE_KEY not in payload
    assert "receipt" not in projection.model_dump(mode="json")
    with pytest.raises(RuntimeError, match="already|one"):
        authority.publish_native_prewarm()
    authority.close()
    secrets.close()


def test_actual_resolved_source_identity_must_match_signed_attestation(
    tmp_path: Path,
) -> None:
    (
        _context,
        request,
        identity,
        _expectations,
        proof_signer,
        verified,
        _profile_path,
        _signature_path,
        _bundle,
    ) = _verified_fixture(tmp_path)
    sources = list(_resolved_sources())
    sources[0] = "rtsp://operator:wrong-secret@10.20.0.10/live"
    secrets = NativeSourceSecretsV2(
        resolved_sources=tuple(sources),
        commitment_key=COMMITMENT_KEY,
        milestone_authenticator_key=MILESTONE_KEY,
        proof_signer=proof_signer,
    )
    authority = NativeExact20SourceAuthorityV2(
        verified_attestation=verified,
        launch_request=request,
        runtime_identity=identity,
        secrets=secrets,
        projection_path=tmp_path / "must-not-exist.json",
        monotonic_ns=lambda: identity.runtime_epoch_started_monotonic_ns,
    )

    with pytest.raises(ValueError, match="identity|commitment|profile"):
        authority.acquire(
            request.source_bindings[0].camera_id,
            request.source_bindings[0].source_index,
        )
    assert not (tmp_path / "must-not-exist.json").exists()
    with pytest.raises(ValueError, match="exact|20|source"):
        authority.publish_native_prewarm()
    authority.close()
    secrets.close()


def test_restart_is_a_new_epoch_with_fresh_leases_and_prewarm(
    tmp_path: Path,
) -> None:
    authority, request, identity, output, secrets = _authority(
        tmp_path,
        runtime_epoch=2,
    )
    leases = tuple(
        authority.acquire(binding.camera_id, binding.source_index)
        for binding in request.source_bindings
    )
    _drive_real_native_prewarm(
        leases,
        epoch_started_monotonic_ns=(identity.runtime_epoch_started_monotonic_ns),
    )
    projection = authority.publish_native_prewarm()

    assert projection.runtime_epoch == 2
    assert projection.runtime_epoch_started_generation == 2
    assert projection.ready_at_monotonic_ns == (
        identity.runtime_epoch_started_monotonic_ns + 60_080_000_000
    )
    assert output.exists()
    authority.close()
    secrets.close()


def test_child_secret_and_authority_capabilities_are_not_copyable_or_serializable(
    tmp_path: Path,
) -> None:
    authority, _request, _identity, _output, secrets = _authority(tmp_path)
    for capability in (authority, secrets):
        with pytest.raises(TypeError):
            copy.copy(capability)
        with pytest.raises(TypeError):
            copy.deepcopy(capability)
        with pytest.raises(TypeError):
            pickle.dumps(capability)
    assert "camera-secret" not in repr(secrets)
    assert COMMITMENT_KEY.hex() not in repr(secrets)
    authority.close()
    secrets.close()
