"""Child-owned exact-20 source authority for native target prewarm."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path

from protector.pilot.acceptance_source_profile import (
    VerifiedTargetSourceProfileAttestationV2,
    _require_verified_target_source_profile_attestation,
)
from protector.pilot.acceptance_target import (
    TargetNativePrewarmProjectionV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
)
from protector.pilot.runtime.native_acceptance import NativePrewarmProjectorV2
from protector.pilot.runtime.source_probe import (
    NativeSourceProbeBridge,
    SourceProbeLease,
    verify_and_issue_exact_20_prewarm_receipt,
)
from protector.pilot.runtime.source_profile import (
    NativeSourceProfileTracker,
    SourceProfileProofSigner,
)
from protector.pilot.trusted_artifacts import ed25519_public_key_spki_sha256

_CAMERA_COUNT = 20
_KEY_BYTES = 32
_MAX_SOURCE_BYTES = 16_384
_MAX_BOOTSTRAP_EPOCH = 1024


def _owned_key(value: object, *, label: str) -> bytes:
    if type(value) is bytes:
        owned = value
    elif type(value) is bytearray:
        owned = bytes(value)
    else:
        owned = b""
    if len(owned) != _KEY_BYTES:
        owned = b""
        raise ValueError(f"{label} must be exactly 32-byte")
    return owned


def _validated_sources(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) != _CAMERA_COUNT:
        raise ValueError("native source secrets require one exact 20-item tuple")
    owned: list[str] = []
    for source in value:
        if (
            type(source) is not str
            or not source
            or "\x00" in source
            or len(source.encode("utf-8")) > _MAX_SOURCE_BYTES
        ):
            raise ValueError("resolved native source identity is invalid")
        owned.append(source)
    return tuple(owned)


class NativeSourceSecretsV2:
    """Single-transfer child secret bundle; repr and durable output stay redacted."""

    __slots__ = (
        "_claimed",
        "_commitment_key",
        "_milestone_authenticator_key",
        "_proof_signer",
        "_resolved_sources",
    )

    def __init__(
        self,
        *,
        resolved_sources: tuple[str, ...],
        commitment_key: bytes | bytearray,
        milestone_authenticator_key: bytes | bytearray,
        proof_signer: SourceProfileProofSigner,
    ) -> None:
        owned_sources = _validated_sources(resolved_sources)
        owned_commitment_key = _owned_key(
            commitment_key,
            label="source commitment key",
        )
        owned_milestone_key = _owned_key(
            milestone_authenticator_key,
            label="source milestone authenticator key",
        )
        if (
            not isinstance(proof_signer.key_id, str)
            or not proof_signer.key_id
            or type(proof_signer.public_key) is not bytes
            or not callable(proof_signer.sign)
        ):
            raise ValueError("source profile proof signer is invalid")
        self._resolved_sources = owned_sources
        self._commitment_key = owned_commitment_key
        self._milestone_authenticator_key = owned_milestone_key
        self._proof_signer = proof_signer
        self._claimed = False

    def __repr__(self) -> str:
        return "NativeSourceSecretsV2(<redacted>)"

    def __copy__(self) -> None:
        raise TypeError("native source secrets cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("native source secrets cannot be copied")

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        raise TypeError("native source secrets cannot be serialized")

    def _claim(
        self,
    ) -> tuple[
        tuple[str, ...],
        bytes,
        bytes,
        SourceProfileProofSigner,
    ]:
        if self._claimed:
            raise RuntimeError("native source secrets were already transferred")
        self._claimed = True
        result = (
            self._resolved_sources,
            self._commitment_key,
            self._milestone_authenticator_key,
            self._proof_signer,
        )
        self._resolved_sources = ()
        self._commitment_key = b""
        self._milestone_authenticator_key = b""
        self._proof_signer = _ClosedProofSigner()
        return result

    def close(self) -> None:
        self._claimed = True
        self._resolved_sources = ()
        self._commitment_key = b""
        self._milestone_authenticator_key = b""
        self._proof_signer = _ClosedProofSigner()


class _ClosedProofSigner:
    @property
    def key_id(self) -> str:
        return "closed"

    @property
    def public_key(self) -> bytes:
        return b""

    def sign(self, payload: bytes) -> bytes:
        del payload
        raise RuntimeError("source proof signer is closed")


def _exact_request(
    value: TargetRuntimeLaunchRequestV2,
) -> TargetRuntimeLaunchRequestV2:
    if type(value) is not TargetRuntimeLaunchRequestV2:
        raise TypeError("native source authority requires the exact launch request")
    return TargetRuntimeLaunchRequestV2.model_validate(value)


def _exact_identity(
    value: TargetRuntimeIdentityV2,
    *,
    request: TargetRuntimeLaunchRequestV2,
) -> TargetRuntimeIdentityV2:
    if type(value) is not TargetRuntimeIdentityV2:
        raise TypeError("native source authority requires the exact runtime identity")
    identity = TargetRuntimeIdentityV2.model_validate(value)
    if identity.launch_request != request:
        raise ValueError("native source runtime identity differs from the launch request")
    return identity


def _raise_cleanup_failures(failures: list[BaseException]) -> None:
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup(
            "native source authority cleanup failed",
            failures,
        )


class NativeExact20SourceAuthorityV2:
    """Own one tracker and the current exact lease for each signed source."""

    __slots__ = (
        "_attestation",
        "_bridge_capacity",
        "_bridges",
        "_closed",
        "_commitment_key",
        "_identity",
        "_leases",
        "_lock",
        "_milestone_key",
        "_monotonic_ns",
        "_projected",
        "_projection_path",
        "_proof_signer",
        "_request",
        "_resolved_sources",
        "_tracker",
    )

    def __init__(
        self,
        *,
        verified_attestation: VerifiedTargetSourceProfileAttestationV2,
        launch_request: TargetRuntimeLaunchRequestV2,
        runtime_identity: TargetRuntimeIdentityV2,
        secrets: NativeSourceSecretsV2,
        projection_path: Path,
        bridge_capacity: int = 64,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        attestation = _require_verified_target_source_profile_attestation(verified_attestation)
        request = _exact_request(launch_request)
        identity = _exact_identity(runtime_identity, request=request)
        if (
            not isinstance(projection_path, Path)
            or type(bridge_capacity) is not int
            or not 1 <= bridge_capacity <= 1_000_000
            or not callable(monotonic_ns)
        ):
            raise ValueError("native source authority configuration is invalid")
        if (
            attestation.launch_request_sha256 != request.request_sha256
            or attestation.site_id != request.launch.site_id
            or attestation.campaign_id != request.campaign_id
            or attestation.gate != request.gate
            or attestation.source_identity_commitments
            != tuple(binding.source_identity_commitment for binding in request.source_bindings)
            or identity.source_bindings != request.source_bindings
        ):
            raise ValueError("native source attestation differs from launch identity")
        if (
            request.runtime_epoch != request.runtime_epoch_started_generation
            or not 1 <= request.runtime_epoch <= _MAX_BOOTSTRAP_EPOCH
            or identity.runtime_epoch_started_monotonic_ns < request.runtime_epoch - 1
        ):
            raise ValueError("native source runtime epoch/start generation cannot be bootstrapped")
        if type(secrets) is not NativeSourceSecretsV2:
            raise TypeError("native source authority requires child-owned secrets")

        (
            resolved_sources,
            commitment_key,
            milestone_key,
            proof_signer,
        ) = secrets._claim()  # noqa: SLF001
        try:
            if (
                proof_signer.key_id != attestation.source_profile_proof_key_id
                or ed25519_public_key_spki_sha256(proof_signer.public_key)
                != attestation.source_profile_proof_public_key_spki_sha256
            ):
                raise ValueError("source proof signer differs from the signed source attestation")
            epoch = request.runtime_epoch
            final_epoch_started = identity.runtime_epoch_started_monotonic_ns
            initial_epoch_started = final_epoch_started - (epoch - 1)
            tracker = NativeSourceProfileTracker(
                site_id=attestation.site_id,
                expectations=tuple(
                    item.to_tracker_expectation() for item in attestation.expectations
                ),
                commitment_key=commitment_key,
                milestone_authenticator_key_id=(attestation.milestone_authenticator_key_id),
                milestone_authenticator_key=milestone_key,
                epoch_started_monotonic_ns=initial_epoch_started,
                proof_signer=proof_signer,
            )
            for offset in range(1, epoch):
                tracker.restart_epoch(started_monotonic_ns=initial_epoch_started + offset)
            snapshot = tracker.snapshot()
            if (
                snapshot.epoch != request.runtime_epoch
                or snapshot.epoch_started_generation != request.runtime_epoch_started_generation
                or snapshot.epoch_started_monotonic_ns
                != identity.runtime_epoch_started_monotonic_ns
            ):
                raise RuntimeError("native source tracker epoch differs from the runtime launch")
        except BaseException:
            resolved_sources = ()
            commitment_key = b""
            milestone_key = b""
            raise

        self._attestation = attestation
        self._request = request
        self._identity = identity
        self._resolved_sources = resolved_sources
        self._commitment_key = commitment_key
        self._milestone_key = milestone_key
        self._proof_signer = proof_signer
        self._projection_path = projection_path
        self._monotonic_ns = monotonic_ns
        self._tracker = tracker
        self._bridges: dict[int, NativeSourceProbeBridge] = {}
        self._leases: dict[int, SourceProbeLease] = {}
        self._lock = threading.RLock()
        self._projected = False
        self._closed = False
        self._bridge_capacity = bridge_capacity

    def __repr__(self) -> str:
        return (
            "NativeExact20SourceAuthorityV2("
            f"site_id={self._request.launch.site_id!r}, "
            f"runtime_epoch={self._request.runtime_epoch})"
        )

    def __copy__(self) -> None:
        raise TypeError("native source authority cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("native source authority cannot be copied")

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        raise TypeError("native source authority cannot be serialized")

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("native source authority is closed")

    def acquire(self, camera_id: str, source_id: int) -> SourceProbeLease:
        """Bind the actual resolved source and issue one bridge-owned lease."""

        with self._lock:
            self._require_open()
            if self._projected:
                raise RuntimeError(
                    "native source authority cannot replace leases after prewarm projection"
                )
            if type(source_id) is not int or not 0 <= source_id < _CAMERA_COUNT:
                raise ValueError("native source index is outside exact 20")
            binding = self._request.source_bindings[source_id]
            if camera_id != binding.camera_id or source_id != binding.source_index:
                raise ValueError("native source acquisition differs from signed source order")
            bound_monotonic_ns = self._monotonic_ns()
            if type(bound_monotonic_ns) is not int:
                raise ValueError("native source monotonic clock is invalid")
            callbacks = self._tracker.bind_source(
                camera_id=camera_id,
                resolved_url=self._resolved_sources[source_id],
                commitment_key=self._commitment_key,
                bound_monotonic_ns=bound_monotonic_ns,
            )
            source = self._tracker.snapshot().sources[source_id]
            if (
                source.camera_id != camera_id
                or source.source_index != source_id
                or not source.identity_verified
                or source.failures
            ):
                callbacks.close()
                raise ValueError("resolved source identity differs from signed profile commitment")
            bridge = NativeSourceProbeBridge(capacity=self._bridge_capacity)
            try:
                lease = bridge.bind(callbacks)
            except BaseException:
                callbacks.close()
                raise
            self._bridges[source_id] = bridge
            self._leases[source_id] = lease
            return lease

    def publish_native_prewarm(self) -> TargetNativePrewarmProjectionV2:
        """Issue and consume the live receipt in this child; return projection only."""

        with self._lock:
            self._require_open()
            if self._projected:
                raise RuntimeError("native source prewarm projection was already attempted")
            if tuple(self._leases) != tuple(range(_CAMERA_COUNT)):
                raise ValueError("native source prewarm requires current exact ordered 20 leases")
            leases = tuple(self._leases[index] for index in range(_CAMERA_COUNT))
            proof = self._tracker.authoritative_proof()
            receipt = verify_and_issue_exact_20_prewarm_receipt(
                proof,
                native_leases=leases,
                expected_key_id=(self._attestation.source_profile_proof_key_id),
                trusted_public_key=self._proof_signer.public_key,
                expected_milestone_authenticator_key_id=(
                    self._attestation.milestone_authenticator_key_id
                ),
                trusted_milestone_authenticator_key=self._milestone_key,
                expected_site_id=self._attestation.site_id,
                expected_source_identity_commitments=(
                    self._attestation.source_identity_commitments
                ),
                expected_epoch=self._request.runtime_epoch,
                expected_epoch_started_generation=(self._request.runtime_epoch_started_generation),
            )
            projector = NativePrewarmProjectorV2(self._projection_path)
            projection = projector.project(
                receipt=receipt,
                launch_request=self._request,
                runtime_identity=self._identity,
            )
            self._projected = True
            return projection

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            leases = tuple(reversed(tuple(self._leases.values())))
            self._leases.clear()
            self._bridges.clear()
            self._resolved_sources = ()
            self._commitment_key = b""
            self._milestone_key = b""
        failures: list[BaseException] = []
        for lease in leases:
            try:
                lease.close()
            except BaseException as failure:
                failures.append(failure)
        _raise_cleanup_failures(failures)


__all__ = (
    "NativeExact20SourceAuthorityV2",
    "NativeSourceSecretsV2",
)
