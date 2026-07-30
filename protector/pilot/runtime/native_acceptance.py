"""Single-use native prewarm projection for the non-authorizing target seam."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from protector.pilot.acceptance_target import (
    TargetNativePrewarmProjectionV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
)
from protector.pilot.acceptance_trust import load_canonical_json_bytes
from protector.pilot.runtime.source_probe import (
    Exact20NativePrewarmReceiptV1,
    VerifiedExact20NativePrewarmV1,
    verify_and_consume_exact_20_prewarm_receipt,
)

MAX_NATIVE_PREWARM_PROJECTION_BYTES = 64 * 1024
_PROJECTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_consume_native_prewarm_receipt = verify_and_consume_exact_20_prewarm_receipt
_close_descriptor = os.close


def _raise_collected_failures(
    label: str,
    failures: list[BaseException],
) -> None:
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup(label, failures)


def _append_close_failures(
    descriptors: tuple[int | None, ...],
    failures: list[BaseException],
) -> None:
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            _close_descriptor(descriptor)
        except BaseException as close_failure:
            failures.append(close_failure)


def _checked_request(
    value: TargetRuntimeLaunchRequestV2,
) -> TargetRuntimeLaunchRequestV2:
    if type(value) is not TargetRuntimeLaunchRequestV2:
        raise TypeError("native projection requires a typed launch request")
    return TargetRuntimeLaunchRequestV2.model_validate(value)


def _checked_identity(
    value: TargetRuntimeIdentityV2,
    *,
    request: TargetRuntimeLaunchRequestV2,
) -> TargetRuntimeIdentityV2:
    if type(value) is not TargetRuntimeIdentityV2:
        raise TypeError("native projection requires a typed runtime identity")
    checked = TargetRuntimeIdentityV2.model_validate(value)
    if checked.launch_request != request:
        raise ValueError("runtime identity differs from native projection launch")
    return checked


def _open_parent(path: Path) -> tuple[int, str]:
    if (
        not path.is_absolute()
        or _PROJECTION_NAME.fullmatch(path.name) is None
        or path.parent.resolve(strict=True) != path.parent
    ):
        raise ValueError("native projection path is not canonical")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.parent, flags)
    try:
        metadata = os.fstat(descriptor)
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        _append_close_failures((descriptor,), failures)
        _raise_collected_failures("native projection parent inspection failed", failures)
        raise AssertionError("unreachable native projection parent inspection")
    if not stat.S_ISDIR(metadata.st_mode):
        failures: list[BaseException] = [ValueError("native projection parent is not a directory")]
        _append_close_failures((descriptor,), failures)
        _raise_collected_failures("native projection parent cleanup failed", failures)
        raise AssertionError("unreachable native projection parent validation")
    return descriptor, path.name


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("native projection write made no progress")
        offset += written


def _cleanup_created_leaf(
    *,
    parent_descriptor: int,
    name: str,
    created_metadata: os.stat_result,
) -> None:
    try:
        current = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if current.st_dev != created_metadata.st_dev or current.st_ino != created_metadata.st_ino:
        raise RuntimeError("native projection cleanup identity changed")
    os.unlink(name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


class NativePrewarmProjectorV2:
    """Consume one live receipt and durably publish one non-authorizing projection."""

    __slots__ = ("_output_path", "_used")

    def __init__(self, output_path: Path) -> None:
        if not isinstance(output_path, Path):
            raise TypeError("native projection output must be a Path")
        self._output_path = output_path
        self._used = False

    def __copy__(self) -> None:
        raise TypeError("native projector capability cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("native projector capability cannot be copied")

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        raise TypeError("native projector capability cannot be serialized or pickled")

    def project(
        self,
        *,
        receipt: Exact20NativePrewarmReceiptV1,
        launch_request: TargetRuntimeLaunchRequestV2,
        runtime_identity: TargetRuntimeIdentityV2,
    ) -> TargetNativePrewarmProjectionV2:
        if self._used:
            raise RuntimeError("native projector capability was already used")
        self._used = True

        request = _checked_request(launch_request)
        identity = _checked_identity(runtime_identity, request=request)
        if type(receipt) is not Exact20NativePrewarmReceiptV1:
            raise TypeError("native projection requires the exact live receipt")
        try:
            receipt_site_id = receipt.site_id
            receipt_epoch = receipt.epoch
            receipt_epoch_started_generation = receipt.epoch_started_generation
            receipt_ready_at = receipt.ready_at_monotonic_ns
            receipt_identity_digest = receipt.source_identity_commitments_sha256
            receipt_native_claims_digest = receipt.native_claims_sha256
            receipt_proof_digest = receipt.proof_sha256
        except (AttributeError, TypeError):
            raise ValueError("native prewarm receipt fields are invalid") from None
        if (
            type(receipt_site_id) is not str
            or type(receipt_epoch) is not int
            or type(receipt_epoch_started_generation) is not int
            or type(receipt_ready_at) is not int
            or receipt_site_id != request.launch.site_id
            or receipt_epoch != request.runtime_epoch
            or receipt_epoch_started_generation != request.runtime_epoch_started_generation
            or receipt_ready_at - identity.runtime_epoch_started_monotonic_ns < 60_000_000_000
            or receipt_ready_at < identity.identity_observed_monotonic_ns
        ):
            raise ValueError("native prewarm receipt site, epoch, or 60-second window differs")

        parent_descriptor, name = _open_parent(self._output_path)
        output_descriptor: int | None = None
        created_metadata: os.stat_result | None = None
        projection: TargetNativePrewarmProjectionV2 | None = None
        failures: list[BaseException] = []
        try:
            output_descriptor = os.open(
                name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            created_metadata = os.fstat(output_descriptor)
            if (
                not stat.S_ISREG(created_metadata.st_mode)
                or created_metadata.st_nlink != 1
                or stat.S_IMODE(created_metadata.st_mode) != 0o600
            ):
                raise ValueError("native projection output is not one private regular file")

            verified = _consume_native_prewarm_receipt(
                receipt,
                expected_site_id=request.launch.site_id,
                expected_epoch=request.runtime_epoch,
                expected_epoch_started_generation=(request.runtime_epoch_started_generation),
                expected_source_identity_commitments=tuple(
                    binding.source_identity_commitment for binding in request.source_bindings
                ),
                expected_proof_sha256=receipt_proof_digest,
            )
            if type(verified) is not VerifiedExact20NativePrewarmV1:
                raise TypeError("native receipt consumer returned an invalid capability")
            projection = TargetNativePrewarmProjectionV2(
                schema_version="target-native-prewarm-projection.v2",
                launch_request_sha256=request.request_sha256,
                runtime_identity_sha256=identity.identity_sha256,
                site_id=request.launch.site_id,
                campaign_id=request.campaign_id,
                launch_nonce=request.launch_nonce,
                runtime_epoch=request.runtime_epoch,
                runtime_epoch_started_generation=(request.runtime_epoch_started_generation),
                runtime_epoch_started_monotonic_ns=(identity.runtime_epoch_started_monotonic_ns),
                ready_at_monotonic_ns=receipt_ready_at,
                source_bindings=request.source_bindings,
                source_identity_commitments_sha256=receipt_identity_digest,
                native_claims_sha256=receipt_native_claims_digest,
                source_profile_proof_sha256=receipt_proof_digest,
            )
            payload = projection.canonical_bytes
            if not 1 <= len(payload) <= MAX_NATIVE_PREWARM_PROJECTION_BYTES:
                raise ValueError("native projection exceeds its byte bound")
            _write_all(output_descriptor, payload)
            os.fsync(output_descriptor)
            final_metadata = os.fstat(output_descriptor)
            leaf_metadata = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                final_metadata.st_dev != created_metadata.st_dev
                or final_metadata.st_ino != created_metadata.st_ino
                or leaf_metadata.st_dev != created_metadata.st_dev
                or leaf_metadata.st_ino != created_metadata.st_ino
                or final_metadata.st_size != len(payload)
            ):
                raise RuntimeError("native projection identity changed during publication")
            os.fsync(parent_descriptor)
        except BaseException as primary:
            failures.append(primary)
            if created_metadata is not None:
                try:
                    _cleanup_created_leaf(
                        parent_descriptor=parent_descriptor,
                        name=name,
                        created_metadata=created_metadata,
                    )
                except BaseException as cleanup_failure:
                    failures.append(cleanup_failure)
        finally:
            _append_close_failures(
                (output_descriptor, parent_descriptor),
                failures,
            )
        _raise_collected_failures(
            "native projection publication or cleanup failed",
            failures,
        )
        if projection is None:
            raise AssertionError("native projection publication returned no projection")
        return projection


def _read_projection_once(path: Path) -> bytes:
    parent_descriptor, name = _open_parent(path)
    descriptor: int | None = None
    payload: bytes | None = None
    failures: list[BaseException] = []
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= MAX_NATIVE_PREWARM_PROJECTION_BYTES
        ):
            raise ValueError("native projection must be one private bounded regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("native projection changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("native projection exceeds its captured byte size")
        after = os.fstat(descriptor)
        leaf = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or leaf.st_dev != before.st_dev
            or leaf.st_ino != before.st_ino
        ):
            raise ValueError("native projection was replaced while reading")
        payload = b"".join(chunks)
    except (FileNotFoundError, IsADirectoryError, OSError):
        failures.append(ValueError("native projection is not a readable regular file"))
    except BaseException as primary:
        failures.append(primary)
    finally:
        _append_close_failures(
            (descriptor, parent_descriptor),
            failures,
        )
    _raise_collected_failures(
        "native projection read or cleanup failed",
        failures,
    )
    if payload is None:
        raise AssertionError("native projection read returned no payload")
    return payload


def load_native_prewarm_projection(
    path: Path,
    *,
    launch_request: TargetRuntimeLaunchRequestV2,
    runtime_identity: TargetRuntimeIdentityV2,
) -> TargetNativePrewarmProjectionV2:
    """Load one exact captured projection as non-authorizing evidence."""

    request = _checked_request(launch_request)
    identity = _checked_identity(runtime_identity, request=request)
    payload = _read_projection_once(path)
    projection = load_canonical_json_bytes(
        payload,
        TargetNativePrewarmProjectionV2,
        max_bytes=MAX_NATIVE_PREWARM_PROJECTION_BYTES,
        label="native prewarm projection",
    )
    if (
        projection.launch_request_sha256 != request.request_sha256
        or projection.runtime_identity_sha256 != identity.identity_sha256
        or projection.site_id != request.launch.site_id
        or projection.campaign_id != request.campaign_id
        or projection.launch_nonce != request.launch_nonce
        or projection.runtime_epoch != request.runtime_epoch
        or projection.runtime_epoch_started_generation != request.runtime_epoch_started_generation
        or projection.runtime_epoch_started_monotonic_ns
        != identity.runtime_epoch_started_monotonic_ns
        or projection.source_bindings != request.source_bindings
        or projection.authorizing is not False
    ):
        raise ValueError("native projection differs from launch/runtime identity")
    return projection


__all__ = [
    "MAX_NATIVE_PREWARM_PROJECTION_BYTES",
    "NativePrewarmProjectorV2",
    "load_native_prewarm_projection",
]
