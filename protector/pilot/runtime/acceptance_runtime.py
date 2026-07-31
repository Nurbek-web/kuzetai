"""Protected child-side V3 acceptance authority wiring for DeepStream."""

from __future__ import annotations

import os
import stat
import threading
import time
from pathlib import Path
from typing import Callable

from protector.pilot.acceptance_channel import RuntimeAcceptanceChannelV3
from protector.pilot.runtime.native_source_authority import (
    NativeExact20SourceAuthorityV2,
    NativeSourceSecretsV2,
)
from protector.pilot.runtime.work_authority import TargetUniqueWorkRuntimeLedger
from protector.pilot.runtime.source_profile import Ed25519SourceProfileProofSigner


def _read_secret(
    directory: int,
    *,
    root_identity: tuple[int, int],
    name: str,
    max_bytes: int,
) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or not 1 <= metadata.st_size <= max_bytes
            or metadata.st_dev != root_identity[0]
        ):
            raise ValueError("acceptance native secret is unsafe or unbounded")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16 * 1024))
            if not chunk:
                raise ValueError("acceptance native secret changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        leaf = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or (leaf.st_dev, leaf.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise ValueError("acceptance native secret changed while reading")
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_native_source_secrets_v2(
    root: Path,
    *,
    proof_key_id: str,
) -> NativeSourceSecretsV2:
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("acceptance native secret root must be absolute")
    directory = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        parent = os.fstat(directory)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_mode & 0o022
            or parent.st_uid not in {0, os.geteuid()}
        ):
            raise ValueError("acceptance native secret root is unsafe")
        root_identity = (parent.st_dev, parent.st_ino)
        resolved_sources = tuple(
            _read_secret(
                directory,
                root_identity=root_identity,
                name=f"camera-{index:02}.rtsp",
                max_bytes=16_384,
            )
            .decode("utf-8")
            .strip()
            for index in range(20)
        )
        commitment_key = _read_secret(
            directory,
            root_identity=root_identity,
            name="source-commitment.key",
            max_bytes=32,
        )
        milestone_key = _read_secret(
            directory,
            root_identity=root_identity,
            name="source-milestone.key",
            max_bytes=32,
        )
        proof_seed = _read_secret(
            directory,
            root_identity=root_identity,
            name="source-proof.seed",
            max_bytes=32,
        )
        after = os.fstat(directory)
        path_after = root.lstat()
        if (
            (after.st_dev, after.st_ino) != root_identity
            or (path_after.st_dev, path_after.st_ino) != root_identity
        ):
            raise ValueError("acceptance native secret root changed")
    finally:
        os.close(directory)
    return NativeSourceSecretsV2(
        resolved_sources=resolved_sources,
        commitment_key=commitment_key,
        milestone_authenticator_key=milestone_key,
        proof_signer=Ed25519SourceProfileProofSigner(
            key_id=proof_key_id,
            signing_seed=proof_seed,
        ),
    )


class _WorkCompletionBridge:
    __slots__ = ("_ledger", "_lock")

    def __init__(self) -> None:
        self._ledger: TargetUniqueWorkRuntimeLedger | None = None
        self._lock = threading.RLock()

    def activate(self, ledger: TargetUniqueWorkRuntimeLedger) -> None:
        with self._lock:
            if self._ledger is not None:
                raise RuntimeError("acceptance work bridge was already activated")
            self._ledger = ledger

    def __call__(
        self,
        *,
        camera_id: str,
        source_index: int,
        module: str,
        detection_count: int,
    ) -> object:
        with self._lock:
            if self._ledger is None:
                return None
            return self._ledger.record_scheduled_post_analytics_frame(
                camera_id=camera_id,
                source_index=source_index,
                module=module,
                detection_count=detection_count,
            )


class TargetAcceptanceRuntimeV3:
    """Own native leases, real work accounting, result, and directive/ack."""

    def __init__(
        self,
        *,
        channel_path: Path,
        native_source_secrets: NativeSourceSecretsV2 | None = None,
        native_source_secrets_root: Path | None = None,
        native_projection_path: Path,
        work_projection_path: Path,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if (native_source_secrets is None) == (native_source_secrets_root is None):
            raise ValueError("exactly one native source secret input is required")
        if (
            not isinstance(channel_path, Path)
            or not isinstance(native_projection_path, Path)
            or not isinstance(work_projection_path, Path)
            or not channel_path.is_absolute()
            or not native_projection_path.is_absolute()
            or not work_projection_path.is_absolute()
            or not callable(monotonic_ns)
        ):
            raise ValueError("acceptance runtime paths and clock are invalid")
        if native_source_secrets_root is not None and (
            not isinstance(native_source_secrets_root, Path)
            or not native_source_secrets_root.is_absolute()
        ):
            raise ValueError("acceptance native secret root is invalid")
        channel = RuntimeAcceptanceChannelV3.claim_path(channel_path)
        grant = channel.consume_grant_wait()
        verified_source = channel.verified_source_profile()
        signed_source_profile = grant.signed_source_profile
        if signed_source_profile is None:
            raise RuntimeError("acceptance source profile is unavailable")
        source_attestation = signed_source_profile.attestation
        secrets = (
            native_source_secrets
            if native_source_secrets is not None
            else load_native_source_secrets_v2(
                native_source_secrets_root,
                proof_key_id=(
                    source_attestation.source_profile_proof_key_id
                ),
            )
        )
        native = NativeExact20SourceAuthorityV2(
            verified_attestation=verified_source,
            launch_request=grant.launch_request,
            runtime_identity=grant.runtime_identity,
            secrets=secrets,
            projection_path=native_projection_path,
            monotonic_ns=monotonic_ns,
        )
        self.channel = channel
        self.grant = grant
        self.native_source_authority = native
        self.work_completion = _WorkCompletionBridge()
        self._work_projection_path = work_projection_path
        self._monotonic_ns = monotonic_ns
        self._ledger: TargetUniqueWorkRuntimeLedger | None = None
        self._stage = "prewarm"
        self._failed: BaseException | None = None
        self._fatal_callback: Callable[[], None] | None = None
        self._prewarm_deadline_ns = (
            grant.runtime_identity.runtime_epoch_started_monotonic_ns
            + 120_000_000_000
        )

    @property
    def failed(self) -> BaseException | None:
        return self._failed

    def analytics_publication_enabled(self) -> bool:
        return self.channel.analytics_publication_enabled()

    def _fail(self, failure: BaseException) -> bool:
        self._failed = failure
        if self._fatal_callback is not None:
            self._fatal_callback()
        return False

    def _advance(self) -> bool:
        try:
            if self._stage == "prewarm":
                now = self._monotonic_ns()
                earliest = (
                    self.grant.runtime_identity.runtime_epoch_started_monotonic_ns
                    + 60_000_000_000
                )
                if now < earliest:
                    return True
                try:
                    prewarm = self.native_source_authority.publish_native_prewarm()
                except ValueError:
                    if now < self._prewarm_deadline_ns:
                        return True
                    raise RuntimeError(
                        "native exact-20 prewarm did not complete within its bound"
                    ) from None
                ledger = TargetUniqueWorkRuntimeLedger(
                    plan=self.grant.unique_work_plan,
                    native_prewarm=prewarm,
                )
                self._ledger = ledger
                self._prewarm = prewarm
                self.work_completion.activate(ledger)
                self._stage = "work"
                return True
            if self._stage == "work":
                assert self._ledger is not None
                horizon = (
                    self._ledger.measurement_started_monotonic_ns
                    + self.grant.unique_work_plan.measurement_duration_ns
                )
                if self._monotonic_ns() < horizon:
                    return True
                projection = self._ledger.publish_projection(
                    self._work_projection_path
                )
                assert self._prewarm is not None
                self.channel.publish_result(
                    native_prewarm=self._prewarm,
                    unique_work_projection=projection,
                )
                self._stage = "directive"
                return True
            if self._stage == "directive":
                try:
                    self.channel.consume_directive()
                except FileNotFoundError:
                    return True
                self.channel.publish_ack()
                self._stage = "complete"
                return False
            return False
        except BaseException as failure:
            return self._fail(failure)

    def start(
        self,
        glib: object,
        *,
        fatal_callback: Callable[[], None],
    ) -> None:
        if not callable(fatal_callback):
            raise TypeError("acceptance runtime fatal callback is required")
        timeout_add = getattr(glib, "timeout_add", None)
        if not callable(timeout_add):
            raise TypeError("acceptance runtime requires GLib timeout scheduling")
        self._fatal_callback = fatal_callback
        timeout_add(250, self._advance)

    def close(self) -> None:
        self.native_source_authority.close()


__all__ = (
    "TargetAcceptanceRuntimeV3",
    "load_native_source_secrets_v2",
)
