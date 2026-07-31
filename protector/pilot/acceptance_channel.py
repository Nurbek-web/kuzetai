"""Protected, launch-bound controller/target acceptance channel.

The channel is intentionally file based so the exact runtime container can
receive it through a reviewed read/write bind mount.  Every message is
canonical, HMAC authenticated, no-replace, finite, and consumed once.  Public
models are evidence only; the process-local receipt returned to the
controller is the authority-bearing value.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import hmac
import os
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from protector.pilot.acceptance_source_profile import (
    TransmittedTargetSourceProfileV2,
    VerifiedTargetSourceProfileAttestationV2,
    export_verified_target_source_profile,
    verify_transmitted_target_source_profile,
)
from protector.pilot.acceptance_target import (
    TargetNativePrewarmProjectionV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
)
from protector.pilot.acceptance_trust import (
    canonical_json_bytes,
    load_canonical_json_bytes,
)
from protector.pilot.acceptance_transaction import (
    C2_CAPABILITY_TRANSACTION_LOCK,
)
from protector.pilot.acceptance_work import (
    MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES,
    TargetUniqueWorkPlanV2,
    TargetUniqueWorkProjectionV2,
)
from protector.pilot.config import FrozenModel
from protector.pilot.runtime.source_profile import Ed25519SourceProfileProofSigner
from protector.pilot.trusted_artifacts import (
    ed25519_public_key_spki_sha256,
    verify_ed25519_payload,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeId = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$"),
]
MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES = MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES + 1024 * 1024
_CHANNEL_NAME = "channel"
_RUNTIME_KEY_NAME = "runtime.key"
_CLAIM_NAME = "runtime.claim"
_GRANT_NAME = "grant.json"
_RESULT_NAME = "result.json"
_DIRECTIVE_NAME = "directive.json"
_ACK_NAME = "ack.json"


class _StrictFrozenModel(FrozenModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class AcceptanceRuntimeGrantV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-runtime-grant.v3"]
    collector_id: SafeId
    channel_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    launch_request_sha256: Digest
    runtime_identity_sha256: Digest
    unique_work_plan_sha256: Digest
    launch_request: TargetRuntimeLaunchRequestV2
    runtime_identity: TargetRuntimeIdentityV2
    unique_work_plan: TargetUniqueWorkPlanV2
    signed_source_profile: TransmittedTargetSourceProfileV2 | None = None

    @model_validator(mode="after")
    def exact_graph(self) -> AcceptanceRuntimeGrantV3:
        if (
            self.launch_request.request_sha256 != self.launch_request_sha256
            or self.runtime_identity.identity_sha256 != self.runtime_identity_sha256
            or self.unique_work_plan.plan_sha256 != self.unique_work_plan_sha256
            or self.runtime_identity.launch_request != self.launch_request
            or self.unique_work_plan.launch_request_sha256 != self.launch_request_sha256
            or self.unique_work_plan.runtime_identity_sha256 != self.runtime_identity_sha256
            or self.launch_request.launch_nonce != self.channel_nonce
            or self.unique_work_plan.launch_nonce != self.channel_nonce
        ):
            raise ValueError("acceptance runtime grant graph differs")
        if self.signed_source_profile is not None and (
            self.signed_source_profile.attestation.launch_request_sha256
            != self.launch_request_sha256
            or self.signed_source_profile.attestation.site_id
            != self.launch_request.launch.site_id
            or self.signed_source_profile.attestation.campaign_id
            != self.launch_request.campaign_id
            or self.signed_source_profile.attestation.gate
            != self.launch_request.gate
        ):
            raise ValueError("acceptance runtime source profile graph differs")
        return self


class AcceptanceRuntimeResultV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-runtime-result.v3"]
    collector_id: SafeId
    channel_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    launch_request_sha256: Digest
    runtime_identity_sha256: Digest
    runtime_epoch: Annotated[int, Field(ge=1, le=2**63 - 1)]
    runtime_epoch_started_generation: Annotated[int, Field(ge=1, le=2**63 - 1)]
    native_prewarm: TargetNativePrewarmProjectionV2
    unique_work_projection: TargetUniqueWorkProjectionV2
    verified_source_profile_sha256: Digest | None = None
    analytics_publication_enabled: Literal[False] = False

    @model_validator(mode="after")
    def exact_graph(self) -> AcceptanceRuntimeResultV3:
        if (
            self.native_prewarm.launch_request_sha256 != self.launch_request_sha256
            or self.native_prewarm.runtime_identity_sha256 != self.runtime_identity_sha256
            or self.native_prewarm.launch_nonce != self.channel_nonce
            or self.native_prewarm.runtime_epoch != self.runtime_epoch
            or self.native_prewarm.runtime_epoch_started_generation
            != self.runtime_epoch_started_generation
            or self.unique_work_projection.launch_request_sha256
            != self.launch_request_sha256
            or self.unique_work_projection.runtime_identity_sha256
            != self.runtime_identity_sha256
            or self.unique_work_projection.native_prewarm_projection_sha256
            != self.native_prewarm.projection_sha256
        ):
            raise ValueError("acceptance runtime result graph differs")
        return self

    @property
    def result_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


class AcceptanceRuntimeDirectiveV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-runtime-directive.v3"]
    collector_id: SafeId
    channel_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    result_sha256: Digest
    action: Literal["restart", "authorize"]


class AcceptanceRuntimeAckV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-runtime-ack.v3"]
    collector_id: SafeId
    channel_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    result_sha256: Digest
    action: Literal["restart", "authorize"]
    acknowledged_at_monotonic_ns: Annotated[int, Field(ge=1, le=2**63 - 1)]


class _RuntimeKeyMaterialV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-runtime-key-material.v3"]
    controller_public_key_pem_base64: Annotated[
        str,
        Field(min_length=1, max_length=1024),
    ]
    controller_public_key_spki_sha256: Digest
    runtime_mac_key_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    def public_key(self) -> bytes:
        try:
            value = base64.b64decode(
                self.controller_public_key_pem_base64,
                validate=True,
            )
        except ValueError:
            raise ValueError("acceptance controller public key is invalid") from None
        if (
            not 1 <= len(value) <= 1024
            or ed25519_public_key_spki_sha256(value)
            != self.controller_public_key_spki_sha256
        ):
            raise ValueError("acceptance controller public key differs")
        return value


class _ChannelEnvelopeV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-channel-envelope.v3"]
    kind: Literal["grant", "result", "directive", "ack"]
    channel_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    payload_sha256: Digest
    payload: dict[str, object]
    authentication: Literal["controller-ed25519", "runtime-hmac-sha256"]
    authentication_hex: Annotated[
        str,
        Field(pattern=r"^(?:[0-9a-f]{64}|[0-9a-f]{128})$"),
    ]

    @field_validator("payload")
    @classmethod
    def payload_is_bounded(cls, value: dict[str, object]) -> dict[str, object]:
        if len(canonical_json_bytes(value)) > MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES:
            raise ValueError("acceptance channel payload exceeds its finite bound")
        return value


def _message_authentication_payload(
    *,
    kind: str,
    channel_nonce: str,
    payload_sha256: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "acceptance-channel-authentication.v3",
            "kind": kind,
            "channel_nonce": channel_nonce,
            "payload_sha256": payload_sha256,
        }
    )


def _controller_envelope(
    *,
    signer: Ed25519SourceProfileProofSigner,
    kind: Literal["grant", "directive"],
    channel_nonce: str,
    value: FrozenModel,
) -> bytes:
    payload = value.model_dump(mode="json")
    payload_sha256 = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    authentication = signer.sign(
        _message_authentication_payload(
            kind=kind,
            channel_nonce=channel_nonce,
            payload_sha256=payload_sha256,
        )
    )
    if type(authentication) is not bytes or len(authentication) != 64:
        raise RuntimeError("acceptance controller signer returned an invalid signature")
    envelope = _ChannelEnvelopeV3(
        schema_version="acceptance-channel-envelope.v3",
        kind=kind,
        channel_nonce=channel_nonce,
        payload_sha256=payload_sha256,
        payload=payload,
        authentication="controller-ed25519",
        authentication_hex=authentication.hex(),
    )
    encoded = canonical_json_bytes(envelope)
    if not 1 <= len(encoded) <= MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES:
        raise ValueError("acceptance channel message exceeds its finite bound")
    return encoded


def _runtime_envelope(
    *,
    key: bytes,
    kind: Literal["result", "ack"],
    channel_nonce: str,
    value: FrozenModel,
) -> bytes:
    payload = value.model_dump(mode="json")
    payload_sha256 = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    authentication = hmac.digest(
        key,
        _message_authentication_payload(
            kind=kind,
            channel_nonce=channel_nonce,
            payload_sha256=payload_sha256,
        ),
        "sha256",
    )
    envelope = _ChannelEnvelopeV3(
        schema_version="acceptance-channel-envelope.v3",
        kind=kind,
        channel_nonce=channel_nonce,
        payload_sha256=payload_sha256,
        payload=payload,
        authentication="runtime-hmac-sha256",
        authentication_hex=authentication.hex(),
    )
    encoded = canonical_json_bytes(envelope)
    if not 1 <= len(encoded) <= MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES:
        raise ValueError("acceptance channel message exceeds its finite bound")
    return encoded


def _decode_controller(
    payload: bytes,
    *,
    public_key: bytes,
    public_key_spki_sha256: str,
    kind: Literal["grant", "directive"],
    channel_nonce: str,
    model: type[_StrictFrozenModel],
) -> _StrictFrozenModel:
    envelope = load_canonical_json_bytes(
        payload,
        _ChannelEnvelopeV3,
        max_bytes=MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES,
        label=f"acceptance channel {kind}",
    )
    nested = canonical_json_bytes(envelope.payload)
    nested_sha256 = hashlib.sha256(nested).hexdigest()
    if (
        envelope.kind != kind
        or envelope.channel_nonce != channel_nonce
        or envelope.payload_sha256 != nested_sha256
        or envelope.authentication != "controller-ed25519"
        or len(envelope.authentication_hex) != 128
    ):
        raise ValueError("acceptance channel message authentication differs")
    try:
        signature = bytes.fromhex(envelope.authentication_hex)
    except ValueError:
        raise ValueError("acceptance channel message signature is invalid") from None
    fingerprint = verify_ed25519_payload(
        payload=_message_authentication_payload(
            kind=kind,
            channel_nonce=channel_nonce,
            payload_sha256=nested_sha256,
        ),
        signature=signature,
        trusted_public_key=public_key,
        label=f"acceptance channel {kind}",
    )
    if fingerprint != public_key_spki_sha256:
        raise ValueError("acceptance channel controller key differs")
    return model.model_validate_json(nested, strict=True)


def _decode_runtime(
    payload: bytes,
    *,
    key: bytes,
    kind: Literal["result", "ack"],
    channel_nonce: str,
    model: type[_StrictFrozenModel],
) -> _StrictFrozenModel:
    envelope = load_canonical_json_bytes(
        payload,
        _ChannelEnvelopeV3,
        max_bytes=MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES,
        label=f"acceptance channel {kind}",
    )
    nested = canonical_json_bytes(envelope.payload)
    nested_sha256 = hashlib.sha256(nested).hexdigest()
    expected_mac = hmac.digest(
        key,
        _message_authentication_payload(
            kind=kind,
            channel_nonce=channel_nonce,
            payload_sha256=nested_sha256,
        ),
        "sha256",
    ).hex()
    if (
        envelope.kind != kind
        or envelope.channel_nonce != channel_nonce
        or envelope.payload_sha256 != nested_sha256
        or envelope.authentication != "runtime-hmac-sha256"
        or len(envelope.authentication_hex) != 64
        or not hmac.compare_digest(envelope.authentication_hex, expected_mac)
    ):
        raise ValueError("acceptance channel message authentication differs")
    return model.model_validate_json(nested, strict=True)


def _validate_root(root: Path) -> None:
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("acceptance channel root must be an absolute non-symlink")
    metadata = root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("acceptance channel root must be private and owner controlled")


def _read_private(path: Path, *, max_bytes: int) -> bytes:
    parent = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    descriptor = -1
    failures: list[BaseException] = []
    payload: bytes | None = None
    try:
        parent_metadata = os.fstat(parent)
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= max_bytes
            or before.st_dev != parent_metadata.st_dev
        ):
            raise ValueError("acceptance channel artifact is unsafe or unbounded")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("acceptance channel artifact changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("acceptance channel artifact exceeds its captured size")
        after = os.fstat(descriptor)
        leaf = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or (leaf.st_dev, leaf.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("acceptance channel artifact changed while reading")
        payload = b"".join(chunks)
    except BaseException as primary:
        failures.append(primary)
    finally:
        for candidate in (descriptor, parent):
            if candidate < 0:
                continue
            try:
                os.close(candidate)
            except BaseException as cleanup:
                failures.append(cleanup)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup(
            "acceptance channel read and cleanup failed",
            failures,
        )
    if payload is None:
        raise AssertionError("acceptance channel read returned no payload")
    return payload


def _publish_private(path: Path, payload: bytes) -> None:
    """Durably stage bytes, then expose the complete leaf without replacement."""

    if type(payload) is not bytes or not payload:
        raise ValueError("acceptance channel publication payload is invalid")
    parent = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    descriptor = -1
    staging_name = f".{path.name}.staged-{secrets.token_hex(16)}"
    staging_owned = False
    final_owned = False
    failures: list[BaseException] = []
    try:
        descriptor = os.open(
            staging_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent,
        )
        staging_owned = True
        created_metadata = os.fstat(descriptor)
        parent_metadata = os.fstat(parent)
        if (
            not stat.S_ISREG(created_metadata.st_mode)
            or created_metadata.st_uid != os.geteuid()
            or created_metadata.st_nlink != 1
            or created_metadata.st_dev != parent_metadata.st_dev
            or stat.S_IMODE(created_metadata.st_mode) != 0o600
        ):
            raise ValueError("acceptance channel output is unsafe")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("acceptance channel write made no progress")
            offset += written
        os.fsync(descriptor)
        staged_metadata = os.fstat(descriptor)
        staged_leaf = os.stat(
            staging_name,
            dir_fd=parent,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(staged_metadata.st_mode)
            or staged_metadata.st_uid != os.geteuid()
            or staged_metadata.st_nlink != 1
            or staged_metadata.st_dev != parent_metadata.st_dev
            or stat.S_IMODE(staged_metadata.st_mode) != 0o600
            or staged_metadata.st_size != len(payload)
            or (staged_metadata.st_dev, staged_metadata.st_ino)
            != (staged_leaf.st_dev, staged_leaf.st_ino)
        ):
            raise RuntimeError("acceptance channel staged output changed")
        # Persist the staged inode before the only operation that exposes it
        # under the protocol-visible name.
        os.fsync(parent)
        _rename_private_no_replace(
            parent,
            source_name=staging_name,
            destination_name=path.name,
        )
        staging_owned = False
        final_owned = True
        final_leaf = os.stat(
            path.name,
            dir_fd=parent,
            follow_symlinks=False,
        )
        if (final_leaf.st_dev, final_leaf.st_ino) != (
            staged_metadata.st_dev,
            staged_metadata.st_ino,
        ):
            raise RuntimeError("acceptance channel final output identity changed")
        os.fsync(parent)
    except BaseException as primary:
        failures.append(primary)
        owned_name = (
            path.name
            if final_owned
            else staging_name if staging_owned else None
        )
        if owned_name is not None:
            try:
                opened = os.fstat(descriptor)
                named = os.stat(
                    owned_name,
                    dir_fd=parent,
                    follow_symlinks=False,
                )
                if (opened.st_dev, opened.st_ino) != (
                    named.st_dev,
                    named.st_ino,
                ):
                    raise RuntimeError(
                        "acceptance channel rollback target identity changed"
                    )
                os.unlink(owned_name, dir_fd=parent)
                os.fsync(parent)
            except FileNotFoundError:
                pass
            except BaseException as cleanup:
                failures.append(cleanup)
    finally:
        for candidate in (descriptor, parent):
            if candidate < 0:
                continue
            try:
                os.close(candidate)
            except BaseException as cleanup:
                failures.append(cleanup)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup(
            "acceptance channel publication and cleanup failed",
            failures,
        )


def _rename_private_no_replace(
    directory: int,
    *,
    source_name: str,
    destination_name: str,
) -> None:
    """Linux atomic no-replace rename relative to one pinned directory."""

    if (
        type(directory) is not int
        or directory < 0
        or type(source_name) is not str
        or type(destination_name) is not str
        or not source_name
        or not destination_name
        or "/" in source_name
        or "/" in destination_name
    ):
        raise ValueError("acceptance channel rename input is invalid")
    library = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = library.renameat2
    except AttributeError:
        raise RuntimeError(
            "atomic no-replace publication requires Linux renameat2"
        ) from None
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            directory,
            os.fsencode(source_name),
            directory,
            os.fsencode(destination_name),
            1,  # RENAME_NOREPLACE
        )
        == 0
    ):
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(
            error,
            os.strerror(error),
            destination_name,
        )
    raise OSError(error, os.strerror(error), destination_name)


def _unlink_private(path: Path) -> None:
    parent = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    failures: list[BaseException] = []
    try:
        os.unlink(path.name, dir_fd=parent)
        os.fsync(parent)
    except BaseException as primary:
        failures.append(primary)
    finally:
        try:
            os.close(parent)
        except BaseException as cleanup:
            failures.append(cleanup)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup(
            "acceptance channel unlink and cleanup failed",
            failures,
        )


class _RuntimeClaim:
    __slots__ = ("channel_root",)

    def __init__(self, channel_root: Path) -> None:
        self.channel_root = channel_root

    def __copy__(self) -> None:
        raise TypeError("runtime channel claim cannot be copied or serialized")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("runtime channel claim cannot be copied or serialized")

    def __reduce_ex__(self, _protocol: int) -> None:
        raise TypeError("runtime channel claim cannot be copied or serialized")


def _make_receipt_tools():
    issuer = object()
    provenance_key = secrets.token_bytes(32)

    class _VerifiedChannelReceipt:
        __slots__ = (
            "__ack_payload",
            "__consumed",
            "__lock",
            "__payload",
            "__provenance",
        )

        def __init__(self, *, token: object, payload: bytes) -> None:
            if token is not issuer:
                raise TypeError("channel receipt requires the private controller issuer")
            self.__payload = payload
            self.__provenance = hmac.digest(provenance_key, payload, "sha256")
            self.__ack_payload: bytes | None = None
            self.__consumed = False
            self.__lock = threading.Lock()

        def __copy__(self) -> None:
            raise TypeError("channel receipt capability cannot be copied or serialized")

        def __deepcopy__(self, _memo: object) -> None:
            raise TypeError("channel receipt capability cannot be copied or serialized")

        def __reduce_ex__(self, _protocol: int) -> None:
            raise TypeError("channel receipt capability cannot be copied or serialized")

    def issue(result: AcceptanceRuntimeResultV3) -> object:
        return _VerifiedChannelReceipt(
            token=issuer,
            payload=canonical_json_bytes(result),
        )

    def bind_ack(candidate: object, ack: AcceptanceRuntimeAckV3) -> None:
        if type(candidate) is not _VerifiedChannelReceipt:
            raise TypeError("verified acceptance channel receipt is required")
        with candidate._VerifiedChannelReceipt__lock:
            if candidate._VerifiedChannelReceipt__consumed:
                raise RuntimeError("acceptance channel receipt was already consumed")
            if candidate._VerifiedChannelReceipt__ack_payload is not None:
                raise RuntimeError("acceptance channel receipt already has an acknowledgement")
            candidate._VerifiedChannelReceipt__ack_payload = canonical_json_bytes(ack)

    def _inspect_locked(
        candidate: object,
        *,
        consume: bool,
    ) -> tuple[AcceptanceRuntimeResultV3, AcceptanceRuntimeAckV3]:
        if type(candidate) is not _VerifiedChannelReceipt:
            raise TypeError("verified acceptance channel receipt is required")
        with candidate._VerifiedChannelReceipt__lock:
            if candidate._VerifiedChannelReceipt__consumed:
                raise RuntimeError("acceptance channel receipt was already consumed")
            payload = candidate._VerifiedChannelReceipt__payload
            ack_payload = candidate._VerifiedChannelReceipt__ack_payload
            provenance = candidate._VerifiedChannelReceipt__provenance
            if (
                type(payload) is not bytes
                or type(ack_payload) is not bytes
                or type(provenance) is not bytes
                or not hmac.compare_digest(
                    provenance,
                    hmac.digest(provenance_key, payload, "sha256"),
                )
            ):
                raise ValueError("acceptance channel receipt provenance is invalid")
            result = AcceptanceRuntimeResultV3.model_validate_json(payload, strict=True)
            ack = AcceptanceRuntimeAckV3.model_validate_json(
                ack_payload,
                strict=True,
            )
            if (
                ack.collector_id != result.collector_id
                or ack.channel_nonce != result.channel_nonce
                or ack.result_sha256 != result.result_sha256
                or ack.acknowledged_at_monotonic_ns
                < result.unique_work_projection.measurement_completed_monotonic_ns
            ):
                raise ValueError(
                    "acceptance channel acknowledgement differs from completed result"
                )
            if consume:
                candidate._VerifiedChannelReceipt__consumed = True
            return result, ack

    def inspect(
        candidate: object,
        *,
        consume: bool,
    ) -> tuple[AcceptanceRuntimeResultV3, AcceptanceRuntimeAckV3]:
        with C2_CAPABILITY_TRANSACTION_LOCK:
            return _inspect_locked(candidate, consume=consume)

    def peek(
        candidate: object,
    ) -> tuple[AcceptanceRuntimeResultV3, AcceptanceRuntimeAckV3]:
        return inspect(candidate, consume=False)

    def consume(
        candidate: object,
    ) -> tuple[AcceptanceRuntimeResultV3, AcceptanceRuntimeAckV3]:
        return inspect(candidate, consume=True)

    return issue, bind_ack, peek, consume


(
    _issue_channel_receipt,
    _bind_channel_ack,
    _peek_channel_receipt,
    _require_channel_receipt,
) = _make_receipt_tools()


class ControllerAcceptanceChannelV3:
    """Controller half of one exact launch channel."""

    __slots__ = (
        "_aborted",
        "_ack_consumed",
        "_channel_root",
        "_collector_id",
        "_controller_key_path",
        "_controller_public_key_spki_sha256",
        "_controller_seed",
        "_controller_signer",
        "_directive",
        "_nonce",
        "_request",
        "_result_consumed",
        "_result_receipt",
        "_runtime_key",
    )

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del _args, _kwargs
        raise TypeError("controller acceptance channels come only from create")

    @classmethod
    def create(
        cls,
        *,
        root: Path,
        collector_id: str,
        launch_request: TargetRuntimeLaunchRequestV2,
    ) -> ControllerAcceptanceChannelV3:
        _validate_root(root)
        if type(launch_request) is not TargetRuntimeLaunchRequestV2:
            raise TypeError("acceptance channel requires the exact launch request")
        request = TargetRuntimeLaunchRequestV2.model_validate(launch_request)
        if (
            type(collector_id) is not str
            or not 1 <= len(collector_id) <= 160
            or any(
                character
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-"
                for character in collector_id
            )
        ):
            raise ValueError("acceptance channel collector identity is invalid")
        channel_root = root / f"{_CHANNEL_NAME}-{request.launch_nonce}"
        os.mkdir(channel_root, 0o700)
        try:
            controller_seed = secrets.token_bytes(32)
            controller_signer = Ed25519SourceProfileProofSigner(
                key_id=f"acceptance-channel-{request.launch_nonce}",
                signing_seed=controller_seed,
            )
            controller_public_key = controller_signer.public_key
            controller_public_key_spki_sha256 = ed25519_public_key_spki_sha256(
                controller_public_key
            )
            runtime_key = secrets.token_bytes(32)
            controller_key_payload = controller_seed + runtime_key
            runtime_key_payload = canonical_json_bytes(
                _RuntimeKeyMaterialV3(
                    schema_version="acceptance-runtime-key-material.v3",
                    controller_public_key_pem_base64=base64.b64encode(
                        controller_public_key
                    ).decode("ascii"),
                    controller_public_key_spki_sha256=(
                        controller_public_key_spki_sha256
                    ),
                    runtime_mac_key_hex=runtime_key.hex(),
                )
            )
        except BaseException as primary:
            try:
                os.rmdir(channel_root)
            except BaseException as cleanup:
                raise BaseExceptionGroup(
                    "acceptance channel key creation and rollback failed",
                    [primary, cleanup],
                ) from primary
            raise
        controller_key_path = root / f".controller-key-{request.launch_nonce}"
        created: list[Path] = []
        try:
            _publish_private(controller_key_path, controller_key_payload)
            created.append(controller_key_path)
            _publish_private(channel_root / _RUNTIME_KEY_NAME, runtime_key_payload)
            created.append(channel_root / _RUNTIME_KEY_NAME)
        except BaseException as primary:
            failures: list[BaseException] = [primary]
            for path in reversed(created):
                try:
                    _unlink_private(path)
                except FileNotFoundError:
                    pass
                except BaseException as cleanup:
                    failures.append(cleanup)
            try:
                os.rmdir(channel_root)
            except BaseException as cleanup:
                failures.append(cleanup)
            if len(failures) == 1:
                raise failures[0]
            raise BaseExceptionGroup(
                "acceptance channel creation and rollback failed",
                failures,
            ) from primary
        channel = object.__new__(cls)
        channel._aborted = False
        channel._ack_consumed = False
        channel._channel_root = channel_root
        channel._collector_id = collector_id
        channel._controller_key_path = controller_key_path
        channel._controller_public_key_spki_sha256 = (
            controller_public_key_spki_sha256
        )
        channel._controller_seed = controller_seed
        channel._controller_signer = controller_signer
        channel._directive = None
        channel._nonce = request.launch_nonce
        channel._request = request
        channel._result_consumed = False
        channel._result_receipt = None
        channel._runtime_key = runtime_key
        return channel

    @property
    def runtime_claim(self) -> object:
        return _RuntimeClaim(self._channel_root)

    @property
    def runtime_claim_path(self) -> Path:
        """Exact reviewed bind-mount path passed to the target process."""

        return self._channel_root

    def abort(self) -> None:
        """Destroy this finite channel after runtime cleanup or any failed launch."""

        if self._aborted:
            return
        failures: list[BaseException] = []
        for name in (
            _ACK_NAME,
            _DIRECTIVE_NAME,
            _RESULT_NAME,
            _GRANT_NAME,
            _CLAIM_NAME,
            _RUNTIME_KEY_NAME,
        ):
            try:
                _unlink_private(self._channel_root / name)
            except FileNotFoundError:
                pass
            except BaseException as cleanup:
                failures.append(cleanup)
        try:
            os.rmdir(self._channel_root)
        except FileNotFoundError:
            pass
        except BaseException as cleanup:
            failures.append(cleanup)
        try:
            _unlink_private(self._controller_key_path)
        except FileNotFoundError:
            pass
        except BaseException as cleanup:
            failures.append(cleanup)
        self._aborted = True
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup(
                "acceptance channel cleanup failed",
                failures,
            )

    def _controller_authority(
        self,
    ) -> tuple[Ed25519SourceProfileProofSigner, bytes]:
        observed = _read_private(self._controller_key_path, max_bytes=64)
        expected = self._controller_seed + self._runtime_key
        if len(observed) != 64 or not hmac.compare_digest(observed, expected):
            raise RuntimeError("acceptance controller channel key changed")
        if (
            ed25519_public_key_spki_sha256(self._controller_signer.public_key)
            != self._controller_public_key_spki_sha256
        ):
            raise RuntimeError("acceptance controller signing key changed")
        return self._controller_signer, self._runtime_key

    def publish_grant(
        self,
        *,
        runtime_identity: TargetRuntimeIdentityV2,
        unique_work_plan: TargetUniqueWorkPlanV2,
        verified_source_profile: VerifiedTargetSourceProfileAttestationV2 | None = None,
    ) -> AcceptanceRuntimeGrantV3:
        signed_source_profile = (
            None
            if verified_source_profile is None
            else export_verified_target_source_profile(
                verified_source_profile
            )
        )
        grant = AcceptanceRuntimeGrantV3(
            schema_version="acceptance-runtime-grant.v3",
            collector_id=self._collector_id,
            channel_nonce=self._nonce,
            launch_request_sha256=self._request.request_sha256,
            runtime_identity_sha256=runtime_identity.identity_sha256,
            unique_work_plan_sha256=unique_work_plan.plan_sha256,
            launch_request=self._request,
            runtime_identity=runtime_identity,
            unique_work_plan=unique_work_plan,
            signed_source_profile=signed_source_profile,
        )
        _publish_private(
            self._channel_root / _GRANT_NAME,
            _controller_envelope(
                signer=self._controller_authority()[0],
                kind="grant",
                channel_nonce=self._nonce,
                value=grant,
            ),
        )
        return grant

    def consume_result(self) -> tuple[AcceptanceRuntimeResultV3, object]:
        if self._result_consumed:
            raise RuntimeError("acceptance runtime result was already consumed")
        payload = _read_private(
            self._channel_root / _RESULT_NAME,
            max_bytes=MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES,
        )
        result = _decode_runtime(
            payload,
            key=self._controller_authority()[1],
            kind="result",
            channel_nonce=self._nonce,
            model=AcceptanceRuntimeResultV3,
        )
        assert isinstance(result, AcceptanceRuntimeResultV3)
        if (
            result.collector_id != self._collector_id
            or result.launch_request_sha256 != self._request.request_sha256
            or result.runtime_epoch != self._request.runtime_epoch
            or result.runtime_epoch_started_generation
            != self._request.runtime_epoch_started_generation
        ):
            raise ValueError("acceptance runtime result differs from exact launch")
        self._result_consumed = True
        receipt = _issue_channel_receipt(result)
        self._result_receipt = receipt
        return result, receipt

    def publish_directive(
        self,
        *,
        action: Literal["restart", "authorize"],
    ) -> AcceptanceRuntimeDirectiveV3:
        if not self._result_consumed or self._result_receipt is None:
            raise RuntimeError(
                "acceptance runtime result completion is required before a directive"
            )
        if self._directive is not None:
            raise RuntimeError("acceptance runtime directive was already published")
        result_payload = _read_private(
            self._channel_root / _RESULT_NAME,
            max_bytes=MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES,
        )
        result = _decode_runtime(
            result_payload,
            key=self._controller_authority()[1],
            kind="result",
            channel_nonce=self._nonce,
            model=AcceptanceRuntimeResultV3,
        )
        assert isinstance(result, AcceptanceRuntimeResultV3)
        directive = AcceptanceRuntimeDirectiveV3(
            schema_version="acceptance-runtime-directive.v3",
            collector_id=self._collector_id,
            channel_nonce=self._nonce,
            result_sha256=result.result_sha256,
            action=action,
        )
        _publish_private(
            self._channel_root / _DIRECTIVE_NAME,
            _controller_envelope(
                signer=self._controller_authority()[0],
                kind="directive",
                channel_nonce=self._nonce,
                value=directive,
            ),
        )
        self._directive = directive
        return directive

    def consume_ack(self) -> AcceptanceRuntimeAckV3:
        if self._directive is None or self._result_receipt is None:
            raise RuntimeError("acceptance runtime directive is required before acknowledgement")
        if self._ack_consumed:
            raise RuntimeError("acceptance runtime acknowledgement was already consumed")
        payload = _read_private(
            self._channel_root / _ACK_NAME,
            max_bytes=MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES,
        )
        ack = _decode_runtime(
            payload,
            key=self._controller_authority()[1],
            kind="ack",
            channel_nonce=self._nonce,
            model=AcceptanceRuntimeAckV3,
        )
        assert isinstance(ack, AcceptanceRuntimeAckV3)
        if (
            ack.collector_id != self._collector_id
            or ack.channel_nonce != self._nonce
            or ack.result_sha256 != self._directive.result_sha256
            or ack.action != self._directive.action
        ):
            raise ValueError("acceptance runtime acknowledgement differs from directive")
        _bind_channel_ack(self._result_receipt, ack)
        self._ack_consumed = True
        return ack


class RuntimeAcceptanceChannelV3:
    """Exact child half.  Claiming consumes the runtime key before any grant."""

    __slots__ = (
        "_ack_published",
        "_channel_root",
        "_collector_id",
        "_controller_public_key",
        "_controller_public_key_spki_sha256",
        "_directive",
        "_grant",
        "_nonce",
        "_publication_enabled",
        "_result_published",
        "_runtime_key",
        "_verified_source_profile",
    )

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del _args, _kwargs
        raise TypeError("runtime acceptance channels come only from claim")

    @classmethod
    def claim(cls, claim: object) -> RuntimeAcceptanceChannelV3:
        if type(claim) is not _RuntimeClaim:
            raise TypeError("exact runtime channel claim is required")
        return cls.claim_path(claim.channel_root)

    @classmethod
    def claim_path(cls, root: Path) -> RuntimeAcceptanceChannelV3:
        """Claim a protected channel from inside the exact launched container."""

        if not isinstance(root, Path):
            raise TypeError("runtime channel path must be an exact Path")
        _validate_root(root)
        nonce = root.name.removeprefix(f"{_CHANNEL_NAME}-")
        if (
            root.name != f"{_CHANNEL_NAME}-{nonce}"
            or len(nonce) != 32
            or any(character not in "0123456789abcdef" for character in nonce)
        ):
            raise ValueError("runtime acceptance channel path is not launch bound")
        claimed = False
        try:
            _publish_private(root / _CLAIM_NAME, secrets.token_bytes(32))
            claimed = True
        except FileExistsError:
            raise RuntimeError("runtime acceptance channel was already claimed") from None
        try:
            key_payload = _read_private(
                root / _RUNTIME_KEY_NAME,
                max_bytes=4 * 1024,
            )
            key_material = load_canonical_json_bytes(
                key_payload,
                _RuntimeKeyMaterialV3,
                max_bytes=4 * 1024,
                label="acceptance runtime key material",
            )
            controller_public_key = key_material.public_key()
            runtime_key = bytes.fromhex(key_material.runtime_mac_key_hex)
            if len(runtime_key) != 32:
                raise ValueError("runtime acceptance channel key is invalid")
            _unlink_private(root / _RUNTIME_KEY_NAME)
        except BaseException as primary:
            failures: list[BaseException] = [primary]
            if claimed:
                try:
                    _unlink_private(root / _CLAIM_NAME)
                except FileNotFoundError:
                    pass
                except BaseException as cleanup:
                    failures.append(cleanup)
            if len(failures) == 1:
                raise
            raise BaseExceptionGroup(
                "runtime channel claim and rollback both failed",
                failures,
            ) from primary
        channel = object.__new__(cls)
        channel._ack_published = False
        channel._channel_root = root
        channel._collector_id = ""
        channel._controller_public_key = controller_public_key
        channel._controller_public_key_spki_sha256 = (
            key_material.controller_public_key_spki_sha256
        )
        channel._directive = None
        channel._grant = None
        channel._nonce = nonce
        channel._publication_enabled = False
        channel._result_published = False
        channel._runtime_key = runtime_key
        channel._verified_source_profile = None
        return channel

    def consume_grant(self) -> AcceptanceRuntimeGrantV3:
        if self._grant is not None:
            raise RuntimeError("acceptance runtime grant was already consumed")
        payload = _read_private(
            self._channel_root / _GRANT_NAME,
            max_bytes=MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES,
        )
        grant = _decode_controller(
            payload,
            public_key=self._controller_public_key,
            public_key_spki_sha256=(
                self._controller_public_key_spki_sha256
            ),
            kind="grant",
            channel_nonce=self._nonce,
            model=AcceptanceRuntimeGrantV3,
        )
        assert isinstance(grant, AcceptanceRuntimeGrantV3)
        self._grant = grant
        self._collector_id = grant.collector_id
        return grant

    def consume_grant_wait(
        self,
        *,
        timeout_seconds: float = 300.0,
        poll_seconds: float = 0.05,
        monotonic: object = time.monotonic,
        sleep: object = time.sleep,
    ) -> AcceptanceRuntimeGrantV3:
        """Wait only for the launch-bound grant after the child has claimed."""

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < float(timeout_seconds) <= 300.0
            or isinstance(poll_seconds, bool)
            or not isinstance(poll_seconds, (int, float))
            or not 0 < float(poll_seconds) <= 1.0
            or not callable(monotonic)
            or not callable(sleep)
        ):
            raise ValueError("acceptance grant wait bound is invalid")
        deadline = monotonic() + float(timeout_seconds)
        while True:
            try:
                return self.consume_grant()
            except FileNotFoundError:
                if monotonic() >= deadline:
                    raise RuntimeError(
                        "acceptance runtime timed out waiting for its grant"
                    ) from None
                sleep(float(poll_seconds))

    def publish_result(
        self,
        *,
        native_prewarm: TargetNativePrewarmProjectionV2,
        unique_work_projection: TargetUniqueWorkProjectionV2,
    ) -> AcceptanceRuntimeResultV3:
        if self._grant is None:
            raise RuntimeError("acceptance runtime grant must be consumed first")
        if self._result_published:
            raise RuntimeError("acceptance runtime result was already published")
        grant = self._grant
        verified_source_profile_sha256: str | None = None
        if grant.signed_source_profile is not None:
            verified = self._verified_source_profile
            if (
                type(verified)
                is not VerifiedTargetSourceProfileAttestationV2
                or verified.verified_binding_sha256
                != grant.signed_source_profile.verified_binding_sha256
            ):
                raise RuntimeError(
                    "acceptance runtime must verify its signed source profile"
                )
            verified_source_profile_sha256 = (
                verified.verified_binding_sha256
            )
        result = AcceptanceRuntimeResultV3(
            schema_version="acceptance-runtime-result.v3",
            collector_id=grant.collector_id,
            channel_nonce=grant.channel_nonce,
            launch_request_sha256=grant.launch_request_sha256,
            runtime_identity_sha256=grant.runtime_identity_sha256,
            runtime_epoch=grant.launch_request.runtime_epoch,
            runtime_epoch_started_generation=(
                grant.launch_request.runtime_epoch_started_generation
            ),
            native_prewarm=native_prewarm,
            unique_work_projection=unique_work_projection,
            verified_source_profile_sha256=verified_source_profile_sha256,
            analytics_publication_enabled=False,
        )
        _publish_private(
            self._channel_root / _RESULT_NAME,
            _runtime_envelope(
                key=self._runtime_key,
                kind="result",
                channel_nonce=self._nonce,
                value=result,
            ),
        )
        self._result_published = True
        return result

    def verified_source_profile(
        self,
    ) -> VerifiedTargetSourceProfileAttestationV2:
        if self._grant is None:
            raise RuntimeError("acceptance runtime grant must be consumed first")
        grant = self._grant
        if grant.signed_source_profile is None:
            raise RuntimeError("acceptance runtime source profile is unavailable")
        if self._verified_source_profile is None:
            self._verified_source_profile = (
                verify_transmitted_target_source_profile(
                    grant.signed_source_profile,
                    launch_request=grant.launch_request,
                )
            )
        return self._verified_source_profile

    def consume_directive(self) -> AcceptanceRuntimeDirectiveV3:
        if not self._result_published:
            raise RuntimeError("acceptance runtime result is required before directive")
        if self._directive is not None:
            raise RuntimeError("acceptance runtime directive was already consumed")
        payload = _read_private(
            self._channel_root / _DIRECTIVE_NAME,
            max_bytes=MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES,
        )
        directive = _decode_controller(
            payload,
            public_key=self._controller_public_key,
            public_key_spki_sha256=(
                self._controller_public_key_spki_sha256
            ),
            kind="directive",
            channel_nonce=self._nonce,
            model=AcceptanceRuntimeDirectiveV3,
        )
        assert isinstance(directive, AcceptanceRuntimeDirectiveV3)
        result_payload = _read_private(
            self._channel_root / _RESULT_NAME,
            max_bytes=MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES,
        )
        result = _decode_runtime(
            result_payload,
            key=self._runtime_key,
            kind="result",
            channel_nonce=self._nonce,
            model=AcceptanceRuntimeResultV3,
        )
        assert isinstance(result, AcceptanceRuntimeResultV3)
        if (
            directive.collector_id != self._collector_id
            or directive.channel_nonce != self._nonce
            or directive.result_sha256 != result.result_sha256
        ):
            raise ValueError("acceptance runtime directive differs from completed result")
        self._directive = directive
        return directive

    def publish_ack(self) -> AcceptanceRuntimeAckV3:
        if self._directive is None:
            raise RuntimeError("acceptance runtime directive must be consumed before ack")
        if self._ack_published:
            raise RuntimeError("acceptance runtime acknowledgement was already published")
        ack = AcceptanceRuntimeAckV3(
            schema_version="acceptance-runtime-ack.v3",
            collector_id=self._collector_id,
            channel_nonce=self._nonce,
            result_sha256=self._directive.result_sha256,
            action=self._directive.action,
            acknowledged_at_monotonic_ns=time.monotonic_ns(),
        )
        _publish_private(
            self._channel_root / _ACK_NAME,
            _runtime_envelope(
                key=self._runtime_key,
                kind="ack",
                channel_nonce=self._nonce,
                value=ack,
            ),
        )
        self._ack_published = True
        self._publication_enabled = self._directive.action == "authorize"
        return ack

    def analytics_publication_enabled(self) -> bool:
        return self._publication_enabled is True


__all__ = (
    "AcceptanceRuntimeGrantV3",
    "AcceptanceRuntimeAckV3",
    "AcceptanceRuntimeDirectiveV3",
    "AcceptanceRuntimeResultV3",
    "ControllerAcceptanceChannelV3",
    "MAX_ACCEPTANCE_CHANNEL_MESSAGE_BYTES",
    "RuntimeAcceptanceChannelV3",
)
