"""Captured-byte verification for externally attested pilot artifacts."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_PUBLIC_KEY_PEM = re.compile(
    rb"[ \t\r\n\v\f]*"
    rb"-----BEGIN PUBLIC KEY-----\r?\n"
    rb"(?:[A-Za-z0-9+/]{1,64}={0,2}\r?\n)+"
    rb"-----END PUBLIC KEY-----"
    rb"[ \t\r\n\v\f]*"
)


@dataclass(frozen=True)
class VerifiedDetachedArtifact:
    payload: bytes
    signature: bytes
    trust_key: bytes
    payload_sha256: str
    signature_sha256: str
    trust_key_spki_sha256: str


@dataclass(frozen=True)
class CapturedRegularArtifact:
    payload: bytes
    metadata: os.stat_result


def capture_regular_bounded(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> CapturedRegularArtifact:
    """Capture exact bytes through a component-pinned O_NOFOLLOW descriptor."""
    try:
        encoded_path = os.fsencode(path)
    except (TypeError, ValueError, UnicodeError):
        raise ValueError(f"{label} path or bound is invalid") from None
    if (
        not path.is_absolute()
        or path.anchor != "/"
        or any(component in {"", ".", ".."} for component in path.parts[1:])
        or len(path.parts) < 2
        or len(path.parts) - 1 > 64
        or len(encoded_path) > 4096
        or not 0 < max_bytes <= 64 * 1024 * 1024
    ):
        raise ValueError(f"{label} path or bound is invalid")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    directory_descriptor = -1
    descriptor = -1
    opened_descriptors: list[int] = []
    opened_directories: list[tuple[int, os.stat_result]] = []
    opened_edges: list[tuple[int, str, int, os.stat_result]] = []
    try:
        directory_descriptor = os.open("/", directory_flags)
        opened_descriptors.append(directory_descriptor)
        root_metadata = os.fstat(directory_descriptor)
        _validate_open_directory(root_metadata, label=label)
        opened_directories.append((directory_descriptor, root_metadata))
        for component in path.parts[1:-1]:
            parent_descriptor = directory_descriptor
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            opened_descriptors.append(next_descriptor)
            directory_metadata = os.fstat(next_descriptor)
            _validate_open_directory(directory_metadata, label=label)
            opened_directories.append((next_descriptor, directory_metadata))
            opened_edges.append(
                (
                    parent_descriptor,
                    component,
                    next_descriptor,
                    directory_metadata,
                )
            )
            directory_descriptor = next_descriptor
        descriptor = os.open(
            path.parts[-1],
            file_flags,
            dir_fd=directory_descriptor,
        )
        opened_descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or before.st_mode & 0o022
            or before.st_nlink != 1
            or not 0 < before.st_size <= max_bytes
        ):
            raise ValueError(f"{label} is not one trusted bounded regular file")
        opened_edges.append(
            (
                directory_descriptor,
                path.parts[-1],
                descriptor,
                before,
            )
        )
        captured = bytearray()
        captured_size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, max_bytes + 1 - captured_size),
            )
            if not chunk:
                break
            captured.extend(chunk)
            captured_size += len(chunk)
            if captured_size > max_bytes:
                raise ValueError(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        if captured_size != before.st_size or _metadata_identity(before) != _metadata_identity(
            after
        ):
            raise ValueError(f"{label} changed while it was captured")
        _revalidate_opened_path(
            opened_directories=opened_directories,
            opened_edges=opened_edges,
            label=label,
        )
        payload = bytes(captured)
    except OSError:
        raise ValueError(f"{label} is unavailable") from None
    finally:
        for opened_descriptor in reversed(opened_descriptors):
            try:
                os.close(opened_descriptor)
            except OSError:
                pass
    return CapturedRegularArtifact(payload=payload, metadata=after)


def read_regular_bounded(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Capture exact bytes while intentionally discarding stable metadata."""
    return capture_regular_bounded(
        path,
        max_bytes=max_bytes,
        label=label,
    ).payload


def _validate_open_directory(metadata: os.stat_result, *, label: str) -> None:
    writable = bool(metadata.st_mode & 0o022)
    trusted_sticky = bool(metadata.st_mode & stat.S_ISVTX)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or writable
        and not trusted_sticky
        or metadata.st_nlink < 1
    ):
        raise ValueError(f"{label} path contains an unsafe directory")


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_trust_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _revalidate_opened_path(
    *,
    opened_directories: list[tuple[int, os.stat_result]],
    opened_edges: list[tuple[int, str, int, os.stat_result]],
    label: str,
) -> None:
    try:
        for directory_descriptor, before in opened_directories:
            after = os.fstat(directory_descriptor)
            _validate_open_directory(after, label=label)
            if _directory_trust_identity(before) != _directory_trust_identity(after):
                raise ValueError(f"{label} changed while it was captured")
        for parent_descriptor, component, child_descriptor, before in opened_edges:
            opened_after = os.fstat(child_descriptor)
            relative_after = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISDIR(before.st_mode):
                _validate_open_directory(opened_after, label=label)
                _validate_open_directory(relative_after, label=label)
                before_identity = _directory_trust_identity(before)
                opened_identity = _directory_trust_identity(opened_after)
                relative_identity = _directory_trust_identity(relative_after)
            else:
                before_identity = _metadata_identity(before)
                opened_identity = _metadata_identity(opened_after)
                relative_identity = _metadata_identity(relative_after)
            if before_identity != opened_identity or opened_identity != relative_identity:
                raise ValueError(f"{label} changed while it was captured")
    except OSError:
        raise ValueError(f"{label} changed while it was captured") from None


def verify_ed25519_payload(
    *,
    payload: bytes,
    signature: bytes,
    trusted_public_key: bytes,
    label: str,
) -> str:
    """Verify exact in-memory bytes and return the canonical SPKI fingerprint."""
    if (
        not 1 <= len(payload) <= 64 * 1024 * 1024
        or len(signature) != 64
        or not 1 <= len(trusted_public_key) <= 64 * 1024
    ):
        raise ValueError(f"{label} signature input is invalid")
    fingerprint = ed25519_public_key_spki_sha256(trusted_public_key)
    with tempfile.TemporaryDirectory(prefix="kuzet-payload-verification-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        payload_path = root / "payload"
        signature_path = root / "signature"
        public_key_path = root / "authority.pem"
        _write_snapshot(payload_path, payload)
        _write_snapshot(signature_path, signature)
        _write_snapshot(public_key_path, trusted_public_key)
        result = subprocess.run(
            (
                trusted_openssl_executable(),
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-sigfile",
                str(signature_path),
                "-in",
                str(payload_path),
            ),
            check=False,
            capture_output=True,
            timeout=30,
        )
    if result.returncode:
        raise ValueError(f"{label} signature is invalid")
    return fingerprint


def _write_snapshot(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def trusted_openssl_executable() -> str:
    """Resolve only an administrator- or runner-owned non-writable OpenSSL 3 binary."""
    candidates = (
        Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
        Path("/usr/local/opt/openssl@3/bin/openssl"),
        Path("/usr/bin/openssl"),
    )
    for candidate in candidates:
        try:
            executable = candidate.resolve(strict=True)
            metadata = executable.stat()
        except OSError:
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid in {0, os.geteuid()}
            and not metadata.st_mode & 0o022
            and os.access(executable, os.X_OK)
        ):
            return str(executable)
    raise ValueError("trusted OpenSSL executable is unavailable")


def _ed25519_public_key_der(public_key_payload: bytes) -> bytes:
    if (
        not isinstance(public_key_payload, bytes)
        or not 1 <= len(public_key_payload) <= 64 * 1024
        or _PUBLIC_KEY_PEM.fullmatch(public_key_payload) is None
    ):
        raise ValueError("Ed25519 public key is unbounded")
    with tempfile.TemporaryDirectory(prefix="kuzet-spki-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        captured_key = root / "public.pem"
        _write_snapshot(captured_key, public_key_payload)
        result = subprocess.run(
            (
                trusted_openssl_executable(),
                "pkey",
                "-pubin",
                "-in",
                str(captured_key),
                "-outform",
                "DER",
            ),
            check=False,
            capture_output=True,
            timeout=10,
        )
    if result.returncode or not 1 <= len(result.stdout) <= 1024:
        raise ValueError("trust key must be a valid Ed25519 public key")
    # RFC 8410 Ed25519 SPKI is exactly a 12-byte header plus 32-byte key.
    if len(result.stdout) != 44 or not result.stdout.startswith(
        bytes.fromhex("302a300506032b6570032100")
    ):
        raise ValueError("trust key must be Ed25519")
    return result.stdout


def canonical_ed25519_public_key_pem(public_key_payload: bytes) -> bytes:
    """Validate and return one canonical Ed25519 PUBLIC KEY PEM block."""
    der = _ed25519_public_key_der(public_key_payload)
    encoded = base64.b64encode(der)
    body = b"\n".join(encoded[offset : offset + 64] for offset in range(0, len(encoded), 64))
    return b"-----BEGIN PUBLIC KEY-----\n" + body + b"\n-----END PUBLIC KEY-----\n"


def ed25519_public_key_spki_sha256(public_key_payload: bytes) -> str:
    """Return the canonical DER SubjectPublicKeyInfo fingerprint."""
    return hashlib.sha256(_ed25519_public_key_der(public_key_payload)).hexdigest()


def verify_detached_artifact(
    *,
    payload_path: Path,
    signature_path: Path,
    trusted_public_key_path: Path,
    expected_payload_sha256: str | None,
    max_payload_bytes: int,
    label: str,
) -> VerifiedDetachedArtifact:
    """Verify a detached signature over the exact bytes returned to the caller."""
    payload = read_regular_bounded(
        payload_path,
        max_bytes=max_payload_bytes,
        label=label,
    )
    signature = read_regular_bounded(
        signature_path,
        max_bytes=64 * 1024,
        label=f"{label} signature",
    )
    trust_key = canonical_ed25519_public_key_pem(
        read_regular_bounded(
            trusted_public_key_path,
            max_bytes=64 * 1024,
            label=f"{label} trust key",
        )
    )
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    if (
        len(signature) != 64
        or expected_payload_sha256 is not None
        and (
            len(expected_payload_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_payload_sha256)
            or payload_sha256 != expected_payload_sha256
        )
    ):
        raise ValueError(f"{label} digest does not match reviewed bytes")
    trust_key_spki_sha256 = verify_ed25519_payload(
        payload=payload,
        signature=signature,
        trusted_public_key=trust_key,
        label=label,
    )
    return VerifiedDetachedArtifact(
        payload=payload,
        signature=signature,
        trust_key=trust_key,
        payload_sha256=payload_sha256,
        signature_sha256=hashlib.sha256(signature).hexdigest(),
        trust_key_spki_sha256=trust_key_spki_sha256,
    )
