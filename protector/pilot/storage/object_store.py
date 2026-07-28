"""Atomic evidence publication to KZ S3-compatible or attested encrypted storage."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol
from urllib.parse import urlparse
from uuid import uuid4

from protector.pilot.config import SiteConfig
from protector.pilot.runtime.evidence import (
    ClipAssembler,
    CodecTool,
    EncodedFragmentRing,
    FfmpegCodecTool,
    FfprobeMediaProbe,
    MediaProbe,
)
from protector.pilot.storage.journal import (
    EvidenceJournalReplayWorker,
    SQLiteWALJournal,
    is_retryable_database_error,
)
from protector.pilot.storage.repositories import EvidenceInput, PilotRepository

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ObjectPublishError(RuntimeError):
    """An object was not durably promoted to its final key."""


class ObjectIntegrityError(ObjectPublishError):
    """Local or remote object bytes do not match the declared SHA-256."""


def validate_object_key(key: str) -> str:
    """Reject absolute, ambiguous, traversal, and reserved temporary keys."""
    if not key or len(key) > 1024 or "\\" in key or "\x00" in key:
        raise ValueError("unsafe object key")
    if key.startswith("/") or key.startswith(".incomplete/") or "//" in key:
        raise ValueError("unsafe object key")
    path = PurePosixPath(key)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("unsafe object key")
    canonical = path.as_posix()
    if canonical != key:
        raise ValueError("object key must be canonical POSIX syntax")
    return canonical


def _validate_digest(digest: str) -> str:
    if not _SHA256_PATTERN.fullmatch(digest):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
    return digest


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_attested_source(
    source: Path,
    *,
    expected_sha256: str,
    max_object_bytes: int,
) -> bytes:
    """Read, bound, and hash one no-follow descriptor so pathname swaps cannot alter bytes."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
        try:
            source_stat = os.fstat(descriptor)
            if not stat.S_ISREG(source_stat.st_mode):
                raise ObjectPublishError("evidence source must be a regular file")
            if source_stat.st_size <= 0:
                raise ObjectPublishError("evidence source must not be empty")
            if source_stat.st_size > max_object_bytes:
                raise ObjectPublishError("evidence source exceeds the configured maximum")
            payload = bytearray()
            digest = hashlib.sha256()
            while block := os.read(descriptor, min(1024 * 1024, max_object_bytes + 1)):
                payload.extend(block)
                digest.update(block)
                if len(payload) > max_object_bytes:
                    raise ObjectPublishError("evidence source exceeds the configured maximum")
            if digest.hexdigest() != expected_sha256:
                raise ObjectIntegrityError("local evidence SHA-256 does not match declaration")
            return bytes(payload)
        finally:
            os.close(descriptor)
    except ObjectPublishError:
        raise
    except OSError as exc:
        raise ObjectPublishError("evidence source could not be read safely") from exc


def _require_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("retention cutoff must be UTC-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class StoredObject:
    key: str
    sha256: str
    size_bytes: int
    path: Path | None = None


class EvidenceObjectStore(Protocol):
    def publish(self, source: Path, key: str, *, sha256: str) -> StoredObject: ...

    def delete(self, key: str) -> None: ...


@dataclass(frozen=True, slots=True)
class EncryptedVolumeAttestation:
    """Signed software gate bound to one verified encrypted mount."""

    volume_id: str
    mount_path: Path
    record_id: str
    verified_at: datetime
    verifier: str
    signature_sha256: str
    encryption: Literal["luks2", "fscrypt"]

    def __post_init__(self) -> None:
        if not all((self.volume_id, self.record_id, self.verifier)):
            raise ValueError("encrypted volume attestation identifiers must be non-empty")
        _require_aware_utc(self.verified_at)
        _validate_digest(self.signature_sha256)
        object.__setattr__(self, "mount_path", Path(self.mount_path).absolute())


class S3CompatibleObjectStore:
    """Immutable, checksummed Boto-compatible adapter scoped to one evidence prefix."""

    def __init__(
        self,
        *,
        client: Any,
        endpoint: str,
        bucket: str,
        country_code: str,
        evidence_prefix: str,
        max_object_bytes: int,
        server_side_encryption: Literal["AES256", "aws:kms"],
        kms_key_id: str | None = None,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("S3-compatible evidence endpoint must use HTTPS")
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("S3 endpoint must not contain credentials or ambiguous components")
        if country_code != "KZ":
            raise ValueError("S3-compatible evidence boundary must be in Kazakhstan")
        if not bucket or "/" in bucket:
            raise ValueError("S3 bucket name must be non-empty and unambiguous")
        if max_object_bytes <= 0:
            raise ValueError("max_object_bytes must be finite and positive")
        prefix = validate_object_key(evidence_prefix).rstrip("/")
        if prefix == ".incomplete" or prefix.startswith(".incomplete/"):
            raise ValueError("evidence prefix cannot use the incomplete namespace")
        if server_side_encryption == "aws:kms" and not kms_key_id:
            raise ValueError("aws:kms evidence encryption requires kms_key_id")
        if server_side_encryption == "AES256" and kms_key_id is not None:
            raise ValueError("kms_key_id is only valid with aws:kms")
        self._client = client
        port = f":{parsed.port}" if parsed.port is not None else ""
        self.endpoint = f"https://{parsed.hostname}{port}"
        self.bucket = bucket
        self.country_code = country_code
        self.evidence_prefix = prefix
        self.max_object_bytes = max_object_bytes
        self.server_side_encryption = server_side_encryption
        self.kms_key_id = kms_key_id

    def publish(self, source: Path, key: str, *, sha256: str) -> StoredObject:
        key = validate_object_key(key)
        sha256 = _validate_digest(sha256)
        payload = _read_attested_source(
            Path(source),
            expected_sha256=sha256,
            max_object_bytes=self.max_object_bytes,
        )
        size = len(payload)
        remote_key = self._remote_key(key)
        existing = self._head(remote_key)
        if existing is not None:
            return self._validated_object(key, sha256, size, existing)

        checksum = base64.b64encode(bytes.fromhex(sha256)).decode()
        arguments: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": remote_key,
            "Body": payload,
            "IfNoneMatch": "*",
            "ChecksumAlgorithm": "SHA256",
            "ChecksumSHA256": checksum,
            "ServerSideEncryption": self.server_side_encryption,
        }
        if self.kms_key_id is not None:
            arguments["SSEKMSKeyId"] = self.kms_key_id
        try:
            self._client.put_object(**arguments)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if not self._is_precondition_failed(exc):
                raise ObjectPublishError("immutable S3 evidence publish failed") from exc
        final = self._head(remote_key)
        if final is None:
            raise ObjectPublishError("final object was not durable after conditional create")
        return self._validated_object(key, sha256, size, final)

    def delete(self, key: str) -> None:
        try:
            self._client.delete_object(
                Bucket=self.bucket,
                Key=self._remote_key(validate_object_key(key)),
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ObjectPublishError("S3 evidence delete failed") from exc

    def delete_older_than(self, cutoff: datetime) -> tuple[str, ...]:
        cutoff = _require_aware_utc(cutoff)
        deleted: list[str] = []
        continuation: str | None = None
        while True:
            arguments: dict[str, Any] = {
                "Bucket": self.bucket,
                "Prefix": f"{self.evidence_prefix}/",
            }
            if continuation is not None:
                arguments["ContinuationToken"] = continuation
            try:
                response = self._client.list_objects_v2(**arguments)
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise ObjectPublishError("S3 evidence retention listing failed") from exc
            for item in response.get("Contents", ()):
                remote_key = str(item["Key"])
                prefix = f"{self.evidence_prefix}/"
                if not remote_key.startswith(prefix):
                    continue
                key = remote_key.removeprefix(prefix)
                modified = item["LastModified"]
                if key.startswith(".incomplete/"):
                    if _require_aware_utc(modified) < cutoff:
                        self._delete_remote(remote_key)
                        deleted.append(key)
                    continue
                try:
                    safe_key = validate_object_key(key)
                except ValueError:
                    continue
                if _require_aware_utc(modified) < cutoff:
                    self.delete(safe_key)
                    deleted.append(safe_key)
            if not response.get("IsTruncated"):
                break
            continuation = response.get("NextContinuationToken")
            if not continuation:
                raise ObjectPublishError("truncated S3 listing omitted continuation token")
        return tuple(sorted(deleted))

    def _head(self, key: str) -> dict[str, Any] | None:
        try:
            return self._client.head_object(
                Bucket=self.bucket,
                Key=key,
                ChecksumMode="ENABLED",
            )
        except BaseException as exc:
            if isinstance(exc, KeyError) or self._is_not_found(exc):
                return None
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ObjectPublishError("S3 object metadata lookup failed") from exc

    @staticmethod
    def _is_not_found(exc: BaseException) -> bool:
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            return False
        error = response.get("Error", {})
        code = str(error.get("Code", ""))
        return code in {"404", "NoSuchKey", "NotFound"}

    @staticmethod
    def _is_precondition_failed(exc: BaseException) -> bool:
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            return False
        error = response.get("Error", {})
        return str(error.get("Code", "")) in {"409", "412", "PreconditionFailed"}

    def _validated_object(
        self,
        key: str,
        sha256: str,
        size: int,
        head: dict[str, Any],
    ) -> StoredObject:
        expected_checksum = base64.b64encode(bytes.fromhex(sha256)).decode()
        if (
            int(head.get("ContentLength", -1)) != size
            or head.get("ChecksumSHA256") != expected_checksum
        ):
            raise ObjectIntegrityError("remote service checksum or size does not match")
        if head.get("ServerSideEncryption") != self.server_side_encryption:
            raise ObjectIntegrityError("remote evidence encryption does not match policy")
        if self.kms_key_id is not None and head.get("SSEKMSKeyId") != self.kms_key_id:
            raise ObjectIntegrityError("remote evidence KMS key does not match policy")
        return StoredObject(key=key, sha256=sha256, size_bytes=size)

    def _remote_key(self, key: str) -> str:
        return f"{self.evidence_prefix}/{key}"

    def _delete_remote(self, remote_key: str) -> None:
        try:
            self._client.delete_object(Bucket=self.bucket, Key=remote_key)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ObjectPublishError("S3 evidence retention delete failed") from exc


class EncryptedLocalObjectStore:
    """Immutable local adapter gated by a signed attestation bound to one mount."""

    def __init__(
        self,
        root: str | Path,
        *,
        encrypted_volume_attestation: EncryptedVolumeAttestation,
        attestation_verifier: Callable[[EncryptedVolumeAttestation], bool],
        attestation_max_age: timedelta,
        evidence_prefix: str,
        max_object_bytes: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(encrypted_volume_attestation, EncryptedVolumeAttestation):
            raise TypeError("encrypted local evidence volume requires a structured attestation")
        if max_object_bytes <= 0:
            raise ValueError("max_object_bytes must be finite and positive")
        if attestation_max_age <= timedelta(0):
            raise ValueError("attestation_max_age must be finite and positive")
        if not attestation_verifier(encrypted_volume_attestation):
            raise ValueError("encrypted volume attestation signature is not trusted")
        now = _require_aware_utc((clock or (lambda: datetime.now(UTC)))())
        verified_at = _require_aware_utc(encrypted_volume_attestation.verified_at)
        if verified_at > now or now - verified_at > attestation_max_age:
            raise ValueError("encrypted volume attestation is stale")
        prefix = validate_object_key(evidence_prefix).rstrip("/")
        if prefix == ".incomplete" or prefix.startswith(".incomplete/"):
            raise ValueError("evidence prefix cannot use the incomplete namespace")
        self.encrypted_volume_attestation = encrypted_volume_attestation
        candidate = Path(root).absolute()
        if candidate.exists() and candidate.is_symlink():
            raise ValueError("encrypted evidence root must not be a symlink")
        candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = candidate.resolve(strict=True)
        attested_mount = encrypted_volume_attestation.mount_path.resolve(strict=True)
        if self.root != attested_mount:
            raise ValueError("encrypted volume attestation does not match the mounted root")
        root_stat = self.root.stat()
        if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o022:
            raise ValueError("encrypted evidence root ownership or permissions are unsafe")
        self.evidence_prefix = prefix
        self.max_object_bytes = max_object_bytes
        prefix_root = self.root / self.evidence_prefix
        prefix_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._prefix_root = prefix_root.resolve(strict=True)
        if not self._prefix_root.is_relative_to(self.root):
            raise ValueError("evidence prefix escaped the encrypted volume")
        incomplete = self._prefix_root / ".incomplete"
        if incomplete.is_symlink():
            raise ValueError("incomplete namespace must not be a symlink")
        if incomplete.exists():
            shutil.rmtree(incomplete)
        incomplete.mkdir(mode=0o700)
        self._incomplete_root = incomplete

    def publish(self, source: Path, key: str, *, sha256: str) -> StoredObject:
        key = validate_object_key(key)
        sha256 = _validate_digest(sha256)
        payload = _read_attested_source(
            Path(source),
            expected_sha256=sha256,
            max_object_bytes=self.max_object_bytes,
        )
        size = len(payload)
        destination = self._prefix_root / key
        parent_descriptor = -1
        incomplete_descriptor = -1
        temporary_name = f"{hashlib.sha256(key.encode()).hexdigest()}.{sha256}.part"
        try:
            parent_descriptor, final_name = self._open_parent(key, create=True)
            existing = self._read_existing(
                parent_descriptor,
                final_name,
                max_bytes=self.max_object_bytes,
            )
            if existing is not None:
                if len(existing) != size or hashlib.sha256(existing).hexdigest() != sha256:
                    raise ObjectIntegrityError(
                        "existing local evidence object has different bytes"
                    )
                return StoredObject(
                    key=key,
                    sha256=sha256,
                    size_bytes=size,
                    path=destination,
                )
            incomplete_descriptor = self._open_directory(self._incomplete_root)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=incomplete_descriptor,
            )
            with os.fdopen(descriptor, "wb") as output_file:
                output_file.write(payload)
                output_file.flush()
                os.fsync(output_file.fileno())
            try:
                os.link(
                    temporary_name,
                    final_name,
                    src_dir_fd=incomplete_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                existing = self._read_existing(
                    parent_descriptor,
                    final_name,
                    max_bytes=self.max_object_bytes,
                )
                if (
                    existing is None
                    or len(existing) != size
                    or hashlib.sha256(existing).hexdigest() != sha256
                ):
                    raise ObjectIntegrityError(
                        "concurrent local evidence object has different bytes"
                    )
            os.unlink(temporary_name, dir_fd=incomplete_descriptor)
            os.fsync(incomplete_descriptor)
            os.fsync(parent_descriptor)
        except ObjectPublishError:
            self._unlink_quietly(temporary_name, dir_fd=incomplete_descriptor)
            raise
        except (OSError, ValueError) as exc:
            self._unlink_quietly(temporary_name, dir_fd=incomplete_descriptor)
            raise ObjectPublishError("atomic local evidence publish failed") from exc
        finally:
            if incomplete_descriptor >= 0:
                os.close(incomplete_descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)
        return StoredObject(key=key, sha256=sha256, size_bytes=size, path=destination)

    def delete(self, key: str) -> None:
        key = validate_object_key(key)
        parent_descriptor = -1
        try:
            parent_descriptor, final_name = self._open_parent(key, create=False)
            try:
                os.unlink(final_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            os.fsync(parent_descriptor)
        except ObjectPublishError:
            raise
        except OSError as exc:
            raise ObjectPublishError("local evidence delete failed") from exc
        finally:
            if parent_descriptor >= 0:
                os.close(parent_descriptor)

    def delete_older_than(self, cutoff: datetime) -> tuple[str, ...]:
        cutoff = _require_aware_utc(cutoff)
        deleted: list[str] = []
        for path in sorted(self._prefix_root.rglob("*")):
            if path.is_relative_to(self._incomplete_root):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(self._prefix_root):
                continue
            modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
            if modified < cutoff:
                key = path.relative_to(self._prefix_root).as_posix()
                self.delete(key)
                deleted.append(key)
        return tuple(sorted(deleted))

    def _open_parent(self, key: str, *, create: bool) -> tuple[int, str]:
        descriptor = self._open_directory(self._prefix_root)
        try:
            parts = PurePosixPath(key).parts
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                        os.fsync(descriptor)
                    except FileExistsError:
                        pass
                child = os.open(
                    part,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            return descriptor, parts[-1]
        except OSError as exc:
            os.close(descriptor)
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise ValueError("evidence destination must not traverse a symlink") from exc
            raise

    @staticmethod
    def _open_directory(path: Path) -> int:
        return os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )

    @staticmethod
    def _read_existing(
        parent_descriptor: int,
        name: str,
        *,
        max_bytes: int,
    ) -> bytes | None:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            return None
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ValueError("evidence destination must be a regular file")
            if file_stat.st_size > max_bytes:
                raise ObjectIntegrityError("existing local evidence object exceeds maximum")
            payload = bytearray()
            while block := os.read(descriptor, 1024 * 1024):
                payload.extend(block)
                if len(payload) > max_bytes:
                    raise ObjectIntegrityError("existing local evidence object exceeds maximum")
            return bytes(payload)
        finally:
            os.close(descriptor)

    @staticmethod
    def _unlink_quietly(name: str, *, dir_fd: int) -> None:
        if dir_fd < 0:
            return
        try:
            os.unlink(name, dir_fd=dir_fd)
        except FileNotFoundError:
            return


class EvidencePublisher:
    """Upload first, then atomically align evidence and candidate database state."""

    def __init__(
        self,
        *,
        store: EvidenceObjectStore,
        repository: PilotRepository,
        journal: SQLiteWALJournal | None = None,
    ) -> None:
        self._store = store
        self._repository = repository
        self._journal = journal

    def publish(self, source: Path, evidence: EvidenceInput) -> EvidenceInput:
        if evidence.status not in ("pending", "failed"):
            raise ValueError("evidence publication must begin from pending or failed")
        try:
            stored = self._store.publish(source, evidence.object_key, sha256=evidence.sha256)
        except ObjectPublishError:
            self.mark_failed(evidence)
            raise
        if stored.sha256 != evidence.sha256 or stored.key != evidence.object_key:
            self.mark_failed(evidence)
            raise ObjectIntegrityError("object store returned a different evidence identity")
        ready = replace(evidence, status="ready")
        self._finalize_or_journal(ready, status="ready")
        return ready

    def mark_failed(self, evidence: EvidenceInput) -> EvidenceInput:
        failed = replace(evidence, status="failed")
        self._finalize_or_journal(failed, status="failed")
        return failed

    def _finalize_or_journal(
        self,
        evidence: EvidenceInput,
        *,
        status: Literal["ready", "failed"],
    ) -> None:
        try:
            self._repository.finalize_evidence(evidence, status=status)
        except Exception as exc:
            if self._journal is None or not is_retryable_database_error(exc):
                raise
            payload = {
                "schema_version": "evidence-work.v1",
                "evidence_id": str(evidence.evidence_id),
                "event_id": str(evidence.event_id),
                "object_key": evidence.object_key,
                "sha256": evidence.sha256,
                "codec": evidence.codec,
                "start_at": evidence.start_at.isoformat(),
                "end_at": evidence.end_at.isoformat(),
                "source_reference": evidence.source_reference,
                "status": status,
            }
            self._journal.enqueue(
                kind="evidence",
                schema_version="evidence-work.v1",
                idempotency_key=f"evidence-finalize:{evidence.evidence_id}:{status}",
                payload=payload,
            )


class PreviewWorkspaceCapacityError(RuntimeError):
    """The finite preview workspace cannot accept another temporary clip."""


class PreviewWorkspace:
    """Owned finite workspace for preview/final temporary media only."""

    _MARKER = ".kuzet-evidence-preview-workspace.v1"
    _MARKER_PAYLOAD = b"kuzet-evidence-preview-workspace.v1\n"
    _MAX_METADATA_BYTES = 8_192
    _MEDIA_PATTERN = re.compile(r"^(?P<key>[0-9a-f]{64})\.(preview|final)\.mp4$")
    _METADATA_PATTERN = re.compile(r"^(?P<key>[0-9a-f]{64})\.json$")
    _TEMP_PATTERN = re.compile(r"^\.kuzet-preview-[0-9a-f]{32}\.tmp$")

    def __init__(
        self,
        root: str | Path,
        *,
        ttl: timedelta,
        max_items: int,
        max_bytes: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if ttl <= timedelta(0):
            raise ValueError("preview workspace TTL must be positive")
        if max_items < 1 or max_bytes < 1:
            raise ValueError("preview workspace bounds must be positive")
        self.root = Path(root).absolute()
        if self.root == Path(self.root.anchor):
            raise ValueError("preview workspace must be a dedicated directory")
        if self.root.exists() and self.root.is_symlink():
            raise ValueError("preview workspace must not be a symlink")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root_stat = self.root.stat(follow_symlinks=False)
        if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o022:
            raise ValueError("preview workspace ownership or permissions are unsafe")
        marker = self.root / self._MARKER
        existing = tuple(self.root.iterdir())
        if not marker.exists() and existing:
            raise ValueError("preview workspace is not an owned empty namespace")
        if marker.is_symlink():
            raise ValueError("preview workspace marker must not be a symlink")
        if not marker.exists():
            self._atomic_write(marker, self._MARKER_PAYLOAD)
        if self._read_private_file(
            marker,
            max_bytes=len(self._MARKER_PAYLOAD),
        ) != self._MARKER_PAYLOAD:
            raise ValueError("preview workspace marker content is invalid")
        self.ttl = ttl
        self.max_items = max_items
        self.max_bytes = max_bytes
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._assert_owned_namespace()

    @property
    def item_count(self) -> int:
        return len(self._records())

    @property
    def used_bytes(self) -> int:
        self._assert_owned_namespace()
        total = 0
        for path in self.root.iterdir():
            if self._MEDIA_PATTERN.fullmatch(path.name) or self._TEMP_PATTERN.fullmatch(
                path.name
            ):
                try:
                    file_stat = path.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(file_stat.st_mode):
                    total += file_stat.st_size
        return total

    def path_for(self, reservation_id: str, *, kind: Literal["preview", "final"]) -> Path:
        key = self._key(reservation_id)
        return self.root / f"{key}.{kind}.mp4"

    def prepare(
        self,
        reservation_id: str,
        *,
        kind: Literal["preview", "final"],
        evidence: EvidenceInput | None = None,
    ) -> Path:
        with self._lock:
            key = self._key(reservation_id)
            records = self._records()
            current = records.get(key)
            if current is None and len(records) >= self.max_items:
                raise PreviewWorkspaceCapacityError(
                    "preview workspace item bound reached"
                )
            if self.used_bytes >= self.max_bytes:
                raise PreviewWorkspaceCapacityError(
                    "preview workspace byte bound reached"
                )
            self._write_record(
                key=key,
                reservation_id=reservation_id,
                created_at=(
                    self._now()
                    if current is None
                    else datetime.fromisoformat(str(current["created_at"]))
                ),
                paths=[] if current is None else current["paths"],
                evidence=(
                    evidence
                    if evidence is not None
                    else None if current is None else current["evidence"]
                ),
            )
            return self.path_for(reservation_id, kind=kind)

    def register(
        self,
        reservation_id: str,
        *,
        kind: Literal["preview", "final"],
        path: Path,
        evidence: EvidenceInput | None = None,
    ) -> None:
        expected = self.path_for(reservation_id, kind=kind)
        if Path(path).absolute() != expected:
            raise ValueError("temporary evidence path escaped the preview workspace")
        file_stat = expected.stat(follow_symlinks=False)
        if not stat.S_ISREG(file_stat.st_mode) or expected.is_symlink():
            raise ValueError("temporary evidence must be a regular owned file")
        with self._lock:
            key = self._key(reservation_id)
            records = self._records()
            current = records.get(key)
            created_at = (
                self._now()
                if current is None
                else datetime.fromisoformat(str(current["created_at"]))
            )
            paths = set(() if current is None else current["paths"])
            paths.add(expected.name)
            self._write_record(
                key=key,
                reservation_id=reservation_id,
                created_at=created_at,
                paths=sorted(paths),
                evidence=(
                    evidence
                    if evidence is not None
                    else None if current is None else current["evidence"]
                ),
            )
            if self.item_count > self.max_items or self.used_bytes > self.max_bytes:
                cleanup_errors = self.cleanup(reservation_id)
                if cleanup_errors:
                    raise ExceptionGroup(
                        "preview workspace capacity cleanup failed",
                        [
                            PreviewWorkspaceCapacityError(
                                "preview workspace bound reached"
                            ),
                            *cleanup_errors,
                        ],
                    )
                raise PreviewWorkspaceCapacityError(
                    "preview workspace bound reached"
                )

    def abandoned_records(
        self,
    ) -> tuple[tuple[str, EvidenceInput | None], ...]:
        return tuple(
            sorted(
                [
                    (
                        str(record["reservation_id"]),
                        record["evidence"],
                    )
                    for record in self._records().values()
                ],
                key=lambda item: item[0],
            )
        )

    def expired_reservation_ids(self) -> tuple[str, ...]:
        now = self._now()
        return tuple(
            sorted(
                str(record["reservation_id"])
                for record in self._records().values()
                if now - datetime.fromisoformat(str(record["created_at"])) >= self.ttl
            )
        )

    def cleanup(self, reservation_id: str) -> list[Exception]:
        key = self._key(reservation_id)
        errors: list[Exception] = []
        for path in (
            self.root / f"{key}.preview.mp4",
            self.root / f"{key}.final.mp4",
            self.root / f"{key}.json",
        ):
            try:
                path.unlink(missing_ok=True)
            except Exception as exc:
                errors.append(exc)
        try:
            self._fsync_root()
        except Exception as exc:
            errors.append(exc)
        return errors

    def cleanup_orphans(self) -> list[Exception]:
        errors: list[Exception] = []
        known_keys = set(self._records())
        for path in self.root.iterdir():
            media_match = self._MEDIA_PATTERN.fullmatch(path.name)
            metadata_match = self._METADATA_PATTERN.fullmatch(path.name)
            is_orphan = (
                self._TEMP_PATTERN.fullmatch(path.name) is not None
                or (media_match is not None and media_match.group("key") not in known_keys)
                or (metadata_match is not None and metadata_match.group("key") not in known_keys)
            )
            if not is_orphan:
                continue
            try:
                path.unlink(missing_ok=True)
            except Exception as exc:
                errors.append(exc)
        try:
            self._fsync_root()
        except Exception as exc:
            errors.append(exc)
        return errors

    def _records(self) -> dict[str, dict[str, Any]]:
        self._assert_owned_namespace()
        records: dict[str, dict[str, Any]] = {}
        for path in self.root.iterdir():
            match = self._METADATA_PATTERN.fullmatch(path.name)
            if match is None or path.is_symlink():
                continue
            try:
                raw = json.loads(
                    self._read_private_file(
                        path,
                        max_bytes=self._MAX_METADATA_BYTES,
                    )
                )
                reservation_id = str(raw["reservation_id"])
                if self._key(reservation_id) != match.group("key"):
                    continue
                created_at = datetime.fromisoformat(str(raw["created_at"]))
                if created_at.tzinfo is None or created_at.utcoffset() is None:
                    continue
                paths = raw["paths"]
                if not isinstance(paths, list) or not all(
                    isinstance(item, str)
                    and self._MEDIA_PATTERN.fullmatch(item)
                    and item.startswith(match.group("key"))
                    for item in paths
                ):
                    continue
                evidence_payload = raw.get("evidence")
                evidence = (
                    None
                    if evidence_payload is None
                    else EvidenceInput.from_payload(evidence_payload)
                )
            except (OSError, TypeError, ValueError, KeyError) as exc:
                raise PreviewWorkspaceCapacityError(
                    "preview workspace contains invalid bounded metadata"
                ) from exc
            records[match.group("key")] = {
                "reservation_id": reservation_id,
                "created_at": created_at.astimezone(UTC).isoformat(),
                "paths": paths,
                "evidence": evidence,
            }
        return records

    def _assert_owned_namespace(self) -> None:
        for path in self.root.iterdir():
            if path.name == self._MARKER:
                continue
            if not (
                self._MEDIA_PATTERN.fullmatch(path.name)
                or self._METADATA_PATTERN.fullmatch(path.name)
                or self._TEMP_PATTERN.fullmatch(path.name)
            ):
                raise PreviewWorkspaceCapacityError(
                    "preview workspace contains an unexpected entry"
                )
            file_stat = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(file_stat.st_mode) or path.is_symlink():
                raise PreviewWorkspaceCapacityError(
                    "preview workspace entry is not a regular owned file"
                )

    def _write_record(
        self,
        *,
        key: str,
        reservation_id: str,
        created_at: datetime,
        paths: list[str],
        evidence: EvidenceInput | None,
    ) -> None:
        payload = {
            "reservation_id": reservation_id,
            "created_at": created_at.isoformat(),
            "paths": paths,
            "evidence": (
                None
                if evidence is None
                else {
                    "evidence_id": str(evidence.evidence_id),
                    "event_id": str(evidence.event_id),
                    "object_key": evidence.object_key,
                    "sha256": evidence.sha256,
                    "codec": evidence.codec,
                    "start_at": evidence.start_at.isoformat(),
                    "end_at": evidence.end_at.isoformat(),
                    "source_reference": evidence.source_reference,
                    "status": evidence.status,
                }
            ),
        }
        encoded_payload = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if len(encoded_payload) > self._MAX_METADATA_BYTES:
            raise ValueError("preview workspace metadata exceeds finite bound")
        self._atomic_write(self.root / f"{key}.json", encoded_payload)

    @staticmethod
    def _read_private_file(path: Path, *, max_bytes: int) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > max_bytes:
                raise ValueError("preview workspace metadata is not a finite regular file")
            payload = bytearray()
            while block := os.read(descriptor, min(4_096, max_bytes + 1 - len(payload))):
                payload.extend(block)
                if len(payload) > max_bytes:
                    raise ValueError("preview workspace metadata exceeds finite bound")
            return bytes(payload)
        finally:
            os.close(descriptor)

    @staticmethod
    def _key(reservation_id: str) -> str:
        if not reservation_id or len(reservation_id) > 128:
            raise ValueError("reservation_id must be non-empty and bounded")
        return hashlib.sha256(reservation_id.encode()).hexdigest()

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("preview workspace clock must be timezone-aware")
        return value.astimezone(UTC)

    def _atomic_write(self, destination: Path, payload: bytes) -> None:
        temporary = self.root / f".kuzet-preview-{uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
            self._fsync_root()
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def _fsync_root(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class EvidenceCoordinator:
    """Own the complete evidence lifecycle, including pins and temporary media."""

    def __init__(
        self,
        *,
        ring: Any,
        assembler: Any,
        publisher: EvidencePublisher,
        preview_workspace: PreviewWorkspace,
    ) -> None:
        self._ring = ring
        self._assembler = assembler
        self._publisher = publisher
        self.preview_workspace = preview_workspace
        startup_errors: list[Exception] = []
        for reservation_id, evidence in preview_workspace.abandoned_records():
            if evidence is not None:
                try:
                    self._publisher.mark_failed(evidence)
                except Exception as exc:
                    startup_errors.append(exc)
            startup_errors.extend(self._release_and_cleanup(reservation_id))
        startup_errors.extend(preview_workspace.cleanup_orphans())
        if startup_errors:
            raise ExceptionGroup(
                "abandoned preview workspace recovery failed",
                startup_errors,
            )

    def create_preview(
        self,
        reservation: Any,
        *,
        evidence: EvidenceInput | None = None,
    ) -> Any:
        try:
            output_path = self.preview_workspace.prepare(
                reservation.reservation_id,
                kind="preview",
                evidence=evidence,
            )
            preview = self._assembler.assemble_preview(reservation, output_path)
            self.preview_workspace.register(
                reservation.reservation_id,
                kind="preview",
                path=preview.path,
                evidence=evidence,
            )
            return preview
        except Exception as primary:
            cleanup_errors: list[Exception] = []
            if evidence is not None:
                try:
                    self._publisher.mark_failed(evidence)
                except Exception as exc:
                    cleanup_errors.append(exc)
            cleanup_errors.extend(
                self._release_and_cleanup(reservation.reservation_id)
            )
            self._raise_lifecycle_failure(primary, cleanup_errors)

    def complete(
        self,
        reservation: Any,
        evidence: EvidenceInput,
    ) -> EvidenceInput:
        primary: Exception | None = None
        result: EvidenceInput | None = None
        phase: Literal["assemble", "publish"] = "assemble"
        try:
            output_path = self.preview_workspace.prepare(
                reservation.reservation_id,
                kind="final",
                evidence=evidence,
            )
            assembled = self._assembler.assemble(reservation, output_path)
            self.preview_workspace.register(
                reservation.reservation_id,
                kind="final",
                path=assembled.path,
                evidence=evidence,
            )
            bounded = replace(
                evidence,
                sha256=assembled.sha256,
                codec="h264",
                start_at=assembled.start_at,
                end_at=assembled.end_at,
                status="pending",
            )
            phase = "publish"
            result = self._publisher.publish(assembled.path, bounded)
        except Exception as exc:
            primary = exc
        cleanup_errors: list[Exception] = []
        if primary is not None and phase == "assemble":
            try:
                self._publisher.mark_failed(evidence)
            except Exception as exc:
                cleanup_errors.append(exc)
        cleanup_errors.extend(self._release_and_cleanup(reservation.reservation_id))
        if primary is not None:
            self._raise_lifecycle_failure(primary, cleanup_errors)
        if cleanup_errors:
            raise ExceptionGroup("evidence lifecycle cleanup failed", cleanup_errors)
        assert result is not None
        return result

    def retry(
        self,
        reservation: Any,
        evidence: EvidenceInput,
    ) -> EvidenceInput:
        """Retry with a newly acquired reservation; consumed pins are never reused."""
        return self.complete(reservation, evidence)

    def cancel(
        self,
        reservation_id: str,
        *,
        evidence: EvidenceInput | None = None,
    ) -> None:
        errors: list[Exception] = []
        if evidence is not None:
            try:
                self._publisher.mark_failed(evidence)
            except Exception as exc:
                errors.append(exc)
        errors.extend(self._release_and_cleanup(reservation_id))
        if errors:
            raise ExceptionGroup("evidence cancellation failed", errors)

    def sweep_expired(self) -> tuple[str, ...]:
        expired = self.preview_workspace.expired_reservation_ids()
        errors: list[Exception] = []
        for reservation_id in expired:
            try:
                self.cancel(reservation_id)
            except ExceptionGroup as exc:
                errors.extend(
                    error
                    for error in exc.exceptions
                    if isinstance(error, Exception)
                )
        if errors:
            raise ExceptionGroup("expired preview cleanup failed", errors)
        return expired

    def _release_and_cleanup(self, reservation_id: str) -> list[Exception]:
        errors: list[Exception] = []
        try:
            self._ring.release(reservation_id)
        except Exception as exc:
            errors.append(exc)
        errors.extend(self.preview_workspace.cleanup(reservation_id))
        return errors

    @staticmethod
    def _raise_lifecycle_failure(
        primary: Exception,
        cleanup_errors: list[Exception],
    ) -> None:
        if cleanup_errors:
            raise ExceptionGroup(
                "evidence lifecycle failed",
                [primary, *cleanup_errors],
            )
        raise primary


@dataclass(frozen=True, slots=True)
class EvidenceDeliveryServices:
    """Production dependencies handed to the Task 8 candidate trigger."""

    store: S3CompatibleObjectStore
    publisher: EvidencePublisher
    assembler: ClipAssembler
    coordinator: EvidenceCoordinator
    replay_worker: EvidenceJournalReplayWorker
    preview_workspace: PreviewWorkspace


def build_s3_evidence_delivery(
    *,
    site: SiteConfig,
    client: Any,
    repository: PilotRepository,
    journal: SQLiteWALJournal,
    ring: EncodedFragmentRing,
    max_nvenc_jobs: int,
    codec_tool: CodecTool | None = None,
    media_probe: MediaProbe | None = None,
    journal_replay_batch_size: int = 32,
    journal_retry_backoff_seconds: float = 5.0,
    preview_workspace_root: str | Path | None = None,
    preview_ttl: timedelta = timedelta(minutes=5),
    preview_max_items: int = 64,
    preview_max_bytes: int | None = None,
) -> EvidenceDeliveryServices:
    """Construct the configured non-secret evidence policy around injected credentials."""
    storage = site.storage
    store = S3CompatibleObjectStore(
        client=client,
        endpoint=str(storage.endpoint),
        bucket=storage.bucket,
        country_code=storage.country_code,
        evidence_prefix=storage.evidence_prefix,
        max_object_bytes=storage.max_evidence_object_bytes,
        server_side_encryption=storage.server_side_encryption,
        kms_key_id=storage.kms_key_id,
    )
    publisher = EvidencePublisher(
        store=store,
        repository=repository,
        journal=journal,
    )
    assembler = ClipAssembler(
        codec_tool or FfmpegCodecTool(),
        media_probe or FfprobeMediaProbe(),
        max_nvenc_jobs=max_nvenc_jobs,
    )
    preview_workspace = PreviewWorkspace(
        (
            Path(preview_workspace_root)
            if preview_workspace_root is not None
            else ring.root.parent / f"{ring.root.name}-previews"
        ),
        ttl=preview_ttl,
        max_items=preview_max_items,
        max_bytes=(
            storage.max_evidence_object_bytes * 2
            if preview_max_bytes is None
            else preview_max_bytes
        ),
    )
    coordinator = EvidenceCoordinator(
        ring=ring,
        assembler=assembler,
        publisher=publisher,
        preview_workspace=preview_workspace,
    )
    replay_worker = EvidenceJournalReplayWorker(
        journal=journal,
        processor=repository.persist_journal_item,
        batch_size=journal_replay_batch_size,
        retry_backoff_seconds=journal_retry_backoff_seconds,
    )
    replay_worker.startup_drain()
    return EvidenceDeliveryServices(
        store=store,
        publisher=publisher,
        assembler=assembler,
        coordinator=coordinator,
        replay_worker=replay_worker,
        preview_workspace=preview_workspace,
    )
