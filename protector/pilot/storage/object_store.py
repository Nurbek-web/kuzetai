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
from typing import Any, Literal, Protocol, runtime_checkable
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


class EvidencePublicationFailure(ExceptionGroup):
    """Object publication failed and the durable failed transition also failed."""


class EvidenceReadyTransitionFailure(RuntimeError):
    """Object exists but the ready transition was not committed or journaled."""

    def __init__(self, stored: StoredObject, cause: Exception) -> None:
        super().__init__("evidence object is durable but ready transition failed")
        self.stored = stored
        self.transition_durable = False
        self.cause = cause


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


@runtime_checkable
class DescriptorEvidenceSource(Protocol):
    def duplicate_descriptor(self) -> int: ...


EvidenceSource = Path | DescriptorEvidenceSource


def _read_attested_source(
    source: EvidenceSource,
    *,
    expected_sha256: str,
    max_object_bytes: int,
) -> bytes:
    """Read, bound, and hash one no-follow descriptor so pathname swaps cannot alter bytes."""
    try:
        if isinstance(source, DescriptorEvidenceSource):
            descriptor = source.duplicate_descriptor()
        else:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
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
    def publish(
        self,
        source: EvidenceSource,
        key: str,
        *,
        sha256: str,
    ) -> StoredObject: ...

    def verify(
        self,
        key: str,
        *,
        sha256: str,
        size_bytes: int,
    ) -> StoredObject | None: ...

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

    def publish(
        self,
        source: EvidenceSource,
        key: str,
        *,
        sha256: str,
    ) -> StoredObject:
        key = validate_object_key(key)
        sha256 = _validate_digest(sha256)
        payload = _read_attested_source(
            source,
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

    def verify(
        self,
        key: str,
        *,
        sha256: str,
        size_bytes: int,
    ) -> StoredObject | None:
        key = validate_object_key(key)
        sha256 = _validate_digest(sha256)
        if size_bytes <= 0 or size_bytes > self.max_object_bytes:
            raise ObjectIntegrityError(
                "remote evidence size is outside the configured bound"
            )
        head = self._head(self._remote_key(key))
        if head is None:
            return None
        return self._validated_object(key, sha256, size_bytes, head)

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

    def publish(
        self,
        source: EvidenceSource,
        key: str,
        *,
        sha256: str,
    ) -> StoredObject:
        key = validate_object_key(key)
        sha256 = _validate_digest(sha256)
        payload = _read_attested_source(
            source,
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

    def verify(
        self,
        key: str,
        *,
        sha256: str,
        size_bytes: int,
    ) -> StoredObject | None:
        key = validate_object_key(key)
        sha256 = _validate_digest(sha256)
        if size_bytes <= 0 or size_bytes > self.max_object_bytes:
            raise ObjectIntegrityError(
                "local evidence size is outside the configured bound"
            )
        parent_descriptor = -1
        try:
            parent_descriptor, final_name = self._open_parent(key, create=False)
            payload = self._read_existing(
                parent_descriptor,
                final_name,
                max_bytes=self.max_object_bytes,
            )
        except FileNotFoundError:
            return None
        finally:
            if parent_descriptor >= 0:
                os.close(parent_descriptor)
        if payload is None:
            return None
        if len(payload) != size_bytes or hashlib.sha256(payload).hexdigest() != sha256:
            raise ObjectIntegrityError(
                "local evidence object identity does not match ready intent"
            )
        return StoredObject(
            key=key,
            sha256=sha256,
            size_bytes=size_bytes,
            path=self._prefix_root / key,
        )

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

    def publish(
        self,
        source: EvidenceSource,
        evidence: EvidenceInput,
    ) -> EvidenceInput:
        if evidence.status not in ("pending", "failed"):
            raise ValueError("evidence publication must begin from pending or failed")
        try:
            stored = self._store.publish(source, evidence.object_key, sha256=evidence.sha256)
        except ObjectPublishError as primary:
            self._raise_after_failed_transition(primary, evidence)
        if stored.sha256 != evidence.sha256 or stored.key != evidence.object_key:
            self._raise_after_failed_transition(
                ObjectIntegrityError(
                    "object store returned a different evidence identity"
                ),
                evidence,
            )
        try:
            return self.mark_ready(evidence)
        except Exception as exc:
            try:
                exc.evidence_object_durable = True  # type: ignore[attr-defined]
                exc.ready_transition_durable = False  # type: ignore[attr-defined]
                exc.stored_object = stored  # type: ignore[attr-defined]
            except Exception:
                raise EvidenceReadyTransitionFailure(stored, exc) from exc
            raise

    def mark_ready(self, evidence: EvidenceInput) -> EvidenceInput:
        ready = replace(evidence, status="ready")
        self._finalize_or_journal(ready, status="ready")
        return ready

    def verify_ready_object(
        self,
        evidence: EvidenceInput,
        *,
        size_bytes: int,
    ) -> StoredObject | None:
        return self._store.verify(
            evidence.object_key,
            sha256=evidence.sha256,
            size_bytes=size_bytes,
        )

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

    def _raise_after_failed_transition(
        self,
        primary: ObjectPublishError,
        evidence: EvidenceInput,
    ) -> None:
        try:
            self.mark_failed(evidence)
        except Exception as secondary:
            raise EvidencePublicationFailure(
                "evidence publication and failed transition both failed",
                [primary, secondary],
            ) from None
        raise primary


class PreviewWorkspaceCapacityError(RuntimeError):
    """The finite preview workspace cannot accept another temporary clip."""


@dataclass(frozen=True, slots=True)
class RegisteredWorkspaceOutput:
    """Immutable identity measured from the pinned assembly descriptor."""

    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class WorkspaceRecoveryRecord:
    """Bounded durable intent used to reconcile abandoned evidence work."""

    reservation_id: str
    evidence: EvidenceInput | None
    intent: Literal["ready"] | None
    size_bytes: int | None


class WorkspaceEvidenceSource:
    """Read-only evidence source pinned to an attested workspace inode."""

    def __init__(
        self,
        *,
        workspace: PreviewWorkspace,
        descriptor: int,
        max_bytes: int,
    ) -> None:
        self.workspace = workspace
        self.descriptor = descriptor
        self.max_bytes = max_bytes

    def duplicate_descriptor(self) -> int:
        if self.descriptor < 0:
            raise ObjectPublishError("workspace evidence source is closed")
        self.workspace._assert_root_attested()
        duplicate = os.dup(self.descriptor)
        os.lseek(duplicate, 0, os.SEEK_SET)
        return duplicate

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __enter__(self) -> WorkspaceEvidenceSource:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class WorkspaceAssemblyTarget:
    """Pre-opened seekable output pinned to one attested preview workspace."""

    def __init__(
        self,
        *,
        workspace: PreviewWorkspace,
        reservation_id: str,
        kind: Literal["preview", "final"],
        temporary_name: str,
        final_name: str,
        descriptor: int,
    ) -> None:
        self.workspace = workspace
        self.reservation_id = reservation_id
        self.kind = kind
        self.temporary_name = temporary_name
        self.final_name = final_name
        self.descriptor = descriptor
        self.max_bytes = workspace.max_file_bytes
        self.promoted = False

    @property
    def descriptor_path(self) -> Path:
        self._require_open()
        return Path(f"/dev/fd/{self.descriptor}")

    def write_bytes(self, payload: bytes) -> int:
        self._require_open()
        if not payload or len(payload) > self.max_bytes:
            raise PreviewWorkspaceCapacityError(
                "assembled evidence output exceeds its finite byte bound"
            )
        self.workspace._assert_root_attested()
        os.ftruncate(self.descriptor, 0)
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        view = memoryview(payload)
        while view:
            written = os.write(self.descriptor, view)
            view = view[written:]
        os.fsync(self.descriptor)
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        return len(payload)

    def read_bytes(self) -> bytes:
        duplicate = self.duplicate_descriptor()
        try:
            payload = bytearray()
            while block := os.read(
                duplicate,
                min(1024 * 1024, self.max_bytes + 1 - len(payload)),
            ):
                payload.extend(block)
                if len(payload) > self.max_bytes:
                    raise PreviewWorkspaceCapacityError(
                        "assembled evidence output exceeds its finite byte bound"
                    )
            return bytes(payload)
        finally:
            os.close(duplicate)

    def duplicate_descriptor(self) -> int:
        self._require_open()
        self.workspace._assert_root_attested()
        duplicate = os.dup(self.descriptor)
        os.lseek(duplicate, 0, os.SEEK_SET)
        return duplicate

    def validate(self) -> tuple[int, str]:
        self._require_open()
        self.workspace._assert_root_attested()
        output_stat = os.fstat(self.descriptor)
        if (
            not stat.S_ISREG(output_stat.st_mode)
            or output_stat.st_uid != os.getuid()
            or output_stat.st_mode & 0o022
            or output_stat.st_size <= 0
            or output_stat.st_size > self.max_bytes
        ):
            raise PreviewWorkspaceCapacityError(
                "assembled evidence output failed descriptor validation"
            )
        digest = hashlib.sha256()
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        remaining = self.max_bytes + 1
        while remaining > 0:
            block = os.read(self.descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            digest.update(block)
            remaining -= len(block)
        if remaining == 0 and os.read(self.descriptor, 1):
            raise PreviewWorkspaceCapacityError(
                "assembled evidence output exceeds its finite byte bound"
            )
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        return output_stat.st_size, digest.hexdigest()

    def exists(self) -> bool:
        name = self.final_name if self.promoted else self.temporary_name
        try:
            os.stat(
                name,
                dir_fd=self.workspace._root_fd,
                follow_symlinks=False,
            )
        except (FileNotFoundError, OSError):
            return False
        return True

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        self.workspace._open_targets.discard(self)

    def _require_open(self) -> None:
        if self.descriptor < 0:
            raise PreviewWorkspaceCapacityError(
                "assembled evidence output descriptor is closed"
            )

    def __del__(self) -> None:
        descriptor = getattr(self, "descriptor", -1)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self.descriptor = -1


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
        max_file_bytes: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if ttl <= timedelta(0):
            raise ValueError("preview workspace TTL must be positive")
        if max_items < 1 or max_bytes < 1:
            raise ValueError("preview workspace bounds must be positive")
        if (
            max_file_bytes is not None
            and (max_file_bytes < 1 or max_file_bytes > max_bytes)
        ):
            raise ValueError(
                "preview workspace file bound must fit within its total byte bound"
            )
        self.root = Path(os.path.abspath(os.fspath(root)))
        if self.root == Path(self.root.anchor):
            raise ValueError("preview workspace must be a dedicated directory")
        self._reject_symlinked_ancestors(self.root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._reject_symlinked_ancestors(self.root)
        self.ttl = ttl
        self.max_items = max_items
        self.max_bytes = max_bytes
        self.max_file_bytes = (
            max_bytes if max_file_bytes is None else max_file_bytes
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._open_targets: set[WorkspaceAssemblyTarget] = set()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        self._root_fd = os.open(self.root, flags)
        try:
            root_stat = os.fstat(self._root_fd)
            if (
                not stat.S_ISDIR(root_stat.st_mode)
                or root_stat.st_uid != os.getuid()
                or root_stat.st_mode & 0o022
            ):
                raise ValueError(
                    "preview workspace ownership or permissions are unsafe"
                )
            self._root_identity = (
                root_stat.st_dev,
                root_stat.st_ino,
                root_stat.st_uid,
                stat.S_IMODE(root_stat.st_mode),
            )
            existing = tuple(os.listdir(self._root_fd))
            if self._MARKER not in existing:
                if existing:
                    raise ValueError(
                        "preview workspace is not an owned empty namespace"
                    )
                self._atomic_write_name(self._MARKER, self._MARKER_PAYLOAD)
            if self._read_private_name(
                self._MARKER,
                max_bytes=len(self._MARKER_PAYLOAD),
            ) != self._MARKER_PAYLOAD:
                raise ValueError("preview workspace marker content is invalid")
            self._assert_owned_namespace()
            self._assert_path_attested()
        except BaseException:
            os.close(self._root_fd)
            self._root_fd = -1
            raise

    def close(self) -> None:
        with self._lock:
            for target in tuple(self._open_targets):
                target.close()
            if self._root_fd >= 0:
                os.close(self._root_fd)
                self._root_fd = -1

    def __del__(self) -> None:
        descriptor = getattr(self, "_root_fd", -1)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._root_fd = -1

    @property
    def item_count(self) -> int:
        return len(self._records())

    @property
    def used_bytes(self) -> int:
        self._assert_owned_namespace()
        total = 0
        for name in os.listdir(self._root_fd):
            if self._MEDIA_PATTERN.fullmatch(name) or self._TEMP_PATTERN.fullmatch(
                name
            ):
                try:
                    file_stat = os.stat(
                        name,
                        dir_fd=self._root_fd,
                        follow_symlinks=False,
                    )
                except OSError:
                    continue
                if stat.S_ISREG(file_stat.st_mode):
                    total += file_stat.st_size
        return total

    def path_for(self, reservation_id: str, *, kind: Literal["preview", "final"]) -> Path:
        self._assert_path_attested()
        key = self._key(reservation_id)
        return self.root / f"{key}.{kind}.mp4"

    def prepare(
        self,
        reservation_id: str,
        *,
        kind: Literal["preview", "final"],
        evidence: EvidenceInput | None = None,
    ) -> WorkspaceAssemblyTarget:
        with self._lock:
            self._assert_path_attested()
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
                intent=None if current is None else current["intent"],
                size_bytes=None if current is None else current["size_bytes"],
            )
            self._assert_path_attested()
            temporary_name = f".kuzet-preview-{uuid4().hex}.tmp"
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=self._root_fd,
            )
            target = WorkspaceAssemblyTarget(
                workspace=self,
                reservation_id=reservation_id,
                kind=kind,
                temporary_name=temporary_name,
                final_name=f"{key}.{kind}.mp4",
                descriptor=descriptor,
            )
            self._open_targets.add(target)
            return target

    def register(
        self,
        reservation_id: str,
        *,
        kind: Literal["preview", "final"],
        path: WorkspaceAssemblyTarget,
        evidence: EvidenceInput | None = None,
    ) -> RegisteredWorkspaceOutput:
        self._assert_path_attested()
        key = self._key(reservation_id)
        expected_name = f"{key}.{kind}.mp4"
        if (
            not isinstance(path, WorkspaceAssemblyTarget)
            or path.workspace is not self
            or path.reservation_id != reservation_id
            or path.kind != kind
            or path.final_name != expected_name
        ):
            raise ValueError("temporary evidence path escaped the preview workspace")
        with self._lock:
            self._assert_path_attested()
            size_bytes, digest = path.validate()
            self._assert_target_name_bound(path, path.temporary_name)
            os.replace(
                path.temporary_name,
                expected_name,
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._root_fd,
            )
            self._assert_target_name_bound(path, expected_name)
            path.promoted = True
            self._fsync_root()
            records = self._records()
            current = records.get(key)
            created_at = (
                self._now()
                if current is None
                else datetime.fromisoformat(str(current["created_at"]))
            )
            paths = set(() if current is None else current["paths"])
            paths.add(expected_name)
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
                intent=None if current is None else current["intent"],
                size_bytes=None if current is None else current["size_bytes"],
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
            self._assert_path_attested()
            return RegisteredWorkspaceOutput(
                size_bytes=size_bytes,
                sha256=digest,
            )

    def abandoned_records(
        self,
    ) -> tuple[WorkspaceRecoveryRecord, ...]:
        return tuple(
            sorted(
                [
                    WorkspaceRecoveryRecord(
                        reservation_id=str(record["reservation_id"]),
                        evidence=record["evidence"],
                        intent=record["intent"],
                        size_bytes=record["size_bytes"],
                    )
                    for record in self._records().values()
                ],
                key=lambda item: item.reservation_id,
            )
        )

    def persist_ready_intent(
        self,
        reservation_id: str,
        *,
        evidence: EvidenceInput,
        size_bytes: int,
    ) -> None:
        if evidence.status != "pending":
            raise ValueError("ready intent evidence must remain pending")
        if size_bytes <= 0 or size_bytes > self.max_file_bytes:
            raise PreviewWorkspaceCapacityError(
                "ready intent size is outside the finite workspace bound"
            )
        with self._lock:
            self._assert_path_attested()
            key = self._key(reservation_id)
            current = self._records().get(key)
            final_name = f"{key}.final.mp4"
            if current is None or final_name not in current["paths"]:
                raise PreviewWorkspaceCapacityError(
                    "ready intent requires a registered final evidence object"
                )
            self._write_record(
                key=key,
                reservation_id=reservation_id,
                created_at=datetime.fromisoformat(str(current["created_at"])),
                paths=current["paths"],
                evidence=evidence,
                intent="ready",
                size_bytes=size_bytes,
            )

    def open_final_source(
        self,
        reservation_id: str,
        *,
        evidence: EvidenceInput,
        size_bytes: int,
    ) -> WorkspaceEvidenceSource | None:
        with self._lock:
            self._assert_path_attested()
            key = self._key(reservation_id)
            current = self._records().get(key)
            if (
                current is None
                or current["intent"] != "ready"
                or current["evidence"] != evidence
                or current["size_bytes"] != size_bytes
            ):
                raise PreviewWorkspaceCapacityError(
                    "workspace ready intent identity changed"
                )
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(
                    f"{key}.final.mp4",
                    flags,
                    dir_fd=self._root_fd,
                )
            except FileNotFoundError:
                return None
            try:
                file_stat = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(file_stat.st_mode)
                    or file_stat.st_uid != os.getuid()
                    or file_stat.st_mode & 0o022
                    or file_stat.st_size != size_bytes
                    or file_stat.st_size > self.max_file_bytes
                ):
                    raise ObjectIntegrityError(
                        "local recovery evidence identity is unsafe"
                    )
                digest = hashlib.sha256()
                remaining = self.max_bytes + 1
                while remaining > 0:
                    block = os.read(descriptor, min(1024 * 1024, remaining))
                    if not block:
                        break
                    digest.update(block)
                    remaining -= len(block)
                if remaining == 0 and os.read(descriptor, 1):
                    raise ObjectIntegrityError(
                        "local recovery evidence exceeds its finite bound"
                    )
                if digest.hexdigest() != evidence.sha256:
                    raise ObjectIntegrityError(
                        "local recovery evidence SHA-256 changed"
                    )
                os.lseek(descriptor, 0, os.SEEK_SET)
                return WorkspaceEvidenceSource(
                    workspace=self,
                    descriptor=descriptor,
                    max_bytes=self.max_file_bytes,
                )
            except BaseException:
                os.close(descriptor)
                raise

    def expired_reservation_ids(self) -> tuple[str, ...]:
        now = self._now()
        return tuple(
            sorted(
                str(record["reservation_id"])
                for record in self._records().values()
                if now - datetime.fromisoformat(str(record["created_at"])) >= self.ttl
            )
        )

    def evidence_for(self, reservation_id: str) -> EvidenceInput | None:
        record = self._records().get(self._key(reservation_id))
        if record is None:
            return None
        return record["evidence"]

    def cleanup(
        self,
        reservation_id: str,
        *,
        preserve_record: bool = False,
    ) -> list[Exception]:
        key = self._key(reservation_id)
        errors: list[Exception] = []
        try:
            self._assert_root_attested()
        except Exception as exc:
            return [exc]
        for target in tuple(self._open_targets):
            if target.reservation_id == reservation_id:
                try:
                    self._unlink_bound_target(target)
                except Exception as exc:
                    errors.append(exc)
                target.close()
        names = [f"{key}.preview.mp4", f"{key}.final.mp4"]
        if not preserve_record:
            names.append(f"{key}.json")
        for name in names:
            try:
                os.unlink(name, dir_fd=self._root_fd)
            except FileNotFoundError:
                pass
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
        for name in os.listdir(self._root_fd):
            media_match = self._MEDIA_PATTERN.fullmatch(name)
            metadata_match = self._METADATA_PATTERN.fullmatch(name)
            is_orphan = (
                self._TEMP_PATTERN.fullmatch(name) is not None
                or (media_match is not None and media_match.group("key") not in known_keys)
                or (metadata_match is not None and metadata_match.group("key") not in known_keys)
            )
            if not is_orphan:
                continue
            try:
                os.unlink(name, dir_fd=self._root_fd)
            except FileNotFoundError:
                pass
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
        for name in os.listdir(self._root_fd):
            match = self._METADATA_PATTERN.fullmatch(name)
            if match is None:
                continue
            try:
                raw = json.loads(
                    self._read_private_name(
                        name,
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
                intent = raw.get("intent")
                size_bytes = raw.get("size_bytes")
                if intent not in (None, "ready"):
                    raise ValueError("unsupported workspace recovery intent")
                if intent == "ready" and (
                    evidence is None
                    or evidence.status != "pending"
                    or not isinstance(size_bytes, int)
                    or isinstance(size_bytes, bool)
                    or size_bytes <= 0
                    or size_bytes > self.max_file_bytes
                ):
                    raise ValueError("invalid ready recovery identity")
                if intent is None and size_bytes is not None:
                    raise ValueError("workspace size requires a recovery intent")
            except (OSError, TypeError, ValueError, KeyError) as exc:
                raise PreviewWorkspaceCapacityError(
                    "preview workspace contains invalid bounded metadata"
                ) from exc
            records[match.group("key")] = {
                "reservation_id": reservation_id,
                "created_at": created_at.astimezone(UTC).isoformat(),
                "paths": paths,
                "evidence": evidence,
                "intent": intent,
                "size_bytes": size_bytes,
            }
        return records

    def _assert_owned_namespace(self) -> None:
        self._assert_root_attested()
        for name in os.listdir(self._root_fd):
            if name == self._MARKER:
                continue
            if not (
                self._MEDIA_PATTERN.fullmatch(name)
                or self._METADATA_PATTERN.fullmatch(name)
                or self._TEMP_PATTERN.fullmatch(name)
            ):
                raise PreviewWorkspaceCapacityError(
                    "preview workspace contains an unexpected entry"
                )
            file_stat = os.stat(
                name,
                dir_fd=self._root_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.getuid()
                or file_stat.st_mode & 0o022
            ):
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
        intent: Literal["ready"] | None = None,
        size_bytes: int | None = None,
    ) -> None:
        payload = {
            "reservation_id": reservation_id,
            "created_at": created_at.isoformat(),
            "paths": paths,
            "intent": intent,
            "size_bytes": size_bytes,
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
        self._atomic_write_name(f"{key}.json", encoded_payload)

    def _assert_target_name_bound(
        self,
        target: WorkspaceAssemblyTarget,
        name: str,
    ) -> None:
        descriptor_stat = os.fstat(target.descriptor)
        try:
            name_stat = os.stat(
                name,
                dir_fd=self._root_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise PreviewWorkspaceCapacityError(
                "assembly target basename inode is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(name_stat.st_mode)
            or (name_stat.st_dev, name_stat.st_ino)
            != (descriptor_stat.st_dev, descriptor_stat.st_ino)
        ):
            raise PreviewWorkspaceCapacityError(
                "assembly target basename inode changed"
            )

    def _unlink_bound_target(self, target: WorkspaceAssemblyTarget) -> None:
        if target.descriptor < 0:
            return
        descriptor_stat = os.fstat(target.descriptor)
        for name in os.listdir(self._root_fd):
            if (
                self._TEMP_PATTERN.fullmatch(name) is None
                and name != target.final_name
            ):
                continue
            try:
                name_stat = os.stat(
                    name,
                    dir_fd=self._root_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            if (name_stat.st_dev, name_stat.st_ino) == (
                descriptor_stat.st_dev,
                descriptor_stat.st_ino,
            ):
                os.unlink(name, dir_fd=self._root_fd)
                self._fsync_root()
                return

    def _read_private_name(self, name: str, *, max_bytes: int) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, dir_fd=self._root_fd)
        try:
            file_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.getuid()
                or file_stat.st_mode & 0o022
                or file_stat.st_size > max_bytes
            ):
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

    def _atomic_write_name(self, destination: str, payload: bytes) -> None:
        if "/" in destination or destination in ("", ".", ".."):
            raise ValueError("preview workspace destination must be one basename")
        self._assert_root_identity()
        temporary = f".kuzet-preview-{uuid4().hex}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=self._root_fd)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(
                temporary,
                destination,
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._root_fd,
            )
            self._fsync_root()
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=self._root_fd)
            except FileNotFoundError:
                pass
            raise

    def _fsync_root(self) -> None:
        self._assert_root_identity()
        os.fsync(self._root_fd)

    def _assert_root_identity(self) -> None:
        if self._root_fd < 0:
            raise PreviewWorkspaceCapacityError("preview workspace is closed")
        root_stat = os.fstat(self._root_fd)
        identity = (
            root_stat.st_dev,
            root_stat.st_ino,
            root_stat.st_uid,
            stat.S_IMODE(root_stat.st_mode),
        )
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or identity != self._root_identity
            or root_stat.st_uid != os.getuid()
            or root_stat.st_mode & 0o022
        ):
            raise PreviewWorkspaceCapacityError(
                "preview workspace descriptor attestation changed"
            )

    def _assert_root_attested(self) -> None:
        self._assert_root_identity()
        try:
            marker = self._read_private_name(
                self._MARKER,
                max_bytes=len(self._MARKER_PAYLOAD),
            )
        except (OSError, ValueError) as exc:
            raise PreviewWorkspaceCapacityError(
                "preview workspace marker attestation failed"
            ) from exc
        if marker != self._MARKER_PAYLOAD:
            raise PreviewWorkspaceCapacityError(
                "preview workspace marker content is invalid"
            )

    def _assert_path_attested(self) -> None:
        self._assert_root_attested()
        try:
            self._reject_symlinked_ancestors(self.root)
            descriptor = os.open(
                self.root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except (OSError, ValueError) as exc:
            raise PreviewWorkspaceCapacityError(
                "preview workspace pathname no longer identifies the attested root"
            ) from exc
        try:
            current = os.fstat(descriptor)
            current_identity = (
                current.st_dev,
                current.st_ino,
                current.st_uid,
                stat.S_IMODE(current.st_mode),
            )
            if current_identity != self._root_identity:
                raise PreviewWorkspaceCapacityError(
                    "preview workspace pathname no longer identifies the attested root"
                )
        finally:
            os.close(descriptor)

    @staticmethod
    def _reject_symlinked_ancestors(path: Path) -> None:
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            try:
                entry_stat = os.lstat(current)
            except FileNotFoundError:
                break
            if stat.S_ISLNK(entry_stat.st_mode):
                raise ValueError(
                    "preview workspace path must not contain symlinked ancestors"
                )


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
        for record in preview_workspace.abandoned_records():
            if record.intent == "ready":
                startup_errors.extend(self._recover_ready_intent(record))
            else:
                startup_errors.extend(
                    self._reconcile_terminal(
                        record.reservation_id,
                        evidence=record.evidence,
                    )
                )
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
            if preview.path is not output_path:
                raise ObjectIntegrityError(
                    "preview assembler returned a different workspace target"
                )
            self.preview_workspace.register(
                reservation.reservation_id,
                kind="preview",
                path=output_path,
                evidence=evidence,
            )
            return preview
        except Exception as primary:
            cleanup_errors = self._reconcile_terminal(
                reservation.reservation_id,
                evidence=evidence,
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
            if assembled.path is not output_path:
                raise ObjectIntegrityError(
                    "final assembler returned a different workspace target"
                )
            registered = self.preview_workspace.register(
                reservation.reservation_id,
                kind="final",
                path=output_path,
                evidence=evidence,
            )
            if assembled.sha256 != registered.sha256:
                raise ObjectIntegrityError(
                    "assembler identity does not match the pinned final descriptor"
                )
            bounded = replace(
                evidence,
                sha256=registered.sha256,
                codec="h264",
                start_at=assembled.start_at,
                end_at=assembled.end_at,
                status="pending",
            )
            self.preview_workspace.persist_ready_intent(
                reservation.reservation_id,
                evidence=bounded,
                size_bytes=registered.size_bytes,
            )
            phase = "publish"
            result = self._publisher.publish(output_path, bounded)
        except Exception as exc:
            primary = exc
        cleanup_errors: list[Exception] = []
        if primary is not None and phase == "assemble":
            cleanup_errors.extend(
                self._reconcile_terminal(
                    reservation.reservation_id,
                    evidence=evidence,
                )
            )
        elif primary is not None and isinstance(
            primary,
            (EvidencePublicationFailure, EvidenceReadyTransitionFailure),
        ) or (
            primary is not None
            and getattr(primary, "evidence_object_durable", False) is True
            and getattr(primary, "ready_transition_durable", True) is False
        ):
            cleanup_errors.extend(
                self._release_media_preserving_record(reservation.reservation_id)
            )
        else:
            cleanup_errors.extend(
                self._release_and_cleanup(reservation.reservation_id)
            )
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
        errors = self._reconcile_terminal(
            reservation_id,
            evidence=(
                evidence
                if evidence is not None
                else self.preview_workspace.evidence_for(reservation_id)
            ),
        )
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

    def _recover_ready_intent(
        self,
        record: WorkspaceRecoveryRecord,
    ) -> list[Exception]:
        evidence = record.evidence
        size_bytes = record.size_bytes
        if evidence is None or size_bytes is None:
            return [
                PreviewWorkspaceCapacityError(
                    "ready recovery record omitted immutable evidence identity"
                )
            ]
        try:
            stored = self._publisher.verify_ready_object(
                evidence,
                size_bytes=size_bytes,
            )
            if stored is None:
                source = self.preview_workspace.open_final_source(
                    record.reservation_id,
                    evidence=evidence,
                    size_bytes=size_bytes,
                )
                if source is None:
                    self._publisher.mark_failed(evidence)
                else:
                    with source:
                        self._publisher.publish(source, evidence)
            else:
                self._publisher.mark_ready(evidence)
        except ObjectIntegrityError:
            try:
                self._publisher.mark_failed(evidence)
            except Exception as transition_error:
                errors: list[Exception] = [transition_error]
                errors.extend(
                    self._release_media_preserving_record(record.reservation_id)
                )
                return errors
        except Exception as primary:
            errors = [primary]
            errors.extend(
                self._release_media_preserving_record(record.reservation_id)
            )
            return errors
        return self._release_and_cleanup(record.reservation_id)

    def _release_and_cleanup(self, reservation_id: str) -> list[Exception]:
        errors = self._release_media_preserving_record(reservation_id)
        if errors:
            return errors
        return self.preview_workspace.cleanup(reservation_id)

    def _release_media_preserving_record(
        self,
        reservation_id: str,
    ) -> list[Exception]:
        errors: list[Exception] = []
        try:
            self._ring.release(reservation_id)
        except Exception as exc:
            errors.append(exc)
        errors.extend(
            self.preview_workspace.cleanup(
                reservation_id,
                preserve_record=True,
            )
        )
        return errors

    def _reconcile_terminal(
        self,
        reservation_id: str,
        *,
        evidence: EvidenceInput | None,
    ) -> list[Exception]:
        errors: list[Exception] = []
        if evidence is not None:
            try:
                self._publisher.mark_failed(evidence)
            except Exception as exc:
                errors.append(exc)
        errors.extend(self._release_media_preserving_record(reservation_id))
        if not errors:
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
        max_file_bytes=storage.max_evidence_object_bytes,
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
