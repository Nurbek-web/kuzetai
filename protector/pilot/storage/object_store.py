"""Atomic evidence publication to KZ S3-compatible or attested encrypted storage."""

from __future__ import annotations

import base64
import errno
import hashlib
import os
import re
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from sqlalchemy.exc import SQLAlchemyError

from protector.pilot.config import SiteConfig
from protector.pilot.runtime.evidence import (
    ClipAssembler,
    CodecTool,
    EncodedFragmentRing,
    FfmpegCodecTool,
    FfprobeMediaProbe,
    MediaProbe,
)
from protector.pilot.storage.journal import SQLiteWALJournal
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
        except (OSError, SQLAlchemyError):
            if self._journal is None:
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


class EvidenceCoordinator:
    """Own the complete evidence lifecycle, including pins and temporary media."""

    def __init__(
        self,
        *,
        ring: Any,
        assembler: Any,
        publisher: EvidencePublisher,
    ) -> None:
        self._ring = ring
        self._assembler = assembler
        self._publisher = publisher
        self._previews: dict[str, Path] = {}
        self._consumed_reservations: set[str] = set()

    def create_preview(
        self,
        reservation: Any,
        output: str | Path,
        *,
        evidence: EvidenceInput | None = None,
    ) -> Any:
        output_path = Path(output).absolute()
        try:
            preview = self._assembler.assemble_preview(reservation, output_path)
            self._previews[reservation.reservation_id] = preview.path
            return preview
        except Exception:
            if evidence is not None:
                self._publisher.mark_failed(evidence)
            self._release_and_cleanup(reservation.reservation_id, output_path)
            raise

    def complete(
        self,
        reservation: Any,
        evidence: EvidenceInput,
        output: str | Path,
    ) -> EvidenceInput:
        output_path = Path(output).absolute()
        if reservation.reservation_id in self._consumed_reservations:
            raise ValueError("retry requires a fresh pinned evidence reservation")
        try:
            try:
                assembled = self._assembler.assemble(reservation, output_path)
            except Exception:
                self._publisher.mark_failed(evidence)
                raise
            bounded = replace(
                evidence,
                sha256=assembled.sha256,
                codec="h264",
                start_at=assembled.start_at,
                end_at=assembled.end_at,
                status="pending",
            )
            return self._publisher.publish(assembled.path, bounded)
        finally:
            self._consumed_reservations.add(reservation.reservation_id)
            self._release_and_cleanup(reservation.reservation_id, output_path)

    def retry(
        self,
        reservation: Any,
        evidence: EvidenceInput,
        output: str | Path,
    ) -> EvidenceInput:
        """Retry with a newly acquired reservation; consumed pins are never reused."""
        return self.complete(reservation, evidence, output)

    def _release_and_cleanup(self, reservation_id: str, *paths: Path) -> None:
        self._ring.release(reservation_id)
        preview = self._previews.pop(reservation_id, None)
        for path in (*paths, *((preview,) if preview is not None else ())):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                # Pin release must not be skipped because a UI preview cleanup failed.
                continue


@dataclass(frozen=True, slots=True)
class EvidenceDeliveryServices:
    """Production dependencies handed to the Task 8 candidate trigger."""

    store: S3CompatibleObjectStore
    publisher: EvidencePublisher
    assembler: ClipAssembler
    coordinator: EvidenceCoordinator


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
    coordinator = EvidenceCoordinator(
        ring=ring,
        assembler=assembler,
        publisher=publisher,
    )
    return EvidenceDeliveryServices(
        store=store,
        publisher=publisher,
        assembler=assembler,
        coordinator=coordinator,
    )
