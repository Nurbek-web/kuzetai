"""Atomic evidence publication to KZ S3-compatible or attested encrypted storage."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import uuid4

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


class S3CompatibleObjectStore:
    """Boto-compatible client adapter with deterministic incomplete-key promotion."""

    def __init__(
        self,
        *,
        client: Any,
        endpoint: str,
        bucket: str,
        country_code: str,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("S3-compatible evidence endpoint must use HTTPS")
        if country_code != "KZ":
            raise ValueError("S3-compatible evidence boundary must be in Kazakhstan")
        if not bucket or "/" in bucket:
            raise ValueError("S3 bucket name must be non-empty and unambiguous")
        self._client = client
        self.endpoint = endpoint
        self.bucket = bucket
        self.country_code = country_code

    def publish(self, source: Path, key: str, *, sha256: str) -> StoredObject:
        key = validate_object_key(key)
        sha256 = _validate_digest(sha256)
        source = Path(source)
        if source.is_symlink() or not source.is_file():
            raise ObjectPublishError("evidence source must be a regular file")
        actual_digest = _sha256_file(source)
        if actual_digest != sha256:
            raise ObjectIntegrityError("local evidence SHA-256 does not match declaration")
        size = source.stat().st_size
        if size <= 0:
            raise ObjectPublishError("evidence source must not be empty")

        existing = self._head(key)
        if existing is not None:
            return self._validated_object(key, sha256, size, existing)

        key_digest = hashlib.sha256(key.encode()).hexdigest()
        temporary_key = f".incomplete/{sha256}/{key_digest}.part"
        promoted = False
        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=temporary_key,
                Body=source.read_bytes(),
                Metadata={"sha256": sha256},
            )
            temporary = self._head(temporary_key)
            if temporary is None:
                raise ObjectPublishError("incomplete upload was not durable")
            self._validated_object(temporary_key, sha256, size, temporary)
            self._client.copy_object(
                Bucket=self.bucket,
                Key=key,
                CopySource={"Bucket": self.bucket, "Key": temporary_key},
                MetadataDirective="COPY",
            )
            promoted = True
            final = self._head(key)
            if final is None:
                raise ObjectPublishError("final object was not durable after promotion")
            stored = self._validated_object(key, sha256, size, final)
        except ObjectIntegrityError:
            if promoted:
                self._delete_quietly(key)
            self._delete_quietly(temporary_key)
            raise
        except BaseException as exc:
            if promoted:
                self._delete_quietly(key)
            self._delete_quietly(temporary_key)
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ObjectPublishError("atomic S3 evidence publish failed") from exc
        self._delete_quietly(temporary_key)
        return stored

    def delete(self, key: str) -> None:
        self._client.delete_object(Bucket=self.bucket, Key=validate_object_key(key))

    def delete_older_than(self, cutoff: datetime) -> tuple[str, ...]:
        cutoff = _require_aware_utc(cutoff)
        deleted: list[str] = []
        continuation: str | None = None
        while True:
            arguments: dict[str, Any] = {"Bucket": self.bucket, "Prefix": ""}
            if continuation is not None:
                arguments["ContinuationToken"] = continuation
            response = self._client.list_objects_v2(**arguments)
            for item in response.get("Contents", ()):
                key = str(item["Key"])
                modified = item["LastModified"]
                if key.startswith(".incomplete/"):
                    if _require_aware_utc(modified) < cutoff:
                        self._client.delete_object(Bucket=self.bucket, Key=key)
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
            return self._client.head_object(Bucket=self.bucket, Key=key)
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

    def _validated_object(
        self,
        key: str,
        sha256: str,
        size: int,
        head: dict[str, Any],
    ) -> StoredObject:
        metadata = head.get("Metadata", {})
        if int(head.get("ContentLength", -1)) != size or metadata.get("sha256") != sha256:
            raise ObjectIntegrityError("remote evidence SHA-256 or size does not match")
        return StoredObject(key=key, sha256=sha256, size_bytes=size)

    def _delete_quietly(self, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self.bucket, Key=key)
        except Exception:
            # A retry overwrites the deterministic incomplete key before promotion.
            return


class EncryptedLocalObjectStore:
    """Atomic local-volume adapter gated by an explicit encryption attestation."""

    def __init__(
        self,
        root: str | Path,
        *,
        encrypted_volume_attestation: str,
    ) -> None:
        if not encrypted_volume_attestation.strip():
            raise ValueError("encrypted local evidence volume requires an attestation")
        self.encrypted_volume_attestation = encrypted_volume_attestation
        candidate = Path(root).absolute()
        if candidate.exists() and candidate.is_symlink():
            raise ValueError("encrypted evidence root must not be a symlink")
        candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = candidate.resolve(strict=True)
        for incomplete in self.root.rglob("*"):
            if ".part" not in incomplete.name:
                continue
            if incomplete.is_symlink() or incomplete.is_file():
                incomplete.unlink(missing_ok=True)

    def publish(self, source: Path, key: str, *, sha256: str) -> StoredObject:
        key = validate_object_key(key)
        sha256 = _validate_digest(sha256)
        source = Path(source)
        if source.is_symlink() or not source.is_file():
            raise ObjectPublishError("evidence source must be a regular file")
        actual_digest = _sha256_file(source)
        if actual_digest != sha256:
            raise ObjectIntegrityError("local evidence SHA-256 does not match declaration")
        size = source.stat().st_size
        if size <= 0:
            raise ObjectPublishError("evidence source must not be empty")
        destination = self._safe_destination(key)
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink():
                raise ValueError("evidence destination must not traverse a symlink")
            if destination.stat().st_size != size or _sha256_file(destination) != sha256:
                raise ObjectIntegrityError("existing local evidence object has different bytes")
            return StoredObject(key=key, sha256=sha256, size_bytes=size, path=destination)

        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.part")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output_file:
                for block in iter(lambda: input_file.read(1024 * 1024), b""):
                    output_file.write(block)
                output_file.flush()
                os.fsync(output_file.fileno())
            if _sha256_file(temporary) != sha256:
                raise ObjectIntegrityError("copied local evidence SHA-256 does not match")
            os.replace(temporary, destination)
            self._fsync_directory(destination.parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return StoredObject(key=key, sha256=sha256, size_bytes=size, path=destination)

    def delete(self, key: str) -> None:
        destination = self._safe_destination(validate_object_key(key))
        if destination.is_symlink():
            raise ValueError("evidence destination must not traverse a symlink")
        destination.unlink(missing_ok=True)
        self._fsync_directory(destination.parent)

    def delete_older_than(self, cutoff: datetime) -> tuple[str, ...]:
        cutoff = _require_aware_utc(cutoff)
        deleted: list[str] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_symlink() or not path.is_file() or ".part" in path.name:
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(self.root):
                continue
            modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
            if modified < cutoff:
                key = path.relative_to(self.root).as_posix()
                path.unlink()
                deleted.append(key)
        return tuple(deleted)

    def _safe_destination(self, key: str) -> Path:
        current = self.root
        parts = PurePosixPath(key).parts
        for part in parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise ValueError("evidence destination must not traverse a symlink")
            current.mkdir(mode=0o700, exist_ok=True)
            resolved = current.resolve(strict=True)
            if not resolved.is_relative_to(self.root):
                raise ValueError("evidence destination escaped encrypted volume")
            current = resolved
        destination = current / parts[-1]
        if destination.parent.resolve(strict=True).is_relative_to(self.root) is False:
            raise ValueError("evidence destination escaped encrypted volume")
        return destination

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class EvidencePublisher:
    """Upload first, then atomically align evidence and candidate database state."""

    def __init__(
        self,
        *,
        store: EvidenceObjectStore,
        repository: PilotRepository,
    ) -> None:
        self._store = store
        self._repository = repository

    def publish(self, source: Path, evidence: EvidenceInput) -> EvidenceInput:
        if evidence.status not in ("pending", "failed"):
            raise ValueError("evidence publication must begin from pending or failed")
        try:
            stored = self._store.publish(source, evidence.object_key, sha256=evidence.sha256)
        except ObjectPublishError:
            self._repository.finalize_evidence(evidence, status="failed")
            raise
        if stored.sha256 != evidence.sha256 or stored.key != evidence.object_key:
            self._repository.finalize_evidence(evidence, status="failed")
            raise ObjectIntegrityError("object store returned a different evidence identity")
        ready = replace(evidence, status="ready")
        self._repository.finalize_evidence(ready, status="ready")
        return ready
