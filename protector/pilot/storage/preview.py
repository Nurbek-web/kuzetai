"""Immutable, bounded preview publication and same-origin delivery contracts."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol
from urllib.parse import urlparse
from uuid import UUID, uuid4

from protector.pilot.storage.object_store import (
    EvidenceSource,
    _has_exact_bounded_lifecycle,
    _read_attested_source,
    validate_object_key,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MEDIA_TYPE = "video/mp4"


class PreviewStoreError(RuntimeError):
    """A preview could not be published or read safely."""


class PreviewIntegrityError(PreviewStoreError):
    """Remote preview bytes or metadata differ from the durable receipt."""


class PreviewAccessDenied(PreviewStoreError):
    """Preview bytes were withheld because access could not be audited."""


def _digest(value: str, *, label: str) -> str:
    if not _SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _identifier(value: str, *, label: str) -> str:
    if not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class PreviewObjectContext:
    """Authority-derived provenance embedded in an immutable preview object."""

    site_id: str
    event_id: UUID
    evidence_id: UUID
    configuration_sha256: str
    runtime_session_id: str
    runtime_writer_generation: int
    configuration_activation_generation: int
    source_epoch: UUID
    rule_revision_sha256: str
    candidate_body_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.site_id, label="site_id")
        if not isinstance(self.event_id, UUID) or not isinstance(
            self.evidence_id,
            UUID,
        ):
            raise TypeError("preview event and evidence identities must be UUIDs")
        _digest(self.configuration_sha256, label="configuration_sha256")
        _identifier(self.runtime_session_id, label="runtime_session_id")
        for value, label in (
            (self.runtime_writer_generation, "runtime_writer_generation"),
            (
                self.configuration_activation_generation,
                "configuration_activation_generation",
            ),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
            ):
                raise ValueError(f"{label} must be a positive integer")
        if not isinstance(self.source_epoch, UUID):
            raise TypeError("source_epoch must be a UUID")
        _digest(self.rule_revision_sha256, label="rule_revision_sha256")
        _digest(
            self.candidate_body_sha256,
            label="candidate_body_sha256",
        )


@dataclass(frozen=True, slots=True)
class PreviewPublicationIntentV1:
    """Durable pre-upload identity that makes retries and orphan cleanup finite."""

    schema_version: Literal["preview-publication-intent.v1"]
    site_id: str
    event_id: UUID
    evidence_id: UUID
    object_key: str
    sha256: str
    configuration_sha256: str
    runtime_session_id: str
    runtime_writer_generation: int
    configuration_activation_generation: int
    source_epoch: UUID
    rule_revision_sha256: str
    candidate_body_sha256: str
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != "preview-publication-intent.v1":
            raise ValueError("unsupported preview publication intent schema")
        PreviewObjectContext(
            site_id=self.site_id,
            event_id=self.event_id,
            evidence_id=self.evidence_id,
            configuration_sha256=self.configuration_sha256,
            runtime_session_id=self.runtime_session_id,
            runtime_writer_generation=self.runtime_writer_generation,
            configuration_activation_generation=(
                self.configuration_activation_generation
            ),
            source_epoch=self.source_epoch,
            rule_revision_sha256=self.rule_revision_sha256,
            candidate_body_sha256=self.candidate_body_sha256,
        )
        validate_object_key(self.object_key)
        _digest(self.sha256, label="sha256")
        created_at = _aware_utc(self.created_at, label="created_at")
        expires_at = _aware_utc(self.expires_at, label="expires_at")
        if not created_at < expires_at <= created_at + timedelta(hours=1):
            raise ValueError(
                "preview publication grace must be positive and at most one hour"
            )
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)

    @property
    def context(self) -> PreviewObjectContext:
        return PreviewObjectContext(
            site_id=self.site_id,
            event_id=self.event_id,
            evidence_id=self.evidence_id,
            configuration_sha256=self.configuration_sha256,
            runtime_session_id=self.runtime_session_id,
            runtime_writer_generation=self.runtime_writer_generation,
            configuration_activation_generation=(
                self.configuration_activation_generation
            ),
            source_epoch=self.source_epoch,
            rule_revision_sha256=self.rule_revision_sha256,
            candidate_body_sha256=self.candidate_body_sha256,
        )


@dataclass(frozen=True, slots=True)
class PreviewObjectReceiptV1:
    """Exact remote identity required before a preview may be served."""

    schema_version: Literal["preview-object-receipt.v1"]
    site_id: str
    event_id: UUID
    evidence_id: UUID
    object_key: str
    sha256: str
    checksum_sha256: str
    size_bytes: int
    media_type: Literal["video/mp4"]
    etag: str
    version_id: str
    server_side_encryption: Literal["AES256", "aws:kms"]
    kms_key_id: str | None
    configuration_sha256: str
    runtime_session_id: str
    runtime_writer_generation: int
    configuration_activation_generation: int
    source_epoch: UUID
    rule_revision_sha256: str
    candidate_body_sha256: str
    created_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != "preview-object-receipt.v1":
            raise ValueError("unsupported preview receipt schema")
        PreviewObjectContext(
            site_id=self.site_id,
            event_id=self.event_id,
            evidence_id=self.evidence_id,
            configuration_sha256=self.configuration_sha256,
            runtime_session_id=self.runtime_session_id,
            runtime_writer_generation=self.runtime_writer_generation,
            configuration_activation_generation=(
                self.configuration_activation_generation
            ),
            source_epoch=self.source_epoch,
            rule_revision_sha256=self.rule_revision_sha256,
            candidate_body_sha256=self.candidate_body_sha256,
        )
        validate_object_key(self.object_key)
        _digest(self.sha256, label="sha256")
        expected_checksum = base64.b64encode(bytes.fromhex(self.sha256)).decode()
        if self.checksum_sha256 != expected_checksum:
            raise ValueError("preview checksum does not match sha256")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes <= 0
        ):
            raise ValueError("preview size must be a positive integer")
        if self.media_type != _MEDIA_TYPE:
            raise ValueError("preview media type is unsupported")
        if (
            not self.etag
            or len(self.etag) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in self.etag)
        ):
            raise ValueError("preview ETag is invalid")
        if (
            not self.version_id
            or len(self.version_id) > 1024
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.version_id
            )
        ):
            raise ValueError("preview version identity is invalid")
        if self.server_side_encryption not in ("AES256", "aws:kms"):
            raise ValueError("preview encryption is unsupported")
        if self.server_side_encryption == "aws:kms":
            if (
                self.kms_key_id is None
                or not self.kms_key_id
                or len(self.kms_key_id) > 2048
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in self.kms_key_id
                )
            ):
                raise ValueError("KMS preview receipt requires a key identity")
        elif self.kms_key_id is not None:
            raise ValueError("AES256 preview receipt cannot contain a KMS key")
        object.__setattr__(
            self,
            "created_at",
            _aware_utc(self.created_at, label="created_at"),
        )

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "schema_version": self.schema_version,
                "site_id": self.site_id,
                "event_id": str(self.event_id),
                "evidence_id": str(self.evidence_id),
                "object_key": self.object_key,
                "sha256": self.sha256,
                "checksum_sha256": self.checksum_sha256,
                "size_bytes": self.size_bytes,
                "media_type": self.media_type,
                "etag": self.etag,
                "version_id": self.version_id,
                "server_side_encryption": self.server_side_encryption,
                "kms_key_id": self.kms_key_id,
                "configuration_sha256": self.configuration_sha256,
                "runtime_session_id": self.runtime_session_id,
                "runtime_writer_generation": self.runtime_writer_generation,
                "configuration_activation_generation": (
                    self.configuration_activation_generation
                ),
                "source_epoch": str(self.source_epoch),
                "rule_revision_sha256": self.rule_revision_sha256,
                "candidate_body_sha256": self.candidate_body_sha256,
                "created_at": self.created_at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def receipt_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class PreviewAccessReceipt:
    """Redacted audit identity committed before preview bytes are returned."""

    schema_version: Literal["preview-access-receipt.v1"]
    access_id: UUID
    site_id: str
    event_id: UUID
    actor_id: str
    receipt_sha256: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != "preview-access-receipt.v1":
            raise ValueError("unsupported preview access schema")
        if not isinstance(self.access_id, UUID) or not isinstance(self.event_id, UUID):
            raise TypeError("preview access identities must be UUIDs")
        _identifier(self.site_id, label="site_id")
        _identifier(self.actor_id, label="actor_id")
        _digest(self.receipt_sha256, label="receipt_sha256")
        object.__setattr__(
            self,
            "occurred_at",
            _aware_utc(self.occurred_at, label="occurred_at"),
        )


@dataclass(frozen=True, slots=True)
class PreviewPayload:
    """Only the bounded media payload crosses the API provider boundary."""

    content: bytes
    media_type: Literal["video/mp4"]

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes) or not self.content:
            raise ValueError("preview payload must contain bytes")
        if self.media_type != _MEDIA_TYPE:
            raise ValueError("preview media type is unsupported")


@dataclass(frozen=True, slots=True)
class PreviewObjectVersionV1:
    """One bounded, exact object version observed by the retention identity."""

    object_key: str
    version_id: str
    etag: str
    size_bytes: int
    last_modified: datetime

    def __post_init__(self) -> None:
        validate_object_key(self.object_key)
        if (
            not isinstance(self.version_id, str)
            or not isinstance(self.etag, str)
            or not self.version_id
            or len(self.version_id) > 1024
            or not self.etag
            or len(self.etag) > 512
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.version_id + self.etag
            )
        ):
            raise ValueError("preview object version identity is invalid")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or not 0 <= self.size_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("preview object version size is invalid")
        if not isinstance(self.last_modified, datetime):
            raise ValueError("preview object version time is invalid")
        object.__setattr__(
            self,
            "last_modified",
            _aware_utc(self.last_modified, label="last_modified"),
        )


@dataclass(frozen=True, slots=True)
class PreviewObjectVersionPageV1:
    versions: tuple[PreviewObjectVersionV1, ...]
    next_key_marker: str | None
    next_version_id_marker: str | None

    def __post_init__(self) -> None:
        if len(self.versions) > 1_000:
            raise ValueError("preview object version page exceeds its bound")
        if (self.next_key_marker is None) != (
            self.next_version_id_marker is None
        ):
            raise ValueError("preview object version cursor is incomplete")


class PreviewReceiptRepository(Protocol):
    """Site-scoped durable receipt and audit operations."""

    def prepare_preview_publication(
        self,
        *,
        context: PreviewObjectContext,
        object_key: str,
        sha256: str,
        requested_at: datetime,
        expires_at: datetime,
    ) -> PreviewPublicationIntentV1: ...

    def finalize_preview_receipt(
        self,
        *,
        intent: PreviewPublicationIntentV1,
        receipt: PreviewObjectReceiptV1,
    ) -> None: ...

    def get_preview_receipt(
        self,
        *,
        site_id: str,
        event_id: UUID,
    ) -> PreviewObjectReceiptV1 | None: ...

    def commit_preview_access(self, access: PreviewAccessReceipt) -> bool: ...


class S3PreviewObjectStore:
    """Conditional S3 preview writer plus exact receipt-bound ranged reader."""

    def __init__(
        self,
        *,
        client: Any,
        endpoint: str,
        bucket: str,
        country_code: str,
        preview_prefix: str,
        max_preview_bytes: int,
        server_side_encryption: Literal["AES256", "aws:kms"],
        kms_key_id: str | None = None,
    ) -> None:
        parsed = urlparse(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("preview endpoint must be an unambiguous HTTPS origin")
        if country_code != "KZ":
            raise ValueError("preview storage boundary must be in Kazakhstan")
        if (
            not bucket
            or "/" in bucket
            or len(bucket) > 255
            or any(
                ord(character) < 33 or ord(character) == 127
                for character in bucket
            )
        ):
            raise ValueError("preview bucket is invalid")
        if (
            not isinstance(max_preview_bytes, int)
            or isinstance(max_preview_bytes, bool)
            or max_preview_bytes <= 0
        ):
            raise ValueError("max_preview_bytes must be finite and positive")
        prefix = validate_object_key(preview_prefix).rstrip("/")
        if server_side_encryption == "aws:kms" and not kms_key_id:
            raise ValueError("aws:kms previews require a KMS key")
        if server_side_encryption == "AES256" and kms_key_id is not None:
            raise ValueError("AES256 previews cannot specify a KMS key")
        self._client = client
        self.endpoint = f"https://{parsed.hostname}"
        if parsed.port is not None:
            self.endpoint += f":{parsed.port}"
        self.bucket = bucket
        self.country_code = country_code
        self.preview_prefix = prefix
        self.max_preview_bytes = max_preview_bytes
        self.server_side_encryption = server_side_encryption
        self.kms_key_id = kms_key_id

    def publish(
        self,
        source: EvidenceSource,
        *,
        intent: PreviewPublicationIntentV1,
        sha256: str,
    ) -> PreviewObjectReceiptV1:
        if not isinstance(intent, PreviewPublicationIntentV1):
            raise TypeError("preview publication intent must be durable")
        sha256 = _digest(sha256, label="sha256")
        if sha256 != intent.sha256:
            raise PreviewIntegrityError(
                "preview source digest differs from publication intent"
            )
        payload = _read_attested_source(
            source,
            expected_sha256=sha256,
            max_object_bytes=self.max_preview_bytes,
        )
        object_key = self.planned_object_key(intent.context, sha256)
        if object_key != intent.object_key:
            raise PreviewIntegrityError(
                "preview object key differs from publication intent"
            )
        metadata = self._metadata(intent)
        existing = self._head(self._remote_key(object_key))
        if existing is not None:
            return self._receipt(
                intent=intent,
                size_bytes=len(payload),
                head=existing,
            )
        checksum = base64.b64encode(bytes.fromhex(sha256)).decode()
        arguments: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": self._remote_key(object_key),
            "Body": payload,
            "IfNoneMatch": "*",
            "ChecksumAlgorithm": "SHA256",
            "ChecksumSHA256": checksum,
            "ContentType": _MEDIA_TYPE,
            "Metadata": metadata,
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
                raise PreviewStoreError("immutable preview publication failed") from exc
        final = self._head(self._remote_key(object_key))
        if final is None:
            raise PreviewStoreError("preview was not durable after publication")
        return self._receipt(
            intent=intent,
            size_bytes=len(payload),
            head=final,
        )

    def attest_bounded_lifecycle(self, *, retention_days: int) -> None:
        """Require versioning and an enabled bounded lifecycle for this prefix."""

        if (
            not isinstance(retention_days, int)
            or isinstance(retention_days, bool)
            or not 1 <= retention_days <= 365
        ):
            raise ValueError("preview retention must be between 1 and 365 days")
        try:
            versioning = self._client.get_bucket_versioning(
                Bucket=self.bucket,
            )
            lifecycle = self._client.get_bucket_lifecycle_configuration(
                Bucket=self.bucket,
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise PreviewStoreError(
                "preview lifecycle policy could not be verified"
            ) from exc
        if (
            not isinstance(versioning, dict)
            or versioning.get("Status") != "Enabled"
            or not isinstance(lifecycle, dict)
        ):
            raise PreviewIntegrityError(
                "preview storage versioning is not enabled"
            )
        expected_prefix = f"{self.preview_prefix}/"
        if _has_exact_bounded_lifecycle(
            lifecycle,
            expected_prefix=expected_prefix,
            expiration_days=retention_days,
            noncurrent_days=1,
        ):
            return
        raise PreviewIntegrityError(
            "preview prefix lacks a bounded version lifecycle policy"
        )

    def delete_exact(self, receipt: PreviewObjectReceiptV1) -> None:
        """Delete and verify the exact immutable object version in a receipt."""

        if not isinstance(receipt, PreviewObjectReceiptV1):
            raise TypeError("preview deletion requires an exact receipt")
        self.delete_version(
            object_key=receipt.object_key,
            version_id=receipt.version_id,
            etag=receipt.etag,
        )

    def list_versions(
        self,
        *,
        max_items: int,
        key_marker: str | None = None,
        version_id_marker: str | None = None,
    ) -> PreviewObjectVersionPageV1:
        """List one finite exact-version page under only the preview prefix."""

        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or not 1 <= max_items <= 1_000
            or (key_marker is None) != (version_id_marker is None)
        ):
            raise ValueError("preview object version listing bound is invalid")
        arguments: dict[str, Any] = {
            "Bucket": self.bucket,
            "Prefix": f"{self.preview_prefix}/",
            "MaxKeys": max_items,
        }
        if key_marker is not None:
            arguments["KeyMarker"] = key_marker
            arguments["VersionIdMarker"] = version_id_marker
        try:
            result = self._client.list_object_versions(**arguments)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise PreviewStoreError(
                "preview object version listing failed"
            ) from exc
        if not isinstance(result, dict):
            raise PreviewIntegrityError(
                "preview object version listing is invalid"
            )
        raw_versions = result.get("Versions", ())
        if (
            not isinstance(raw_versions, (tuple, list))
            or len(raw_versions) > max_items
        ):
            raise PreviewIntegrityError(
                "preview object version listing exceeded its bound"
            )
        prefix = f"{self.preview_prefix}/"
        versions: list[PreviewObjectVersionV1] = []
        for item in raw_versions:
            if not isinstance(item, dict):
                raise PreviewIntegrityError(
                    "preview object version entry is invalid"
                )
            remote_key = item.get("Key")
            if (
                not isinstance(remote_key, str)
                or not remote_key.startswith(prefix)
            ):
                raise PreviewIntegrityError(
                    "preview object version escaped its prefix"
                )
            versions.append(
                PreviewObjectVersionV1(
                    object_key=remote_key[len(prefix) :],
                    version_id=item.get("VersionId"),
                    etag=item.get("ETag"),
                    size_bytes=item.get("Size"),
                    last_modified=item.get("LastModified"),
                )
            )
        truncated = result.get("IsTruncated")
        if truncated is True:
            next_key = result.get("NextKeyMarker")
            next_version = result.get("NextVersionIdMarker")
            if not isinstance(next_key, str) or not isinstance(
                next_version,
                str,
            ):
                raise PreviewIntegrityError(
                    "preview object version cursor is missing"
                )
        elif truncated is False:
            next_key = None
            next_version = None
        else:
            raise PreviewIntegrityError(
                "preview object version truncation state is invalid"
            )
        return PreviewObjectVersionPageV1(
            versions=tuple(versions),
            next_key_marker=next_key,
            next_version_id_marker=next_version,
        )

    def delete_version(
        self,
        *,
        object_key: str,
        version_id: str,
        etag: str,
    ) -> None:
        """Delete and verify one observed version without following a latest alias."""

        validate_object_key(object_key)
        PreviewObjectVersionV1(
            object_key=object_key,
            version_id=version_id,
            etag=etag,
            size_bytes=0,
            last_modified=datetime.now(UTC),
        )
        try:
            self._client.delete_object(
                Bucket=self.bucket,
                Key=self._remote_key(object_key),
                VersionId=version_id,
                IfMatch=etag,
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise PreviewStoreError("exact preview deletion failed") from exc
        if (
            self._head(
                self._remote_key(object_key),
                version_id=version_id,
            )
            is not None
        ):
            raise PreviewIntegrityError(
                "deleted preview version remains accessible"
            )

    def read(
        self,
        receipt: PreviewObjectReceiptV1,
        *,
        max_bytes: int,
    ) -> bytes:
        if not isinstance(receipt, PreviewObjectReceiptV1):
            raise TypeError("preview read requires a structured receipt")
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes <= 0
            or receipt.size_bytes > max_bytes
            or receipt.size_bytes > self.max_preview_bytes
        ):
            raise PreviewIntegrityError("preview size is outside the read bound")
        context = PreviewObjectContext(
            site_id=receipt.site_id,
            event_id=receipt.event_id,
            evidence_id=receipt.evidence_id,
            configuration_sha256=receipt.configuration_sha256,
            runtime_session_id=receipt.runtime_session_id,
            runtime_writer_generation=receipt.runtime_writer_generation,
            configuration_activation_generation=(
                receipt.configuration_activation_generation
            ),
            source_epoch=receipt.source_epoch,
            rule_revision_sha256=receipt.rule_revision_sha256,
            candidate_body_sha256=receipt.candidate_body_sha256,
        )
        if receipt.object_key != self.planned_object_key(
            context,
            receipt.sha256,
        ):
            raise PreviewIntegrityError("preview receipt object identity is invalid")
        head = self._head(
            self._remote_key(receipt.object_key),
            version_id=receipt.version_id,
        )
        if head is None:
            raise PreviewIntegrityError("preview object is unavailable")
        observed = self._receipt(
            intent=PreviewPublicationIntentV1(
                schema_version="preview-publication-intent.v1",
                site_id=receipt.site_id,
                event_id=receipt.event_id,
                evidence_id=receipt.evidence_id,
                object_key=receipt.object_key,
                sha256=receipt.sha256,
                configuration_sha256=receipt.configuration_sha256,
                runtime_session_id=receipt.runtime_session_id,
                runtime_writer_generation=(
                    receipt.runtime_writer_generation
                ),
                configuration_activation_generation=(
                    receipt.configuration_activation_generation
                ),
                source_epoch=receipt.source_epoch,
                rule_revision_sha256=receipt.rule_revision_sha256,
                candidate_body_sha256=receipt.candidate_body_sha256,
                created_at=receipt.created_at,
                expires_at=receipt.created_at + timedelta(hours=1),
            ),
            size_bytes=receipt.size_bytes,
            head=head,
        )
        if observed != receipt:
            raise PreviewIntegrityError("preview object no longer matches its receipt")
        arguments: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": self._remote_key(receipt.object_key),
            "Range": f"bytes=0-{receipt.size_bytes - 1}",
            "IfMatch": receipt.etag,
            "ChecksumMode": "ENABLED",
        }
        arguments["VersionId"] = receipt.version_id
        try:
            response = self._client.get_object(**arguments)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise PreviewStoreError("preview read failed") from exc
        if (
            int(response.get("ContentLength", -1)) != receipt.size_bytes
            or response.get("ContentRange")
            != f"bytes 0-{receipt.size_bytes - 1}/{receipt.size_bytes}"
            or response.get("ETag") != receipt.etag
            or response.get("VersionId") != receipt.version_id
        ):
            self._close_body(response.get("Body"))
            raise PreviewIntegrityError("preview ranged response identity changed")
        body = response.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            self._close_body(body)
            raise PreviewIntegrityError("preview response omitted a bounded body")
        payload = bytearray()
        try:
            while len(payload) < receipt.size_bytes:
                block = body.read(min(64 * 1024, receipt.size_bytes - len(payload)))
                if not block:
                    break
                if not isinstance(block, bytes):
                    raise PreviewIntegrityError("preview body returned non-bytes data")
                payload.extend(block)
            if body.read(1):
                raise PreviewIntegrityError("preview body exceeds its receipt")
        finally:
            self._close_body(body)
        if (
            len(payload) != receipt.size_bytes
            or hashlib.sha256(payload).hexdigest() != receipt.sha256
        ):
            raise PreviewIntegrityError("preview body differs from its receipt")
        return bytes(payload)

    def _receipt(
        self,
        *,
        intent: PreviewPublicationIntentV1,
        size_bytes: int,
        head: dict[str, Any],
    ) -> PreviewObjectReceiptV1:
        expected_metadata = self._metadata(intent)
        expected_checksum = base64.b64encode(
            bytes.fromhex(intent.sha256)
        ).decode()
        if (
            int(head.get("ContentLength", -1)) != size_bytes
            or head.get("ChecksumSHA256") != expected_checksum
            or head.get("ContentType") != _MEDIA_TYPE
            or head.get("ServerSideEncryption") != self.server_side_encryption
            or head.get("Metadata") != expected_metadata
            or (
                self.kms_key_id is not None
                and head.get("SSEKMSKeyId") != self.kms_key_id
            )
            or (
                self.kms_key_id is None
                and head.get("SSEKMSKeyId") is not None
            )
        ):
            raise PreviewIntegrityError("remote preview metadata is invalid")
        etag = head.get("ETag")
        version_id = head.get("VersionId")
        if (
            not isinstance(etag, str)
            or not etag
            or len(etag) > 512
            or any(ord(character) < 32 for character in etag)
        ):
            raise PreviewIntegrityError("remote preview omitted an ETag")
        if (
            not isinstance(version_id, str)
            or not version_id
            or len(version_id) > 1024
            or any(ord(character) < 32 for character in version_id)
        ):
            raise PreviewIntegrityError("remote preview version identity is invalid")
        return PreviewObjectReceiptV1(
            schema_version="preview-object-receipt.v1",
            site_id=intent.site_id,
            event_id=intent.event_id,
            evidence_id=intent.evidence_id,
            object_key=intent.object_key,
            sha256=intent.sha256,
            checksum_sha256=expected_checksum,
            size_bytes=size_bytes,
            media_type=_MEDIA_TYPE,
            etag=etag,
            version_id=version_id,
            server_side_encryption=self.server_side_encryption,
            kms_key_id=self.kms_key_id,
            configuration_sha256=intent.configuration_sha256,
            runtime_session_id=intent.runtime_session_id,
            runtime_writer_generation=intent.runtime_writer_generation,
            configuration_activation_generation=(
                intent.configuration_activation_generation
            ),
            source_epoch=intent.source_epoch,
            rule_revision_sha256=intent.rule_revision_sha256,
            candidate_body_sha256=intent.candidate_body_sha256,
            created_at=intent.created_at,
        )

    def _head(
        self,
        remote_key: str,
        *,
        version_id: str | None = None,
    ) -> dict[str, Any] | None:
        arguments: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": remote_key,
            "ChecksumMode": "ENABLED",
        }
        if version_id is not None:
            arguments["VersionId"] = version_id
        try:
            result = self._client.head_object(**arguments)
        except BaseException as exc:
            if isinstance(exc, KeyError) or self._is_not_found(exc):
                return None
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise PreviewStoreError("preview metadata lookup failed") from exc
        if not isinstance(result, dict):
            raise PreviewIntegrityError("preview metadata response is invalid")
        return result

    def planned_object_key(
        self,
        context: PreviewObjectContext,
        sha256: str,
    ) -> str:
        if not isinstance(context, PreviewObjectContext):
            raise TypeError("preview context must be authority-derived")
        sha256 = _digest(sha256, label="sha256")
        return validate_object_key(
            f"{context.site_id}/{context.event_id}/{context.evidence_id}/{sha256}.mp4"
        )

    def _remote_key(self, object_key: str) -> str:
        return f"{self.preview_prefix}/{validate_object_key(object_key)}"

    @staticmethod
    def _metadata(
        intent: PreviewPublicationIntentV1,
    ) -> dict[str, str]:
        return {
            "schema-version": "preview-object.v1",
            "site-id": intent.site_id,
            "event-id": str(intent.event_id),
            "evidence-id": str(intent.evidence_id),
            "configuration-sha256": intent.configuration_sha256,
            "runtime-session-id": intent.runtime_session_id,
            "runtime-writer-generation": str(intent.runtime_writer_generation),
            "configuration-activation-generation": str(
                intent.configuration_activation_generation
            ),
            "source-epoch": str(intent.source_epoch),
            "rule-revision-sha256": intent.rule_revision_sha256,
            "candidate-body-sha256": intent.candidate_body_sha256,
            "content-sha256": intent.sha256,
            "created-at": intent.created_at.isoformat(),
        }

    @staticmethod
    def _is_not_found(exc: BaseException) -> bool:
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            return False
        error = response.get("Error", {})
        return str(error.get("Code", "")) in {
            "404",
            "NoSuchKey",
            "NoSuchVersion",
            "NotFound",
        }

    @staticmethod
    def _is_precondition_failed(exc: BaseException) -> bool:
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            return False
        error = response.get("Error", {})
        return str(error.get("Code", "")) in {
            "409",
            "412",
            "PreconditionFailed",
        }

    @staticmethod
    def _close_body(body: Any) -> None:
        close = getattr(body, "close", None)
        if callable(close):
            close()


class DurablePreviewPublisher:
    """Persist intent, publish once, then finalize the exact immutable receipt."""

    def __init__(
        self,
        *,
        store: S3PreviewObjectStore,
        repository: PreviewReceiptRepository,
        clock: Callable[[], datetime],
        publication_grace_seconds: int = 900,
        storage_policy_check: Callable[[], None] | None = None,
    ) -> None:
        if not callable(clock):
            raise TypeError("preview publisher clock must be callable")
        if (
            not isinstance(publication_grace_seconds, int)
            or isinstance(publication_grace_seconds, bool)
            or not 60 <= publication_grace_seconds <= 3_600
        ):
            raise ValueError(
                "preview publication grace must be between 60 and 3600 seconds"
            )
        if storage_policy_check is not None and not callable(
            storage_policy_check
        ):
            raise TypeError("preview storage policy check must be callable")
        self._store = store
        self._repository = repository
        self._clock = clock
        self._storage_policy_check = storage_policy_check
        self._publication_grace = timedelta(
            seconds=publication_grace_seconds
        )

    def publish(
        self,
        source: EvidenceSource,
        *,
        context: PreviewObjectContext,
        sha256: str,
    ) -> PreviewObjectReceiptV1:
        if self._storage_policy_check is not None:
            self._storage_policy_check()
        requested_at = _aware_utc(
            self._clock(),
            label="preview publisher clock",
        )
        object_key = self._store.planned_object_key(context, sha256)
        intent = self._repository.prepare_preview_publication(
            context=context,
            object_key=object_key,
            sha256=sha256,
            requested_at=requested_at,
            expires_at=requested_at + self._publication_grace,
        )
        if (
            not isinstance(intent, PreviewPublicationIntentV1)
            or intent.context != context
            or intent.object_key != object_key
            or intent.sha256 != sha256
        ):
            raise PreviewIntegrityError(
                "durable preview publication intent changed"
            )
        receipt = self._store.publish(source, intent=intent, sha256=sha256)
        self._repository.finalize_preview_receipt(
            intent=intent,
            receipt=receipt,
        )
        return receipt


class DurablePreviewEvidenceCoordinator:
    """Require remote publication and receipt commit before preview visibility."""

    def __init__(
        self,
        *,
        delegate: Any,
        publisher: DurablePreviewPublisher,
        context_factory: Callable[[Any, Any], PreviewObjectContext],
    ) -> None:
        if not callable(context_factory):
            raise TypeError("preview context factory must be callable")
        if not callable(getattr(delegate, "create_preview", None)) or not callable(
            getattr(delegate, "complete", None)
        ) or not callable(getattr(delegate, "cancel", None)):
            raise TypeError("preview delegate is invalid")
        if not callable(getattr(publisher, "publish", None)):
            raise TypeError("preview publisher is invalid")
        self._delegate = delegate
        self._publisher = publisher
        self._context_factory = context_factory

    def create_preview(
        self,
        reservation: Any,
        *,
        evidence: Any,
    ) -> Any:
        context = self._context_factory(reservation, evidence)
        if not isinstance(context, PreviewObjectContext):
            raise PreviewIntegrityError(
                "preview context is not authority-derived"
            )
        try:
            reservation_epoch = UUID(str(reservation.stream_epoch))
        except (AttributeError, TypeError, ValueError) as exc:
            raise PreviewIntegrityError(
                "preview reservation epoch is invalid"
            ) from exc
        if (
            context.event_id != getattr(evidence, "event_id", None)
            or context.evidence_id != getattr(evidence, "evidence_id", None)
            or context.source_epoch != reservation_epoch
        ):
            raise PreviewIntegrityError(
                "preview context event, evidence, or epoch does not match"
            )
        preview = self._delegate.create_preview(
            reservation,
            evidence=evidence,
        )
        path = getattr(preview, "path", None)
        sha256 = getattr(preview, "sha256", None)
        if path is None or not isinstance(sha256, str):
            raise PreviewIntegrityError(
                "assembled preview omitted its immutable identity"
            )
        try:
            self._publisher.publish(
                path,
                context=context,
                sha256=sha256,
            )
        except BaseException as primary:
            try:
                self._delegate.cancel(
                    reservation.reservation_id,
                    evidence=evidence,
                )
            except BaseException as cleanup:
                raise BaseExceptionGroup(
                    "preview publication and local cleanup failed",
                    (primary, cleanup),
                )
            raise
        return preview

    def complete(self, reservation: Any, evidence: Any) -> Any:
        return self._delegate.complete(reservation, evidence)


class ProductionPreviewProvider:
    """Site-scoped reader that withholds payloads unless access audit commits."""

    def __init__(
        self,
        *,
        store: S3PreviewObjectStore,
        repository: PreviewReceiptRepository,
        clock: Callable[[], datetime],
        storage_policy_check: Callable[[], None] | None = None,
    ) -> None:
        if storage_policy_check is not None and not callable(
            storage_policy_check
        ):
            raise TypeError("preview storage policy check must be callable")
        self._store = store
        self._repository = repository
        self._clock = clock
        self._storage_policy_check = storage_policy_check

    def get_preview(
        self,
        *,
        site_id: str,
        event_id: UUID,
        actor_id: str,
        max_bytes: int,
    ) -> PreviewPayload | None:
        _identifier(site_id, label="site_id")
        _identifier(actor_id, label="actor_id")
        if self._storage_policy_check is not None:
            try:
                self._storage_policy_check()
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise PreviewAccessDenied(
                    "preview storage policy could not be re-attested"
                ) from exc
        receipt = self._repository.get_preview_receipt(
            site_id=site_id,
            event_id=event_id,
        )
        if receipt is None:
            return None
        payload = self._store.read(receipt, max_bytes=max_bytes)
        access = PreviewAccessReceipt(
            schema_version="preview-access-receipt.v1",
            access_id=uuid4(),
            site_id=site_id,
            event_id=event_id,
            actor_id=actor_id,
            receipt_sha256=receipt.receipt_sha256,
            occurred_at=_aware_utc(self._clock(), label="preview access clock"),
        )
        try:
            committed = self._repository.commit_preview_access(access)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise PreviewAccessDenied("preview access audit did not commit") from exc
        if committed is not True:
            raise PreviewAccessDenied("preview receipt changed before access audit")
        return PreviewPayload(content=payload, media_type=_MEDIA_TYPE)
