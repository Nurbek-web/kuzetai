"""Age-encrypted, asymmetrically signed S3 audit archive publication."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from protector.pilot.retention import PublishedAuditArchive
from protector.pilot.storage.object_store import validate_object_key

_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class EncryptedAuditArchiveStore:
    """Publish immutable age ciphertext with a verified sender-signed receipt."""

    def __init__(
        self,
        *,
        client: Any,
        bucket: str,
        archive_prefix: str,
        site_id: str,
        age_recipient_file: Path,
        signing_private_key_file: Path,
        signing_public_key_file: Path,
        signing_key_id: str,
        server_side_encryption: str,
        kms_key_id: str | None = None,
        max_plaintext_bytes: int = 64 * 1024 * 1024,
        command_runner: Callable[..., object] = subprocess.run,
    ) -> None:
        if not bucket or "/" in bucket:
            raise ValueError("audit archive bucket is invalid")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", site_id) is None:
            raise ValueError("audit archive site identity is invalid")
        self.archive_prefix = validate_object_key(archive_prefix).rstrip("/")
        if not signing_key_id or len(signing_key_id) > 128:
            raise ValueError("audit archive signing key identity is invalid")
        if not 1_024 <= max_plaintext_bytes <= 64 * 1024 * 1024:
            raise ValueError("audit archive plaintext bound is invalid")
        if server_side_encryption not in {"AES256", "aws:kms"}:
            raise ValueError("audit archive S3 encryption policy is invalid")
        if (server_side_encryption == "aws:kms") != (kms_key_id is not None):
            raise ValueError("audit archive KMS identity does not match encryption policy")
        self._client = client
        self.bucket = bucket
        self.site_id = site_id
        self._age_recipient_file = self._validate_key(age_recipient_file)
        self._signing_private_key_file = self._validate_key(signing_private_key_file)
        self._signing_public_key_file = self._validate_key(signing_public_key_file)
        self.signing_key_id = signing_key_id
        self.server_side_encryption = server_side_encryption
        self.kms_key_id = kms_key_id
        self.max_plaintext_bytes = max_plaintext_bytes
        self.max_ciphertext_bytes = max_plaintext_bytes + 64 * 1024
        self._command_runner = command_runner

    @staticmethod
    def _validate_key(path: Path) -> Path:
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            raise ValueError("audit archive key file is unavailable")
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 16 <= metadata.st_size <= 16 * 1024
        ):
            raise ValueError("audit archive key file is invalid")
        return path

    def publish(self, *, object_key: str, plaintext: bytes) -> PublishedAuditArchive:
        logical_key = validate_object_key(object_key)
        if not 1 <= len(plaintext) <= self.max_plaintext_bytes:
            raise ValueError("audit archive exceeds plaintext bound")
        plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
        if plaintext_sha256 not in logical_key:
            raise ValueError("audit archive key is not content addressed")
        remote_key = f"{self.archive_prefix}/{logical_key}"
        existing = self._load_existing(
            remote_key=remote_key,
            logical_key=logical_key,
            plaintext_sha256=plaintext_sha256,
        )
        if existing is not None:
            return existing

        encryption = self._command_runner(
            [
                "age",
                "--recipients-file",
                str(self._age_recipient_file),
            ],
            input=plaintext,
            capture_output=True,
            check=True,
            timeout=30,
        )
        ciphertext = bytes(encryption.stdout)  # type: ignore[attr-defined]
        if not ciphertext or len(ciphertext) > self.max_ciphertext_bytes:
            raise RuntimeError("age audit archive output is invalid")
        encrypted_sha256 = hashlib.sha256(ciphertext).hexdigest()
        receipt = self._canonical_receipt(
            logical_key=logical_key,
            remote_key=remote_key,
            plaintext_sha256=plaintext_sha256,
            encrypted_sha256=encrypted_sha256,
            ciphertext_size=len(ciphertext),
        )
        signature = self._sign(receipt)
        self._verify(receipt, signature)
        metadata = {
            "plaintext-sha256": plaintext_sha256,
            "encrypted-sha256": encrypted_sha256,
            "ciphertext-size": str(len(ciphertext)),
            "receipt-signature": base64.b64encode(signature).decode("ascii"),
            "signing-key-id": self.signing_key_id,
        }
        try:
            put_arguments: dict[str, object] = {
                "Bucket": self.bucket,
                "Key": remote_key,
                "Body": ciphertext,
                "IfNoneMatch": "*",
                "ChecksumAlgorithm": "SHA256",
                "ChecksumSHA256": base64.b64encode(
                    bytes.fromhex(encrypted_sha256)
                ).decode("ascii"),
                "ServerSideEncryption": self.server_side_encryption,
                "Metadata": metadata,
            }
            if self.kms_key_id is not None:
                put_arguments["SSEKMSKeyId"] = self.kms_key_id
            self._client.put_object(
                **put_arguments,
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if (
                self._load_existing(
                    remote_key=remote_key,
                    logical_key=logical_key,
                    plaintext_sha256=plaintext_sha256,
                )
                is None
            ):
                raise RuntimeError("immutable audit archive publication failed") from exc
        published = self._load_existing(
            remote_key=remote_key,
            logical_key=logical_key,
            plaintext_sha256=plaintext_sha256,
        )
        if published is None:
            raise RuntimeError("audit archive was not durable after upload")
        return published

    def _load_existing(
        self,
        *,
        remote_key: str,
        logical_key: str,
        plaintext_sha256: str,
    ) -> PublishedAuditArchive | None:
        try:
            head = self._client.head_object(
                Bucket=self.bucket,
                Key=remote_key,
                ChecksumMode="ENABLED",
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            response = getattr(exc, "response", {})
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status in {404, 410}:
                return None
            raise RuntimeError("audit archive identity lookup failed") from exc
        metadata = head.get("Metadata")
        if not isinstance(metadata, dict):
            raise RuntimeError("audit archive receipt metadata is missing")
        encrypted_sha256 = metadata.get("encrypted-sha256")
        size_text = metadata.get("ciphertext-size")
        signature_text = metadata.get("receipt-signature")
        signing_key_id = metadata.get("signing-key-id")
        try:
            ciphertext_size = int(size_text)
            signature = base64.b64decode(signature_text, validate=True)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("audit archive receipt metadata is invalid") from exc
        expected_checksum = (
            base64.b64encode(bytes.fromhex(encrypted_sha256)).decode("ascii")
            if isinstance(encrypted_sha256, str)
            and _DIGEST.fullmatch(encrypted_sha256)
            else None
        )
        if (
            metadata.get("plaintext-sha256") != plaintext_sha256
            or expected_checksum is None
            or not 1 <= ciphertext_size <= self.max_ciphertext_bytes
            or head.get("ContentLength") != ciphertext_size
            or head.get("ChecksumSHA256") != expected_checksum
            or head.get("ServerSideEncryption") != self.server_side_encryption
            or head.get("SSEKMSKeyId") != self.kms_key_id
            or not signature
            or len(signature) > 16 * 1024
            or signing_key_id != self.signing_key_id
        ):
            raise RuntimeError("audit archive immutable identity does not match")
        response = self._client.get_object(Bucket=self.bucket, Key=remote_key)
        body = response.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            raise RuntimeError("audit archive ciphertext is unavailable")
        try:
            ciphertext = body.read(self.max_ciphertext_bytes + 1)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        if (
            not isinstance(ciphertext, bytes)
            or len(ciphertext) != ciphertext_size
            or hashlib.sha256(ciphertext).hexdigest() != encrypted_sha256
        ):
            raise RuntimeError("audit archive ciphertext integrity verification failed")
        receipt = self._canonical_receipt(
            logical_key=logical_key,
            remote_key=remote_key,
            plaintext_sha256=plaintext_sha256,
            encrypted_sha256=encrypted_sha256,
            ciphertext_size=ciphertext_size,
        )
        self._verify(receipt, signature)
        return PublishedAuditArchive(
            object_key=logical_key,
            encrypted_sha256=encrypted_sha256,
            detached_signature=base64.b64encode(signature).decode("ascii"),
            signing_key_id=signing_key_id,
            canonical_receipt=receipt.decode("utf-8"),
        )

    def _canonical_receipt(
        self,
        *,
        logical_key: str,
        remote_key: str,
        plaintext_sha256: str,
        encrypted_sha256: str,
        ciphertext_size: int,
    ) -> bytes:
        return (
            "schema=kuzet-audit-archive-receipt.v1\n"
            f"site_id={self.site_id}\n"
            f"bucket={self.bucket}\n"
            f"remote_key={remote_key}\n"
            f"object_key={logical_key}\n"
            f"plaintext_sha256={plaintext_sha256}\n"
            f"encrypted_sha256={encrypted_sha256}\n"
            f"ciphertext_size={ciphertext_size}\n"
            f"server_side_encryption={self.server_side_encryption}\n"
            f"kms_key_id={self.kms_key_id or '-'}\n"
            f"signing_key_id={self.signing_key_id}\n"
        ).encode("utf-8")

    def _sign(self, receipt: bytes) -> bytes:
        result = self._command_runner(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(self._signing_private_key_file),
            ],
            input=receipt,
            capture_output=True,
            check=True,
            timeout=10,
        )
        signature = bytes(result.stdout)  # type: ignore[attr-defined]
        if not signature or len(signature) > 16 * 1024:
            raise RuntimeError("audit archive sender signature is invalid")
        return signature

    def _verify(self, receipt: bytes, signature: bytes) -> None:
        with tempfile.TemporaryDirectory(prefix="kuzet-audit-verify-") as directory:
            root = Path(directory)
            receipt_path = root / "receipt.txt"
            signature_path = root / "receipt.sig"
            receipt_path.write_bytes(receipt)
            signature_path.write_bytes(signature)
            os.chmod(receipt_path, 0o600)
            os.chmod(signature_path, 0o600)
            try:
                self._command_runner(
                    [
                        "openssl",
                        "dgst",
                        "-sha256",
                        "-verify",
                        str(self._signing_public_key_file),
                        "-signature",
                        str(signature_path),
                        str(receipt_path),
                    ],
                    capture_output=True,
                    check=True,
                    timeout=10,
                )
            except subprocess.CalledProcessError as exc:
                raise RuntimeError(
                    "audit archive sender signature verification failed"
                ) from exc
