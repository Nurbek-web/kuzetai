"""Read-only verifier for acceptance reports emitted by commit 400fe18.

This module deliberately freezes the historical V1 report surface.  It has no
writer, evaluator, manifest/run loader, trust grant, or execution authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ModuleMode = Literal["pass/operator", "shadow", "disabled"]
_SENSITIVE_KEYS = frozenset(
    {
        "rtsp_url",
        "object_url",
        "token",
        "password",
        "secret",
        "notes",
        "username",
        "provider_body",
        "raw_video",
        "frame",
    }
)
_SENSITIVE_NORMALIZED_KEYS = frozenset(
    {
        *(
            "".join(character for character in key if character.isalnum())
            for key in _SENSITIVE_KEYS
        ),
        "apikey",
        "accesstoken",
        "refreshtoken",
        "machinecredential",
        "objectstoreurl",
        "objectstoreuri",
        "objectstoreendpoint",
    }
)


class FrozenModel(BaseModel):
    """Historical immutable model configuration from commit 400fe18."""

    model_config = ConfigDict(extra="forbid", frozen=True)


def _utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be UTC-aware")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be UTC")
    return value.astimezone(timezone.utc)


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_secret_like(value: Any, *, path: str = "record") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = "".join(
                character for character in str(key).lower() if character.isalnum()
            )
            if normalized_key in _SENSITIVE_NORMALIZED_KEYS:
                raise ValueError(f"{path} contains forbidden sensitive field")
            _reject_secret_like(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_like(item, path=f"{path}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        if (
            "rtsp://" in lowered
            or "rtsps://" in lowered
            or "s3://" in lowered
            or "minio://" in lowered
            or "gs://" in lowered
            or "az://" in lowered
            or "://user:" in lowered
            or (
                "://" in lowered
                and "@"
                in lowered.split("://", maxsplit=1)[1].split("/", maxsplit=1)[0]
            )
            or "bearer " in lowered
            or "password=" in lowered
            or "token=" in lowered
        ):
            raise ValueError(f"{path} contains secret-like data")


class ModuleDispositionV1(FrozenModel):
    """Exact historical V1 report module disposition."""

    module: Annotated[str, Field(min_length=1, max_length=64)]
    mode: ModuleMode
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    evidence_reference: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    artifact_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    registry_entry_sha256: Digest | None = None
    rights_sha256: Digest | None = None
    artifact_sha256: Digest | None = None
    site_matrix_sha256: Digest | None = None
    gate_decision_sha256: Digest | None = None

    @model_validator(mode="after")
    def conditional_operator_requires_signed_exact_evidence(
        self,
    ) -> ModuleDispositionV1:
        if self.mode == "pass/operator" and self.module in {"fire_smoke", "weapon"}:
            if (
                self.rights_sha256 is None
                or self.artifact_id is None
                or self.registry_entry_sha256 is None
                or self.artifact_sha256 is None
                or self.site_matrix_sha256 is None
                or self.evidence_reference is None
            ):
                raise ValueError(
                    "conditional operator mode requires rights/artifact/site matrix"
                )
        return self


class ExceptionRecordV1(FrozenModel):
    """Exact historical V1 report exception record."""

    exception_id: Annotated[str, Field(min_length=1, max_length=128)]
    occurred_at: datetime
    component: Annotated[str, Field(min_length=1, max_length=64)]
    category: Literal["handled", "crash", "oom"]
    code: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, "exception timestamp")


class AcceptanceReportV1(FrozenModel):
    """Exact historical V1 signed report model from commit 400fe18."""

    schema_version: Literal["acceptance-report.v1"] = "acceptance-report.v1"
    run_id: str
    site_id: str
    manifest_sha256: Digest
    generated_at: datetime
    gate: Literal["contract", "8h", "72h"]
    environment: Literal["test_only", "target"]
    passed: bool
    reasons: tuple[str, ...]
    metrics: dict[str, float]
    modules: tuple[ModuleDispositionV1, ...]
    exceptions: tuple[ExceptionRecordV1, ...]

    @model_validator(mode="after")
    def report_contains_no_serialized_secrets(self) -> AcceptanceReportV1:
        _reject_secret_like(self.model_dump(mode="json"), path="acceptance report")
        return self


def _read_regular_bounded(path: Path, *, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"symlink is forbidden: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError(f"file is not regular and bounded: {path}")
        payload = os.read(descriptor, limit + 1)
        if len(payload) != metadata.st_size:
            raise ValueError(f"file changed while reading: {path}")
        return payload
    finally:
        os.close(descriptor)


def verify_signed_report_v1(metadata_path: Path, *, public_key: Path) -> bool:
    """Verify, but never create or authorize, one exact historical V1 report."""
    try:
        metadata = json.loads(_read_regular_bounded(metadata_path, limit=64_000))
        if metadata.get("schema_version") != "acceptance-verification.v1":
            return False
        if metadata.get("algorithm") != "Ed25519":
            return False
        if (
            hashlib.sha256(
                _read_regular_bounded(public_key, limit=64_000)
            ).hexdigest()
            != metadata.get("public_key_sha256")
        ):
            return False
        base = metadata_path.parent
        for field in ("signed_file", "signature_file", "html_file"):
            name = metadata.get(field)
            if (
                not isinstance(name, str)
                or not name
                or Path(name).name != name
                or "/" in name
                or "\\" in name
            ):
                return False
        signed = base / metadata["signed_file"]
        signature = base / metadata["signature_file"]
        html_path = base / metadata["html_file"]
        signed_payload = _read_regular_bounded(signed, limit=8 * 1024 * 1024)
        html_payload = _read_regular_bounded(html_path, limit=8 * 1024 * 1024)
        _read_regular_bounded(signature, limit=64 * 1024)
        if hashlib.sha256(signed_payload).hexdigest() != metadata["signed_sha256"]:
            return False
        if hashlib.sha256(html_payload).hexdigest() != metadata["html_sha256"]:
            return False
        envelope = json.loads(signed_payload)
        if _canonical_json(envelope) != signed_payload:
            return False
        if envelope.get("html_sha256") != metadata["html_sha256"]:
            return False
        AcceptanceReportV1.model_validate(envelope.get("report"))
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key),
                "-in",
                str(signed),
                "-sigfile",
                str(signature),
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ):
        return False


__all__ = [
    "AcceptanceReportV1",
    "ExceptionRecordV1",
    "ModuleDispositionV1",
    "verify_signed_report_v1",
]
