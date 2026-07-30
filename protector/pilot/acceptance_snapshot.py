"""Immutable, exact-input snapshots for target acceptance authority V3.

V3 is additive.  It deliberately does not alter the historical V1/V2 report,
journal, or signature contracts.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from protector.pilot.acceptance import (
    AcceptanceManifestV2,
    AcceptanceRunRecordV2,
    ConditionalGateAttestationV2,
)
from protector.pilot.acceptance_operational import (
    AcceptanceLimitsV1,
    AuthoritativeRepositoryBoundaryV1,
    OperationalAcceptanceEvidenceV1,
)
from protector.pilot.acceptance_trust import (
    _load_canonical_json_object,
    canonical_json_bytes,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BoundedId = Annotated[str, Field(min_length=1, max_length=160)]
MAX_ACCEPTANCE_SNAPSHOT_BYTES = 64 * 1024 * 1024

_STANDARD_POLICY = b"kuzet.acceptance.standard-evaluator.v3:acceptance.evaluate_acceptance"
_OPERATIONAL_POLICY = (
    b"kuzet.acceptance.operational-evaluator.v3:"
    b"acceptance_operational.evaluate_operational_acceptance"
)
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "rtspurl",
        "objectstoreendpoint",
        "privatekey",
    }
)


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 32 * 1024 * 1024:
            raise RuntimeError("acceptance evaluator source is not a bounded regular file")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


class EvaluatorIdentityV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-evaluator-identity.v3"]
    name: Literal["standard", "operational"]
    module: Literal[
        "protector.pilot.acceptance",
        "protector.pilot.acceptance_operational",
    ]
    function: Literal[
        "evaluate_acceptance",
        "evaluate_operational_acceptance",
    ]
    source_sha256: Digest
    policy_sha256: Digest

    @model_validator(mode="after")
    def name_matches_callable(self) -> EvaluatorIdentityV3:
        expected = {
            "standard": (
                "protector.pilot.acceptance",
                "evaluate_acceptance",
            ),
            "operational": (
                "protector.pilot.acceptance_operational",
                "evaluate_operational_acceptance",
            ),
        }[self.name]
        if (self.module, self.function) != expected:
            raise ValueError("evaluator name does not match its exact callable")
        return self


def expected_evaluator_identities_v3() -> tuple[EvaluatorIdentityV3, EvaluatorIdentityV3]:
    root = Path(__file__).resolve().parent
    return (
        EvaluatorIdentityV3(
            schema_version="acceptance-evaluator-identity.v3",
            name="standard",
            module="protector.pilot.acceptance",
            function="evaluate_acceptance",
            source_sha256=_file_sha256(root / "acceptance.py"),
            policy_sha256=hashlib.sha256(_STANDARD_POLICY).hexdigest(),
        ),
        EvaluatorIdentityV3(
            schema_version="acceptance-evaluator-identity.v3",
            name="operational",
            module="protector.pilot.acceptance_operational",
            function="evaluate_operational_acceptance",
            source_sha256=_file_sha256(root / "acceptance_operational.py"),
            policy_sha256=hashlib.sha256(_OPERATIONAL_POLICY).hexdigest(),
        ),
    )


class TargetAuthorityBindingV3(_StrictFrozenModel):
    """Typed C2 authority result.  No scalar capacity claim is accepted here."""

    schema_version: Literal["target-authority-binding.v3"]
    authorized: bool
    runtime_identity_sha256: Digest
    gpu_inventory_sha256: Digest
    source_profile_sha256: Digest
    native_prewarm_sha256: Digest
    unique_work_sha256: Digest
    completion_sha256: Digest
    journal_proof_sha256: Digest
    authority_receipt_sha256: Digest

    @model_validator(mode="after")
    def constituents_are_distinct(self) -> TargetAuthorityBindingV3:
        values = (
            self.runtime_identity_sha256,
            self.gpu_inventory_sha256,
            self.source_profile_sha256,
            self.native_prewarm_sha256,
            self.unique_work_sha256,
            self.completion_sha256,
            self.journal_proof_sha256,
            self.authority_receipt_sha256,
        )
        if len(set(values)) != len(values):
            raise ValueError("target authority constituent digests must be distinct")
        return self


def _owned_model[T: BaseModel](value: object, expected: type[T], label: str) -> T:
    if type(value) is not expected:
        raise ValueError(f"{label} must be one exact typed authority value")
    try:
        payload = canonical_json_bytes(value)
        result = expected.model_validate_json(payload, strict=True)
    except (TypeError, ValueError):
        raise ValueError(f"{label} cannot be reconstructed exactly") from None
    if canonical_json_bytes(result) != payload:
        raise ValueError(f"{label} is not canonically reconstructable")
    return result


def _reject_secret_material(value: object, *, path: str = "snapshot") -> None:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = "".join(character.lower() for character in key if character.isalnum())
            if normalized in _SENSITIVE_KEYS:
                raise ValueError(f"{path} contains a forbidden secret field")
            _reject_secret_material(nested, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _reject_secret_material(nested, path=f"{path}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        if "://" in lowered and (
            "@" in lowered or "token=" in lowered or "password=" in lowered or "secret=" in lowered
        ):
            raise ValueError(f"{path} contains credential-bearing material")


class AcceptanceAuthoritySnapshotV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-authority-snapshot.v3"]
    collector_id: BoundedId
    site_id: BoundedId
    campaign_id: BoundedId
    gate: Literal["8h", "72h"]
    offline_root_spki_sha256: Digest
    policy_id: BoundedId
    policy_sha256: Digest
    manifest_payload_sha256: Digest
    manifest_sha256: Digest
    controller_image_sha256: Digest
    controller_code_sha256: Digest
    target_authority: TargetAuthorityBindingV3
    manifest: AcceptanceManifestV2
    run_record: AcceptanceRunRecordV2
    run_record_sha256: Digest
    operational_limits: AcceptanceLimitsV1
    operational_evidence: OperationalAcceptanceEvidenceV1
    repository_boundary: AuthoritativeRepositoryBoundaryV1
    conditional_gate_decisions: tuple[ConditionalGateAttestationV2, ...]
    standard_evaluator: EvaluatorIdentityV3
    operational_evaluator: EvaluatorIdentityV3

    @model_validator(mode="before")
    @classmethod
    def serialized_snapshot_contains_no_secret_material(cls, value: object) -> object:
        _reject_secret_material(value)
        return value

    @field_validator(
        "target_authority",
        "manifest",
        "run_record",
        "operational_limits",
        "operational_evidence",
        "repository_boundary",
        "standard_evaluator",
        "operational_evaluator",
        mode="before",
    )
    @classmethod
    def reconstruct_nested_authority_values(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> BaseModel:
        field_name = info.field_name
        assert field_name is not None
        expected: dict[str, type[BaseModel]] = {
            "target_authority": TargetAuthorityBindingV3,
            "manifest": AcceptanceManifestV2,
            "run_record": AcceptanceRunRecordV2,
            "operational_limits": AcceptanceLimitsV1,
            "operational_evidence": OperationalAcceptanceEvidenceV1,
            "repository_boundary": AuthoritativeRepositoryBoundaryV1,
            "standard_evaluator": EvaluatorIdentityV3,
            "operational_evaluator": EvaluatorIdentityV3,
        }
        model = expected[field_name]
        if type(value) is model:
            return value  # type: ignore[return-value]
        if type(value) is not dict:
            raise ValueError(f"{field_name} must be one exact typed authority value")
        try:
            return model.model_validate_json(canonical_json_bytes(value))
        except ValueError:
            raise ValueError(f"{field_name} cannot be reconstructed exactly") from None

    @field_validator("conditional_gate_decisions", mode="before")
    @classmethod
    def reconstruct_conditional_gate_decisions(cls, value: object) -> tuple[object, ...]:
        if type(value) not in {list, tuple}:
            raise ValueError("conditional gate decisions must be one bounded sequence")
        result: list[ConditionalGateAttestationV2] = []
        for item in value:
            if type(item) is ConditionalGateAttestationV2:
                result.append(item)
            elif type(item) is dict:
                result.append(
                    ConditionalGateAttestationV2.model_validate_json(canonical_json_bytes(item))
                )
            else:
                raise ValueError("conditional gate decision has the wrong exact type")
        return tuple(result)

    @model_validator(mode="after")
    def exact_authority_graph(self) -> AcceptanceAuthoritySnapshotV3:
        manifest = _owned_model(self.manifest, AcceptanceManifestV2, "manifest")
        run = _owned_model(self.run_record, AcceptanceRunRecordV2, "run record")
        limits = _owned_model(
            self.operational_limits,
            AcceptanceLimitsV1,
            "operational limits",
        )
        evidence = _owned_model(
            self.operational_evidence,
            OperationalAcceptanceEvidenceV1,
            "operational evidence",
        )
        boundary = _owned_model(
            self.repository_boundary,
            AuthoritativeRepositoryBoundaryV1,
            "repository boundary",
        )
        target = _owned_model(
            self.target_authority,
            TargetAuthorityBindingV3,
            "target authority",
        )
        standard = _owned_model(
            self.standard_evaluator,
            EvaluatorIdentityV3,
            "standard evaluator",
        )
        operational = _owned_model(
            self.operational_evaluator,
            EvaluatorIdentityV3,
            "operational evaluator",
        )
        decisions = tuple(
            _owned_model(item, ConditionalGateAttestationV2, "conditional gate decision")
            for item in self.conditional_gate_decisions
        )
        camera_ids = tuple(item.camera_id for item in manifest.sources)
        canonical_run = canonical_json_bytes(run)
        if (
            self.collector_id != run.run_id
            or self.site_id != manifest.site_id
            or self.site_id != run.site_id
            or self.site_id != limits.site_id
            or self.site_id != evidence.site_id
            or self.site_id != boundary.site_id
            or self.gate != run.gate
            or self.gate != limits.gate
            or run.environment != "target"
            or self.manifest_sha256 != manifest.manifest_sha256
            or self.manifest_sha256 != run.manifest_sha256
            or self.manifest_sha256 != limits.manifest_sha256
            or self.manifest_sha256 != evidence.manifest_sha256
            or self.manifest_sha256 != boundary.manifest_sha256
            or run.launch != manifest.launch
            or run.started_at != limits.started_at
            or run.ended_at != limits.ended_at
            or run.started_at != evidence.started_at
            or run.ended_at != evidence.ended_at
            or limits.camera_ids != camera_ids
            or self.run_record_sha256 != hashlib.sha256(canonical_run).hexdigest()
            or (standard, operational) != expected_evaluator_identities_v3()
            or target != self.target_authority
            or decisions != self.conditional_gate_decisions
        ):
            raise ValueError("acceptance authority snapshot bindings differ")
        _reject_secret_material(self)
        return self

    @property
    def canonical_run_record(self) -> bytes:
        return canonical_json_bytes(self.run_record)

    @property
    def canonical_bytes(self) -> bytes:
        payload = canonical_json_bytes(self)
        if not 1 <= len(payload) <= MAX_ACCEPTANCE_SNAPSHOT_BYTES:
            raise ValueError("acceptance authority snapshot exceeds its finite bound")
        return payload

    @property
    def snapshot_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def build_acceptance_authority_snapshot_v3(
    *,
    collector_id: str,
    campaign_id: str,
    offline_root_spki_sha256: str,
    policy_id: str,
    policy_sha256: str,
    manifest_payload_sha256: str,
    controller_image_sha256: str,
    controller_code_sha256: str,
    target_authority: TargetAuthorityBindingV3,
    manifest: AcceptanceManifestV2,
    run_record: AcceptanceRunRecordV2,
    operational_limits: AcceptanceLimitsV1,
    operational_evidence: OperationalAcceptanceEvidenceV1,
    repository_boundary: AuthoritativeRepositoryBoundaryV1,
    conditional_gate_decisions: tuple[ConditionalGateAttestationV2, ...],
) -> AcceptanceAuthoritySnapshotV3:
    """Build from complete typed inputs; there is intentionally no candidate."""

    owned_run = _owned_model(run_record, AcceptanceRunRecordV2, "run record")
    standard, operational = expected_evaluator_identities_v3()
    return AcceptanceAuthoritySnapshotV3(
        schema_version="acceptance-authority-snapshot.v3",
        collector_id=collector_id,
        site_id=owned_run.site_id,
        campaign_id=campaign_id,
        gate=owned_run.gate,
        offline_root_spki_sha256=offline_root_spki_sha256,
        policy_id=policy_id,
        policy_sha256=policy_sha256,
        manifest_payload_sha256=manifest_payload_sha256,
        manifest_sha256=owned_run.manifest_sha256,
        controller_image_sha256=controller_image_sha256,
        controller_code_sha256=controller_code_sha256,
        target_authority=_owned_model(
            target_authority,
            TargetAuthorityBindingV3,
            "target authority",
        ),
        manifest=_owned_model(manifest, AcceptanceManifestV2, "manifest"),
        run_record=owned_run,
        run_record_sha256=hashlib.sha256(canonical_json_bytes(owned_run)).hexdigest(),
        operational_limits=_owned_model(
            operational_limits,
            AcceptanceLimitsV1,
            "operational limits",
        ),
        operational_evidence=_owned_model(
            operational_evidence,
            OperationalAcceptanceEvidenceV1,
            "operational evidence",
        ),
        repository_boundary=_owned_model(
            repository_boundary,
            AuthoritativeRepositoryBoundaryV1,
            "repository boundary",
        ),
        conditional_gate_decisions=tuple(
            _owned_model(item, ConditionalGateAttestationV2, "conditional gate decision")
            for item in conditional_gate_decisions
        ),
        standard_evaluator=standard,
        operational_evaluator=operational,
    )


@dataclass(frozen=True)
class PublishedAcceptanceSnapshotV3:
    path: Path
    sha256: str
    byte_size: int


class AcceptanceAuthoritySnapshotStoreV3:
    """Private descriptor-relative O_EXCL/no-replace snapshot storage."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("acceptance snapshot root must be an absolute non-symlink")
        try:
            metadata = root.lstat()
        except OSError:
            raise ValueError("acceptance snapshot root is unavailable") from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("acceptance snapshot root ownership or mode is unsafe")
        self.root = root
        self._descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(self._descriptor)
        self._identity = (opened.st_dev, opened.st_ino)
        if self._identity != (metadata.st_dev, metadata.st_ino):
            os.close(self._descriptor)
            raise ValueError("acceptance snapshot root changed while opening")

    def __del__(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._descriptor = -1

    @staticmethod
    def _stem(collector_id: str) -> str:
        if (
            type(collector_id) is not str
            or not 1 <= len(collector_id) <= 160
            or any(ord(character) < 32 for character in collector_id)
        ):
            raise ValueError("snapshot collector identity is invalid")
        return hashlib.sha256(collector_id.encode("utf-8")).hexdigest()

    def pending_name(self, collector_id: str) -> str:
        return f".snapshot-{self._stem(collector_id)}.pending"

    def _final_name(self, collector_id: str) -> str:
        return f"snapshot-{self._stem(collector_id)}.json"

    def _validate_root(self) -> None:
        try:
            path_metadata = self.root.lstat()
            opened = os.fstat(self._descriptor)
        except OSError:
            raise RuntimeError("acceptance snapshot root identity changed") from None
        if (
            stat.S_ISLNK(path_metadata.st_mode)
            or not stat.S_ISDIR(path_metadata.st_mode)
            or stat.S_IMODE(path_metadata.st_mode) != 0o700
            or path_metadata.st_uid != os.geteuid()
            or (path_metadata.st_dev, path_metadata.st_ino) != self._identity
            or (opened.st_dev, opened.st_ino) != self._identity
        ):
            raise RuntimeError("acceptance snapshot root identity changed")

    def _read_name(self, name: str) -> bytes:
        self._validate_root()
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=self._descriptor,
        )
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or not 1 <= before.st_size <= MAX_ACCEPTANCE_SNAPSHOT_BYTES
                or before.st_dev != self._identity[0]
            ):
                raise RuntimeError("acceptance snapshot artifact is unsafe or unbounded")
            payload = bytearray()
            while chunk := os.read(
                descriptor,
                min(1024 * 1024, MAX_ACCEPTANCE_SNAPSHOT_BYTES + 1 - len(payload)),
            ):
                payload.extend(chunk)
                if len(payload) > MAX_ACCEPTANCE_SNAPSHOT_BYTES:
                    raise RuntimeError("acceptance snapshot artifact is unbounded")
            after = os.fstat(descriptor)
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
            ):
                raise RuntimeError("acceptance snapshot changed while reading")
            return bytes(payload)
        finally:
            os.close(descriptor)

    def _existing(self, collector_id: str) -> PublishedAcceptanceSnapshotV3:
        name = self._final_name(collector_id)
        payload = self._read_name(name)
        return PublishedAcceptanceSnapshotV3(
            path=self.root / name,
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_size=len(payload),
        )

    def publish(
        self,
        snapshot: AcceptanceAuthoritySnapshotV3,
    ) -> PublishedAcceptanceSnapshotV3:
        owned = _owned_model(
            snapshot,
            AcceptanceAuthoritySnapshotV3,
            "authority snapshot",
        )
        payload = owned.canonical_bytes
        expected = (owned.snapshot_sha256, len(payload))
        final_name = self._final_name(owned.collector_id)
        pending_name = self.pending_name(owned.collector_id)
        self._validate_root()

        try:
            existing = self._existing(owned.collector_id)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (existing.sha256, existing.byte_size) != expected:
                raise RuntimeError("existing acceptance snapshot differs; replace is forbidden")
            return existing

        try:
            descriptor = os.open(
                pending_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self._descriptor,
            )
        except FileExistsError:
            pending_payload = self._read_name(pending_name)
            if pending_payload != payload:
                raise RuntimeError("pending acceptance snapshot differs from exact recovery")
        else:
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short acceptance snapshot write")
                    view = view[written:]
                os.fsync(descriptor)
            except BaseException:
                os.close(descriptor)
                raise
            os.close(descriptor)

        try:
            os.link(
                pending_name,
                final_name,
                src_dir_fd=self._descriptor,
                dst_dir_fd=self._descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = self._existing(owned.collector_id)
            if (existing.sha256, existing.byte_size) != expected:
                raise RuntimeError("raced acceptance snapshot differs; replace is forbidden")
        else:
            os.unlink(pending_name, dir_fd=self._descriptor)
            os.fsync(self._descriptor)
        try:
            os.unlink(pending_name, dir_fd=self._descriptor)
            os.fsync(self._descriptor)
        except FileNotFoundError:
            pass
        published = self._existing(owned.collector_id)
        if (published.sha256, published.byte_size) != expected:
            raise RuntimeError("published acceptance snapshot differs from exact input")
        return published

    def load_exact(
        self,
        collector_id: str,
        expected_sha256: str,
    ) -> AcceptanceAuthoritySnapshotV3:
        if (
            type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise ValueError("expected snapshot digest is invalid")
        payload = self._read_name(self._final_name(collector_id))
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise RuntimeError("acceptance snapshot digest differs")
        _load_canonical_json_object(
            payload,
            max_bytes=MAX_ACCEPTANCE_SNAPSHOT_BYTES,
            label="acceptance authority snapshot",
        )
        try:
            snapshot = AcceptanceAuthoritySnapshotV3.model_validate_json(
                payload,
                strict=True,
            )
        except ValueError:
            raise RuntimeError("acceptance snapshot is invalid") from None
        if snapshot.canonical_bytes != payload:
            raise RuntimeError("acceptance snapshot is not exact canonical bytes")
        return snapshot
