"""Canonical acceptance artifacts and the offline-root trust policy."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal, TypeVar

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator
from yaml.events import AliasEvent, ScalarEvent
from yaml.nodes import MappingNode, Node, ScalarNode

from protector.pilot.acceptance import AcceptanceManifestV2
from protector.pilot.config import FrozenModel
from protector.pilot.trusted_artifacts import (
    canonical_ed25519_public_key_pem,
    ed25519_public_key_spki_sha256,
    read_regular_bounded,
    verify_ed25519_payload,
)

MAX_TRUST_POLICY_BYTES = 64 * 1024
MAX_ACCEPTANCE_ATTESTATION_BYTES = 64 * 1024
MAX_ACCEPTANCE_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ACCEPTANCE_CAPACITY_BYTES = 8 * 1024 * 1024
MAX_ACCEPTANCE_RUN_RECORD_BYTES = 32 * 1024 * 1024
MAX_OPERATIONAL_YAML_BYTES = 8 * 1024 * 1024
MAX_CANONICAL_JSON_BYTES = 64 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_STRUCTURED_DEPTH = 32
MAX_STRUCTURED_NODES = 50_000
MAX_STRUCTURED_SCALAR_BYTES = 64 * 1024

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeIdentifier = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
]
AcceptanceGate = Literal["8h", "72h"]
ModelT = TypeVar("ModelT", bound=BaseModel)

_ROLE_NAMES = ("manifest", "capacity", "run", "report", "conditional")
_ALLOWED_YAML_TAGS = frozenset(
    {
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:map",
    }
)
_YAML_NULL = re.compile(r"^(?:null)$")
_YAML_BOOL = re.compile(r"^(?:true|false)$")
_YAML_INT = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
_YAML_FLOAT = re.compile(
    r"^-?(?:(?:0|[1-9][0-9]*)\.[0-9]+(?:[eE][+-]?[0-9]+)?|"
    r"(?:0|[1-9][0-9]*)[eE][+-]?[0-9]+)$"
)
_YAML_LEGACY_BOOLEAN_OR_NONFINITE = frozenset(
    {
        "yes",
        "no",
        "y",
        "n",
        "t",
        "f",
        "on",
        "off",
        "null",
        "true",
        "false",
        "none",
        "nil",
        "~",
        ".nan",
        ".inf",
        "+.inf",
        "-.inf",
        "nan",
        "inf",
        "+inf",
        "-inf",
        "infinity",
        "+infinity",
        "-infinity",
    }
)
_YAML_LEGACY_INTEGER = re.compile(r"^[+-]?0(?:[0-9_]+|[xXoObB][0-9A-Fa-f_]+)$")
_YAML_NUMERIC_LIKE = re.compile(
    r"^[+-]?(?:[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9_]*)?"
    r"|\.[0-9_]+(?:[eE][+-]?[0-9_]*)?)$"
)
_YAML_SEXAGESIMAL = re.compile(r"^[+-]?[0-9][0-9_]*(?::[0-9_]+)+(?:\.[0-9_]*)?$")
_YAML_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ]"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?)?$"
)


def canonical_json_bytes(value: object) -> bytes:
    """Encode exactly one compact, sorted UTF-8 JSON value."""
    try:
        _require_string_json_mapping_keys(value)
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json")
            _require_string_json_mapping_keys(value)
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError):
        raise ValueError("value cannot be represented as canonical JSON") from None


def _require_string_json_mapping_keys(value: object) -> None:
    if isinstance(value, BaseModel):
        for field_name in type(value).model_fields:
            _require_string_json_mapping_keys(getattr(value, field_name))
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical JSON mapping keys must be strings")
            _require_string_json_mapping_keys(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _require_string_json_mapping_keys(nested)


class _DuplicateJsonKeyError(ValueError):
    pass


class _NonfiniteJsonError(ValueError):
    pass


def _reject_json_constant(_value: str) -> None:
    raise _NonfiniteJsonError("non-finite JSON constant is forbidden")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError("duplicate JSON key is forbidden")
        result[key] = value
    return result


def _bounded_payload(payload: bytes, *, max_bytes: int, label: str) -> bytes:
    if (
        not isinstance(payload, bytes)
        or not 1 <= max_bytes <= MAX_CANONICAL_JSON_BYTES
        or not 1 <= len(payload) <= max_bytes
    ):
        raise ValueError(f"{label} is empty or exceeds its byte bound")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{label} must not contain a UTF-8 BOM")
    return payload


def _load_canonical_json_object(
    payload: bytes,
    *,
    max_bytes: int,
    label: str,
) -> dict[str, Any]:
    bounded = _bounded_payload(payload, max_bytes=max_bytes, label=label)
    try:
        text = bounded.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKeyError:
        raise ValueError(f"{label} contains a duplicate JSON key") from None
    except _NonfiniteJsonError:
        raise ValueError(f"{label} contains a non-finite JSON value") from None
    except (RecursionError, UnicodeError, ValueError):
        raise ValueError(f"{label} is not one strict JSON document") from None
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be one JSON object")
    try:
        _validate_structured_value(parsed, label=label)
    except UnicodeError:
        raise ValueError(f"{label} is not one strict JSON document") from None
    try:
        canonical = canonical_json_bytes(parsed)
    except ValueError:
        raise ValueError(f"{label} is not one strict JSON document") from None
    if canonical != bounded:
        raise ValueError(f"{label} must use exact canonical JSON bytes")
    return parsed


def _validate_structured_value(value: object, *, label: str) -> None:
    node_count = 0

    def visit(item: object, depth: int) -> None:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_STRUCTURED_NODES:
            raise ValueError(f"{label} exceeds the structured nodes bound")
        if depth > MAX_STRUCTURED_DEPTH:
            raise ValueError(f"{label} exceeds the structured depth bound")
        if isinstance(item, dict):
            for key, nested in item.items():
                if len(key.encode("utf-8")) > MAX_STRUCTURED_SCALAR_BYTES:
                    raise ValueError(f"{label} exceeds the scalar byte bound")
                node_count += 1
                if node_count > MAX_STRUCTURED_NODES:
                    raise ValueError(f"{label} exceeds the structured nodes bound")
                visit(nested, depth + 1)
        elif isinstance(item, list):
            for nested in item:
                visit(nested, depth + 1)
        elif isinstance(item, str) and len(item.encode("utf-8")) > MAX_STRUCTURED_SCALAR_BYTES:
            raise ValueError(f"{label} exceeds the scalar byte bound")

    visit(value, 0)


def load_canonical_json_bytes(
    payload: bytes,
    model: type[ModelT],
    *,
    max_bytes: int = MAX_CANONICAL_JSON_BYTES,
    label: str = "canonical JSON artifact",
) -> ModelT:
    """Load exact canonical bytes into an extra-forbidding frozen model."""
    if not issubclass(model, FrozenModel):
        raise ValueError("canonical JSON models must inherit FrozenModel")
    _load_canonical_json_object(
        payload,
        max_bytes=max_bytes,
        label=label,
    )
    try:
        validated = model.model_validate_json(payload, strict=True)
    except ValueError:
        raise ValueError(f"{label} does not match its frozen schema") from None
    try:
        canonical_validated = canonical_json_bytes(validated)
    except ValueError:
        raise ValueError(f"{label} does not match its frozen schema") from None
    if canonical_validated != payload:
        raise ValueError(f"{label} must match its validated canonical model")
    return validated


def load_canonical_json_path(
    path: Path,
    model: type[ModelT],
    *,
    max_bytes: int = MAX_CANONICAL_JSON_BYTES,
    label: str = "canonical JSON artifact",
) -> ModelT:
    """Descriptor-capture a bounded path before decoding its exact bytes."""
    payload = read_regular_bounded(
        path,
        max_bytes=max_bytes,
        label=label,
    )
    return load_canonical_json_bytes(
        payload,
        model,
        max_bytes=max_bytes,
        label=label,
    )


class _RestrictedYamlInputError(ValueError):
    pass


class _RestrictedYamlLoader(yaml.SafeLoader):
    def __init__(self, stream: object) -> None:
        super().__init__(stream)
        self._structured_depth = 0
        self._structured_nodes = 0

    def compose_node(self, parent: Node | None, index: int | None) -> Node:
        event = self.peek_event()
        if isinstance(event, AliasEvent):
            raise _RestrictedYamlInputError("YAML aliases are forbidden")
        if getattr(event, "anchor", None) is not None:
            raise _RestrictedYamlInputError("YAML anchors are forbidden")
        if getattr(event, "tag", None) is not None:
            raise _RestrictedYamlInputError("explicit YAML tags are forbidden")
        if (
            isinstance(event, ScalarEvent)
            and len(event.value.encode("utf-8")) > MAX_STRUCTURED_SCALAR_BYTES
        ):
            raise _RestrictedYamlInputError("YAML scalar exceeds its byte bound")
        if (
            isinstance(event, ScalarEvent)
            and event.style is None
            and _ambiguous_plain_yaml_scalar(event.value)
        ):
            raise _RestrictedYamlInputError("legacy or typed YAML scalar is forbidden")
        self._structured_nodes += 1
        if self._structured_nodes > MAX_STRUCTURED_NODES:
            raise _RestrictedYamlInputError("YAML exceeds its structured nodes bound")
        self._structured_depth += 1
        if self._structured_depth > MAX_STRUCTURED_DEPTH:
            raise _RestrictedYamlInputError("YAML exceeds its structured depth bound")
        try:
            node = super().compose_node(parent, index)
        finally:
            self._structured_depth -= 1
        if node.tag not in _ALLOWED_YAML_TAGS:
            raise _RestrictedYamlInputError("custom or complex YAML tags are forbidden")
        return node

    def construct_mapping(
        self,
        node: MappingNode,
        deep: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(node, MappingNode):
            raise _RestrictedYamlInputError("YAML mapping node is invalid")
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if (
                key_node.tag == "tag:yaml.org,2002:merge"
                or isinstance(key_node, ScalarNode)
                and key_node.value == "<<"
            ):
                raise _RestrictedYamlInputError("YAML merge keys are forbidden")
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise _RestrictedYamlInputError("YAML mapping keys must be strings")
            if key in result:
                raise _RestrictedYamlInputError("duplicate YAML key is forbidden")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


_RestrictedYamlLoader.yaml_implicit_resolvers = {}
_RestrictedYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:null",
    _YAML_NULL,
    ["n"],
)
_RestrictedYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    _YAML_BOOL,
    ["t", "f"],
)
_RestrictedYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    _YAML_INT,
    list("-0123456789"),
)
_RestrictedYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    _YAML_FLOAT,
    list("-0123456789"),
)


def _ambiguous_plain_yaml_scalar(value: str) -> bool:
    lowered = value.lower()
    if (
        value in {"null", "true", "false"}
        or _YAML_INT.fullmatch(value) is not None
        or _YAML_FLOAT.fullmatch(value) is not None
    ):
        return False
    return (
        not value
        or lowered in _YAML_LEGACY_BOOLEAN_OR_NONFINITE
        or _legacy_yaml_implicitly_typed(value)
        or _YAML_NUMERIC_LIKE.fullmatch(value) is not None
        or _YAML_LEGACY_INTEGER.fullmatch(value) is not None
        or _YAML_SEXAGESIMAL.fullmatch(value) is not None
        or _YAML_TIMESTAMP.fullmatch(value) is not None
    )


def _legacy_yaml_implicitly_typed(value: str) -> bool:
    first = value[0] if value else ""
    resolvers = (
        *yaml.SafeLoader.yaml_implicit_resolvers.get(first, ()),
        *yaml.SafeLoader.yaml_implicit_resolvers.get(None, ()),
    )
    return any(
        tag != "tag:yaml.org,2002:str" and pattern.match(value) for tag, pattern in resolvers
    )


def _reject_nonfinite(value: object) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite(item)
    elif isinstance(value, list):
        for item in value:
            _reject_nonfinite(item)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite YAML values are forbidden")


def load_restricted_yaml_bytes(
    payload: bytes,
    *,
    max_bytes: int = MAX_OPERATIONAL_YAML_BYTES,
    label: str = "operational YAML",
) -> dict[str, Any]:
    """Load one bounded operational YAML mapping without ambiguous YAML features."""
    bounded = _bounded_payload(payload, max_bytes=max_bytes, label=label)
    try:
        text = bounded.decode("utf-8", errors="strict")
        parsed = yaml.load(text, Loader=_RestrictedYamlLoader)
    except _RestrictedYamlInputError as exc:
        raise ValueError(f"{label}: {exc}") from None
    except (UnicodeError, yaml.YAMLError, ValueError):
        raise ValueError(f"{label} is not restricted operational YAML") from None
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be one mapping")
    _reject_nonfinite(parsed)
    return parsed


def load_restricted_yaml_path(
    path: Path,
    *,
    max_bytes: int = MAX_OPERATIONAL_YAML_BYTES,
    label: str = "operational YAML",
) -> dict[str, Any]:
    """Descriptor-capture and load one bounded operational YAML mapping."""
    payload = read_regular_bounded(
        path,
        max_bytes=max_bytes,
        label=label,
    )
    return load_restricted_yaml_bytes(
        payload,
        max_bytes=max_bytes,
        label=label,
    )


class AcceptanceRolePinsV2(FrozenModel):
    schema_version: Literal["acceptance-role-pins.v2"]
    manifest_spki_sha256: Digest
    capacity_spki_sha256: Digest
    run_spki_sha256: Digest
    report_spki_sha256: Digest
    conditional_spki_sha256: Digest

    def fingerprints(self) -> tuple[str, ...]:
        return tuple(getattr(self, f"{role}_spki_sha256") for role in _ROLE_NAMES)


class AcceptanceTrustPolicyV2(FrozenModel):
    schema_version: Literal["acceptance-trust-policy.v2"]
    policy_id: SafeIdentifier
    campaign_id: SafeIdentifier
    site_id: SafeIdentifier
    signature_algorithm: Literal["Ed25519"]
    root_spki_sha256: Digest
    valid_from: datetime
    valid_until: datetime
    allowed_gates: Annotated[tuple[AcceptanceGate, ...], Field(min_length=1, max_length=2)]
    manifest_payload_sha256: Digest
    roles: AcceptanceRolePinsV2

    @field_validator("valid_from", "valid_until")
    @classmethod
    def validity_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None or value.utcoffset() != timedelta(0):
            raise ValueError("trust-policy validity must be UTC-aware UTC")
        if value.microsecond:
            raise ValueError("trust-policy validity must use exact whole seconds")
        return value.astimezone(timezone.utc)

    @field_validator("allowed_gates")
    @classmethod
    def gates_are_ordered_and_unique(
        cls,
        gates: tuple[AcceptanceGate, ...],
    ) -> tuple[AcceptanceGate, ...]:
        expected = tuple(gate for gate in ("8h", "72h") if gate in gates)
        if gates != expected:
            raise ValueError("allowed gates must be a canonical ordered unique subset")
        return gates

    @model_validator(mode="after")
    def validity_and_roles_are_bounded(self) -> AcceptanceTrustPolicyV2:
        validity = self.valid_until - self.valid_from
        if validity <= timedelta(0) or validity > timedelta(days=366):
            raise ValueError("trust-policy validity must be positive and at most 366 days")
        fingerprints = (self.root_spki_sha256, *self.roles.fingerprints())
        if len(set(fingerprints)) != 6:
            raise ValueError("root and five role fingerprints must be pairwise distinct")
        return self


@dataclass(frozen=True)
class AcceptanceRolePublicKeyPathsV2:
    manifest: Path
    capacity: Path
    run: Path
    report: Path
    conditional: Path


@dataclass(frozen=True)
class VerifiedAcceptanceRolePublicKeysV2:
    manifest: bytes
    capacity: bytes
    run: bytes
    report: bytes
    conditional: bytes


@dataclass(frozen=True, init=False)
class VerifiedAcceptanceTrustV2:
    policy: AcceptanceTrustPolicyV2
    manifest: AcceptanceManifestV2
    policy_payload: bytes
    policy_sha256: str
    policy_signature: bytes
    policy_signature_sha256: str
    root_public_key: bytes
    root_spki_sha256: str
    role_public_keys: VerifiedAcceptanceRolePublicKeysV2
    manifest_payload: bytes
    manifest_payload_sha256: str
    manifest_signature: bytes
    manifest_signature_sha256: str
    _verification_receipt: ClassVar[bytes] = b""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("verified acceptance trust can only be created by the verifier")


_VERIFIED_TRUST_PROVENANCE_KEY = secrets.token_bytes(32)


def _named_length_framed_bytes(
    *,
    domain: bytes,
    fields: tuple[tuple[str, bytes], ...],
) -> bytes:
    """Injectively frame named fields for process-local provenance receipts."""
    result = bytearray()

    def append(value: bytes) -> None:
        result.extend(len(value).to_bytes(8, "big"))
        result.extend(value)

    append(domain)
    result.extend(len(fields).to_bytes(8, "big"))
    for name, value in fields:
        append(name.encode("ascii", errors="strict"))
        append(value)
    return bytes(result)


def _verified_acceptance_trust_fields(
    *,
    policy: AcceptanceTrustPolicyV2,
    manifest: AcceptanceManifestV2,
    policy_payload: bytes,
    policy_sha256: str,
    policy_signature: bytes,
    policy_signature_sha256: str,
    root_public_key: bytes,
    root_spki_sha256: str,
    role_public_keys: VerifiedAcceptanceRolePublicKeysV2,
    manifest_payload: bytes,
    manifest_payload_sha256: str,
    manifest_signature: bytes,
    manifest_signature_sha256: str,
) -> tuple[tuple[str, bytes], ...]:
    return (
        ("policy", canonical_json_bytes(policy)),
        ("manifest", canonical_json_bytes(manifest)),
        ("policy_payload", policy_payload),
        ("policy_sha256", policy_sha256.encode("ascii", errors="strict")),
        ("policy_signature", policy_signature),
        (
            "policy_signature_sha256",
            policy_signature_sha256.encode("ascii", errors="strict"),
        ),
        ("root_public_key", root_public_key),
        (
            "root_spki_sha256",
            root_spki_sha256.encode("ascii", errors="strict"),
        ),
        ("role_public_key.manifest", role_public_keys.manifest),
        ("role_public_key.capacity", role_public_keys.capacity),
        ("role_public_key.run", role_public_keys.run),
        ("role_public_key.report", role_public_keys.report),
        ("role_public_key.conditional", role_public_keys.conditional),
        ("manifest_payload", manifest_payload),
        (
            "manifest_payload_sha256",
            manifest_payload_sha256.encode("ascii", errors="strict"),
        ),
        ("manifest_signature", manifest_signature),
        (
            "manifest_signature_sha256",
            manifest_signature_sha256.encode("ascii", errors="strict"),
        ),
    )


def _verified_acceptance_trust_mac(
    *,
    policy: AcceptanceTrustPolicyV2,
    manifest: AcceptanceManifestV2,
    policy_payload: bytes,
    policy_sha256: str,
    policy_signature: bytes,
    policy_signature_sha256: str,
    root_public_key: bytes,
    root_spki_sha256: str,
    role_public_keys: VerifiedAcceptanceRolePublicKeysV2,
    manifest_payload: bytes,
    manifest_payload_sha256: str,
    manifest_signature: bytes,
    manifest_signature_sha256: str,
) -> bytes:
    framed = _named_length_framed_bytes(
        domain=b"kuzet.acceptance.verified-trust.v2",
        fields=_verified_acceptance_trust_fields(
            policy=policy,
            manifest=manifest,
            policy_payload=policy_payload,
            policy_sha256=policy_sha256,
            policy_signature=policy_signature,
            policy_signature_sha256=policy_signature_sha256,
            root_public_key=root_public_key,
            root_spki_sha256=root_spki_sha256,
            role_public_keys=role_public_keys,
            manifest_payload=manifest_payload,
            manifest_payload_sha256=manifest_payload_sha256,
            manifest_signature=manifest_signature,
            manifest_signature_sha256=manifest_signature_sha256,
        ),
    )
    return hmac.digest(_VERIFIED_TRUST_PROVENANCE_KEY, framed, "sha256")


def _mint_verified_acceptance_trust(
    *,
    policy: AcceptanceTrustPolicyV2,
    manifest: AcceptanceManifestV2,
    policy_payload: bytes,
    policy_sha256: str,
    policy_signature: bytes,
    policy_signature_sha256: str,
    root_public_key: bytes,
    root_spki_sha256: str,
    role_public_keys: VerifiedAcceptanceRolePublicKeysV2,
    manifest_payload: bytes,
    manifest_payload_sha256: str,
    manifest_signature: bytes,
    manifest_signature_sha256: str,
) -> VerifiedAcceptanceTrustV2:
    values: dict[str, object] = {
        "policy": policy,
        "manifest": manifest,
        "policy_payload": policy_payload,
        "policy_sha256": policy_sha256,
        "policy_signature": policy_signature,
        "policy_signature_sha256": policy_signature_sha256,
        "root_public_key": root_public_key,
        "root_spki_sha256": root_spki_sha256,
        "role_public_keys": role_public_keys,
        "manifest_payload": manifest_payload,
        "manifest_payload_sha256": manifest_payload_sha256,
        "manifest_signature": manifest_signature,
        "manifest_signature_sha256": manifest_signature_sha256,
    }
    receipt = _verified_acceptance_trust_mac(
        policy=policy,
        manifest=manifest,
        policy_payload=policy_payload,
        policy_sha256=policy_sha256,
        policy_signature=policy_signature,
        policy_signature_sha256=policy_signature_sha256,
        root_public_key=root_public_key,
        root_spki_sha256=root_spki_sha256,
        role_public_keys=role_public_keys,
        manifest_payload=manifest_payload,
        manifest_payload_sha256=manifest_payload_sha256,
        manifest_signature=manifest_signature,
        manifest_signature_sha256=manifest_signature_sha256,
    )
    trust = object.__new__(VerifiedAcceptanceTrustV2)
    for name, value in values.items():
        object.__setattr__(trust, name, value)
    object.__setattr__(trust, "_verification_receipt", receipt)
    return trust


def _acceptance_trust_provenance_receipt(
    trust: VerifiedAcceptanceTrustV2,
) -> bytes:
    """Revalidate and return the non-persistent process-local trust receipt."""
    if type(trust) is not VerifiedAcceptanceTrustV2:
        raise ValueError("acceptance trust provenance is invalid")
    try:
        receipt = trust._verification_receipt
        expected = _verified_acceptance_trust_mac(
            policy=trust.policy,
            manifest=trust.manifest,
            policy_payload=trust.policy_payload,
            policy_sha256=trust.policy_sha256,
            policy_signature=trust.policy_signature,
            policy_signature_sha256=trust.policy_signature_sha256,
            root_public_key=trust.root_public_key,
            root_spki_sha256=trust.root_spki_sha256,
            role_public_keys=trust.role_public_keys,
            manifest_payload=trust.manifest_payload,
            manifest_payload_sha256=trust.manifest_payload_sha256,
            manifest_signature=trust.manifest_signature,
            manifest_signature_sha256=trust.manifest_signature_sha256,
        )
    except (AttributeError, TypeError, UnicodeError, ValueError):
        raise ValueError("acceptance trust provenance is invalid") from None
    if (
        not isinstance(receipt, bytes)
        or len(receipt) != hashlib.sha256().digest_size
        or not hmac.compare_digest(receipt, expected)
    ):
        raise ValueError("acceptance trust provenance is invalid")
    return receipt


@dataclass(frozen=True)
class ExecutionTrustGrantV2:
    trust: VerifiedAcceptanceTrustV2
    site_id: str
    campaign_id: str
    gate: AcceptanceGate
    execution_started_at: datetime
    execution_ends_at: datetime


@dataclass(frozen=True)
class HistoricalTrustVerificationV2:
    trust: VerifiedAcceptanceTrustV2
    site_id: str
    campaign_id: str
    gate: AcceptanceGate
    execution_started_at: datetime
    execution_ends_at: datetime
    verified_at: datetime


def _capture_role_keys(
    paths: AcceptanceRolePublicKeyPathsV2,
) -> VerifiedAcceptanceRolePublicKeysV2:
    return VerifiedAcceptanceRolePublicKeysV2(
        **{
            role: canonical_ed25519_public_key_pem(
                read_regular_bounded(
                    getattr(paths, role),
                    max_bytes=MAX_PUBLIC_KEY_BYTES,
                    label=f"acceptance {role} role public key",
                )
            )
            for role in _ROLE_NAMES
        }
    )


def _require_digest(value: str, *, label: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be one lowercase SHA-256 fingerprint")
    return value


def _require_utc(value: datetime, *, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{label} must be UTC-aware UTC")
    return value.astimezone(timezone.utc)


def verify_acceptance_trust_chain(
    *,
    expected_offline_root_spki_sha256: str,
    root_public_key_path: Path,
    policy_path: Path,
    policy_signature_path: Path,
    role_public_key_paths: AcceptanceRolePublicKeyPathsV2,
    manifest_path: Path,
    manifest_signature_path: Path,
) -> VerifiedAcceptanceTrustV2:
    """Verify exact signed bytes from one offline root pin, independent of time."""
    expected_root = _require_digest(
        expected_offline_root_spki_sha256,
        label="expected offline root SPKI",
    )

    # Capture every caller-supplied path before assigning trust to any of its bytes.
    root_public_key = canonical_ed25519_public_key_pem(
        read_regular_bounded(
            root_public_key_path,
            max_bytes=MAX_PUBLIC_KEY_BYTES,
            label="offline root public key",
        )
    )
    policy_payload = read_regular_bounded(
        policy_path,
        max_bytes=MAX_TRUST_POLICY_BYTES,
        label="acceptance trust policy",
    )
    policy_signature = read_regular_bounded(
        policy_signature_path,
        max_bytes=MAX_SIGNATURE_BYTES,
        label="acceptance trust policy signature",
    )
    role_public_keys = _capture_role_keys(role_public_key_paths)
    manifest_payload = read_regular_bounded(
        manifest_path,
        max_bytes=MAX_ACCEPTANCE_MANIFEST_BYTES,
        label="target acceptance manifest",
    )
    manifest_signature = read_regular_bounded(
        manifest_signature_path,
        max_bytes=MAX_SIGNATURE_BYTES,
        label="target acceptance manifest signature",
    )

    root_spki_sha256 = ed25519_public_key_spki_sha256(root_public_key)
    if root_spki_sha256 != expected_root:
        raise ValueError("offline root SPKI fingerprint does not match")
    verified_policy_root = verify_ed25519_payload(
        payload=policy_payload,
        signature=policy_signature,
        trusted_public_key=root_public_key,
        label="acceptance trust policy",
    )
    if verified_policy_root != root_spki_sha256:
        raise ValueError("acceptance trust policy root identity changed")

    policy = load_canonical_json_bytes(
        policy_payload,
        AcceptanceTrustPolicyV2,
        max_bytes=MAX_TRUST_POLICY_BYTES,
        label="acceptance trust policy",
    )
    if policy.root_spki_sha256 != root_spki_sha256:
        raise ValueError("acceptance trust policy root pin does not match")

    manifest = load_canonical_json_bytes(
        manifest_payload,
        AcceptanceManifestV2,
        max_bytes=MAX_ACCEPTANCE_MANIFEST_BYTES,
        label="target acceptance manifest",
    )
    manifest_payload_sha256 = hashlib.sha256(manifest_payload).hexdigest()
    if manifest_payload_sha256 != policy.manifest_payload_sha256:
        raise ValueError("target acceptance manifest hash does not match policy")
    if manifest.site_id != policy.site_id:
        raise ValueError("target acceptance manifest site does not match policy")
    if manifest.launch.run_authority_public_key_spki_sha256 != policy.roles.run_spki_sha256:
        raise ValueError("target acceptance manifest run role pin does not match policy")
    if manifest.launch.capacity_trust_key_spki_sha256 != policy.roles.capacity_spki_sha256:
        raise ValueError("target acceptance manifest capacity role pin does not match policy")
    if any(
        module.gate_trust_key_spki_sha256 is not None
        and module.gate_trust_key_spki_sha256 != policy.roles.conditional_spki_sha256
        for module in manifest.modules
    ):
        raise ValueError("target acceptance manifest conditional role pin does not match policy")

    actual_role_fingerprints = {
        role: ed25519_public_key_spki_sha256(getattr(role_public_keys, role))
        for role in _ROLE_NAMES
    }
    if any(
        actual_role_fingerprints[role] != getattr(policy.roles, f"{role}_spki_sha256")
        for role in _ROLE_NAMES
    ):
        raise ValueError("one or more acceptance role key fingerprints do not match policy")

    verified_manifest_key = verify_ed25519_payload(
        payload=manifest_payload,
        signature=manifest_signature,
        trusted_public_key=role_public_keys.manifest,
        label="target acceptance manifest",
    )
    if verified_manifest_key != actual_role_fingerprints["manifest"]:
        raise ValueError("target acceptance manifest role identity changed")

    return _mint_verified_acceptance_trust(
        policy=policy,
        manifest=manifest,
        policy_payload=policy_payload,
        policy_sha256=hashlib.sha256(policy_payload).hexdigest(),
        policy_signature=policy_signature,
        policy_signature_sha256=hashlib.sha256(policy_signature).hexdigest(),
        root_public_key=root_public_key,
        root_spki_sha256=root_spki_sha256,
        role_public_keys=role_public_keys,
        manifest_payload=manifest_payload,
        manifest_payload_sha256=manifest_payload_sha256,
        manifest_signature=manifest_signature,
        manifest_signature_sha256=hashlib.sha256(manifest_signature).hexdigest(),
    )


def _execution_interval(
    trust: VerifiedAcceptanceTrustV2,
    *,
    expected_site_id: str,
    expected_campaign_id: str,
    expected_gate: AcceptanceGate,
    execution_started_at: datetime,
) -> tuple[datetime, datetime]:
    _acceptance_trust_provenance_receipt(trust)
    started_at = _require_utc(
        execution_started_at,
        label="execution start timestamp",
    )
    policy = trust.policy
    if (
        policy.site_id != expected_site_id
        or policy.campaign_id != expected_campaign_id
        or expected_gate not in policy.allowed_gates
    ):
        raise ValueError("acceptance trust policy context does not match")
    duration = timedelta(hours=8 if expected_gate == "8h" else 72)
    ends_at = started_at + duration
    if not policy.valid_from <= started_at < policy.valid_until:
        raise ValueError("acceptance trust policy is not valid at execution start")
    if ends_at > policy.valid_until:
        raise ValueError("the full gate does not fit within trust-policy validity")
    return started_at, ends_at


def authorize_acceptance_execution(
    trust: VerifiedAcceptanceTrustV2,
    *,
    expected_site_id: str,
    expected_campaign_id: str,
    expected_gate: AcceptanceGate,
    execution_started_at: datetime,
) -> ExecutionTrustGrantV2:
    """Create the only result type that authorizes a new 8h/72h execution."""
    started_at, ends_at = _execution_interval(
        trust,
        expected_site_id=expected_site_id,
        expected_campaign_id=expected_campaign_id,
        expected_gate=expected_gate,
        execution_started_at=execution_started_at,
    )
    return ExecutionTrustGrantV2(
        trust=trust,
        site_id=expected_site_id,
        campaign_id=expected_campaign_id,
        gate=expected_gate,
        execution_started_at=started_at,
        execution_ends_at=ends_at,
    )


def verify_historical_acceptance_trust(
    trust: VerifiedAcceptanceTrustV2,
    *,
    expected_site_id: str,
    expected_campaign_id: str,
    expected_gate: AcceptanceGate,
    execution_started_at: datetime,
    verified_at: datetime,
) -> HistoricalTrustVerificationV2:
    """Verify a past valid execution without returning execution authority."""
    historical_verified_at = _require_utc(
        verified_at,
        label="historical verification timestamp",
    )
    started_at, ends_at = _execution_interval(
        trust,
        expected_site_id=expected_site_id,
        expected_campaign_id=expected_campaign_id,
        expected_gate=expected_gate,
        execution_started_at=execution_started_at,
    )
    if historical_verified_at < ends_at:
        raise ValueError("historical verification requires a finished execution")
    return HistoricalTrustVerificationV2(
        trust=trust,
        site_id=expected_site_id,
        campaign_id=expected_campaign_id,
        gate=expected_gate,
        execution_started_at=started_at,
        execution_ends_at=ends_at,
        verified_at=historical_verified_at,
    )
