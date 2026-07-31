"""Signed, bounded, camera-scoped analytic rules for the controlled pilot."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from protector.pilot.config import FrozenModel, NonEmptyString, SiteConfig
from protector.pilot.domain import GateMode
from protector.pilot.gates import (
    OperationalGateDecisionEnvelopeV2,
    site_config_sha256,
    validate_credential_free_reference,
)
from protector.pilot.trusted_artifacts import (
    VerifiedDetachedArtifact,
    verify_detached_artifact,
)

_DIGEST = frozenset("0123456789abcdef")
_SHADOW_ONLY_MODULES = frozenset({"fight", "fall", "violence", "xclip", "vit"})
_SUPPORTED_RULE_MODULES = frozenset(
    {
        "person",
        "restricted_zone",
        "intrusion",
        "loitering",
        "line_crossing",
        "fire_smoke",
        "weapon",
        *_SHADOW_ONLY_MODULES,
    }
)
MAX_RULE_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_RULES_PER_SITE = 512


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_digest(value: str, *, field_name: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(character not in _DIGEST for character in normalized):
        raise ValueError(f"{field_name} must be a 64-character hexadecimal digest")
    return normalized


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("review timestamp must be UTC-aware")
    return value.astimezone(timezone.utc)


def _strict_finite_number(
    value: object,
    *,
    field_name: str,
    minimum: float,
    maximum: float,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not minimum <= float(value) <= maximum
    ):
        raise ValueError(
            f"{field_name} must be a finite number within [{minimum}, {maximum}]"
        )
    return float(value)


def _normalised_point(
    value: object,
    *,
    field_name: str,
) -> tuple[float, float]:
    if (
        not isinstance(value, (tuple, list))
        or len(value) != 2
        or any(isinstance(item, bool) for item in value)
        or any(not isinstance(item, (int, float)) for item in value)
        or any(not math.isfinite(item) for item in value)
        or any(not 0.0 <= float(item) <= 1.0 for item in value)
    ):
        raise ValueError(f"{field_name} must contain two finite normalised coordinates")
    return (float(value[0]), float(value[1]))


def _polygon_area(points: tuple[tuple[float, float], ...]) -> float:
    return sum(
        first[0] * second[1] - second[0] * first[1]
        for first, second in zip(points, (*points[1:], points[0]))
    ) / 2.0


def _orientation(
    first: tuple[float, float],
    second: tuple[float, float],
    third: tuple[float, float],
) -> float:
    return (second[0] - first[0]) * (third[1] - first[1]) - (
        second[1] - first[1]
    ) * (third[0] - first[0])


def _point_on_segment(
    start: tuple[float, float],
    point: tuple[float, float],
    end: tuple[float, float],
) -> bool:
    return (
        abs(_orientation(start, end, point)) <= 1e-12
        and min(start[0], end[0]) - 1e-12
        <= point[0]
        <= max(start[0], end[0]) + 1e-12
        and min(start[1], end[1]) - 1e-12
        <= point[1]
        <= max(start[1], end[1]) + 1e-12
    )


def _segments_intersect(
    first_start: tuple[float, float],
    first_end: tuple[float, float],
    second_start: tuple[float, float],
    second_end: tuple[float, float],
) -> bool:
    orientations = (
        _orientation(first_start, first_end, second_start),
        _orientation(first_start, first_end, second_end),
        _orientation(second_start, second_end, first_start),
        _orientation(second_start, second_end, first_end),
    )
    if (
        orientations[0] * orientations[1] < -1e-12
        and orientations[2] * orientations[3] < -1e-12
    ):
        return True
    return (
        abs(orientations[0]) <= 1e-12
        and _point_on_segment(first_start, second_start, first_end)
        or abs(orientations[1]) <= 1e-12
        and _point_on_segment(first_start, second_end, first_end)
        or abs(orientations[2]) <= 1e-12
        and _point_on_segment(second_start, first_start, second_end)
        or abs(orientations[3]) <= 1e-12
        and _point_on_segment(second_start, first_end, second_end)
    )


def _is_simple_polygon(points: tuple[tuple[float, float], ...]) -> bool:
    if len(points) != len(set(points)):
        return False
    for index, current in enumerate(points):
        previous = points[index - 1]
        following = points[(index + 1) % len(points)]
        if abs(_orientation(previous, current, following)) <= 1e-12 and (
            _point_on_segment(previous, following, current)
            or _point_on_segment(current, previous, following)
        ):
            return False
    edges = tuple(zip(points, (*points[1:], points[0])))
    for first_index, (first_start, first_end) in enumerate(edges):
        for second_index, (second_start, second_end) in enumerate(edges):
            if second_index <= first_index:
                continue
            if second_index in {first_index - 1, first_index + 1} or {
                first_index,
                second_index,
            } == {0, len(edges) - 1}:
                continue
            if _segments_intersect(
                first_start,
                first_end,
                second_start,
                second_end,
            ):
                return False
    return True


class ModuleRuleSpecV1(FrozenModel):
    kind: Literal["module"] = "module"
    source_module: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*$")
    ]
    class_names: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...],
        Field(min_length=1, max_length=32),
    ]
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    merge_window_seconds: float
    cooldown_seconds: float

    @field_validator("class_names")
    @classmethod
    def classes_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            len(value) != len(set(value))
            or any(item != item.strip() or not item for item in value)
        ):
            raise ValueError("module rule classes must be unique")
        return value

    @field_validator("reason")
    @classmethod
    def reason_is_not_blank(cls, value: str) -> str:
        if value != value.strip() or not value:
            raise ValueError("module rule reason must be canonical non-blank text")
        return value

    @field_validator(
        "merge_window_seconds",
        "cooldown_seconds",
        mode="before",
    )
    @classmethod
    def timing_is_bounded(cls, value: object, info: object) -> float:
        return _strict_finite_number(
            value,
            field_name=getattr(info, "field_name", "timing"),
            minimum=0.0,
            maximum=3_600.0,
        )


class ZoneRuleSpecV1(FrozenModel):
    kind: Literal["zone"] = "zone"
    mode: Literal["intrusion", "loitering"]
    polygon: Annotated[tuple[tuple[float, float], ...], Field(min_length=3, max_length=32)]
    loiter_seconds: float = 0.0
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    merge_window_seconds: float
    cooldown_seconds: float

    @field_validator("polygon", mode="before")
    @classmethod
    def polygon_is_normalised(cls, value: object) -> object:
        if not isinstance(value, (tuple, list)) or not 3 <= len(value) <= 32:
            raise ValueError("zone polygon requires 3..32 points")
        return tuple(
            _normalised_point(point, field_name=f"polygon[{index}]")
            for index, point in enumerate(value)
        )

    @field_validator("reason")
    @classmethod
    def reason_is_not_blank(cls, value: str) -> str:
        if value != value.strip() or not value:
            raise ValueError("zone rule reason must be canonical non-blank text")
        return value

    @field_validator(
        "loiter_seconds",
        "merge_window_seconds",
        "cooldown_seconds",
        mode="before",
    )
    @classmethod
    def timing_is_bounded(cls, value: object, info: object) -> float:
        return _strict_finite_number(
            value,
            field_name=getattr(info, "field_name", "timing"),
            minimum=0.0,
            maximum=3_600.0,
        )

    @model_validator(mode="after")
    def geometry_and_mode_are_valid(self) -> ZoneRuleSpecV1:
        if (
            not _is_simple_polygon(self.polygon)
            or abs(_polygon_area(self.polygon)) <= 1e-12
        ):
            raise ValueError(
                "zone polygon must be simple with unique points and non-zero area"
            )
        if self.mode == "loitering" and self.loiter_seconds <= 0.0:
            raise ValueError("loitering rule requires a positive bounded duration")
        if self.mode == "intrusion" and self.loiter_seconds != 0.0:
            raise ValueError("intrusion rule cannot declare loiter duration")
        return self


class LineRuleSpecV1(FrozenModel):
    kind: Literal["line"] = "line"
    start: tuple[float, float]
    end: tuple[float, float]
    direction: Literal["positive_to_negative", "negative_to_positive"]
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    merge_window_seconds: float
    cooldown_seconds: float

    @field_validator("start", "end", mode="before")
    @classmethod
    def endpoints_are_normalised(cls, value: object, info: object) -> tuple[float, float]:
        return _normalised_point(
            value,
            field_name=getattr(info, "field_name", "line endpoint"),
        )

    @field_validator("reason")
    @classmethod
    def reason_is_not_blank(cls, value: str) -> str:
        if value != value.strip() or not value:
            raise ValueError("line rule reason must be canonical non-blank text")
        return value

    @field_validator(
        "merge_window_seconds",
        "cooldown_seconds",
        mode="before",
    )
    @classmethod
    def timing_is_bounded(cls, value: object, info: object) -> float:
        return _strict_finite_number(
            value,
            field_name=getattr(info, "field_name", "timing"),
            minimum=0.0,
            maximum=3_600.0,
        )

    @model_validator(mode="after")
    def endpoints_differ(self) -> LineRuleSpecV1:
        if self.start == self.end:
            raise ValueError("line endpoints must differ")
        return self


RuleSpecV1 = Annotated[
    ModuleRuleSpecV1 | ZoneRuleSpecV1 | LineRuleSpecV1,
    Field(discriminator="kind"),
]


class ReviewedSiteConfigRevisionV1(FrozenModel):
    """One immutable, human-reviewed, detached-signature site configuration."""

    schema_version: Literal["reviewed-site-config.v1"] = "reviewed-site-config.v1"
    config_revision_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ]
    revision: Annotated[int, Field(strict=True, ge=1, le=1_000_000_000)]
    site_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ]
    config: SiteConfig
    config_sha256: str
    reviewed_by: Annotated[str, Field(min_length=1, max_length=255)]
    reviewed_at: datetime
    review_reference: Annotated[str, Field(min_length=1, max_length=2048)]

    @field_validator("config_sha256")
    @classmethod
    def digest_is_canonical(cls, value: str) -> str:
        return _require_digest(value, field_name="config_sha256")

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @field_validator("review_reference")
    @classmethod
    def review_reference_is_safe(cls, value: str) -> str:
        return validate_credential_free_reference(value)

    @model_validator(mode="after")
    def digest_matches_canonical_config(self) -> ReviewedSiteConfigRevisionV1:
        if self.config_sha256 != site_config_sha256(self.config):
            raise ValueError("site configuration digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        config_revision_id: str,
        revision: int,
        site_id: str,
        config: SiteConfig,
        reviewed_by: str,
        reviewed_at: datetime,
        review_reference: str,
    ) -> ReviewedSiteConfigRevisionV1:
        return cls(
            config_revision_id=config_revision_id,
            revision=revision,
            site_id=site_id,
            config=config,
            config_sha256=site_config_sha256(config),
            reviewed_by=reviewed_by,
            reviewed_at=reviewed_at,
            review_reference=review_reference,
        )


class CameraRuleV1(FrozenModel):
    """One reviewed rule revision bound to exactly one site camera and model decision."""

    schema_version: Literal["camera-rule.v1"] = "camera-rule.v1"
    rule_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ]
    revision: Annotated[int, Field(strict=True, ge=1, le=1_000_000_000)]
    site_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ]
    camera_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ]
    module: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*$")
    ]
    enabled: Annotated[bool, Field(strict=True)]
    model_artifact_id: Annotated[str, Field(min_length=1, max_length=255)]
    model_decision_sha256: str
    minimum_confidence: float
    minimum_votes: Annotated[int, Field(strict=True, ge=1, le=64)]
    sample_count: Annotated[int, Field(strict=True, ge=1, le=64)]
    window_seconds: float
    evidence_seconds: Annotated[int, Field(strict=True, ge=4, le=10)]
    spec: RuleSpecV1
    rule_revision_sha256: str

    @field_validator("model_decision_sha256", "rule_revision_sha256")
    @classmethod
    def digests_are_canonical(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "digest")
        return _require_digest(value, field_name=field_name)

    @field_validator("minimum_confidence", mode="before")
    @classmethod
    def confidence_is_strict_finite(cls, value: object) -> float:
        return _strict_finite_number(
            value,
            field_name="minimum_confidence",
            minimum=0.0,
            maximum=1.0,
        )

    @field_validator("window_seconds", mode="before")
    @classmethod
    def window_is_strict_finite(cls, value: object) -> float:
        return _strict_finite_number(
            value,
            field_name="window_seconds",
            minimum=1e-9,
            maximum=60.0,
        )

    @model_validator(mode="after")
    def revision_digest_matches_body(self) -> CameraRuleV1:
        if self.module in {"restricted_zone", "intrusion", "loitering"}:
            if not isinstance(self.spec, ZoneRuleSpecV1):
                raise ValueError("zone analytic requires a discriminated zone rule")
            expected_mode = (
                "loitering" if self.module == "loitering" else "intrusion"
            )
            if self.spec.mode != expected_mode:
                raise ValueError("zone rule mode does not match analytic module")
        elif self.module == "line_crossing":
            if not isinstance(self.spec, LineRuleSpecV1):
                raise ValueError("line analytic requires a discriminated line rule")
            if self.minimum_votes != 1 or self.sample_count != 1:
                raise ValueError("line rule debounce must be one-of-one")
        elif not isinstance(self.spec, ModuleRuleSpecV1):
            raise ValueError("non-geometric analytic requires a module rule")
        if self.minimum_votes > self.sample_count:
            raise ValueError("minimum_votes cannot exceed sample_count")
        expected = _canonical_sha256(
            self.model_dump(mode="json", exclude={"rule_revision_sha256"})
        )
        if self.rule_revision_sha256 != expected:
            raise ValueError("camera rule revision digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        rule_id: str,
        revision: int,
        site_id: str,
        camera_id: str,
        module: str,
        enabled: bool,
        model_artifact_id: str,
        model_decision_sha256: str,
        minimum_confidence: float,
        minimum_votes: int,
        sample_count: int | None = None,
        window_seconds: float,
        evidence_seconds: int,
        spec: ModuleRuleSpecV1 | ZoneRuleSpecV1 | LineRuleSpecV1 | None = None,
    ) -> CameraRuleV1:
        if (
            type(revision) is not int
            or type(enabled) is not bool
            or type(minimum_votes) is not int
            or (
                sample_count is not None
                and type(sample_count) is not int
            )
            or type(evidence_seconds) is not int
        ):
            raise ValueError("camera rule integers and enabled flag must be strict")
        minimum_confidence = _strict_finite_number(
            minimum_confidence,
            field_name="minimum_confidence",
            minimum=0.0,
            maximum=1.0,
        )
        window_seconds = _strict_finite_number(
            window_seconds,
            field_name="window_seconds",
            minimum=1e-9,
            maximum=60.0,
        )
        if spec is None:
            spec = ModuleRuleSpecV1(
                source_module=module,
                class_names=(module,),
                reason=f"{module} candidate",
                merge_window_seconds=0.0,
                cooldown_seconds=0.0,
            )
        body = {
            "schema_version": "camera-rule.v1",
            "rule_id": rule_id,
            "revision": revision,
            "site_id": site_id,
            "camera_id": camera_id,
            "module": module,
            "enabled": enabled,
            "model_artifact_id": model_artifact_id,
            "model_decision_sha256": _require_digest(
                model_decision_sha256,
                field_name="model_decision_sha256",
            ),
            "minimum_confidence": minimum_confidence,
            "minimum_votes": minimum_votes,
            "sample_count": minimum_votes if sample_count is None else sample_count,
            "window_seconds": window_seconds,
            "evidence_seconds": evidence_seconds,
            "spec": spec.model_dump(mode="json"),
        }
        return cls(**body, rule_revision_sha256=_canonical_sha256(body))


class ReviewedCameraRulesetV1(FrozenModel):
    """One bounded reviewed ruleset; the detached signature covers this whole document."""

    schema_version: Literal["reviewed-camera-ruleset.v1"] = (
        "reviewed-camera-ruleset.v1"
    )
    ruleset_revision_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ]
    ruleset_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ]
    revision: Annotated[int, Field(strict=True, ge=1, le=1_000_000_000)]
    site_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ]
    site_config_sha256: str
    frozen_workload_sha256: str
    engine_sha256: str
    runtime_manifest_sha256: str
    rules: Annotated[tuple[CameraRuleV1, ...], Field(min_length=1, max_length=512)]
    reviewed_by: Annotated[str, Field(min_length=1, max_length=255)]
    reviewed_at: datetime
    review_reference: Annotated[str, Field(min_length=1, max_length=2048)]
    ruleset_sha256: str

    @field_validator(
        "site_config_sha256",
        "frozen_workload_sha256",
        "engine_sha256",
        "runtime_manifest_sha256",
        "ruleset_sha256",
    )
    @classmethod
    def digests_are_canonical(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "digest")
        return _require_digest(value, field_name=field_name)

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @field_validator("review_reference")
    @classmethod
    def review_reference_is_safe(cls, value: str) -> str:
        return validate_credential_free_reference(value)

    @model_validator(mode="after")
    def rules_are_unique_and_digest_matches(self) -> ReviewedCameraRulesetV1:
        identities = [rule.rule_id for rule in self.rules]
        camera_modules = [(rule.camera_id, rule.module) for rule in self.rules]
        if len(identities) != len(set(identities)):
            raise ValueError("camera rule_id values must be unique in one ruleset")
        if len(camera_modules) != len(set(camera_modules)):
            raise ValueError("one ruleset may contain only one rule per camera and module")
        if any(rule.site_id != self.site_id for rule in self.rules):
            raise ValueError("camera rule site does not match ruleset site")
        expected = _canonical_sha256(
            self.model_dump(mode="json", exclude={"ruleset_sha256"})
        )
        if self.ruleset_sha256 != expected:
            raise ValueError("camera ruleset digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        ruleset_revision_id: str,
        ruleset_id: str,
        revision: int,
        site_id: str,
        site_config_sha256: str,
        frozen_workload_sha256: str,
        engine_sha256: str,
        runtime_manifest_sha256: str,
        rules: tuple[CameraRuleV1, ...],
        reviewed_by: str,
        reviewed_at: datetime,
        review_reference: str,
    ) -> ReviewedCameraRulesetV1:
        body = {
            "schema_version": "reviewed-camera-ruleset.v1",
            "ruleset_revision_id": ruleset_revision_id,
            "ruleset_id": ruleset_id,
            "revision": revision,
            "site_id": site_id,
            "site_config_sha256": _require_digest(
                site_config_sha256,
                field_name="site_config_sha256",
            ),
            "frozen_workload_sha256": _require_digest(
                frozen_workload_sha256,
                field_name="frozen_workload_sha256",
            ),
            "engine_sha256": _require_digest(
                engine_sha256,
                field_name="engine_sha256",
            ),
            "runtime_manifest_sha256": _require_digest(
                runtime_manifest_sha256,
                field_name="runtime_manifest_sha256",
            ),
            "rules": [rule.model_dump(mode="json") for rule in rules],
            "reviewed_by": reviewed_by,
            "reviewed_at": _require_utc(reviewed_at).isoformat().replace("+00:00", "Z"),
            "review_reference": review_reference,
        }
        return cls(**body, ruleset_sha256=_canonical_sha256(body))


_VERIFIED_SITE_CONFIG_AUTHORITY = object()
_VERIFIED_RULESET_AUTHORITY = object()
_VERIFIED_GATE_DECISION_AUTHORITY = object()
_COMPILED_RULES_AUTHORITY = object()
_VERIFIED_CAPABILITY_BINDINGS: dict[object, tuple[str, ...]] = {}


def _attestation_binding(
    value: VerifiedDetachedArtifact,
) -> tuple[str, ...]:
    return (
        hashlib.sha256(value.payload).hexdigest(),
        hashlib.sha256(value.signature).hexdigest(),
        hashlib.sha256(value.trust_key).hexdigest(),
        value.payload_sha256,
        value.signature_sha256,
        value.trust_key_spki_sha256,
    )


def _copy_attestation(
    value: VerifiedDetachedArtifact,
) -> VerifiedDetachedArtifact:
    return VerifiedDetachedArtifact(
        payload=value.payload,
        signature=value.signature,
        trust_key=value.trust_key,
        payload_sha256=value.payload_sha256,
        signature_sha256=value.signature_sha256,
        trust_key_spki_sha256=value.trust_key_spki_sha256,
    )


class _OpaqueCapability:
    __slots__ = ()

    def __copy__(self) -> object:
        raise TypeError("authority capability cannot be copied")

    def __deepcopy__(self, _: object) -> object:
        raise TypeError("authority capability cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("authority capability cannot be serialized")

    def __reduce_ex__(self, _: int) -> object:
        raise TypeError("authority capability cannot be serialized")


class VerifiedSiteConfigRevision(_OpaqueCapability):
    """Opaque result of successful detached signature and document validation."""

    __slots__ = ("_attestation", "_authority", "_document")

    def __init__(
        self,
        *,
        authority: object,
        document: ReviewedSiteConfigRevisionV1,
        attestation: VerifiedDetachedArtifact,
    ) -> None:
        if authority is not _VERIFIED_SITE_CONFIG_AUTHORITY:
            raise TypeError("verified site configuration must come from signature verification")
        self._document = document
        self._attestation = attestation
        self._authority = authority
        _VERIFIED_CAPABILITY_BINDINGS[self] = _attestation_binding(attestation)

    @property
    def document(self) -> ReviewedSiteConfigRevisionV1:
        return self._document.model_copy(deep=True)

    @property
    def attestation(self) -> VerifiedDetachedArtifact:
        return _copy_attestation(self._attestation)


class VerifiedCameraRulesetRevision(_OpaqueCapability):
    """Opaque result of successful detached signature and document validation."""

    __slots__ = ("_attestation", "_authority", "_document")

    def __init__(
        self,
        *,
        authority: object,
        document: ReviewedCameraRulesetV1,
        attestation: VerifiedDetachedArtifact,
    ) -> None:
        if authority is not _VERIFIED_RULESET_AUTHORITY:
            raise TypeError("verified ruleset must come from signature verification")
        self._document = document
        self._attestation = attestation
        self._authority = authority
        _VERIFIED_CAPABILITY_BINDINGS[self] = _attestation_binding(attestation)

    @property
    def document(self) -> ReviewedCameraRulesetV1:
        return self._document.model_copy(deep=True)

    @property
    def attestation(self) -> VerifiedDetachedArtifact:
        return _copy_attestation(self._attestation)


class VerifiedModelGateDecision(_OpaqueCapability):
    """Opaque detached-signature verification result for one model gate decision."""

    __slots__ = ("_attestation", "_authority", "_decision")

    def __init__(
        self,
        *,
        authority: object,
        decision: OperationalGateDecisionEnvelopeV2,
        attestation: VerifiedDetachedArtifact,
    ) -> None:
        if authority is not _VERIFIED_GATE_DECISION_AUTHORITY:
            raise TypeError("verified gate decision must come from signature verification")
        self._decision = decision
        self._attestation = attestation
        self._authority = authority
        _VERIFIED_CAPABILITY_BINDINGS[self] = _attestation_binding(attestation)

    @property
    def decision(self) -> OperationalGateDecisionEnvelopeV2:
        return self._decision.model_copy(deep=True)

    @property
    def attestation(self) -> VerifiedDetachedArtifact:
        return _copy_attestation(self._attestation)


def _parse_signed_document(
    verified: VerifiedDetachedArtifact,
    *,
    label: str,
) -> object:
    def unique_mapping(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} document contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        decoded = verified.payload.decode("utf-8")
        if not decoded.lstrip().startswith("{"):
            raise ValueError(f"{label} document must be canonical JSON without aliases")
        payload = json.loads(
            decoded,
            object_pairs_hook=unique_mapping,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"{label} document contains non-finite number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} document is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} document must be one mapping")
    nodes = 0

    def visit(value: object, *, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > 32 or nodes > 20_000:
            raise ValueError(f"{label} document exceeds structural bounds")
        if isinstance(value, dict):
            if len(value) > 1_024:
                raise ValueError(f"{label} mapping exceeds item bound")
            for key, item in value.items():
                if not isinstance(key, str) or len(key) > 2_048:
                    raise ValueError(f"{label} mapping key is invalid")
                visit(item, depth=depth + 1)
        elif isinstance(value, list):
            if len(value) > 10_000:
                raise ValueError(f"{label} sequence exceeds item bound")
            for item in value:
                visit(item, depth=depth + 1)
        elif isinstance(value, str) and len(value) > 65_536:
            raise ValueError(f"{label} string exceeds byte-independent bound")

    visit(payload, depth=0)
    return payload


def _assert_verified_site_capability(
    value: object,
) -> VerifiedSiteConfigRevision:
    if type(value) is not VerifiedSiteConfigRevision:
        raise TypeError("site revision must be an exact verified capability")
    assert isinstance(value, VerifiedSiteConfigRevision)
    attestation = value._attestation
    if (
        value._authority is not _VERIFIED_SITE_CONFIG_AUTHORITY
        or _VERIFIED_CAPABILITY_BINDINGS.get(value)
        != _attestation_binding(attestation)
        or hashlib.sha256(attestation.payload).hexdigest()
        != attestation.payload_sha256
    ):
        raise TypeError("site revision attestation has been altered")
    captured = ReviewedSiteConfigRevisionV1.model_validate(
        _parse_signed_document(attestation, label="reviewed site configuration")
    )
    if captured != value._document:
        raise TypeError("site revision capability does not match its signed payload")
    return value


def _assert_verified_ruleset_capability(
    value: object,
) -> VerifiedCameraRulesetRevision:
    if type(value) is not VerifiedCameraRulesetRevision:
        raise TypeError("ruleset revision must be an exact verified capability")
    assert isinstance(value, VerifiedCameraRulesetRevision)
    attestation = value._attestation
    if (
        value._authority is not _VERIFIED_RULESET_AUTHORITY
        or _VERIFIED_CAPABILITY_BINDINGS.get(value)
        != _attestation_binding(attestation)
        or hashlib.sha256(attestation.payload).hexdigest()
        != attestation.payload_sha256
    ):
        raise TypeError("ruleset revision attestation has been altered")
    captured = ReviewedCameraRulesetV1.model_validate(
        _parse_signed_document(attestation, label="reviewed camera ruleset")
    )
    if captured != value._document:
        raise TypeError("ruleset capability does not match its signed payload")
    return value


def _assert_verified_gate_capability(
    value: object,
) -> VerifiedModelGateDecision:
    if type(value) is not VerifiedModelGateDecision:
        raise TypeError("gate decision must be an exact verified capability")
    assert isinstance(value, VerifiedModelGateDecision)
    attestation = value._attestation
    if (
        value._authority is not _VERIFIED_GATE_DECISION_AUTHORITY
        or _VERIFIED_CAPABILITY_BINDINGS.get(value)
        != _attestation_binding(attestation)
        or hashlib.sha256(attestation.payload).hexdigest()
        != attestation.payload_sha256
    ):
        raise TypeError("gate decision attestation has been altered")
    captured = OperationalGateDecisionEnvelopeV2.model_validate(
        _parse_signed_document(attestation, label="model gate decision")
    )
    if captured != value._decision:
        raise TypeError("gate decision capability does not match its signed payload")
    return value


def load_verified_site_config_revision(
    *,
    payload_path: Path,
    signature_path: Path,
    trusted_public_key_path: Path,
    expected_payload_sha256: str,
    expected_site_id: str,
) -> VerifiedSiteConfigRevision:
    """Capture, hash, authenticate, and validate one site configuration revision."""

    verified = verify_detached_artifact(
        payload_path=payload_path,
        signature_path=signature_path,
        trusted_public_key_path=trusted_public_key_path,
        expected_payload_sha256=expected_payload_sha256,
        max_payload_bytes=MAX_RULE_ARTIFACT_BYTES,
        label="reviewed site configuration",
    )
    document = ReviewedSiteConfigRevisionV1.model_validate(
        _parse_signed_document(verified, label="reviewed site configuration")
    )
    if document.site_id != expected_site_id:
        raise ValueError("reviewed site configuration has the wrong site")
    return VerifiedSiteConfigRevision(
        authority=_VERIFIED_SITE_CONFIG_AUTHORITY,
        document=document,
        attestation=verified,
    )


def load_verified_camera_ruleset(
    *,
    payload_path: Path,
    signature_path: Path,
    trusted_public_key_path: Path,
    expected_payload_sha256: str,
    expected_site_id: str,
) -> VerifiedCameraRulesetRevision:
    """Capture, hash, authenticate, and validate one bounded ruleset revision."""

    verified = verify_detached_artifact(
        payload_path=payload_path,
        signature_path=signature_path,
        trusted_public_key_path=trusted_public_key_path,
        expected_payload_sha256=expected_payload_sha256,
        max_payload_bytes=MAX_RULE_ARTIFACT_BYTES,
        label="reviewed camera ruleset",
    )
    document = ReviewedCameraRulesetV1.model_validate(
        _parse_signed_document(verified, label="reviewed camera ruleset")
    )
    if document.site_id != expected_site_id:
        raise ValueError("reviewed camera ruleset has the wrong site")
    return VerifiedCameraRulesetRevision(
        authority=_VERIFIED_RULESET_AUTHORITY,
        document=document,
        attestation=verified,
    )


def load_verified_model_gate_decision(
    *,
    payload_path: Path,
    signature_path: Path,
    trusted_public_key_path: Path,
    expected_payload_sha256: str,
    expected_site_id: str,
) -> VerifiedModelGateDecision:
    """Authenticate one immutable gate result before it can influence compilation."""

    verified = verify_detached_artifact(
        payload_path=payload_path,
        signature_path=signature_path,
        trusted_public_key_path=trusted_public_key_path,
        expected_payload_sha256=expected_payload_sha256,
        max_payload_bytes=256 * 1024,
        label="model gate decision",
    )
    decision = OperationalGateDecisionEnvelopeV2.model_validate(
        _parse_signed_document(verified, label="model gate decision")
    )
    if decision.decision.site_id != expected_site_id:
        raise ValueError("model gate decision has the wrong site")
    return VerifiedModelGateDecision(
        authority=_VERIFIED_GATE_DECISION_AUTHORITY,
        decision=decision,
        attestation=verified,
    )


class CompiledCameraRuleV1(FrozenModel):
    schema_version: Literal["compiled-camera-rule.v1"] = "compiled-camera-rule.v1"
    rule_id: NonEmptyString
    revision: int
    site_id: NonEmptyString
    camera_id: NonEmptyString
    module: NonEmptyString
    enabled: bool
    model_artifact_id: NonEmptyString
    model_decision_sha256: str
    gate_mode: GateMode
    minimum_confidence: float
    minimum_votes: int
    sample_count: int
    window_seconds: float
    evidence_seconds: int
    spec: RuleSpecV1
    rule_revision_sha256: str


class RuleEvaluationV1(FrozenModel):
    schema_version: Literal["rule-evaluation.v1"] = "rule-evaluation.v1"
    rule_id: NonEmptyString
    rule_revision: int
    rule_revision_sha256: str
    gate_mode: Literal["shadow", "operator"]
    model_artifact_id: NonEmptyString
    model_gate_decision_sha256: str
    evidence_seconds: int


class CameraBoundEventEngine:
    """An EventEngine boundary that refuses observations for every other camera."""

    __slots__ = ("_camera_id", "_engine")

    def __init__(self, *, camera_id: str, engine: object) -> None:
        self._camera_id = camera_id
        self._engine = engine

    @property
    def camera_id(self) -> str:
        return self._camera_id

    @property
    def status(self) -> object:
        return self._engine.status  # type: ignore[attr-defined]

    def ingest(self, observation: object) -> object:
        from protector.pilot.runtime.event_engine import EngineIngestResult

        if getattr(observation, "camera_id", None) != self._camera_id:
            return EngineIngestResult(
                accepted=False,
                rejection_reason="camera_rule_scope_mismatch",
                triggers=(),
            )
        return self._engine.ingest(observation)  # type: ignore[attr-defined]

    def advance(self, **values: object) -> object:
        if values.get("camera_id") != self._camera_id:
            return ()
        return self._engine.advance(**values)  # type: ignore[attr-defined]

    def flush(self) -> object:
        return self._engine.flush()  # type: ignore[attr-defined]


class CompiledCameraRules(_OpaqueCapability):
    """Immutable exact-camera lookup; disabled rules never produce a match."""

    __slots__ = (
        "_by_camera_module",
        "rules",
        "ruleset_revision_id",
        "ruleset_sha256",
        "site_config_revision_id",
        "site_config_sha256",
        "site_id",
    )

    def __init__(
        self,
        *,
        authority: object,
        site_id: str,
        site_config_revision_id: str,
        site_config_sha256: str,
        ruleset_revision_id: str,
        ruleset_sha256: str,
        rules: tuple[CompiledCameraRuleV1, ...],
    ) -> None:
        if authority is not _COMPILED_RULES_AUTHORITY:
            raise TypeError("compiled rules must come from verified rule compilation")
        self.site_id = site_id
        self.site_config_revision_id = site_config_revision_id
        self.site_config_sha256 = site_config_sha256
        self.ruleset_revision_id = ruleset_revision_id
        self.ruleset_sha256 = ruleset_sha256
        self.rules = rules
        self._by_camera_module = MappingProxyType(
            {(rule.camera_id, rule.module): rule for rule in rules}
        )

    def rule_ids_for_camera(self, camera_id: str) -> tuple[str, ...]:
        return tuple(
            rule.rule_id for rule in self.rules if rule.camera_id == camera_id
        )

    def build_event_engine(self, *, camera_id: str) -> CameraBoundEventEngine:
        from protector.pilot.runtime.event_engine import (
            DebounceSpec,
            EventEngine,
            LineRule,
            ModuleRule,
            ZoneRule,
        )

        selected = tuple(rule for rule in self.rules if rule.camera_id == camera_id)
        if not selected:
            raise KeyError(f"no reviewed camera rules for camera: {camera_id}")
        module_rules: list[ModuleRule] = []
        zone_rules: list[ZoneRule] = []
        line_rules: list[LineRule] = []
        for rule in selected:
            debounce = DebounceSpec(
                votes_required=rule.minimum_votes,
                sample_count=rule.sample_count,
                window_seconds=rule.window_seconds,
            )
            spec = rule.spec
            if isinstance(spec, ModuleRuleSpecV1):
                module_rules.append(
                    ModuleRule(
                        rule_id=rule.rule_id,
                        event_module=rule.module,
                        source_module=spec.source_module,
                        class_names=spec.class_names,
                        gate_mode=rule.gate_mode,
                        reason=spec.reason,
                        min_confidence=rule.minimum_confidence,
                        debounce=debounce,
                        merge_window_seconds=spec.merge_window_seconds,
                        cooldown_seconds=spec.cooldown_seconds,
                    )
                )
            elif isinstance(spec, ZoneRuleSpecV1):
                zone_rules.append(
                    ZoneRule(
                        rule_id=rule.rule_id,
                        event_module=rule.module,
                        polygon=spec.polygon,
                        mode=spec.mode,
                        gate_mode=rule.gate_mode,
                        reason=spec.reason,
                        min_confidence=rule.minimum_confidence,
                        debounce=debounce,
                        loiter_seconds=spec.loiter_seconds,
                        merge_window_seconds=spec.merge_window_seconds,
                        cooldown_seconds=spec.cooldown_seconds,
                    )
                )
            else:
                line_rules.append(
                    LineRule(
                        rule_id=rule.rule_id,
                        event_module=rule.module,
                        start=spec.start,
                        end=spec.end,
                        direction=spec.direction,
                        gate_mode=rule.gate_mode,
                        reason=spec.reason,
                        min_confidence=rule.minimum_confidence,
                        debounce=debounce,
                        merge_window_seconds=spec.merge_window_seconds,
                        cooldown_seconds=spec.cooldown_seconds,
                    )
                )
        return CameraBoundEventEngine(
            camera_id=camera_id,
            engine=EventEngine(
                module_rules=tuple(module_rules),
                zone_rules=tuple(zone_rules),
                line_rules=tuple(line_rules),
            ),
        )

    def evaluate(
        self,
        *,
        camera_id: str,
        module: str,
        confidence: float,
        votes: int,
        window_seconds: float,
    ) -> RuleEvaluationV1 | None:
        """Evaluate only the named camera's rule and return provenance, never an action."""

        rule = self._by_camera_module.get((camera_id, module))
        numeric_input_is_valid = (
            not isinstance(confidence, bool)
            and isinstance(confidence, (int, float))
            and math.isfinite(confidence)
            and not isinstance(votes, bool)
            and isinstance(votes, int)
            and not isinstance(window_seconds, bool)
            and isinstance(window_seconds, (int, float))
            and math.isfinite(window_seconds)
        )
        if (
            rule is None
            or not rule.enabled
            or rule.gate_mode == "disabled"
            or not numeric_input_is_valid
            or not 0.0 <= confidence <= 1.0
            or votes < 0
            or window_seconds < 0.0
            or confidence < rule.minimum_confidence
            or votes < rule.minimum_votes
            or window_seconds > rule.window_seconds
        ):
            return None
        return RuleEvaluationV1(
            rule_id=rule.rule_id,
            rule_revision=rule.revision,
            rule_revision_sha256=rule.rule_revision_sha256,
            gate_mode=rule.gate_mode,
            model_artifact_id=rule.model_artifact_id,
            model_gate_decision_sha256=rule.model_decision_sha256,
            evidence_seconds=rule.evidence_seconds,
        )


def compile_verified_camera_rules(
    *,
    site_revision: VerifiedSiteConfigRevision,
    ruleset_revision: VerifiedCameraRulesetRevision,
    gate_decisions: tuple[VerifiedModelGateDecision, ...],
) -> CompiledCameraRules:
    """Compile only signed site/rule revisions against exact gate decision digests."""

    checked_site_revision = _assert_verified_site_capability(site_revision)
    checked_ruleset_revision = _assert_verified_ruleset_capability(ruleset_revision)
    site_document = checked_site_revision._document
    ruleset_document = checked_ruleset_revision._document
    if ruleset_document.site_id != site_document.site_id:
        raise ValueError("ruleset site does not match site configuration")
    if ruleset_document.site_config_sha256 != site_document.config_sha256:
        raise ValueError("ruleset site configuration digest mismatch")
    feeds_by_camera = {
        feed.camera_id: feed
        for feed in site_document.config.ready_to_start.feeds
    }
    decisions: dict[tuple[str, str], OperationalGateDecisionEnvelopeV2] = {}
    for verified_decision in gate_decisions:
        checked_decision = _assert_verified_gate_capability(verified_decision)
        envelope = checked_decision._decision
        decision = envelope.decision
        if (
            decision.site_id != site_document.site_id
            or envelope.site_config_sha256 != site_document.config_sha256
            or envelope.frozen_workload_sha256
            != ruleset_document.frozen_workload_sha256
            or envelope.engine_sha256 != ruleset_document.engine_sha256
            or envelope.runtime_manifest_sha256
            != ruleset_document.runtime_manifest_sha256
        ):
            raise ValueError(
                "gate evidence is not bound to the reviewed site, workload, and runtime"
            )
        key = (decision.module, decision.artifact_id)
        if key in decisions:
            raise ValueError("gate decisions must be unique by module and artifact")
        decisions[key] = envelope

    compiled: list[CompiledCameraRuleV1] = []
    for rule in sorted(
        ruleset_document.rules,
        key=lambda item: (item.camera_id, item.module, item.rule_id, item.revision),
    ):
        if rule.site_id != site_document.site_id:
            raise ValueError("camera rule has the wrong site")
        if rule.camera_id not in feeds_by_camera:
            raise ValueError(f"camera rule references unknown camera: {rule.camera_id}")
        if rule.module not in _SUPPORTED_RULE_MODULES:
            raise ValueError("camera rule module is not approved for the controlled pilot")
        schedule_module = (
            "person"
            if rule.module
            in {
                "restricted_zone",
                "intrusion",
                "loitering",
                "line_crossing",
            }
            else rule.module
        )
        configured_hz = feeds_by_camera[rule.camera_id].analytics_hz.get(
            schedule_module
        )
        if rule.enabled and (configured_hz is None or configured_hz <= 0.0):
            raise ValueError(
                f"camera rule module is not enabled in camera schedule: {rule.camera_id}"
            )
        envelope = decisions.get((rule.module, rule.model_artifact_id))
        if (
            envelope is None
            or envelope.decision.site_id != site_document.site_id
            or envelope.authority_sha256 != rule.model_decision_sha256
        ):
            raise ValueError("camera rule model gate decision mismatch")
        decision = envelope.decision
        gate_mode: GateMode = decision.mode
        if rule.module in _SHADOW_ONLY_MODULES and gate_mode == "operator":
            gate_mode = "shadow"
        compiled.append(
            CompiledCameraRuleV1(
                rule_id=rule.rule_id,
                revision=rule.revision,
                site_id=rule.site_id,
                camera_id=rule.camera_id,
                module=rule.module,
                enabled=rule.enabled,
                model_artifact_id=rule.model_artifact_id,
                model_decision_sha256=decision.decision_sha256,
                gate_mode=gate_mode,
                minimum_confidence=rule.minimum_confidence,
                minimum_votes=rule.minimum_votes,
                sample_count=rule.sample_count,
                window_seconds=rule.window_seconds,
                evidence_seconds=rule.evidence_seconds,
                spec=rule.spec,
                rule_revision_sha256=rule.rule_revision_sha256,
            )
        )
    return CompiledCameraRules(
        authority=_COMPILED_RULES_AUTHORITY,
        site_id=site_document.site_id,
        site_config_revision_id=site_document.config_revision_id,
        site_config_sha256=site_document.config_sha256,
        ruleset_revision_id=ruleset_document.ruleset_revision_id,
        ruleset_sha256=ruleset_document.ruleset_sha256,
        rules=tuple(compiled),
    )
