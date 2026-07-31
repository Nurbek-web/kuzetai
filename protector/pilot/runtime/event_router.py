"""Camera-scoped event-engine routing for one shared multistream runtime."""

from __future__ import annotations

from collections import defaultdict
from types import MappingProxyType
from typing import Iterable
from uuid import UUID

from protector.pilot.domain import ObservationV1
from protector.pilot.rules import (
    CompiledCameraRuleV1,
    LineRuleSpecV1,
    ModuleRuleSpecV1,
    ZoneRuleSpecV1,
)
from protector.pilot.runtime.event_engine import (
    CandidateTrigger,
    DebounceSpec,
    EngineIngestResult,
    EngineLimits,
    EventEngine,
    LineRule,
    ModuleRule,
    ZoneRule,
)

_MAX_RULES = 512
_MAX_CAMERAS = 64


class CameraRuleEventRouter:
    """Route metadata into bounded camera-local state behind one shared graph."""

    __slots__ = ("_engines", "limits")

    def __init__(
        self,
        *,
        engines: dict[str, EventEngine],
        limits: EngineLimits,
    ) -> None:
        if (
            not engines
            or len(engines) > min(_MAX_CAMERAS, limits.max_cameras)
            or any(
                not camera_id or type(engine) is not EventEngine
                for camera_id, engine in engines.items()
            )
        ):
            raise ValueError("event router requires a finite camera-engine map")
        self._engines = MappingProxyType(dict(sorted(engines.items())))
        self.limits = limits

    @classmethod
    def from_compiled_rules(
        cls,
        *,
        rules: tuple[CompiledCameraRuleV1, ...],
        limits: EngineLimits | None = None,
    ) -> CameraRuleEventRouter:
        """Rebuild CPU-only camera state from already reviewed compiled rules."""

        if type(rules) is not tuple or not 1 <= len(rules) <= _MAX_RULES:
            raise ValueError("compiled event rules must be one bounded tuple")
        if any(type(rule) is not CompiledCameraRuleV1 for rule in rules):
            raise TypeError("compiled event rules must use exact contracts")
        identities = tuple(rule.rule_id for rule in rules)
        camera_modules = tuple((rule.camera_id, rule.module) for rule in rules)
        if len(set(identities)) != len(identities) or len(set(camera_modules)) != len(
            camera_modules
        ):
            raise ValueError("compiled event rule identities must be unique")
        selected = tuple(
            rule
            for rule in rules
            if rule.enabled and rule.gate_mode in {"shadow", "operator"}
        )
        configured_limits = limits or EngineLimits(max_cameras=_MAX_CAMERAS)
        grouped: dict[str, list[CompiledCameraRuleV1]] = defaultdict(list)
        for rule in selected:
            grouped[rule.camera_id].append(rule)
        if not grouped:
            # A fully disabled reviewed ruleset is valid, but it must remain an
            # explicit no-candidate router rather than an unbounded fallback.
            return _DisabledCameraRuleEventRouter(  # type: ignore[return-value]
                limits=configured_limits
            )
        return cls(
            engines={
                camera_id: _build_camera_engine(
                    camera_rules,
                    limits=configured_limits,
                )
                for camera_id, camera_rules in grouped.items()
            },
            limits=configured_limits,
        )

    @property
    def camera_ids(self) -> tuple[str, ...]:
        return tuple(self._engines)

    def ingest(self, observation: ObservationV1) -> EngineIngestResult:
        if type(observation) is not ObservationV1:
            raise TypeError("event router requires an exact observation")
        engine = self._engines.get(observation.camera_id)
        if engine is None:
            return EngineIngestResult(
                accepted=False,
                rejection_reason="camera_rules_unavailable",
                triggers=(),
            )
        return engine.ingest(observation)

    def advance(
        self,
        *,
        camera_id: str,
        stream_epoch: UUID,
        source_time: object,
    ) -> tuple[CandidateTrigger, ...]:
        engine = self._engines.get(camera_id)
        if engine is None:
            return ()
        return engine.advance(
            camera_id=camera_id,
            stream_epoch=stream_epoch,
            source_time=source_time,  # type: ignore[arg-type]
        )

    def active_epoch(self, camera_id: str) -> UUID | None:
        engine = self._engines.get(camera_id)
        return None if engine is None else engine.active_epoch(camera_id)

    def flush(self) -> tuple[CandidateTrigger, ...]:
        return tuple(
            trigger
            for camera_id in self.camera_ids
            for trigger in self._engines[camera_id].flush()
        )


class _DisabledCameraRuleEventRouter(CameraRuleEventRouter):
    """Exact no-rule implementation used when every reviewed rule is disabled."""

    __slots__ = ()

    def __init__(self, *, limits: EngineLimits) -> None:
        self._engines = MappingProxyType({})
        self.limits = limits


def _build_camera_engine(
    rules: Iterable[CompiledCameraRuleV1],
    *,
    limits: EngineLimits,
) -> EventEngine:
    module_rules: list[ModuleRule] = []
    zone_rules: list[ZoneRule] = []
    line_rules: list[LineRule] = []
    for rule in rules:
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
        elif isinstance(spec, LineRuleSpecV1):
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
        else:  # pragma: no cover - Pydantic's discriminated union owns this.
            raise TypeError("compiled event rule has an unsupported specification")
    return EventEngine(
        module_rules=tuple(module_rules),
        zone_rules=tuple(zone_rules),
        line_rules=tuple(line_rules),
        limits=limits,
        initial_evidence_status="pending",
    )


__all__ = ("CameraRuleEventRouter",)
