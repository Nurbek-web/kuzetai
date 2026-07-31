from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from protector.pilot.domain import ObservationV1
from protector.pilot.rules import (
    CompiledCameraRuleV1,
    ModuleRuleSpecV1,
)
from protector.pilot.runtime.event_router import CameraRuleEventRouter

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
EPOCH_A = UUID("10000000-0000-0000-0000-000000000001")
EPOCH_B = UUID("20000000-0000-0000-0000-000000000002")
DIGEST = "a" * 64


def _rule(camera_id: str, rule_id: str) -> CompiledCameraRuleV1:
    return CompiledCameraRuleV1(
        rule_id=rule_id,
        revision=1,
        site_id="site-1",
        camera_id=camera_id,
        module="person",
        enabled=True,
        model_artifact_id="person-primary",
        model_decision_sha256=DIGEST,
        gate_mode="operator",
        minimum_confidence=0.5,
        minimum_votes=1,
        sample_count=1,
        window_seconds=1.0,
        evidence_seconds=4,
        spec=ModuleRuleSpecV1(
            source_module="person",
            class_names=("person",),
            reason="reviewed person candidate",
            merge_window_seconds=0.0,
            cooldown_seconds=0.0,
        ),
        rule_revision_sha256=DIGEST,
    )


def _observation(
    *,
    camera_id: str,
    epoch: UUID,
    sequence: int,
    source_time: datetime,
) -> ObservationV1:
    return ObservationV1(
        observation_id=uuid4(),
        camera_id=camera_id,
        stream_epoch=epoch,
        source_time=source_time,
        timestamp_quality="camera_rtcp",
        monotonic_seq=sequence,
        module="person",
        class_name="person",
        confidence=0.9,
        bbox=(0.1, 0.1, 0.8, 0.9),
        track_id=f"track-{sequence}",
        model_artifact_id="person-primary",
        sample_kind="fresh",
        runtime_state="online",
        received_at=source_time,
    )


def test_router_keeps_camera_epochs_and_timestamp_state_isolated() -> None:
    router = CameraRuleEventRouter.from_compiled_rules(
        rules=(
            _rule("camera-01", "rule-01"),
            _rule("camera-02", "rule-02"),
        ),
    )

    first = router.ingest(
        _observation(
            camera_id="camera-01",
            epoch=EPOCH_A,
            sequence=1,
            source_time=NOW,
        )
    )
    second = router.ingest(
        _observation(
            camera_id="camera-02",
            epoch=EPOCH_B,
            sequence=1,
            source_time=NOW - timedelta(seconds=1),
        )
    )

    assert first.accepted is True
    assert second.accepted is True
    assert first.triggers[0].event.camera_id == "camera-01"
    assert second.triggers[0].event.camera_id == "camera-02"
    assert router.active_epoch("camera-01") == EPOCH_A
    assert router.active_epoch("camera-02") == EPOCH_B


def test_router_rejects_unreviewed_camera_without_allocating_state() -> None:
    router = CameraRuleEventRouter.from_compiled_rules(
        rules=(_rule("camera-01", "rule-01"),),
    )

    result = router.ingest(
        _observation(
            camera_id="camera-99",
            epoch=EPOCH_A,
            sequence=1,
            source_time=NOW,
        )
    )

    assert result.accepted is False
    assert result.rejection_reason == "camera_rules_unavailable"
    assert result.triggers == ()
    assert router.active_epoch("camera-99") is None


def test_router_excludes_disabled_rules_and_rejects_ambiguous_bindings() -> None:
    disabled = _rule("camera-01", "rule-disabled").model_copy(
        update={"enabled": False, "gate_mode": "disabled"}
    )
    router = CameraRuleEventRouter.from_compiled_rules(rules=(disabled,))

    assert router.camera_ids == ()
    with pytest.raises(ValueError, match="unique"):
        CameraRuleEventRouter.from_compiled_rules(
            rules=(
                _rule("camera-01", "rule-01"),
                _rule("camera-01", "rule-01"),
            ),
        )
