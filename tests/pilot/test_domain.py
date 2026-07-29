from __future__ import annotations

from datetime import timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from protector.pilot.domain import CandidateEventV1, NotificationOutboxRecordV1, ObservationV1


def _observation_payload() -> dict[str, object]:
    return {
        "schema_version": "observation.v1",
        "observation_id": "d1e5c479-21b3-4dfc-8f67-08bb8818a89d",
        "camera_id": "camera-01",
        "stream_epoch": "7cce5d2c-b077-4dd6-b9ec-1f0a46aa0aec",
        "source_time": "2026-07-22T09:30:00Z",
        "timestamp_quality": "camera_rtcp",
        "monotonic_seq": 42,
        "module": "weapon",
        "class_name": "handgun",
        "confidence": 0.91,
        "bbox": [0.1, 0.2, 0.8, 0.9],
        "track_id": "track-17",
        "model_artifact_id": "weapon-rfdetr-2026-07-22",
        "sample_kind": "fresh",
        "runtime_state": "online",
        "received_at": "2026-07-22T09:30:01Z",
    }


def _event_payload(*, gate_mode: str = "operator") -> dict[str, object]:
    return {
        "schema_version": "candidate-event.v1",
        "event_id": "e99f0a47-86b8-4e9c-997b-7c54c8fca2fc",
        "camera_id": "camera-01",
        "module": "weapon",
        "opened_at": "2026-07-22T09:30:00Z",
        "last_seen_at": "2026-07-22T09:30:02Z",
        "peak_confidence": 0.91,
        "reason": "verified handgun candidate",
        "model_artifact_id": "weapon-rfdetr-2026-07-22",
        "gate_mode": gate_mode,
        "evidence_status": "pending",
        "review_status": "candidate",
    }


def test_observation_round_trips_as_immutable_json_with_a_deterministic_dedupe_key():
    observation = ObservationV1.model_validate(_observation_payload())
    restored = ObservationV1.model_validate_json(observation.model_dump_json())

    assert restored == observation
    assert restored.dedupe_key == (
        "camera-01:7cce5d2c-b077-4dd6-b9ec-1f0a46aa0aec:42:weapon:"
        "weapon-rfdetr-2026-07-22"
    )
    assert restored.source_time.tzinfo == timezone.utc
    assert isinstance(restored.observation_id, UUID)
    with pytest.raises(ValidationError):
        restored.camera_id = "camera-02"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "observation.v2"),
        ("source_time", "2026-07-22T09:30:00"),
        ("received_at", "2026-07-22T09:30:01"),
        ("bbox", [0.1, 0.2, 1.1, 0.9]),
        ("bbox", [0.8, 0.2, 0.1, 0.9]),
    ],
)
def test_observation_rejects_an_incompatible_contract_or_invalid_fresh_signal(
    field: str, value: object
):
    payload = _observation_payload()
    payload[field] = value

    with pytest.raises(ValidationError):
        ObservationV1.model_validate(payload)


def test_cached_display_observations_cannot_be_used_as_fresh_event_votes():
    payload = _observation_payload()
    payload["sample_kind"] = "cached_display"
    payload["runtime_state"] = "online"

    observation = ObservationV1.model_validate(payload)

    assert observation.is_fresh is False


def test_observation_freshness_is_independent_from_runtime_health_context():
    fresh_degraded = _observation_payload()
    fresh_degraded["runtime_state"] = "degraded"
    cached_online = _observation_payload()
    cached_online["sample_kind"] = "cached_display"

    assert ObservationV1.model_validate(fresh_degraded).is_fresh is True
    assert ObservationV1.model_validate(cached_online).is_fresh is False


def test_candidate_event_transitions_only_through_human_review_states():
    event = CandidateEventV1.model_validate(_event_payload())

    confirmed = event.transition_to("confirmed")
    escalated = confirmed.transition_to("escalated")

    assert confirmed.review_status == "confirmed"
    assert escalated.review_status == "escalated"
    assert event.dedupe_key == (
        f"{event.event_id}:camera-01:weapon:weapon-rfdetr-2026-07-22:"
        "2026-07-22T09:30:00+00:00"
    )
    with pytest.raises(ValueError, match="illegal event transition"):
        event.transition_to("escalated")
    with pytest.raises(ValueError, match="illegal event transition"):
        confirmed.transition_to("rejected")


@pytest.mark.parametrize("gate_mode", ["shadow", "disabled"])
def test_nonoperator_events_cannot_create_notification_outbox_records(gate_mode: str):
    event = CandidateEventV1.model_validate(_event_payload(gate_mode=gate_mode)).transition_to(
        "confirmed"
    )

    with pytest.raises(ValueError, match="operator gate mode"):
        NotificationOutboxRecordV1.from_confirmed_event(event, idempotency_key="notify-1")


def test_only_confirmed_operator_events_create_notification_outbox_records():
    event = CandidateEventV1.model_validate(_event_payload()).transition_to("confirmed")

    outbox = NotificationOutboxRecordV1.from_confirmed_event(event, idempotency_key="notify-1")

    assert outbox.event_id == event.event_id
    assert outbox.idempotency_key == "notify-1"
    assert outbox.schema_version == "notification-outbox.v1"


def test_confirmed_event_snapshot_requires_and_round_trips_legal_transition_provenance():
    direct_confirmed = _event_payload()
    direct_confirmed["review_status"] = "confirmed"

    with pytest.raises(ValidationError, match="transition_history"):
        CandidateEventV1.model_validate(direct_confirmed)

    event = CandidateEventV1.model_validate(_event_payload()).transition_to("confirmed")
    restored = CandidateEventV1.model_validate_json(event.model_dump_json())
    outbox = NotificationOutboxRecordV1.from_confirmed_event(restored, idempotency_key="notify-2")

    assert restored.transition_history == ("observation", "candidate", "confirmed")
    assert outbox.event_id == event.event_id
