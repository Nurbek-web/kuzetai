from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from protector.pilot.domain import (
    CameraEpochActivationReceiptV1,
    RuntimeWriterReceiptV1,
)
from protector.pilot.runtime.camera_epoch_fence import (
    CameraEpochFencedEventService,
    CameraEpochFenceError,
)
from protector.pilot.runtime.provenance import (
    ProvenanceRuleBinding,
    RuntimeCandidateAuthority,
)

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
EPOCH_A = UUID("10000000-0000-0000-0000-000000000001")
EPOCH_B = UUID("20000000-0000-0000-0000-000000000002")
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


def _writer() -> RuntimeWriterReceiptV1:
    return RuntimeWriterReceiptV1._issue(
        site_id="site-1",
        runtime_session_id="runtime-1",
        runtime_writer_generation=7,
        configuration_activation_generation=4,
        config_revision_id="config-1",
        site_config_sha256=DIGEST_A,
        ruleset_revision_id="rules-1",
        ruleset_sha256=DIGEST_B,
        rule_revision_digests={"rule-1": DIGEST_C},
        issued_at=NOW,
    )


def _authority() -> RuntimeCandidateAuthority:
    return RuntimeCandidateAuthority(
        writer_receipt=_writer(),
        rule_bindings=(
            ProvenanceRuleBinding(
                rule_id="rule-1",
                revision=1,
                rule_revision_sha256=DIGEST_C,
                camera_id="camera-01",
                module="person",
                model_artifact_id="person-primary",
                model_gate_decision_sha256=DIGEST_D,
                gate_mode="operator",
            ),
        ),
    )


class _Repository:
    def __init__(self) -> None:
        self.calls: list[tuple[str, UUID, UUID | None]] = []
        self.return_wrong_camera = False

    def activate_camera_epoch(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        camera_id: str,
        source_epoch: UUID,
        expected_source_epoch: UUID | None,
        activated_at: datetime,
    ) -> CameraEpochActivationReceiptV1:
        self.calls.append((camera_id, source_epoch, expected_source_epoch))
        return CameraEpochActivationReceiptV1(
            site_id=receipt.site_id,
            camera_id="camera-02" if self.return_wrong_camera else camera_id,
            source_epoch=source_epoch,
            previous_source_epoch=expected_source_epoch,
            runtime_session_id=receipt.runtime_session_id,
            runtime_writer_generation=receipt.runtime_writer_generation,
            configuration_activation_generation=(
                receipt.configuration_activation_generation
            ),
            activated_at=activated_at,
        )


class _Delegate:
    def __init__(self) -> None:
        self.started = 0
        self.processed: list[object] = []
        self.periodic: list[tuple[str, UUID, datetime]] = []

    def start(self) -> str:
        self.started += 1
        return "started"

    def process(self, observation: object) -> str:
        self.processed.append(observation)
        return "processed"

    def run_periodic(
        self,
        *,
        camera_id: str,
        stream_epoch: UUID,
        source_time: datetime,
    ) -> str:
        self.periodic.append((camera_id, stream_epoch, source_time))
        return "periodic"


class _Observation:
    camera_id = "camera-01"
    stream_epoch = EPOCH_A
    source_time = NOW


def test_epoch_fence_commits_causal_epochs_before_event_processing() -> None:
    repository = _Repository()
    delegate = _Delegate()
    service = CameraEpochFencedEventService(
        delegate=delegate,
        repository=repository,
        authority=_authority(),
        event_camera_ids=("camera-01",),
        clock=lambda: NOW,
    )

    assert service.start() == "started"
    assert service.process(_Observation()) == "processed"
    assert service.process(_Observation()) == "processed"
    assert service.run_periodic(
        camera_id="camera-01",
        stream_epoch=EPOCH_B,
        source_time=NOW + timedelta(seconds=1),
    ) == "periodic"

    assert repository.calls == [
        ("camera-01", EPOCH_A, None),
        ("camera-01", EPOCH_B, EPOCH_A),
    ]
    assert delegate.processed == [_Observation(), _Observation()]


def test_epoch_fence_fails_closed_before_delegate_on_invalid_receipt() -> None:
    repository = _Repository()
    repository.return_wrong_camera = True
    delegate = _Delegate()
    service = CameraEpochFencedEventService(
        delegate=delegate,
        repository=repository,
        authority=_authority(),
        event_camera_ids=("camera-01",),
        clock=lambda: NOW,
    )

    with pytest.raises(CameraEpochFenceError):
        service.process(_Observation())

    assert delegate.processed == []


def test_epoch_fence_does_not_claim_authority_for_unreviewed_camera() -> None:
    repository = _Repository()
    delegate = _Delegate()
    service = CameraEpochFencedEventService(
        delegate=delegate,
        repository=repository,
        authority=_authority(),
        event_camera_ids=("camera-01",),
        clock=lambda: NOW,
    )

    service.run_periodic(
        camera_id="camera-02",
        stream_epoch=EPOCH_A,
        source_time=NOW,
    )

    assert repository.calls == []
    assert delegate.periodic == [("camera-02", EPOCH_A, NOW)]
