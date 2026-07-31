from __future__ import annotations

import inspect
import unittest
from pathlib import Path

from pydantic import ValidationError

from protector.pilot.acceptance import ExecutionBindingV2
from protector.pilot import acceptance_campaign
from protector.pilot.acceptance_c2 import (
    TargetC2ContinuationEvidenceV3,
    TargetC2EvidenceV3,
    TargetEpochEvidenceV3,
    TargetExecutionTransitionEntryV3,
    TargetExecutionTransitionJournalV3,
)
from protector.pilot import acceptance_capture_v3
from protector.pilot import acceptance_controller_v3


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _epoch(number: int, disposition: str) -> TargetEpochEvidenceV3:
    digest = f"{number:x}" * 64
    return TargetEpochEvidenceV3(
        schema_version="target-epoch-evidence.v3",
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
        runtime_epoch=number,
        runtime_epoch_started_generation=number,
        launch_nonce=f"{number:032x}",
        container_id=digest,
        launch_request_sha256=digest,
        runtime_identity_sha256=digest,
        gpu_inventory_sha256=digest,
        source_profile_sha256=digest,
        native_prewarm_sha256=digest,
        unique_work_plan_sha256=digest,
        unique_work_sha256=digest,
        completion_sha256=digest,
        runtime_epoch_started_monotonic_ns=number * 1_000_000_000,
        identity_observed_monotonic_ns=number * 1_000_000_000 + 1,
        prewarm_ready_at_monotonic_ns=number * 1_000_000_000 + 2,
        measurement_started_monotonic_ns=number * 1_000_000_000 + 3,
        measurement_completed_monotonic_ns=(
            number * 1_000_000_000 + 60_000_000_003
        ),
        disposition=disposition,
    )


def _execution(number: int) -> ExecutionBindingV2:
    digest = f"{number:x}" * 64
    return ExecutionBindingV2(
        schema_version="acceptance-execution-binding.v2",
        launch_attestation_sha256="a" * 64,
        launch_nonce=f"{number:032x}",
        container_id=digest,
        container_config_sha256="b" * 64,
        runtime_image_id_sha256="c" * 64,
        acceptance_adapter_sha256="d" * 64,
        acceptance_adapter_policy_sha256="e" * 64,
        acceptance_observer_sha256="f" * 64,
        acceptance_observer_policy_sha256="1" * 64,
        control_network_id="2" * 64,
        control_network_config_sha256="3" * 64,
        camera_network_id="4" * 64,
        camera_network_config_sha256="5" * 64,
        observed_gpu_inventory_sha256="6" * 64,
    )


def _continuation(
    *,
    compatibility_boot_id: str,
) -> TargetC2ContinuationEvidenceV3:
    base = TargetC2EvidenceV3(
        schema_version="target-c2-evidence.v3",
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
        epochs=(_epoch(1, "restart"), _epoch(2, "authorize")),
    )
    previous_execution = _execution(2)
    continuation_execution = _execution(3)
    continuation_epoch = _epoch(3, "authorize")
    common = {
        "schema_version": "target-execution-transition-entry.v3",
        "collector_id": base.collector_id,
        "site_id": base.site_id,
        "campaign_id": base.campaign_id,
        "gate": base.gate,
        "runtime_restart_fault_id": "runtime-restart-01",
        "base_c2_evidence_sha256": base.evidence_sha256,
        "previous_epoch_sha256": base.epochs[-1].epoch_sha256,
        "previous_execution_binding_sha256": (
            previous_execution.binding_sha256
        ),
        "previous_runtime_identity_sha256": (
            base.epochs[-1].runtime_identity_sha256
        ),
        "continuation_launch_request_sha256": (
            continuation_epoch.launch_request_sha256
        ),
        "continuation_launch_nonce": continuation_epoch.launch_nonce,
        "continuation_runtime_epoch": continuation_epoch.runtime_epoch,
    }
    requested = TargetExecutionTransitionEntryV3(
        **common,
        sequence=1,
        phase="requested",
        previous_entry_sha256="0" * 64,
        recorded_monotonic_ns=1,
    )
    runtime_fields = {
        "continuation_execution_binding_sha256": (
            continuation_execution.binding_sha256
        ),
        "continuation_runtime_identity_sha256": (
            continuation_epoch.runtime_identity_sha256
        ),
        "continuation_runtime_boot_id": f"container:{'3' * 64}",
        "v2_compatibility_runtime_boot_id": compatibility_boot_id,
    }
    observed = TargetExecutionTransitionEntryV3(
        **common,
        **runtime_fields,
        sequence=2,
        phase="runtime_observed",
        previous_entry_sha256=requested.entry_sha256,
        recorded_monotonic_ns=2,
    )
    authorized = TargetExecutionTransitionEntryV3(
        **common,
        **runtime_fields,
        sequence=3,
        phase="authorized",
        source_profile_sha256=continuation_epoch.source_profile_sha256,
        native_prewarm_sha256=continuation_epoch.native_prewarm_sha256,
        unique_work_plan_sha256=continuation_epoch.unique_work_plan_sha256,
        unique_work_sha256=continuation_epoch.unique_work_sha256,
        completion_sha256=continuation_epoch.completion_sha256,
        previous_entry_sha256=observed.entry_sha256,
        recorded_monotonic_ns=3,
    )
    return TargetC2ContinuationEvidenceV3(
        schema_version="target-c2-continuation-evidence.v3",
        base_c2=base,
        runtime_restart_fault_id="runtime-restart-01",
        injected_monotonic_offset_seconds=40.0,
        recovered_monotonic_offset_seconds=43.0,
        previous_execution=previous_execution,
        continuation_execution=continuation_execution,
        continuation_epoch=continuation_epoch,
        continuation_runtime_boot_id=runtime_fields[
            "continuation_runtime_boot_id"
        ],
        v2_compatibility_runtime_boot_id=compatibility_boot_id,
        transition_journal=TargetExecutionTransitionJournalV3(
            schema_version="target-execution-transition-journal.v3",
            entries=(requested, observed, authorized),
        ),
    )


class AcceptanceRestartContinuationContractTests(unittest.TestCase):
    def test_exact_controller_owned_continuation_type_exists(self) -> None:
        coordinator = getattr(
            acceptance_campaign,
            "TargetRuntimeContinuationCoordinatorV3",
            None,
        )
        self.assertIsInstance(coordinator, type)
        for method in (
            "request_restart",
            "launch_replacement",
            "record_v2_recovery",
            "poll_authorization",
            "cleanup",
        ):
            self.assertTrue(callable(getattr(coordinator, method, None)))

    def test_compatibility_boot_is_derived_from_actual_epoch_three(self) -> None:
        expected = f"{_execution(2).launch_nonce}.container-{'3' * 32}"
        self.assertEqual(
            _continuation(
                compatibility_boot_id=expected,
            ).v2_compatibility_runtime_boot_id,
            expected,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "compatibility|runtime|restart|bind",
        ):
            _continuation(
                compatibility_boot_id=(
                    f"{_execution(2).launch_nonce}.container-{'9' * 32}"
                ),
            )

    def test_production_runner_requires_three_profiles_and_fresh_nonces(
        self,
    ) -> None:
        source = (
            REPOSITORY_ROOT / "scripts/pilot/replay_20.py"
        ).read_text(encoding="utf-8")
        self.assertIn("len(profile_paths) != 3", source)
        self.assertIn("len(signature_paths) != 3", source)
        self.assertIn("len(launch_nonces) != 3", source)
        self.assertIn("TargetRuntimeContinuationCoordinatorV3", source)
        self.assertNotIn(
            "_require_authoritative_retained_runtime_restart()",
            inspect.getsource(
                acceptance_campaign.TargetCampaignCoordinatorV3.run
            ),
        )

    def test_final_binding_is_data_gated_not_flag_gated(self) -> None:
        c2_source = (
            REPOSITORY_ROOT / "protector/pilot/acceptance_c2.py"
        ).read_text(encoding="utf-8")
        bind_start = c2_source.index("def bind_target_authority_v3(")
        bind_end = c2_source.index(
            "\ndef _bind_target_authority_v3_locked(",
            bind_start,
        )
        binding = c2_source[bind_start:bind_end]
        self.assertNotIn(
            "_require_target_runtime_restart_continuation_authority()",
            binding,
        )
        self.assertIn(
            "_require_continuation_capability",
            binding,
        )

    def test_capture_and_snapshot_paths_require_signed_continuation(self) -> None:
        capture_source = inspect.getsource(
            acceptance_capture_v3.ProtectedAcceptanceCaptureRepositoryV3
        )
        controller_source = inspect.getsource(
            acceptance_controller_v3.CollectorBoundAcceptanceControllerV3
        )
        self.assertIn(
            "require_target_authority_continuation_v3",
            capture_source,
        )
        self.assertIn(
            "require_target_authority_continuation_v3",
            controller_source,
        )
        self.assertNotIn(
            "_require_target_runtime_restart_continuation_authority()",
            controller_source,
        )

    def test_runner_finalizes_only_through_packaged_v3_route(self) -> None:
        replay_source = (
            REPOSITORY_ROOT / "scripts/pilot/replay_20.py"
        ).read_text(encoding="utf-8")
        production_start = replay_source.index(
            "def _run_production_target_v3_locked("
        )
        production_end = replay_source.index(
            "\ndef run_target(",
            production_start,
        )
        production = replay_source[production_start:production_end]

        self.assertIn(
            "/api/internal/acceptance/v3/collectors/",
            replay_source,
        )
        self.assertIn("collector.finalize_v3(", production)
        self.assertNotIn("AcceptanceAuthorityStateStoreV3(", production)
        self.assertNotIn("AcceptanceAuthoritySnapshotStoreV3(", production)
        self.assertNotIn("AcceptanceProofStoreV3(", production)
        self.assertNotIn("CollectorBoundAcceptanceControllerV3(", production)


if __name__ == "__main__":
    unittest.main()
