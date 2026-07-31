from __future__ import annotations

import copy
import hashlib
import os
import pickle
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from protector.pilot.acceptance import (
    LaunchAttestationV2,
    ScheduledFaultV2,
)
from protector.pilot.acceptance_authority import (
    AcceptanceFaultAckResponseV2,
)
from protector.pilot import acceptance_campaign as campaign_module
from protector.pilot.acceptance_c2 import (
    SQLiteTargetExecutionTransitionJournalV3,
    TargetC2EvidenceV3,
    TargetEpochEvidenceV3,
    _execution_binding_from_runtime_identity,
    _peek_transition_journal_capability,
)
from protector.pilot.acceptance_campaign import (
    TargetCampaignCompletionV3,
    TargetRuntimeContinuationCoordinatorV3,
    _advance_target_runtime_restart_v3,
    _make_authenticated_fault_acknowledgement_tools,
    _require_distinct_authority_files,
)
from protector.pilot.acceptance_target import (
    ObservedGpuDeviceV2,
    ObservedGpuInventoryV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
    TargetRuntimeObservationV2,
    TargetSourceBindingV2,
)
from protector.pilot.acceptance_target_controller import (
    TargetRuntimeControllerEnvironmentV2,
)

GPU_UUID = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def _inventory() -> ObservedGpuInventoryV2:
    return ObservedGpuInventoryV2(
        schema_version="observed-gpu-inventory.v2",
        devices=(
            ObservedGpuDeviceV2(
                uuid=GPU_UUID,
                product_name="NVIDIA L4",
                pci_bus_id="0000:01:00.0",
                total_vram_bytes=24_000_000_000,
                compute_capability="8.9",
                mig_mode="disabled",
            ),
        ),
        nvidia_driver_version="570.86.15",
        cuda_driver_version="12.8",
        cuda_runtime_version="12.8",
        nvidia_container_toolkit_version="1.17.4",
    )


def _launch(inventory: ObservedGpuInventoryV2) -> LaunchAttestationV2:
    return LaunchAttestationV2(
        schema_version="acceptance-launch-attestation.v2",
        site_id="school-01",
        site_config_file_sha256="1" * 64,
        site_config_sha256="2" * 64,
        runtime_manifest_file_sha256="3" * 64,
        measured_capacity_file_sha256="4" * 64,
        capacity_signature_sha256="5" * 64,
        capacity_trust_key_spki_sha256="6" * 64,
        artifact_id="person-primary-v1",
        artifact_sha256="7" * 64,
        registry_entry_sha256="8" * 64,
        frozen_workload_sha256="9" * 64,
        expected_workload_sha256="9" * 64,
        engine_sha256="b" * 64,
        image_sha256="c" * 64,
        runtime_image_id_sha256="d" * 64,
        runtime_image_config_sha256="e" * 64,
        runtime_code_sha256="f" * 64,
        mount_contract_sha256="0" * 64,
        control_network="kuzet-control",
        camera_network="kuzet-camera",
        expected_control_network_id="1" * 64,
        expected_control_network_config_sha256="2" * 64,
        expected_camera_network_id="3" * 64,
        expected_camera_network_config_sha256="4" * 64,
        gpu_device_ids=(GPU_UUID,),
        gpu_product_name="NVIDIA L4",
        gpu_pci_bus_id="0000:01:00.0",
        gpu_total_vram_bytes=24_000_000_000,
        gpu_compute_capability="8.9",
        gpu_mig_mode="disabled",
        gpu_inventory_sha256=inventory.launch_compatibility_sha256,
        nvidia_driver_version="570.86.15",
        cuda_driver_version="12.8",
        cuda_runtime_version="12.8",
        nvidia_container_toolkit_version="1.17.4",
        acceptance_adapter_sha256="5" * 64,
        acceptance_adapter_policy_sha256="6" * 64,
        acceptance_observer_sha256="7" * 64,
        acceptance_observer_policy_sha256="8" * 64,
        runtime_api_host="api",
        runtime_api_port=8000,
        controller_api_host="127.0.0.1",
        controller_api_port=8765,
        run_authority_public_key_spki_sha256="9" * 64,
        source_profiles_sha256="b" * 64,
        required_throughput_hz=100.0,
        measured_effective_throughput_hz=125.0,
        stream_count=20,
    )


def _bindings() -> tuple[TargetSourceBindingV2, ...]:
    return tuple(
        TargetSourceBindingV2(
            camera_id=f"camera-{index:02}",
            source_index=index,
            source_identity_commitment=hashlib.sha256(
                f"source-{index}".encode()
            ).hexdigest(),
        )
        for index in range(20)
    )


def _request(
    epoch: int,
    *,
    inventory: ObservedGpuInventoryV2,
    launch: LaunchAttestationV2,
) -> TargetRuntimeLaunchRequestV2:
    return TargetRuntimeLaunchRequestV2(
        schema_version="target-runtime-launch-request.v2",
        campaign_id="campaign-01",
        gate="8h",
        launch_nonce=f"{epoch:032x}",
        manifest_sha256="2" * 64,
        acceptance_trust_binding_sha256="3" * 64,
        module_gate_bindings_sha256="4" * 64,
        controller_image_id_sha256="5" * 64,
        controller_image_config_sha256="6" * 64,
        controller_code_sha256="7" * 64,
        runtime_epoch=epoch,
        runtime_epoch_started_generation=epoch,
        launch=launch,
        source_bindings=_bindings(),
    )


def _identity(
    request: TargetRuntimeLaunchRequestV2,
    inventory: ObservedGpuInventoryV2,
) -> TargetRuntimeIdentityV2:
    container_id = f"{request.runtime_epoch:064x}"
    return TargetRuntimeIdentityV2(
        schema_version="target-runtime-identity.v2",
        launch_request=request,
        process_id=f"docker:{container_id}",
        runtime_boot_id=f"container:{container_id}",
        container_id=container_id,
        container_config_sha256="9" * 64,
        runtime_image_id_sha256=request.launch.runtime_image_id_sha256,
        runtime_image_config_sha256=(
            request.launch.runtime_image_config_sha256
        ),
        runtime_code_sha256=request.launch.runtime_code_sha256,
        mount_contract_sha256=request.launch.mount_contract_sha256,
        controller_image_id_sha256=request.controller_image_id_sha256,
        controller_image_config_sha256=(
            request.controller_image_config_sha256
        ),
        controller_code_sha256=request.controller_code_sha256,
        control_network_id=request.launch.expected_control_network_id,
        control_network_config_sha256=(
            request.launch.expected_control_network_config_sha256
        ),
        camera_network_id=request.launch.expected_camera_network_id,
        camera_network_config_sha256=(
            request.launch.expected_camera_network_config_sha256
        ),
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=(
            request.runtime_epoch_started_generation
        ),
        runtime_epoch_started_monotonic_ns=(
            request.runtime_epoch * 1_000_000_000
        ),
        identity_observed_monotonic_ns=(
            request.runtime_epoch * 1_000_000_000 + 1
        ),
        observed_gpu_inventory=inventory,
        source_bindings=request.source_bindings,
    )


def _epoch(
    identity: TargetRuntimeIdentityV2,
    disposition: str,
) -> TargetEpochEvidenceV3:
    request = identity.launch_request
    digest = f"{request.runtime_epoch:x}" * 64
    started = identity.runtime_epoch_started_monotonic_ns
    return TargetEpochEvidenceV3(
        schema_version="target-epoch-evidence.v3",
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=request.runtime_epoch,
        launch_nonce=request.launch_nonce,
        container_id=identity.container_id,
        launch_request_sha256=request.request_sha256,
        runtime_identity_sha256=identity.identity_sha256,
        gpu_inventory_sha256=identity.observed_gpu_inventory.inventory_sha256,
        source_profile_sha256=digest,
        native_prewarm_sha256=digest,
        unique_work_plan_sha256=digest,
        unique_work_sha256=digest,
        completion_sha256=digest,
        runtime_epoch_started_monotonic_ns=started,
        identity_observed_monotonic_ns=started + 1,
        prewarm_ready_at_monotonic_ns=started + 60_000_000_000,
        measurement_started_monotonic_ns=started + 60_000_000_001,
        measurement_completed_monotonic_ns=(
            started + 120_000_000_001
        ),
        disposition=disposition,
    )


class _Runtime:
    def __init__(
        self,
        identity: TargetRuntimeIdentityV2,
        events: list[str],
        label: str,
        *,
        wait_code: int = 0,
    ) -> None:
        self.identity = identity
        self.events = events
        self.label = label
        self.wait_code = wait_code
        self.cleanup_count = 0

    def reverify_identity(self) -> TargetRuntimeIdentityV2:
        self.events.append(f"{self.label}:reverify")
        return self.identity

    def poll(self) -> None:
        self.events.append(f"{self.label}:poll")
        return None

    def terminate(self, *, timeout_seconds: int) -> None:
        self.events.append(f"{self.label}:terminate")

    def wait(self, *, timeout_seconds: float) -> int:
        self.events.append(f"{self.label}:wait")
        return self.wait_code

    def cleanup(self) -> None:
        self.cleanup_count += 1
        self.events.append(f"{self.label}:cleanup")
        if self.cleanup_count > 1:
            raise RuntimeError(f"{self.label} cleaned more than once")


class _Channel:
    def __init__(self, path: Path, events: list[str], label: str) -> None:
        self.runtime_claim_path = path
        self.events = events
        self.label = label
        self.abort_count = 0
        self.result_available = False
        self.ack_available = False
        self.directive_count = 0
        self.native = SimpleNamespace(projection_sha256="a" * 64)
        self.result = SimpleNamespace(
            native_prewarm=self.native,
            unique_work_projection=object(),
        )

    def publish_grant(self, **_kwargs: object) -> object:
        self.events.append(f"{self.label}:grant")
        return object()

    def consume_result(self) -> tuple[object, object]:
        if not self.result_available:
            raise FileNotFoundError
        return self.result, object()

    def publish_directive(self, *, action: str) -> None:
        if action != "authorize":
            raise AssertionError(action)
        self.directive_count += 1
        self.events.append(f"{self.label}:directive")

    def consume_ack(self) -> object:
        if not self.ack_available:
            raise FileNotFoundError
        self.events.append(f"{self.label}:ack")
        return object()

    def abort(self) -> None:
        self.abort_count += 1
        self.events.append(f"{self.label}:abort")
        if self.abort_count > 1:
            raise RuntimeError(f"{self.label} aborted more than once")


class _Journal:
    def __init__(self) -> None:
        self.responses: dict[str, dict[str, object]] = {}

    def response(self, key: str) -> dict[str, object] | None:
        value = self.responses.get(key)
        return None if value is None else dict(value)


class _FakeCollector:
    def __init__(
        self,
        *,
        fault: ScheduledFaultV2,
        execution: object,
        compatibility_boot_id: str,
        issue: object,
        events: list[str],
    ) -> None:
        self._operation_lock = threading.RLock()
        self._binding = {
            "collector_id": "collector-01",
            "site_id": "school-01",
            "manifest_sha256": "2" * 64,
            "gate": "8h",
            "launch_attestation_sha256": (
                execution.launch_attestation_sha256
            ),
            "execution_binding_sha256": execution.binding_sha256,
            "fault_schedule_sha256": "f" * 64,
            "trust_binding": None,
        }
        self._schedule = {fault.fault_id: fault}
        self._fault_acknowledgements: dict[
            tuple[str, str],
            dict[str, object],
        ] = {}
        self._journal = _Journal()
        self._fault = fault
        self._execution = execution
        self._compatibility_boot_id = compatibility_boot_id
        self._issue = issue
        self.events = events

    def acknowledgement(
        self,
        *,
        boot_id: str | None = None,
        committed_prepare_only: bool = False,
    ) -> tuple[AcceptanceFaultAckResponseV2, object]:
        acknowledgement = AcceptanceFaultAckResponseV2(
            schema_version="acceptance-fault-ack-response.v2",
            **self._binding,
            fault_id=self._fault.fault_id,
            phase="recover",
            commanded_monotonic_offset_seconds=43.0,
            command_id="runtime-restart-recover",
            state="online",
            runtime_boot_id=boot_id or self._compatibility_boot_id,
            api_boot_id="api-boot-01",
            observed_at=datetime.now(UTC),
        )
        encoded = acknowledgement.model_dump(mode="json")
        self._fault_acknowledgements[
            (acknowledgement.fault_id, acknowledgement.phase)
        ] = encoded
        if committed_prepare_only:
            self._journal.responses.pop(
                f"fault-ack:{acknowledgement.command_id}",
                None,
            )
            self._journal.responses[
                f"fault-prepare:{acknowledgement.fault_id}:recover"
            ] = {
                **encoded,
                "schema_version": (
                    "acceptance-fault-prepare-response.v2"
                ),
                "state": "COMMITTED",
            }
        else:
            self._journal.responses[
                f"fault-ack:{acknowledgement.command_id}"
            ] = encoded
        capability = self._issue(
            acknowledgement=acknowledgement,
            collector=self,
        )
        return acknowledgement, capability

    def command_fault(
        self,
        *,
        fault_id: str,
        phase: str,
        at_offset: float,
    ) -> object:
        self.events.extend(
            (
                f"collector:{phase}:{at_offset:g}",
                f"executor:{phase}",
                f"observer:{phase}",
            )
        )
        if fault_id != self._fault.fault_id:
            raise AssertionError(fault_id)
        if phase == "inject":
            return object()
        _acknowledgement, capability = self.acknowledgement()
        return capability


def _coordinator(
    *,
    request: TargetRuntimeLaunchRequestV2,
    runtime3: _Runtime,
    channel3: _Channel,
    collector: _FakeCollector,
    journal: SQLiteTargetExecutionTransitionJournalV3,
) -> TargetRuntimeContinuationCoordinatorV3:
    coordinator = object.__new__(TargetRuntimeContinuationCoordinatorV3)
    coordinator._collector_id = "collector-01"
    coordinator._trust_context = object()
    coordinator._request = request
    coordinator._graph = object()
    coordinator._channel_root = channel3.runtime_claim_path.parent
    coordinator._environment_factory = lambda *_args: (
        TargetRuntimeControllerEnvironmentV2(
            engine_path=Path("/usr/bin/docker"),
            nvidia_ctk_path=Path("/usr/bin/nvidia-ctk"),
            command=("runtime",),
            reviewed_mount_argv=(),
        )
    )
    coordinator._source_profile_provider = lambda _request: (
        SimpleNamespace(verified_binding_sha256="b" * 64)
    )
    coordinator._transition_journal = journal
    coordinator._authenticated_collector = collector
    coordinator._runtime_launcher = lambda *_args: (
        runtime3,
        TargetRuntimeObservationV2(identity=runtime3.identity),
    )
    coordinator._child_grant_hook = None
    coordinator._reviewed_mount_sources = frozenset()
    coordinator._stop_grace_seconds = 30
    coordinator._configuration_capability = object()
    coordinator._stage = "configured"
    coordinator._campaign = None
    coordinator._fault = None
    coordinator._previous_execution = None
    coordinator._requested = None
    coordinator._observed = None
    coordinator._runtime = None
    coordinator._channel = None
    coordinator._identity = None
    coordinator._source_profile = None
    coordinator._plan = None
    coordinator._plan_authority = None
    coordinator._result = None
    coordinator._channel_receipt = None
    coordinator._work_capability = None
    coordinator._work_projection = None
    coordinator._directive_published = False
    coordinator._completion = None
    coordinator._cleanup_started = False
    coordinator._lock = threading.RLock()
    coordinator._require_configuration = lambda: None
    return coordinator


class AcceptanceRestartContinuationBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        register, consume = (
            _make_authenticated_fault_acknowledgement_tools()
        )
        cls.register = staticmethod(register)
        cls.consume = staticmethod(consume)
        cls.issue = staticmethod(
            register(_FakeCollector)
        )

    def setUp(self) -> None:
        self.inventory = _inventory()
        self.launch = _launch(self.inventory)
        self.requests = tuple(
            _request(
                epoch,
                inventory=self.inventory,
                launch=self.launch,
            )
            for epoch in (1, 2, 3)
        )
        self.identities = tuple(
            _identity(request, self.inventory)
            for request in self.requests
        )
        self.execution = _execution_binding_from_runtime_identity(
            self.identities[1]
        )
        self.fault = ScheduledFaultV2(
            fault_id="fault-03-runtime-restart",
            kind="runtime_restart",
            target="shared-runtime",
            offset_seconds=40.0,
            duration_seconds=3.0,
            expected_degraded="offline",
            expected_recovery="online",
        )
        self.events: list[str] = []
        compatibility_boot_id = (
            f"{self.execution.launch_nonce}.container-"
            f"{self.identities[2].container_id[:32]}"
        )
        self.collector = _FakeCollector(
            fault=self.fault,
            execution=self.execution,
            compatibility_boot_id=compatibility_boot_id,
            issue=self.issue,
            events=self.events,
        )

    def _campaign(
        self,
        runtime2: _Runtime,
        channel2: _Channel,
    ) -> TargetCampaignCompletionV3:
        evidence = TargetC2EvidenceV3(
            schema_version="target-c2-evidence.v3",
            collector_id="collector-01",
            site_id="school-01",
            campaign_id="campaign-01",
            gate="8h",
            epochs=(
                _epoch(self.identities[0], "restart"),
                _epoch(self.identities[1], "authorize"),
            ),
        )
        return TargetCampaignCompletionV3(
            c2_evidence=evidence,
            c2_capability=object(),
            final_runtime=runtime2,
            final_channel=channel2,
        )

    def _journal(
        self,
        root: Path,
        name: str,
    ) -> SQLiteTargetExecutionTransitionJournalV3:
        root.chmod(0o700)
        return SQLiteTargetExecutionTransitionJournalV3(root / name)

    def test_exact_restart_launch_work_journal_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime2 = _Runtime(self.identities[1], self.events, "epoch2")
            channel2 = _Channel(root / "epoch2.claim", self.events, "epoch2")
            runtime3 = _Runtime(self.identities[2], self.events, "epoch3")
            channel3 = _Channel(root / "epoch3.claim", self.events, "epoch3")
            observed_journals: list[object] = []
            coordinator = _coordinator(
                request=self.requests[2],
                runtime3=runtime3,
                channel3=channel3,
                collector=self.collector,
                journal=self._journal(root, "transition.sqlite3"),
            )
            base = self._campaign(runtime2, channel2)
            plan = SimpleNamespace(plan_sha256="c" * 64)
            projection = SimpleNamespace(
                projection_sha256="d" * 64,
                completed_work_ledger_sha256="e" * 64,
            )

            def authorize(**kwargs: object) -> tuple[object, object]:
                observed_journals.append(
                    _peek_transition_journal_capability(
                        kwargs["transition_journal_capability"]
                    )
                )
                return object(), object()

            with (
                patch.object(
                    campaign_module.ControllerAcceptanceChannelV3,
                    "create",
                    return_value=channel3,
                ),
                patch.object(
                    campaign_module,
                    "_require_exact_channel_mount",
                ),
                patch.object(
                    campaign_module,
                    "_require_verified_target_source_profile_attestation",
                ),
                patch.object(
                    campaign_module,
                    "derive_target_unique_work_plan",
                    return_value=(plan, object()),
                ),
                patch.object(
                    campaign_module,
                    "verify_target_unique_work_projection_value",
                    return_value=(projection, object()),
                ),
                patch.object(
                    campaign_module,
                    "_consume_controller_owned_runtime_for_c2",
                    return_value=object(),
                ),
                patch.object(
                    campaign_module,
                    "authorize_target_c2_continuation_v3",
                    side_effect=authorize,
                ),
                patch.object(
                    campaign_module,
                    "_consume_authenticated_fault_acknowledgement",
                    side_effect=self.consume,
                ),
            ):
                runtime = _advance_target_runtime_restart_v3(
                    continuation=coordinator,
                    collector=self.collector,
                    campaign=base,
                    previous_execution=self.execution,
                    fault=self.fault,
                    phase="inject",
                    at_offset=40.0,
                )
                self.assertIsNone(runtime)
                self.assertEqual(
                    self.events[:8],
                    [
                        "epoch2:reverify",
                        "epoch2:terminate",
                        "epoch2:wait",
                        "epoch2:cleanup",
                        "epoch2:abort",
                        "collector:inject:40",
                        "executor:inject",
                        "observer:inject",
                    ],
                )
                runtime = _advance_target_runtime_restart_v3(
                    continuation=coordinator,
                    collector=self.collector,
                    campaign=base,
                    previous_execution=self.execution,
                    fault=self.fault,
                    phase="recover",
                    at_offset=43.0,
                )
                self.assertIs(runtime, runtime3)
                self.assertLess(
                    self.events.index("epoch3:grant"),
                    self.events.index("collector:recover:43"),
                )
                self.assertLess(
                    self.events.index("executor:recover"),
                    self.events.index("observer:recover"),
                )
                self.assertIsNone(coordinator.poll_authorization())
                self.assertEqual(channel3.directive_count, 0)
                channel3.result_available = True
                self.assertIsNone(coordinator.poll_authorization())
                self.assertEqual(channel3.directive_count, 1)
                channel3.ack_available = True
                completion = coordinator.poll_authorization()
                self.assertIsNotNone(completion)

            self.assertEqual(len(observed_journals), 1)
            transition = observed_journals[0]
            self.assertEqual(
                tuple(entry.phase for entry in transition.entries),
                ("requested", "runtime_observed", "authorized"),
            )
            coordinator.cleanup(base)
            coordinator.cleanup(base)
            self.assertEqual(runtime2.cleanup_count, 1)
            self.assertEqual(channel2.abort_count, 1)
            self.assertEqual(runtime3.cleanup_count, 1)
            self.assertEqual(channel3.abort_count, 1)

    def test_raw_and_mismatched_acknowledgements_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime2 = _Runtime(self.identities[1], self.events, "epoch2")
            channel2 = _Channel(root / "epoch2.claim", self.events, "epoch2")
            runtime3 = _Runtime(self.identities[2], self.events, "epoch3")
            channel3 = _Channel(root / "epoch3.claim", self.events, "epoch3")
            coordinator = _coordinator(
                request=self.requests[2],
                runtime3=runtime3,
                channel3=channel3,
                collector=self.collector,
                journal=self._journal(root, "raw.sqlite3"),
            )
            base = self._campaign(runtime2, channel2)
            with (
                patch.object(
                    campaign_module.ControllerAcceptanceChannelV3,
                    "create",
                    return_value=channel3,
                ),
                patch.object(
                    campaign_module,
                    "_require_exact_channel_mount",
                ),
                patch.object(
                    campaign_module,
                    "_require_verified_target_source_profile_attestation",
                ),
                patch.object(
                    campaign_module,
                    "derive_target_unique_work_plan",
                    return_value=(
                        SimpleNamespace(plan_sha256="c" * 64),
                        object(),
                    ),
                ),
            ):
                coordinator.request_restart(
                    campaign=base,
                    previous_execution=self.execution,
                    fault=self.fault,
                    at_offset=40.0,
                )
                coordinator.launch_replacement(at_offset=43.0)
            with patch.object(
                campaign_module,
                "_consume_authenticated_fault_acknowledgement",
                side_effect=self.consume,
            ):
                raw, _unused = self.collector.acknowledgement()
                with self.assertRaisesRegex(TypeError, "authenticated"):
                    coordinator.record_v2_recovery(raw)
                _wrong, wrong_capability = self.collector.acknowledgement(
                    boot_id=(
                        f"{self.execution.launch_nonce}.container-"
                        f"{'9' * 32}"
                    )
                )
                with self.assertRaisesRegex(ValueError, "fresh controller"):
                    coordinator.record_v2_recovery(wrong_capability)
                _correct, capability = self.collector.acknowledgement()
                coordinator.record_v2_recovery(capability)
            self.assertEqual(coordinator._stage, "observed")
            coordinator.cleanup(base)

    def test_capability_is_one_shot_immutable_and_accepts_committed_retry(
        self,
    ) -> None:
        _ack, capability = self.collector.acknowledgement()
        with self.assertRaises(TypeError):
            copy.copy(capability)
        with self.assertRaises(TypeError):
            pickle.dumps(capability)
        self.assertFalse(hasattr(capability, "__dict__"))

        _ack, mutated = self.collector.acknowledgement()
        setattr(
            mutated,
            "_AuthenticatedFaultAcknowledgement__acknowledgement_bytes",
            b"{}",
        )
        with self.assertRaisesRegex(RuntimeError, "provenance"):
            self.consume(
                mutated,
                collector=self.collector,
            )

        expected, committed = self.collector.acknowledgement(
            committed_prepare_only=True
        )
        consumed = self.consume(
            committed,
            collector=self.collector,
        )
        self.assertEqual(consumed, expected)
        with self.assertRaisesRegex(RuntimeError, "already consumed"):
            self.consume(
                committed,
                collector=self.collector,
            )
        with self.assertRaisesRegex(RuntimeError, "already registered"):
            self.register(_FakeCollector)

    def test_failed_retirement_cleanup_is_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime2 = _Runtime(
                self.identities[1],
                self.events,
                "epoch2",
                wait_code=1,
            )
            channel2 = _Channel(root / "epoch2.claim", self.events, "epoch2")
            runtime3 = _Runtime(self.identities[2], self.events, "epoch3")
            channel3 = _Channel(root / "epoch3.claim", self.events, "epoch3")
            coordinator = _coordinator(
                request=self.requests[2],
                runtime3=runtime3,
                channel3=channel3,
                collector=self.collector,
                journal=self._journal(root, "failure.sqlite3"),
            )
            base = self._campaign(runtime2, channel2)
            with self.assertRaisesRegex(RuntimeError, "did not stop cleanly"):
                coordinator.request_restart(
                    campaign=base,
                    previous_execution=self.execution,
                    fault=self.fault,
                    at_offset=40.0,
                )
            coordinator.cleanup(base)
            coordinator.cleanup(base)
            self.assertEqual(runtime2.cleanup_count, 1)
            self.assertEqual(channel2.abort_count, 1)
            self.assertEqual(runtime3.cleanup_count, 0)
            self.assertEqual(channel3.abort_count, 0)

    def test_authority_database_paths_reject_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            collector = root / "collector.sqlite3"
            transition = root / "transition.sqlite3"
            v3_state = root / "v3.sqlite3"
            _require_distinct_authority_files(
                (
                    ("collector state", collector),
                    ("transition journal", transition),
                    ("V3 state", v3_state),
                )
            )
            with self.assertRaisesRegex(ValueError, "distinct"):
                _require_distinct_authority_files(
                    (
                        ("collector state", collector),
                        ("transition journal", collector),
                        ("V3 state", v3_state),
                    )
                )
            collector.write_bytes(b"collector")
            os.link(collector, transition)
            with self.assertRaisesRegex(
                ValueError,
                "distinct|regular|inode",
            ):
                _require_distinct_authority_files(
                    (
                        ("collector state", collector),
                        ("transition journal", transition),
                        ("V3 state", v3_state),
                    )
                )


if __name__ == "__main__":
    unittest.main()
