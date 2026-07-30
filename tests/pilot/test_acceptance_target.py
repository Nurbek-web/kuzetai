from __future__ import annotations

import copy
import hashlib
import pickle

import pytest
from pydantic import ValidationError

from protector.pilot.acceptance import LaunchAttestationV2
from protector.pilot.acceptance_target import (
    ObservedGpuDeviceV2,
    ObservedGpuInventoryV2,
    TargetRuntimeCompletionV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
    TargetRuntimeObservationV2,
    TargetSourceBindingV2,
    launch_and_observe_target_runtime,
)

HEX = "a" * 64
GPU_UUID = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def _gpu_inventory(**updates: object) -> ObservedGpuInventoryV2:
    payload: dict[str, object] = {
        "schema_version": "observed-gpu-inventory.v2",
        "devices": (
            ObservedGpuDeviceV2(
                uuid=GPU_UUID,
                product_name="NVIDIA L4",
                pci_bus_id="0000:01:00.0",
                total_vram_bytes=24_000_000_000,
                compute_capability="8.9",
                mig_mode="disabled",
            ),
        ),
        "nvidia_driver_version": "570.86.15",
        "cuda_driver_version": "12.8",
        "cuda_runtime_version": "12.8",
        "nvidia_container_toolkit_version": "1.17.4",
    }
    payload.update(updates)
    return ObservedGpuInventoryV2.model_validate(payload)


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


def _source_bindings() -> tuple[TargetSourceBindingV2, ...]:
    return tuple(
        TargetSourceBindingV2(
            camera_id=f"camera-{index:02}",
            source_index=index,
            source_identity_commitment=hashlib.sha256(f"source-{index}".encode()).hexdigest(),
        )
        for index in range(20)
    )


def _request(
    *,
    inventory: ObservedGpuInventoryV2 | None = None,
    source_bindings: tuple[TargetSourceBindingV2, ...] | None = None,
    runtime_epoch: int = 1,
) -> TargetRuntimeLaunchRequestV2:
    observed = inventory or _gpu_inventory()
    return TargetRuntimeLaunchRequestV2(
        schema_version="target-runtime-launch-request.v2",
        campaign_id="campaign-2026-001",
        gate="8h",
        launch_nonce="1" * 32,
        manifest_sha256="2" * 64,
        acceptance_trust_binding_sha256="3" * 64,
        module_gate_bindings_sha256="4" * 64,
        controller_image_id_sha256="5" * 64,
        controller_image_config_sha256="6" * 64,
        controller_code_sha256="7" * 64,
        runtime_epoch=runtime_epoch,
        runtime_epoch_started_generation=runtime_epoch,
        launch=_launch(observed),
        source_bindings=source_bindings or _source_bindings(),
    )


def _identity(
    request: TargetRuntimeLaunchRequestV2,
    *,
    inventory: ObservedGpuInventoryV2 | None = None,
) -> TargetRuntimeIdentityV2:
    return TargetRuntimeIdentityV2(
        schema_version="target-runtime-identity.v2",
        launch_request=request,
        process_id="runtime-process-001",
        runtime_boot_id=f"runtime-boot-{request.runtime_epoch}",
        container_id="8" * 64,
        container_config_sha256="9" * 64,
        runtime_image_id_sha256=request.launch.runtime_image_id_sha256,
        runtime_image_config_sha256=request.launch.runtime_image_config_sha256,
        runtime_code_sha256=request.launch.runtime_code_sha256,
        mount_contract_sha256=request.launch.mount_contract_sha256,
        controller_image_id_sha256=request.controller_image_id_sha256,
        controller_image_config_sha256=request.controller_image_config_sha256,
        controller_code_sha256=request.controller_code_sha256,
        control_network_id=request.launch.expected_control_network_id,
        control_network_config_sha256=(request.launch.expected_control_network_config_sha256),
        camera_network_id=request.launch.expected_camera_network_id,
        camera_network_config_sha256=(request.launch.expected_camera_network_config_sha256),
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=request.runtime_epoch_started_generation,
        runtime_epoch_started_monotonic_ns=1_000_000_000,
        identity_observed_monotonic_ns=1_000_000_001,
        observed_gpu_inventory=inventory or _gpu_inventory(),
        source_bindings=request.source_bindings,
    )


def test_observed_gpu_inventory_is_strict_immutable_and_binds_full_inventory() -> None:
    inventory = _gpu_inventory()

    with pytest.raises((TypeError, ValidationError)):
        inventory.devices[0].total_vram_bytes = 1  # type: ignore[misc]
    with pytest.raises(ValidationError):
        _gpu_inventory(
            devices=(
                {
                    **inventory.devices[0].model_dump(mode="json"),
                    "total_vram_bytes": "24000000000",
                },
            )
        )
    with pytest.raises(ValidationError):
        _gpu_inventory(unreviewed_fallback=True)

    changed = _gpu_inventory(nvidia_driver_version="570.86.16")
    assert changed.inventory_sha256 != inventory.inventory_sha256
    assert changed.launch_compatibility_sha256 != inventory.launch_compatibility_sha256


def test_launch_request_requires_exact_ordered_twenty_camera_bindings() -> None:
    bindings = _source_bindings()
    for malformed in (
        bindings[:-1],
        bindings[:-1] + (bindings[0],),
        (bindings[1], bindings[0], *bindings[2:]),
        bindings[:-1] + (bindings[-1].model_copy(update={"camera_id": bindings[0].camera_id}),),
    ):
        with pytest.raises(ValidationError, match="20|source|camera|order|unique"):
            _request(source_bindings=malformed)


def test_typed_factory_cannot_substitute_expectation_for_observed_inventory() -> None:
    request = _request()
    identity = _identity(request)

    class GoodProcess:
        cleanup_count = 0

        def observe_identity(self) -> TargetRuntimeIdentityV2:
            return identity

        def cleanup(self) -> None:
            self.cleanup_count += 1

    class GoodFactory:
        def launch(self, launch_request: TargetRuntimeLaunchRequestV2) -> GoodProcess:
            assert launch_request == request
            return GoodProcess()

    process, observed = launch_and_observe_target_runtime(GoodFactory(), request)
    assert type(process) is GoodProcess
    assert type(observed) is TargetRuntimeObservationV2
    assert observed.authorizing is False
    assert observed.identity == identity
    assert observed.identity.observed_gpu_inventory.devices[0].product_name == "NVIDIA L4"
    assert not hasattr(observed, "accepted")
    assert process.cleanup_count == 0

    class DigestOnlyProcess:
        cleanup_count = 0

        def observe_identity(self) -> str:
            return request.launch.gpu_inventory_sha256

        def cleanup(self) -> None:
            self.cleanup_count += 1

    class DigestOnlyFactory:
        process = DigestOnlyProcess()

        def launch(
            self,
            launch_request: TargetRuntimeLaunchRequestV2,
        ) -> DigestOnlyProcess:
            assert launch_request == request
            return self.process

    with pytest.raises(TypeError, match="typed runtime identity"):
        factory = DigestOnlyFactory()
        launch_and_observe_target_runtime(factory, request)
    assert factory.process.cleanup_count == 1

    wrong_inventory = _gpu_inventory(nvidia_driver_version="570.86.16")
    forged = identity.model_copy(update={"observed_gpu_inventory": wrong_inventory})

    class ForgedProcess:
        cleanup_count = 0

        def observe_identity(self) -> TargetRuntimeIdentityV2:
            return forged

        def cleanup(self) -> None:
            self.cleanup_count += 1

    class ForgedFactory:
        process = ForgedProcess()

        def launch(self, launch_request: TargetRuntimeLaunchRequestV2) -> ForgedProcess:
            assert launch_request == request
            return self.process

    with pytest.raises(ValidationError, match="GPU|inventory|launch"):
        forged_factory = ForgedFactory()
        launch_and_observe_target_runtime(forged_factory, request)
    assert forged_factory.process.cleanup_count == 1


def test_public_process_seam_strictly_reparses_model_construct_and_cleans_once() -> None:
    request = _request()
    malformed = TargetRuntimeIdentityV2.model_construct(
        schema_version="target-runtime-identity.v2",
        launch_request=request,
        process_id="runtime-process-001",
        runtime_boot_id="runtime-boot-1",
        container_id="8" * 64,
        container_config_sha256="9" * 64,
        runtime_image_id_sha256=request.launch.runtime_image_id_sha256,
        runtime_image_config_sha256=request.launch.runtime_image_config_sha256,
        runtime_code_sha256=request.launch.runtime_code_sha256,
        mount_contract_sha256=request.launch.mount_contract_sha256,
        controller_image_id_sha256=request.controller_image_id_sha256,
        controller_image_config_sha256=request.controller_image_config_sha256,
        controller_code_sha256=request.controller_code_sha256,
        control_network_id=request.launch.expected_control_network_id,
        control_network_config_sha256=(request.launch.expected_control_network_config_sha256),
        camera_network_id=request.launch.expected_camera_network_id,
        camera_network_config_sha256=(request.launch.expected_camera_network_config_sha256),
        runtime_epoch=1,
        runtime_epoch_started_generation=1,
        runtime_epoch_started_monotonic_ns=True,
        identity_observed_monotonic_ns=1_000_000_001,
        observed_gpu_inventory=_gpu_inventory(),
        source_bindings=request.source_bindings,
        authorizing=False,
    )

    class MalformedProcess:
        cleanup_count = 0

        def observe_identity(self) -> TargetRuntimeIdentityV2:
            return malformed

        def cleanup(self) -> None:
            self.cleanup_count += 1

    class MalformedFactory:
        process = MalformedProcess()

        def launch(self, launch_request: TargetRuntimeLaunchRequestV2) -> MalformedProcess:
            assert launch_request == request
            return self.process

    factory = MalformedFactory()
    with pytest.raises(ValidationError):
        launch_and_observe_target_runtime(factory, request)
    assert factory.process.cleanup_count == 1


def test_process_observation_preserves_primary_and_cleanup_baseexceptions() -> None:
    request = _request()

    class FailingProcess:
        cleanup_count = 0

        def observe_identity(self) -> TargetRuntimeIdentityV2:
            raise RuntimeError("primary observation failure")

        def cleanup(self) -> None:
            self.cleanup_count += 1
            raise KeyboardInterrupt("cleanup abort")

    class FailingFactory:
        process = FailingProcess()

        def launch(self, launch_request: TargetRuntimeLaunchRequestV2) -> FailingProcess:
            assert launch_request == request
            return self.process

    factory = FailingFactory()
    with pytest.raises(BaseExceptionGroup) as raised:
        launch_and_observe_target_runtime(factory, request)
    assert factory.process.cleanup_count == 1
    assert [type(error) for error in raised.value.exceptions] == [
        RuntimeError,
        KeyboardInterrupt,
    ]


def test_completion_is_non_authorizing_and_rejects_caller_throughput_scalars() -> None:
    from protector.pilot.acceptance_target import TargetNativePrewarmProjectionV2

    request = _request()
    identity = _identity(request)
    projection = TargetNativePrewarmProjectionV2(
        schema_version="target-native-prewarm-projection.v2",
        launch_request_sha256=request.request_sha256,
        runtime_identity_sha256=identity.identity_sha256,
        site_id=request.launch.site_id,
        campaign_id=request.campaign_id,
        launch_nonce=request.launch_nonce,
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=request.runtime_epoch_started_generation,
        runtime_epoch_started_monotonic_ns=identity.runtime_epoch_started_monotonic_ns,
        ready_at_monotonic_ns=61_000_000_000,
        source_bindings=request.source_bindings,
        source_identity_commitments_sha256="8" * 64,
        native_claims_sha256="9" * 64,
        source_profile_proof_sha256="b" * 64,
    )
    completion = TargetRuntimeCompletionV2(
        schema_version="target-runtime-completion.v2",
        launch_request=request,
        runtime_identity=identity,
        native_prewarm=projection,
        measurement_started_monotonic_ns=61_000_000_000,
        measurement_completed_monotonic_ns=121_000_000_000,
        offered_work_units=8_000,
        completed_unique_work_units=7_500,
        completed_work_ledger_sha256="c" * 64,
        exit_code=0,
    )

    assert completion.authorizing is False
    assert completion.measured_duration_seconds == 60.0
    assert not hasattr(completion, "accepted")
    assert not hasattr(completion, "throughput_headroom_fraction")
    assert not hasattr(completion, "has_required_headroom")
    with pytest.raises(ValidationError, match="extra"):
        TargetRuntimeCompletionV2.model_validate(
            {
                **completion.model_dump(mode="json"),
                "effective_throughput_hz": 999.0,
            }
        )


@pytest.mark.parametrize(
    ("updates", "match"),
    (
        ({"completed_unique_work_units": 8_001}, "completed|offered"),
        ({"exit_code": 1}, "exit|literal|0"),
        (
            {
                "measurement_started_monotonic_ns": 60_999_999_999,
                "measurement_completed_monotonic_ns": 121_000_000_000,
            },
            "prewarm|measurement",
        ),
        (
            {
                "measurement_started_monotonic_ns": 61_000_000_000,
                "measurement_completed_monotonic_ns": 61_000_000_000,
            },
            "measurement|interval",
        ),
    ),
)
def test_completion_bounds_fail_closed(updates: dict[str, object], match: str) -> None:
    from protector.pilot.acceptance_target import TargetNativePrewarmProjectionV2

    request = _request()
    identity = _identity(request)
    projection = TargetNativePrewarmProjectionV2(
        schema_version="target-native-prewarm-projection.v2",
        launch_request_sha256=request.request_sha256,
        runtime_identity_sha256=identity.identity_sha256,
        site_id=request.launch.site_id,
        campaign_id=request.campaign_id,
        launch_nonce=request.launch_nonce,
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=request.runtime_epoch_started_generation,
        runtime_epoch_started_monotonic_ns=identity.runtime_epoch_started_monotonic_ns,
        ready_at_monotonic_ns=61_000_000_000,
        source_bindings=request.source_bindings,
        source_identity_commitments_sha256="8" * 64,
        native_claims_sha256="9" * 64,
        source_profile_proof_sha256="b" * 64,
    )
    payload: dict[str, object] = {
        "schema_version": "target-runtime-completion.v2",
        "launch_request": request,
        "runtime_identity": identity,
        "native_prewarm": projection,
        "measurement_started_monotonic_ns": 61_000_000_000,
        "measurement_completed_monotonic_ns": 121_000_000_000,
        "offered_work_units": 8_000,
        "completed_unique_work_units": 7_500,
        "completed_work_ledger_sha256": "c" * 64,
        "exit_code": 0,
    }
    payload.update(updates)

    with pytest.raises(ValidationError, match=match):
        TargetRuntimeCompletionV2.model_validate(payload)


def test_runtime_restart_requires_a_new_epoch_and_fresh_prewarm_projection() -> None:
    from protector.pilot.acceptance_target import TargetNativePrewarmProjectionV2

    first_request = _request(runtime_epoch=1)
    first_identity = _identity(first_request)
    old_projection = TargetNativePrewarmProjectionV2(
        schema_version="target-native-prewarm-projection.v2",
        launch_request_sha256=first_request.request_sha256,
        runtime_identity_sha256=first_identity.identity_sha256,
        site_id=first_request.launch.site_id,
        campaign_id=first_request.campaign_id,
        launch_nonce=first_request.launch_nonce,
        runtime_epoch=1,
        runtime_epoch_started_generation=1,
        runtime_epoch_started_monotonic_ns=1_000_000_000,
        ready_at_monotonic_ns=61_000_000_000,
        source_bindings=first_request.source_bindings,
        source_identity_commitments_sha256="8" * 64,
        native_claims_sha256="9" * 64,
        source_profile_proof_sha256="b" * 64,
    )
    restarted_request = _request(runtime_epoch=2)
    restarted_identity = _identity(restarted_request)

    with pytest.raises(ValidationError, match="prewarm|epoch|launch|identity"):
        TargetRuntimeCompletionV2(
            schema_version="target-runtime-completion.v2",
            launch_request=restarted_request,
            runtime_identity=restarted_identity,
            native_prewarm=old_projection,
            measurement_started_monotonic_ns=61_000_000_000,
            measurement_completed_monotonic_ns=121_000_000_000,
            offered_work_units=8_000,
            completed_unique_work_units=7_500,
            completed_work_ledger_sha256="c" * 64,
            exit_code=0,
        )


def test_target_contracts_are_non_mutable_and_safe_to_serialize() -> None:
    request = _request()
    identity = _identity(request)

    with pytest.raises((TypeError, ValidationError)):
        request.runtime_epoch = 2  # type: ignore[misc]
    assert copy.deepcopy(identity) == identity
    assert pickle.loads(pickle.dumps(identity)) == identity
