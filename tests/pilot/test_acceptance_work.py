from __future__ import annotations

import copy
import hashlib
import pickle
from pathlib import Path

import pytest
from pydantic import ValidationError

from protector.pilot.acceptance import (
    AcceptanceManifestV2,
    LaunchAttestationV2,
    source_profiles_sha256,
)
from protector.pilot.acceptance_target import (
    ObservedGpuDeviceV2,
    ObservedGpuInventoryV2,
    TargetNativePrewarmProjectionV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
    TargetSourceBindingV2,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.acceptance_work import (
    TargetUniqueWorkPlanV2,
    TargetUniqueWorkProjectionV2,
    derive_target_unique_work_plan,
    verify_target_unique_work_projection,
)
from protector.pilot.runtime.deepstream import (
    GPU_MEMORY_TYPE,
    DeepStreamGraphSpec,
    ElementSpec,
    OptionalBranchSpec,
    SourcePlan,
)
from tests.pilot.acceptance_trust_helpers import authority_trust_context
from tests.pilot.test_acceptance_report import _manifest


def _manifest_with_person_rate(
    root: Path,
    *,
    person_rate: float = 0.1,
    extra_rate: tuple[str, float] | None = None,
) -> AcceptanceManifestV2:
    base = _manifest(root)
    schedules = {"person": person_rate}
    if extra_rate is not None:
        schedules[extra_rate[0]] = extra_rate[1]
    sources = tuple(
        source.model_copy(update={"analytics_hz": schedules}) for source in base.sources
    )
    launch = LaunchAttestationV2.model_validate(
        {
            **base.launch.model_dump(mode="python"),
            "source_profiles_sha256": source_profiles_sha256(sources),
        }
    )
    return AcceptanceManifestV2.model_validate(
        {
            **base.model_dump(mode="python"),
            "sources": sources,
            "launch": launch,
        }
    )


def _inventory(launch: LaunchAttestationV2) -> ObservedGpuInventoryV2:
    return ObservedGpuInventoryV2(
        schema_version="observed-gpu-inventory.v2",
        devices=(
            ObservedGpuDeviceV2(
                uuid=launch.gpu_device_ids[0],
                product_name=launch.gpu_product_name,
                pci_bus_id=launch.gpu_pci_bus_id,
                total_vram_bytes=launch.gpu_total_vram_bytes,
                compute_capability=launch.gpu_compute_capability,
                mig_mode=launch.gpu_mig_mode,
            ),
        ),
        nvidia_driver_version=launch.nvidia_driver_version,
        cuda_driver_version=launch.cuda_driver_version,
        cuda_runtime_version=launch.cuda_runtime_version,
        nvidia_container_toolkit_version=launch.nvidia_container_toolkit_version,
    )


def _target_inputs(
    root: Path,
    *,
    person_rate: float = 0.1,
    extra_rate: tuple[str, float] | None = None,
):
    manifest = _manifest_with_person_rate(
        root,
        person_rate=person_rate,
        extra_rate=extra_rate,
    )
    context = authority_trust_context(root, manifest)
    bindings = tuple(
        TargetSourceBindingV2(
            camera_id=source.camera_id,
            source_index=source.source_index,
            source_identity_commitment=hashlib.sha256(
                f"lawful-source:{source.camera_id}".encode()
            ).hexdigest(),
        )
        for source in manifest.sources
    )
    request = TargetRuntimeLaunchRequestV2(
        schema_version="target-runtime-launch-request.v2",
        campaign_id=context.configured_campaign_id,
        gate=context.configured_gate,
        launch_nonce="1" * 32,
        manifest_sha256=manifest.manifest_sha256,
        acceptance_trust_binding_sha256=hashlib.sha256(
            canonical_json_bytes(context.binding)
        ).hexdigest(),
        module_gate_bindings_sha256=hashlib.sha256(
            canonical_json_bytes([item.model_dump(mode="json") for item in manifest.modules])
        ).hexdigest(),
        controller_image_id_sha256="3" * 64,
        controller_image_config_sha256="4" * 64,
        controller_code_sha256="5" * 64,
        runtime_epoch=7,
        runtime_epoch_started_generation=11,
        launch=manifest.launch,
        source_bindings=bindings,
    )
    identity = TargetRuntimeIdentityV2(
        schema_version="target-runtime-identity.v2",
        launch_request=request,
        process_id="docker:" + "6" * 64,
        runtime_boot_id="container:" + "6" * 64,
        container_id="6" * 64,
        container_config_sha256="7" * 64,
        runtime_image_id_sha256=request.launch.runtime_image_id_sha256,
        runtime_image_config_sha256=request.launch.runtime_image_config_sha256,
        runtime_code_sha256=request.launch.runtime_code_sha256,
        mount_contract_sha256=request.launch.mount_contract_sha256,
        controller_image_id_sha256=request.controller_image_id_sha256,
        controller_image_config_sha256=request.controller_image_config_sha256,
        controller_code_sha256=request.controller_code_sha256,
        control_network_id=request.launch.expected_control_network_id,
        control_network_config_sha256=request.launch.expected_control_network_config_sha256,
        camera_network_id=request.launch.expected_camera_network_id,
        camera_network_config_sha256=request.launch.expected_camera_network_config_sha256,
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=request.runtime_epoch_started_generation,
        runtime_epoch_started_monotonic_ns=1_000_000_000,
        identity_observed_monotonic_ns=1_000_000_001,
        observed_gpu_inventory=_inventory(request.launch),
        source_bindings=request.source_bindings,
    )
    graph = DeepStreamGraphSpec(
        sources=tuple(
            SourcePlan(
                camera_id=source.camera_id,
                source_id=source.source_index,
                codec=source.codec,
                width=source.width,
                height=source.height,
                fps=source.fps,
                bitrate_kbps=source.bitrate_kbps,
                queue_capacity=8,
            )
            for source in manifest.sources
        ),
        elements=(
            ElementSpec(
                name="streammux",
                factory="nvstreammux",
                properties={
                    "batch-size": 20,
                    "live-source": 1,
                    "nvbuf-memory-type": GPU_MEMORY_TYPE,
                },
            ),
            ElementSpec(
                name="primary-queue",
                factory="queue",
                properties={"max-size-buffers": 64, "leaky": "downstream"},
            ),
            ElementSpec(
                name="person-primary",
                factory="nvinfer",
                properties={"role": "primary", "batch-size": 20, "precision": "fp16"},
            ),
            ElementSpec(name="tracker", factory="nvtracker", properties={"shared": True}),
            ElementSpec(name="analytics", factory="nvdsanalytics", properties={"shared": True}),
        ),
        optional_branches=tuple(
            OptionalBranchSpec(
                module=module,
                queue=ElementSpec(
                    name=f"{module}-queue",
                    factory="queue",
                    properties={"max-size-buffers": 4, "leaky": "downstream"},
                ),
                valve=ElementSpec(
                    name=f"{module}-valve",
                    factory="valve",
                    properties={"drop": True},
                ),
            )
            for module in ("fire_smoke", "weapon")
        ),
    )
    graph.validate()
    return context, request, identity, graph


def _prewarm(
    request: TargetRuntimeLaunchRequestV2,
    identity: TargetRuntimeIdentityV2,
) -> TargetNativePrewarmProjectionV2:
    return TargetNativePrewarmProjectionV2(
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
        source_profile_proof_sha256="a" * 64,
    )


def test_signed_manifest_and_real_shared_graph_derive_exact_decimal_stress_schedule(
    tmp_path: Path,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)

    plan, authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )

    assert type(plan) is TargetUniqueWorkPlanV2
    assert plan.authorizing is False
    assert plan.measurement_duration_ns == 60_000_000_000
    assert plan.required_work_numerator == 120
    assert plan.required_work_denominator == 1
    assert plan.offered_work_units == 160
    assert len(plan.slots) == 160
    assert tuple(slot.slot_index for slot in plan.slots) == tuple(range(160))
    assert {slot.module for slot in plan.slots} == {"person"}
    assert len({slot.work_id for slot in plan.slots}) == 160
    assert not hasattr(plan, "accepted")
    assert not hasattr(authority, "accepted")


def test_each_camera_module_rounds_up_independently_at_twenty_five_percent(
    tmp_path: Path,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path, person_rate=0.01)

    plan, _authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )

    # 0.01 * 60 * 5/4 = 0.75, so every one of the exact 20 cameras gets one
    # real scheduled work item instead of disappearing through float rounding.
    assert plan.required_work_numerator == 12
    assert plan.required_work_denominator == 1
    assert plan.offered_work_units == 20
    assert {slot.camera_id for slot in plan.slots} == {f"camera-{index:02}" for index in range(20)}


def test_positive_schedule_without_an_enabled_real_shared_branch_fails_closed(
    tmp_path: Path,
) -> None:
    context, request, identity, graph = _target_inputs(
        tmp_path,
        extra_rate=("weapon", 0.1),
    )

    with pytest.raises(ValueError, match="weapon|enabled|branch|graph"):
        derive_target_unique_work_plan(
            trust_context=context,
            launch_request=request,
            runtime_identity=identity,
            graph=graph,
        )


def test_launch_throughput_scalars_are_ignored_but_exact_identity_is_bound(
    tmp_path: Path,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    changed_launch = LaunchAttestationV2.model_validate(
        {
            **request.launch.model_dump(mode="python"),
            "required_throughput_hz": 1.0,
            "measured_effective_throughput_hz": 999_999.0,
        }
    )
    changed_request = TargetRuntimeLaunchRequestV2.model_validate(
        {
            **request.model_dump(mode="python"),
            "launch": changed_launch,
        }
    )
    changed_identity = TargetRuntimeIdentityV2.model_validate(
        {
            **identity.model_dump(mode="python"),
            "launch_request": changed_request,
        }
    )
    changed_plan, _changed_authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=changed_request,
        runtime_identity=changed_identity,
        graph=graph,
    )

    plan, _authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    assert changed_plan.required_work_numerator == plan.required_work_numerator
    assert changed_plan.required_work_denominator == plan.required_work_denominator
    assert changed_plan.offered_work_units == plan.offered_work_units
    assert not hasattr(plan, "measured_effective_throughput_hz")
    assert not hasattr(plan, "launch_required_throughput_hz")


def test_public_plan_projection_and_fabricated_counter_digest_cannot_authorize(
    tmp_path: Path,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    plan, authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    forged = TargetUniqueWorkProjectionV2.model_construct(
        schema_version="target-unique-work-projection.v2",
        plan_sha256=plan.plan_sha256,
        launch_request_sha256=request.request_sha256,
        runtime_identity_sha256=identity.identity_sha256,
        native_prewarm_projection_sha256="b" * 64,
        measurement_started_monotonic_ns=61_000_000_000,
        measurement_completed_monotonic_ns=121_000_000_000,
        offered_work_units=160,
        completed_unique_work_units=160,
        required_work_numerator=1,
        required_work_denominator=1,
        effective_rate_numerator=999_999,
        effective_rate_denominator=1,
        completed_work_ledger_sha256="c" * 64,
        completions=(),
        authorizing=False,
    )
    path = tmp_path / "forged-work.json"
    path.write_bytes(forged.model_dump_json().encode())
    path.chmod(0o600)

    with pytest.raises(
        (TypeError, ValueError, ValidationError), match="canonical|ledger|work|projection"
    ):
        verify_target_unique_work_projection(
            path,
            plan_authority=authority,
            native_prewarm=_prewarm(request, identity),
        )


def test_plan_authority_and_verified_work_capability_reject_copy_and_pickle(
    tmp_path: Path,
) -> None:
    context, request, identity, graph = _target_inputs(tmp_path)
    _plan, authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )

    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises((TypeError, pickle.PickleError), match="copy|serial|capability"):
            operation(authority)
