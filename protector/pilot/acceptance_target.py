"""Portable, non-authorizing contracts for a future target acceptance lane.

These contracts make target observations explicit and type checked.  They do
not grant acceptance authority: controller-owned observation, unique-work
derivation, fresh-journal creation, and dual evaluation are intentionally
outside this slice.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal, Protocol, TypeVar

from pydantic import ConfigDict, Field, field_validator, model_validator

from protector.pilot.acceptance import LaunchAttestationV2
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.config import FrozenModel

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_Int64Positive = Annotated[int, Field(ge=1, le=2**63 - 1)]
_Int64NonNegative = Annotated[int, Field(ge=0, le=2**63 - 1)]
_M = TypeVar("_M", bound="_StrictFrozenModel")


class _StrictFrozenModel(FrozenModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


def _revalidate_exact(value: object, model: type[_M], label: str) -> _M:
    if type(value) is model:
        return model.model_validate(value)
    if type(value) is dict:
        return model.model_validate(value)
    else:
        raise TypeError(f"{label} must use the exact typed contract")


class ObservedGpuDeviceV2(_StrictFrozenModel):
    uuid: Annotated[
        str,
        Field(pattern=r"^GPU-[A-Fa-f0-9-]{16,64}$"),
    ]
    product_name: Annotated[str, Field(min_length=1, max_length=128)]
    pci_bus_id: Annotated[
        str,
        Field(pattern=r"^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$"),
    ]
    total_vram_bytes: _Int64Positive
    compute_capability: Annotated[
        str,
        Field(pattern=r"^[0-9]{1,2}\.[0-9]{1,2}$"),
    ]
    mig_mode: Literal["disabled"]


class ObservedGpuInventoryV2(_StrictFrozenModel):
    """The complete runtime-observed visible GPU inventory, never an expectation."""

    schema_version: Literal["observed-gpu-inventory.v2"]
    devices: Annotated[
        tuple[ObservedGpuDeviceV2, ...],
        Field(min_length=1, max_length=1),
    ]
    nvidia_driver_version: Annotated[str, Field(min_length=1, max_length=64)]
    cuda_driver_version: Annotated[str, Field(min_length=1, max_length=64)]
    cuda_runtime_version: Annotated[str, Field(min_length=1, max_length=64)]
    nvidia_container_toolkit_version: Annotated[
        str,
        Field(min_length=1, max_length=64),
    ]
    authorizing: Literal[False] = False

    @field_validator("devices", mode="before")
    @classmethod
    def devices_are_strictly_reparsed(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            raise TypeError("observed GPU devices must be a finite sequence")
        return tuple(
            ObservedGpuDeviceV2.model_validate(item) if type(item) is ObservedGpuDeviceV2 else item
            for item in value
        )

    @model_validator(mode="after")
    def inventory_is_exact(self) -> ObservedGpuInventoryV2:
        if len({device.uuid for device in self.devices}) != 1:
            raise ValueError("observed GPU inventory must contain one unique visible device")
        return self

    @property
    def inventory_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()

    @property
    def launch_compatibility_sha256(self) -> str:
        """Digest the full observation using the frozen launch-v1 wire shape."""
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema_version": "measured-gpu-inventory.v1",
                    "devices": [
                        device.model_dump(
                            mode="json",
                            exclude={"authorizing"},
                        )
                        for device in self.devices
                    ],
                    "nvidia_driver_version": self.nvidia_driver_version,
                    "cuda_driver_version": self.cuda_driver_version,
                    "cuda_runtime_version": self.cuda_runtime_version,
                    "nvidia_container_toolkit_version": (self.nvidia_container_toolkit_version),
                }
            )
        ).hexdigest()


class TargetSourceBindingV2(_StrictFrozenModel):
    camera_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    source_index: Annotated[int, Field(ge=0, lt=20)]
    source_identity_commitment: Digest
    authorizing: Literal[False] = False


def _reparse_source_bindings(value: object) -> tuple[TargetSourceBindingV2, ...]:
    if type(value) not in {tuple, list}:
        raise TypeError("source bindings must be one finite sequence")
    return tuple(TargetSourceBindingV2.model_validate(item) for item in value)


def _validate_exact_source_bindings(
    bindings: tuple[TargetSourceBindingV2, ...],
) -> None:
    if (
        len(bindings) != 20
        or tuple(item.source_index for item in bindings) != tuple(range(20))
        or len({item.camera_id for item in bindings}) != 20
        or len({item.source_identity_commitment for item in bindings}) != 20
    ):
        raise ValueError("target runtime requires exact ordered 20 unique camera/source bindings")


class TargetRuntimeLaunchRequestV2(_StrictFrozenModel):
    """A frozen launch request; still not an execution or acceptance grant."""

    schema_version: Literal["target-runtime-launch-request.v2"]
    campaign_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    gate: Literal["8h", "72h"]
    launch_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    manifest_sha256: Digest
    acceptance_trust_binding_sha256: Digest
    module_gate_bindings_sha256: Digest
    controller_image_id_sha256: Digest
    controller_image_config_sha256: Digest
    controller_code_sha256: Digest
    runtime_epoch: _Int64Positive
    runtime_epoch_started_generation: _Int64Positive
    launch: LaunchAttestationV2
    source_bindings: Annotated[
        tuple[TargetSourceBindingV2, ...],
        Field(min_length=20, max_length=20),
    ]
    authorizing: Literal[False] = False

    @field_validator("launch", mode="before")
    @classmethod
    def launch_is_existing_validated_contract(
        cls,
        value: object,
    ) -> LaunchAttestationV2:
        if type(value) is LaunchAttestationV2:
            return LaunchAttestationV2.model_validate(value.model_dump(mode="python"))
        if type(value) is not dict:
            raise TypeError("target launch must use the validated launch attestation")
        return LaunchAttestationV2.model_validate(value)

    @field_validator("source_bindings", mode="before")
    @classmethod
    def bindings_are_strictly_reparsed(
        cls,
        value: object,
    ) -> tuple[TargetSourceBindingV2, ...]:
        return _reparse_source_bindings(value)

    @model_validator(mode="after")
    def exact_twenty_and_existing_gates_are_bound(
        self,
    ) -> TargetRuntimeLaunchRequestV2:
        _validate_exact_source_bindings(self.source_bindings)
        if self.launch.expected_workload_sha256 != self.launch.frozen_workload_sha256:
            raise ValueError("target launch workload bindings differ")
        return self

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


class TargetRuntimeIdentityV2(_StrictFrozenModel):
    """Full process/runtime observation.  It is evidence, not authority."""

    schema_version: Literal["target-runtime-identity.v2"]
    launch_request: TargetRuntimeLaunchRequestV2
    process_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
    ]
    runtime_boot_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
    ]
    container_id: Digest
    container_config_sha256: Digest
    runtime_image_id_sha256: Digest
    runtime_image_config_sha256: Digest
    runtime_code_sha256: Digest
    mount_contract_sha256: Digest
    controller_image_id_sha256: Digest
    controller_image_config_sha256: Digest
    controller_code_sha256: Digest
    control_network_id: Digest
    control_network_config_sha256: Digest
    camera_network_id: Digest
    camera_network_config_sha256: Digest
    runtime_epoch: _Int64Positive
    runtime_epoch_started_generation: _Int64Positive
    runtime_epoch_started_monotonic_ns: _Int64NonNegative
    identity_observed_monotonic_ns: _Int64Positive
    observed_gpu_inventory: ObservedGpuInventoryV2
    source_bindings: Annotated[
        tuple[TargetSourceBindingV2, ...],
        Field(min_length=20, max_length=20),
    ]
    authorizing: Literal[False] = False

    @field_validator("launch_request", mode="before")
    @classmethod
    def request_is_strictly_reparsed(
        cls,
        value: object,
    ) -> TargetRuntimeLaunchRequestV2:
        return _revalidate_exact(value, TargetRuntimeLaunchRequestV2, "launch request")

    @field_validator("observed_gpu_inventory", mode="before")
    @classmethod
    def gpu_inventory_is_strictly_reparsed(
        cls,
        value: object,
    ) -> ObservedGpuInventoryV2:
        return _revalidate_exact(value, ObservedGpuInventoryV2, "observed GPU inventory")

    @field_validator("source_bindings", mode="before")
    @classmethod
    def bindings_are_strictly_reparsed(
        cls,
        value: object,
    ) -> tuple[TargetSourceBindingV2, ...]:
        return _reparse_source_bindings(value)

    @model_validator(mode="after")
    def identity_matches_the_exact_launch(self) -> TargetRuntimeIdentityV2:
        request = self.launch_request
        launch = request.launch
        device = self.observed_gpu_inventory.devices[0]
        if (
            self.runtime_epoch != request.runtime_epoch
            or self.runtime_epoch_started_generation != request.runtime_epoch_started_generation
            or self.identity_observed_monotonic_ns < self.runtime_epoch_started_monotonic_ns
            or self.source_bindings != request.source_bindings
            or self.runtime_image_id_sha256 != launch.runtime_image_id_sha256
            or self.runtime_image_config_sha256 != launch.runtime_image_config_sha256
            or self.runtime_code_sha256 != launch.runtime_code_sha256
            or self.mount_contract_sha256 != launch.mount_contract_sha256
            or self.controller_image_id_sha256 != request.controller_image_id_sha256
            or self.controller_image_config_sha256 != request.controller_image_config_sha256
            or self.controller_code_sha256 != request.controller_code_sha256
            or self.control_network_id != launch.expected_control_network_id
            or self.control_network_config_sha256 != launch.expected_control_network_config_sha256
            or self.camera_network_id != launch.expected_camera_network_id
            or self.camera_network_config_sha256 != launch.expected_camera_network_config_sha256
            or self.observed_gpu_inventory.launch_compatibility_sha256
            != launch.gpu_inventory_sha256
            or tuple(item.uuid for item in self.observed_gpu_inventory.devices)
            != launch.gpu_device_ids
            or device.product_name != launch.gpu_product_name
            or device.pci_bus_id != launch.gpu_pci_bus_id
            or device.total_vram_bytes != launch.gpu_total_vram_bytes
            or device.compute_capability != launch.gpu_compute_capability
            or device.mig_mode != launch.gpu_mig_mode
            or self.observed_gpu_inventory.nvidia_driver_version != launch.nvidia_driver_version
            or self.observed_gpu_inventory.cuda_driver_version != launch.cuda_driver_version
            or self.observed_gpu_inventory.cuda_runtime_version != launch.cuda_runtime_version
            or self.observed_gpu_inventory.nvidia_container_toolkit_version
            != launch.nvidia_container_toolkit_version
        ):
            raise ValueError(
                "observed GPU or process/runtime identity differs from the exact launch"
            )
        return self

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


class TargetRuntimeObservationV2(_StrictFrozenModel):
    schema_version: Literal["target-runtime-observation.v2"] = "target-runtime-observation.v2"
    identity: TargetRuntimeIdentityV2
    authorizing: Literal[False] = False

    @field_validator("identity", mode="before")
    @classmethod
    def identity_is_strictly_reparsed(
        cls,
        value: object,
    ) -> TargetRuntimeIdentityV2:
        return _revalidate_exact(value, TargetRuntimeIdentityV2, "runtime identity")


class TargetNativePrewarmProjectionV2(_StrictFrozenModel):
    """Serializable child projection; canonical bytes alone never authorize."""

    schema_version: Literal["target-native-prewarm-projection.v2"]
    launch_request_sha256: Digest
    runtime_identity_sha256: Digest
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    campaign_id: Annotated[str, Field(min_length=1, max_length=128)]
    launch_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    runtime_epoch: _Int64Positive
    runtime_epoch_started_generation: _Int64Positive
    runtime_epoch_started_monotonic_ns: _Int64NonNegative
    ready_at_monotonic_ns: _Int64Positive
    source_bindings: Annotated[
        tuple[TargetSourceBindingV2, ...],
        Field(min_length=20, max_length=20),
    ]
    source_identity_commitments_sha256: Digest
    native_claims_sha256: Digest
    source_profile_proof_sha256: Digest
    authorizing: Literal[False] = False

    @field_validator("source_bindings", mode="before")
    @classmethod
    def bindings_are_strictly_reparsed(
        cls,
        value: object,
    ) -> tuple[TargetSourceBindingV2, ...]:
        return _reparse_source_bindings(value)

    @model_validator(mode="after")
    def prewarm_is_exact_and_fresh(self) -> TargetNativePrewarmProjectionV2:
        _validate_exact_source_bindings(self.source_bindings)
        if self.ready_at_monotonic_ns - self.runtime_epoch_started_monotonic_ns < 60_000_000_000:
            raise ValueError("native prewarm must be fresh for at least 60 seconds")
        return self

    @property
    def prewarm_duration_seconds(self) -> float:
        return (
            self.ready_at_monotonic_ns - self.runtime_epoch_started_monotonic_ns
        ) / 1_000_000_000

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    @property
    def projection_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


class TargetRuntimeCompletionV2(_StrictFrozenModel):
    """Bounded completion observation; unique-work authority is not implemented."""

    schema_version: Literal["target-runtime-completion.v2"]
    launch_request: TargetRuntimeLaunchRequestV2
    runtime_identity: TargetRuntimeIdentityV2
    native_prewarm: TargetNativePrewarmProjectionV2
    measurement_started_monotonic_ns: _Int64NonNegative
    measurement_completed_monotonic_ns: _Int64Positive
    offered_work_units: _Int64NonNegative
    completed_unique_work_units: _Int64NonNegative
    completed_work_ledger_sha256: Digest
    exit_code: Literal[0]
    authorizing: Literal[False] = False

    @field_validator("launch_request", mode="before")
    @classmethod
    def request_is_strictly_reparsed(
        cls,
        value: object,
    ) -> TargetRuntimeLaunchRequestV2:
        return _revalidate_exact(value, TargetRuntimeLaunchRequestV2, "launch request")

    @field_validator("runtime_identity", mode="before")
    @classmethod
    def identity_is_strictly_reparsed(
        cls,
        value: object,
    ) -> TargetRuntimeIdentityV2:
        return _revalidate_exact(value, TargetRuntimeIdentityV2, "runtime identity")

    @field_validator("native_prewarm", mode="before")
    @classmethod
    def prewarm_is_strictly_reparsed(
        cls,
        value: object,
    ) -> TargetNativePrewarmProjectionV2:
        return _revalidate_exact(
            value,
            TargetNativePrewarmProjectionV2,
            "native prewarm projection",
        )

    @model_validator(mode="after")
    def completion_is_bounded_but_non_authorizing(self) -> TargetRuntimeCompletionV2:
        request = self.launch_request
        identity = self.runtime_identity
        prewarm = self.native_prewarm
        duration_ns = (
            self.measurement_completed_monotonic_ns - self.measurement_started_monotonic_ns
        )
        if (
            identity.launch_request != request
            or prewarm.launch_request_sha256 != request.request_sha256
            or prewarm.runtime_identity_sha256 != identity.identity_sha256
            or prewarm.site_id != request.launch.site_id
            or prewarm.campaign_id != request.campaign_id
            or prewarm.launch_nonce != request.launch_nonce
            or prewarm.runtime_epoch != request.runtime_epoch
            or prewarm.runtime_epoch_started_generation != request.runtime_epoch_started_generation
            or prewarm.runtime_epoch_started_monotonic_ns
            != identity.runtime_epoch_started_monotonic_ns
            or prewarm.ready_at_monotonic_ns < identity.identity_observed_monotonic_ns
            or prewarm.source_bindings != request.source_bindings
        ):
            raise ValueError("completion native prewarm differs from launch/runtime identity")
        if self.measurement_started_monotonic_ns < prewarm.ready_at_monotonic_ns:
            raise ValueError("completion measurement starts before native prewarm")
        if not 0 < duration_ns <= 259_200_000_000_000:
            raise ValueError("completion measurement interval is invalid")
        if self.completed_unique_work_units > self.offered_work_units:
            raise ValueError("completed work exceeds offered work")
        return self

    @property
    def measured_duration_seconds(self) -> float:
        return (
            self.measurement_completed_monotonic_ns - self.measurement_started_monotonic_ns
        ) / 1_000_000_000


class TargetRuntimeProcessV2(Protocol):
    """Typed process surface used only to collect non-authorizing observations."""

    def observe_identity(self) -> TargetRuntimeIdentityV2: ...

    def cleanup(self) -> None: ...


class TargetRuntimeFactoryV2(Protocol):
    def launch(
        self,
        request: TargetRuntimeLaunchRequestV2,
    ) -> TargetRuntimeProcessV2: ...


def launch_and_observe_target_runtime(
    factory: TargetRuntimeFactoryV2,
    request: TargetRuntimeLaunchRequestV2,
) -> tuple[TargetRuntimeProcessV2, TargetRuntimeObservationV2]:
    """Launch and strictly observe a process without granting authority.

    A malformed or digest-only observation is rejected and the just-launched
    process receives exactly one cleanup call.
    """

    checked_request = _revalidate_exact(
        request,
        TargetRuntimeLaunchRequestV2,
        "target runtime launch request",
    )
    process = factory.launch(checked_request)
    try:
        candidate = process.observe_identity()
        if type(candidate) is not TargetRuntimeIdentityV2:
            raise TypeError("process did not return the typed runtime identity")
        checked_identity = TargetRuntimeIdentityV2.model_validate(candidate)
        if checked_identity.launch_request != checked_request:
            raise ValueError("runtime identity does not bind the exact launch request")
        observation = TargetRuntimeObservationV2(identity=checked_identity)
    except BaseException as primary:
        try:
            process.cleanup()
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "runtime observation and cleanup both failed",
                [primary, cleanup],
            ) from primary
        raise
    return process, observation


__all__ = [
    "ObservedGpuDeviceV2",
    "ObservedGpuInventoryV2",
    "TargetNativePrewarmProjectionV2",
    "TargetRuntimeCompletionV2",
    "TargetRuntimeFactoryV2",
    "TargetRuntimeIdentityV2",
    "TargetRuntimeLaunchRequestV2",
    "TargetRuntimeObservationV2",
    "TargetRuntimeProcessV2",
    "TargetSourceBindingV2",
    "launch_and_observe_target_runtime",
]
