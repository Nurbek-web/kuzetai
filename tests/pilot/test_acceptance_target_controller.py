from __future__ import annotations

import copy
import pickle
import time
from pathlib import Path
from typing import Callable

import pytest
from pydantic import ValidationError

from protector.pilot import acceptance_target_controller
from protector.pilot.acceptance_target import (
    ObservedGpuInventoryV2,
    TargetRuntimeLaunchRequestV2,
)
from protector.pilot.acceptance_target_controller import (
    TargetRuntimeControllerEnvironmentV2,
    launch_and_observe_controller_owned_target_runtime,
)
from protector.pilot.runtime import container_runner
from protector.pilot.runtime.container_runner import (
    DockerRuntimeProcess,
    launch_docker_runtime,
)
from tests.pilot.test_acceptance_target import _request
from tests.pilot.test_container_runner import (
    _gpu_inventory_payload,
    _runner_fixture,
)


def _matching_request(arguments: dict[str, object]) -> TargetRuntimeLaunchRequestV2:
    request = _request()
    launch = request.launch.model_copy(
        update={
            "runtime_image_id_sha256": str(arguments["image_id"]).removeprefix("sha256:"),
            "runtime_image_config_sha256": arguments["image_config_sha256"],
            "runtime_code_sha256": arguments["runtime_code_sha256"],
            "mount_contract_sha256": arguments["mount_contract_sha256"],
            "control_network": arguments["control_network"],
            "camera_network": arguments["camera_network"],
            "expected_control_network_id": arguments["expected_control_network_id"],
            "expected_control_network_config_sha256": arguments[
                "expected_control_network_config_sha256"
            ],
            "expected_camera_network_id": arguments["expected_camera_network_id"],
            "expected_camera_network_config_sha256": arguments[
                "expected_camera_network_config_sha256"
            ],
            "gpu_device_ids": arguments["expected_gpu_device_ids"],
            "gpu_product_name": arguments["expected_gpu_product_name"],
            "gpu_pci_bus_id": arguments["expected_gpu_pci_bus_id"],
            "gpu_total_vram_bytes": arguments["expected_gpu_total_vram_bytes"],
            "gpu_compute_capability": arguments["expected_gpu_compute_capability"],
            "gpu_mig_mode": arguments["expected_gpu_mig_mode"],
            "gpu_inventory_sha256": arguments["expected_gpu_inventory_sha256"],
            "nvidia_driver_version": arguments["expected_nvidia_driver_version"],
            "cuda_driver_version": arguments["expected_cuda_driver_version"],
            "cuda_runtime_version": arguments["expected_cuda_runtime_version"],
            "nvidia_container_toolkit_version": arguments[
                "expected_nvidia_container_toolkit_version"
            ],
        }
    )
    return TargetRuntimeLaunchRequestV2.model_validate(
        request.model_copy(
            update={
                "launch_nonce": arguments["launch_nonce"],
                "launch": launch,
            }
        ).model_dump(mode="python")
    )


def _environment(
    arguments: dict[str, object],
) -> TargetRuntimeControllerEnvironmentV2:
    return TargetRuntimeControllerEnvironmentV2(
        engine_path=arguments["engine_path"],
        nvidia_ctk_path=arguments["nvidia_ctk_path"],
        command=arguments["command"],
        reviewed_mount_argv=arguments["mount_argv"],
    )


def _expected_launcher_arguments(
    request: TargetRuntimeLaunchRequestV2,
    environment: TargetRuntimeControllerEnvironmentV2,
) -> dict[str, object]:
    launch = request.launch
    return {
        "engine_path": environment.engine_path,
        "nvidia_ctk_path": environment.nvidia_ctk_path,
        "image_id": f"sha256:{launch.runtime_image_id_sha256}",
        "image_config_sha256": launch.runtime_image_config_sha256,
        "runtime_code_sha256": launch.runtime_code_sha256,
        "mount_contract_sha256": launch.mount_contract_sha256,
        "launch_nonce": request.launch_nonce,
        "command": environment.command,
        "mount_argv": environment.reviewed_mount_argv,
        "control_network": launch.control_network,
        "camera_network": launch.camera_network,
        "expected_control_network_id": launch.expected_control_network_id,
        "expected_control_network_config_sha256": (launch.expected_control_network_config_sha256),
        "expected_camera_network_id": launch.expected_camera_network_id,
        "expected_camera_network_config_sha256": (launch.expected_camera_network_config_sha256),
        "expected_gpu_device_ids": launch.gpu_device_ids,
        "expected_gpu_product_name": launch.gpu_product_name,
        "expected_gpu_pci_bus_id": launch.gpu_pci_bus_id,
        "expected_gpu_total_vram_bytes": launch.gpu_total_vram_bytes,
        "expected_gpu_compute_capability": launch.gpu_compute_capability,
        "expected_gpu_mig_mode": launch.gpu_mig_mode,
        "expected_gpu_inventory_sha256": launch.gpu_inventory_sha256,
        "expected_nvidia_driver_version": launch.nvidia_driver_version,
        "expected_cuda_driver_version": launch.cuda_driver_version,
        "expected_cuda_runtime_version": launch.cuda_runtime_version,
        "expected_nvidia_container_toolkit_version": (launch.nvidia_container_toolkit_version),
    }


def _install_real_launcher(
    monkeypatch: pytest.MonkeyPatch,
    *,
    run: Callable[..., object],
    transform: Callable[[DockerRuntimeProcess], object] | None = None,
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )

    def launch(**arguments: object) -> object:
        calls.append(arguments)
        process = launch_docker_runtime(**arguments, run=run)  # type: ignore[arg-type]
        return transform(process) if transform is not None else process

    monkeypatch.setattr(
        acceptance_target_controller,
        "launch_docker_runtime",
        launch,
    )
    return calls


def test_controller_environment_is_exact_frozen_and_bounded() -> None:
    arguments, _run, _state = _runner_fixture()
    environment = _environment(arguments)

    with pytest.raises((TypeError, ValidationError)):
        environment.command = ("changed",)  # type: ignore[misc]
    with pytest.raises(ValidationError):
        TargetRuntimeControllerEnvironmentV2(
            engine_path=Path("/usr/bin/docker"),
            nvidia_ctk_path=Path("/usr/bin/nvidia-ctk"),
            command=tuple("x" for _ in range(129)),
            reviewed_mount_argv=(),
        )
    with pytest.raises(ValidationError):
        TargetRuntimeControllerEnvironmentV2(
            engine_path=Path("/usr/bin/docker"),
            nvidia_ctk_path=Path("/usr/bin/nvidia-ctk"),
            command=("run",),
            reviewed_mount_argv=(),
            caller_expected_gpu="forged",  # type: ignore[call-arg]
        )


def test_controller_launch_derives_every_expectation_and_binds_full_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, state = _runner_fixture()
    request = _matching_request(arguments)
    environment = _environment(arguments)
    retained: list[DockerRuntimeProcess] = []

    def retain(process: DockerRuntimeProcess) -> DockerRuntimeProcess:
        retained.append(process)
        return process

    calls = _install_real_launcher(
        monkeypatch,
        run=run,
        transform=retain,
    )
    before = time.monotonic_ns()

    capability, observation = launch_and_observe_controller_owned_target_runtime(
        request,
        environment,
    )
    after = time.monotonic_ns()

    assert calls == [_expected_launcher_arguments(request, environment)]
    assert type(observation.identity.launch_request) is TargetRuntimeLaunchRequestV2
    assert observation.authorizing is False
    assert observation.identity.authorizing is False
    assert observation.identity.process_id == (f"docker:{'a' * 64}")
    assert observation.identity.runtime_boot_id == (f"container:{'a' * 64}")
    assert observation.identity.container_id == "a" * 64
    assert observation.identity.container_config_sha256 == (retained[0].container_config_sha256)
    assert observation.identity.runtime_image_id_sha256 == (request.launch.runtime_image_id_sha256)
    assert observation.identity.runtime_image_config_sha256 == (
        request.launch.runtime_image_config_sha256
    )
    assert observation.identity.runtime_code_sha256 == (request.launch.runtime_code_sha256)
    assert observation.identity.mount_contract_sha256 == (request.launch.mount_contract_sha256)
    assert observation.identity.control_network_id == (request.launch.expected_control_network_id)
    assert observation.identity.control_network_config_sha256 == (
        request.launch.expected_control_network_config_sha256
    )
    assert observation.identity.camera_network_id == (request.launch.expected_camera_network_id)
    assert observation.identity.camera_network_config_sha256 == (
        request.launch.expected_camera_network_config_sha256
    )
    assert observation.identity.controller_image_id_sha256 == (request.controller_image_id_sha256)
    assert observation.identity.controller_image_config_sha256 == (
        request.controller_image_config_sha256
    )
    assert observation.identity.controller_code_sha256 == (request.controller_code_sha256)
    assert observation.identity.observed_gpu_inventory == (
        ObservedGpuInventoryV2.model_validate(_gpu_inventory_payload())
    )
    assert observation.identity.source_bindings == request.source_bindings
    assert (
        before
        <= observation.identity.runtime_epoch_started_monotonic_ns
        <= observation.identity.identity_observed_monotonic_ns
        <= after
    )
    assert not hasattr(capability, "accepted")
    assert not hasattr(capability, "headroom")
    assert not hasattr(capability, "authority")
    assert not hasattr(capability, "process")
    assert not hasattr(capability, "__dict__")
    assert state["cleanup_calls"] == 0

    capability.cleanup()


def test_controller_strictly_reparses_constructed_request_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, _state = _runner_fixture()
    request = _matching_request(arguments)
    environment = _environment(arguments)
    malformed_request = TargetRuntimeLaunchRequestV2.model_construct(
        **{
            **request.model_dump(mode="python"),
            "runtime_epoch": True,
        }
    )
    malformed_environment = TargetRuntimeControllerEnvironmentV2.model_construct(
        **{
            **environment.model_dump(mode="python"),
            "command": ("",),
        }
    )
    calls = 0

    def forbidden_launcher(**_arguments: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("launcher must not receive invalid input")

    monkeypatch.setattr(
        acceptance_target_controller,
        "launch_docker_runtime",
        forbidden_launcher,
    )

    with pytest.raises(ValidationError):
        launch_and_observe_controller_owned_target_runtime(
            malformed_request,
            environment,
        )
    with pytest.raises(ValidationError):
        launch_and_observe_controller_owned_target_runtime(
            request,
            malformed_environment,
        )
    assert calls == 0


def test_controller_rejects_arbitrary_duck_process_and_cleans_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, _state = _runner_fixture()
    request = _matching_request(arguments)
    environment = _environment(arguments)

    class DuckProcess:
        container_id = "a" * 64
        container_config_sha256 = "b" * 64
        control_network_id = request.launch.expected_control_network_id
        control_network_config_sha256 = request.launch.expected_control_network_config_sha256
        camera_network_id = request.launch.expected_camera_network_id
        camera_network_config_sha256 = request.launch.expected_camera_network_config_sha256
        cleanup_count = 0

        def verify_identity(self) -> ObservedGpuInventoryV2:
            return ObservedGpuInventoryV2.model_validate(_gpu_inventory_payload())

        def remove(self) -> None:
            self.cleanup_count += 1

    duck = DuckProcess()
    monkeypatch.setattr(
        acceptance_target_controller,
        "launch_docker_runtime",
        lambda **_arguments: duck,
    )

    with pytest.raises(TypeError, match="exact Docker runtime process"):
        launch_and_observe_controller_owned_target_runtime(
            request,
            environment,
        )
    assert duck.cleanup_count == 1


def test_post_launch_invalid_identity_and_baseexception_clean_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, state = _runner_fixture(raise_on_observation=3)
    request = _matching_request(arguments)
    environment = _environment(arguments)
    _install_real_launcher(
        monkeypatch,
        run=run,
    )

    with pytest.raises(KeyboardInterrupt, match="GPU probe interrupted"):
        launch_and_observe_controller_owned_target_runtime(
            request,
            environment,
        )
    assert state["cleanup_calls"] == 1


def test_post_launch_primary_and_cleanup_baseexceptions_preserve_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, _state = _runner_fixture(raise_on_observation=3)
    request = _matching_request(arguments)
    environment = _environment(arguments)
    cleanup_calls = 0

    def make_cleanup_fail(process: DockerRuntimeProcess) -> DockerRuntimeProcess:
        def remove() -> None:
            nonlocal cleanup_calls
            cleanup_calls += 1
            raise RuntimeError("cleanup exploded")

        process.remove = remove  # type: ignore[method-assign]
        return process

    _install_real_launcher(
        monkeypatch,
        run=run,
        transform=make_cleanup_fail,
    )

    with pytest.raises(BaseExceptionGroup) as raised:
        launch_and_observe_controller_owned_target_runtime(
            request,
            environment,
        )
    assert cleanup_calls == 1
    assert [type(error) for error in raised.value.exceptions] == [
        KeyboardInterrupt,
        RuntimeError,
    ]


def test_invalid_exact_process_fields_are_reparsed_and_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, state = _runner_fixture()
    request = _matching_request(arguments)
    environment = _environment(arguments)

    def invalidate(process: DockerRuntimeProcess) -> DockerRuntimeProcess:
        process.container_config_sha256 = "not-a-digest"
        return process

    _install_real_launcher(
        monkeypatch,
        run=run,
        transform=invalidate,
    )

    with pytest.raises(ValidationError):
        launch_and_observe_controller_owned_target_runtime(
            request,
            environment,
        )
    assert state["cleanup_calls"] == 1


def test_constructed_gpu_observation_is_strictly_reparsed_and_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, state = _runner_fixture()
    request = _matching_request(arguments)
    environment = _environment(arguments)
    malformed = ObservedGpuInventoryV2.model_construct(
        **{
            **_gpu_inventory_payload(),
            "devices": (),
        }
    )

    def invalidate(process: DockerRuntimeProcess) -> DockerRuntimeProcess:
        process._verify_identity = lambda: malformed
        return process

    _install_real_launcher(
        monkeypatch,
        run=run,
        transform=invalidate,
    )

    with pytest.raises(RuntimeError, match="strict observed GPU inventory"):
        launch_and_observe_controller_owned_target_runtime(
            request,
            environment,
        )
    assert state["cleanup_calls"] == 1


def test_controller_capability_rejects_copy_pickle_and_removes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, state = _runner_fixture()
    request = _matching_request(arguments)
    environment = _environment(arguments)
    remove_delegations = 0

    def count_remove(process: DockerRuntimeProcess) -> DockerRuntimeProcess:
        original = process.remove

        def remove() -> None:
            nonlocal remove_delegations
            remove_delegations += 1
            original()

        process.remove = remove  # type: ignore[method-assign]
        return process

    _install_real_launcher(
        monkeypatch,
        run=run,
        transform=count_remove,
    )
    capability, _observation = launch_and_observe_controller_owned_target_runtime(
        request,
        environment,
    )

    for operation in (
        lambda: copy.copy(capability),
        lambda: copy.deepcopy(capability),
        lambda: pickle.dumps(capability),
    ):
        with pytest.raises(TypeError, match="cannot be copied or serialized"):
            operation()
    capability.cleanup()
    capability.cleanup()
    assert remove_delegations == 1
    assert state["cleanup_calls"] == 1


def test_reverification_rejects_full_inventory_drift_and_cleans_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, state = _runner_fixture(
        inventory_mutation=("device.product_name", "drifted"),
        mutation_start_observation=4,
    )
    request = _matching_request(arguments)
    environment = _environment(arguments)
    _install_real_launcher(
        monkeypatch,
        run=run,
    )
    capability, observation = launch_and_observe_controller_owned_target_runtime(
        request,
        environment,
    )

    assert observation.identity.observed_gpu_inventory.devices[0].product_name == ("NVIDIA L4")
    with pytest.raises(RuntimeError, match="GPU inventory"):
        capability.reverify_identity()
    assert state["cleanup_calls"] == 1


def test_reverification_rejects_full_process_identity_drift_and_cleans_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, state = _runner_fixture()
    request = _matching_request(arguments)
    environment = _environment(arguments)
    retained: list[DockerRuntimeProcess] = []

    def retain(process: DockerRuntimeProcess) -> DockerRuntimeProcess:
        retained.append(process)
        return process

    _install_real_launcher(
        monkeypatch,
        run=run,
        transform=retain,
    )
    capability, _observation = launch_and_observe_controller_owned_target_runtime(
        request,
        environment,
    )
    retained[0].container_config_sha256 = "f" * 64

    with pytest.raises(RuntimeError, match="identity changed"):
        capability.reverify_identity()
    assert state["cleanup_calls"] == 1


def test_lifecycle_baseexception_fails_closed_and_cleans_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, run, state = _runner_fixture()
    request = _matching_request(arguments)
    environment = _environment(arguments)
    retained: list[DockerRuntimeProcess] = []

    def retain(process: DockerRuntimeProcess) -> DockerRuntimeProcess:
        retained.append(process)
        return process

    _install_real_launcher(
        monkeypatch,
        run=run,
        transform=retain,
    )
    capability, _observation = launch_and_observe_controller_owned_target_runtime(
        request,
        environment,
    )

    def interrupted() -> int | None:
        raise KeyboardInterrupt("poll interrupted")

    retained[0].poll = interrupted  # type: ignore[method-assign]

    with pytest.raises(KeyboardInterrupt, match="poll interrupted"):
        capability.poll()
    assert state["cleanup_calls"] == 1
