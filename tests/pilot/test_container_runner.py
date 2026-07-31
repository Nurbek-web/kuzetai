import copy
import hashlib
import json
import pickle
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from protector.pilot.acceptance_target import (
    ObservedGpuDeviceV2,
    ObservedGpuInventoryV2,
)
from protector.pilot.runtime import container_runner
from protector.pilot.runtime.container_runner import (
    DockerRuntimeProcess,
    _cuda_version_string,
    _parse_nvidia_ctk_version,
    _reconcile_runner_container,
    _strict_observed_gpu_inventory,
    launch_docker_runtime,
)

CONTAINER_ID = "a" * 64
NONCE = "b" * 32
NAME = f"kuzet-acceptance-{NONCE}"


def _completed(
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_uncertain_create_reconciliation_catches_delayed_daemon_container() -> None:
    list_calls = 0
    removed: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        nonlocal list_calls
        if command[1:3] == ("container", "ls"):
            list_calls += 1
            return _completed(
                stdout=f"{CONTAINER_ID}\n" if list_calls == 3 else ""
            )
        if command[1] == "inspect":
            return _completed(
                stdout=json.dumps(
                    {
                        "Id": CONTAINER_ID,
                        "Name": f"/{NAME}",
                        "Config": {
                            "Labels": {
                                "ai.kuzet.launch-nonce": NONCE,
                            }
                        },
                    }
                )
            )
        if command[1:3] == ("rm", "--force"):
            removed.append(command)
            return _completed()
        raise AssertionError(command)

    _reconcile_runner_container(
        engine="/usr/bin/docker",
        name=NAME,
        launch_nonce=NONCE,
        run=run,
        uncertain_create=True,
        pause=lambda _seconds: None,
    )

    assert removed == [
        ("/usr/bin/docker", "rm", "--force", CONTAINER_ID)
    ]
    assert list_calls >= 123


def test_uncertain_create_reconciliation_keeps_full_absence_horizon_after_late_create() -> None:
    list_calls = 0
    removed: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        nonlocal list_calls
        if command[1:3] == ("container", "ls"):
            list_calls += 1
            return _completed(
                stdout=f"{CONTAINER_ID}\n" if list_calls == 120 else ""
            )
        if command[1] == "inspect":
            return _completed(
                stdout=json.dumps(
                    {
                        "Id": CONTAINER_ID,
                        "Name": f"/{NAME}",
                        "Config": {
                            "Labels": {
                                "ai.kuzet.launch-nonce": NONCE,
                            }
                        },
                    }
                )
            )
        if command[1:3] == ("rm", "--force"):
            removed.append(command)
            return _completed()
        raise AssertionError(command)

    _reconcile_runner_container(
        engine="/usr/bin/docker",
        name=NAME,
        launch_nonce=NONCE,
        run=run,
        uncertain_create=True,
        pause=lambda _seconds: None,
    )

    assert removed == [
        ("/usr/bin/docker", "rm", "--force", CONTAINER_ID)
    ]
    assert list_calls == 240


def test_reconciliation_surfaces_nonzero_remove_and_never_claims_absence() -> None:
    remove_calls = 0

    def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        nonlocal remove_calls
        if command[1:3] == ("container", "ls"):
            return _completed(stdout=f"{CONTAINER_ID}\n")
        if command[1] == "inspect":
            return _completed(
                stdout=json.dumps(
                    {
                        "Id": CONTAINER_ID,
                        "Name": f"/{NAME}",
                        "Config": {
                            "Labels": {
                                "ai.kuzet.launch-nonce": NONCE,
                            }
                        },
                    }
                )
            )
        if command[1:3] == ("rm", "--force"):
            remove_calls += 1
            return _completed(returncode=1, stderr="daemon busy")
        raise AssertionError(command)

    with pytest.raises(RuntimeError, match="absence could not be proven"):
        _reconcile_runner_container(
            engine="/usr/bin/docker",
            name=NAME,
            launch_nonce=NONCE,
            run=run,
            uncertain_create=False,
            pause=lambda _seconds: None,
        )
    assert remove_calls == 24


def test_reconciliation_never_removes_name_collision_without_launch_label() -> None:
    remove_called = False

    def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        nonlocal remove_called
        if command[1:3] == ("container", "ls"):
            return _completed(stdout=f"{CONTAINER_ID}\n")
        if command[1] == "inspect":
            return _completed(
                stdout=json.dumps(
                    {
                        "Id": CONTAINER_ID,
                        "Name": f"/{NAME}",
                        "Config": {"Labels": {}},
                    }
                )
            )
        if command[1:3] == ("rm", "--force"):
            remove_called = True
            return _completed()
        raise AssertionError(command)

    with pytest.raises(RuntimeError, match="refusing to remove"):
        _reconcile_runner_container(
            engine="/usr/bin/docker",
            name=NAME,
            launch_nonce=NONCE,
            run=run,
            uncertain_create=False,
            pause=lambda _seconds: None,
        )
    assert remove_called is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        (12080, "12.8"),
        (12081, "12.8.1"),
        (13000, "13.0"),
    ),
)
def test_cuda_version_integer_is_canonical(raw: int, expected: str) -> None:
    assert _cuda_version_string(raw) == expected


@pytest.mark.parametrize("raw", (-1, 0, 999, 100_000, True))
def test_cuda_version_integer_rejects_invalid_values(raw: object) -> None:
    with pytest.raises(ValueError, match="CUDA version"):
        _cuda_version_string(raw)


def test_nvidia_ctk_version_is_parsed_from_exact_cli_banner() -> None:
    assert (
        _parse_nvidia_ctk_version(
            "NVIDIA Container Toolkit CLI version 1.17.8\n"
            "commit: 0123456789abcdef\n"
        )
        == "1.17.8"
    )


@pytest.mark.parametrize(
    "payload",
    (
        "1.17.8\n",
        "NVIDIA Container Toolkit CLI version latest\n",
        "prefix NVIDIA Container Toolkit CLI version 1.17.8\n",
        "NVIDIA Container Toolkit CLI version 1.17.8 trailing\n",
    ),
)
def test_nvidia_ctk_version_rejects_ambiguous_output(payload: str) -> None:
    with pytest.raises(RuntimeError, match="toolkit version"):
        _parse_nvidia_ctk_version(payload)


def _gpu_inventory_payload(
    **overrides: object,
) -> dict[str, object]:
    device = {
        "uuid": "GPU-11111111-2222-3333-4444-555555555555",
        "product_name": "NVIDIA L4",
        "pci_bus_id": "0000:01:00.0",
        "total_vram_bytes": 23_040 * 1024 * 1024,
        "compute_capability": "8.9",
        "mig_mode": "disabled",
    }
    device.update(overrides.pop("device", {}))  # type: ignore[arg-type]
    return {
        "schema_version": "observed-gpu-inventory.v2",
        "devices": [device],
        "nvidia_driver_version": "570.86.15",
        "cuda_driver_version": "12.8",
        "cuda_runtime_version": "12.8",
        "nvidia_container_toolkit_version": "1.17.8",
        "authorizing": False,
        **overrides,
    }


def _compatibility_inventory_payload() -> dict[str, object]:
    payload = _gpu_inventory_payload()
    return {
        "schema_version": "measured-gpu-inventory.v1",
        "devices": payload["devices"],
        "nvidia_driver_version": payload["nvidia_driver_version"],
        "cuda_driver_version": payload["cuda_driver_version"],
        "cuda_runtime_version": payload["cuda_runtime_version"],
        "nvidia_container_toolkit_version": payload[
            "nvidia_container_toolkit_version"
        ],
    }


def _literal_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _runner_fixture(
    *,
    inventory_mutation: tuple[str, object] | None = None,
    mutation_start_observation: int = 3,
    raise_on_observation: int | None = None,
    cleanup_raises: bool = False,
) -> tuple[dict[str, object], Any, dict[str, object]]:
    image_id = f"sha256:{'1' * 64}"
    runtime_code_sha256 = "2" * 64
    command = ("--site-config", "/run/config/site.yaml")
    control_network = "kuzet-control"
    camera_network = "kuzet-camera"
    control_network_id = "3" * 64
    camera_network_id = "4" * 64
    control_network_payload = {
        "Id": control_network_id,
        "Name": control_network,
        "Driver": "bridge",
        "Internal": True,
        "IPAM": {
            "Config": [
                {
                    "Subnet": "10.20.0.0/24",
                    "Gateway": "10.20.0.1",
                }
            ]
        },
        "Options": {},
        "Labels": {},
    }
    camera_network_payload = {
        "Id": camera_network_id,
        "Name": camera_network,
        "Driver": "macvlan",
        "Internal": False,
        "IPAM": {
            "Config": [
                {
                    "Subnet": "10.30.0.0/24",
                    "Gateway": "10.30.0.1",
                }
            ]
        },
        "Options": {},
        "Labels": {"ai.kuzet.camera-policy": "reviewed"},
    }
    image_config = {
        "Entrypoint": [
            "python3",
            "-m",
            "protector.pilot.runtime.production_main",
        ],
        "Cmd": None,
        "User": "10001:10001",
        "Env": ["PYTHONUNBUFFERED=1"],
        "WorkingDir": "/app",
        "Labels": {"ai.kuzet.runtime-code-sha256": runtime_code_sha256},
    }
    image_payload = {"Id": image_id, "Config": image_config}
    container_config = {
        "Cmd": [
            "-m",
            "protector.pilot.runtime.deepstream",
            *command,
        ],
        "Entrypoint": ["python3"],
        "User": "10001:10001",
        "Labels": {
            "ai.kuzet.launch-nonce": NONCE,
            "ai.kuzet.runtime-code-sha256": runtime_code_sha256,
            "ai.kuzet.mount-contract-sha256": "5" * 64,
        },
    }
    host_config = {
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "Privileged": False,
        "RestartPolicy": {"Name": "no"},
        "PidsLimit": 512,
        "Memory": 16 * 1024**3,
        "NanoCpus": 8_000_000_000,
        "PidMode": "",
        "IpcMode": "private",
        "Tmpfs": {
            "/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=1777",
            "/var/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777",
        },
        "LogConfig": {
            "Type": "local",
            "Config": {"max-file": "3", "max-size": "10m"},
        },
        "DeviceRequests": [
            {
                "DeviceIDs": [
                    "GPU-11111111-2222-3333-4444-555555555555"
                ],
                "Count": 0,
                "Capabilities": [["compute", "utility", "video"]],
            }
        ],
    }
    container_payload = {
        "Id": CONTAINER_ID,
        "Image": image_id,
        "Name": f"/{NAME}",
        "State": {"Status": "created"},
        "Config": container_config,
        "HostConfig": host_config,
        "Mounts": [],
        "NetworkSettings": {
            "Networks": {
                control_network: {"NetworkID": control_network_id},
                camera_network: {"NetworkID": camera_network_id},
            }
        },
    }
    inventory_observations = 0
    state: dict[str, object] = {
        "cleanup_calls": 0,
        "invocations": [],
        "removed": False,
        "restart_calls": 0,
    }

    def run(
        invocation: tuple[str, ...],
        **_kwargs: object,
    ) -> SimpleNamespace:
        nonlocal inventory_observations
        invocations = state["invocations"]
        assert isinstance(invocations, list)
        invocations.append(invocation)
        if invocation[0] == "/usr/bin/nvidia-ctk":
            version = "1.17.8"
            if (
                inventory_mutation
                == ("nvidia_container_toolkit_version", "1.18.0")
                and inventory_observations >= mutation_start_observation
            ):
                version = "1.18.0"
            return _completed(
                stdout=(
                    f"NVIDIA Container Toolkit CLI version {version}\n"
                    "commit: abcdef\n"
                )
            )
        command_tail = invocation[1:]
        if command_tail[:3] == (
            "network",
            "inspect",
            "--format",
        ):
            payload = (
                control_network_payload
                if command_tail[-1] == control_network
                else camera_network_payload
            )
            return _completed(stdout=json.dumps(payload))
        if command_tail[:3] == ("image", "inspect", "--format"):
            return _completed(stdout=json.dumps(image_payload))
        if command_tail and command_tail[0] == "create":
            return _completed(stdout=f"{CONTAINER_ID}\n")
        if command_tail[:2] == ("network", "connect"):
            return _completed()
        if command_tail[:2] == ("inspect", "--format"):
            return _completed(stdout=json.dumps(container_payload))
        if command_tail[:2] == ("container", "ls"):
            if cleanup_raises:
                raise RuntimeError("cleanup exploded")
            return _completed(
                stdout="" if state["removed"] else f"{CONTAINER_ID}\n"
            )
        if command_tail[:2] == ("rm", "--force"):
            state["cleanup_calls"] = int(state["cleanup_calls"]) + 1
            state["removed"] = True
            return _completed()
        if command_tail[:2] == ("start", CONTAINER_ID):
            return _completed()
        if command_tail[:2] == ("restart", "--time"):
            state["restart_calls"] = int(state["restart_calls"]) + 1
            return _completed()
        if command_tail[:3] == ("exec", CONTAINER_ID, "nvidia-smi"):
            inventory_observations += 1
            if inventory_observations == raise_on_observation:
                raise KeyboardInterrupt("GPU probe interrupted")
            inventory = _gpu_inventory_payload()
            if (
                inventory_mutation is not None
                and inventory_observations >= mutation_start_observation
            ):
                field, value = inventory_mutation
                if field.startswith("device."):
                    inventory["devices"][0][field.removeprefix("device.")] = value  # type: ignore[index]
                else:
                    inventory[field] = value
            device = inventory["devices"][0]  # type: ignore[index]
            return _completed(
                stdout=(
                    f"{device['uuid']}, {device['product_name']}, "  # type: ignore[index]
                    f"{device['pci_bus_id']}, "  # type: ignore[index]
                    f"{int(device['total_vram_bytes']) // 1024 // 1024}, "  # type: ignore[index]
                    f"{device['compute_capability']}, "  # type: ignore[index]
                    f"{device['mig_mode']}, "  # type: ignore[index]
                    f"{inventory['nvidia_driver_version']}\n"
                )
            )
        if command_tail[:3] == ("exec", CONTAINER_ID, "python3"):
            inventory = _gpu_inventory_payload()
            if (
                inventory_mutation is not None
                and inventory_observations >= mutation_start_observation
            ):
                field, value = inventory_mutation
                if field in {"cuda_driver_version", "cuda_runtime_version"}:
                    inventory[field] = value
            version_to_integer = {
                "12.8": 12080,
                "12.9": 12090,
            }
            return _completed(
                stdout=json.dumps(
                    {
                        "cuda_driver_version_integer": version_to_integer[
                            inventory["cuda_driver_version"]
                        ],
                        "cuda_runtime_version_integer": version_to_integer[
                            inventory["cuda_runtime_version"]
                        ],
                    }
                )
            )
        raise AssertionError(invocation)

    expected = {
        "engine_path": Path("/usr/bin/docker"),
        "nvidia_ctk_path": Path("/usr/bin/nvidia-ctk"),
        "image_id": image_id,
        "image_config_sha256": _literal_digest(
            {
                field: image_config.get(field)
                for field in (
                    "Entrypoint",
                    "Cmd",
                    "User",
                    "Env",
                    "WorkingDir",
                    "Labels",
                )
            }
        ),
        "runtime_code_sha256": runtime_code_sha256,
        "mount_contract_sha256": "5" * 64,
        "launch_nonce": NONCE,
        "command": command,
        "mount_argv": (),
        "control_network": control_network,
        "camera_network": camera_network,
        "expected_control_network_id": control_network_id,
        "expected_control_network_config_sha256": _literal_digest(
            control_network_payload
        ),
        "expected_camera_network_id": camera_network_id,
        "expected_camera_network_config_sha256": _literal_digest(
            camera_network_payload
        ),
        "expected_gpu_device_ids": (
            "GPU-11111111-2222-3333-4444-555555555555",
        ),
        "expected_gpu_product_name": "NVIDIA L4",
        "expected_gpu_pci_bus_id": "0000:01:00.0",
        "expected_gpu_total_vram_bytes": 23_040 * 1024 * 1024,
        "expected_gpu_compute_capability": "8.9",
        "expected_gpu_mig_mode": "disabled",
        "expected_gpu_inventory_sha256": _literal_digest(
            _compatibility_inventory_payload()
        ),
        "expected_nvidia_driver_version": "570.86.15",
        "expected_cuda_driver_version": "12.8",
        "expected_cuda_runtime_version": "12.8",
        "expected_nvidia_container_toolkit_version": "1.17.8",
        "run": run,
    }
    return expected, run, state


def test_docker_runtime_process_rejects_nonissuer_construction() -> None:
    inventory = ObservedGpuInventoryV2.model_validate(
        _gpu_inventory_payload()
    )
    with pytest.raises(RuntimeError, match="exact runner issuer"):
        DockerRuntimeProcess(
            _issuer=object(),
            engine="/usr/bin/docker",
            container_id=CONTAINER_ID,
            container_config_sha256="1" * 64,
            control_network_id="2" * 64,
            control_network_config_sha256="3" * 64,
            camera_network_id="4" * 64,
            camera_network_config_sha256="5" * 64,
            observed_gpu_inventory=inventory,
            name=NAME,
            launch_nonce=NONCE,
            verify_identity=lambda: inventory,
            run=lambda *_args, **_kwargs: _completed(),
        )


def test_strict_inventory_parser_revalidates_model_construct() -> None:
    malformed = ObservedGpuInventoryV2.model_construct(
        schema_version="observed-gpu-inventory.v2",
        devices=(
            ObservedGpuDeviceV2.model_construct(
                uuid="not-a-gpu",
                product_name="NVIDIA L4",
                pci_bus_id="0000:01:00.0",
                total_vram_bytes=1,
                compute_capability="8.9",
                mig_mode="disabled",
            ),
        ),
        nvidia_driver_version="570.86.15",
        cuda_driver_version="12.8",
        cuda_runtime_version="12.8",
        nvidia_container_toolkit_version="1.17.8",
        authorizing=False,
    )
    with pytest.raises(RuntimeError, match="strict observed GPU inventory"):
        _strict_observed_gpu_inventory(malformed)


def test_launch_retains_and_reverifies_complete_immutable_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, _state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )

    process = launch_docker_runtime(**arguments)

    initial = process.initial_observed_gpu_inventory
    assert initial == ObservedGpuInventoryV2.model_validate(
        _gpu_inventory_payload()
    )
    assert process.observed_gpu_inventory == initial
    assert process.observed_gpu_inventory_sha256 == _literal_digest(
        _compatibility_inventory_payload()
    )
    with pytest.raises(ValidationError):
        initial.devices[0].product_name = "mutated"


def test_create_explicitly_overrides_acceptance_runtime_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )

    launch_docker_runtime(**arguments)

    invocations = state["invocations"]
    assert isinstance(invocations, list)
    create = next(
        invocation
        for invocation in invocations
        if invocation[1:2] == ("create",)
    )
    assert create.count("--entrypoint") == 1
    entrypoint = create.index("--entrypoint")
    assert entrypoint < create.index(arguments["image_id"])
    assert create[entrypoint + 1] == "python3"
    image = create.index(arguments["image_id"])
    assert create[image + 1 :] == (
        "-m",
        "protector.pilot.runtime.deepstream",
        *arguments["command"],
    )


def test_create_preserves_literal_quotes_in_gpu_capabilities_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )

    launch_docker_runtime(**arguments)

    invocations = state["invocations"]
    assert isinstance(invocations, list)
    create = next(
        invocation
        for invocation in invocations
        if invocation[1:2] == ("create",)
    )
    assert create.count("--gpus") == 1
    gpus = create.index("--gpus")
    assert create[gpus : gpus + 2] == (
        "--gpus",
        (
            "device=GPU-11111111-2222-3333-4444-555555555555,"
            '"capabilities=compute,utility,video"'
        ),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("device.uuid", "GPU-99999999-2222-3333-4444-555555555555"),
        ("device.product_name", "NVIDIA L4 changed"),
        ("device.pci_bus_id", "0000:02:00.0"),
        ("device.total_vram_bytes", 22_000 * 1024 * 1024),
        ("device.compute_capability", "9.0"),
        ("device.mig_mode", "enabled"),
        ("nvidia_driver_version", "571.00"),
        ("cuda_driver_version", "12.9"),
        ("cuda_runtime_version", "12.9"),
        ("nvidia_container_toolkit_version", "1.18.0"),
    ),
)
def test_verify_identity_rejects_each_complete_inventory_field_drift(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    arguments, _run, _state = _runner_fixture(
        inventory_mutation=(field, value),
    )
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )
    process = launch_docker_runtime(**arguments)

    with pytest.raises(
        RuntimeError,
        match="GPU inventory|strict observed GPU inventory",
    ):
        process.verify_identity()


def test_process_capability_cannot_be_copied_deepcopied_or_pickled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, _state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )
    process = launch_docker_runtime(**arguments)

    for clone in (
        lambda: copy.copy(process),
        lambda: copy.deepcopy(process),
        lambda: pickle.dumps(process),
    ):
        with pytest.raises(TypeError, match="cannot be copied or serialized"):
            clone()


def test_returned_inventory_cannot_alias_or_mutate_process_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, _state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )
    process = launch_docker_runtime(**arguments)

    exposed = process.initial_observed_gpu_inventory
    exposed.devices[0].__dict__["product_name"] = "TAMPERED"

    assert (
        process.initial_observed_gpu_inventory.devices[0].product_name
        == "NVIDIA L4"
    )
    assert process.verify_identity().devices[0].product_name == "NVIDIA L4"


def test_post_start_identity_failure_reconciles_created_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, state = _runner_fixture(
        inventory_mutation=("device.product_name", "drifted"),
        mutation_start_observation=2,
    )
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )

    with pytest.raises(RuntimeError, match="GPU inventory"):
        launch_docker_runtime(**arguments)

    assert state["cleanup_calls"] == 1
    assert state["removed"] is True


def test_post_start_baseexception_and_cleanup_failure_preserve_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, state = _runner_fixture(
        raise_on_observation=2,
        cleanup_raises=True,
    )
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )

    caught: BaseException | None = None
    try:
        launch_docker_runtime(**arguments)
    except BaseException as exc:
        caught = exc

    assert isinstance(caught, BaseExceptionGroup)
    assert [type(item) for item in caught.exceptions] == [
        KeyboardInterrupt,
        RuntimeError,
    ]
    assert state["cleanup_calls"] == 0


def test_verify_identity_rejects_hostile_untyped_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, _state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )
    process = launch_docker_runtime(**arguments)
    process._verify_identity = lambda: _gpu_inventory_payload()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="strict observed GPU inventory"):
        process.verify_identity()


def test_verify_identity_rejects_callback_model_subclass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InventorySubclass(ObservedGpuInventoryV2):
        pass

    arguments, _run, _state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )
    process = launch_docker_runtime(**arguments)
    subclass = InventorySubclass.model_validate(_gpu_inventory_payload())
    process._verify_identity = lambda: subclass  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="strict observed GPU inventory"):
        process.verify_identity()


def test_verify_identity_revalidates_callback_model_construct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, _state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )
    process = launch_docker_runtime(**arguments)
    malformed = ObservedGpuInventoryV2.model_construct(
        **{
            **_gpu_inventory_payload(),
            "devices": (
                ObservedGpuDeviceV2.model_construct(
                    **{
                        **_gpu_inventory_payload()["devices"][0],  # type: ignore[index]
                        "uuid": "invalid",
                    }
                ),
            ),
        }
    )
    process._verify_identity = lambda: malformed

    with pytest.raises(RuntimeError, match="strict observed GPU inventory"):
        process.verify_identity()


def test_verify_identity_preserves_callback_baseexception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, _state = _runner_fixture()
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )
    process = launch_docker_runtime(**arguments)

    def interrupted() -> ObservedGpuInventoryV2:
        raise KeyboardInterrupt("probe interrupted")

    process._verify_identity = interrupted

    with pytest.raises(KeyboardInterrupt, match="probe interrupted"):
        process.verify_identity()


def test_restart_requeries_and_rejects_full_inventory_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, _run, state = _runner_fixture(
        inventory_mutation=("device.product_name", "drifted"),
    )
    monkeypatch.setattr(
        container_runner,
        "_trusted_engine",
        lambda path: str(path),
    )
    process = launch_docker_runtime(**arguments)

    with pytest.raises(RuntimeError, match="GPU inventory"):
        process.restart(timeout_seconds=5)

    assert state["restart_calls"] == 1


def test_runner_issuer_token_is_not_a_module_global() -> None:
    assert not hasattr(container_runner, "_PROCESS_ISSUER")
