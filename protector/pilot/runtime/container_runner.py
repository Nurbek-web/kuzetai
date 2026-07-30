"""Runner-owned immutable Docker process for target acceptance."""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Callable

from protector.pilot.acceptance_target import ObservedGpuInventoryV2

__all__ = ("DockerRuntimeProcess", "launch_docker_runtime")

_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_NVIDIA_CTK_VERSION = re.compile(
    r"^NVIDIA Container Toolkit CLI version "
    r"([0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)$"
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _trusted_engine(path: Path) -> str:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("container engine must be an absolute non-symlink path")
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not os.access(resolved, os.X_OK)
    ):
        raise ValueError("container engine ownership or mode is unsafe")
    for ancestor in (resolved.parent, *resolved.parents):
        ancestor_metadata = ancestor.stat()
        if ancestor_metadata.st_uid != 0 or ancestor_metadata.st_mode & 0o022:
            raise ValueError("container engine ancestor ownership or mode is unsafe")
    return str(resolved)


def _parse_nvidia_ctk_version(payload: str) -> str:
    """Parse the version from the exact first-line nvidia-ctk banner."""
    lines = payload.splitlines()
    if not lines:
        raise RuntimeError("NVIDIA container toolkit version is unavailable")
    matched = _NVIDIA_CTK_VERSION.fullmatch(lines[0])
    if matched is None:
        raise RuntimeError("NVIDIA container toolkit version output is invalid")
    return matched.group(1)


def _cuda_version_string(value: object) -> str:
    """Convert the CUDA integer API representation to a canonical version."""
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1_000 <= value < 100_000
    ):
        raise ValueError("CUDA version integer is invalid")
    major = value // 1_000
    minor = value % 1_000 // 10
    patch = value % 10
    if minor > 99:
        raise ValueError("CUDA version integer is invalid")
    return (
        f"{major}.{minor}"
        if patch == 0
        else f"{major}.{minor}.{patch}"
    )


def _strict_observed_gpu_inventory(
    value: object,
) -> ObservedGpuInventoryV2:
    try:
        if type(value) is not ObservedGpuInventoryV2:
            raise TypeError("unexpected observed GPU inventory type")
        return ObservedGpuInventoryV2.model_validate(
            value.model_dump(mode="python")
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError("strict observed GPU inventory is invalid") from exc


def _reconcile_runner_container(
    *,
    engine: str,
    name: str,
    launch_nonce: str,
    run: Callable[..., subprocess.CompletedProcess[str]],
    uncertain_create: bool,
    pause: Callable[[float], None] = time.sleep,
) -> None:
    """Remove only the exact runner-labelled container and prove it is absent."""
    # A timed-out create request may continue in the daemon for the original
    # 30-second client horizon. Do not declare absence during that race window.
    required_absent_observations = 120 if uncertain_create else 2
    absent_observations = 0
    failures: list[str] = []
    # Cover the full create-timeout horizon and retain the same consecutive
    # absence horizon after a container appears at its very end.
    minimum_observations = 120 if uncertain_create else 0
    for attempt in range(240 if uncertain_create else 24):
        try:
            listed = run(
                (
                    engine,
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    f"name=^/{name}$",
                    "--format",
                    "{{.ID}}",
                ),
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(type(exc).__name__)
            absent_observations = 0
            pause(0.25)
            continue
        if (
            listed.returncode
            or len(listed.stdout.encode()) > 4096
            or len(listed.stderr.encode()) > 4096
        ):
            failures.append("list")
            absent_observations = 0
            pause(0.25)
            continue
        container_ids = tuple(
            line.strip()
            for line in listed.stdout.splitlines()
            if line.strip()
        )
        if not container_ids:
            absent_observations += 1
            if (
                attempt + 1 >= minimum_observations
                and absent_observations >= required_absent_observations
            ):
                return
            pause(0.25)
            continue
        absent_observations = 0
        if (
            len(container_ids) != 1
            or _CONTAINER_ID.fullmatch(container_ids[0]) is None
        ):
            raise RuntimeError(
                "runner-owned container cleanup identity is ambiguous"
            )
        container_id = container_ids[0]
        inspected = run(
            (engine, "inspect", "--format", "{{json .}}", container_id),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        try:
            details = json.loads(inspected.stdout)
            labels = details["Config"]["Labels"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "runner-owned container cleanup inspection failed"
            ) from exc
        if (
            inspected.returncode
            or details.get("Id") != container_id
            or details.get("Name") != f"/{name}"
            or not isinstance(labels, dict)
            or labels.get("ai.kuzet.launch-nonce") != launch_nonce
        ):
            raise RuntimeError(
                "refusing to remove container without exact runner ownership"
            )
        removed = run(
            (engine, "rm", "--force", container_id),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if removed.returncode:
            failures.append("remove")
        pause(0.25)
    suffix = f" ({','.join(failures[-4:])})" if failures else ""
    raise RuntimeError(
        f"runner-owned container absence could not be proven{suffix}"
    )


class DockerRuntimeProcess:
    """Small process-like wrapper that controls only its runner-created container."""

    def __init__(
        self,
        *,
        _issuer: object | None = None,
        engine: str,
        container_id: str,
        container_config_sha256: str,
        control_network_id: str,
        control_network_config_sha256: str,
        camera_network_id: str,
        camera_network_config_sha256: str,
        observed_gpu_inventory: ObservedGpuInventoryV2,
        name: str,
        launch_nonce: str,
        verify_identity: Callable[[], ObservedGpuInventoryV2],
        run: Callable[..., subprocess.CompletedProcess[str]],
    ) -> None:
        if not _is_process_issuer(_issuer):
            raise RuntimeError(
                "Docker runtime process requires its exact runner issuer"
            )
        self._engine = engine
        self.container_id = container_id
        self.container_config_sha256 = container_config_sha256
        self.control_network_id = control_network_id
        self.control_network_config_sha256 = control_network_config_sha256
        self.camera_network_id = camera_network_id
        self.camera_network_config_sha256 = camera_network_config_sha256
        initial_inventory = _strict_observed_gpu_inventory(
            observed_gpu_inventory
        )
        self._initial_observed_gpu_inventory_json = _canonical_json(
            initial_inventory.model_dump(mode="json")
        )
        self.observed_gpu_inventory_sha256 = (
            initial_inventory.launch_compatibility_sha256
        )
        self._name = name
        self._launch_nonce = launch_nonce
        self._verify_identity = verify_identity
        self._run = run
        self.returncode: int | None = None
        self._removed = False

    def __copy__(self) -> DockerRuntimeProcess:
        raise TypeError(
            "Docker runtime process capability cannot be copied or serialized"
        )

    def __deepcopy__(
        self,
        _memo: dict[int, object],
    ) -> DockerRuntimeProcess:
        raise TypeError(
            "Docker runtime process capability cannot be copied or serialized"
        )

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError(
            "Docker runtime process capability cannot be copied or serialized"
        )

    def _command(self, *arguments: str, timeout: float = 30) -> str:
        if _trusted_engine(Path(self._engine)) != self._engine:
            raise RuntimeError("trusted container engine identity changed")
        result = self._run(
            (self._engine, *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode:
            raise RuntimeError("runner-owned container command failed")
        if len(result.stdout.encode()) > 1024 * 1024:
            raise RuntimeError("runner-owned container response exceeded its bound")
        return result.stdout.strip()

    def poll(self) -> int | None:
        output = self._command(
            "inspect",
            "--format",
            "{{.State.Status}} {{.State.ExitCode}}",
            self.container_id,
        )
        status, separator, exit_code = output.partition(" ")
        if separator != " " or not exit_code.isdigit():
            raise RuntimeError("runner-owned container state response is invalid")
        if status in {"created", "running", "restarting"}:
            return None
        if status in {"exited", "dead"}:
            self.returncode = int(exit_code)
            return self.returncode
        raise RuntimeError("runner-owned container entered an unexpected state")

    def restart(self, *, timeout_seconds: int) -> None:
        self._command(
            "restart",
            "--time",
            str(timeout_seconds),
            self.container_id,
            timeout=timeout_seconds + 30,
        )
        self.returncode = None
        self.verify_identity()

    @property
    def initial_observed_gpu_inventory(self) -> ObservedGpuInventoryV2:
        return _strict_observed_gpu_inventory(
            ObservedGpuInventoryV2.model_validate_json(
                self._initial_observed_gpu_inventory_json
            )
        )

    @property
    def observed_gpu_inventory(self) -> ObservedGpuInventoryV2:
        return self.verify_identity()

    def verify_identity(self) -> ObservedGpuInventoryV2:
        if self._removed:
            raise RuntimeError("runner-owned container was already removed")
        current = _strict_observed_gpu_inventory(self._verify_identity())
        if (
            _canonical_json(current.model_dump(mode="json"))
            != self._initial_observed_gpu_inventory_json
        ):
            raise RuntimeError(
                "runner-owned full observed GPU inventory changed"
            )
        return current

    def terminate(self, *, timeout_seconds: int) -> None:
        if not 1 <= timeout_seconds <= 60:
            raise ValueError("container stop grace is invalid")
        self._command(
            "stop",
            "--time",
            str(timeout_seconds),
            self.container_id,
            timeout=timeout_seconds + 30,
        )

    def wait(self, timeout: float) -> int:
        output = self._command("wait", self.container_id, timeout=timeout)
        if not output.isdigit():
            raise RuntimeError("runner-owned container wait response is invalid")
        self.returncode = int(output)
        return self.returncode

    def kill(self) -> None:
        self._command("kill", self.container_id)

    def remove(self) -> None:
        if self._removed:
            return
        _reconcile_runner_container(
            engine=self._engine,
            name=self._name,
            launch_nonce=self._launch_nonce,
            run=self._run,
            uncertain_create=False,
        )
        self._removed = True


def _make_process_issuer() -> tuple[
    Callable[[object], bool],
    Callable[..., DockerRuntimeProcess],
]:
    token = object()

    def is_issuer(candidate: object) -> bool:
        return candidate is token

    def issue(**arguments: object) -> DockerRuntimeProcess:
        return DockerRuntimeProcess(_issuer=token, **arguments)

    return is_issuer, issue


_is_process_issuer, _issue_docker_runtime_process = _make_process_issuer()


def launch_docker_runtime(
    *,
    engine_path: Path,
    nvidia_ctk_path: Path,
    image_id: str,
    image_config_sha256: str,
    runtime_code_sha256: str,
    mount_contract_sha256: str,
    launch_nonce: str,
    command: tuple[str, ...],
    mount_argv: tuple[str, ...],
    control_network: str,
    camera_network: str,
    expected_control_network_id: str,
    expected_control_network_config_sha256: str,
    expected_camera_network_id: str,
    expected_camera_network_config_sha256: str,
    expected_gpu_device_ids: tuple[str, ...],
    expected_gpu_product_name: str,
    expected_gpu_pci_bus_id: str,
    expected_gpu_total_vram_bytes: int,
    expected_gpu_compute_capability: str,
    expected_gpu_mig_mode: str,
    expected_gpu_inventory_sha256: str,
    expected_nvidia_driver_version: str,
    expected_cuda_driver_version: str,
    expected_cuda_runtime_version: str,
    expected_nvidia_container_toolkit_version: str,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> DockerRuntimeProcess:
    """Inspect, create, re-inspect, and start one exact immutable runtime."""
    engine = _trusted_engine(engine_path)
    nvidia_ctk = _trusted_engine(nvidia_ctk_path)
    if (
        _IMAGE_ID.fullmatch(image_id) is None
        or not re.fullmatch(r"[a-f0-9]{64}", image_config_sha256)
        or not re.fullmatch(r"[a-f0-9]{64}", runtime_code_sha256)
        or not re.fullmatch(r"[a-f0-9]{64}", mount_contract_sha256)
        or not re.fullmatch(r"[a-f0-9]{32}", launch_nonce)
        or not _SAFE_NAME.fullmatch(control_network)
        or not _SAFE_NAME.fullmatch(camera_network)
        or control_network == camera_network
        or not re.fullmatch(r"[a-f0-9]{64}", expected_control_network_id)
        or not re.fullmatch(
            r"[a-f0-9]{64}",
            expected_control_network_config_sha256,
        )
        or not re.fullmatch(r"[a-f0-9]{64}", expected_camera_network_id)
        or not re.fullmatch(
            r"[a-f0-9]{64}",
            expected_camera_network_config_sha256,
        )
        or len(expected_gpu_device_ids) != 1
        or len(set(expected_gpu_device_ids)) != len(expected_gpu_device_ids)
        or any(
            re.fullmatch(r"GPU-[A-Fa-f0-9-]{16,64}", device_id) is None
            for device_id in expected_gpu_device_ids
        )
        or not expected_gpu_product_name
        or not expected_gpu_pci_bus_id
        or expected_gpu_total_vram_bytes <= 0
        or not expected_gpu_compute_capability
        or expected_gpu_mig_mode != "disabled"
        or not re.fullmatch(r"[a-f0-9]{64}", expected_gpu_inventory_sha256)
        or any(
            not value or len(value) > 64
            for value in (
                expected_nvidia_driver_version,
                expected_cuda_driver_version,
                expected_cuda_runtime_version,
                expected_nvidia_container_toolkit_version,
            )
        )
        or control_network in {"bridge", "host", "none", "default"}
        or camera_network in {"bridge", "host", "none", "default"}
        or not command
        or any(not argument or "\x00" in argument for argument in command)
    ):
        raise ValueError("immutable runtime launch identity is invalid")
    if len(mount_argv) % 2:
        raise ValueError("runtime mount argv must contain exact option/value pairs")
    expected_mounts: set[tuple[str, str, bool]] = set()
    mount_source_identities: dict[str, tuple[int, ...]] = {}

    def capture_mount_source(
        source: str,
        *,
        read_only: bool,
    ) -> tuple[int, ...]:
        path = Path(source)
        for candidate in (path, *path.parents):
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(
                    "runtime mount source or ancestor cannot be a symlink"
                )
        metadata = path.stat()
        if read_only:
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    "read-only runtime mount source must be a regular file"
                )
        elif (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 10_001
            or metadata.st_gid != 10_001
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError(
                "writable runtime mount must be private runtime-owned directory"
            )
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
        )

    for option, specification in zip(
        mount_argv[::2],
        mount_argv[1::2],
        strict=True,
    ):
        if option != "--mount":
            raise ValueError("runtime mount argv contains a non-mount option")
        matched = re.fullmatch(
            r"type=bind,src=([^,]+),dst=([^,]+)(,readonly)?",
            specification,
        )
        if matched is None:
            raise ValueError("runtime bind mount syntax is invalid")
        source, destination, read_only = matched.groups()
        if (
            not Path(source).is_absolute()
            or not Path(destination).is_absolute()
            or source != os.path.normpath(source)
            or destination != os.path.normpath(destination)
            or destination == "/"
            or "docker.sock" in {Path(source).name, Path(destination).name}
        ):
            raise ValueError("runtime bind mount path is unsafe")
        identity = (source, destination, read_only is not None)
        if any(existing[1] == destination for existing in expected_mounts):
            raise ValueError("runtime bind mount target is duplicated")
        expected_mounts.add(identity)
        captured_identity = capture_mount_source(
            source,
            read_only=read_only is not None,
        )
        prior_identity = mount_source_identities.setdefault(
            source,
            captured_identity,
        )
        if prior_identity != captured_identity:
            raise ValueError("runtime mount source identity changed")

    def invoke(*arguments: str, timeout: float = 30) -> str:
        if _trusted_engine(Path(engine)) != engine:
            raise RuntimeError("trusted container engine identity changed")
        result = run(
            (engine, *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode:
            raise RuntimeError("container engine refused immutable runtime launch")
        if len(result.stdout.encode()) > 1024 * 1024:
            raise RuntimeError("container engine response exceeded its bound")
        return result.stdout.strip()

    def invoke_nvidia_ctk() -> str:
        if _trusted_engine(Path(nvidia_ctk)) != nvidia_ctk:
            raise RuntimeError("trusted NVIDIA container toolkit identity changed")
        result = run(
            (nvidia_ctk, "--version"),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if (
            result.returncode
            or len(result.stdout.encode()) > 4096
            or len(result.stderr.encode()) > 4096
        ):
            raise RuntimeError(
                "NVIDIA container toolkit version is unavailable"
            )
        return result.stdout

    observed_nvidia_container_toolkit_version = (
        _parse_nvidia_ctk_version(invoke_nvidia_ctk())
    )
    if (
        observed_nvidia_container_toolkit_version
        != expected_nvidia_container_toolkit_version
    ):
        raise RuntimeError(
            "host NVIDIA container toolkit differs from signed capacity"
        )

    def inspect_network(name: str, *, role: str) -> tuple[str, str]:
        try:
            network = json.loads(
                invoke(
                    "network",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    name,
                )
            )
            network_id = network["Id"]
            driver = network["Driver"]
            internal = network["Internal"]
            ipam = network["IPAM"]
            labels = network.get("Labels") or {}
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("reviewed container network inspection is incomplete") from exc
        ipam_config = ipam.get("Config") if isinstance(ipam, dict) else None
        try:
            networks = tuple(
                ipaddress.ip_network(item["Subnet"], strict=False)
                for item in ipam_config
            )
            gateways = tuple(
                None
                if not item.get("Gateway")
                else ipaddress.ip_address(item["Gateway"])
                for item in ipam_config
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            ipaddress.AddressValueError,
            ipaddress.NetmaskValueError,
        ) as exc:
            raise RuntimeError(
                "reviewed container network address policy is invalid"
            ) from exc
        if (
            not re.fullmatch(r"[a-f0-9]{64}", network_id)
            or network.get("Name") != name
            or not isinstance(ipam, dict)
            or not isinstance(ipam_config, list)
            or not 1 <= len(ipam_config) <= 16
            or len(networks) != len(ipam_config)
            or any(
                subnet.is_multicast
                or subnet.is_loopback
                or subnet.is_link_local
                or subnet.is_unspecified
                or not subnet.is_private
                for subnet in networks
            )
            or any(
                gateway is not None
                and (
                    gateway.version != subnet.version
                    or gateway not in subnet
                    or gateway.is_multicast
                    or gateway.is_loopback
                    or gateway.is_link_local
                    or gateway.is_unspecified
                )
                for subnet, gateway in zip(networks, gateways, strict=True)
            )
            or (
                role == "control"
                and (driver != "bridge" or internal is not True)
            )
            or (
                role == "camera"
                and (
                    driver not in {"ipvlan", "macvlan"}
                    or labels.get("ai.kuzet.camera-policy") != "reviewed"
                )
            )
        ):
            raise RuntimeError("reviewed container network policy is unsafe")
        policy = {
            "Id": network_id,
            "Name": name,
            "Driver": driver,
            "Internal": internal,
            "IPAM": ipam,
            "Options": network.get("Options") or {},
            "Labels": labels,
        }
        return network_id, hashlib.sha256(_canonical_json(policy)).hexdigest()

    control_network_id, control_network_config_sha256 = inspect_network(
        control_network,
        role="control",
    )
    camera_network_id, camera_network_config_sha256 = inspect_network(
        camera_network,
        role="camera",
    )
    if (
        control_network_id != expected_control_network_id
        or control_network_config_sha256
        != expected_control_network_config_sha256
        or camera_network_id != expected_camera_network_id
        or camera_network_config_sha256
        != expected_camera_network_config_sha256
    ):
        raise RuntimeError(
            "container network identity differs from signed launch policy"
        )

    image_payload = invoke(
        "image",
        "inspect",
        "--format",
        "{{json .}}",
        image_id,
    )
    try:
        image = json.loads(image_payload)
        labels = image["Config"]["Labels"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("container image inspection is incomplete") from exc
    if (
        image.get("Id") != image_id
        or not isinstance(labels, dict)
        or labels.get("ai.kuzet.runtime-code-sha256") != runtime_code_sha256
    ):
        raise RuntimeError("container image identity differs from measured capacity")
    measured_image_config_sha256 = hashlib.sha256(
        _canonical_json(
            {
                field: image["Config"].get(field)
                for field in (
                    "Entrypoint",
                    "Cmd",
                    "User",
                    "Env",
                    "WorkingDir",
                    "Labels",
                )
            }
        )
    ).hexdigest()
    if measured_image_config_sha256 != image_config_sha256:
        raise RuntimeError("container image config differs from measured capacity")
    name = f"kuzet-acceptance-{launch_nonce}"
    if any(
        capture_mount_source(
            source,
            read_only=read_only,
        )
        != mount_source_identities[source]
        for source, _destination, read_only in expected_mounts
    ):
        raise RuntimeError("runtime mount source changed before container create")
    create_arguments = (
        "create",
        "--name",
        name,
        "--label",
        f"ai.kuzet.launch-nonce={launch_nonce}",
        "--label",
        f"ai.kuzet.runtime-code-sha256={runtime_code_sha256}",
        "--label",
        f"ai.kuzet.mount-contract-sha256={mount_contract_sha256}",
        "--gpus",
        (
            f"device={expected_gpu_device_ids[0]},"
            "capabilities=compute,utility,video"
        ),
        "--user",
        "10001:10001",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "512",
        "--memory",
        "16g",
        "--cpus",
        "8",
        "--network",
        control_network,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
        "--tmpfs",
        "/var/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
        "--log-driver",
        "local",
        "--log-opt",
        "max-size=10m",
        "--log-opt",
        "max-file=3",
        *mount_argv,
        image_id,
        *command,
    )
    try:
        container_id = invoke(*create_arguments)
        if _CONTAINER_ID.fullmatch(container_id) is None:
            raise RuntimeError(
                "container engine returned an invalid container identity"
            )
    except BaseException as primary:
        try:
            _reconcile_runner_container(
                engine=engine,
                name=name,
                launch_nonce=launch_nonce,
                run=run,
                uncertain_create=True,
            )
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "immutable runtime create and cleanup both failed",
                [primary, cleanup],
            ) from primary
        raise
    try:
        invoke("network", "connect", camera_network, container_id)
        inspected_payload = invoke(
            "inspect",
            "--format",
            "{{json .}}",
            container_id,
        )
        inspected = json.loads(inspected_payload)
        actual_mounts = {
            (item["Source"], item["Destination"], not item["RW"])
            for item in inspected["Mounts"]
        }
        container_labels = inspected["Config"]["Labels"]
        host = inspected["HostConfig"]
        device_requests = host.get("DeviceRequests")
        attached_networks = inspected["NetworkSettings"]["Networks"]
        if (
            inspected.get("Id") != container_id
            or inspected.get("Image") != image_id
            or inspected["Name"] != f"/{name}"
            or inspected["State"]["Status"] != "created"
            or tuple(inspected["Config"]["Cmd"]) != command
            or inspected["Config"]["Entrypoint"]
            != ["python3", "-m", "protector.pilot.runtime.deepstream"]
            or inspected["Config"]["User"] != "10001:10001"
            or host["ReadonlyRootfs"] is not True
            or "ALL" not in host["CapDrop"]
            or "no-new-privileges:true"
            not in host["SecurityOpt"]
            or host["Privileged"] is not False
            or host["RestartPolicy"]["Name"] != "no"
            or host["PidsLimit"] != 512
            or host["Memory"] != 16 * 1024**3
            or host["NanoCpus"] != 8_000_000_000
            or host.get("PidMode") not in {"", None}
            or host.get("IpcMode") not in {"", "private", None}
            or host["Tmpfs"]
            != {
                "/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=1777",
                "/var/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777",
            }
            or host["LogConfig"] != {
                "Type": "local",
                "Config": {"max-file": "3", "max-size": "10m"},
            }
            or not isinstance(device_requests, list)
            or len(device_requests) != 1
            or tuple(device_requests[0].get("DeviceIDs") or ())
            != expected_gpu_device_ids
            or device_requests[0].get("Count") not in {0, -1}
            or not {"compute", "utility", "video"}.issubset({
                capability
                for group in device_requests[0].get("Capabilities", ())
                for capability in group
            })
            or set(attached_networks) != {control_network, camera_network}
            or attached_networks[control_network]["NetworkID"]
            != control_network_id
            or attached_networks[camera_network]["NetworkID"]
            != camera_network_id
            or container_labels.get("ai.kuzet.launch-nonce") != launch_nonce
            or actual_mounts != expected_mounts
            or any(
                capture_mount_source(
                    source,
                    read_only=read_only,
                )
                != mount_source_identities[source]
                for source, _destination, read_only in expected_mounts
            )
        ):
            raise RuntimeError("created container differs from exact launch contract")
        inspected_config_sha256 = hashlib.sha256(
            _canonical_json(
                {
                    "Image": inspected["Image"],
                    "Config": inspected["Config"],
                    "HostConfig": inspected["HostConfig"],
                    "Mounts": inspected["Mounts"],
                }
            )
        ).hexdigest()
        invoke("start", container_id)
        def observed_gpu_inventory() -> ObservedGpuInventoryV2:
            gpu_csv = invoke(
                "exec",
                container_id,
                "nvidia-smi",
                (
                    "--query-gpu=uuid,name,pci.bus_id,memory.total,"
                    "compute_cap,mig.mode.current,driver_version"
                ),
                "--format=csv,noheader,nounits",
            )
            rows = tuple(csv.reader(io.StringIO(gpu_csv)))
            if len(rows) != 1 or len(rows[0]) != 7:
                raise RuntimeError("runtime GPU inventory is not exact")
            (
                uuid,
                product_name,
                pci_bus_id,
                vram_mib,
                compute_capability,
                mig_mode,
                driver_version,
            ) = tuple(value.strip() for value in rows[0])
            domain, separator, remainder = pci_bus_id.partition(":")
            if separator and len(domain) == 8:
                pci_bus_id = f"{domain[-4:]}:{remainder}"
            try:
                if re.fullmatch(r"[0-9]+", vram_mib) is None:
                    raise ValueError
                total_vram_bytes = int(vram_mib) * 1024 * 1024
            except ValueError as exc:
                raise RuntimeError(
                    "runtime GPU VRAM observation is invalid"
                ) from exc
            cuda_versions_payload = invoke(
                "exec",
                container_id,
                "python3",
                "-c",
                (
                    "import ctypes,json;"
                    "driver=ctypes.CDLL('libcuda.so.1');"
                    "runtime=ctypes.CDLL('libcudart.so');"
                    "driver_version=ctypes.c_int();"
                    "runtime_version=ctypes.c_int();"
                    "assert driver.cuInit(0)==0;"
                    "assert driver.cuDriverGetVersion("
                    "ctypes.byref(driver_version))==0;"
                    "assert runtime.cudaRuntimeGetVersion("
                    "ctypes.byref(runtime_version))==0;"
                    "print(json.dumps({"
                    "'cuda_driver_version_integer':driver_version.value,"
                    "'cuda_runtime_version_integer':runtime_version.value"
                    "},sort_keys=True,separators=(',',':')))"
                ),
            )
            try:
                cuda_versions = json.loads(cuda_versions_payload)
                if (
                    not isinstance(cuda_versions, dict)
                    or set(cuda_versions)
                    != {
                        "cuda_driver_version_integer",
                        "cuda_runtime_version_integer",
                    }
                ):
                    raise ValueError
                cuda_driver_version = _cuda_version_string(
                    cuda_versions["cuda_driver_version_integer"]
                )
                cuda_runtime_version = _cuda_version_string(
                    cuda_versions["cuda_runtime_version_integer"]
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "runtime CUDA version observation is invalid"
                ) from exc
            current_toolkit_version = _parse_nvidia_ctk_version(
                invoke_nvidia_ctk()
            )
            try:
                parsed_inventory = ObservedGpuInventoryV2.model_validate({
                    "schema_version": "observed-gpu-inventory.v2",
                    "devices": [
                        {
                            "uuid": uuid,
                            "product_name": product_name,
                            "pci_bus_id": pci_bus_id,
                            "total_vram_bytes": total_vram_bytes,
                            "compute_capability": compute_capability,
                            "mig_mode": mig_mode.casefold(),
                        }
                    ],
                    "nvidia_driver_version": driver_version,
                    "cuda_driver_version": cuda_driver_version,
                    "cuda_runtime_version": cuda_runtime_version,
                    "nvidia_container_toolkit_version": (
                        current_toolkit_version
                    ),
                    "authorizing": False,
                })
                inventory = _strict_observed_gpu_inventory(
                    parsed_inventory
                )
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    "strict observed GPU inventory is invalid"
                ) from exc

            return inventory

        def verify_expected_gpu_inventory(
            inventory: ObservedGpuInventoryV2,
        ) -> None:
            observed_device = inventory.devices[0]
            if (
                tuple(device.uuid for device in inventory.devices)
                != expected_gpu_device_ids
                or inventory.launch_compatibility_sha256
                != expected_gpu_inventory_sha256
                or expected_gpu_product_name
                != observed_device.product_name
                or expected_gpu_pci_bus_id
                != observed_device.pci_bus_id
                or expected_gpu_total_vram_bytes
                != observed_device.total_vram_bytes
                or expected_gpu_compute_capability
                != observed_device.compute_capability
                or expected_gpu_mig_mode
                != observed_device.mig_mode
                or expected_nvidia_driver_version
                != inventory.nvidia_driver_version
                or expected_cuda_driver_version
                != inventory.cuda_driver_version
                or expected_cuda_runtime_version
                != inventory.cuda_runtime_version
                or expected_nvidia_container_toolkit_version
                != inventory.nvidia_container_toolkit_version
            ):
                raise RuntimeError(
                    "runtime-visible GPU inventory differs from signed capacity"
                )

        initial_observed_gpu_inventory = observed_gpu_inventory()
        verify_expected_gpu_inventory(initial_observed_gpu_inventory)
    except BaseException as primary:
        try:
            _reconcile_runner_container(
                engine=engine,
                name=name,
                launch_nonce=launch_nonce,
                run=run,
                uncertain_create=False,
            )
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "immutable runtime verification and cleanup both failed",
                [primary, cleanup],
            ) from primary
        raise
    def verify_running_identity() -> ObservedGpuInventoryV2:
        current_payload = invoke(
            "inspect",
            "--format",
            "{{json .}}",
            container_id,
        )
        try:
            current = json.loads(current_payload)
            current_mounts = {
                (item["Source"], item["Destination"], not item["RW"])
                for item in current["Mounts"]
            }
            current_networks = current["NetworkSettings"]["Networks"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "runner-owned container identity inspection is incomplete"
            ) from exc
        current_config_sha256 = hashlib.sha256(
            _canonical_json(
                {
                    "Image": current["Image"],
                    "Config": current["Config"],
                    "HostConfig": current["HostConfig"],
                    "Mounts": current["Mounts"],
                }
            )
        ).hexdigest()
        current_gpu_inventory = observed_gpu_inventory()
        verify_expected_gpu_inventory(current_gpu_inventory)
        if (
            current.get("Id") != container_id
            or current.get("Image") != image_id
            or current_config_sha256 != inspected_config_sha256
            or current_mounts != expected_mounts
            or set(current_networks) != {control_network, camera_network}
            or current_networks[control_network]["NetworkID"]
            != control_network_id
            or current_networks[camera_network]["NetworkID"]
            != camera_network_id
            or current_gpu_inventory != initial_observed_gpu_inventory
            or any(
                capture_mount_source(
                    source,
                    read_only=read_only,
                )
                != mount_source_identities[source]
                for source, _destination, read_only in expected_mounts
            )
        ):
            raise RuntimeError(
                "runner-owned container identity changed during acceptance"
            )
        return current_gpu_inventory

    try:
        verify_running_identity()
        return _issue_docker_runtime_process(
            engine=engine,
            container_id=container_id,
            container_config_sha256=inspected_config_sha256,
            control_network_id=control_network_id,
            control_network_config_sha256=(
                control_network_config_sha256
            ),
            camera_network_id=camera_network_id,
            camera_network_config_sha256=camera_network_config_sha256,
            observed_gpu_inventory=initial_observed_gpu_inventory,
            name=name,
            launch_nonce=launch_nonce,
            verify_identity=verify_running_identity,
            run=run,
        )
    except BaseException as primary:
        try:
            _reconcile_runner_container(
                engine=engine,
                name=name,
                launch_nonce=launch_nonce,
                run=run,
                uncertain_create=False,
            )
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "post-start identity and cleanup both failed",
                [primary, cleanup],
            ) from primary
        raise
