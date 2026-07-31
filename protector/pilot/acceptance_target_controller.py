"""Controller-owned Docker observation for the non-authorizing target lane."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from pathlib import Path
from typing import Annotated, Callable, TypeVar, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from protector.pilot.acceptance_target import (
    ObservedGpuInventoryV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
    TargetRuntimeObservationV2,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.acceptance_transaction import (
    C2_CAPABILITY_TRANSACTION_LOCK,
)
from protector.pilot.config import FrozenModel
from protector.pilot.runtime.container_runner import (
    DockerRuntimeProcess,
    launch_docker_runtime,
)

_M = TypeVar("_M", bound=FrozenModel)
_R = TypeVar("_R")
_Argv = Annotated[tuple[str, ...], Field(max_length=128)]


class TargetRuntimeControllerEnvironmentV2(FrozenModel):
    """Bounded host inputs whose contents are reviewed outside this slice."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    engine_path: Path
    nvidia_ctk_path: Path
    command: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    reviewed_mount_argv: _Argv

    @field_validator("command", "reviewed_mount_argv", mode="before")
    @classmethod
    def argv_is_an_exact_tuple(cls, value: object) -> object:
        if type(value) is not tuple:
            raise TypeError("controller launch argv must be an exact tuple")
        if any(
            type(argument) is not str
            or not argument
            or "\x00" in argument
            or len(argument.encode()) > 4096
            for argument in value
        ):
            raise ValueError("controller launch argv is invalid")
        return value

    @model_validator(mode="after")
    def environment_is_bounded(self) -> TargetRuntimeControllerEnvironmentV2:
        paths = (self.engine_path, self.nvidia_ctk_path)
        if (
            any(
                not path.is_absolute() or "\x00" in str(path) or len(str(path).encode()) > 4096
                for path in paths
            )
            or self.engine_path == self.nvidia_ctk_path
            or len(self.reviewed_mount_argv) % 2
            or sum(
                len(argument.encode()) for argument in (*self.command, *self.reviewed_mount_argv)
            )
            > 65_536
        ):
            raise ValueError("controller launch environment is invalid")
        return self


def _strict_exact(value: object, model: type[_M], label: str) -> _M:
    if type(value) is not model:
        raise TypeError(f"{label} must use the exact typed contract")
    return model.model_validate(value)


def _build_identity(
    *,
    request: TargetRuntimeLaunchRequestV2,
    process: DockerRuntimeProcess,
    inventory: ObservedGpuInventoryV2,
    epoch_started_monotonic_ns: int,
    observed_monotonic_ns: int,
) -> TargetRuntimeIdentityV2:
    container_id = process.container_id
    identity = TargetRuntimeIdentityV2(
        schema_version="target-runtime-identity.v2",
        launch_request=request,
        process_id=f"docker:{container_id}",
        runtime_boot_id=f"container:{container_id}",
        container_id=container_id,
        container_config_sha256=process.container_config_sha256,
        runtime_image_id_sha256=request.launch.runtime_image_id_sha256,
        runtime_image_config_sha256=(request.launch.runtime_image_config_sha256),
        runtime_code_sha256=request.launch.runtime_code_sha256,
        mount_contract_sha256=request.launch.mount_contract_sha256,
        controller_image_id_sha256=request.controller_image_id_sha256,
        controller_image_config_sha256=(request.controller_image_config_sha256),
        controller_code_sha256=request.controller_code_sha256,
        control_network_id=process.control_network_id,
        control_network_config_sha256=(process.control_network_config_sha256),
        camera_network_id=process.camera_network_id,
        camera_network_config_sha256=(process.camera_network_config_sha256),
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=(request.runtime_epoch_started_generation),
        runtime_epoch_started_monotonic_ns=epoch_started_monotonic_ns,
        identity_observed_monotonic_ns=observed_monotonic_ns,
        observed_gpu_inventory=inventory,
        source_bindings=request.source_bindings,
        authorizing=False,
    )
    return TargetRuntimeIdentityV2.model_validate(identity.model_dump(mode="python"))


def _remove_after_failure(
    process: object,
    primary: BaseException,
) -> None:
    try:
        cast(DockerRuntimeProcess, process).remove()
    except BaseException as cleanup:
        raise BaseExceptionGroup(
            "target runtime observation and cleanup both failed",
            [primary, cleanup],
        ) from primary


class _ControllerOwnedDockerRuntime:
    """Non-serializable owner of one exact, non-restartable Docker process."""

    __slots__ = (
        "__cleanup_failure",
        "__cleanup_started",
        "__c2_consumed",
        "__identity",
        "__lock",
        "__process",
        "__request",
        "__started_monotonic_ns",
    )

    def __init__(
        self,
        *,
        _issuer: object | None = None,
        process: DockerRuntimeProcess,
        request: TargetRuntimeLaunchRequestV2,
        identity: TargetRuntimeIdentityV2,
        started_monotonic_ns: int,
    ) -> None:
        if (
            not _is_controller_runtime_owner_issuer(_issuer)
            or type(process) is not DockerRuntimeProcess
            or type(request) is not TargetRuntimeLaunchRequestV2
            or type(identity) is not TargetRuntimeIdentityV2
            or type(started_monotonic_ns) is not int
        ):
            raise TypeError(
                "controller runtime owner requires exact private Docker provenance"
            )
        self.__process = process
        self.__request = request
        self.__identity = identity
        self.__started_monotonic_ns = started_monotonic_ns
        self.__lock = threading.Lock()
        self.__cleanup_started = False
        self.__cleanup_failure: BaseException | None = None
        self.__c2_consumed = False

    def __copy__(self) -> _ControllerOwnedDockerRuntime:
        raise TypeError("controller-owned runtime capability cannot be copied or serialized")

    def __deepcopy__(
        self,
        _memo: dict[int, object],
    ) -> _ControllerOwnedDockerRuntime:
        raise TypeError("controller-owned runtime capability cannot be copied or serialized")

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("controller-owned runtime capability cannot be copied or serialized")

    def _require_live(self) -> None:
        if self.__cleanup_started:
            raise RuntimeError("controller-owned runtime cleanup already started")

    def _cleanup_after_failure(self, primary: BaseException) -> None:
        self.__cleanup_started = True
        try:
            self.__process.remove()
        except BaseException as cleanup:
            self.__cleanup_failure = cleanup
            raise BaseExceptionGroup(
                "target runtime operation and cleanup both failed",
                [primary, cleanup],
            ) from primary

    def _delegate(self, operation: Callable[[], _R]) -> _R:
        with self.__lock:
            self._require_live()
            try:
                return operation()
            except BaseException as primary:
                self._cleanup_after_failure(primary)
                raise

    def observe_identity(self) -> TargetRuntimeIdentityV2:
        return self._delegate(
            lambda: TargetRuntimeIdentityV2.model_validate(
                self.__identity.model_dump(mode="python")
            )
        )

    def reverify_identity(self) -> TargetRuntimeIdentityV2:
        with self.__lock:
            self._require_live()
            try:
                inventory = self.__process.verify_identity()
                observed_monotonic_ns = time.monotonic_ns()
                identity = _build_identity(
                    request=self.__request,
                    process=self.__process,
                    inventory=inventory,
                    epoch_started_monotonic_ns=(self.__started_monotonic_ns),
                    observed_monotonic_ns=observed_monotonic_ns,
                )
                if identity.model_dump(
                    mode="python",
                    exclude={"identity_observed_monotonic_ns"},
                ) != self.__identity.model_dump(
                    mode="python",
                    exclude={"identity_observed_monotonic_ns"},
                ):
                    raise RuntimeError("controller-owned runtime identity changed")
            except BaseException as primary:
                self._cleanup_after_failure(primary)
                raise
            return TargetRuntimeIdentityV2.model_validate(
                self.__identity.model_dump(mode="python")
            )

    def poll(self) -> int | None:
        return self._delegate(self.__process.poll)

    def terminate(self, *, timeout_seconds: int) -> None:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
            raise ValueError("container stop grace is invalid")
        self._delegate(lambda: self.__process.terminate(timeout_seconds=timeout_seconds))

    def wait(self, *, timeout_seconds: float) -> int:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 300
        ):
            raise ValueError("container wait timeout is invalid")
        return self._delegate(lambda: self.__process.wait(float(timeout_seconds)))

    def kill(self) -> None:
        self._delegate(self.__process.kill)

    def cleanup(self) -> None:
        with self.__lock:
            if self.__cleanup_started:
                if self.__cleanup_failure is not None:
                    raise RuntimeError(
                        "controller-owned runtime cleanup previously failed"
                    ) from self.__cleanup_failure
                return
            self.__cleanup_started = True
            try:
                self.__process.remove()
            except BaseException as cleanup:
                self.__cleanup_failure = cleanup
                raise

    def _mark_c2_consumed(self) -> None:
        with self.__lock:
            self._require_live()
            if self.__c2_consumed:
                raise RuntimeError(
                    "controller-owned runtime capability was already consumed"
                )
            self.__c2_consumed = True


def _make_controller_runtime_owner_issuer() -> tuple[
    Callable[[object], bool],
    Callable[
        ...,
        tuple[_ControllerOwnedDockerRuntime, TargetRuntimeIdentityV2],
    ],
]:
    token = object()

    def is_issuer(candidate: object) -> bool:
        return candidate is token

    def issue(
        *,
        process: DockerRuntimeProcess,
        request: TargetRuntimeLaunchRequestV2,
        epoch_started_monotonic_ns: int,
        identity_observed_monotonic_ns: int,
    ) -> tuple[_ControllerOwnedDockerRuntime, TargetRuntimeIdentityV2]:
        if (
            type(process) is not DockerRuntimeProcess
            or type(request) is not TargetRuntimeLaunchRequestV2
            or type(epoch_started_monotonic_ns) is not int
            or type(identity_observed_monotonic_ns) is not int
            or epoch_started_monotonic_ns < 0
            or identity_observed_monotonic_ns < epoch_started_monotonic_ns
        ):
            raise TypeError(
                "controller runtime owner requires exact Docker launch values"
            )
        identity = _build_identity(
            request=request,
            process=process,
            inventory=process.verify_identity(),
            epoch_started_monotonic_ns=epoch_started_monotonic_ns,
            observed_monotonic_ns=identity_observed_monotonic_ns,
        )
        runtime = _ControllerOwnedDockerRuntime(
            _issuer=token,
            process=process,
            request=request,
            identity=identity,
            started_monotonic_ns=epoch_started_monotonic_ns,
        )
        return runtime, identity

    return is_issuer, issue


(
    _is_controller_runtime_owner_issuer,
    _issue_controller_owned_docker_runtime,
) = _make_controller_runtime_owner_issuer()


def _make_controller_runtime_authority_tools():
    issuer = object()
    key = secrets.token_bytes(32)

    class _VerifiedControllerRuntime:
        __slots__ = (
            "__consumed",
            "__identity_bytes",
            "__lock",
            "__receipt",
            "__runtime",
        )

        def __init__(
            self,
            *,
            token: object,
            runtime: _ControllerOwnedDockerRuntime,
            identity: TargetRuntimeIdentityV2,
        ) -> None:
            if token is not issuer:
                raise TypeError("controller runtime authority requires its private issuer")
            self.__runtime = runtime
            self.__identity_bytes = canonical_json_bytes(identity)
            self.__receipt = hmac.digest(key, self.__identity_bytes, "sha256")
            self.__consumed = False
            self.__lock = threading.Lock()

        def __copy__(self) -> None:
            raise TypeError("verified runtime capability cannot be copied or serialized")

        def __deepcopy__(self, _memo: object) -> None:
            raise TypeError("verified runtime capability cannot be copied or serialized")

        def __reduce_ex__(self, _protocol: int) -> None:
            raise TypeError("verified runtime capability cannot be copied or serialized")

    def issue(
        runtime: _ControllerOwnedDockerRuntime,
    ) -> object:
        if type(runtime) is not _ControllerOwnedDockerRuntime:
            raise TypeError("exact controller-owned runtime capability is required")
        identity = runtime.reverify_identity()
        runtime._mark_c2_consumed()  # noqa: SLF001
        return _VerifiedControllerRuntime(
            token=issuer,
            runtime=runtime,
            identity=identity,
        )

    def _inspect_locked(
        capability: object,
        *,
        consume: bool,
    ) -> tuple[_ControllerOwnedDockerRuntime, TargetRuntimeIdentityV2]:
        if type(capability) is not _VerifiedControllerRuntime:
            raise TypeError("verified controller runtime capability is required")
        with capability._VerifiedControllerRuntime__lock:
            if capability._VerifiedControllerRuntime__consumed:
                raise RuntimeError(
                    "verified controller runtime capability was already consumed"
                )
            identity_bytes = capability._VerifiedControllerRuntime__identity_bytes
            receipt = capability._VerifiedControllerRuntime__receipt
            if (
                type(identity_bytes) is not bytes
                or type(receipt) is not bytes
                or not hmac.compare_digest(
                    receipt,
                    hmac.digest(key, identity_bytes, "sha256"),
                )
            ):
                raise ValueError("verified controller runtime provenance is invalid")
            try:
                identity = TargetRuntimeIdentityV2.model_validate_json(
                    identity_bytes,
                    strict=True,
                )
            except ValueError:
                raise ValueError("verified controller runtime identity is invalid") from None
            if hashlib.sha256(canonical_json_bytes(identity)).hexdigest() != (
                identity.identity_sha256
            ):
                raise ValueError("verified controller runtime identity digest differs")
            runtime = capability._VerifiedControllerRuntime__runtime
            if type(runtime) is not _ControllerOwnedDockerRuntime:
                raise ValueError("verified controller runtime owner changed")
            if consume:
                capability._VerifiedControllerRuntime__consumed = True
            return runtime, identity

    def inspect(
        capability: object,
        *,
        consume: bool,
    ) -> tuple[_ControllerOwnedDockerRuntime, TargetRuntimeIdentityV2]:
        with C2_CAPABILITY_TRANSACTION_LOCK:
            return _inspect_locked(capability, consume=consume)

    def peek(
        capability: object,
    ) -> tuple[_ControllerOwnedDockerRuntime, TargetRuntimeIdentityV2]:
        return inspect(capability, consume=False)

    def consume(
        capability: object,
    ) -> tuple[_ControllerOwnedDockerRuntime, TargetRuntimeIdentityV2]:
        return inspect(capability, consume=True)

    return issue, peek, consume


(
    _consume_controller_owned_runtime_for_c2,
    _peek_controller_runtime_authority,
    _require_controller_runtime_authority,
) = _make_controller_runtime_authority_tools()


def launch_and_observe_controller_owned_target_runtime(
    request: TargetRuntimeLaunchRequestV2,
    environment: TargetRuntimeControllerEnvironmentV2,
) -> tuple[_ControllerOwnedDockerRuntime, TargetRuntimeObservationV2]:
    """Launch, fully observe, and privately retain one non-authorizing runtime."""

    checked_request = _strict_exact(
        request,
        TargetRuntimeLaunchRequestV2,
        "target runtime launch request",
    )
    checked_environment = _strict_exact(
        environment,
        TargetRuntimeControllerEnvironmentV2,
        "target runtime controller environment",
    )
    launch = checked_request.launch
    epoch_started_monotonic_ns = time.monotonic_ns()
    process: object = launch_docker_runtime(
        engine_path=checked_environment.engine_path,
        nvidia_ctk_path=checked_environment.nvidia_ctk_path,
        image_id=f"sha256:{launch.runtime_image_id_sha256}",
        image_config_sha256=launch.runtime_image_config_sha256,
        runtime_code_sha256=launch.runtime_code_sha256,
        mount_contract_sha256=launch.mount_contract_sha256,
        launch_nonce=checked_request.launch_nonce,
        command=checked_environment.command,
        mount_argv=checked_environment.reviewed_mount_argv,
        control_network=launch.control_network,
        camera_network=launch.camera_network,
        expected_control_network_id=launch.expected_control_network_id,
        expected_control_network_config_sha256=(launch.expected_control_network_config_sha256),
        expected_camera_network_id=launch.expected_camera_network_id,
        expected_camera_network_config_sha256=(launch.expected_camera_network_config_sha256),
        expected_gpu_device_ids=launch.gpu_device_ids,
        expected_gpu_product_name=launch.gpu_product_name,
        expected_gpu_pci_bus_id=launch.gpu_pci_bus_id,
        expected_gpu_total_vram_bytes=launch.gpu_total_vram_bytes,
        expected_gpu_compute_capability=launch.gpu_compute_capability,
        expected_gpu_mig_mode=launch.gpu_mig_mode,
        expected_gpu_inventory_sha256=launch.gpu_inventory_sha256,
        expected_nvidia_driver_version=launch.nvidia_driver_version,
        expected_cuda_driver_version=launch.cuda_driver_version,
        expected_cuda_runtime_version=launch.cuda_runtime_version,
        expected_nvidia_container_toolkit_version=(launch.nvidia_container_toolkit_version),
    )
    try:
        if type(process) is not DockerRuntimeProcess:
            raise TypeError("launcher did not return the exact Docker runtime process")
        checked_process = cast(DockerRuntimeProcess, process)
        observed_monotonic_ns = time.monotonic_ns()
        capability, identity = _issue_controller_owned_docker_runtime(
            process=checked_process,
            request=checked_request,
            epoch_started_monotonic_ns=(
                epoch_started_monotonic_ns
            ),
            identity_observed_monotonic_ns=observed_monotonic_ns,
        )
        observation = TargetRuntimeObservationV2.model_validate(
            {
                "schema_version": "target-runtime-observation.v2",
                "identity": identity.model_dump(mode="python"),
                "authorizing": False,
            }
        )
    except BaseException as primary:
        _remove_after_failure(process, primary)
        raise
    return capability, observation


__all__ = (
    "TargetRuntimeControllerEnvironmentV2",
    "launch_and_observe_controller_owned_target_runtime",
)
