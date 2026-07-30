"""Runtime-owned completion ledger for centrally planned unique work."""

from __future__ import annotations

import os
import stat
import threading
import time
from fractions import Fraction
from pathlib import Path

from protector.pilot.acceptance_target import TargetNativePrewarmProjectionV2
from protector.pilot.acceptance_work import (
    MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES,
    TargetUniqueWorkCompletionV2,
    TargetUniqueWorkPlanV2,
    TargetUniqueWorkProjectionV2,
    completed_work_ledger_sha256,
)

_MAX_PROJECTION_NAME_BYTES = 128


def _monotonic_ns() -> int:
    return time.monotonic_ns()


def _strict_plan(value: object) -> TargetUniqueWorkPlanV2:
    if type(value) is not TargetUniqueWorkPlanV2:
        raise TypeError("runtime work ledger requires the exact typed plan")
    return TargetUniqueWorkPlanV2.model_validate(value.model_dump(mode="python"))


def _strict_prewarm(value: object) -> TargetNativePrewarmProjectionV2:
    if type(value) is not TargetNativePrewarmProjectionV2:
        raise TypeError("runtime work ledger requires the exact native prewarm projection")
    return TargetNativePrewarmProjectionV2.model_validate(value.model_dump(mode="python"))


def _checked_now() -> int:
    value = _monotonic_ns()
    if type(value) is not int or not 0 < value <= 2**63 - 1:
        raise RuntimeError("runtime monotonic clock returned an invalid value")
    return value


def _open_parent(path: Path) -> tuple[int, str]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or not path.name
        or len(path.name.encode()) > _MAX_PROJECTION_NAME_BYTES
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in path.name
        )
        or path.name[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        or path.parent.resolve(strict=True) != path.parent
    ):
        raise ValueError("unique-work projection path is not canonical")
    descriptor = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("unique-work projection parent is not a directory")
    except BaseException as primary:
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "unique-work parent inspection and cleanup both failed",
                [primary, cleanup],
            ) from primary
        raise
    return descriptor, path.name


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if type(written) is not int or written <= 0:
            raise OSError("unique-work projection write made no progress")
        offset += written


def _cleanup_created_leaf(
    *,
    parent_descriptor: int,
    name: str,
    created: os.stat_result,
) -> None:
    try:
        current = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if current.st_dev != created.st_dev or current.st_ino != created.st_ino:
        raise RuntimeError("unique-work projection cleanup identity changed")
    os.unlink(name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _append_close_failures(
    descriptors: tuple[int | None, ...],
    failures: list[BaseException],
) -> None:
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except BaseException as close_failure:
            failures.append(close_failure)


def _raise_failures(label: str, failures: list[BaseException]) -> None:
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup(label, failures)


def _publish_no_replace(
    path: Path,
    projection: TargetUniqueWorkProjectionV2,
) -> None:
    payload = projection.canonical_bytes
    if not 1 <= len(payload) <= MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES:
        raise ValueError("unique-work projection exceeds its byte bound")
    parent, name = _open_parent(path)
    descriptor: int | None = None
    created: os.stat_result | None = None
    failures: list[BaseException] = []
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent,
        )
        created = os.fstat(descriptor)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_nlink != 1
            or stat.S_IMODE(created.st_mode) != 0o600
        ):
            raise ValueError("unique-work projection output is not one private regular file")
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        leaf = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            (final.st_dev, final.st_ino) != (created.st_dev, created.st_ino)
            or (leaf.st_dev, leaf.st_ino) != (created.st_dev, created.st_ino)
            or final.st_size != len(payload)
        ):
            raise RuntimeError("unique-work projection identity changed during publication")
        os.fsync(parent)
    except BaseException as primary:
        failures.append(primary)
        if created is not None:
            try:
                _cleanup_created_leaf(
                    parent_descriptor=parent,
                    name=name,
                    created=created,
                )
            except BaseException as cleanup:
                failures.append(cleanup)
    finally:
        _append_close_failures((descriptor, parent), failures)
    _raise_failures(
        "unique-work projection publication or cleanup failed",
        failures,
    )


class TargetUniqueWorkRuntimeLedger:
    """Accept only the next planned completion from the shared analytics path."""

    __slots__ = (
        "__completions",
        "__last_completed_at",
        "__lock",
        "__plan",
        "__prewarm",
        "__started_at",
    )

    def __init__(
        self,
        *,
        plan: TargetUniqueWorkPlanV2,
        native_prewarm: TargetNativePrewarmProjectionV2,
    ) -> None:
        checked_plan = _strict_plan(plan)
        checked_prewarm = _strict_prewarm(native_prewarm)
        started_at = _checked_now()
        if (
            checked_prewarm.launch_request_sha256 != checked_plan.launch_request_sha256
            or checked_prewarm.runtime_identity_sha256 != checked_plan.runtime_identity_sha256
            or checked_prewarm.site_id != checked_plan.site_id
            or checked_prewarm.campaign_id != checked_plan.campaign_id
            or checked_prewarm.launch_nonce != checked_plan.launch_nonce
            or checked_prewarm.runtime_epoch != checked_plan.runtime_epoch
            or checked_prewarm.runtime_epoch_started_generation
            != checked_plan.runtime_epoch_started_generation
        ):
            raise ValueError("runtime work ledger prewarm differs from its exact plan")
        if started_at < checked_prewarm.ready_at_monotonic_ns:
            raise ValueError("runtime work measurement starts before native prewarm")
        if started_at + checked_plan.measurement_duration_ns > 2**63 - 1:
            raise ValueError("runtime work measurement interval exceeds its bound")
        self.__plan = checked_plan
        self.__prewarm = checked_prewarm
        self.__started_at = started_at
        self.__completions: list[TargetUniqueWorkCompletionV2] = []
        self.__last_completed_at = started_at
        self.__lock = threading.Lock()

    def __copy__(self):
        raise TypeError("runtime work-ledger capability cannot be copied or serialized")

    def __deepcopy__(self, _memo: object):
        raise TypeError("runtime work-ledger capability cannot be copied or serialized")

    def __reduce_ex__(self, _protocol: int):
        raise TypeError("runtime work-ledger capability cannot be copied or serialized")

    @property
    def measurement_started_monotonic_ns(self) -> int:
        return self.__started_at

    def record_post_shared_analytics_completion(
        self,
        *,
        work_id: str,
        runtime_epoch: int,
        runtime_epoch_started_generation: int,
        camera_id: str,
        source_index: int,
        module: str,
        slot_index: int,
        detection_count: int,
    ) -> TargetUniqueWorkCompletionV2:
        """Record one completed scheduled frame, including zero detections."""

        if (
            type(work_id) is not str
            or type(runtime_epoch) is not int
            or type(runtime_epoch_started_generation) is not int
            or type(camera_id) is not str
            or type(source_index) is not int
            or type(module) is not str
            or type(slot_index) is not int
            or type(detection_count) is not int
        ):
            raise TypeError("runtime work completion fields must use exact scalar types")
        now = _checked_now()
        with self.__lock:
            next_index = len(self.__completions)
            if next_index >= len(self.__plan.slots):
                raise ValueError("runtime work ledger bounded capacity is exhausted")
            slot = self.__plan.slots[next_index]
            if runtime_epoch != self.__plan.runtime_epoch:
                raise ValueError("runtime work completion epoch differs")
            if runtime_epoch_started_generation != self.__plan.runtime_epoch_started_generation:
                raise ValueError("runtime work completion epoch generation differs")
            if work_id != slot.work_id:
                raise ValueError("runtime work completion is duplicate, unknown, or replayed")
            if camera_id != slot.camera_id:
                raise ValueError("runtime work completion camera differs")
            if source_index != slot.source_index:
                raise ValueError("runtime work completion source differs")
            if module != slot.module:
                raise ValueError("runtime work completion module differs")
            if slot_index != slot.slot_index:
                raise ValueError("runtime work completion slot order differs")
            if not 0 <= detection_count <= 1_000_000:
                raise ValueError("runtime work detection count is invalid")
            required_at = self.__started_at + slot.scheduled_offset_ns
            measurement_end = self.__started_at + self.__plan.measurement_duration_ns
            if now < required_at:
                raise ValueError("runtime work completed before its monotonic slot")
            if now < self.__last_completed_at:
                raise ValueError("runtime work completion clock regressed")
            if now > measurement_end:
                raise ValueError("runtime work completion exceeded the finite measurement")
            completion = TargetUniqueWorkCompletionV2(
                work_id=slot.work_id,
                slot_index=slot.slot_index,
                completed_at_monotonic_ns=now,
                camera_id=slot.camera_id,
                source_index=slot.source_index,
                module=slot.module,
                detection_count=detection_count,
            )
            self.__completions.append(completion)
            self.__last_completed_at = now
            return completion

    def publish_projection(
        self,
        path: Path,
    ) -> TargetUniqueWorkProjectionV2:
        with self.__lock:
            observed_now = _checked_now()
            completed_at = self.__started_at + self.__plan.measurement_duration_ns
            if observed_now < completed_at:
                raise ValueError("runtime work measurement has not reached its finite horizon")
            completions = tuple(self.__completions)
            completed = len(completions)
            required = Fraction(
                self.__plan.required_work_numerator,
                self.__plan.required_work_denominator,
            )
            effective = Fraction(
                completed * 1_000_000_000,
                self.__plan.measurement_duration_ns,
            )
            headroom = Fraction(completed, 1) / required - 1
            projection = TargetUniqueWorkProjectionV2(
                schema_version="target-unique-work-projection.v2",
                plan_sha256=self.__plan.plan_sha256,
                launch_request_sha256=self.__plan.launch_request_sha256,
                runtime_identity_sha256=self.__plan.runtime_identity_sha256,
                native_prewarm_projection_sha256=self.__prewarm.projection_sha256,
                measurement_started_monotonic_ns=self.__started_at,
                measurement_completed_monotonic_ns=completed_at,
                offered_work_units=self.__plan.offered_work_units,
                completed_unique_work_units=completed,
                required_work_numerator=self.__plan.required_work_numerator,
                required_work_denominator=self.__plan.required_work_denominator,
                effective_rate_numerator=effective.numerator,
                effective_rate_denominator=effective.denominator,
                headroom_numerator=headroom.numerator,
                headroom_denominator=headroom.denominator,
                completed_work_ledger_sha256=completed_work_ledger_sha256(completions),
                completions=completions,
                authorizing=False,
            )
            _publish_no_replace(path, projection)
            return projection


__all__ = ("TargetUniqueWorkRuntimeLedger",)
