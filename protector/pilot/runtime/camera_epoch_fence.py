"""Database-backed camera epoch fencing ahead of candidate processing."""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from protector.pilot.domain import (
    CameraEpochActivationReceiptV1,
    RuntimeWriterReceiptV1,
)
from protector.pilot.runtime.provenance import RuntimeCandidateAuthority

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CameraEpochFenceError(RuntimeError):
    """A source epoch could not acquire current durable writer authority."""


class _CameraEpochRepository(Protocol):
    def activate_camera_epoch(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        camera_id: str,
        source_epoch: UUID,
        expected_source_epoch: UUID | None,
        activated_at: datetime,
    ) -> CameraEpochActivationReceiptV1: ...


class CameraEpochFencedEventService:
    """CAS each event-producing camera epoch before it reaches its engine."""

    __slots__ = (
        "_authority",
        "_clock",
        "_current",
        "_delegate",
        "_event_camera_ids",
        "_lock",
        "_repository",
    )

    def __init__(
        self,
        *,
        delegate: Any,
        repository: _CameraEpochRepository,
        authority: RuntimeCandidateAuthority,
        event_camera_ids: tuple[str, ...],
        clock: Callable[[], datetime],
    ) -> None:
        if (
            not callable(getattr(delegate, "start", None))
            or not callable(getattr(delegate, "process", None))
            or not callable(getattr(delegate, "run_periodic", None))
        ):
            raise TypeError("camera epoch fence delegate is invalid")
        if (
            not callable(getattr(repository, "activate_camera_epoch", None))
            or type(authority) is not RuntimeCandidateAuthority
            or not callable(clock)
        ):
            raise TypeError("camera epoch fence authority is invalid")
        if (
            type(event_camera_ids) is not tuple
            or len(event_camera_ids) > 64
            or len(set(event_camera_ids)) != len(event_camera_ids)
            or any(_IDENTIFIER.fullmatch(value) is None for value in event_camera_ids)
        ):
            raise ValueError("event camera identities must be finite and unique")
        self._delegate = delegate
        self._repository = repository
        self._authority = authority
        self._event_camera_ids = frozenset(event_camera_ids)
        self._clock = clock
        self._current: dict[str, UUID] = {}
        self._lock = threading.RLock()

    @property
    def status(self) -> Any:
        return self._delegate.status

    def start(self) -> Any:
        return self._delegate.start()

    def process(self, observation: Any) -> Any:
        camera_id = getattr(observation, "camera_id", None)
        source_epoch = getattr(observation, "stream_epoch", None)
        if camera_id in self._event_camera_ids:
            self._activate(camera_id=camera_id, source_epoch=source_epoch)
        return self._delegate.process(observation)

    def run_periodic(
        self,
        *,
        camera_id: str,
        stream_epoch: UUID,
        source_time: datetime,
    ) -> Any:
        if camera_id in self._event_camera_ids:
            self._activate(camera_id=camera_id, source_epoch=stream_epoch)
        return self._delegate.run_periodic(
            camera_id=camera_id,
            stream_epoch=stream_epoch,
            source_time=source_time,
        )

    def _activate(self, *, camera_id: object, source_epoch: object) -> None:
        if (
            type(camera_id) is not str
            or _IDENTIFIER.fullmatch(camera_id) is None
            or type(source_epoch) is not UUID
        ):
            raise CameraEpochFenceError("camera epoch identity is invalid")
        with self._lock:
            previous = self._current.get(camera_id)
            if previous == source_epoch:
                return
            activated_at = self._clock()
            if (
                type(activated_at) is not datetime
                or activated_at.tzinfo is None
                or activated_at.utcoffset() is None
            ):
                raise CameraEpochFenceError("camera epoch clock is invalid")
            activated_at = activated_at.astimezone(UTC)
            try:
                receipt = self._repository.activate_camera_epoch(
                    receipt=self._authority.writer_receipt,
                    camera_id=camera_id,
                    source_epoch=source_epoch,
                    expected_source_epoch=previous,
                    activated_at=activated_at,
                )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise CameraEpochFenceError(
                    "camera epoch persistence failed closed"
                ) from exc
            if (
                type(receipt) is not CameraEpochActivationReceiptV1
                or receipt.camera_id != camera_id
                or receipt.source_epoch != source_epoch
                or receipt.previous_source_epoch != previous
                or receipt.site_id != self._authority.writer_receipt.site_id
                or receipt.runtime_session_id
                != self._authority.writer_receipt.runtime_session_id
                or receipt.runtime_writer_generation
                != self._authority.writer_receipt.runtime_writer_generation
                or receipt.configuration_activation_generation
                != self._authority.writer_receipt.configuration_activation_generation
            ):
                raise CameraEpochFenceError(
                    "camera epoch repository returned a mismatched receipt"
                )
            try:
                self._authority.activate_camera_epoch(receipt)
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise CameraEpochFenceError(
                    "camera epoch authority rejected its durable receipt"
                ) from exc
            self._current[camera_id] = source_epoch


__all__ = (
    "CameraEpochFenceError",
    "CameraEpochFencedEventService",
)
