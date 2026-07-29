"""Bounded encoded-fragment evidence spool and browser clip assembly.

The customer NVR remains the continuous-video owner.  This module accepts only
already encoded MP4 fragments, keeps a short finite spool, and never writes a
decoded-frame cache.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable
from uuid import uuid4

Codec = Literal["h264", "h265"]
ReservationStatus = Literal["pending", "ready"]
_FRAGMENT_SCHEMA = "encoded-fragment.v1"
_SPOOL_MARKER = ".kuzet-encoded-evidence-spool.v1"


class SpoolCapacityError(RuntimeError):
    """No unpinned fragment can be removed without violating a finite bound."""


class ClipAssemblyError(RuntimeError):
    """A browser evidence clip could not be assembled safely."""


class NvencCapacityError(ClipAssemblyError):
    """The bounded NVIDIA transcode pool is already full."""


def _require_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be UTC-aware")
    normalised = value.astimezone(UTC)
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must use UTC")
    return normalised


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    incomplete = path.parent / ".incomplete"
    incomplete.mkdir(mode=0o700, exist_ok=True)
    temporary = incomplete / f"{path.name}.{uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@dataclass(frozen=True, slots=True)
class EncodedFragment:
    """One independently identified, source-time-ordered encoded fragment."""

    fragment_id: str
    camera_id: str
    stream_epoch: str
    path: Path
    start_at: datetime
    end_at: datetime
    codec: Codec
    starts_with_keyframe: bool
    sha256: str
    size_bytes: int

    @property
    def duration_seconds(self) -> float:
        return (self.end_at - self.start_at).total_seconds()


@dataclass(frozen=True, slots=True)
class EvidenceReservation:
    """Pinned fragments for one candidate, including a pending playable prefix."""

    reservation_id: str
    camera_id: str
    target_start_at: datetime
    target_end_at: datetime
    fragments: tuple[EncodedFragment, ...]
    status: ReservationStatus

    @property
    def preview_fragment(self) -> EncodedFragment | None:
        return self.fragments[0] if self.fragments else None

    @property
    def start_at(self) -> datetime | None:
        return self.fragments[0].start_at if self.fragments else None

    @property
    def end_at(self) -> datetime | None:
        return self.fragments[-1].end_at if self.fragments else None

    @property
    def duration_seconds(self) -> float:
        if self.start_at is None or self.end_at is None:
            return 0.0
        return (self.end_at - self.start_at).total_seconds()


@dataclass(frozen=True, slots=True)
class BoundedMediaDescriptor:
    """One held regular-file descriptor with a finite byte ceiling."""

    descriptor: int
    max_bytes: int

    @property
    def descriptor_path(self) -> Path:
        return Path(f"/dev/fd/{self.descriptor}")


@dataclass(slots=True)
class _FragmentRecord:
    fragment: EncodedFragment
    pins: dict[str, datetime]


class EncodedFragmentRing:
    """Per-camera 15-second-or-less spool with finite byte bounds and durable pins."""

    def __init__(
        self,
        spool_root: str | Path,
        *,
        ring_seconds: int,
        max_camera_bytes: int,
        max_spool_bytes: int,
        pin_ttl: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= ring_seconds <= 15:
            raise ValueError("ring_seconds must be finite and between 1 and 15")
        if max_camera_bytes <= 0 or max_spool_bytes <= 0:
            raise ValueError("spool byte bounds must be finite and positive")
        if max_camera_bytes > max_spool_bytes:
            raise ValueError("per-camera byte bound cannot exceed total spool bound")
        if pin_ttl <= timedelta(0):
            raise ValueError("pin_ttl must be positive")
        self.root = Path(spool_root).absolute()
        if self.root == Path(self.root.anchor):
            raise ValueError("spool root must be a dedicated namespaced directory")
        if self.root.exists() and self.root.is_symlink():
            raise ValueError("spool root must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve(strict=True)
        root_stat = self.root.stat()
        if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o022:
            raise ValueError("spool root ownership or permissions are unsafe")
        marker = self.root / _SPOOL_MARKER
        if marker.exists():
            if marker.is_symlink() or not marker.is_file():
                raise ValueError("spool ownership marker is unsafe")
            if marker.read_text(encoding="utf-8") != _SPOOL_MARKER:
                raise ValueError("spool ownership marker is invalid")
        else:
            if any(self.root.iterdir()):
                raise ValueError("spool root is nonempty and not owned by Kuzet evidence")
            _atomic_write(marker, _SPOOL_MARKER.encode())
        self.ring_seconds = ring_seconds
        self.max_camera_bytes = max_camera_bytes
        self.max_spool_bytes = max_spool_bytes
        self.pin_ttl = pin_ttl
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._records: dict[str, _FragmentRecord] = {}
        self._staging_reservations: dict[str, int] = {}
        self._inflight_adoption_bytes: dict[str, int] = {}
        self._pending_write_bytes: dict[str, int] = {}
        self._scan()

    @property
    def used_bytes(self) -> int:
        with self._lock:
            adopted = sum(record.fragment.size_bytes for record in self._records.values())
            inflight = sum(self._inflight_adoption_bytes.values())
            pending = sum(self._pending_write_bytes.values())
            incoming_by_camera = self._incoming_bytes_by_camera()
            staged = sum(
                max(reserved, incoming_by_camera.pop(camera_id, 0))
                for camera_id, reserved in self._staging_reservations.items()
            )
            return (
                adopted
                + inflight
                + pending
                + staged
                + sum(incoming_by_camera.values())
            )

    def reserve_staging(self, camera_id: str, max_fragment_bytes: int) -> None:
        """Reserve one open splitmux fragment before a camera writer is attached."""
        if not camera_id or max_fragment_bytes <= 0:
            raise ValueError("camera staging reservation must be finite and positive")
        if max_fragment_bytes > self.max_camera_bytes:
            raise SpoolCapacityError("camera staging reservation exceeds its spool bound")
        with self._lock:
            existing = self._staging_reservations.get(camera_id)
            if existing is not None:
                if existing != max_fragment_bytes:
                    raise SpoolCapacityError("camera staging reservation changed during rebuild")
                self.assert_staging_within_bounds(camera_id)
                return
            self._staging_reservations[camera_id] = max_fragment_bytes
            try:
                self._enforce_bounds(protected_fragment_id=None)
                self.assert_staging_within_bounds(camera_id)
            except BaseException:
                self._staging_reservations.pop(camera_id, None)
                raise

    def release_staging(self, camera_id: str) -> None:
        with self._lock:
            self._staging_reservations.pop(camera_id, None)

    def assert_staging_within_bounds(self, camera_id: str) -> None:
        """Fail as soon as closed/open incoming files exceed either physical budget."""
        with self._lock:
            if (
                self._camera_bytes(camera_id) > self.max_camera_bytes
                or self.used_bytes > self.max_spool_bytes
            ):
                raise SpoolCapacityError("incoming evidence staging exceeded spool capacity")

    def fragments(self, camera_id: str) -> tuple[EncodedFragment, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (
                        record.fragment
                        for record in self._records.values()
                        if record.fragment.camera_id == camera_id
                    ),
                    key=lambda item: (item.start_at, item.end_at, item.fragment_id),
                )
            )

    def append(
        self,
        *,
        camera_id: str,
        payload: bytes,
        start_at: datetime,
        end_at: datetime,
        codec: Codec,
        starts_with_keyframe: bool,
        stream_epoch: str = "default",
    ) -> EncodedFragment:
        """Atomically publish one already-encoded 1–2 second fragment."""
        if not camera_id or len(camera_id) > 128:
            raise ValueError("camera_id must be non-empty and at most 128 characters")
        if not stream_epoch or len(stream_epoch) > 128:
            raise ValueError("stream_epoch must be non-empty and at most 128 characters")
        start_at = _require_utc(start_at, field="start_at")
        end_at = _require_utc(end_at, field="end_at")
        duration = (end_at - start_at).total_seconds()
        if not 1.0 <= duration <= 2.0:
            raise ValueError("encoded fragment duration must be 1-2 seconds")
        if codec not in ("h264", "h265"):
            raise ValueError("encoded fragment codec must be h264 or h265")
        if not payload:
            raise ValueError("encoded fragment payload must not be empty")
        if len(payload) > self.max_camera_bytes or len(payload) > self.max_spool_bytes:
            raise SpoolCapacityError("fragment exceeds configured spool byte bounds")

        digest = hashlib.sha256(payload).hexdigest()
        fragment_id = self._fragment_identity(
            camera_id=camera_id,
            stream_epoch=stream_epoch,
            start_at=start_at,
            end_at=end_at,
            codec=codec,
            starts_with_keyframe=starts_with_keyframe,
            digest=digest,
        )
        directory = self._camera_directory(camera_id)
        path = directory / f"{fragment_id}.mp4"
        fragment = EncodedFragment(
            fragment_id=fragment_id,
            camera_id=camera_id,
            stream_epoch=stream_epoch,
            path=path,
            start_at=start_at,
            end_at=end_at,
            codec=codec,
            starts_with_keyframe=starts_with_keyframe,
            sha256=digest,
            size_bytes=len(payload),
        )

        with self._lock:
            existing = self._records.get(fragment_id)
            if existing is not None:
                if existing.fragment != fragment:
                    raise ValueError("fragment identity was reused with different metadata")
                return existing.fragment
            same_stream = [
                record.fragment
                for record in self._records.values()
                if record.fragment.camera_id == camera_id
                and record.fragment.stream_epoch == stream_epoch
            ]
            if same_stream and start_at < max(item.end_at for item in same_stream):
                raise ValueError("fragment interval would overlap or regress within stream epoch")
            record = _FragmentRecord(fragment=fragment, pins={})
            self._adjust_accounted_bytes(
                self._pending_write_bytes,
                camera_id=camera_id,
                delta=len(payload),
            )
            pending_write = True
            record_added = False
            try:
                self._enforce_bounds(protected_fragment_id=None)
                _atomic_write(path, payload)
                self._records[fragment_id] = record
                record_added = True
                self._adjust_accounted_bytes(
                    self._pending_write_bytes,
                    camera_id=camera_id,
                    delta=-len(payload),
                )
                pending_write = False
                self._write_metadata(record)
                self._enforce_bounds(protected_fragment_id=fragment_id)
            except BaseException:
                if pending_write:
                    self._adjust_accounted_bytes(
                        self._pending_write_bytes,
                        camera_id=camera_id,
                        delta=-len(payload),
                    )
                if record_added:
                    self._records.pop(fragment_id, None)
                self._delete_files(fragment)
                raise
            return fragment

    def reserve(
        self,
        *,
        reservation_id: str,
        camera_id: str,
        stream_epoch: str,
        event_at: datetime,
        pre_roll: float,
        post_roll: float,
    ) -> EvidenceReservation:
        """Select a camera-local keyframe-decodable prefix and pin it durably."""
        if not reservation_id:
            raise ValueError("reservation_id must be non-empty")
        if not stream_epoch or len(stream_epoch) > 128:
            raise ValueError("stream_epoch must be non-empty and at most 128 characters")
        event_at = _require_utc(event_at, field="event_at")
        window_seconds = pre_roll + post_roll
        if pre_roll < 0 or post_roll < 0 or not 4.0 <= window_seconds <= 10.0:
            raise ValueError("evidence reservation window must be 4-10 seconds")
        target_start = event_at - timedelta(seconds=pre_roll)
        target_end = event_at + timedelta(seconds=post_roll)

        with self._lock:
            self.expire_pins()
            available = [
                fragment
                for fragment in self.fragments(camera_id)
                if fragment.stream_epoch == stream_epoch
            ]
            keyframe_index = next(
                (
                    index
                    for index in range(len(available) - 1, -1, -1)
                    if available[index].starts_with_keyframe
                    and available[index].start_at <= target_start
                ),
                None,
            )
            if keyframe_index is None:
                raise ValueError("no camera-local keyframe can decode the requested pre-roll")
            available = available[keyframe_index:]
            selected: list[EncodedFragment] = []
            previous_end: datetime | None = None
            for fragment in available:
                if fragment.start_at >= target_end:
                    break
                if previous_end is not None and fragment.start_at != previous_end:
                    break
                selected.append(fragment)
                previous_end = fragment.end_at
            if not selected:
                raise ValueError("no encoded fragments overlap the evidence window")
            codecs = {fragment.codec for fragment in selected}
            if len(codecs) != 1:
                raise ValueError("one evidence reservation cannot mix source codecs")
            duration = (selected[-1].end_at - selected[0].start_at).total_seconds()
            if duration > 10.0:
                raise ValueError("keyframe boundary would exceed the 10-second evidence limit")
            ready = (
                selected[0].start_at <= target_start
                and selected[-1].end_at >= target_end
                and 4.0 <= duration <= 10.0
            )
            expires_at = _require_utc(self._clock(), field="clock") + self.pin_ttl
            for fragment in selected:
                record = self._records[fragment.fragment_id]
                record.pins[reservation_id] = expires_at
                self._write_metadata(record)
            return EvidenceReservation(
                reservation_id=reservation_id,
                camera_id=camera_id,
                target_start_at=target_start,
                target_end_at=target_end,
                fragments=tuple(selected),
                status="ready" if ready else "pending",
            )

    def commit_closed_fragment(
        self,
        *,
        camera_id: str,
        part_path: str | Path,
        start_at: datetime,
        end_at: datetime,
        codec: Codec,
        starts_with_keyframe: bool,
        max_bytes: int,
        packet_probe: Callable[[BoundedMediaDescriptor], bool],
        stream_epoch: str = "default",
    ) -> EncodedFragment:
        """Adopt one splitmux-closed encoded file through the normal atomic path."""
        part_path = Path(part_path).absolute()
        incoming_root = self.root / ".incoming"
        if not part_path.is_relative_to(incoming_root):
            raise ValueError("closed splitmux fragment must be a regular file under .incoming")
        relative = part_path.relative_to(incoming_root)
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes <= 0
            or max_bytes > self.max_camera_bytes
        ):
            raise ValueError("closed splitmux fragment byte bound is invalid")
        directory_descriptor = os.open(
            incoming_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            for part in relative.parts[:-1]:
                child = os.open(
                    part,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
                os.close(directory_descriptor)
                directory_descriptor = child
            descriptor = os.open(
                relative.parts[-1],
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_descriptor,
            )
            inflight_bytes = 0
            try:
                file_stat = os.fstat(descriptor)
                if not stat.S_ISREG(file_stat.st_mode):
                    raise ValueError("closed splitmux fragment must be a regular file")
                if file_stat.st_size <= 0 or file_stat.st_size > max_bytes:
                    raise SpoolCapacityError(
                        "closed splitmux fragment exceeds configured byte bound"
                    )
                with self._lock:
                    os.unlink(relative.parts[-1], dir_fd=directory_descriptor)
                    self._adjust_accounted_bytes(
                        self._inflight_adoption_bytes,
                        camera_id=camera_id,
                        delta=file_stat.st_size,
                    )
                    inflight_bytes = file_stat.st_size
                    os.fsync(directory_descriptor)
                    self._enforce_bounds(protected_fragment_id=None)
                    self.assert_staging_within_bounds(camera_id)
                source = BoundedMediaDescriptor(
                    descriptor=descriptor,
                    max_bytes=max_bytes,
                )
                if not packet_probe(source):
                    raise ValueError(
                        "closed splitmux fragment does not start with a keyframe"
                    )
                os.lseek(descriptor, 0, os.SEEK_SET)
                payload = bytearray()
                while block := os.read(
                    descriptor,
                    min(1024 * 1024, max_bytes + 1 - len(payload)),
                ):
                    payload.extend(block)
                    if len(payload) > max_bytes:
                        raise SpoolCapacityError(
                            "closed splitmux fragment exceeds configured byte bound"
                        )
            finally:
                os.close(descriptor)
                if inflight_bytes:
                    with self._lock:
                        self._adjust_accounted_bytes(
                            self._inflight_adoption_bytes,
                            camera_id=camera_id,
                            delta=-inflight_bytes,
                        )
            fragment = self.append(
                camera_id=camera_id,
                payload=bytes(payload),
                start_at=start_at,
                end_at=end_at,
                codec=codec,
                starts_with_keyframe=starts_with_keyframe,
                stream_epoch=stream_epoch,
            )
            return fragment
        except OSError as exc:
            raise ValueError("closed splitmux fragment could not be adopted safely") from exc
        finally:
            os.close(directory_descriptor)

    def release(self, reservation_id: str) -> int:
        with self._lock:
            released = 0
            for record in self._records.values():
                if record.pins.pop(reservation_id, None) is not None:
                    self._write_metadata(record)
                    released += 1
            return released

    def expire_pins(self) -> int:
        now = _require_utc(self._clock(), field="clock")
        with self._lock:
            expired = 0
            for record in self._records.values():
                stale = [pin for pin, expires_at in record.pins.items() if expires_at <= now]
                for pin in stale:
                    del record.pins[pin]
                    expired += 1
                if stale:
                    self._write_metadata(record)
            return expired

    def _camera_directory(self, camera_id: str) -> Path:
        digest = hashlib.sha256(camera_id.encode()).hexdigest()
        directory = self.root / "cameras" / digest
        directory.mkdir(parents=True, exist_ok=True)
        resolved = directory.resolve(strict=True)
        if not resolved.is_relative_to(self.root):
            raise ValueError("camera spool path escaped the configured root")
        return resolved

    def _metadata_path(self, fragment: EncodedFragment) -> Path:
        return fragment.path.with_suffix(".json")

    def _write_metadata(self, record: _FragmentRecord) -> None:
        fragment = record.fragment
        payload = {
            "schema_version": _FRAGMENT_SCHEMA,
            "fragment_id": fragment.fragment_id,
            "camera_id": fragment.camera_id,
            "stream_epoch": fragment.stream_epoch,
            "path": fragment.path.name,
            "start_at": fragment.start_at.isoformat(),
            "end_at": fragment.end_at.isoformat(),
            "codec": fragment.codec,
            "starts_with_keyframe": fragment.starts_with_keyframe,
            "sha256": fragment.sha256,
            "size_bytes": fragment.size_bytes,
            "pins": {
                reservation_id: expires_at.isoformat()
                for reservation_id, expires_at in sorted(record.pins.items())
            },
        }
        _atomic_write(
            self._metadata_path(fragment),
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
        )

    def _scan(self) -> None:
        for incomplete in self.root.rglob(".incomplete"):
            if incomplete.is_symlink():
                incomplete.unlink(missing_ok=True)
            elif incomplete.is_dir():
                shutil.rmtree(incomplete)

        valid_data: set[Path] = set()
        for metadata_path in sorted(self.root.rglob("*.json")):
            try:
                if metadata_path.is_symlink():
                    raise ValueError("symlink metadata")
                resolved_metadata = metadata_path.resolve(strict=True)
                if not resolved_metadata.is_relative_to(self.root):
                    raise ValueError("metadata escaped spool")
                raw = json.loads(metadata_path.read_text(encoding="utf-8"))
                if raw.get("schema_version") != _FRAGMENT_SCHEMA:
                    raise ValueError("unknown fragment schema")
                fragment_id = str(raw["fragment_id"])
                camera_id = str(raw["camera_id"])
                stream_epoch = str(raw["stream_epoch"])
                if raw["path"] != f"{fragment_id}.mp4":
                    raise ValueError("fragment path is not canonical")
                if metadata_path.parent != self._camera_directory(camera_id):
                    raise ValueError("camera directory mismatch")
                path = metadata_path.parent / raw["path"]
                if path.is_symlink() or not path.is_file():
                    raise ValueError("fragment file is missing or unsafe")
                resolved_path = path.resolve(strict=True)
                if not resolved_path.is_relative_to(self.root):
                    raise ValueError("fragment escaped spool")
                start_at = _require_utc(datetime.fromisoformat(raw["start_at"]), field="start_at")
                end_at = _require_utc(datetime.fromisoformat(raw["end_at"]), field="end_at")
                codec = raw["codec"]
                if codec not in ("h264", "h265"):
                    raise ValueError("unsupported codec")
                starts_with_keyframe = raw["starts_with_keyframe"]
                if type(starts_with_keyframe) is not bool:
                    raise ValueError("starts_with_keyframe must be a boolean")
                size = path.stat().st_size
                digest = _sha256_file(path)
                if size != raw["size_bytes"] or digest != raw["sha256"]:
                    raise ValueError("fragment integrity mismatch")
                expected_identity = self._fragment_identity(
                    camera_id=camera_id,
                    stream_epoch=stream_epoch,
                    start_at=start_at,
                    end_at=end_at,
                    codec=codec,
                    starts_with_keyframe=starts_with_keyframe,
                    digest=digest,
                )
                if fragment_id != expected_identity:
                    raise ValueError("fragment identity does not match metadata")
                fragment = EncodedFragment(
                    fragment_id=fragment_id,
                    camera_id=camera_id,
                    stream_epoch=stream_epoch,
                    path=resolved_path,
                    start_at=start_at,
                    end_at=end_at,
                    codec=codec,
                    starts_with_keyframe=starts_with_keyframe,
                    sha256=digest,
                    size_bytes=size,
                )
                pins = {
                    str(reservation_id): _require_utc(
                        datetime.fromisoformat(expires_at), field="pin expiry"
                    )
                    for reservation_id, expires_at in dict(raw.get("pins", {})).items()
                }
                self._records[fragment_id] = _FragmentRecord(fragment=fragment, pins=pins)
                valid_data.add(resolved_path)
            except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
                self._remove_unsafe_pair(metadata_path)

        self._discard_overlapping_restart_records()
        valid_data = {record.fragment.path for record in self._records.values()}
        for path in self.root.rglob("*.mp4"):
            if path.is_symlink():
                path.unlink(missing_ok=True)
                continue
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                continue
            if resolved.is_relative_to(self.root) and resolved not in valid_data:
                path.unlink(missing_ok=True)
        self.expire_pins()
        self._enforce_bounds(protected_fragment_id=None)

    def _remove_unsafe_pair(self, metadata_path: Path) -> None:
        try:
            raw = json.loads(metadata_path.read_text(encoding="utf-8"))
            name = raw.get("path")
            if isinstance(name, str) and name == Path(name).name:
                candidate = metadata_path.parent / name
                if candidate.is_symlink() or (
                    candidate.exists()
                    and candidate.resolve(strict=True).is_relative_to(self.root)
                ):
                    candidate.unlink(missing_ok=True)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            pass
        metadata_path.unlink(missing_ok=True)

    def _enforce_bounds(self, *, protected_fragment_id: str | None) -> None:
        self.expire_pins()
        while True:
            camera_ids = (
                {record.fragment.camera_id for record in self._records.values()}
                | set(self._staging_reservations)
                | set(self._inflight_adoption_bytes)
                | set(self._pending_write_bytes)
                | set(self._incoming_bytes_by_camera())
            )
            camera_over = {
                camera_id
                for camera_id in camera_ids
                if self._camera_duration(camera_id) > self.ring_seconds
                or self._camera_bytes(camera_id) > self.max_camera_bytes
            }
            total_over = self.used_bytes > self.max_spool_bytes
            if not camera_over and not total_over:
                return
            now = _require_utc(self._clock(), field="clock")
            candidates = [
                record.fragment
                for record in self._records.values()
                if record.fragment.fragment_id != protected_fragment_id
                and not any(expiry > now for expiry in record.pins.values())
                and (total_over or record.fragment.camera_id in camera_over)
            ]
            if not candidates:
                raise SpoolCapacityError("configured spool bound is held by pinned fragments")
            victim = min(candidates, key=lambda item: (item.start_at, item.fragment_id))
            self._records.pop(victim.fragment_id)
            self._delete_files(victim)

    def _camera_duration(self, camera_id: str) -> float:
        fragments = self.fragments(camera_id)
        if not fragments:
            return 0.0
        return (fragments[-1].end_at - fragments[0].start_at).total_seconds()

    def _camera_bytes(self, camera_id: str) -> int:
        adopted = sum(fragment.size_bytes for fragment in self.fragments(camera_id))
        incoming = self._incoming_bytes_by_camera().get(camera_id, 0)
        reserved = self._staging_reservations.get(camera_id, 0)
        inflight = self._inflight_adoption_bytes.get(camera_id, 0)
        pending = self._pending_write_bytes.get(camera_id, 0)
        return adopted + inflight + pending + max(incoming, reserved)

    @staticmethod
    def _adjust_accounted_bytes(
        accounting: dict[str, int],
        *,
        camera_id: str,
        delta: int,
    ) -> None:
        updated = accounting.get(camera_id, 0) + delta
        if updated < 0:
            raise RuntimeError("evidence byte accounting underflow")
        if updated:
            accounting[camera_id] = updated
        else:
            accounting.pop(camera_id, None)

    def _incoming_bytes_by_camera(self) -> dict[str, int]:
        incoming_root = self.root / ".incoming"
        if not incoming_root.exists() or incoming_root.is_symlink():
            return {}
        camera_keys = {
            hashlib.sha256(camera_id.encode()).hexdigest(): camera_id
            for camera_id in self._staging_reservations
        }
        totals: dict[str, int] = {}
        for directory in incoming_root.iterdir():
            if directory.is_symlink() or not directory.is_dir():
                continue
            camera_id = camera_keys.get(directory.name, f"unreserved:{directory.name}")
            total = 0
            for path in directory.rglob("*"):
                try:
                    path_stat = path.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(path_stat.st_mode):
                    total += path_stat.st_size
            totals[camera_id] = total
        return totals

    def _delete_files(self, fragment: EncodedFragment) -> None:
        self._metadata_path(fragment).unlink(missing_ok=True)
        fragment.path.unlink(missing_ok=True)
        if fragment.path.parent.exists():
            _fsync_directory(fragment.path.parent)

    @staticmethod
    def _fragment_identity(
        *,
        camera_id: str,
        stream_epoch: str,
        start_at: datetime,
        end_at: datetime,
        codec: Codec,
        starts_with_keyframe: bool,
        digest: str,
    ) -> str:
        material = (
            f"{camera_id}\0{stream_epoch}\0{start_at.isoformat()}\0{end_at.isoformat()}\0"
            f"{codec}\0{int(starts_with_keyframe)}\0{digest}"
        ).encode()
        return hashlib.sha256(material).hexdigest()

    def _discard_overlapping_restart_records(self) -> None:
        previous_end: dict[tuple[str, str], datetime] = {}
        ordered = sorted(
            self._records.values(),
            key=lambda record: (
                record.fragment.camera_id,
                record.fragment.stream_epoch,
                record.fragment.start_at,
                record.fragment.end_at,
                record.fragment.fragment_id,
            ),
        )
        for record in ordered:
            fragment = record.fragment
            key = (fragment.camera_id, fragment.stream_epoch)
            if key in previous_end and fragment.start_at < previous_end[key]:
                self._records.pop(fragment.fragment_id, None)
                self._delete_files(fragment)
                continue
            previous_end[key] = fragment.end_at


@dataclass(frozen=True, slots=True)
class GStreamerSplitMuxSinkSpec:
    """Import-free target contract for the source-side encoded splitmux writer."""

    factory: Literal["splitmuxsink"]
    properties: Mapping[str, object]
    codec: Codec
    decoded_frame_spool: Literal[False] = False


def gstreamer_splitmux_sink_spec(
    *,
    spool_root: str | Path,
    camera_id: str,
    codec: Codec,
    fragment_seconds: int,
    max_fragment_bytes: int,
    ring_seconds: int,
    max_camera_bytes: int,
    writer_generation: str = "standalone",
) -> GStreamerSplitMuxSinkSpec:
    """Return the exact bounded target sink contract without importing GStreamer."""
    if fragment_seconds not in (1, 2):
        raise ValueError("splitmux fragments must be 1-2 seconds")
    if max_fragment_bytes <= 0:
        raise ValueError("splitmux max_fragment_bytes must be finite and positive")
    if ring_seconds <= 0 or max_camera_bytes < max_fragment_bytes:
        raise ValueError("splitmux staging bounds must cover one finite fragment")
    if codec not in ("h264", "h265"):
        raise ValueError("splitmux codec must be h264 or h265")
    camera_key = hashlib.sha256(camera_id.encode()).hexdigest()
    if not writer_generation or "/" in writer_generation or "\\" in writer_generation:
        raise ValueError("writer generation must be one safe path component")
    incoming = (
        Path(spool_root).absolute()
        / ".incoming"
        / camera_key
        / writer_generation
    )
    duration_files = (ring_seconds + fragment_seconds - 1) // fragment_seconds
    byte_files = max_camera_bytes // max_fragment_bytes
    staging_max_files = max(1, min(duration_files, byte_files))
    return GStreamerSplitMuxSinkSpec(
        factory="splitmuxsink",
        codec=codec,
        properties={
            "location": incoming / "%05d.part.mp4",
            "muxer-factory": "mp4mux",
            "max-size-time": fragment_seconds * 1_000_000_000,
            # GStreamer documents keyframe requests as effective only when
            # byte-based splitting is disabled. Byte bounds are enforced by
            # the ring's separate staging reservation.
            "max-size-bytes": 0,
            "send-keyframe-requests": True,
            "async-finalize": False,
            # These files are unadopted staging only, never ring-owned or
            # pinned evidence. Synchronous close adoption removes them first;
            # the finite fallback prevents an unhealthy bus from accumulating
            # unbounded closed fragments.
            "max-files": staging_max_files,
        },
    )


class SourceTimeMappingError(RuntimeError):
    """A splitmux running timestamp cannot be bound to trusted source UTC."""


@dataclass(frozen=True, slots=True)
class _SourceTimeTransform:
    stream_epoch: str
    canonical_running_time_ns: int
    canonical_source_time: datetime
    validated_running_time_ns: int
    validated_source_time: datetime


_GST_CLOCK_TIME_NONE = 2**64 - 1


def _require_gstreamer_running_time(value: object) -> int:
    if type(value) is not int or not 0 <= value < _GST_CLOCK_TIME_NONE:
        raise SourceTimeMappingError(
            "GStreamer running time must be a non-negative integer clock value"
        )
    return value


class SourceTimeMapper:
    """Map one stream epoch through an immutable running-time-to-UTC transform."""

    def __init__(
        self,
        *,
        max_delta_seconds: float = 60.0,
        max_anchor_error_seconds: float = 0.250,
    ) -> None:
        if not math.isfinite(max_delta_seconds) or max_delta_seconds <= 0:
            raise ValueError("source-time mapping delta must be finite and positive")
        if (
            not math.isfinite(max_anchor_error_seconds)
            or max_anchor_error_seconds <= 0
        ):
            raise ValueError("source-time anchor error must be finite and positive")
        self.max_delta_seconds = max_delta_seconds
        self.max_anchor_error_seconds = max_anchor_error_seconds
        self._transforms: dict[str, _SourceTimeTransform] = {}
        self._lock = threading.RLock()

    def anchor(
        self,
        *,
        camera_id: str,
        stream_epoch: str,
        running_time_ns: int,
        source_time: datetime,
    ) -> None:
        if not camera_id or not stream_epoch:
            raise SourceTimeMappingError("invalid source-time anchor")
        running_time_ns = _require_gstreamer_running_time(running_time_ns)
        source_time = _require_utc(source_time, field="source_time")
        with self._lock:
            current = self._transforms.get(camera_id)
            if current is None or current.stream_epoch != stream_epoch:
                self._transforms[camera_id] = _SourceTimeTransform(
                    stream_epoch=stream_epoch,
                    canonical_running_time_ns=running_time_ns,
                    canonical_source_time=source_time,
                    validated_running_time_ns=running_time_ns,
                    validated_source_time=source_time,
                )
                return
            if running_time_ns < current.validated_running_time_ns:
                raise SourceTimeMappingError("running time regressed within a stream epoch")
            predicted_source_time = current.canonical_source_time + timedelta(
                seconds=(
                    running_time_ns - current.canonical_running_time_ns
                )
                / 1_000_000_000
            )
            anchor_error = abs((source_time - predicted_source_time).total_seconds())
            if anchor_error > self.max_anchor_error_seconds:
                raise SourceTimeMappingError(
                    "source clock discontinuity requires a new stream epoch"
                )
            self._transforms[camera_id] = _SourceTimeTransform(
                stream_epoch=stream_epoch,
                canonical_running_time_ns=current.canonical_running_time_ns,
                canonical_source_time=current.canonical_source_time,
                validated_running_time_ns=running_time_ns,
                validated_source_time=source_time,
            )

    def map(
        self,
        *,
        camera_id: str,
        stream_epoch: str,
        running_time_ns: int,
    ) -> datetime:
        running_time_ns = _require_gstreamer_running_time(running_time_ns)
        with self._lock:
            transform = self._transforms.get(camera_id)
        if transform is None or transform.stream_epoch != stream_epoch:
            raise SourceTimeMappingError("source-time mapping is not anchored for this epoch")
        validation_delta_seconds = (
            running_time_ns - transform.validated_running_time_ns
        ) / 1_000_000_000
        if abs(validation_delta_seconds) > self.max_delta_seconds:
            raise SourceTimeMappingError("splitmux timestamp is outside the mapping horizon")
        canonical_delta_seconds = (
            running_time_ns - transform.canonical_running_time_ns
        ) / 1_000_000_000
        return transform.canonical_source_time + timedelta(
            seconds=canonical_delta_seconds
        )


@dataclass(frozen=True, slots=True)
class _OpenedSplitMuxFragment:
    camera_id: str
    location: Path
    running_time_ns: int
    starts_with_keyframe: bool | None


@dataclass(frozen=True, slots=True)
class _WriterBinding:
    camera_id: str
    codec: Codec
    incoming_directory: Path
    stream_epoch: str | None = None


class SplitMuxEvidenceSinkFactory:
    """Target-side splitmux writer injected into Task 6 without importing GI on M2."""

    def __init__(
        self,
        *,
        ring: EncodedFragmentRing,
        fragment_seconds: int,
        max_fragment_bytes: int,
        packet_probe: Callable[[BoundedMediaDescriptor], bool] | None = None,
    ) -> None:
        if fragment_seconds not in (1, 2):
            raise ValueError("splitmux fragments must be 1-2 seconds")
        if max_fragment_bytes <= 0 or max_fragment_bytes > ring.max_camera_bytes:
            raise ValueError("splitmux max fragment bytes must fit the camera spool bound")
        self.ring = ring
        self.fragment_seconds = fragment_seconds
        self.max_fragment_bytes = max_fragment_bytes
        self._packet_probe = packet_probe or self._probe_first_packet_keyframe
        self._opened: dict[tuple[str, Path], _OpenedSplitMuxFragment] = {}
        self._writers: dict[int, _WriterBinding] = {}
        self._lock = threading.RLock()

    def __call__(self, gst: object, source: object) -> object:
        camera_id = str(getattr(source, "camera_id"))
        source_id = int(getattr(source, "source_id"))
        codec = getattr(source, "codec")
        self.ring.reserve_staging(camera_id, self.max_fragment_bytes)
        writer_generation = uuid4().hex
        spec = gstreamer_splitmux_sink_spec(
            spool_root=self.ring.root,
            camera_id=camera_id,
            codec=codec,
            fragment_seconds=self.fragment_seconds,
            max_fragment_bytes=self.max_fragment_bytes,
            ring_seconds=self.ring.ring_seconds,
            max_camera_bytes=self.ring.max_camera_bytes,
            writer_generation=writer_generation,
        )
        try:
            location = Path(spec.properties["location"])
            location.parent.mkdir(parents=True, exist_ok=True)
            sink = gst.ElementFactory.make(spec.factory, f"evidence-writer-{source_id}")  # type: ignore[attr-defined]
            if sink is None:
                raise RuntimeError("required GStreamer splitmuxsink is unavailable")
            for name, value in spec.properties.items():
                sink.set_property(name, str(value) if name == "location" else value)
            with self._lock:
                self._writers[id(sink)] = _WriterBinding(
                    camera_id=camera_id,
                    codec=codec,
                    incoming_directory=location.parent,
                )
            return sink
        except BaseException:
            self.ring.release_staging(camera_id)
            raise

    def disable(self, camera_id: str) -> None:
        """Release the open-fragment reservation after the writer is stopped."""
        self.reset_camera(camera_id)
        with self._lock:
            writer_ids = [
                writer_id
                for writer_id, binding in self._writers.items()
                if binding.camera_id == camera_id
            ]
        for writer_id in writer_ids:
            self._unbind_writer_id(writer_id)
        self.ring.release_staging(camera_id)

    def reset_camera(self, camera_id: str) -> None:
        """Discard stale open callbacks before a camera-local source rebuild."""
        with self._lock:
            self._opened = {
                key: opened
                for key, opened in self._opened.items()
                if opened.camera_id != camera_id
            }

    def bind_writer(self, writer: object, *, stream_epoch: str) -> None:
        if not stream_epoch:
            raise ValueError("writer stream epoch must be non-empty")
        with self._lock:
            binding = self._writers.get(id(writer))
            if binding is None:
                raise ValueError("evidence writer was not created by this factory")
            self._writers[id(writer)] = _WriterBinding(
                camera_id=binding.camera_id,
                codec=binding.codec,
                incoming_directory=binding.incoming_directory,
                stream_epoch=stream_epoch,
            )

    def unbind_writer(self, writer: object) -> None:
        self._unbind_writer_id(id(writer))

    def _unbind_writer_id(self, writer_id: int) -> None:
        with self._lock:
            binding = self._writers.pop(writer_id, None)
            if binding is None:
                return
            self._opened = {
                key: opened
                for key, opened in self._opened.items()
                if not opened.location.is_relative_to(binding.incoming_directory)
            }
            has_replacement = any(
                item.camera_id == binding.camera_id for item in self._writers.values()
            )
        if binding.incoming_directory.exists():
            shutil.rmtree(binding.incoming_directory)
            _fsync_directory(binding.incoming_directory.parent)
        if not has_replacement:
            self.ring.release_staging(binding.camera_id)

    def handle_writer_message(
        self,
        *,
        writer: object,
        structure: object,
        source_time_mapper: SourceTimeMapper,
    ) -> EncodedFragment | None:
        with self._lock:
            binding = self._writers.get(id(writer))
        if binding is None:
            # Delayed messages from a stopped/rebuilt writer are stale by
            # construction and must never inherit a replacement's epoch.
            return None
        if binding.stream_epoch is None:
            raise SourceTimeMappingError("evidence writer has no bound stream epoch")
        return self.handle_splitmux_message(
            camera_id=binding.camera_id,
            codec=binding.codec,
            stream_epoch=binding.stream_epoch,
            structure=structure,
            source_time_mapper=source_time_mapper,
        )

    def handle_splitmux_message(
        self,
        *,
        camera_id: str,
        codec: Codec,
        stream_epoch: str,
        structure: object,
        source_time_mapper: SourceTimeMapper,
    ) -> EncodedFragment | None:
        """Consume standard splitmux opened/closed element messages."""
        name = str(structure.get_name())  # type: ignore[attr-defined]
        if name not in {"splitmuxsink-fragment-opened", "splitmuxsink-fragment-closed"}:
            return None
        location_value = self._structure_value(structure, "location")
        running_value = self._structure_value(structure, "running-time")
        if not isinstance(location_value, str):
            raise ValueError("splitmux message omitted location or running-time")
        try:
            running_value = _require_gstreamer_running_time(running_value)
        except SourceTimeMappingError as exc:
            raise ValueError("splitmux message has invalid running-time") from exc
        location = Path(location_value).absolute()
        key = (camera_id, location)
        if name == "splitmuxsink-fragment-opened":
            keyframe_value = self._structure_value(
                structure,
                "starts-with-keyframe",
                default=None,
            )
            if keyframe_value is not None and type(keyframe_value) is not bool:
                raise ValueError("splitmux keyframe state must be boolean")
            if keyframe_value is False:
                raise ValueError("splitmux fragment does not start with a keyframe")
            opened = _OpenedSplitMuxFragment(
                camera_id=camera_id,
                location=location,
                running_time_ns=running_value,
                starts_with_keyframe=keyframe_value,
            )
            with self._lock:
                if key in self._opened:
                    raise ValueError("splitmux fragment was opened twice")
                self._opened[key] = opened
            self.ring.assert_staging_within_bounds(camera_id)
            return None
        with self._lock:
            opened = self._opened.pop(key, None)
        if opened is None or running_value <= opened.running_time_ns:
            raise ValueError("splitmux close did not match a valid open fragment")
        start_at = source_time_mapper.map(
            camera_id=camera_id,
            stream_epoch=stream_epoch,
            running_time_ns=opened.running_time_ns,
        )
        end_at = source_time_mapper.map(
            camera_id=camera_id,
            stream_epoch=stream_epoch,
            running_time_ns=running_value,
        )
        return self.commit_closed_fragment(
            camera_id=camera_id,
            part_path=location,
            start_at=start_at,
            end_at=end_at,
            codec=codec,
            starts_with_keyframe=True,
            stream_epoch=stream_epoch,
        )

    @staticmethod
    def _probe_first_packet_keyframe(source: BoundedMediaDescriptor) -> bool:
        return FfprobeMediaProbe().probe(
            source,
            pass_fds=(source.descriptor,),
        ).first_packet_keyframe

    @staticmethod
    def _structure_value(
        structure: object,
        name: str,
        *,
        default: object | None = None,
    ) -> object:
        try:
            value = structure.get_value(name)  # type: ignore[attr-defined]
        except (AttributeError, KeyError, TypeError):
            return default
        return default if value is None else value

    def commit_closed_fragment(
        self,
        *,
        camera_id: str,
        part_path: str | Path,
        start_at: datetime,
        end_at: datetime,
        codec: Codec,
        starts_with_keyframe: bool,
        stream_epoch: str = "default",
    ) -> EncodedFragment:
        """Finalise a target splitmux fragment after its close message supplies source time."""
        if starts_with_keyframe is not True:
            raise ValueError("splitmux fragment does not start with a keyframe")
        self.ring.assert_staging_within_bounds(camera_id)
        try:
            return self.ring.commit_closed_fragment(
                camera_id=camera_id,
                part_path=part_path,
                start_at=start_at,
                end_at=end_at,
                codec=codec,
                starts_with_keyframe=True,
                max_bytes=self.max_fragment_bytes,
                packet_probe=self._packet_probe,
                stream_epoch=stream_epoch,
            )
        except ClipAssemblyError as exc:
            raise ValueError(
                "closed splitmux fragment keyframe truth could not be derived"
            ) from exc


class CodecTool(Protocol):
    nvenc_available: bool

    def remux_h264(
        self,
        inputs: tuple[Path, ...],
        output: Path | AssemblyOutput,
        *,
        pass_fds: tuple[int, ...],
    ) -> None: ...

    def transcode_h265_nvenc(
        self,
        inputs: tuple[Path, ...],
        output: Path | AssemblyOutput,
        *,
        pass_fds: tuple[int, ...],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class MediaInfo:
    """Probed browser-relevant media facts, never inferred from extension alone."""

    duration_seconds: float
    codec: str
    profile: str
    pixel_format: str
    browser_compatible: bool
    first_packet_keyframe: bool


class MediaProbe(Protocol):
    def probe(
        self,
        path: Path | AssemblyOutput,
        *,
        pass_fds: tuple[int, ...] = (),
    ) -> MediaInfo: ...


@runtime_checkable
class AssemblyOutput(Protocol):
    """Seekable pre-opened output supplied by a descriptor-pinned workspace."""

    descriptor: int
    max_bytes: int

    @property
    def descriptor_path(self) -> Path: ...


class FfprobeMediaProbe:
    """Bounded ffprobe adapter used to model actual browser compatibility."""

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or shutil.which("ffprobe") or "ffprobe"

    def probe(
        self,
        path: Path | AssemblyOutput,
        *,
        pass_fds: tuple[int, ...] = (),
    ) -> MediaInfo:
        try:
            if isinstance(path, AssemblyOutput):
                if (
                    not isinstance(path.max_bytes, int)
                    or isinstance(path.max_bytes, bool)
                    or path.max_bytes <= 0
                ):
                    raise ValueError(
                        "descriptor media byte ceiling must be finite and positive"
                    )
                source_stat = os.fstat(path.descriptor)
                if (
                    not stat.S_ISREG(source_stat.st_mode)
                    or source_stat.st_size <= 0
                    or source_stat.st_size > path.max_bytes
                ):
                    raise ValueError("descriptor media exceeds its finite byte ceiling")
                os.lseek(path.descriptor, 0, os.SEEK_SET)
                source_arguments = ("-fd", str(path.descriptor), "fd:")
            else:
                source_arguments = (str(path),)
            result = subprocess.run(
                (
                    self.executable,
                    "-v",
                    "error",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "format=duration:stream=codec_name,profile,pix_fmt:"
                    "packet=size,flags",
                    "-show_packets",
                    "-of",
                    "json",
                    *source_arguments,
                ),
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
                pass_fds=pass_fds,
            )
            if isinstance(path, AssemblyOutput):
                source_stat = os.fstat(path.descriptor)
                if source_stat.st_size <= 0 or source_stat.st_size > path.max_bytes:
                    raise ValueError("descriptor media exceeded its finite byte ceiling")
                os.lseek(path.descriptor, 0, os.SEEK_SET)
            payload = json.loads(result.stdout)
            if result.stderr.strip():
                raise ValueError("ffprobe reported media errors")
            stream = payload["streams"][0]
            duration = float(payload["format"]["duration"])
            codec = str(stream["codec_name"]).lower()
            profile = str(stream.get("profile", ""))
            pixel_format = str(stream.get("pix_fmt", "")).lower()
            packets = payload["packets"]
            first_packet_keyframe = (
                isinstance(packets, list)
                and bool(packets)
                and "K" in str(packets[0].get("flags", ""))
            )
            if (
                not isinstance(packets, list)
                or not packets
                or any(int(packet["size"]) <= 0 for packet in packets)
                or not first_packet_keyframe
            ):
                raise ValueError("media packet structure is invalid")
        except (
            IndexError,
            KeyError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as exc:
            raise ClipAssemblyError("media compatibility probe failed") from exc
        compatible_profiles = {"baseline", "constrained baseline", "main", "high"}
        browser_compatible = (
            codec == "h264"
            and profile.strip().lower() in compatible_profiles
            and pixel_format == "yuv420p"
        )
        return MediaInfo(
            duration_seconds=duration,
            codec=codec,
            profile=profile,
            pixel_format=pixel_format,
            browser_compatible=browser_compatible,
            first_packet_keyframe=first_packet_keyframe,
        )


class FfmpegCodecTool:
    """Exact ffmpeg adapter; NVENC remains a Linux/L4 deployment gate."""

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or shutil.which("ffmpeg") or "ffmpeg"
        self.nvenc_available = self._detect_nvenc()

    @staticmethod
    def remux_command(
        concat_file: Path,
        output: Path | AssemblyOutput,
    ) -> tuple[str, ...]:
        prefix = (
            "ffmpeg",
            "-nostdin",
            "-y",
            "-v",
            "error",
            "-f",
            "concat",
            "-safe",
            "0",
            "-protocol_whitelist",
            "file,pipe,crypto,data",
            "-i",
            str(concat_file),
            "-map",
            "0",
            "-c",
            "copy",
            "-f",
            "mp4",
        )
        if isinstance(output, AssemblyOutput):
            return (*prefix, "-fd", str(output.descriptor), "fd:")
        return (*prefix, "-movflags", "+faststart", str(output))

    @staticmethod
    def nvenc_command(
        concat_file: Path,
        output: Path | AssemblyOutput,
    ) -> tuple[str, ...]:
        prefix = (
            "ffmpeg",
            "-nostdin",
            "-y",
            "-v",
            "error",
            "-f",
            "concat",
            "-safe",
            "0",
            "-protocol_whitelist",
            "file,pipe,crypto,data",
            "-i",
            str(concat_file),
            "-map",
            "0:v:0",
            "-map",
            "0:a?",
            "-c:v",
            "h264_nvenc",
            "-preset",
            "p4",
            "-profile:v",
            "high",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-f",
            "mp4",
        )
        if isinstance(output, AssemblyOutput):
            return (*prefix, "-fd", str(output.descriptor), "fd:")
        return (*prefix, "-movflags", "+faststart", str(output))

    def remux_h264(
        self,
        inputs: tuple[Path, ...],
        output: Path | AssemblyOutput,
        *,
        pass_fds: tuple[int, ...],
    ) -> None:
        self._run(inputs, output, nvenc=False, pass_fds=pass_fds)

    def transcode_h265_nvenc(
        self,
        inputs: tuple[Path, ...],
        output: Path | AssemblyOutput,
        *,
        pass_fds: tuple[int, ...],
    ) -> None:
        if not self.nvenc_available:
            raise ClipAssemblyError("NVENC H.264 encoder is unavailable")
        self._run(inputs, output, nvenc=True, pass_fds=pass_fds)

    def _detect_nvenc(self) -> bool:
        try:
            result = subprocess.run(
                [self.executable, "-nostdin", "-hide_banner", "-encoders"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False
        return "h264_nvenc" in result.stdout

    def _run(
        self,
        inputs: tuple[Path, ...],
        output: Path | AssemblyOutput,
        *,
        nvenc: bool,
        pass_fds: tuple[int, ...],
    ) -> None:
        if not isinstance(output, AssemblyOutput):
            raise ClipAssemblyError(
                "production ffmpeg assembly requires a finite descriptor output"
            )
        if (
            not isinstance(output.max_bytes, int)
            or isinstance(output.max_bytes, bool)
            or output.max_bytes <= 0
        ):
            raise ClipAssemblyError(
                "ffmpeg output byte ceiling must be finite and positive"
            )
        try:
            with tempfile.TemporaryDirectory(
                prefix="kuzet-ffmpeg-concat-"
            ) as directory:
                concat_file = Path(directory) / "fragments.concat"
                lines = []
                for path in inputs:
                    reference = (
                        f"file:{path}"
                        if str(path).startswith("/dev/fd/")
                        else str(path)
                    )
                    escaped = reference.replace("'", "'\\''")
                    lines.append(f"file '{escaped}'")
                _atomic_write(concat_file, ("\n".join(lines) + "\n").encode())
                command = (
                    self.nvenc_command(concat_file, output)
                    if nvenc
                    else self.remux_command(concat_file, output)
                )
                command = (self.executable, *command[1:])
                limited_command = (
                    sys.executable,
                    "-m",
                    "protector.pilot.runtime._limit_exec",
                    str(output.max_bytes),
                    "--",
                    *command,
                )
                subprocess.run(
                    limited_command,
                    check=True,
                    capture_output=True,
                    timeout=120,
                    pass_fds=pass_fds,
                )
        except (
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as exc:
            raise ClipAssemblyError("ffmpeg evidence assembly failed") from exc


@dataclass(frozen=True, slots=True)
class AssembledEvidence:
    path: Path | AssemblyOutput
    sha256: str
    codec: Literal["h264"]
    start_at: datetime
    end_at: datetime
    source_codec: Codec


class ClipAssembler:
    """Atomic H.264 remux or bounded target-only H.265→H.264 NVENC assembly."""

    def __init__(
        self,
        codec_tool: CodecTool,
        media_probe: MediaProbe,
        *,
        max_nvenc_jobs: int,
    ) -> None:
        if max_nvenc_jobs <= 0:
            raise ValueError("max_nvenc_jobs must be a finite positive bound")
        self._codec_tool = codec_tool
        self._media_probe = media_probe
        self._nvenc_slots = threading.BoundedSemaphore(max_nvenc_jobs)

    def assemble(
        self,
        reservation: EvidenceReservation,
        output: str | Path | AssemblyOutput,
    ) -> AssembledEvidence:
        """Build the final, duration-attested evidence clip."""
        if reservation.status != "ready":
            raise ClipAssemblyError("post-roll is still pending")
        return self._assemble(reservation, output, final=True)

    def assemble_preview(
        self,
        reservation: EvidenceReservation,
        output: str | Path | AssemblyOutput,
    ) -> AssembledEvidence:
        """Build a browser-playable pending preview without releasing its pins."""
        return self._assemble(reservation, output, final=False)

    def _assemble(
        self,
        reservation: EvidenceReservation,
        output: str | Path | AssemblyOutput,
        *,
        final: bool,
    ) -> AssembledEvidence:
        expected_duration = reservation.duration_seconds
        if not reservation.fragments:
            raise ClipAssemblyError("evidence reservation has no encoded fragments")
        if final and not 4.0 <= expected_duration <= 10.0:
            raise ClipAssemblyError("evidence clip must be 4-10 seconds")
        if not final and not 0.0 < expected_duration <= 10.0:
            raise ClipAssemblyError("evidence preview must be no longer than 10 seconds")
        self._validate_fragment_chain(reservation)
        codecs = {fragment.codec for fragment in reservation.fragments}
        if len(codecs) != 1:
            raise ClipAssemblyError("evidence fragments use mixed codecs")
        source_codec = next(iter(codecs))
        descriptor_output = output if isinstance(output, AssemblyOutput) else None
        if descriptor_output is None:
            output_path = Path(output).absolute()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = output_path.with_name(
                f".{output_path.stem}.{uuid4().hex}.part.mp4"
            )
            output_fds: tuple[int, ...] = ()
        else:
            output_path = descriptor_output.descriptor_path
            temporary = output_path
            output_fds = (descriptor_output.descriptor,)
            os.ftruncate(descriptor_output.descriptor, 0)
            os.lseek(descriptor_output.descriptor, 0, os.SEEK_SET)
        acquired = False
        try:
            with self._attested_inputs(reservation) as (inputs, pass_fds):
                codec_fds = (*pass_fds, *output_fds)
                media_items: list[MediaInfo] = []
                for path, descriptor in zip(inputs, pass_fds, strict=True):
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    media_items.append(
                        self._media_probe.probe(path, pass_fds=(descriptor,))
                    )
                media = tuple(media_items)
                self._rewind_descriptors(pass_fds)
                source_is_browser_compatible = (
                    source_codec == "h264"
                    and all(item.browser_compatible for item in media)
                )
                if source_is_browser_compatible:
                    self._codec_tool.remux_h264(
                        inputs,
                        (
                            temporary
                            if descriptor_output is None
                            else descriptor_output
                        ),
                        pass_fds=codec_fds,
                    )
                else:
                    if not self._codec_tool.nvenc_available:
                        raise ClipAssemblyError("NVENC H.264 encoder is unavailable")
                    acquired = self._nvenc_slots.acquire(blocking=False)
                    if not acquired:
                        raise NvencCapacityError("NVENC evidence transcode capacity is full")
                    self._codec_tool.transcode_h265_nvenc(
                        inputs,
                        (
                            temporary
                            if descriptor_output is None
                            else descriptor_output
                        ),
                        pass_fds=codec_fds,
                    )
            if descriptor_output is None:
                if not temporary.is_file() or temporary.stat().st_size <= 0:
                    raise ClipAssemblyError("codec tool did not produce a playable clip")
            else:
                os.fsync(descriptor_output.descriptor)
                output_stat = os.fstat(descriptor_output.descriptor)
                if (
                    not stat.S_ISREG(output_stat.st_mode)
                    or output_stat.st_uid != os.getuid()
                    or output_stat.st_mode & 0o022
                    or output_stat.st_size <= 0
                    or output_stat.st_size > descriptor_output.max_bytes
                ):
                    raise ClipAssemblyError(
                        "codec tool output failed finite descriptor validation"
                    )
                os.lseek(descriptor_output.descriptor, 0, os.SEEK_SET)
            output_media = self._media_probe.probe(
                temporary if descriptor_output is None else descriptor_output,
                pass_fds=output_fds,
            )
            if not output_media.browser_compatible or output_media.codec != "h264":
                raise ClipAssemblyError("assembled evidence is not browser-compatible H.264")
            if abs(output_media.duration_seconds - expected_duration) > 0.25:
                raise ClipAssemblyError("assembled evidence duration does not match source time")
            if final and not 4.0 <= output_media.duration_seconds <= 10.0:
                raise ClipAssemblyError("assembled evidence duration is outside 4-10 seconds")
            if not final and not 0.0 < output_media.duration_seconds <= 10.0:
                raise ClipAssemblyError("assembled preview duration is outside its finite bound")
            if descriptor_output is None:
                os.replace(temporary, output_path)
                _fsync_directory(output_path.parent)
        finally:
            if acquired:
                self._nvenc_slots.release()
            if descriptor_output is None:
                temporary.unlink(missing_ok=True)
        assert reservation.start_at is not None
        assert reservation.end_at is not None
        return AssembledEvidence(
            path=output_path if descriptor_output is None else descriptor_output,
            sha256=(
                _sha256_file(output_path)
                if descriptor_output is None
                else self._sha256_descriptor(
                    descriptor_output.descriptor,
                    max_bytes=descriptor_output.max_bytes,
                )
            ),
            codec="h264",
            start_at=reservation.start_at,
            end_at=reservation.end_at,
            source_codec=source_codec,
        )

    @staticmethod
    def _sha256_descriptor(descriptor: int, *, max_bytes: int) -> str:
        digest = hashlib.sha256()
        total = 0
        os.lseek(descriptor, 0, os.SEEK_SET)
        while block := os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total)):
            total += len(block)
            if total > max_bytes:
                raise ClipAssemblyError(
                    "assembled evidence exceeds its finite byte bound"
                )
            digest.update(block)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return digest.hexdigest()

    @staticmethod
    def _rewind_descriptors(descriptors: tuple[int, ...]) -> None:
        for descriptor in descriptors:
            os.lseek(descriptor, 0, os.SEEK_SET)

    @staticmethod
    def _validate_fragment_chain(reservation: EvidenceReservation) -> None:
        fragments = reservation.fragments
        if not fragments[0].starts_with_keyframe:
            raise ClipAssemblyError("evidence must begin at a keyframe")
        epoch = fragments[0].stream_epoch
        previous_end: datetime | None = None
        for fragment in fragments:
            if fragment.camera_id != reservation.camera_id or fragment.stream_epoch != epoch:
                raise ClipAssemblyError("evidence fragments cross a camera or stream epoch")
            if previous_end is not None and fragment.start_at != previous_end:
                raise ClipAssemblyError("evidence fragments are not a contiguous source-time chain")
            previous_end = fragment.end_at

    @contextmanager
    def _attested_inputs(
        self,
        reservation: EvidenceReservation,
    ):
        descriptors: list[int] = []
        inputs: list[Path] = []
        try:
            for fragment in reservation.fragments:
                metadata = self._read_metadata_safely(fragment)
                pins = metadata.get("pins")
                if (
                    metadata.get("fragment_id") != fragment.fragment_id
                    or metadata.get("sha256") != fragment.sha256
                    or not isinstance(pins, dict)
                    or reservation.reservation_id not in pins
                ):
                    raise ClipAssemblyError("pinned fragment metadata integrity check failed")
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(fragment.path, flags)
                descriptors.append(descriptor)
                file_stat = os.fstat(descriptor)
                if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size != fragment.size_bytes:
                    raise ClipAssemblyError("pinned fragment integrity check failed")
                digest = hashlib.sha256()
                while block := os.read(descriptor, 1024 * 1024):
                    digest.update(block)
                if digest.hexdigest() != fragment.sha256:
                    raise ClipAssemblyError("pinned fragment integrity check failed")
                os.lseek(descriptor, 0, os.SEEK_SET)
                inputs.append(Path(f"/dev/fd/{descriptor}"))
            yield tuple(inputs), tuple(descriptors)
        except OSError as exc:
            raise ClipAssemblyError("pinned fragment integrity check failed") from exc
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    @staticmethod
    def _read_metadata_safely(fragment: EncodedFragment) -> dict[str, object]:
        metadata_path = fragment.path.with_suffix(".json")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(metadata_path, flags)
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ClipAssemblyError("pinned fragment metadata integrity check failed")
            payload = bytearray()
            while block := os.read(descriptor, 64 * 1024):
                payload.extend(block)
                if len(payload) > 1024 * 1024:
                    raise ClipAssemblyError("pinned fragment metadata is unbounded")
            decoded = json.loads(payload)
            if not isinstance(decoded, dict):
                raise ClipAssemblyError("pinned fragment metadata is invalid")
            return decoded
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ClipAssemblyError("pinned fragment metadata integrity check failed") from exc
        finally:
            os.close(descriptor)
