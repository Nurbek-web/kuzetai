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
import subprocess
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol
from uuid import uuid4

Codec = Literal["h264", "h265"]
ReservationStatus = Literal["pending", "ready"]
_FRAGMENT_SCHEMA = "encoded-fragment.v1"


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
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.part")
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
        if self.root.exists() and self.root.is_symlink():
            raise ValueError("spool root must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve(strict=True)
        self.ring_seconds = ring_seconds
        self.max_camera_bytes = max_camera_bytes
        self.max_spool_bytes = max_spool_bytes
        self.pin_ttl = pin_ttl
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._records: dict[str, _FragmentRecord] = {}
        self._scan()

    @property
    def used_bytes(self) -> int:
        with self._lock:
            return sum(record.fragment.size_bytes for record in self._records.values())

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
    ) -> EncodedFragment:
        """Atomically publish one already-encoded 1–2 second fragment."""
        if not camera_id or len(camera_id) > 128:
            raise ValueError("camera_id must be non-empty and at most 128 characters")
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
        identity_material = (
            f"{camera_id}\0{start_at.isoformat()}\0{end_at.isoformat()}\0{codec}\0"
            f"{int(starts_with_keyframe)}\0{digest}"
        ).encode()
        fragment_id = hashlib.sha256(identity_material).hexdigest()
        directory = self._camera_directory(camera_id)
        path = directory / f"{fragment_id}.mp4"
        fragment = EncodedFragment(
            fragment_id=fragment_id,
            camera_id=camera_id,
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
            _atomic_write(path, payload)
            record = _FragmentRecord(fragment=fragment, pins={})
            self._records[fragment_id] = record
            try:
                self._write_metadata(record)
                self._enforce_bounds(protected_fragment_id=fragment_id)
            except BaseException:
                self._records.pop(fragment_id, None)
                self._delete_files(fragment)
                raise
            return fragment

    def reserve(
        self,
        *,
        reservation_id: str,
        camera_id: str,
        event_at: datetime,
        pre_roll: float,
        post_roll: float,
    ) -> EvidenceReservation:
        """Select a camera-local keyframe-decodable prefix and pin it durably."""
        if not reservation_id:
            raise ValueError("reservation_id must be non-empty")
        event_at = _require_utc(event_at, field="event_at")
        window_seconds = pre_roll + post_roll
        if pre_roll < 0 or post_roll < 0 or not 4.0 <= window_seconds <= 10.0:
            raise ValueError("evidence reservation window must be 4-10 seconds")
        target_start = event_at - timedelta(seconds=pre_roll)
        target_end = event_at + timedelta(seconds=post_roll)

        with self._lock:
            self.expire_pins()
            available = list(self.fragments(camera_id))
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
            selected: list[EncodedFragment] = []
            previous_end: datetime | None = None
            for fragment in available[keyframe_index:]:
                if fragment.start_at >= target_end:
                    break
                if previous_end is not None and fragment.start_at > previous_end:
                    break
                selected.append(fragment)
                previous_end = max(previous_end or fragment.end_at, fragment.end_at)
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
    ) -> EncodedFragment:
        """Adopt one splitmux-closed encoded file through the normal atomic path."""
        part_path = Path(part_path).absolute()
        incoming_root = self.root / ".incoming"
        if (
            part_path.is_symlink()
            or not part_path.is_file()
            or not part_path.resolve(strict=True).is_relative_to(incoming_root)
        ):
            raise ValueError("closed splitmux fragment must be a regular file under .incoming")
        if part_path.stat().st_size > self.max_camera_bytes:
            raise SpoolCapacityError("closed splitmux fragment exceeds configured byte bound")
        fragment = self.append(
            camera_id=camera_id,
            payload=part_path.read_bytes(),
            start_at=start_at,
            end_at=end_at,
            codec=codec,
            starts_with_keyframe=starts_with_keyframe,
        )
        part_path.unlink()
        _fsync_directory(part_path.parent)
        return fragment

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
        for incomplete in self.root.rglob("*"):
            if incomplete.is_symlink():
                if ".part" in incomplete.name:
                    incomplete.unlink(missing_ok=True)
                continue
            if incomplete.is_file() and ".part" in incomplete.name:
                incomplete.unlink(missing_ok=True)

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
                size = path.stat().st_size
                digest = _sha256_file(path)
                if size != raw["size_bytes"] or digest != raw["sha256"]:
                    raise ValueError("fragment integrity mismatch")
                fragment = EncodedFragment(
                    fragment_id=fragment_id,
                    camera_id=camera_id,
                    path=resolved_path,
                    start_at=start_at,
                    end_at=end_at,
                    codec=codec,
                    starts_with_keyframe=bool(raw["starts_with_keyframe"]),
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
            camera_over = {
                camera_id
                for camera_id in {record.fragment.camera_id for record in self._records.values()}
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
        return sum(fragment.duration_seconds for fragment in self.fragments(camera_id))

    def _camera_bytes(self, camera_id: str) -> int:
        return sum(fragment.size_bytes for fragment in self.fragments(camera_id))

    def _delete_files(self, fragment: EncodedFragment) -> None:
        self._metadata_path(fragment).unlink(missing_ok=True)
        fragment.path.unlink(missing_ok=True)
        if fragment.path.parent.exists():
            _fsync_directory(fragment.path.parent)


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
) -> GStreamerSplitMuxSinkSpec:
    """Return the exact bounded target sink contract without importing GStreamer."""
    if fragment_seconds not in (1, 2):
        raise ValueError("splitmux fragments must be 1-2 seconds")
    if max_fragment_bytes <= 0:
        raise ValueError("splitmux max_fragment_bytes must be finite and positive")
    if codec not in ("h264", "h265"):
        raise ValueError("splitmux codec must be h264 or h265")
    camera_key = hashlib.sha256(camera_id.encode()).hexdigest()
    incoming = Path(spool_root).absolute() / ".incoming" / camera_key
    return GStreamerSplitMuxSinkSpec(
        factory="splitmuxsink",
        codec=codec,
        properties={
            "location": incoming / "%05d.part.mp4",
            "muxer-factory": "mp4mux",
            "max-size-time": fragment_seconds * 1_000_000_000,
            "max-size-bytes": max_fragment_bytes,
            "send-keyframe-requests": True,
            "async-finalize": True,
        },
    )


class SplitMuxEvidenceSinkFactory:
    """Target-side splitmux writer injected into Task 6 without importing GI on M2."""

    def __init__(
        self,
        *,
        ring: EncodedFragmentRing,
        fragment_seconds: int,
        max_fragment_bytes: int,
    ) -> None:
        if fragment_seconds not in (1, 2):
            raise ValueError("splitmux fragments must be 1-2 seconds")
        if max_fragment_bytes <= 0 or max_fragment_bytes > ring.max_camera_bytes:
            raise ValueError("splitmux max fragment bytes must fit the camera spool bound")
        self.ring = ring
        self.fragment_seconds = fragment_seconds
        self.max_fragment_bytes = max_fragment_bytes

    def __call__(self, gst: object, source: object) -> object:
        camera_id = str(getattr(source, "camera_id"))
        source_id = int(getattr(source, "source_id"))
        codec = getattr(source, "codec")
        spec = gstreamer_splitmux_sink_spec(
            spool_root=self.ring.root,
            camera_id=camera_id,
            codec=codec,
            fragment_seconds=self.fragment_seconds,
            max_fragment_bytes=self.max_fragment_bytes,
        )
        location = Path(spec.properties["location"])
        location.parent.mkdir(parents=True, exist_ok=True)
        sink = gst.ElementFactory.make(spec.factory, f"evidence-writer-{source_id}")  # type: ignore[attr-defined]
        if sink is None:
            raise RuntimeError("required GStreamer splitmuxsink is unavailable")
        for name, value in spec.properties.items():
            sink.set_property(name, str(value) if name == "location" else value)
        sink.set_property(
            "max-files",
            math.ceil(self.ring.ring_seconds / self.fragment_seconds) + 2,
        )
        return sink

    def commit_closed_fragment(
        self,
        *,
        camera_id: str,
        part_path: str | Path,
        start_at: datetime,
        end_at: datetime,
        codec: Codec,
        starts_with_keyframe: bool,
    ) -> EncodedFragment:
        """Finalise a target splitmux fragment after its close message supplies source time."""
        return self.ring.commit_closed_fragment(
            camera_id=camera_id,
            part_path=part_path,
            start_at=start_at,
            end_at=end_at,
            codec=codec,
            starts_with_keyframe=starts_with_keyframe,
        )


class CodecTool(Protocol):
    nvenc_available: bool

    def remux_h264(self, inputs: tuple[Path, ...], output: Path) -> None: ...

    def transcode_h265_nvenc(self, inputs: tuple[Path, ...], output: Path) -> None: ...


class FfmpegCodecTool:
    """Exact ffmpeg adapter; NVENC remains a Linux/L4 deployment gate."""

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or shutil.which("ffmpeg") or "ffmpeg"
        self.nvenc_available = self._detect_nvenc()

    @staticmethod
    def remux_command(concat_file: Path, output: Path) -> tuple[str, ...]:
        return (
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(concat_file),
            "-map",
            "0",
            "-c",
            "copy",
            "-movflags",
            "+faststart",
            str(output),
        )

    @staticmethod
    def nvenc_command(concat_file: Path, output: Path) -> tuple[str, ...]:
        return (
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-f",
            "concat",
            "-safe",
            "0",
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
            "-c:a",
            "aac",
            "-movflags",
            "+faststart",
            str(output),
        )

    def remux_h264(self, inputs: tuple[Path, ...], output: Path) -> None:
        self._run(inputs, output, nvenc=False)

    def transcode_h265_nvenc(self, inputs: tuple[Path, ...], output: Path) -> None:
        if not self.nvenc_available:
            raise ClipAssemblyError("NVENC H.264 encoder is unavailable")
        self._run(inputs, output, nvenc=True)

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

    def _run(self, inputs: tuple[Path, ...], output: Path, *, nvenc: bool) -> None:
        concat_file = output.with_name(f".{output.name}.{uuid4().hex}.concat")
        try:
            lines = []
            for path in inputs:
                escaped = str(path).replace("'", "'\\''")
                lines.append(f"file '{escaped}'")
            _atomic_write(concat_file, ("\n".join(lines) + "\n").encode())
            command = (
                self.nvenc_command(concat_file, output)
                if nvenc
                else self.remux_command(concat_file, output)
            )
            command = (self.executable, *command[1:])
            subprocess.run(command, check=True, capture_output=True, timeout=120)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ClipAssemblyError("ffmpeg evidence assembly failed") from exc
        finally:
            concat_file.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class AssembledEvidence:
    path: Path
    sha256: str
    codec: Literal["h264"]
    start_at: datetime
    end_at: datetime
    source_codec: Codec


class ClipAssembler:
    """Atomic H.264 remux or bounded target-only H.265→H.264 NVENC assembly."""

    def __init__(self, codec_tool: CodecTool, *, max_nvenc_jobs: int) -> None:
        if max_nvenc_jobs <= 0:
            raise ValueError("max_nvenc_jobs must be a finite positive bound")
        self._codec_tool = codec_tool
        self._nvenc_slots = threading.BoundedSemaphore(max_nvenc_jobs)

    def assemble(self, reservation: EvidenceReservation, output: str | Path) -> AssembledEvidence:
        if reservation.status != "ready":
            raise ClipAssemblyError("post-roll is still pending")
        if not 4.0 <= reservation.duration_seconds <= 10.0:
            raise ClipAssemblyError("evidence clip must be 4-10 seconds")
        if not reservation.fragments[0].starts_with_keyframe:
            raise ClipAssemblyError("evidence must begin at a keyframe")
        codecs = {fragment.codec for fragment in reservation.fragments}
        if len(codecs) != 1:
            raise ClipAssemblyError("evidence fragments use mixed codecs")
        source_codec = next(iter(codecs))
        output_path = Path(output).absolute()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_name(f".{output_path.stem}.{uuid4().hex}.part.mp4")
        inputs = tuple(fragment.path for fragment in reservation.fragments)
        acquired = False
        try:
            if source_codec == "h264":
                self._codec_tool.remux_h264(inputs, temporary)
            else:
                if not self._codec_tool.nvenc_available:
                    raise ClipAssemblyError("NVENC H.264 encoder is unavailable")
                acquired = self._nvenc_slots.acquire(blocking=False)
                if not acquired:
                    raise NvencCapacityError("NVENC evidence transcode capacity is full")
                self._codec_tool.transcode_h265_nvenc(inputs, temporary)
            if not temporary.is_file() or temporary.stat().st_size <= 0:
                raise ClipAssemblyError("codec tool did not produce a playable clip")
            os.replace(temporary, output_path)
            _fsync_directory(output_path.parent)
        finally:
            if acquired:
                self._nvenc_slots.release()
            temporary.unlink(missing_ok=True)
        assert reservation.start_at is not None
        assert reservation.end_at is not None
        return AssembledEvidence(
            path=output_path,
            sha256=_sha256_file(output_path),
            codec="h264",
            start_at=reservation.start_at,
            end_at=reservation.end_at,
            source_codec=source_codec,
        )
