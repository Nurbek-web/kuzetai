from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from protector.pilot.runtime.evidence import (
    ClipAssembler,
    ClipAssemblyError,
    EncodedFragmentRing,
    FfmpegCodecTool,
    NvencCapacityError,
    SplitMuxEvidenceSinkFactory,
    SpoolCapacityError,
    gstreamer_splitmux_sink_spec,
)

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class RecordingCodecTool:
    def __init__(self, *, nvenc_available: bool = True) -> None:
        self.nvenc_available = nvenc_available
        self.calls: list[tuple[str, tuple[Path, ...], Path]] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False

    def remux_h264(self, inputs: tuple[Path, ...], output: Path) -> None:
        self.calls.append(("remux", inputs, output))
        output.write_bytes(b"browser-h264-remux")

    def transcode_h265_nvenc(self, inputs: tuple[Path, ...], output: Path) -> None:
        if not self.nvenc_available:
            raise ClipAssemblyError("NVENC H.264 encoder is unavailable")
        self.calls.append(("nvenc", inputs, output))
        self.entered.set()
        if self.block:
            assert self.release.wait(timeout=2)
        output.write_bytes(b"browser-h264-nvenc")


def _ring(
    root: Path,
    clock: Clock,
    *,
    ring_seconds: int = 15,
    max_camera_bytes: int = 1_000,
    max_spool_bytes: int = 2_000,
) -> EncodedFragmentRing:
    return EncodedFragmentRing(
        root,
        ring_seconds=ring_seconds,
        max_camera_bytes=max_camera_bytes,
        max_spool_bytes=max_spool_bytes,
        pin_ttl=timedelta(seconds=5),
        clock=clock,
    )


def _append(
    ring: EncodedFragmentRing,
    *,
    camera_id: str = "camera-01",
    offset: int,
    payload: bytes = b"encoded",
    codec: str = "h264",
    keyframe: bool = True,
):
    return ring.append(
        camera_id=camera_id,
        payload=payload,
        start_at=NOW + timedelta(seconds=offset),
        end_at=NOW + timedelta(seconds=offset + 2),
        codec=codec,
        starts_with_keyframe=keyframe,
    )


def test_fragment_write_is_atomic_hashed_and_restart_validated(tmp_path: Path) -> None:
    clock = Clock()
    ring = _ring(tmp_path / "spool", clock)

    fragment = _append(ring, offset=0, payload=b"encoded-h264-fragment")

    assert fragment.camera_id == "camera-01"
    assert fragment.codec == "h264"
    assert fragment.starts_with_keyframe is True
    assert fragment.sha256 == "7764cbfddc6727b04bdc577d60189fb64d5934989044d51b400c1a594d9953d1"
    assert fragment.path.read_bytes() == b"encoded-h264-fragment"
    assert not list((tmp_path / "spool").rglob("*.part"))

    restarted = _ring(tmp_path / "spool", clock)
    assert restarted.fragments("camera-01") == (fragment,)


def test_restart_ignores_corrupt_metadata_or_symlinks_outside_spool(tmp_path: Path) -> None:
    clock = Clock()
    root = tmp_path / "spool"
    ring = _ring(root, clock)
    fragment = _append(ring, offset=0)
    outside = tmp_path / "outside.mp4"
    outside.write_bytes(b"customer-nvr-video")
    fragment.path.unlink()
    fragment.path.symlink_to(outside)
    metadata_path = fragment.path.with_suffix(".json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["path"] = "../../outside.mp4"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    (root / "orphan.part").write_bytes(b"incomplete")

    restarted = _ring(root, clock)

    assert restarted.fragments("camera-01") == ()
    assert outside.read_bytes() == b"customer-nvr-video"
    assert not (root / "orphan.part").exists()


def test_rotation_bounds_time_bytes_and_keeps_cameras_isolated(tmp_path: Path) -> None:
    clock = Clock()
    ring = _ring(
        tmp_path / "spool",
        clock,
        ring_seconds=4,
        max_camera_bytes=12,
        max_spool_bytes=20,
    )
    first = _append(ring, camera_id="camera-01", offset=0, payload=b"aaaaaa")
    second = _append(ring, camera_id="camera-01", offset=2, payload=b"bbbbbb")
    third = _append(ring, camera_id="camera-01", offset=4, payload=b"cccccc")
    other = _append(ring, camera_id="camera-02", offset=0, payload=b"dddddd")

    assert ring.fragments("camera-01") == (second, third)
    assert ring.fragments("camera-02") == (other,)
    assert not first.path.exists()
    assert ring.used_bytes <= 20


def test_only_unpinned_fragments_are_pruned_and_expired_pins_release_capacity(
    tmp_path: Path,
) -> None:
    clock = Clock()
    ring = _ring(
        tmp_path / "spool",
        clock,
        ring_seconds=4,
        max_camera_bytes=12,
        max_spool_bytes=12,
    )
    first = _append(ring, offset=0, payload=b"aaaaaa")
    second = _append(ring, offset=2, payload=b"bbbbbb")
    reservation = ring.reserve(
        reservation_id="event-pin",
        camera_id="camera-01",
        event_at=NOW + timedelta(seconds=2),
        pre_roll=2,
        post_roll=2,
    )
    assert reservation.fragments == (first, second)

    with pytest.raises(SpoolCapacityError, match="pinned"):
        _append(ring, offset=4, payload=b"cccccc")
    assert ring.fragments("camera-01") == (first, second)

    clock.advance(6)
    assert ring.expire_pins() == 2
    third = _append(ring, offset=4, payload=b"cccccc")
    assert ring.fragments("camera-01") == (second, third)


def test_reservation_waits_for_post_roll_and_starts_at_a_keyframe(tmp_path: Path) -> None:
    clock = Clock()
    ring = _ring(tmp_path / "spool", clock)
    _append(ring, offset=0, keyframe=True)
    _append(ring, offset=2, keyframe=False)
    _append(ring, offset=4, keyframe=True)

    pending = ring.reserve(
        reservation_id="event-01",
        camera_id="camera-01",
        event_at=NOW + timedelta(seconds=5),
        pre_roll=3,
        post_roll=3,
    )

    assert pending.status == "pending"
    assert pending.preview_fragment is not None
    assert pending.fragments[0].start_at == NOW
    assert pending.fragments[0].starts_with_keyframe is True

    _append(ring, offset=6, keyframe=False)
    ready = ring.reserve(
        reservation_id="event-01",
        camera_id="camera-01",
        event_at=NOW + timedelta(seconds=5),
        pre_roll=3,
        post_roll=3,
    )

    assert ready.status == "ready"
    assert ready.start_at == NOW
    assert ready.end_at == NOW + timedelta(seconds=8)
    assert 4 <= ready.duration_seconds <= 10


def test_reservation_refuses_cross_camera_or_non_keyframe_evidence(tmp_path: Path) -> None:
    clock = Clock()
    ring = _ring(tmp_path / "spool", clock)
    _append(ring, camera_id="camera-01", offset=0, keyframe=False)
    _append(ring, camera_id="camera-02", offset=0, keyframe=True)

    with pytest.raises(ValueError, match="keyframe"):
        ring.reserve(
            reservation_id="event-01",
            camera_id="camera-01",
            event_at=NOW + timedelta(seconds=1),
            pre_roll=1,
            post_roll=3,
        )


def test_h264_is_remuxed_without_decode_and_published_by_atomic_rename(tmp_path: Path) -> None:
    clock = Clock()
    ring = _ring(tmp_path / "spool", clock)
    for offset in (0, 2, 4):
        _append(ring, offset=offset)
    reservation = ring.reserve(
        reservation_id="event-01",
        camera_id="camera-01",
        event_at=NOW + timedelta(seconds=3),
        pre_roll=3,
        post_roll=3,
    )
    tool = RecordingCodecTool()
    assembler = ClipAssembler(tool, max_nvenc_jobs=1)

    result = assembler.assemble(reservation, tmp_path / "evidence.mp4")

    assert result.codec == "h264"
    assert result.path.read_bytes() == b"browser-h264-remux"
    assert [call[0] for call in tool.calls] == ["remux"]
    assert not list(tmp_path.glob("*.part"))


def test_h265_fails_closed_without_nvenc_and_limits_concurrency(tmp_path: Path) -> None:
    clock = Clock()
    ring = _ring(tmp_path / "spool", clock)
    for offset in (0, 2, 4):
        _append(ring, offset=offset, codec="h265")
    reservation = ring.reserve(
        reservation_id="event-01",
        camera_id="camera-01",
        event_at=NOW + timedelta(seconds=3),
        pre_roll=3,
        post_roll=3,
    )

    with pytest.raises(ClipAssemblyError, match="NVENC"):
        ClipAssembler(RecordingCodecTool(nvenc_available=False), max_nvenc_jobs=1).assemble(
            reservation, tmp_path / "unavailable.mp4"
        )

    tool = RecordingCodecTool()
    tool.block = True
    assembler = ClipAssembler(tool, max_nvenc_jobs=1)
    failure: list[BaseException] = []

    def first_job() -> None:
        try:
            assembler.assemble(reservation, tmp_path / "first.mp4")
        except BaseException as exc:  # pragma: no cover - asserted below
            failure.append(exc)

    thread = threading.Thread(target=first_job)
    thread.start()
    assert tool.entered.wait(timeout=2)
    with pytest.raises(NvencCapacityError, match="capacity"):
        assembler.assemble(reservation, tmp_path / "second.mp4")
    tool.release.set()
    thread.join(timeout=2)
    assert not failure


def test_ffmpeg_commands_keep_h264_copy_only_and_h265_target_only_nvenc() -> None:
    h264 = FfmpegCodecTool.remux_command(Path("concat.txt"), Path("clip.part"))
    h265 = FfmpegCodecTool.nvenc_command(Path("concat.txt"), Path("clip.part"))

    assert h264 == (
        "ffmpeg",
        "-nostdin",
        "-v",
        "error",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        "concat.txt",
        "-map",
        "0",
        "-c",
        "copy",
        "-movflags",
        "+faststart",
        "clip.part",
    )
    assert "h264_nvenc" in h265
    assert "videotoolbox" not in h265


def test_splitmux_contract_is_encoded_bounded_and_uses_incomplete_paths(tmp_path: Path) -> None:
    spec = gstreamer_splitmux_sink_spec(
        spool_root=tmp_path / "spool",
        camera_id="camera-01",
        codec="h264",
        fragment_seconds=2,
        max_fragment_bytes=4_000_000,
    )

    assert spec.factory == "splitmuxsink"
    assert spec.properties["max-size-time"] == 2_000_000_000
    assert spec.properties["max-size-bytes"] == 4_000_000
    assert spec.properties["send-keyframe-requests"] is True
    assert spec.properties["muxer-factory"] == "mp4mux"
    assert str(spec.properties["location"]).endswith(".part.mp4")
    assert spec.decoded_frame_spool is False


def test_splitmux_factory_attaches_bounded_writer_and_atomically_adopts_closed_fragment(
    tmp_path: Path,
) -> None:
    class Element:
        def __init__(self, factory: str, name: str) -> None:
            self.factory = factory
            self.name = name
            self.properties: dict[str, object] = {}

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

    class Gst:
        class ElementFactory:
            @staticmethod
            def make(factory: str, name: str) -> Element:
                return Element(factory, name)

    clock = Clock()
    ring = _ring(tmp_path / "spool", clock)
    factory = SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=2,
        max_fragment_bytes=1_000,
    )
    source = SimpleNamespace(camera_id="camera-01", source_id=0, codec="h264")

    sink = factory(Gst, source)

    assert sink.factory == "splitmuxsink"
    assert sink.name == "evidence-writer-0"
    assert sink.properties["max-files"] == 10
    assert sink.properties["async-finalize"] is True

    incoming = Path(str(sink.properties["location"]).replace("%05d", "00001"))
    incoming.parent.mkdir(parents=True, exist_ok=True)
    incoming.write_bytes(b"splitmux-encoded-fragment")
    fragment = factory.commit_closed_fragment(
        camera_id="camera-01",
        part_path=incoming,
        start_at=NOW,
        end_at=NOW + timedelta(seconds=2),
        codec="h264",
        starts_with_keyframe=True,
    )

    assert fragment in ring.fragments("camera-01")
    assert fragment.path.read_bytes() == b"splitmux-encoded-fragment"
    assert not incoming.exists()


@pytest.mark.parametrize(
    ("ring_seconds", "max_camera_bytes", "max_spool_bytes"),
    [(16, 100, 100), (15, 0, 100), (15, 100, 0)],
)
def test_spool_requires_finite_time_and_disk_bounds(
    tmp_path: Path,
    ring_seconds: int,
    max_camera_bytes: int,
    max_spool_bytes: int,
) -> None:
    with pytest.raises(ValueError):
        EncodedFragmentRing(
            tmp_path,
            ring_seconds=ring_seconds,
            max_camera_bytes=max_camera_bytes,
            max_spool_bytes=max_spool_bytes,
        )


def test_fragment_rejects_non_utc_or_non_one_to_two_second_ranges(tmp_path: Path) -> None:
    ring = EncodedFragmentRing(
        tmp_path,
        ring_seconds=15,
        max_camera_bytes=1_000,
        max_spool_bytes=1_000,
    )

    with pytest.raises(ValueError, match="UTC"):
        ring.append(
            camera_id="camera-01",
            payload=b"encoded",
            start_at=NOW.replace(tzinfo=None),
            end_at=NOW.replace(tzinfo=None) + timedelta(seconds=2),
            codec="h264",
            starts_with_keyframe=True,
        )
    with pytest.raises(ValueError, match="1-2"):
        ring.append(
            camera_id="camera-01",
            payload=b"encoded",
            start_at=NOW,
            end_at=NOW + timedelta(seconds=3),
            codec="h264",
            starts_with_keyframe=True,
        )


def test_fragment_identity_is_not_reused_for_different_payload(tmp_path: Path) -> None:
    ring = _ring(tmp_path, Clock())
    first = _append(ring, offset=0, payload=b"first")
    second = _append(ring, offset=0, payload=b"second")

    assert first.fragment_id != second.fragment_id
    assert first.sha256 != second.sha256
    assert {item.fragment_id for item in ring.fragments("camera-01")} == {
        first.fragment_id,
        second.fragment_id,
    }


def test_reservation_requires_four_to_ten_second_window(tmp_path: Path) -> None:
    ring = _ring(tmp_path, Clock())
    _append(ring, offset=0)

    for pre_roll, post_roll in ((1, 2), (6, 5)):
        with pytest.raises(ValueError, match="4-10"):
            ring.reserve(
                reservation_id=str(uuid4()),
                camera_id="camera-01",
                event_at=NOW + timedelta(seconds=1),
                pre_roll=pre_roll,
                post_roll=post_roll,
            )
