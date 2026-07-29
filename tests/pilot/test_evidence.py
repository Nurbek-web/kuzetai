from __future__ import annotations

import json
import os
import shutil
import subprocess
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
    FfprobeMediaProbe,
    MediaInfo,
    NvencCapacityError,
    SourceTimeMapper,
    SourceTimeMappingError,
    SplitMuxEvidenceSinkFactory,
    SpoolCapacityError,
    gstreamer_splitmux_sink_spec,
)
from protector.pilot.storage.object_store import PreviewWorkspace

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
        self.calls: list[tuple[str, tuple[Path, ...], object, tuple[int, ...]]] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False

    def remux_h264(
        self,
        inputs: tuple[Path, ...],
        output: object,
        *,
        pass_fds: tuple[int, ...],
    ) -> None:
        self.calls.append(("remux", inputs, output, pass_fds))
        output.write_bytes(b"browser-h264-remux")  # type: ignore[attr-defined]

    def transcode_h265_nvenc(
        self,
        inputs: tuple[Path, ...],
        output: object,
        *,
        pass_fds: tuple[int, ...],
    ) -> None:
        if not self.nvenc_available:
            raise ClipAssemblyError("NVENC H.264 encoder is unavailable")
        self.calls.append(("nvenc", inputs, output, pass_fds))
        self.entered.set()
        if self.block:
            assert self.release.wait(timeout=2)
        output.write_bytes(b"browser-h264-nvenc")  # type: ignore[attr-defined]


class RecordingMediaProbe:
    def __init__(
        self,
        *,
        source_compatible: bool = True,
        output_duration: float = 6.0,
    ) -> None:
        self.source_compatible = source_compatible
        self.output_duration = output_duration

    def probe(self, path: object, *, pass_fds: tuple[int, ...] = ()) -> MediaInfo:
        is_output = not isinstance(path, Path) or ".part.mp4" in path.name
        return MediaInfo(
            duration_seconds=self.output_duration if is_output else 2.0,
            codec="h264",
            profile="High" if self.source_compatible or is_output else "High 10",
            pixel_format="yuv420p" if self.source_compatible or is_output else "yuv420p10le",
            browser_compatible=self.source_compatible or is_output,
        )


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


def test_spool_requires_owned_dedicated_root_and_preserves_unrelated_siblings(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="dedicated"):
        EncodedFragmentRing(
            Path("/"),
            ring_seconds=15,
            max_camera_bytes=1_000,
            max_spool_bytes=2_000,
        )
    non_owned = tmp_path / "shared"
    non_owned.mkdir()
    unrelated = non_owned / "customer-video.mp4"
    unrelated.write_bytes(b"customer-owned")
    with pytest.raises(ValueError, match="not owned"):
        _ring(non_owned, Clock())
    assert unrelated.read_bytes() == b"customer-owned"

    unsafe = tmp_path / "unsafe-spool"
    unsafe.mkdir(mode=0o770)
    unsafe.chmod(0o770)
    with pytest.raises(ValueError, match="permissions"):
        _ring(unsafe, Clock())

    owned = tmp_path / "kuzet-spool"
    ring = _ring(owned, Clock())
    sibling = tmp_path / "customer-sibling.mp4"
    sibling.write_bytes(b"keep")
    _append(ring, offset=0)
    _ring(owned, Clock())
    assert sibling.read_bytes() == b"keep"


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
    unrelated = root / "orphan.part"
    unrelated.write_bytes(b"unrelated")
    incomplete = root / ".incomplete" / "atomic-write"
    incomplete.parent.mkdir()
    incomplete.write_bytes(b"incomplete")

    restarted = _ring(root, clock)

    assert restarted.fragments("camera-01") == ()
    assert outside.read_bytes() == b"customer-nvr-video"
    assert unrelated.read_bytes() == b"unrelated"
    assert not incomplete.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("start_at", (NOW + timedelta(seconds=1)).isoformat()),
        ("starts_with_keyframe", "false"),
    ],
)
def test_restart_recomputes_identity_and_requires_real_boolean_metadata(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    clock = Clock()
    root = tmp_path / "spool"
    ring = _ring(root, clock)
    fragment = _append(ring, offset=0)
    metadata_path = fragment.path.with_suffix(".json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata[field] = value
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    restarted = _ring(root, clock)

    assert restarted.fragments("camera-01") == ()


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
        stream_epoch="default",
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
        stream_epoch="default",
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
        stream_epoch="default",
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
            stream_epoch="default",
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
        stream_epoch="default",
        event_at=NOW + timedelta(seconds=3),
        pre_roll=3,
        post_roll=3,
    )
    tool = RecordingCodecTool()
    assembler = ClipAssembler(tool, RecordingMediaProbe(), max_nvenc_jobs=1)

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
        stream_epoch="default",
        event_at=NOW + timedelta(seconds=3),
        pre_roll=3,
        post_roll=3,
    )

    with pytest.raises(ClipAssemblyError, match="NVENC"):
        ClipAssembler(
            RecordingCodecTool(nvenc_available=False),
            RecordingMediaProbe(source_compatible=False),
            max_nvenc_jobs=1,
        ).assemble(reservation, tmp_path / "unavailable.mp4")

    tool = RecordingCodecTool()
    tool.block = True
    assembler = ClipAssembler(
        tool,
        RecordingMediaProbe(source_compatible=False),
        max_nvenc_jobs=1,
    )
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


def test_assembler_reopens_and_rehashes_pinned_fragments_before_ffmpeg(
    tmp_path: Path,
) -> None:
    ring = _ring(tmp_path / "spool", Clock())
    for offset in (0, 2, 4):
        _append(ring, offset=offset)
    reservation = ring.reserve(
        reservation_id="event-attest",
        camera_id="camera-01",
        stream_epoch="default",
        event_at=NOW + timedelta(seconds=3),
        pre_roll=3,
        post_roll=3,
    )
    reservation.fragments[0].path.write_bytes(b"tamper!")
    tool = RecordingCodecTool()

    with pytest.raises(ClipAssemblyError, match="integrity"):
        ClipAssembler(tool, RecordingMediaProbe(), max_nvenc_jobs=1).assemble(
            reservation, tmp_path / "tampered.mp4"
        )

    assert tool.calls == []


def test_browser_incompatible_h264_is_probed_and_uses_bounded_nvenc(tmp_path: Path) -> None:
    ring = _ring(tmp_path / "spool", Clock())
    for offset in (0, 2, 4):
        _append(ring, offset=offset, codec="h264")
    reservation = ring.reserve(
        reservation_id="event-incompatible-h264",
        camera_id="camera-01",
        stream_epoch="default",
        event_at=NOW + timedelta(seconds=3),
        pre_roll=3,
        post_roll=3,
    )
    tool = RecordingCodecTool()

    ClipAssembler(
        tool,
        RecordingMediaProbe(source_compatible=False),
        max_nvenc_jobs=1,
    ).assemble(reservation, tmp_path / "compatible.mp4")

    assert [call[0] for call in tool.calls] == ["nvenc"]
    assert all(str(path).startswith("/dev/fd/") for path in tool.calls[0][1])
    assert tool.calls[0][3]


def test_assembler_verifies_actual_media_duration_before_ready(tmp_path: Path) -> None:
    ring = _ring(tmp_path / "spool", Clock())
    for offset in (0, 2, 4):
        _append(ring, offset=offset)
    reservation = ring.reserve(
        reservation_id="event-duration",
        camera_id="camera-01",
        stream_epoch="default",
        event_at=NOW + timedelta(seconds=3),
        pre_roll=3,
        post_roll=3,
    )

    with pytest.raises(ClipAssemblyError, match="duration"):
        ClipAssembler(
            RecordingCodecTool(),
            RecordingMediaProbe(output_duration=9.0),
            max_nvenc_jobs=1,
        ).assemble(reservation, tmp_path / "wrong-duration.mp4")


def test_pending_h265_reservation_produces_browser_playable_preview(tmp_path: Path) -> None:
    ring = _ring(tmp_path / "spool", Clock())
    for offset in (0, 2, 4):
        _append(ring, offset=offset, codec="h265")
    pending = ring.reserve(
        reservation_id="event-preview",
        camera_id="camera-01",
        stream_epoch="default",
        event_at=NOW + timedelta(seconds=5),
        pre_roll=3,
        post_roll=3,
    )
    assert pending.status == "pending"
    tool = RecordingCodecTool()

    preview = ClipAssembler(
        tool,
        RecordingMediaProbe(
            source_compatible=False,
            output_duration=pending.duration_seconds,
        ),
        max_nvenc_jobs=1,
    ).assemble_preview(pending, tmp_path / "preview.mp4")

    assert preview.path.exists()
    assert preview.codec == "h264"
    assert [call[0] for call in tool.calls] == ["nvenc"]


def test_ffmpeg_commands_keep_h264_copy_only_and_h265_target_only_nvenc() -> None:
    h264 = FfmpegCodecTool.remux_command(Path("concat.txt"), Path("clip.part"))
    h265 = FfmpegCodecTool.nvenc_command(Path("concat.txt"), Path("clip.part"))
    descriptor_output = SimpleNamespace(
        descriptor=41,
        max_bytes=1_000,
        descriptor_path=Path("/dev/fd/41"),
    )
    descriptor_h264 = FfmpegCodecTool.remux_command(
        Path("concat.txt"),
        descriptor_output,
    )

    assert h264 == (
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
        "concat.txt",
        "-map",
        "0",
        "-c",
        "copy",
        "-f",
        "mp4",
        "-movflags",
        "+faststart",
        "clip.part",
    )
    assert descriptor_h264[-5:] == ("-f", "mp4", "-fd", "41", "fd:")
    assert "+faststart" not in descriptor_h264
    assert "h264_nvenc" in h265
    assert "yuv420p" in h265
    assert "high" in h265
    assert "videotoolbox" not in h265


def test_ffprobe_rejects_zero_exit_media_with_invalid_nal_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "streams": [
            {
                "codec_name": "h264",
                "profile": "High",
                "pix_fmt": "yuv420p",
            }
        ],
        "format": {"duration": "6.0"},
        "packets": [{"size": "128", "flags": "K_"}],
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=json.dumps(payload),
            stderr="[h264] Invalid NAL unit size",
        ),
    )

    with pytest.raises(ClipAssemblyError, match="probe failed"):
        FfprobeMediaProbe().probe(tmp_path / "partial.mp4")


@pytest.mark.skipif(
    shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None,
    reason="portable FFmpeg descriptor smoke requires local ffmpeg and ffprobe",
)
def test_real_ffmpeg_assembles_and_probes_seekable_workspace_descriptor(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.mp4"
    subprocess.run(
        (
            shutil.which("ffmpeg") or "ffmpeg",
            "-nostdin",
            "-y",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=blue:s=160x120:r=12:d=2",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            str(source),
        ),
        check=True,
        capture_output=True,
        timeout=30,
    )
    ring = _ring(
        tmp_path / "real-spool",
        Clock(),
        max_camera_bytes=source.stat().st_size * 4,
        max_spool_bytes=source.stat().st_size * 4,
    )
    payload = source.read_bytes()
    for offset in (0, 2, 4):
        _append(ring, offset=offset, payload=payload)
    reservation = ring.reserve(
        reservation_id="real-descriptor",
        camera_id="camera-01",
        stream_epoch="default",
        event_at=NOW + timedelta(seconds=3),
        pre_roll=3,
        post_roll=3,
    )
    workspace = PreviewWorkspace(
        tmp_path / "real-previews",
        ttl=timedelta(minutes=5),
        max_items=2,
        max_bytes=source.stat().st_size * 6,
        clock=lambda: NOW,
    )
    target = workspace.prepare("real-descriptor", kind="final")
    descriptor = target.descriptor

    assembled = ClipAssembler(
        FfmpegCodecTool(),
        FfprobeMediaProbe(),
        max_nvenc_jobs=1,
    ).assemble(reservation, target)
    registered = workspace.register(
        "real-descriptor",
        kind="final",
        path=assembled.path,  # type: ignore[arg-type]
    )

    assert registered.sha256 == assembled.sha256
    assert registered.size_bytes > 0
    assert workspace.path_for("real-descriptor", kind="final").is_file()
    assert workspace.cleanup("real-descriptor") == []
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_splitmux_contract_is_encoded_bounded_and_uses_incomplete_paths(tmp_path: Path) -> None:
    spec = gstreamer_splitmux_sink_spec(
        spool_root=tmp_path / "spool",
        camera_id="camera-01",
        codec="h264",
        fragment_seconds=2,
        max_fragment_bytes=4_000_000,
        ring_seconds=15,
        max_camera_bytes=64_000_000,
    )

    assert spec.factory == "splitmuxsink"
    assert spec.properties["max-size-time"] == 2_000_000_000
    assert spec.properties["max-size-bytes"] == 0
    assert spec.properties["send-keyframe-requests"] is True
    assert spec.properties["muxer-factory"] == "mp4mux"
    assert str(spec.properties["location"]).endswith(".part.mp4")
    assert spec.properties["max-files"] == 8
    assert spec.properties["async-finalize"] is False
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
        max_fragment_bytes=100,
    )
    source = SimpleNamespace(camera_id="camera-01", source_id=0, codec="h264")

    sink = factory(Gst, source)

    assert sink.factory == "splitmuxsink"
    assert sink.name == "evidence-writer-0"
    assert sink.properties["max-files"] == 8
    assert sink.properties["async-finalize"] is False

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


def test_open_and_closed_splitmux_staging_consumes_camera_and_global_budgets(
    tmp_path: Path,
) -> None:
    class Element:
        def __init__(self) -> None:
            self.properties: dict[str, object] = {}

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

    class Gst:
        class ElementFactory:
            @staticmethod
            def make(_: str, __: str) -> Element:
                return Element()

    ring = _ring(
        tmp_path / "spool",
        Clock(),
        max_camera_bytes=100,
        max_spool_bytes=150,
    )
    factory = SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=2,
        max_fragment_bytes=80,
    )
    first = SimpleNamespace(camera_id="camera-01", source_id=0, codec="h264")
    second = SimpleNamespace(camera_id="camera-02", source_id=1, codec="h264")

    first_sink = factory(Gst, first)
    assert ring.used_bytes == 80
    with pytest.raises(SpoolCapacityError, match="capacity|bound"):
        factory(Gst, second)

    incoming = Path(str(first_sink.properties["location"]).replace("%05d", "00001"))
    incoming.parent.mkdir(parents=True, exist_ok=True)
    incoming.write_bytes(b"a" * 50)
    incoming.with_name("00002.part.mp4").write_bytes(b"b" * 50)
    assert ring.used_bytes == 100
    incoming.with_name("00003.part.mp4").write_bytes(b"c")
    with pytest.raises(SpoolCapacityError, match="capacity"):
        ring.assert_staging_within_bounds("camera-01")

    factory.disable("camera-01")


def test_splitmux_messages_map_source_time_adopt_immediately_and_survive_rebuild(
    tmp_path: Path,
) -> None:
    class Element:
        def __init__(self) -> None:
            self.properties: dict[str, object] = {}

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

    class Gst:
        class ElementFactory:
            @staticmethod
            def make(_: str, __: str) -> Element:
                return Element()

    class Structure:
        def __init__(self, name: str, **values: object) -> None:
            self.name = name
            self.values = values

        def get_name(self) -> str:
            return self.name

        def get_value(self, name: str) -> object:
            return self.values[name]

    root = tmp_path / "spool"
    ring = _ring(root, Clock())
    factory = SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=2,
        max_fragment_bytes=100,
    )
    source = SimpleNamespace(camera_id="camera-01", source_id=0, codec="h264")
    sink = factory(Gst, source)
    part = Path(str(sink.properties["location"]).replace("%05d", "00001"))
    part.write_bytes(b"first-closed-fragment")
    mapper = SourceTimeMapper()
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=10_000_000_000,
        source_time=NOW,
    )

    assert (
        factory.handle_splitmux_message(
            camera_id="camera-01",
            codec="h264",
            stream_epoch="epoch-1",
            structure=Structure(
                "splitmuxsink-fragment-opened",
                location=str(part),
                **{"running-time": 9_000_000_000, "starts-with-keyframe": True},
            ),
            source_time_mapper=mapper,
        )
        is None
    )
    first = factory.handle_splitmux_message(
        camera_id="camera-01",
        codec="h264",
        stream_epoch="epoch-1",
        structure=Structure(
            "splitmuxsink-fragment-closed",
            location=str(part),
            **{"running-time": 11_000_000_000},
        ),
        source_time_mapper=mapper,
    )

    assert first is not None
    assert first.start_at == NOW - timedelta(seconds=1)
    assert first.end_at == NOW + timedelta(seconds=1)
    assert not part.exists()
    restarted = _ring(root, Clock())
    assert restarted.fragments("camera-01") == (first,)

    rebuilt = SplitMuxEvidenceSinkFactory(
        ring=restarted,
        fragment_seconds=2,
        max_fragment_bytes=100,
    )
    rebuilt_sink = rebuilt(Gst, source)
    second_part = Path(
        str(rebuilt_sink.properties["location"]).replace("%05d", "00002")
    )
    second_part.write_bytes(b"second-closed-fragment")
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-2",
        running_time_ns=1_000_000_000,
        source_time=NOW + timedelta(seconds=10),
    )
    rebuilt.handle_splitmux_message(
        camera_id="camera-01",
        codec="h264",
        stream_epoch="epoch-2",
        structure=Structure(
            "splitmuxsink-fragment-opened",
            location=str(second_part),
            **{"running-time": 0, "starts-with-keyframe": True},
        ),
        source_time_mapper=mapper,
    )
    second = rebuilt.handle_splitmux_message(
        camera_id="camera-01",
        codec="h264",
        stream_epoch="epoch-2",
        structure=Structure(
            "splitmuxsink-fragment-closed",
            location=str(second_part),
            **{"running-time": 2_000_000_000},
        ),
        source_time_mapper=mapper,
    )

    assert second is not None
    assert second.stream_epoch == "epoch-2"
    assert len(restarted.fragments("camera-01")) == 2


def test_source_time_mapping_keeps_one_canonical_transform_across_rtcp_jitter() -> None:
    mapper = SourceTimeMapper(
        max_delta_seconds=120,
        max_anchor_error_seconds=0.020,
    )
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=0,
        source_time=NOW,
    )
    shared_boundary = mapper.map(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=2_000_000_000,
    )

    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=2_000_000_000,
        source_time=NOW + timedelta(seconds=2, milliseconds=10),
    )
    assert mapper.map(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=2_000_000_000,
    ) == shared_boundary

    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=4_000_000_000,
        source_time=NOW + timedelta(seconds=3, milliseconds=995),
    )
    assert mapper.map(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=4_000_000_000,
    ) == NOW + timedelta(seconds=4)
    intervals = tuple(
        (
            mapper.map(
                camera_id="camera-01",
                stream_epoch="epoch-1",
                running_time_ns=start,
            ),
            mapper.map(
                camera_id="camera-01",
                stream_epoch="epoch-1",
                running_time_ns=start + 2_000_000_000,
            ),
        )
        for start in (0, 2_000_000_000)
    )
    assert intervals[0][1] == intervals[1][0]


def test_source_time_mapping_horizon_uses_latest_validated_anchor() -> None:
    mapper = SourceTimeMapper(max_delta_seconds=60)
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=0,
        source_time=NOW,
    )
    seventy_two_hours_ns = 72 * 60 * 60 * 1_000_000_000
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=seventy_two_hours_ns,
        source_time=NOW + timedelta(hours=72),
    )

    assert mapper.map(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=seventy_two_hours_ns - 2_000_000_000,
    ) == NOW + timedelta(hours=72, seconds=-2)
    with pytest.raises(SourceTimeMappingError, match="horizon"):
        mapper.map(
            camera_id="camera-01",
            stream_epoch="epoch-1",
            running_time_ns=0,
        )


@pytest.mark.parametrize("invalid_running_time", [True, -1, 2**64 - 1])
def test_source_time_mapping_rejects_invalid_gstreamer_clock_values(
    invalid_running_time: object,
) -> None:
    mapper = SourceTimeMapper()

    with pytest.raises(SourceTimeMappingError, match="running time|anchor"):
        mapper.anchor(
            camera_id="camera-01",
            stream_epoch="epoch-1",
            running_time_ns=invalid_running_time,  # type: ignore[arg-type]
            source_time=NOW,
        )
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=0,
        source_time=NOW,
    )
    with pytest.raises(SourceTimeMappingError, match="running time"):
        mapper.map(
            camera_id="camera-01",
            stream_epoch="epoch-1",
            running_time_ns=invalid_running_time,  # type: ignore[arg-type]
        )


def test_source_time_discontinuity_requires_a_new_stream_epoch() -> None:
    mapper = SourceTimeMapper(max_anchor_error_seconds=0.050)
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=0,
        source_time=NOW,
    )

    with pytest.raises(SourceTimeMappingError, match="discontinuity"):
        mapper.anchor(
            camera_id="camera-01",
            stream_epoch="epoch-1",
            running_time_ns=2_000_000_000,
            source_time=NOW + timedelta(seconds=3),
        )
    assert mapper.map(
        camera_id="camera-01",
        stream_epoch="epoch-1",
        running_time_ns=2_000_000_000,
    ) == NOW + timedelta(seconds=2)

    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-2",
        running_time_ns=100_000_000,
        source_time=NOW + timedelta(seconds=10),
    )
    assert mapper.map(
        camera_id="camera-01",
        stream_epoch="epoch-2",
        running_time_ns=1_100_000_000,
    ) == NOW + timedelta(seconds=11)


def test_delayed_old_writer_close_cannot_inherit_replacement_stream_epoch(
    tmp_path: Path,
) -> None:
    class Element:
        def __init__(self) -> None:
            self.properties: dict[str, object] = {}

        def set_property(self, name: str, value: object) -> None:
            self.properties[name] = value

    class Gst:
        class ElementFactory:
            @staticmethod
            def make(_: str, __: str) -> Element:
                return Element()

    class Structure:
        def __init__(self, name: str, **values: object) -> None:
            self.name = name
            self.values = values

        def get_name(self) -> str:
            return self.name

        def get_value(self, name: str) -> object:
            return self.values[name]

    ring = _ring(tmp_path / "spool", Clock())
    factory = SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=2,
        max_fragment_bytes=100,
    )
    source = SimpleNamespace(camera_id="camera-01", source_id=0, codec="h264")
    old_writer = factory(Gst, source)
    factory.bind_writer(old_writer, stream_epoch="epoch-old")
    old_part = Path(
        str(old_writer.properties["location"]).replace("%05d", "00001")
    )
    old_part.write_bytes(b"old-unadopted")
    mapper = SourceTimeMapper()
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-old",
        running_time_ns=1_000_000_000,
        source_time=NOW,
    )
    factory.handle_writer_message(
        writer=old_writer,
        structure=Structure(
            "splitmuxsink-fragment-opened",
            location=str(old_part),
            **{"running-time": 0},
        ),
        source_time_mapper=mapper,
    )

    replacement = factory(Gst, source)
    factory.bind_writer(replacement, stream_epoch="epoch-new")
    factory.unbind_writer(old_writer)
    assert not old_part.exists()
    mapper.anchor(
        camera_id="camera-01",
        stream_epoch="epoch-new",
        running_time_ns=1_000_000_000,
        source_time=NOW + timedelta(seconds=10),
    )

    delayed = factory.handle_writer_message(
        writer=old_writer,
        structure=Structure(
            "splitmuxsink-fragment-closed",
            location=str(old_part),
            **{"running-time": 2_000_000_000},
        ),
        source_time_mapper=mapper,
    )

    assert delayed is None
    assert ring.fragments("camera-01") == ()


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


def test_fragment_interval_cannot_overlap_or_regress_within_one_stream_epoch(
    tmp_path: Path,
) -> None:
    ring = _ring(tmp_path, Clock())
    first = _append(ring, offset=0, payload=b"first")
    second = _append(ring, offset=2, payload=b"second")

    with pytest.raises(ValueError, match="overlap|regress"):
        _append(ring, offset=2, payload=b"different-same-interval")
    with pytest.raises(ValueError, match="overlap|regress"):
        _append(ring, offset=-2, payload=b"late-old-fragment")

    assert ring.fragments("camera-01") == (first, second)


def test_persisted_ring_accepts_first_restart_fragment_without_cross_epoch_reservation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "spool"
    before_restart = _ring(root, Clock())
    old = before_restart.append(
        camera_id="camera-01",
        payload=b"old-encoded-fragment",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=2),
        codec="h264",
        starts_with_keyframe=True,
        stream_epoch="runtime-session-a:camera-01:0",
    )

    after_restart = _ring(root, Clock())
    new = after_restart.append(
        camera_id="camera-01",
        payload=b"new-22",
        start_at=NOW,
        end_at=NOW + timedelta(seconds=2),
        codec="h264",
        starts_with_keyframe=True,
        stream_epoch="runtime-session-b:camera-01:0",
    )
    reservation = after_restart.reserve(
        reservation_id="restart-reservation",
        camera_id="camera-01",
        stream_epoch="runtime-session-b:camera-01:0",
        event_at=NOW + timedelta(seconds=2),
        pre_roll=2,
        post_roll=2,
    )

    assert old.fragment_id != new.fragment_id
    assert old.fragment_id > new.fragment_id
    assert len(after_restart.fragments("camera-01")) == 2
    assert reservation.fragments == (new,)
    assert reservation.fragments[0].path.read_bytes() == b"new-22"


def test_time_bound_is_source_span_not_sum_of_fragment_durations(tmp_path: Path) -> None:
    ring = _ring(
        tmp_path,
        Clock(),
        ring_seconds=4,
        max_camera_bytes=1_000,
        max_spool_bytes=1_000,
    )
    second = _append(ring, offset=2, payload=b"second")
    third = _append(ring, offset=4, payload=b"third")

    assert ring.fragments("camera-01") == (second, third)
    assert (
        ring.fragments("camera-01")[-1].end_at - ring.fragments("camera-01")[0].start_at
    ).total_seconds() <= 4


def test_reservation_requires_four_to_ten_second_window(tmp_path: Path) -> None:
    ring = _ring(tmp_path, Clock())
    _append(ring, offset=0)

    for pre_roll, post_roll in ((1, 2), (6, 5)):
        with pytest.raises(ValueError, match="4-10"):
            ring.reserve(
                reservation_id=str(uuid4()),
                camera_id="camera-01",
                stream_epoch="default",
                event_at=NOW + timedelta(seconds=1),
                pre_roll=pre_roll,
                post_roll=post_roll,
            )
