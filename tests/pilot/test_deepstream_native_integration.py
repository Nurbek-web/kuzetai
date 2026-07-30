from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from threading import Event as ThreadEvent
from threading import Thread

import pytest

import protector.pilot.runtime.deepstream as deepstream_module
import protector.pilot.runtime.evidence as evidence_runtime
from protector.pilot.runtime.deepstream import (
    DeepStreamDataPlane,
    DeepStreamGraphSpec,
    FrameMetadataV1,
    MetadataPublisher,
)
from protector.pilot.runtime.evidence import (
    EncodedFragmentRing,
    SourceTimeMappingError,
    SplitMuxEvidenceSinkFactory,
)
from protector.pilot.runtime.source_probe import (
    CorrelatedNtpV1,
    NativeSourceProbeBridge,
)
from protector.pilot.runtime.supervisor import CameraSupervisor
from tests.pilot.test_deepstream_graph import _manifest, _manifest_with_files, _site


class RecordingLease:
    def __init__(
        self,
        *,
        reject: bool = False,
        close_error: bool = False,
        correlated: bool = True,
    ) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.correlation_queries: list[tuple[int, int]] = []
        self.close_calls = 0
        self.reject = reject
        self.close_error = close_error
        self.correlated = correlated
        self.last_ntp_observed_monotonic_ns: int | None = None

    def observe_rtp_caps(self, codec: str, observed_monotonic_ns: int) -> bool:
        self.calls.append(("rtp", codec, observed_monotonic_ns))
        return not self.reject

    def observe_decoder_caps(
        self,
        width: int,
        height: int,
        fps_numerator: int,
        fps_denominator: int,
        observed_monotonic_ns: int,
    ) -> bool:
        self.calls.append(
            (
                "decoder_caps",
                width,
                height,
                fps_numerator,
                fps_denominator,
                observed_monotonic_ns,
            )
        )
        return not self.reject

    def observe_parser_buffer(
        self,
        byte_size: int,
        source_timestamp_ns: int,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        self.calls.append(
            (
                "parser",
                byte_size,
                source_timestamp_ns,
                pts_ns,
                observed_monotonic_ns,
            )
        )
        return not self.reject

    def observe_decoded_buffer(
        self,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        self.calls.append(("decoded", pts_ns, observed_monotonic_ns))
        return not self.reject

    def observe_nvds_ntp(
        self,
        pts_ns: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        self.calls.append(("ntp", pts_ns, source_ntp_ns, observed_monotonic_ns))
        self.last_ntp_observed_monotonic_ns = observed_monotonic_ns
        return not self.reject

    def correlated_ntp(self, pts_ns: int, source_ntp_ns: int) -> object | None:
        self.correlation_queries.append((pts_ns, source_ntp_ns))
        if self.reject or not self.correlated or self.last_ntp_observed_monotonic_ns is None:
            return None
        return CorrelatedNtpV1(
            pts_ns=pts_ns,
            source_ntp_ns=source_ntp_ns,
            parser_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
            decoded_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
            ntp_observed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
            completed_monotonic_ns=self.last_ntp_observed_monotonic_ns,
        )

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error:
            raise RuntimeError("lease cleanup failed")


class AllowingNativeCallbacks:
    def __init__(self) -> None:
        self.failures: list[object] = []
        self.close_calls = 0

    @staticmethod
    def on_rtp_caps(_: object, *, observed_monotonic_ns: int) -> bool:
        del observed_monotonic_ns
        return True

    @staticmethod
    def on_parser_counter(
        *,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        del parser_bytes, source_timestamp_ns, observed_monotonic_ns
        return True

    @staticmethod
    def on_decoded_frame(
        *,
        decoded_frames: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        del decoded_frames, source_ntp_ns, observed_monotonic_ns
        return True

    def on_native_probe_failure(
        self,
        code: object,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        self.failures.append((code, observed_monotonic_ns))
        return False

    def close(self) -> None:
        self.close_calls += 1


class LeaseFactory:
    def __init__(self, leases: list[RecordingLease]) -> None:
        self._leases = iter(leases)
        self.acquisitions: list[tuple[str, int]] = []

    def acquire(self, camera_id: str, source_id: int) -> RecordingLease:
        self.acquisitions.append((camera_id, source_id))
        return next(self._leases)


class SingleLiveRecordingLease(RecordingLease):
    def __init__(
        self,
        *,
        factory: SingleLiveLeaseFactory,
        camera_id: str,
        block_parser_entered: ThreadEvent | None = None,
        release_parser: ThreadEvent | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        super().__init__()
        self._factory = factory
        self._camera_id = camera_id
        self._block_parser_entered = block_parser_entered
        self._release_parser = release_parser
        self._close_error = close_error

    def observe_parser_buffer(
        self,
        byte_size: int,
        source_timestamp_ns: int,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        if self._block_parser_entered is not None:
            self._block_parser_entered.set()
            assert self._release_parser is not None
            if not self._release_parser.wait(timeout=2):
                raise RuntimeError("test parser release timed out")
        return super().observe_parser_buffer(
            byte_size,
            source_timestamp_ns,
            pts_ns,
            observed_monotonic_ns,
        )

    def close(self) -> None:
        self.close_calls += 1
        if self._factory.active.get(self._camera_id) is self:
            self._factory.active.pop(self._camera_id)
        if self._close_error is not None:
            raise self._close_error


class SingleLiveLeaseFactory:
    """Test double for the production one-callback/one-lease-per-camera limit."""

    def __init__(
        self,
        *,
        acquisition_errors: dict[int, BaseException] | None = None,
        block_first_parser: tuple[ThreadEvent, ThreadEvent] | None = None,
        close_errors: dict[int, BaseException] | None = None,
    ) -> None:
        self.acquisition_errors = dict(acquisition_errors or {})
        self.block_first_parser = block_first_parser
        self.close_errors = dict(close_errors or {})
        self.acquisitions: list[tuple[str, int]] = []
        self.active: dict[str, SingleLiveRecordingLease] = {}
        self.leases: list[SingleLiveRecordingLease] = []

    def acquire(self, camera_id: str, source_id: int) -> SingleLiveRecordingLease:
        self.acquisitions.append((camera_id, source_id))
        attempt = len(self.acquisitions)
        error = self.acquisition_errors.get(attempt)
        if error is not None:
            raise error
        if camera_id in self.active:
            raise RuntimeError(f"camera {camera_id} already has a live native lease")
        block_parser_entered = None
        release_parser = None
        if attempt == 1 and self.block_first_parser is not None:
            block_parser_entered, release_parser = self.block_first_parser
        lease = SingleLiveRecordingLease(
            factory=self,
            camera_id=camera_id,
            block_parser_entered=block_parser_entered,
            release_parser=release_parser,
            close_error=self.close_errors.get(attempt),
        )
        self.active[camera_id] = lease
        self.leases.append(lease)
        return lease


class Recovery:
    def __init__(self) -> None:
        self.failures: list[tuple[str, str, bool]] = []

    def handle_camera_failure(
        self,
        camera_id: str,
        reason: str,
        *,
        force: bool = False,
    ) -> None:
        self.failures.append((camera_id, reason, force))


class GstProbe:
    CLOCK_TIME_NONE = 2**64 - 1

    class PadProbeReturn:
        OK = "ok"

    class EventType:
        CAPS = "caps"


class Info:
    def __init__(self, *, buffer: object | None = None, event: object | None = None) -> None:
        self._buffer = buffer
        self._event = event

    def get_buffer(self) -> object | None:
        return self._buffer

    def get_event(self) -> object | None:
        return self._event


class Buffer:
    def __init__(self, *, size: object, dts: object, pts: object) -> None:
        self._size = size
        self.dts = dts
        self.pts = pts

    def get_size(self) -> object:
        return self._size


class Structure:
    def __init__(self, name: str, values: dict[str, object]) -> None:
        self._name = name
        self._values = values

    def get_name(self) -> str:
        return self._name

    def get_string(self, name: str) -> str | None:
        value = self._values.get(name)
        return value if type(value) is str else None

    def get_value(self, name: str) -> object:
        return self._values[name]


class Caps:
    def __init__(self, structure: Structure | None) -> None:
        self._structure = structure

    def get_size(self) -> int:
        return 0 if self._structure is None else 1

    def get_structure(self, _: int) -> Structure | None:
        return self._structure


class Event:
    type = GstProbe.EventType.CAPS

    def __init__(self, caps: Caps) -> None:
        self._caps = caps

    def parse_caps(self) -> Caps:
        return self._caps


class DynamicPad:
    def __init__(self, caps: Caps | None, *, caps_error: BaseException | None = None) -> None:
        self._caps = caps
        self._caps_error = caps_error
        self.link_calls = 0

    def get_current_caps(self) -> Caps | None:
        if self._caps_error is not None:
            raise self._caps_error
        return self._caps

    def query_caps(self, _: object) -> Caps | None:
        if self._caps_error is not None:
            raise self._caps_error
        return self._caps

    def link(self, _: object) -> int:
        self.link_calls += 1
        return 0


class Depay:
    class Sink:
        @staticmethod
        def is_linked() -> bool:
            return False

    def get_static_pad(self, _: str) -> Sink:
        return self.Sink()


def _owned_runtime(
    leases: tuple[RecordingLease, ...],
) -> tuple[DeepStreamDataPlane, CameraSupervisor, Recovery]:
    graph = DeepStreamGraphSpec.from_site(_site())
    factory = LeaseFactory(list(leases))
    times = iter(range(101, 1000))
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=factory,
        monotonic_ns=lambda: next(times),
    )
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in graph.sources),
        observation_queue_size=16,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: datetime(2026, 7, 30, 9, 0, tzinfo=UTC),
    )
    recovery = Recovery()
    runtime._graph = graph
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )
    runtime._recovery = recovery  # type: ignore[assignment]
    for source, lease in zip(graph.sources, leases):
        runtime._active_source_generations[source.camera_id] = deepstream_module._SourceGeneration(
            camera_id=source.camera_id,
            source_id=source.source_id,
            ordinal=1,
            source_bin=object(),
            writer=None,
            lease=lease,  # type: ignore[arg-type]
            lifecycle="live_unauthorized",
        )
    return runtime, supervisor, recovery


@pytest.mark.parametrize(
    ("caps", "expected_codec"),
    (
        (None, ""),
        (Caps(None), ""),
        (
            Caps(
                Structure(
                    "application/x-rtp",
                    {"media": "video", "encoding-name": "VP9"},
                )
            ),
            "",
        ),
        (
            Caps(
                Structure(
                    "application/x-rtp",
                    {"media": "video", "encoding-name": True},
                )
            ),
            "",
        ),
    ),
)
def test_invalid_video_rtp_caps_fail_only_the_owned_camera(
    caps: Caps | None,
    expected_codec: str,
) -> None:
    lease = RecordingLease()
    runtime, supervisor, recovery = _owned_runtime((lease,))
    pad = DynamicPad(caps)

    runtime._link_dynamic_rtsp_pad(
        object(),
        pad,
        Depay(),
        "h264",
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    assert lease.calls == [("rtp", expected_codec, 101)]
    assert recovery.failures == [("camera-01", "native_source_profile_failed", True)]
    assert supervisor.health_for("camera-02").state == "starting"
    assert pad.link_calls == 0


def test_malformed_rtsp_caps_enter_camera_local_recovery_without_escaping() -> None:
    lease = RecordingLease()
    runtime, _, recovery = _owned_runtime((lease,))
    pad = DynamicPad(None, caps_error=ValueError("malformed caps"))

    runtime._link_dynamic_rtsp_pad(
        object(),
        pad,
        Depay(),
        "h264",
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    assert lease.calls == [("rtp", "", 101)]
    assert recovery.failures == [("camera-01", "native_source_profile_failed", True)]
    assert pad.link_calls == 0


def test_overflowing_rtsp_caps_enter_camera_local_recovery_without_escaping() -> None:
    class OverflowCaps:
        @staticmethod
        def get_size() -> int:
            raise OverflowError("caps size overflow")

    lease = RecordingLease()
    runtime, _, recovery = _owned_runtime((lease,))
    pad = DynamicPad(OverflowCaps())  # type: ignore[arg-type]

    runtime._link_dynamic_rtsp_pad(
        object(),
        pad,
        Depay(),
        "h264",
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    assert lease.calls == [("rtp", "", 101)]
    assert recovery.failures == [("camera-01", "native_source_profile_failed", True)]
    assert pad.link_calls == 0


@pytest.mark.parametrize(
    "values",
    (
        {"width": True, "height": 720, "framerate": (25, 1)},
        {"width": 1280, "height": 0, "framerate": (25, 1)},
        {"width": 1280, "height": 720, "framerate": (25, 0)},
        {"width": 1280, "height": 720, "framerate": (True, 1)},
    ),
)
def test_invalid_decoder_caps_are_forwarded_as_authoritative_invalid_primitives(
    values: dict[str, object],
) -> None:
    lease = RecordingLease()
    runtime, _, recovery = _owned_runtime((lease,))

    result = runtime._decoder_caps_probe(
        object(),
        Info(event=Event(Caps(Structure("video/x-raw", values)))),
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    assert result == GstProbe.PadProbeReturn.OK
    assert lease.calls == [("decoder_caps", 0, 0, 0, 0, 101)]
    assert recovery.failures == [("camera-01", "native_source_profile_failed", True)]


def test_overflowing_decoder_caps_are_camera_local_and_never_escape_probe() -> None:
    class OverflowCaps:
        @staticmethod
        def get_size() -> int:
            raise OverflowError("caps size overflow")

    lease = RecordingLease()
    runtime, _, recovery = _owned_runtime((lease,))

    result = runtime._decoder_caps_probe(
        object(),
        Info(event=Event(OverflowCaps())),  # type: ignore[arg-type]
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    assert result == GstProbe.PadProbeReturn.OK
    assert lease.calls == [("decoder_caps", 0, 0, 0, 0, 101)]
    assert recovery.failures == [("camera-01", "native_source_profile_failed", True)]


def test_missing_decoder_caps_are_authoritative_not_plan_fallback() -> None:
    lease = RecordingLease()
    runtime, _, recovery = _owned_runtime((lease,))

    runtime._decoder_caps_probe(
        object(),
        Info(event=Event(Caps(None))),
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    assert lease.calls == [("decoder_caps", 0, 0, 0, 0, 101)]
    assert recovery.failures == [("camera-01", "native_source_profile_failed", True)]


@pytest.mark.parametrize(
    ("buffer", "expected"),
    (
        (None, (0, 0, 0)),
        (Buffer(size=True, dts=10, pts=20), (0, 10, 20)),
        (Buffer(size=100, dts=0, pts=20), (100, 0, 20)),
        (
            Buffer(size=100, dts=10, pts=GstProbe.CLOCK_TIME_NONE),
            (100, 10, GstProbe.CLOCK_TIME_NONE),
        ),
        (Buffer(size=100, dts=10, pts=False), (100, 10, 0)),
    ),
)
def test_invalid_parser_buffers_fail_closed_without_plan_substitution(
    buffer: object | None,
    expected: tuple[int, int, int],
) -> None:
    lease = RecordingLease()
    runtime, _, recovery = _owned_runtime((lease,))

    result = runtime._parser_buffer_probe(
        object(),
        Info(buffer=buffer),
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    assert result == GstProbe.PadProbeReturn.OK
    assert lease.calls == [("parser", *expected, 101)]
    assert recovery.failures == [("camera-01", "native_source_profile_failed", True)]


@pytest.mark.parametrize(
    ("buffer", "expected_pts"),
    (
        (None, 0),
        (Buffer(size=1, dts=1, pts=0), 0),
        (Buffer(size=1, dts=1, pts=True), 0),
        (
            Buffer(size=1, dts=1, pts=GstProbe.CLOCK_TIME_NONE),
            GstProbe.CLOCK_TIME_NONE,
        ),
    ),
)
def test_invalid_decoded_pts_fail_closed(
    buffer: object | None,
    expected_pts: int,
) -> None:
    lease = RecordingLease()
    runtime, _, recovery = _owned_runtime((lease,))

    result = runtime._decoder_buffer_probe(
        object(),
        Info(buffer=buffer),
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    assert result == GstProbe.PadProbeReturn.OK
    assert lease.calls == [("decoded", expected_pts, 101)]
    assert recovery.failures == [("camera-01", "native_source_profile_failed", True)]


@pytest.mark.parametrize(
    ("ntp", "pts"),
    (
        (0, 1),
        (True, 1),
        (2**64 - 1, 1),
        (1, 0),
        (1, False),
        (1, 2**64 - 1),
    ),
)
def test_invalid_nvds_time_precedes_heartbeat_evidence_and_publication(
    ntp: object,
    pts: object,
) -> None:
    first = RecordingLease()
    second = RecordingLease()
    runtime, supervisor, recovery = _owned_runtime((first, second))
    frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": ntp,
            "buf_pts": pts,
            "source_frame_width": 1920,
            "source_frame_height": 1080,
            "frame_num": 1,
            "obj_meta_list": None,
        },
    )()

    valid_pts = type(pts) is int and 0 < pts <= 2**63 - 1
    if valid_pts:
        runtime._record_metadata_owner(
            "camera-01",
            first,  # type: ignore[arg-type]
            pts,
        )
    runtime._publish_frame_metadata(frame, object())

    assert first.calls == (
        [
            (
                "ntp",
                pts,
                ntp if type(ntp) is int else 0,
                101,
            )
        ]
        if valid_pts
        else []
    )
    assert supervisor.health_for("camera-01").state == "starting"
    assert supervisor.health_for("camera-02").state == "starting"
    assert supervisor.drain_observations() == []
    assert recovery.failures == (
        [("camera-01", "camera_rtcp_time_unavailable", True)] if valid_pts else []
    )


def test_invalid_camera_time_isolated_while_another_camera_becomes_online() -> None:
    first = RecordingLease()
    second = RecordingLease()
    runtime, supervisor, recovery = _owned_runtime((first, second))
    source_time_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)

    def frame(source_id: int, ntp: int, pts: int) -> object:
        return type(
            "Frame",
            (),
            {
                "source_id": source_id,
                "ntp_timestamp": ntp,
                "buf_pts": pts,
                "source_frame_width": 1920,
                "source_frame_height": 1080,
                "frame_num": 1,
                "obj_meta_list": None,
            },
        )()

    runtime._record_metadata_owner(
        "camera-01",
        first,  # type: ignore[arg-type]
        1_000_000_000,
    )
    runtime._record_metadata_owner(
        "camera-02",
        second,  # type: ignore[arg-type]
        1_000_000_000,
    )
    runtime._publish_frame_metadata(frame(0, 0, 1_000_000_000), object())
    runtime._publish_frame_metadata(
        frame(1, source_time_ns, 1_000_000_000),
        object(),
    )

    assert supervisor.health_for("camera-01").state == "starting"
    assert supervisor.health_for("camera-02").state == "online"
    assert recovery.failures == [("camera-01", "camera_rtcp_time_unavailable", True)]


def test_valid_ntp_enqueue_without_correlated_callback_never_authorizes_camera() -> None:
    first = RecordingLease(correlated=False)
    second = RecordingLease()
    runtime, supervisor, recovery = _owned_runtime((first, second))
    source_time_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)
    frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": source_time_ns,
            "buf_pts": 1_000_000_000,
            "source_frame_width": 1920,
            "source_frame_height": 1080,
            "frame_num": 1,
            "obj_meta_list": None,
        },
    )()

    runtime._decoder_buffer_probe(
        object(),
        Info(buffer=Buffer(size=1, dts=1, pts=1_000_000_000)),
        "camera-01",
        first,  # type: ignore[arg-type]
        GstProbe,
    )
    runtime._publish_frame_metadata(frame, object())

    assert first.calls == [
        ("decoded", 1_000_000_000, 101),
        ("ntp", 1_000_000_000, source_time_ns, 102),
    ]
    assert first.correlation_queries == [(1_000_000_000, source_time_ns)]
    assert supervisor.health_for("camera-01").state == "starting"
    assert supervisor.drain_observations() == []
    assert recovery.failures == []
    with pytest.raises(SourceTimeMappingError, match="not anchored"):
        runtime._source_time_mapper.map(
            camera_id="camera-01",
            stream_epoch=str(supervisor.health_for("camera-01").stream_epoch),
            running_time_ns=1_000_000_000,
        )


def test_missing_generation_ownership_never_authorizes_valid_nvds_metadata() -> None:
    lease = RecordingLease()
    runtime, supervisor, recovery = _owned_runtime((lease,))
    runtime._active_source_generations.clear()
    runtime._metadata_source_generations.clear()
    source_time_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)
    frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": source_time_ns,
            "buf_pts": 1_000_000_000,
            "source_frame_width": 1920,
            "source_frame_height": 1080,
            "frame_num": 1,
            "obj_meta_list": None,
        },
    )()

    runtime._publish_frame_metadata(frame, object())

    assert supervisor.health_for("camera-01").state == "starting"
    assert supervisor.drain_observations() == []
    assert recovery.failures == []


def test_queued_old_nvds_metadata_is_inert_after_generation_cutover() -> None:
    old = RecordingLease()
    runtime, supervisor, recovery = _owned_runtime((old,))
    old_generation = runtime._active_source_generations["camera-01"]
    pts_ns = 1_000_000_000
    runtime._decoder_buffer_probe(
        object(),
        Info(buffer=Buffer(size=1, dts=1, pts=pts_ns)),
        "camera-01",
        old,  # type: ignore[arg-type]
        GstProbe,
    )

    replacement = RecordingLease()
    replacement_generation = deepstream_module._SourceGeneration(
        camera_id="camera-01",
        source_id=0,
        ordinal=2,
        source_bin=object(),
        writer=None,
        lease=replacement,  # type: ignore[arg-type]
    )
    runtime._active_source_generations["camera-01"] = replacement_generation
    runtime._metadata_source_generations["camera-01"] = replacement_generation
    source_time_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)
    frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": source_time_ns,
            "buf_pts": pts_ns,
            "source_frame_width": 1920,
            "source_frame_height": 1080,
            "frame_num": 1,
            "obj_meta_list": None,
        },
    )()

    runtime._publish_frame_metadata(frame, object())

    assert old_generation.lease is old
    assert old.calls == [("decoded", pts_ns, 101)]
    assert replacement.calls == []
    assert supervisor.health_for("camera-01").state == "starting"
    assert recovery.failures == []


def test_nvds_source_id_resolves_source_plan_identity_not_tuple_position() -> None:
    first = RecordingLease()
    second = RecordingLease()
    runtime, supervisor, recovery = _owned_runtime((first, second))
    assert runtime._graph is not None
    runtime._graph = runtime._graph.model_copy(
        update={"sources": tuple(reversed(runtime._graph.sources))}
    )
    pts_ns = 1_000_000_000
    runtime._decoder_buffer_probe(
        object(),
        Info(buffer=Buffer(size=1, dts=1, pts=pts_ns)),
        "camera-01",
        first,  # type: ignore[arg-type]
        GstProbe,
    )
    source_time_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)
    frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": source_time_ns,
            "buf_pts": pts_ns,
            "source_frame_width": 1920,
            "source_frame_height": 1080,
            "frame_num": 1,
            "obj_meta_list": None,
        },
    )()

    runtime._publish_frame_metadata(frame, object())

    assert supervisor.health_for("camera-01").state == "online"
    assert supervisor.health_for("camera-02").state == "starting"
    assert first.correlation_queries == [(pts_ns, source_time_ns)]
    assert second.calls == []
    assert recovery.failures == []


def test_frame_metadata_domain_accepts_fallback_while_deepstream_emits_camera_rtcp() -> None:
    metadata = FrameMetadataV1(
        camera_id="camera-01",
        source_time=datetime(2026, 7, 30, 9, 0, tzinfo=UTC),
        timestamp_quality="host_ntp_fallback",
        monotonic_seq=1,
        class_name="person",
        confidence=0.9,
        bbox=(0.1, 0.1, 0.2, 0.2),
    )

    assert metadata.timestamp_quality == "host_ntp_fallback"


class LinkPad:
    def __init__(
        self,
        *,
        peer: LinkPad | None = None,
        link_results: list[int] | None = None,
        unlink_results: list[bool] | None = None,
        event_results: list[bool] | None = None,
    ) -> None:
        self.peer = peer
        self.link_results = list(link_results or [0])
        self.unlink_results = list(unlink_results or [True])
        self.event_results = list(event_results or [True, True])
        self.link_calls = 0
        self.unlink_calls = 0
        self.probes_added: list[object] = []
        self.probes_removed: list[int] = []
        self.sent_events: list[object] = []

    def get_peer(self) -> LinkPad | None:
        return self.peer

    def link(self, other: LinkPad) -> int:
        self.link_calls += 1
        result = self.link_results.pop(0) if self.link_results else 0
        if result == 0:
            self.peer = other
        return result

    def unlink(self, other: LinkPad) -> bool:
        self.unlink_calls += 1
        result = self.unlink_results.pop(0) if self.unlink_results else True
        if result:
            self.peer = None
        return result

    def add_probe(self, probe_type: object, callback: object, *arguments: object) -> int:
        self.probes_added.append(probe_type)
        callback(self, object(), *arguments)  # type: ignore[operator]
        return len(self.probes_added)

    def remove_probe(self, probe_id: int) -> None:
        self.probes_removed.append(probe_id)

    def send_event(self, event: object) -> bool:
        self.sent_events.append(event)
        return self.event_results.pop(0) if self.event_results else True


class SourceBin:
    def __init__(
        self,
        name: str,
        pad: LinkPad,
        *,
        sync_results: list[bool] | None = None,
        writer: object | None = None,
    ) -> None:
        self.name = name
        self.pad = pad
        self.sync_results = list(sync_results or [True])
        self.writer = writer
        self.states: list[object] = []

    def get_static_pad(self, _: str) -> LinkPad:
        return self.pad

    def get_by_name(self, _: str) -> object | None:
        return self.writer

    def sync_state_with_parent(self) -> bool:
        return self.sync_results.pop(0) if self.sync_results else True

    def set_state(self, state: object) -> None:
        self.states.append(state)


class Mux:
    def __init__(self, pad: LinkPad) -> None:
        self.pad = pad

    def get_static_pad(self, name: str) -> LinkPad | None:
        return self.pad if name == "sink_0" else None


class Pipeline:
    def __init__(
        self,
        old_bin: SourceBin,
        mux: Mux,
        *,
        add_results: list[bool] | None = None,
        remove_results: list[bool] | None = None,
    ) -> None:
        self.old_bin = old_bin
        self.mux = mux
        self.add_results = list(add_results or [True])
        self.remove_results = list(remove_results or [True])
        self.added: list[SourceBin] = []
        self.removed: list[SourceBin] = []
        self.states: list[object] = []

    def get_by_name(self, name: str) -> object | None:
        if name == "streammux":
            return self.mux
        if name == self.old_bin.name and self.old_bin not in self.removed:
            return self.old_bin
        return next((item for item in self.added if item.name == name), None)

    def add(self, source_bin: SourceBin) -> bool:
        result = self.add_results.pop(0) if self.add_results else True
        if result:
            self.added.append(source_bin)
        return result

    def remove(self, source_bin: SourceBin) -> bool:
        result = self.remove_results.pop(0) if self.remove_results else True
        if result:
            self.removed.append(source_bin)
        return result

    def set_state(self, state: object) -> None:
        self.states.append(state)


class GstRebuild:
    class State:
        NULL = "null"

    class PadLinkReturn:
        OK = 0

    class PadProbeType:
        IDLE = 1
        BLOCK_DOWNSTREAM = 2

    class PadProbeReturn:
        OK = "ok"

    class Event:
        @staticmethod
        def new_flush_start() -> str:
            return "flush-start"

        @staticmethod
        def new_flush_stop(reset_time: bool) -> tuple[str, bool]:
            return "flush-stop", reset_time


def _rebuild_runtime(
    *,
    old_pad: LinkPad,
    replacement: SourceBin,
    add_results: list[bool] | None = None,
    remove_results: list[bool] | None = None,
    old_sync_results: list[bool] | None = None,
) -> tuple[
    DeepStreamDataPlane,
    RecordingLease,
    RecordingLease,
    Pipeline,
    Recovery,
]:
    mux_pad = old_pad.peer or LinkPad()
    old_bin = SourceBin(
        "source-0-generation-1",
        old_pad,
        sync_results=old_sync_results,
    )
    old = RecordingLease()
    new = RecordingLease()
    restored_old = RecordingLease()
    factory = LeaseFactory([old, new, restored_old])
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=factory,
    )
    runtime._graph = DeepStreamGraphSpec.from_site(_site())
    runtime._bindings = deepstream_module._NvidiaBindings(
        gst=GstRebuild,
        glib=object(),
        pyds=object(),
    )
    pipeline = Pipeline(
        old_bin,
        Mux(mux_pad),
        add_results=add_results,
        remove_results=remove_results,
    )
    runtime._pipeline = pipeline
    runtime._locations = {"camera-01": "rtsp://redacted"}
    old_facade = deepstream_module._TransactionalSourceProbeLease(
        factory=factory,
        camera_id="camera-01",
        source_id=0,
    )
    old_facade.activate()
    runtime._active_source_generations["camera-01"] = deepstream_module._SourceGeneration(
        camera_id="camera-01",
        source_id=0,
        ordinal=1,
        source_bin=old_bin,
        writer=None,
        lease=old_facade,
        lifecycle="authorized",
    )
    recovery = Recovery()
    runtime._recovery = recovery  # type: ignore[assignment]
    runtime._build_source_bin = lambda *_: replacement  # type: ignore[method-assign]
    return runtime, old, new, pipeline, recovery


def _single_live_rebuild_runtime(
    *,
    factory: SingleLiveLeaseFactory,
    replacement_sync_results: list[bool] | None = None,
) -> tuple[
    DeepStreamDataPlane,
    deepstream_module._SourceGeneration,
    SourceBin,
    SourceBin,
    Pipeline,
    Recovery,
]:
    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad)
    old_bin = SourceBin(
        "source-0-generation-1",
        old_pad,
        sync_results=[True],
    )
    replacement_bin = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
        sync_results=replacement_sync_results,
    )
    bins = iter((old_bin, replacement_bin))
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=factory,
    )
    runtime._graph = DeepStreamGraphSpec.from_site(_site())
    runtime._bindings = deepstream_module._NvidiaBindings(
        gst=GstRebuild,
        glib=object(),
        pyds=object(),
    )
    runtime._locations = {"camera-01": "rtsp://redacted"}
    runtime._build_source_bin = lambda *_: next(bins)  # type: ignore[method-assign]
    source = runtime._graph.sources[0]
    old_generation = runtime._build_source_generation(
        GstRebuild,
        source,
        runtime._locations[source.camera_id],
    )
    old_generation.lifecycle = "authorized"
    old_generation._added_to_pipeline = True
    runtime._active_source_generations[source.camera_id] = old_generation
    runtime._metadata_source_generations[source.camera_id] = old_generation
    pipeline = Pipeline(old_bin, Mux(mux_pad))
    runtime._pipeline = pipeline
    recovery = Recovery()
    runtime._recovery = recovery  # type: ignore[assignment]
    return (
        runtime,
        old_generation,
        old_bin,
        replacement_bin,
        pipeline,
        recovery,
    )


def test_rebuild_stages_inert_facade_before_single_live_lease_cutover() -> None:
    factory = SingleLiveLeaseFactory()
    runtime, old_generation, _, _, pipeline, recovery = _single_live_rebuild_runtime(
        factory=factory,
    )
    staged_primitive_results: list[bool] = []
    original_add = pipeline.add

    def add_with_stale_staged_primitive(source_bin: SourceBin) -> bool:
        staged = runtime._staged_source_generations["camera-01"]
        staged_primitive_results.append(staged.lease.observe_parser_buffer(100, 10, 20, 30))
        assert factory.acquisitions == [("camera-01", 0)]
        return original_add(source_bin)

    pipeline.add = add_with_stale_staged_primitive  # type: ignore[method-assign]

    runtime._rebuild_source("camera-01")

    replacement = runtime._active_source_generations["camera-01"]
    assert staged_primitive_results == [False]
    assert factory.acquisitions == [("camera-01", 0), ("camera-01", 0)]
    assert [lease.close_calls for lease in factory.leases] == [1, 0]
    assert old_generation.lifecycle == "retired"
    assert replacement.lifecycle == "live_unauthorized"
    assert recovery.failures == []


def test_rebuild_cutover_changes_only_the_selected_camera_generation() -> None:
    factory = SingleLiveLeaseFactory()
    runtime, _, _, _, _, _ = _single_live_rebuild_runtime(factory=factory)
    untouched: dict[str, deepstream_module._SourceGeneration] = {}
    for source in runtime._graph.sources[1:]:
        lease = RecordingLease()
        generation = deepstream_module._SourceGeneration(
            camera_id=source.camera_id,
            source_id=source.source_id,
            ordinal=1,
            source_bin=object(),
            writer=None,
            lease=lease,  # type: ignore[arg-type]
            lifecycle="authorized",
        )
        runtime._active_source_generations[source.camera_id] = generation
        runtime._metadata_source_generations[source.camera_id] = generation
        untouched[source.camera_id] = generation

    runtime._rebuild_source("camera-01")

    assert all(
        runtime._active_source_generations[camera_id] is generation
        and runtime._metadata_source_generations[camera_id] is generation
        and generation.lifecycle == "authorized"
        and generation.lease.close_calls == 0
        for camera_id, generation in untouched.items()
    )
    assert factory.acquisitions == [("camera-01", 0), ("camera-01", 0)]


def test_sync_failure_reacquires_fresh_old_inner_before_restore() -> None:
    factory = SingleLiveLeaseFactory()
    runtime, old_generation, _, _, _, recovery = _single_live_rebuild_runtime(
        factory=factory,
        replacement_sync_results=[False],
    )
    source_ntp_ns = 1_750_000_000_000_000_000
    assert old_generation.lease.observe_parser_buffer(100, 10, 20, 30) is True
    assert old_generation.lease.observe_decoded_buffer(20, 31) is True
    assert old_generation.lease.observe_nvds_ntp(20, source_ntp_ns, 32) is True
    assert old_generation.lease.correlated_ntp(20, source_ntp_ns) is not None

    with pytest.raises(RuntimeError, match="sync rebuilt source bin"):
        runtime._rebuild_source("camera-01")

    assert runtime._active_source_generations["camera-01"] is old_generation
    assert old_generation.lifecycle == "live_unauthorized"
    assert factory.acquisitions == [
        ("camera-01", 0),
        ("camera-01", 0),
        ("camera-01", 0),
    ]
    assert [lease.close_calls for lease in factory.leases] == [1, 1, 0]
    assert old_generation.lease.correlated_ntp(20, source_ntp_ns) is None
    assert old_generation.lease.observe_parser_buffer(101, 11, 20, 40) is True
    assert old_generation.lease.observe_decoded_buffer(20, 41) is True
    assert old_generation.lease.observe_nvds_ntp(20, source_ntp_ns, 42) is True
    assert old_generation.lease.correlated_ntp(20, source_ntp_ns) is not None
    assert factory.leases[0].calls == [
        ("parser", 100, 10, 20, 30),
        ("decoded", 20, 31),
        ("ntp", 20, source_ntp_ns, 32),
    ]
    assert factory.leases[1].calls == []
    assert factory.leases[2].calls == [
        ("parser", 101, 11, 20, 40),
        ("decoded", 20, 41),
        ("ntp", 20, source_ntp_ns, 42),
    ]
    assert recovery.failures == []


def test_failed_old_reacquisition_keeps_camera_inert_and_other_nineteen_unchanged() -> None:
    factory = SingleLiveLeaseFactory(
        acquisition_errors={3: SystemExit("old lease restore failed")},
    )
    runtime, old_generation, _, _, pipeline, recovery = _single_live_rebuild_runtime(
        factory=factory,
        replacement_sync_results=[False],
    )
    staged_generations: list[deepstream_module._SourceGeneration] = []
    original_add = pipeline.add

    def add_and_capture_staged(source_bin: SourceBin) -> bool:
        staged_generations.append(runtime._staged_source_generations["camera-01"])
        return original_add(source_bin)

    pipeline.add = add_and_capture_staged  # type: ignore[method-assign]
    untouched: dict[str, deepstream_module._SourceGeneration] = {}
    for source in runtime._graph.sources[1:]:
        lease = RecordingLease()
        generation = deepstream_module._SourceGeneration(
            camera_id=source.camera_id,
            source_id=source.source_id,
            ordinal=1,
            source_bin=object(),
            writer=None,
            lease=lease,  # type: ignore[arg-type]
            lifecycle="authorized",
        )
        runtime._active_source_generations[source.camera_id] = generation
        runtime._metadata_source_generations[source.camera_id] = generation
        untouched[source.camera_id] = generation

    with pytest.raises(RuntimeError, match="restore old source generation"):
        runtime._rebuild_source("camera-01")

    staged = staged_generations[0]
    assert runtime._active_source_generations["camera-01"] is old_generation
    assert old_generation.lifecycle == "quiescing"
    assert old_generation.lease.observe_parser_buffer(100, 10, 20, 30) is False
    assert staged.lease.observe_parser_buffer(100, 10, 20, 30) is False
    assert [lease.close_calls for lease in factory.leases] == [1, 1]
    assert recovery.failures == [("camera-01", "rtsp_rebuild_rollback_failed", True)]
    assert all(
        runtime._active_source_generations[camera_id] is generation
        and runtime._metadata_source_generations[camera_id] is generation
        and generation.lifecycle == "authorized"
        and generation.lease.close_calls == 0
        for camera_id, generation in untouched.items()
    )


def test_cutover_waits_for_inflight_facade_callback_before_acquiring_replacement() -> None:
    parser_entered = ThreadEvent()
    release_parser = ThreadEvent()
    factory = SingleLiveLeaseFactory(
        block_first_parser=(parser_entered, release_parser),
    )
    runtime, old_generation, _, _, _, recovery = _single_live_rebuild_runtime(
        factory=factory,
    )
    callback_results: list[bool] = []
    rebuild_errors: list[BaseException] = []

    callback_thread = Thread(
        target=lambda: callback_results.append(
            old_generation.lease.observe_parser_buffer(100, 10, 20, 30)
        )
    )
    callback_thread.start()
    assert parser_entered.wait(timeout=2)

    def rebuild() -> None:
        try:
            runtime._rebuild_source("camera-01")
        except BaseException as exc:
            rebuild_errors.append(exc)

    rebuild_thread = Thread(target=rebuild)
    rebuild_thread.start()
    rebuild_thread.join(timeout=0.05)

    cutover_waited_for_callback = rebuild_thread.is_alive()
    acquisitions_before_release = list(factory.acquisitions)
    release_parser.set()
    callback_thread.join(timeout=2)
    rebuild_thread.join(timeout=2)

    assert cutover_waited_for_callback
    assert acquisitions_before_release == [("camera-01", 0)]
    assert not callback_thread.is_alive()
    assert not rebuild_thread.is_alive()
    assert callback_results == [True]
    assert rebuild_errors == []
    assert factory.acquisitions == [("camera-01", 0), ("camera-01", 0)]
    assert recovery.failures == []


def test_baseexception_during_replacement_activation_restores_fresh_old_inner() -> None:
    factory = SingleLiveLeaseFactory(
        acquisition_errors={2: KeyboardInterrupt()},
    )
    runtime, old_generation, _, _, _, recovery = _single_live_rebuild_runtime(
        factory=factory,
    )

    with pytest.raises(KeyboardInterrupt):
        runtime._rebuild_source("camera-01")

    assert runtime._active_source_generations["camera-01"] is old_generation
    assert old_generation.lifecycle == "live_unauthorized"
    assert factory.acquisitions == [
        ("camera-01", 0),
        ("camera-01", 0),
        ("camera-01", 0),
    ]
    assert [lease.close_calls for lease in factory.leases] == [1, 0]
    assert old_generation.lease.observe_decoded_buffer(20, 30) is True
    assert factory.leases[-1].calls == [("decoded", 20, 30)]
    assert recovery.failures == []


def test_baseexception_from_old_inner_close_still_reacquires_fresh_old_inner() -> None:
    factory = SingleLiveLeaseFactory(
        close_errors={1: KeyboardInterrupt()},
    )
    runtime, old_generation, _, _, _, recovery = _single_live_rebuild_runtime(
        factory=factory,
    )

    with pytest.raises(KeyboardInterrupt):
        runtime._rebuild_source("camera-01")

    assert runtime._active_source_generations["camera-01"] is old_generation
    assert old_generation.lifecycle == "live_unauthorized"
    assert old_generation.lease.active
    assert factory.acquisitions == [
        ("camera-01", 0),
        ("camera-01", 0),
    ]
    assert [lease.close_calls for lease in factory.leases] == [1, 0]
    assert old_generation.lease.observe_decoded_buffer(20, 30) is True
    assert factory.leases[-1].calls == [("decoded", 20, 30)]
    assert recovery.failures == []


def test_stop_after_failed_restore_does_not_close_acquired_inners_twice() -> None:
    factory = SingleLiveLeaseFactory(
        acquisition_errors={3: RuntimeError("old lease restore failed")},
    )
    runtime, _, _, _, _, _ = _single_live_rebuild_runtime(
        factory=factory,
        replacement_sync_results=[False],
    )

    with pytest.raises(RuntimeError, match="restore old source generation"):
        runtime._rebuild_source("camera-01")
    runtime.stop()
    runtime.stop()

    assert [lease.close_calls for lease in factory.leases] == [1, 1]


@pytest.mark.parametrize("failure_stage", ("add", "unlink", "sync"))
def test_rebuild_failures_restore_old_generation_and_close_only_replacement(
    failure_stage: str,
) -> None:
    mux_pad = LinkPad()
    old_pad = LinkPad(
        peer=mux_pad,
        unlink_results=[failure_stage != "unlink"],
    )
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
        sync_results=[failure_stage != "sync"],
    )
    runtime, old, new, _, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
        add_results=[failure_stage != "add"],
    )
    old_generation = runtime._active_source_generations["camera-01"]

    with pytest.raises(RuntimeError):
        runtime._rebuild_source("camera-01")

    assert runtime._active_source_generations["camera-01"] is old_generation
    assert old_generation.lease.active
    assert old.close_calls == (1 if failure_stage == "sync" else 0)
    assert new.close_calls == (1 if failure_stage == "sync" else 0)
    assert old_pad.get_peer() is mux_pad
    assert recovery.failures == []


def test_rebuild_uses_acknowledged_camera_local_block_and_flush_cutover() -> None:
    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad)
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
    )
    runtime, old, new, _, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
    )

    runtime._rebuild_source("camera-01")

    assert old_pad.probes_added == [
        GstRebuild.PadProbeType.IDLE | GstRebuild.PadProbeType.BLOCK_DOWNSTREAM
    ]
    assert old_pad.probes_removed == [1]
    assert mux_pad.sent_events == [
        "flush-start",
        ("flush-stop", True),
    ]
    assert old.close_calls == 1
    assert new.close_calls == 0
    assert recovery.failures == []


def test_unacknowledged_cutover_flush_keeps_old_generation_active() -> None:
    mux_pad = LinkPad(event_results=[False])
    old_pad = LinkPad(peer=mux_pad)
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
    )
    runtime, old, new, _, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
    )
    old_generation = runtime._active_source_generations["camera-01"]

    with pytest.raises(RuntimeError, match="flush"):
        runtime._rebuild_source("camera-01")

    assert runtime._active_source_generations["camera-01"] is old_generation
    assert old_generation.lease.active
    assert old_pad.get_peer() is mux_pad
    assert old.close_calls == 0
    assert new.close_calls == 0
    assert recovery.failures == []


def test_failed_flush_stop_retains_quiesced_block_until_retry_completes_cutover() -> None:
    mux_pad = LinkPad(event_results=[True, False, True, True, True])
    old_pad = LinkPad(peer=mux_pad)
    replacements = (
        SourceBin("source-0-generation-2", LinkPad(link_results=[0])),
        SourceBin("source-0-generation-3", LinkPad(link_results=[0])),
    )
    runtime, old, _, pipeline, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacements[0],
    )
    first = RecordingLease()
    second = RecordingLease()
    runtime._native_probe_lease_factory = LeaseFactory([first, second])
    replacement_bins = iter(replacements)
    runtime._build_source_bin = lambda *_: next(replacement_bins)  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="flush stop"):
        runtime._rebuild_source("camera-01")

    generation = runtime._active_source_generations["camera-01"]
    assert generation.lease.active
    assert generation.lifecycle == "quiescing"
    assert old_pad.probes_added == [
        GstRebuild.PadProbeType.IDLE | GstRebuild.PadProbeType.BLOCK_DOWNSTREAM
    ]
    assert old_pad.probes_removed == []
    assert mux_pad.sent_events == ["flush-start", ("flush-stop", True)]
    runtime._record_metadata_owner("camera-01", old, 1_000_000_000)
    assert runtime._take_metadata_owner(0, 1_000_000_000) is None
    assert first.close_calls == 0

    runtime._rebuild_source("camera-01")

    assert runtime._active_source_generations["camera-01"].lease.active
    assert old_pad.probes_added == [
        GstRebuild.PadProbeType.IDLE | GstRebuild.PadProbeType.BLOCK_DOWNSTREAM,
        GstRebuild.PadProbeType.IDLE | GstRebuild.PadProbeType.BLOCK_DOWNSTREAM,
    ]
    assert old_pad.probes_removed == [1, 2]
    assert mux_pad.sent_events == [
        "flush-start",
        ("flush-stop", True),
        ("flush-stop", True),
        "flush-start",
        ("flush-stop", True),
    ]
    assert old.close_calls == 1
    assert first.close_calls == 0
    assert second.close_calls == 0
    assert replacements[0] in pipeline.removed
    assert recovery.failures == []


def test_stop_bounds_failed_pending_flush_stop_and_releases_block_ownership() -> None:
    mux_pad = LinkPad(event_results=[True, False, False])
    old_pad = LinkPad(peer=mux_pad)
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
    )
    runtime, old, new, _, _ = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
    )

    with pytest.raises(RuntimeError, match="flush stop"):
        runtime._rebuild_source("camera-01")
    with pytest.raises(RuntimeError, match="flush stop"):
        runtime.stop()

    assert mux_pad.sent_events == [
        "flush-start",
        ("flush-stop", True),
        ("flush-stop", True),
    ]
    assert old_pad.probes_removed == [1]
    assert old.close_calls == 1
    assert new.close_calls == 0
    assert runtime._active_source_generations == {}
    assert runtime._staged_source_generations == {}


@pytest.mark.parametrize("failure_stage", ("build", "add", "flush"))
def test_early_rebuild_failure_revokes_old_epoch_until_fresh_correlation(
    failure_stage: str,
) -> None:
    class Writer:
        @staticmethod
        def get_name() -> str:
            return "evidence-writer-0"

    class EvidenceFactory:
        def __init__(self) -> None:
            self.bind_epochs: list[str] = []
            self.handle_calls: list[object] = []
            self.reset_calls: list[str] = []

        def bind_writer(self, _: object, *, stream_epoch: str) -> None:
            self.bind_epochs.append(stream_epoch)

        def handle_writer_message(
            self,
            *,
            writer: object,
            structure: object,
            source_time_mapper: object,
        ) -> None:
            del structure, source_time_mapper
            self.handle_calls.append(writer)

        def reset_camera(self, camera_id: str) -> None:
            self.reset_calls.append(camera_id)

    class FailingFactory:
        @staticmethod
        def acquire(_: str, __: int) -> RecordingLease:
            raise RuntimeError("replacement lease unavailable")

    mux_pad = LinkPad(event_results=[failure_stage != "flush"])
    old_pad = LinkPad(peer=mux_pad)
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
    )
    runtime, old, _, _, _ = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
        add_results=[failure_stage != "add"],
    )
    if failure_stage == "build":
        runtime._native_probe_lease_factory = FailingFactory()

    writer = Writer()
    old_generation = runtime._active_source_generations["camera-01"]
    old_generation.writer = writer
    old_generation._writer_bound = True
    old_generation.authorized_running_time_ns = 500_000_000
    old_generation.evidence_open_location = "/evidence/old-epoch.mp4"
    runtime._metadata_source_generations["camera-01"] = old_generation
    evidence = EvidenceFactory()
    runtime._evidence_sink_factory = evidence  # type: ignore[assignment]
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in runtime._graph.sources),
        observation_queue_size=4,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: datetime(2026, 7, 30, 9, 0, tzinfo=UTC),
        runtime_session_seed="rebuild-epoch-test",
    )
    old_epoch = str(supervisor.health_for("camera-01").stream_epoch)
    supervisor.disconnect("camera-01")
    supervisor.recover("camera-01")
    current_epoch = str(supervisor.health_for("camera-01").stream_epoch)
    assert current_epoch != old_epoch
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )

    with pytest.raises(RuntimeError):
        runtime._rebuild_source("camera-01")

    assert old_generation.lifecycle == "live_unauthorized"
    assert old_generation._writer_bound is False
    assert old_generation.authorized_running_time_ns is None
    assert old_generation.evidence_open_location is None

    stale_structure = type(
        "Structure",
        (),
        {
            "get_name": lambda _: "splitmuxsink-fragment-opened",
            "get_value": lambda _, name: {
                "location": "/evidence/stale.mp4",
                "running-time": 1_000_000_000,
            }[name],
        },
    )()
    stale_message = type(
        "Message",
        (),
        {"src": writer, "type": "element", "get_structure": lambda _: stale_structure},
    )()
    runtime._on_bus_message(None, stale_message)
    assert evidence.handle_calls == []

    pts_ns = 1_000_000_000
    source_ntp_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)
    runtime._record_metadata_owner(
        "camera-01",
        old_generation.lease,
        pts_ns,
    )
    runtime._publish_frame_metadata(
        type(
            "Frame",
            (),
            {
                "source_id": 0,
                "ntp_timestamp": source_ntp_ns,
                "buf_pts": pts_ns,
                "source_frame_width": 1920,
                "source_frame_height": 1080,
                "frame_num": 1,
                "obj_meta_list": None,
            },
        )(),
        object(),
    )

    assert old_generation.lifecycle == "authorized"
    assert old_generation._writer_bound is True
    assert old_generation.authorized_running_time_ns == pts_ns
    assert evidence.bind_epochs == [current_epoch]


def test_quiescing_rebuild_fences_inflight_correlation_before_mapper_and_evidence() -> None:
    correlation_entered = ThreadEvent()
    release_correlation = ThreadEvent()
    replacement_build_entered = ThreadEvent()
    release_replacement_build = ThreadEvent()

    class BlockingLease(RecordingLease):
        def correlated_ntp(self, pts_ns: int, source_ntp_ns: int) -> object | None:
            correlation_entered.set()
            if not release_correlation.wait(timeout=2):
                raise RuntimeError("test correlation release timed out")
            return super().correlated_ntp(pts_ns, source_ntp_ns)

    class Writer:
        @staticmethod
        def get_name() -> str:
            return "evidence-writer-0"

    class EvidenceFactory:
        def __init__(self) -> None:
            self.bind_calls: list[object] = []
            self.handle_calls: list[object] = []

        def bind_writer(self, writer: object, *, stream_epoch: str) -> None:
            assert stream_epoch
            self.bind_calls.append(writer)

        def handle_writer_message(
            self,
            *,
            writer: object,
            structure: object,
            source_time_mapper: object,
        ) -> None:
            del structure, source_time_mapper
            self.handle_calls.append(writer)

    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad)
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
    )
    runtime, _, _, _, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
    )
    lease = BlockingLease()
    generation = runtime._active_source_generations["camera-01"]
    old_factory = LeaseFactory([lease])
    old_facade = deepstream_module._TransactionalSourceProbeLease(
        factory=old_factory,
        camera_id="camera-01",
        source_id=0,
    )
    old_facade.activate()
    generation.lease = old_facade
    generation.lifecycle = "live_unauthorized"
    runtime._metadata_source_generations["camera-01"] = generation

    def blocking_replacement_build(*_: object) -> SourceBin:
        replacement_build_entered.set()
        if not release_replacement_build.wait(timeout=2):
            raise RuntimeError("test replacement build release timed out")
        raise RuntimeError("replacement source build unavailable")

    runtime._build_source_bin = blocking_replacement_build  # type: ignore[method-assign]
    writer = Writer()
    generation.writer = writer
    evidence = EvidenceFactory()
    runtime._evidence_sink_factory = evidence  # type: ignore[assignment]
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in runtime._graph.sources),
        observation_queue_size=4,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: datetime(2026, 7, 30, 9, 0, tzinfo=UTC),
    )
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )
    pts_ns = 1_000_000_000
    source_ntp_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)
    runtime._record_metadata_owner(
        "camera-01",
        old_facade,
        pts_ns,
    )
    frame = type(
        "Frame",
        (),
        {
            "source_id": 0,
            "ntp_timestamp": source_ntp_ns,
            "buf_pts": pts_ns,
            "source_frame_width": 1920,
            "source_frame_height": 1080,
            "frame_num": 1,
            "obj_meta_list": None,
        },
    )()
    publish_errors: list[BaseException] = []
    rebuild_errors: list[BaseException] = []

    def publish() -> None:
        try:
            runtime._publish_frame_metadata(frame, object())
        except BaseException as exc:
            publish_errors.append(exc)

    def rebuild() -> None:
        try:
            runtime._rebuild_source("camera-01")
        except BaseException as exc:
            rebuild_errors.append(exc)

    publish_thread = Thread(target=publish)
    publish_thread.start()
    assert correlation_entered.wait(timeout=2)
    rebuild_thread = Thread(target=rebuild)
    rebuild_thread.start()
    assert replacement_build_entered.wait(timeout=2)
    release_correlation.set()
    publish_thread.join(timeout=2)
    assert not publish_thread.is_alive()
    assert publish_errors == []

    structure = type(
        "Structure",
        (),
        {
            "get_name": lambda _: "splitmuxsink-fragment-opened",
            "get_value": lambda _, name: {
                "location": "/evidence/inflight.mp4",
                "running-time": pts_ns,
            }[name],
        },
    )()
    message = type(
        "Message",
        (),
        {"src": writer, "type": "element", "get_structure": lambda _: structure},
    )()
    runtime._on_bus_message(None, message)
    camera_id = "camera-01"
    primitive_call_count = len(lease.calls)
    lease.reject = True
    runtime._parser_buffer_probe(
        object(),
        Info(buffer=Buffer(size=100, dts=10, pts=20)),
        camera_id,
        lease,  # type: ignore[arg-type]
        GstProbe,
    )

    current_epoch = str(supervisor.health_for(camera_id).stream_epoch)
    assert supervisor.health_for(camera_id).state == "starting"
    assert evidence.bind_calls == []
    assert evidence.handle_calls == []
    assert len(lease.calls) == primitive_call_count
    assert recovery.failures == []
    with pytest.raises(SourceTimeMappingError, match="not anchored"):
        runtime._source_time_mapper.map(
            camera_id=camera_id,
            stream_epoch=current_epoch,
            running_time_ns=pts_ns,
        )

    release_replacement_build.set()
    rebuild_thread.join(timeout=2)
    assert not rebuild_thread.is_alive()
    assert len(rebuild_errors) == 1
    assert isinstance(rebuild_errors[0], RuntimeError)
    assert generation.lifecycle == "live_unauthorized"
    assert generation._writer_bound is False


def test_real_bridge_replay_before_epoch_boundary_cannot_reauthorize_after_rollback() -> None:
    class FailingFactory:
        @staticmethod
        def acquire(_: str, __: int) -> RecordingLease:
            raise RuntimeError("replacement lease unavailable")

    callbacks = AllowingNativeCallbacks()
    bridge = NativeSourceProbeBridge(capacity=8)
    lease = bridge.bind(callbacks)

    class OldBridgeFactory:
        def __init__(self) -> None:
            self.acquisitions = 0

        def acquire(self, _: str, __: int) -> object:
            self.acquisitions += 1
            return lease if self.acquisitions == 1 else bridge.bind(callbacks)

    assert lease.observe_rtp_caps("h264", 1)
    assert lease.observe_decoder_caps(1920, 1080, 25, 1, 1)
    wall_time = datetime(2026, 7, 30, 9, 0, tzinfo=UTC)
    source_ntp_ns = int(wall_time.timestamp() * 1_000_000_000)
    source_timestamp_ns = 900_000_000_000
    assert lease.observe_parser_buffer(
        20_000,
        source_timestamp_ns,
        100,
        2,
    )
    assert lease.observe_decoded_buffer(100, 3)
    assert lease.observe_nvds_ntp(
        100,
        source_ntp_ns - 40_000_000,
        4,
    )
    assert lease.observe_parser_buffer(
        20_000,
        source_timestamp_ns + 40_000_000,
        200,
        42_000_000,
    )
    assert lease.observe_decoded_buffer(200, 43_000_000)

    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad)
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
    )
    runtime, _, _, _, _ = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
    )
    monotonic_values = iter(
        (
            41_000_000,
            50_000_000,
            60_000_000,
            41_000_000,
            63_000_000,
            66_000_000,
        )
    )
    runtime._monotonic_ns = lambda: next(monotonic_values)
    generation = runtime._active_source_generations["camera-01"]
    old_factory = OldBridgeFactory()
    old_facade = deepstream_module._TransactionalSourceProbeLease(
        factory=old_factory,  # type: ignore[arg-type]
        camera_id="camera-01",
        source_id=0,
    )
    old_facade.activate()
    generation.lease = old_facade
    generation.lifecycle = "live_unauthorized"
    runtime._metadata_source_generations["camera-01"] = generation
    runtime._native_probe_lease_factory = FailingFactory()
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in runtime._graph.sources),
        observation_queue_size=4,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: wall_time,
    )
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )

    def frame(
        *,
        pts_ns: int,
        ntp_ns: int,
        frame_num: int,
    ) -> object:
        return type(
            "Frame",
            (),
            {
                "source_id": 0,
                "ntp_timestamp": ntp_ns,
                "buf_pts": pts_ns,
                "source_frame_width": 1920,
                "source_frame_height": 1080,
                "frame_num": frame_num,
                "obj_meta_list": None,
            },
        )()

    runtime._record_metadata_owner(
        "camera-01",
        old_facade,
        200,
    )
    runtime._publish_frame_metadata(
        frame(pts_ns=200, ntp_ns=source_ntp_ns, frame_num=1),
        object(),
    )
    assert generation.lifecycle == "authorized"
    supervisor.disconnect("camera-01")
    runtime._recover_camera_epoch("camera-01")

    with pytest.raises(RuntimeError, match="replacement lease unavailable"):
        runtime._rebuild_source("camera-01")

    current_epoch = str(supervisor.health_for("camera-01").stream_epoch)
    assert generation.lifecycle == "live_unauthorized"
    assert generation.correlation_not_before_monotonic_ns == 60_000_000
    assert lease.observe_decoded_buffer(200, 43_000_000) is False
    runtime._record_metadata_owner(
        "camera-01",
        old_facade,
        200,
    )
    runtime._publish_frame_metadata(
        frame(pts_ns=200, ntp_ns=source_ntp_ns, frame_num=2),
        object(),
    )

    assert supervisor.health_for("camera-01").state == "reconnecting"
    assert generation.lifecycle == "live_unauthorized"
    with pytest.raises(SourceTimeMappingError, match="not anchored"):
        runtime._source_time_mapper.map(
            camera_id="camera-01",
            stream_epoch=current_epoch,
            running_time_ns=200,
        )

    assert old_facade.observe_rtp_caps("h264", 60_000_001)
    assert old_facade.observe_decoder_caps(1920, 1080, 25, 1, 60_000_002)
    assert old_facade.observe_parser_buffer(
        20_000,
        source_timestamp_ns + 60_000_000,
        250,
        61_000_000,
    )
    assert old_facade.observe_decoded_buffer(250, 62_000_000)
    runtime._record_metadata_owner(
        "camera-01",
        old_facade,
        250,
    )
    runtime._publish_frame_metadata(
        frame(
            pts_ns=250,
            ntp_ns=source_ntp_ns + 60_000_000,
            frame_num=3,
        ),
        object(),
    )
    assert supervisor.health_for("camera-01").state == "reconnecting"
    assert old_facade.observe_parser_buffer(
        20_000,
        source_timestamp_ns + 80_000_000,
        300,
        64_000_000,
    )
    assert old_facade.observe_decoded_buffer(300, 65_000_000)
    runtime._record_metadata_owner(
        "camera-01",
        old_facade,
        300,
    )
    runtime._publish_frame_metadata(
        frame(
            pts_ns=300,
            ntp_ns=source_ntp_ns + 80_000_000,
            frame_num=4,
        ),
        object(),
    )

    assert supervisor.health_for("camera-01").state == "online"
    assert generation.lifecycle == "authorized"
    assert generation.authorized_stream_epoch == current_epoch
    assert callbacks.failures == []
    old_facade.close()


@pytest.mark.parametrize(
    (
        "parser_observed_ns",
        "decoded_observed_ns",
        "ntp_observed_ns",
        "expected_online",
    ),
    (
        (10_000_000, 60_000_000, 70_000_000, False),
        (60_000_000, 10_000_000, 70_000_000, False),
        (60_000_000, 70_000_000, 10_000_000, False),
        (52_000_000, 60_000_000, 70_000_000, True),
    ),
)
def test_real_bridge_requires_every_frame_primitive_strictly_after_epoch_fence(
    parser_observed_ns: int,
    decoded_observed_ns: int,
    ntp_observed_ns: int,
    expected_online: bool,
) -> None:
    callbacks = AllowingNativeCallbacks()
    bridge = NativeSourceProbeBridge(capacity=8)
    lease = bridge.bind(callbacks)
    assert lease.observe_rtp_caps("h264", 1)
    assert lease.observe_decoder_caps(1920, 1080, 25, 1, 1)
    wall_time = datetime(2026, 7, 30, 9, 0, tzinfo=UTC)
    source_ntp_ns = int(wall_time.timestamp() * 1_000_000_000)
    source_timestamp_ns = 900_000_000_000
    assert lease.observe_parser_buffer(
        20_000,
        source_timestamp_ns,
        100,
        2,
    )
    assert lease.observe_decoded_buffer(100, 3)
    assert lease.observe_nvds_ntp(
        100,
        source_ntp_ns - 40_000_000,
        4,
    )

    runtime, supervisor, recovery = _owned_runtime((lease,))  # type: ignore[arg-type]
    generation = runtime._active_source_generations["camera-01"]
    generation.correlation_not_before_monotonic_ns = 51_000_000
    runtime._monotonic_ns = lambda: ntp_observed_ns
    assert lease.observe_parser_buffer(
        20_000,
        source_timestamp_ns + 40_000_000,
        200,
        parser_observed_ns,
    )
    assert lease.observe_decoded_buffer(200, decoded_observed_ns)
    runtime._record_metadata_owner("camera-01", lease, 200)
    runtime._publish_frame_metadata(
        type(
            "Frame",
            (),
            {
                "source_id": 0,
                "ntp_timestamp": source_ntp_ns,
                "buf_pts": 200,
                "source_frame_width": 1920,
                "source_frame_height": 1080,
                "frame_num": 1,
                "obj_meta_list": None,
            },
        )(),
        object(),
    )

    current_epoch = str(supervisor.health_for("camera-01").stream_epoch)
    assert (supervisor.health_for("camera-01").state == "online") is expected_online
    assert (generation.lifecycle == "authorized") is expected_online
    if expected_online:
        assert generation.authorized_stream_epoch == current_epoch
    else:
        with pytest.raises(SourceTimeMappingError, match="not anchored"):
            runtime._source_time_mapper.map(
                camera_id="camera-01",
                stream_epoch=current_epoch,
                running_time_ns=200,
            )
    assert callbacks.failures == []
    assert recovery.failures == []
    lease.close()


def test_real_bridge_staged_completion_cannot_authorize_after_successful_cutover() -> None:
    callbacks = AllowingNativeCallbacks()
    bridge = NativeSourceProbeBridge(capacity=8)
    wall_time = datetime(2026, 7, 30, 9, 0, tzinfo=UTC)
    source_ntp_ns = int(wall_time.timestamp() * 1_000_000_000)
    source_timestamp_ns = 900_000_000_000

    class Factory:
        def __init__(self) -> None:
            self.acquisitions = 0

        def acquire(self, _: str, __: int) -> object:
            self.acquisitions += 1
            return bridge.bind(callbacks)

    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad)
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
    )
    runtime, _, _, pipeline, _ = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
    )
    factory = Factory()
    runtime._native_probe_lease_factory = factory  # type: ignore[assignment]
    monotonic_values = iter(
        (
            40_000_000,
            50_000_000,
            48_000_000,
            63_000_000,
            66_000_000,
        )
    )
    runtime._monotonic_ns = lambda: next(monotonic_values)
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in runtime._graph.sources),
        observation_queue_size=4,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: wall_time,
    )
    runtime._supervisor = supervisor
    runtime._metadata_publisher = MetadataPublisher(
        supervisor=supervisor,
        model_artifact_id="person-primary-v1",
    )

    original_add = pipeline.add
    staged_results: list[bool] = []

    def add_with_staged_completion(source_bin: SourceBin) -> bool:
        added = original_add(source_bin)
        staged = runtime._staged_source_generations["camera-01"].lease
        staged_results.extend(
            (
                staged.observe_parser_buffer(
                    20_000,
                    source_timestamp_ns + 40_000_000,
                    200,
                    47_000_000,
                ),
                staged.observe_decoded_buffer(200, 50_000_000),
                staged.observe_nvds_ntp(
                    200,
                    source_ntp_ns,
                    48_000_000,
                ),
            )
        )
        assert factory.acquisitions == 0
        return added

    pipeline.add = add_with_staged_completion  # type: ignore[method-assign]
    runtime._rebuild_source("camera-01")

    generation = runtime._active_source_generations["camera-01"]
    lease = generation.lease
    assert lease.active
    assert generation.lifecycle == "live_unauthorized"
    assert generation.correlation_not_before_monotonic_ns == 50_000_000
    assert staged_results == [False, False, False]
    assert factory.acquisitions == 1
    assert lease.observe_rtp_caps("h264", 51_000_000)
    assert lease.observe_decoder_caps(1920, 1080, 25, 1, 52_000_000)

    def frame(
        *,
        pts_ns: int,
        ntp_ns: int,
        frame_num: int,
    ) -> object:
        return type(
            "Frame",
            (),
            {
                "source_id": 0,
                "ntp_timestamp": ntp_ns,
                "buf_pts": pts_ns,
                "source_frame_width": 1920,
                "source_frame_height": 1080,
                "frame_num": frame_num,
                "obj_meta_list": None,
            },
        )()

    runtime._record_metadata_owner("camera-01", lease, 200)
    runtime._publish_frame_metadata(
        frame(pts_ns=200, ntp_ns=source_ntp_ns, frame_num=1),
        object(),
    )

    current_epoch = str(supervisor.health_for("camera-01").stream_epoch)
    assert supervisor.health_for("camera-01").state == "starting"
    assert generation.lifecycle == "live_unauthorized"
    with pytest.raises(SourceTimeMappingError, match="not anchored"):
        runtime._source_time_mapper.map(
            camera_id="camera-01",
            stream_epoch=current_epoch,
            running_time_ns=200,
        )

    assert lease.observe_parser_buffer(
        20_000,
        source_timestamp_ns + 60_000_000,
        250,
        61_000_000,
    )
    assert lease.observe_decoded_buffer(250, 62_000_000)
    runtime._record_metadata_owner("camera-01", lease, 250)
    runtime._publish_frame_metadata(
        frame(
            pts_ns=250,
            ntp_ns=source_ntp_ns + 60_000_000,
            frame_num=2,
        ),
        object(),
    )
    assert supervisor.health_for("camera-01").state == "starting"
    assert lease.observe_parser_buffer(
        20_000,
        source_timestamp_ns + 80_000_000,
        300,
        64_000_000,
    )
    assert lease.observe_decoded_buffer(300, 65_000_000)
    runtime._record_metadata_owner("camera-01", lease, 300)
    runtime._publish_frame_metadata(
        frame(
            pts_ns=300,
            ntp_ns=source_ntp_ns + 80_000_000,
            frame_num=3,
        ),
        object(),
    )

    assert supervisor.health_for("camera-01").state == "online"
    assert generation.lifecycle == "authorized"
    assert generation.authorized_stream_epoch == current_epoch
    assert callbacks.failures == []
    lease.close()


def test_failed_old_relink_is_an_explicit_camera_local_rollback_failure() -> None:
    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad, link_results=[1])
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[1]),
    )
    runtime, old, new, _, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
    )

    with pytest.raises(RuntimeError, match="restore old source generation"):
        runtime._rebuild_source("camera-01")

    assert old.close_calls == 0
    assert new.close_calls == 0
    assert recovery.failures == [("camera-01", "rtsp_rebuild_rollback_failed", True)]


def test_failed_rollback_removal_retains_staged_owner_for_stop_retry() -> None:
    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad)
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[1]),
    )
    runtime, old, new, pipeline, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
        remove_results=[False, True],
    )

    with pytest.raises(RuntimeError, match="restore old source generation"):
        runtime._rebuild_source("camera-01")

    assert runtime._active_source_generations["camera-01"].lease.active
    assert runtime._staged_source_generations["camera-01"].lease.active is False
    assert replacement in pipeline.added
    assert replacement not in pipeline.removed
    assert new.close_calls == 0
    assert recovery.failures == [("camera-01", "rtsp_rebuild_rollback_failed", True)]

    runtime.stop()

    assert replacement in pipeline.removed
    assert runtime._staged_source_generations == {}
    assert new.close_calls == 0


def test_failed_old_retirement_is_retained_for_stop_retry_without_stale_authority() -> None:
    class Writer:
        @staticmethod
        def get_name() -> str:
            return "evidence-writer-0"

    class EvidenceFactory:
        def __init__(self) -> None:
            self.unbind_calls: list[object] = []
            self.handle_calls: list[object] = []

        def unbind_writer(self, writer: object) -> None:
            self.unbind_calls.append(writer)

        def handle_writer_message(
            self,
            *,
            writer: object,
            structure: object,
            source_time_mapper: object,
        ) -> None:
            del structure, source_time_mapper
            self.handle_calls.append(writer)

    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad)
    old_writer = Writer()
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
    )
    runtime, old, new, pipeline, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
        remove_results=[False, True],
    )
    old_generation = runtime._active_source_generations["camera-01"]
    old_generation.writer = old_writer
    old_generation._writer_bound = True
    old_generation._added_to_pipeline = True
    evidence = EvidenceFactory()
    runtime._evidence_sink_factory = evidence  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="retire old source generation"):
        runtime._rebuild_source("camera-01")

    assert runtime._active_source_generations["camera-01"].lease.active
    assert runtime._retired_source_generations["camera-01"] is old_generation
    assert len(runtime._retired_source_generations) == 1
    assert old_generation.lifecycle == "retired"
    assert old.close_calls == 1
    assert evidence.unbind_calls.count(old_writer) == 1

    old.reject = True
    runtime._parser_buffer_probe(
        object(),
        Info(buffer=Buffer(size=100, dts=10, pts=20)),
        "camera-01",
        old,  # type: ignore[arg-type]
        GstProbe,
    )
    stale_structure = type(
        "Structure",
        (),
        {
            "get_name": lambda _: "splitmuxsink-fragment-closed",
            "get_value": lambda _, name: {
                "location": "/evidence/stale.mp4",
                "running-time": 2_000_000_000,
            }[name],
        },
    )()
    stale_message = type(
        "Message",
        (),
        {
            "src": old_writer,
            "type": "element",
            "get_structure": lambda _: stale_structure,
        },
    )()
    runtime._on_bus_message(None, stale_message)
    assert recovery.failures == [("camera-01", "rtsp_rebuild_retirement_failed", True)]
    assert evidence.handle_calls == []

    old_bin = old_generation.source_bin
    runtime.stop()

    assert old_bin in pipeline.removed
    assert runtime._retired_source_generations == {}
    assert old.close_calls == 1
    assert evidence.unbind_calls.count(old_writer) == 1


def test_successful_rebuild_retires_old_writer_and_late_events_are_inert() -> None:
    class Writer:
        def __init__(self, name: str) -> None:
            self.name = name

        def get_name(self) -> str:
            return self.name

    class EvidenceFactory:
        def __init__(self, old_writer: Writer, replacement_writer: Writer) -> None:
            self.bound = {id(old_writer)}
            self.bind_calls: list[object] = []
            self.unbind_calls: list[object] = []
            self.handle_calls: list[object] = []
            self.delivered: list[object] = []

        def bind_writer(self, writer: object, *, stream_epoch: str) -> None:
            assert stream_epoch
            self.bound.add(id(writer))
            self.bind_calls.append(writer)

        def unbind_writer(self, writer: object) -> None:
            self.bound.discard(id(writer))
            self.unbind_calls.append(writer)

        def handle_splitmux_message(self, *_: object, **__: object) -> None:
            return None

        def handle_writer_message(
            self,
            *,
            writer: object,
            structure: object,
            source_time_mapper: object,
        ) -> None:
            del structure, source_time_mapper
            self.handle_calls.append(writer)
            if id(writer) in self.bound:
                self.delivered.append(writer)

    mux_pad = LinkPad()
    old_pad = LinkPad(peer=mux_pad)
    old_writer = Writer("evidence-writer-0")
    replacement_writer = Writer("evidence-writer-0")
    replacement = SourceBin(
        "source-0-generation-2",
        LinkPad(link_results=[0]),
        writer=replacement_writer,
    )
    runtime, old, new, _, recovery = _rebuild_runtime(
        old_pad=old_pad,
        replacement=replacement,
    )
    old_generation = runtime._active_source_generations["camera-01"]
    old_generation.writer = old_writer
    evidence = EvidenceFactory(old_writer, replacement_writer)
    runtime._evidence_sink_factory = evidence  # type: ignore[assignment]
    supervisor = CameraSupervisor(
        camera_ids=tuple(source.camera_id for source in runtime._graph.sources),
        observation_queue_size=4,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: datetime(2026, 7, 30, 9, 0, tzinfo=UTC),
    )
    runtime._supervisor = supervisor

    runtime._rebuild_source("camera-01")

    replacement_generation = runtime._active_source_generations["camera-01"]
    assert replacement_generation.lease.active
    assert replacement_generation.lifecycle == "live_unauthorized"
    assert replacement_generation._writer_bound is False
    assert evidence.bind_calls == []
    assert evidence.unbind_calls == [old_writer]
    assert old.close_calls == 1
    assert new.close_calls == 0

    old.reject = True
    old_primitive_call_count = len(old.calls)
    runtime._parser_buffer_probe(
        object(),
        Info(buffer=Buffer(size=100, dts=10, pts=20)),
        "camera-01",
        old,  # type: ignore[arg-type]
        GstProbe,
    )
    assert len(old.calls) == old_primitive_call_count
    assert recovery.failures == []

    runtime._recovery = None
    message = type(
        "Message",
        (),
        {
            "src": old_writer,
            "type": "element",
            "get_structure": lambda _: type(
                "Structure",
                (),
                {"get_name": lambda _: "splitmuxsink-fragment-closed"},
            )(),
        },
    )()
    runtime._on_bus_message(None, message)
    assert evidence.handle_calls == []
    assert evidence.delivered == []


def test_evidence_writer_waits_for_correlation_and_post_ready_fragment_boundary() -> None:
    class Writer:
        @staticmethod
        def get_name() -> str:
            return "evidence-writer-0"

    class EvidenceFactory:
        def __init__(self) -> None:
            self.bind_calls: list[object] = []
            self.handle_calls: list[str] = []

        def bind_writer(self, writer: object, *, stream_epoch: str) -> None:
            assert stream_epoch
            self.bind_calls.append(writer)

        def handle_splitmux_message(self, *_: object, **__: object) -> None:
            raise AssertionError("legacy handler must not be used")

        def handle_writer_message(
            self,
            *,
            writer: object,
            structure: object,
            source_time_mapper: object,
        ) -> None:
            del writer, source_time_mapper
            self.handle_calls.append(structure.get_name())  # type: ignore[attr-defined]

        def disable(self, _: str) -> None:
            return None

    def message(
        writer: Writer,
        structure_name: str,
        *,
        location: str,
        running_time_ns: int,
    ) -> object:
        structure = type(
            "Structure",
            (),
            {
                "get_name": lambda _: structure_name,
                "get_value": lambda _, name: {
                    "location": location,
                    "running-time": running_time_ns,
                    "starts-with-keyframe": True,
                }[name],
            },
        )()
        return type(
            "Message",
            (),
            {
                "src": writer,
                "type": "element",
                "get_structure": lambda _: structure,
            },
        )()

    lease = RecordingLease()
    runtime, supervisor, _ = _owned_runtime((lease,))
    runtime._recovery = None
    writer = Writer()
    generation = runtime._active_source_generations["camera-01"]
    generation.writer = writer
    evidence = EvidenceFactory()
    runtime._evidence_sink_factory = evidence  # type: ignore[assignment]

    runtime._on_bus_message(
        None,
        message(
            writer,
            "splitmuxsink-fragment-opened",
            location="/evidence/pre-authority.mp4",
            running_time_ns=500_000_000,
        ),
    )
    runtime._on_bus_message(
        None,
        message(
            writer,
            "splitmuxsink-fragment-closed",
            location="/evidence/pre-authority.mp4",
            running_time_ns=750_000_000,
        ),
    )
    assert evidence.bind_calls == []
    assert evidence.handle_calls == []

    pts_ns = 1_000_000_000
    source_time_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)
    runtime._decoder_buffer_probe(
        object(),
        Info(buffer=Buffer(size=1, dts=1, pts=pts_ns)),
        "camera-01",
        lease,  # type: ignore[arg-type]
        GstProbe,
    )
    runtime._publish_frame_metadata(
        type(
            "Frame",
            (),
            {
                "source_id": 0,
                "ntp_timestamp": source_time_ns,
                "buf_pts": pts_ns,
                "source_frame_width": 1920,
                "source_frame_height": 1080,
                "frame_num": 1,
                "obj_meta_list": None,
            },
        )(),
        object(),
    )

    assert supervisor.health_for("camera-01").state == "online"
    assert evidence.bind_calls == [writer]

    runtime._on_bus_message(
        None,
        message(
            writer,
            "splitmuxsink-fragment-opened",
            location="/evidence/delayed-pre-authority.mp4",
            running_time_ns=900_000_000,
        ),
    )
    runtime._on_bus_message(
        None,
        message(
            writer,
            "splitmuxsink-fragment-closed",
            location="/evidence/delayed-pre-authority.mp4",
            running_time_ns=1_500_000_000,
        ),
    )
    assert evidence.handle_calls == []
    runtime._on_bus_message(
        None,
        message(
            writer,
            "splitmuxsink-fragment-opened",
            location="/evidence/first-authorized.mp4",
            running_time_ns=1_000_000_000,
        ),
    )
    runtime._on_bus_message(
        None,
        message(
            writer,
            "splitmuxsink-fragment-closed",
            location="/evidence/first-authorized.mp4",
            running_time_ns=2_000_000_000,
        ),
    )
    assert evidence.handle_calls == [
        "splitmuxsink-fragment-opened",
        "splitmuxsink-fragment-closed",
    ]


def test_evidence_adoption_and_disable_failure_fences_and_recovers_camera() -> None:
    class Writer:
        def __init__(self) -> None:
            self.states: list[object] = []

        @staticmethod
        def get_name() -> str:
            return "evidence-writer-0"

        def set_state(self, state: object) -> None:
            self.states.append(state)

    class EvidenceFactory:
        def __init__(self) -> None:
            self.handle_calls: list[object] = []
            self.disable_calls: list[str] = []
            self.reset_calls: list[str] = []

        def handle_writer_message(
            self,
            *,
            writer: object,
            structure: object,
            source_time_mapper: object,
        ) -> None:
            del structure, source_time_mapper
            self.handle_calls.append(writer)
            raise RuntimeError("primary evidence adoption failed")

        def reset_camera(self, camera_id: str) -> None:
            self.reset_calls.append(camera_id)

        def disable(self, camera_id: str) -> None:
            self.disable_calls.append(camera_id)
            raise OSError("evidence disable cleanup failed")

    class Gst:
        class State:
            NULL = "null"

    lease = RecordingLease()
    runtime, supervisor, recovery = _owned_runtime((lease,))
    writer = Writer()
    evidence = EvidenceFactory()
    generation = runtime._active_source_generations["camera-01"]
    stream_epoch = str(supervisor.health_for("camera-01").stream_epoch)
    generation.writer = writer
    generation.lifecycle = "authorized"
    generation.authorized_running_time_ns = 1_000_000_000
    generation.authorized_stream_epoch = stream_epoch
    generation.evidence_open_location = "/evidence/failed.mp4"
    generation._writer_bound = True
    runtime._evidence_sink_factory = evidence  # type: ignore[assignment]
    runtime._bindings = type("Bindings", (), {"gst": Gst})()
    structure = Structure(
        "splitmuxsink-fragment-closed",
        {
            "location": "/evidence/failed.mp4",
            "running-time": 2_000_000_000,
        },
    )
    message = type(
        "Message",
        (),
        {
            "src": writer,
            "type": "element",
            "get_structure": lambda _: structure,
        },
    )()
    escaped_error: BaseException | None = None

    try:
        runtime._on_bus_message(None, message)
    except BaseException as exc:
        escaped_error = exc

    assert generation.lifecycle == "quiescing"
    assert generation.authorized_running_time_ns is None
    assert generation.authorized_stream_epoch is None
    assert generation.evidence_open_location is None
    assert generation._writer_bound is False
    assert runtime._pending_evidence_disable == {"camera-01"}
    assert writer.states == ["null"]
    assert recovery.failures == [("camera-01", "evidence_fragment_adoption_failed", True)]
    assert evidence.handle_calls == [writer]
    assert evidence.reset_calls == ["camera-01"]
    assert evidence.disable_calls == ["camera-01"]
    assert runtime.evidence_attachment_failures == 1
    assert escaped_error is None


def test_pending_evidence_disable_blocks_repeated_writer_allocation() -> None:
    class EvidenceFactory:
        def __init__(self) -> None:
            self.disable_calls: list[str] = []
            self.writer_allocations = 0

        def __call__(self, _: object, __: object) -> object:
            self.writer_allocations += 1
            return object()

        def disable(self, camera_id: str) -> None:
            self.disable_calls.append(camera_id)
            raise OSError("evidence disable cleanup failed")

    evidence = EvidenceFactory()
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=evidence,
    )
    source = DeepStreamGraphSpec.from_site(_site()).sources[0]
    runtime._pending_evidence_disable.add(source.camera_id)

    for _ in range(2):
        with pytest.raises(OSError, match="evidence disable cleanup failed"):
            runtime._build_source_bin(object(), source, "rtsp://redacted")

    assert evidence.disable_calls == [source.camera_id, source.camera_id]
    assert evidence.writer_allocations == 0
    assert runtime._pending_evidence_disable == {source.camera_id}


@pytest.mark.parametrize("prior_authorized", (False, True))
def test_recovered_supervisor_epoch_rejects_old_generation_before_rebuild_starts(
    prior_authorized: bool,
) -> None:
    class Writer:
        @staticmethod
        def get_name() -> str:
            return "evidence-writer-0"

    class EvidenceFactory:
        def __init__(self) -> None:
            self.bind_epochs: list[str] = []
            self.handle_calls: list[object] = []

        def bind_writer(self, _: object, *, stream_epoch: str) -> None:
            self.bind_epochs.append(stream_epoch)

        def handle_writer_message(
            self,
            *,
            writer: object,
            structure: object,
            source_time_mapper: object,
        ) -> None:
            del structure, source_time_mapper
            self.handle_calls.append(writer)

    lease = RecordingLease()
    runtime, supervisor, _ = _owned_runtime((lease,))
    runtime._recovery = None
    generation = runtime._active_source_generations["camera-01"]
    writer = Writer()
    generation.writer = writer
    evidence = EvidenceFactory()
    runtime._evidence_sink_factory = evidence  # type: ignore[assignment]
    source_ntp_ns = int(datetime(2026, 7, 30, 9, 0, tzinfo=UTC).timestamp() * 1_000_000_000)

    def frame(pts_ns: int, frame_num: int) -> object:
        return type(
            "Frame",
            (),
            {
                "source_id": 0,
                "ntp_timestamp": source_ntp_ns,
                "buf_pts": pts_ns,
                "source_frame_width": 1920,
                "source_frame_height": 1080,
                "frame_num": frame_num,
                "obj_meta_list": None,
            },
        )()

    first_pts_ns = 1_000_000_000
    if prior_authorized:
        runtime._record_metadata_owner(
            "camera-01",
            lease,  # type: ignore[arg-type]
            first_pts_ns,
        )
        runtime._publish_frame_metadata(frame(first_pts_ns, 1), object())
    old_epoch = str(supervisor.health_for("camera-01").stream_epoch)

    assert generation.lifecycle == ("authorized" if prior_authorized else "live_unauthorized")
    assert generation.authorized_stream_epoch == (old_epoch if prior_authorized else None)
    assert evidence.bind_epochs == ([old_epoch] if prior_authorized else [])

    supervisor.disconnect("camera-01")
    runtime._recover_camera_epoch("camera-01")
    current_epoch = str(supervisor.health_for("camera-01").stream_epoch)
    assert current_epoch != old_epoch
    assert generation.lifecycle == "quiescing"
    assert generation.authorized_stream_epoch is None
    second_pts_ns = 2_000_000_000
    runtime._record_metadata_owner(
        "camera-01",
        lease,  # type: ignore[arg-type]
        second_pts_ns,
    )
    runtime._publish_frame_metadata(frame(second_pts_ns, 2), object())

    structure = type(
        "Structure",
        (),
        {
            "get_name": lambda _: "splitmuxsink-fragment-opened",
            "get_value": lambda _, name: {
                "location": "/evidence/old-epoch.mp4",
                "running-time": second_pts_ns,
            }[name],
        },
    )()
    message = type(
        "Message",
        (),
        {"src": writer, "type": "element", "get_structure": lambda _: structure},
    )()
    runtime._on_bus_message(None, message)

    assert supervisor.health_for("camera-01").state == "reconnecting"
    assert generation.authorized_stream_epoch is None
    assert evidence.bind_epochs == ([old_epoch] if prior_authorized else [])
    assert evidence.handle_calls == []
    with pytest.raises(SourceTimeMappingError, match="not anchored"):
        runtime._source_time_mapper.map(
            camera_id="camera-01",
            stream_epoch=current_epoch,
            running_time_ns=second_pts_ns,
        )


def test_initial_attach_keeps_evidence_writer_unbound_until_correlation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = DeepStreamGraphSpec.from_site(_site())
    graph = graph.model_copy(update={"sources": graph.sources[:1]})
    writer = object()
    lease = RecordingLease()

    class EvidenceFactory:
        def __init__(self) -> None:
            self.bind_calls: list[object] = []

        def bind_writer(self, candidate: object, *, stream_epoch: str) -> None:
            assert stream_epoch
            self.bind_calls.append(candidate)

    class InitialPipeline:
        @staticmethod
        def add(_: object) -> bool:
            return True

    class InitialMux:
        @staticmethod
        def request_pad_simple(_: str) -> LinkPad:
            return LinkPad()

    source_bin = SourceBin(
        "source-0-generation-1",
        LinkPad(),
        writer=writer,
    )
    evidence = EvidenceFactory()
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=LeaseFactory([lease]),
        evidence_sink_factory=evidence,
    )
    runtime._bindings = deepstream_module._NvidiaBindings(
        gst=GstRebuild,
        glib=object(),
        pyds=object(),
    )
    runtime._supervisor = CameraSupervisor(
        camera_ids=("camera-01",),
        observation_queue_size=4,
        monotonic_clock=lambda: 0.0,
        wall_clock=lambda: datetime(2026, 7, 30, 9, 0, tzinfo=UTC),
    )
    monkeypatch.setattr(runtime, "_build_source_bin", lambda *_: source_bin)

    runtime._attach_initial_source_generations(
        InitialPipeline(),
        InitialMux(),
        GstRebuild,
        graph,
        {"camera-01": "rtsp://redacted"},
    )

    assert runtime._active_source_generations["camera-01"].writer is writer
    assert evidence.bind_calls == []


def test_generation_writer_unbind_marks_completion_only_after_collaborator_succeeds() -> None:
    writer = object()

    class EvidenceFactory:
        def __init__(self) -> None:
            self.unbind_calls: list[object] = []

        def unbind_writer(self, candidate: object) -> None:
            self.unbind_calls.append(candidate)
            if len(self.unbind_calls) == 1:
                raise RuntimeError("writer cleanup failed")

    evidence = EvidenceFactory()
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=evidence,
    )
    generation = deepstream_module._SourceGeneration(
        camera_id="camera-01",
        source_id=0,
        ordinal=1,
        source_bin=object(),
        writer=writer,
        lease=RecordingLease(),  # type: ignore[arg-type]
        _writer_bound=True,
    )

    with pytest.raises(RuntimeError, match="writer cleanup failed"):
        runtime._unbind_generation_writer(generation)

    assert generation._writer_unbound is False
    assert generation._writer_bound is True
    runtime._unbind_generation_writer(generation)
    runtime._unbind_generation_writer(generation)

    assert evidence.unbind_calls == [writer, writer]
    assert generation._writer_unbound is True
    assert generation._writer_bound is False


def test_stop_closes_every_active_and_staged_generation_despite_one_exception() -> None:
    leases = [
        RecordingLease(),
        RecordingLease(close_error=True),
        RecordingLease(),
    ]

    class EvidenceFactory:
        def __init__(self) -> None:
            self.unbound: list[object] = []

        def unbind_writer(self, writer: object) -> None:
            self.unbound.append(writer)
            if len(self.unbound) == 1:
                raise RuntimeError("writer cleanup failed")

    evidence = EvidenceFactory()
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=evidence,
    )
    writers = [object(), object(), object()]
    for index, lease in enumerate(leases[:2]):
        runtime._active_source_generations[f"camera-{index + 1:02d}"] = (
            deepstream_module._SourceGeneration(
                camera_id=f"camera-{index + 1:02d}",
                source_id=index,
                ordinal=1,
                source_bin=object(),
                writer=writers[index],
                lease=lease,  # type: ignore[arg-type]
            )
        )
    runtime._staged_source_generations["camera-03"] = deepstream_module._SourceGeneration(
        camera_id="camera-03",
        source_id=2,
        ordinal=1,
        source_bin=object(),
        writer=writers[2],
        lease=leases[2],  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="writer cleanup failed"):
        runtime.stop()

    assert evidence.unbound == writers
    assert [lease.close_calls for lease in leases] == [1, 1, 1]
    assert runtime._active_source_generations == {}
    assert runtime._staged_source_generations == {}


def test_second_stop_retries_writer_cleanup_retained_by_first_failure() -> None:
    writer = object()

    class EvidenceFactory:
        def __init__(self) -> None:
            self.unbind_calls: list[object] = []

        def unbind_writer(self, candidate: object) -> None:
            self.unbind_calls.append(candidate)
            if len(self.unbind_calls) == 1:
                raise RuntimeError("writer cleanup failed")

    evidence = EvidenceFactory()
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=evidence,
    )
    lease = RecordingLease()
    generation = deepstream_module._SourceGeneration(
        camera_id="camera-01",
        source_id=0,
        ordinal=1,
        source_bin=object(),
        writer=writer,
        lease=lease,  # type: ignore[arg-type]
        _writer_bound=True,
    )
    runtime._active_source_generations["camera-01"] = generation

    with pytest.raises(RuntimeError, match="writer cleanup failed"):
        runtime.stop()

    assert evidence.unbind_calls == [writer]
    assert generation._writer_unbound is False
    assert len(runtime._pending_writer_cleanup) == 1
    assert lease.close_calls == 1

    runtime.stop()

    assert evidence.unbind_calls == [writer, writer]
    assert generation._writer_unbound is True
    assert runtime._pending_writer_cleanup == {}
    assert lease.close_calls == 1


def test_second_stop_retries_real_evidence_disable_after_graph_is_cleared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingPropertyElement:
        @staticmethod
        def set_property(_: str, __: object) -> None:
            raise RuntimeError("property configuration failed")

    class ConstructionGst:
        class ElementFactory:
            @staticmethod
            def make(_: str, __: str) -> FailingPropertyElement:
                return FailingPropertyElement()

    graph = DeepStreamGraphSpec.from_site(_site())
    source = graph.sources[0]
    ring = EncodedFragmentRing(
        tmp_path / "spool",
        ring_seconds=15,
        max_camera_bytes=100,
        max_spool_bytes=100,
        clock=lambda: datetime(2026, 7, 30, 9, 0, tzinfo=UTC),
    )
    evidence = SplitMuxEvidenceSinkFactory(
        ring=ring,
        fragment_seconds=2,
        max_fragment_bytes=100,
    )
    original_rmtree = evidence_runtime.shutil.rmtree
    rmtree_calls = 0

    def flaky_rmtree(path: Path) -> None:
        nonlocal rmtree_calls
        rmtree_calls += 1
        if rmtree_calls <= 2:
            raise OSError("simulated evidence cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(evidence_runtime.shutil, "rmtree", flaky_rmtree)

    with pytest.raises(RuntimeError, match="property configuration failed"):
        evidence(ConstructionGst, source)

    incoming_directory = next((ring.root / ".incoming").glob("*/*"))
    assert incoming_directory.is_dir()
    assert ring.used_bytes == 100

    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=evidence,
    )
    lease = RecordingLease()
    runtime._graph = graph
    runtime._active_source_generations[source.camera_id] = deepstream_module._SourceGeneration(
        camera_id=source.camera_id,
        source_id=source.source_id,
        ordinal=1,
        source_bin=object(),
        writer=None,
        lease=lease,  # type: ignore[arg-type]
    )

    with pytest.raises(OSError, match="simulated evidence cleanup failure"):
        runtime.stop()

    pending_after_first_stop = set(runtime._pending_evidence_disable)
    assert runtime._graph is None
    assert incoming_directory.is_dir()
    assert ring.used_bytes == 100
    assert lease.close_calls == 1

    runtime.stop()

    assert rmtree_calls == 3
    assert pending_after_first_stop == {source.camera_id}
    assert runtime._pending_evidence_disable == set()
    assert not incoming_directory.exists()
    assert ring.used_bytes == 0
    assert lease.close_calls == 1


def test_start_fails_closed_before_new_graph_when_evidence_disable_is_pending(
    tmp_path: Path,
) -> None:
    class FailingEvidenceFactory:
        def __init__(self) -> None:
            self.disable_calls: list[str] = []

        def disable(self, camera_id: str) -> None:
            self.disable_calls.append(camera_id)
            raise OSError("retained evidence cleanup failed")

    evidence = FailingEvidenceFactory()
    runtime = DeepStreamDataPlane(
        runtime_manifest=_manifest_with_files(tmp_path),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        evidence_sink_factory=evidence,  # type: ignore[arg-type]
    )
    runtime._pending_evidence_disable.add("camera-01")

    with pytest.raises(OSError, match="retained evidence cleanup failed"):
        runtime.start(_site())

    assert evidence.disable_calls == ["camera-01"]
    assert runtime._pending_evidence_disable == {"camera-01"}
    assert runtime._graph is None
    assert runtime._pipeline is None


def test_initial_attach_acquires_exact_twenty_and_partial_failure_closes_each_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = DeepStreamGraphSpec.from_site(_site())

    class InitialBin:
        def __init__(self, name: str) -> None:
            self.name = name
            self.pad = LinkPad()

        def get_static_pad(self, _: str) -> LinkPad:
            return self.pad

        def get_by_name(self, _: str) -> None:
            return None

    class InitialMux:
        def request_pad_simple(self, _: str) -> LinkPad:
            return LinkPad()

    class InitialPipeline:
        def __init__(self, *, fail_at: int | None = None) -> None:
            self.fail_at = fail_at
            self.add_calls = 0

        def add(self, _: object) -> bool:
            result = self.add_calls != self.fail_at
            self.add_calls += 1
            return result

    all_leases = [RecordingLease() for _ in range(20)]
    full_factory = LeaseFactory(all_leases)
    full = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=full_factory,
    )
    full._bindings = deepstream_module._NvidiaBindings(
        gst=GstRebuild,
        glib=object(),
        pyds=object(),
    )
    monkeypatch.setattr(
        full,
        "_build_source_bin",
        lambda _gst, source, _location, *_: InitialBin(f"source-{source.source_id}-generation-1"),
    )

    full._attach_initial_source_generations(
        InitialPipeline(),
        InitialMux(),
        GstRebuild,
        graph,
        {source.camera_id: "rtsp://redacted" for source in graph.sources},
    )

    assert full_factory.acquisitions == [(f"camera-{index + 1:02d}", index) for index in range(20)]
    assert len(full._active_source_generations) == 20
    full.stop()
    assert [lease.close_calls for lease in all_leases] == [1] * 20

    partial_leases = [RecordingLease() for _ in range(8)]
    partial_factory = LeaseFactory(partial_leases)
    partial = DeepStreamDataPlane(
        runtime_manifest=_manifest(),
        runtime_info=lambda: ("8.9", "10.16.0.72"),
        native_probe_lease_factory=partial_factory,
    )
    partial._bindings = deepstream_module._NvidiaBindings(
        gst=GstRebuild,
        glib=object(),
        pyds=object(),
    )
    monkeypatch.setattr(
        partial,
        "_build_source_bin",
        lambda _gst, source, _location, *_: InitialBin(f"source-{source.source_id}-generation-1"),
    )

    with pytest.raises(RuntimeError, match="failed to add camera camera-08"):
        partial._attach_initial_source_generations(
            InitialPipeline(fail_at=7),
            InitialMux(),
            GstRebuild,
            graph,
            {source.camera_id: "rtsp://redacted" for source in graph.sources},
        )
    partial.stop()

    assert partial_factory.acquisitions == [
        (f"camera-{index + 1:02d}", index) for index in range(8)
    ]
    assert [lease.close_calls for lease in partial_leases] == [1] * 8
