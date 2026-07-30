from __future__ import annotations

import copy
import gc
import hashlib
import inspect
import pickle
import threading
import weakref
from concurrent.futures import (
    ThreadPoolExecutor,
    wait,
)
from concurrent.futures import (
    TimeoutError as FutureTimeoutError,
)
from dataclasses import replace

import pytest

import protector.pilot.runtime.source_probe as source_probe_module
from protector.pilot.runtime.source_probe import (
    Exact20NativePrewarmReceiptV1,
    NativeSourceProbeBridge,
    SourceProbeLease,
    verify_and_issue_exact_20_prewarm_receipt,
)
from protector.pilot.runtime.source_profile import (
    NativeSourceCaps,
    NativeSourceProfileProofEnvelopeV1,
    SourceProfileFailureCode,
)
from tests.pilot import test_source_profile as profile_fixtures

INT64_MAX = 2**63 - 1
GST_CLOCK_TIME_NONE = 2**64 - 1
BASE_SOURCE_TIMESTAMP_NS = 900_000_000_000
BASE_SOURCE_NTP_NS = 1_800_000_000_000_000_000


class _VerificationAbort(BaseException):
    pass


class _HousekeepingAbort(BaseException):
    pass


class _RecordingCallbacks:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.failures: list[tuple[SourceProfileFailureCode, int]] = []
        self.close_count = 0
        self._lock = threading.Lock()

    def on_rtp_caps(self, caps: NativeSourceCaps, *, observed_monotonic_ns: int) -> bool:
        with self._lock:
            self.calls.append(("caps", caps, observed_monotonic_ns))
        return True

    def on_parser_counter(
        self,
        *,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            self.calls.append(
                (
                    "parser",
                    parser_bytes,
                    source_timestamp_ns,
                    observed_monotonic_ns,
                )
            )
        return True

    def on_decoded_frame(
        self,
        *,
        decoded_frames: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            self.calls.append(
                (
                    "decoded",
                    decoded_frames,
                    source_ntp_ns,
                    observed_monotonic_ns,
                )
            )
        return True

    def on_native_probe_failure(
        self,
        code: SourceProfileFailureCode,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            self.failures.append((code, observed_monotonic_ns))
        return False

    def close(self) -> None:
        with self._lock:
            self.close_count += 1


class _RaisingParserCallbacks(_RecordingCallbacks):
    def on_parser_counter(
        self,
        *,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        del parser_bytes, source_timestamp_ns, observed_monotonic_ns
        raise RuntimeError("injected parser callback failure")


class _ReentrantCallbacks(_RecordingCallbacks):
    def __init__(self) -> None:
        super().__init__()
        self.lease = None
        self._injected = False

    def on_rtp_caps(self, caps: NativeSourceCaps, *, observed_monotonic_ns: int) -> bool:
        result = super().on_rtp_caps(
            caps,
            observed_monotonic_ns=observed_monotonic_ns,
        )
        if not self._injected:
            self._injected = True
            assert self.lease is not None
            _triple(
                self.lease,
                pts_ns=300,
                byte_size=20_000,
                source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + 80_000_000,
                parser_observed_ns=81_000_000,
                decoded_observed_ns=82_000_000,
                ntp_observed_ns=83_000_000,
                source_ntp_ns=BASE_SOURCE_NTP_NS + 80_000_000,
            )
        return result


class _TerminalCallbacks(_RecordingCallbacks):
    def __init__(self, *, position: str, action: str) -> None:
        super().__init__()
        self.position = position
        self.action = action
        self.lease = None
        self.bridge = None
        self.lock_owned_during_callbacks: list[bool] = []

    def _terminal(self, position: str) -> bool:
        assert self.bridge is not None
        is_owned = getattr(self.bridge._lock, "_is_owned", lambda: False)()  # noqa: SLF001
        self.lock_owned_during_callbacks.append(is_owned)
        if position != self.position:
            return True
        if self.action == "close":
            assert self.lease is not None
            self.lease.close()
            return True
        if self.action == "false":
            return False
        raise RuntimeError(f"injected {position} callback failure")

    def on_rtp_caps(self, caps: NativeSourceCaps, *, observed_monotonic_ns: int) -> bool:
        super().on_rtp_caps(caps, observed_monotonic_ns=observed_monotonic_ns)
        return self._terminal("caps")

    def on_parser_counter(
        self,
        *,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        super().on_parser_counter(
            parser_bytes=parser_bytes,
            source_timestamp_ns=source_timestamp_ns,
            observed_monotonic_ns=observed_monotonic_ns,
        )
        return self._terminal("parser")

    def on_decoded_frame(
        self,
        *,
        decoded_frames: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        super().on_decoded_frame(
            decoded_frames=decoded_frames,
            source_ntp_ns=source_ntp_ns,
            observed_monotonic_ns=observed_monotonic_ns,
        )
        return self._terminal("decoded")


class _ExternalPathCallbacks(_RecordingCallbacks):
    def __init__(self, *, failure_action: str = "false") -> None:
        super().__init__()
        self.failure_action = failure_action
        self.bridge = None
        self.failure_lock_owned: list[bool] = []
        self.close_lock_owned: list[bool] = []

    def on_native_probe_failure(
        self,
        code: SourceProfileFailureCode,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        assert self.bridge is not None
        self.failure_lock_owned.append(self.bridge._lock._is_owned())  # noqa: SLF001
        super().on_native_probe_failure(
            code,
            observed_monotonic_ns=observed_monotonic_ns,
        )
        if self.failure_action == "raise":
            raise RuntimeError("injected native failure callback")
        return False

    def close(self) -> None:
        assert self.bridge is not None
        self.close_lock_owned.append(self.bridge._lock._is_owned())  # noqa: SLF001
        super().close()


class _BlockingCallbacks(_RecordingCallbacks):
    def __init__(self, *, fail_first: bool) -> None:
        super().__init__()
        self.fail_first = fail_first
        self.bridge = None
        self.entered = threading.Event()
        self.release = threading.Event()
        self._blocked = False
        self.lock_owned_during_callbacks: list[bool] = []

    def on_rtp_caps(self, caps: NativeSourceCaps, *, observed_monotonic_ns: int) -> bool:
        assert self.bridge is not None
        self.lock_owned_during_callbacks.append(
            self.bridge._lock._is_owned()  # noqa: SLF001
        )
        result = super().on_rtp_caps(
            caps,
            observed_monotonic_ns=observed_monotonic_ns,
        )
        if not self._blocked:
            self._blocked = True
            self.entered.set()
            assert self.release.wait(timeout=5)
            return result and not self.fail_first
        return result

    def on_parser_counter(
        self,
        *,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        assert self.bridge is not None
        self.lock_owned_during_callbacks.append(
            self.bridge._lock._is_owned()  # noqa: SLF001
        )
        return super().on_parser_counter(
            parser_bytes=parser_bytes,
            source_timestamp_ns=source_timestamp_ns,
            observed_monotonic_ns=observed_monotonic_ns,
        )

    def on_decoded_frame(
        self,
        *,
        decoded_frames: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        assert self.bridge is not None
        self.lock_owned_during_callbacks.append(
            self.bridge._lock._is_owned()  # noqa: SLF001
        )
        return super().on_decoded_frame(
            decoded_frames=decoded_frames,
            source_ntp_ns=source_ntp_ns,
            observed_monotonic_ns=observed_monotonic_ns,
        )


class _BlockingTerminalCallbacks(_RecordingCallbacks):
    def __init__(self) -> None:
        super().__init__()
        self.bridge = None
        self.entered = threading.Event()
        self.release = threading.Event()
        self._callback_active = threading.Event()
        self.terminal_overlap: list[bool] = []

    def on_rtp_caps(self, caps: NativeSourceCaps, *, observed_monotonic_ns: int) -> bool:
        self._callback_active.set()
        try:
            result = super().on_rtp_caps(
                caps,
                observed_monotonic_ns=observed_monotonic_ns,
            )
            self.entered.set()
            assert self.release.wait(timeout=5)
            return result
        finally:
            self._callback_active.clear()

    def on_native_probe_failure(
        self,
        code: SourceProfileFailureCode,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        self.terminal_overlap.append(self._callback_active.is_set())
        return super().on_native_probe_failure(
            code,
            observed_monotonic_ns=observed_monotonic_ns,
        )

    def close(self) -> None:
        self.terminal_overlap.append(self._callback_active.is_set())
        super().close()


class _BlockingStandaloneTerminalCallbacks(_RecordingCallbacks):
    def __init__(self, *, block_on: str) -> None:
        super().__init__()
        self.block_on = block_on
        self.entered = threading.Event()
        self.release = threading.Event()

    def _block(self, position: str) -> None:
        if self.block_on == position:
            self.entered.set()
            assert self.release.wait(timeout=5)

    def on_native_probe_failure(
        self,
        code: SourceProfileFailureCode,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        self._block("failure")
        return super().on_native_probe_failure(
            code,
            observed_monotonic_ns=observed_monotonic_ns,
        )

    def close(self) -> None:
        self._block("close")
        super().close()


def _bound_recording_bridge(*, capacity: int = 8):
    callbacks = _RecordingCallbacks()
    bridge = NativeSourceProbeBridge(capacity=capacity)
    lease = bridge.bind(callbacks)
    return callbacks, bridge, lease


def _caps(lease, *, observed_monotonic_ns: int = 0) -> None:
    assert lease.observe_rtp_caps("h264", observed_monotonic_ns)
    assert lease.observe_decoder_caps(1920, 1080, 25, 1, observed_monotonic_ns)


def _triple(
    lease,
    *,
    pts_ns: int,
    byte_size: int,
    source_timestamp_ns: int,
    parser_observed_ns: int,
    decoded_observed_ns: int,
    ntp_observed_ns: int,
    source_ntp_ns: int,
) -> None:
    assert lease.observe_parser_buffer(
        byte_size,
        source_timestamp_ns,
        pts_ns,
        parser_observed_ns,
    )
    assert lease.observe_decoded_buffer(pts_ns, decoded_observed_ns)
    assert lease.observe_nvds_ntp(pts_ns, source_ntp_ns, ntp_observed_ns)


def _correlated_ntp(lease, pts_ns: int, source_ntp_ns: int):
    method = getattr(lease, "correlated_ntp", None)
    assert callable(method), "source probe lease lacks correlated NTP completion"
    return method(pts_ns, source_ntp_ns)


def test_bridge_derives_caps_cumulative_counters_and_decimal_kbps_from_primitives() -> None:
    callbacks, _, lease = _bound_recording_bridge()
    _caps(lease)

    assert lease.observe_decoded_buffer(100, 2)
    assert lease.observe_nvds_ntp(100, BASE_SOURCE_NTP_NS, 3)
    assert lease.observe_parser_buffer(20_000, BASE_SOURCE_TIMESTAMP_NS, 100, 1)
    assert callbacks.calls == []

    assert lease.observe_nvds_ntp(
        200,
        BASE_SOURCE_NTP_NS + 40_000_000,
        40_000_000,
    )
    assert lease.observe_decoded_buffer(200, 41_000_000)
    assert lease.observe_parser_buffer(
        20_000,
        BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        200,
        43_000_000,
    )

    assert callbacks.calls == [
        (
            "caps",
            NativeSourceCaps(
                codec="h264",
                width=1920,
                height=1080,
                fps=25.0,
                bitrate_kbps=4_000,
            ),
            43_000_000,
        ),
        (
            "parser",
            40_000,
            BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
            43_000_000,
        ),
        (
            "decoded",
            2,
            BASE_SOURCE_NTP_NS + 40_000_000,
            43_000_000,
        ),
    ]


def test_correlated_ntp_exists_only_after_exact_callback_forwarded_commit() -> None:
    callbacks, _, lease = _bound_recording_bridge()
    _caps(lease)

    assert lease.observe_nvds_ntp(50, BASE_SOURCE_NTP_NS - 1, 1)
    assert _correlated_ntp(lease, 50, BASE_SOURCE_NTP_NS - 1) is None
    assert callbacks.calls == []

    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=2,
        decoded_observed_ns=3,
        ntp_observed_ns=4,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )
    assert _correlated_ntp(lease, 100, BASE_SOURCE_NTP_NS) is None
    assert callbacks.calls == []

    assert lease.observe_nvds_ntp(
        200,
        BASE_SOURCE_NTP_NS + 40_000_000,
        41_000_000,
    )
    assert (
        _correlated_ntp(
            lease,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
        )
        is None
    )
    assert lease.observe_parser_buffer(
        20_000,
        BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        200,
        42_000_000,
    )
    assert (
        _correlated_ntp(
            lease,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
        )
        is None
    )
    assert lease.observe_decoded_buffer(200, 43_000_000)

    completion = _correlated_ntp(
        lease,
        200,
        BASE_SOURCE_NTP_NS + 40_000_000,
    )
    assert completion is not None
    assert completion.pts_ns == 200
    assert completion.source_ntp_ns == BASE_SOURCE_NTP_NS + 40_000_000
    assert completion.parser_observed_monotonic_ns == 42_000_000
    assert completion.decoded_observed_monotonic_ns == 43_000_000
    assert completion.ntp_observed_monotonic_ns == 41_000_000
    assert completion.completed_monotonic_ns == 43_000_000
    assert _correlated_ntp(lease, 201, completion.source_ntp_ns) is None
    assert _correlated_ntp(lease, 200, completion.source_ntp_ns + 1) is None
    with pytest.raises(AttributeError):
        completion.pts_ns = 201


def test_correlated_ntp_is_none_during_callback_and_after_close_or_rebind() -> None:
    callbacks = _BlockingCallbacks(fail_first=False)
    bridge = NativeSourceProbeBridge(capacity=8)
    callbacks.bridge = bridge
    lease = bridge.bind(callbacks)
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            _triple,
            lease,
            pts_ns=200,
            byte_size=20_000,
            source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
            parser_observed_ns=41_000_000,
            decoded_observed_ns=42_000_000,
            ntp_observed_ns=43_000_000,
            source_ntp_ns=BASE_SOURCE_NTP_NS + 40_000_000,
        )
        assert callbacks.entered.wait(timeout=5)
        assert (
            _correlated_ntp(
                lease,
                200,
                BASE_SOURCE_NTP_NS + 40_000_000,
            )
            is None
        )
        callbacks.release.set()
        future.result(timeout=5)

    assert (
        _correlated_ntp(
            lease,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
        )
        is not None
    )
    lease.close()
    assert (
        _correlated_ntp(
            lease,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
        )
        is None
    )
    current = bridge.bind(_RecordingCallbacks())
    assert (
        _correlated_ntp(
            lease,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
        )
        is None
    )
    assert (
        _correlated_ntp(
            current,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
        )
        is None
    )


def test_failed_callback_never_publishes_correlated_ntp() -> None:
    callbacks = _TerminalCallbacks(position="decoded", action="false")
    bridge = NativeSourceProbeBridge(capacity=8)
    callbacks.bridge = bridge
    lease = bridge.bind(callbacks)
    callbacks.lease = lease
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )
    assert lease.observe_parser_buffer(
        20_000,
        BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        200,
        41_000_000,
    )
    assert lease.observe_decoded_buffer(200, 42_000_000)
    assert not lease.observe_nvds_ntp(
        200,
        BASE_SOURCE_NTP_NS + 40_000_000,
        43_000_000,
    )

    assert (
        _correlated_ntp(
            lease,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
        )
        is None
    )


def test_bridge_waits_for_oldest_parser_record_and_serializes_cross_branch_order() -> None:
    callbacks, _, lease = _bound_recording_bridge()
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )

    assert lease.observe_parser_buffer(
        20_000,
        BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        200,
        41_000_000,
    )
    assert lease.observe_parser_buffer(
        20_000,
        BASE_SOURCE_TIMESTAMP_NS + 80_000_000,
        300,
        81_000_000,
    )
    assert lease.observe_decoded_buffer(300, 82_000_000)
    assert lease.observe_nvds_ntp(
        300,
        BASE_SOURCE_NTP_NS + 80_000_000,
        83_000_000,
    )
    assert callbacks.calls == []

    assert lease.observe_nvds_ntp(
        200,
        BASE_SOURCE_NTP_NS + 40_000_000,
        43_000_000,
    )
    assert lease.observe_decoded_buffer(200, 42_000_000)

    assert [call[0] for call in callbacks.calls] == [
        "caps",
        "parser",
        "decoded",
        "caps",
        "parser",
        "decoded",
    ]
    assert callbacks.calls[1][1:3] == (
        40_000,
        BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
    )
    assert callbacks.calls[4][1:3] == (
        60_000,
        BASE_SOURCE_TIMESTAMP_NS + 80_000_000,
    )
    assert [callbacks.calls[index][1] for index in (2, 5)] == [2, 3]
    assert [callbacks.calls[index][-1] for index in range(len(callbacks.calls))] == [
        43_000_000,
        43_000_000,
        43_000_000,
        83_000_000,
        83_000_000,
        83_000_000,
    ]
    assert callbacks.calls[0][1].bitrate_kbps == 4_000
    assert callbacks.calls[3][1].bitrate_kbps == 4_000


def test_running_average_bitrate_refreshes_caps_for_every_observation() -> None:
    callbacks, bridge, lease = _bound_recording_bridge()
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )
    _triple(
        lease,
        pts_ns=200,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        parser_observed_ns=41_000_000,
        decoded_observed_ns=42_000_000,
        ntp_observed_ns=43_000_000,
        source_ntp_ns=BASE_SOURCE_NTP_NS + 40_000_000,
    )
    _triple(
        lease,
        pts_ns=300,
        byte_size=60_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + 80_000_000,
        parser_observed_ns=81_000_000,
        decoded_observed_ns=82_000_000,
        ntp_observed_ns=83_000_000,
        source_ntp_ns=BASE_SOURCE_NTP_NS + 80_000_000,
    )

    assert bridge is not None
    assert [call[1].bitrate_kbps for call in callbacks.calls if call[0] == "caps"] == [4_000, 8_000]


def test_exact_duplicate_primitives_coalesce_without_changing_counters() -> None:
    callbacks, bridge, lease = _bound_recording_bridge()
    _caps(lease)
    _caps(lease)
    for _ in range(2):
        assert lease.observe_parser_buffer(
            20_000,
            BASE_SOURCE_TIMESTAMP_NS,
            100,
            1,
        )
        assert lease.observe_decoded_buffer(100, 2)
        assert lease.observe_nvds_ntp(100, BASE_SOURCE_NTP_NS, 3)
    assert bridge is not None
    _triple(
        lease,
        pts_ns=200,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        parser_observed_ns=41_000_000,
        decoded_observed_ns=42_000_000,
        ntp_observed_ns=43_000_000,
        source_ntp_ns=BASE_SOURCE_NTP_NS + 40_000_000,
    )

    assert callbacks.calls[1][1] == 40_000
    assert callbacks.calls[2][1] == 2
    assert callbacks.failures == []


@pytest.mark.parametrize(
    ("method_name", "arguments", "has_valid_observation_time"),
    [
        ("observe_rtp_caps", ("vp9", 0), True),
        ("observe_rtp_caps", ("h264", True), False),
        ("observe_decoder_caps", (True, 1080, 25, 1, 0), True),
        ("observe_decoder_caps", (1920, -1, 25, 1, 0), True),
        ("observe_decoder_caps", (1920, 1080, 0, 1, 0), True),
        ("observe_decoder_caps", (1920, 1080, 25, 0, 0), True),
        ("observe_decoder_caps", (1920, 1080, 241, 1, 0), True),
        ("observe_parser_buffer", (True, 1, 1, 0), True),
        ("observe_parser_buffer", (1, -1, 1, 0), True),
        ("observe_parser_buffer", (1, 1, GST_CLOCK_TIME_NONE, 0), True),
        ("observe_decoded_buffer", (GST_CLOCK_TIME_NONE, 0), True),
        ("observe_nvds_ntp", (1, GST_CLOCK_TIME_NONE, 0), True),
        ("observe_nvds_ntp", (1, 1, INT64_MAX + 1), False),
    ],
)
def test_bridge_rejects_non_exact_int64_clock_none_and_invalid_fps(
    method_name: str,
    arguments: tuple[object, ...],
    has_valid_observation_time: bool,
) -> None:
    callbacks, _, lease = _bound_recording_bridge()

    if has_valid_observation_time:
        assert not getattr(lease, method_name)(*arguments)
        assert callbacks.failures == [
            (SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE, arguments[-1])
        ]
        assert callbacks.close_count == 1
    else:
        with pytest.raises(ValueError):
            getattr(lease, method_name)(*arguments)
        assert callbacks.failures == []
        assert callbacks.close_count == 0


def test_pending_capacity_overflow_is_authoritative_and_permanently_closes_lease() -> None:
    callbacks, _, lease = _bound_recording_bridge(capacity=1)
    _caps(lease)

    assert lease.observe_decoded_buffer(100, 1)
    assert not lease.observe_decoded_buffer(200, 2)
    assert callbacks.failures == [(SourceProfileFailureCode.BUFFER_OVERFLOW, 2)]
    assert callbacks.close_count == 1
    assert not lease.observe_nvds_ntp(100, BASE_SOURCE_NTP_NS, 3)


def test_capacity_bounds_unique_pending_pts_across_all_branches() -> None:
    callbacks, _, lease = _bound_recording_bridge(capacity=2)

    assert lease.observe_decoded_buffer(100, 1)
    assert lease.observe_nvds_ntp(200, BASE_SOURCE_NTP_NS, 2)
    assert not lease.observe_parser_buffer(1, 1, 300, 3)
    assert callbacks.failures == [(SourceProfileFailureCode.BUFFER_OVERFLOW, 3)]
    assert callbacks.close_count == 1


@pytest.mark.parametrize(
    "conflicting_action",
    [
        lambda lease: lease.observe_nvds_ntp(100, BASE_SOURCE_NTP_NS + 1, 3),
        lambda lease: lease.observe_decoded_buffer(100, 3),
    ],
)
def test_conflicting_duplicate_primitives_report_invalid_provenance(conflicting_action) -> None:
    callbacks, _, lease = _bound_recording_bridge()
    assert lease.observe_decoded_buffer(100, 2)
    assert lease.observe_nvds_ntp(100, BASE_SOURCE_NTP_NS, 3)

    assert not conflicting_action(lease)
    assert callbacks.failures == [(SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE, 3)]
    assert callbacks.close_count == 1


def test_parser_source_timestamp_regression_reports_counter_regression() -> None:
    callbacks, _, lease = _bound_recording_bridge()
    assert lease.observe_parser_buffer(1, 10, 100, 1)

    assert not lease.observe_parser_buffer(1, 9, 200, 2)
    assert callbacks.failures == [(SourceProfileFailureCode.COUNTER_REGRESSION, 2)]
    assert callbacks.close_count == 1


@pytest.mark.parametrize(
    "failure_code",
    [
        SourceProfileFailureCode.BUFFER_OVERFLOW,
        SourceProfileFailureCode.COUNTER_REGRESSION,
        SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE,
    ],
)
def test_native_probe_failures_enter_tracker_authoritative_failure_machinery(
    failure_code: SourceProfileFailureCode,
) -> None:
    tracker = profile_fixtures._tracker()
    callback = tracker.bind_source(
        camera_id=profile_fixtures.CAMERA_IDS[0],
        resolved_url=profile_fixtures._resolved_url(0),
        commitment_key=profile_fixtures.COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )

    assert not callback.on_native_probe_failure(
        failure_code,
        observed_monotonic_ns=1,
    )
    assert failure_code.value in profile_fixtures._failures(
        tracker,
        callback.camera_id,
    )
    failure_receipt = tracker._milestone_receipts_unlocked()[-1]  # noqa: SLF001
    assert failure_receipt.failure_code == failure_code
    assert failure_receipt.event_monotonic_ns == 1

    with pytest.raises(ValueError, match="native probe failure"):
        callback.on_native_probe_failure(
            SourceProfileFailureCode.PROFILE_MISMATCH,
            observed_monotonic_ns=2,
        )


def test_old_lease_is_inert_and_cannot_close_rebound_generation() -> None:
    first = _RecordingCallbacks()
    second = _RecordingCallbacks()
    bridge = NativeSourceProbeBridge(capacity=4)
    old = bridge.bind(first)

    with pytest.raises(RuntimeError, match="close"):
        bridge.bind(second)
    old.close()
    old.close()
    current = bridge.bind(second)
    old.close()

    assert first.close_count == 1
    assert second.close_count == 0
    assert not old.observe_rtp_caps("h264", 0)
    assert current.observe_rtp_caps("h264", 0)
    current.close()
    assert second.close_count == 1


def test_lease_gc_closes_only_its_generation_and_repr_is_redacted() -> None:
    callbacks = _RecordingCallbacks()
    bridge = NativeSourceProbeBridge(capacity=4)
    lease = bridge.bind(callbacks)
    reference = weakref.ref(lease)

    assert "callbacks" not in repr(lease).lower()
    assert repr(callbacks) not in repr(lease)
    assert "callbacks" not in repr(bridge).lower()
    del lease
    gc.collect()

    assert reference() is None
    assert callbacks.close_count == 1


def test_live_lease_keeps_bridge_generation_alive_until_lease_close() -> None:
    callbacks = _RecordingCallbacks()
    bridge = NativeSourceProbeBridge(capacity=4)
    bridge_reference = weakref.ref(bridge)
    lease = bridge.bind(callbacks)

    del bridge
    gc.collect()

    assert bridge_reference() is not None
    assert lease.observe_rtp_caps("h264", 0)
    lease.close()
    assert callbacks.close_count == 1


def test_callback_exception_closes_generation_without_silent_partial_delivery() -> None:
    callbacks = _RaisingParserCallbacks()
    bridge = NativeSourceProbeBridge(capacity=4)
    lease = bridge.bind(callbacks)
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )

    with pytest.raises(RuntimeError, match="injected parser"):
        _triple(
            lease,
            pts_ns=200,
            byte_size=20_000,
            source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
            parser_observed_ns=41_000_000,
            decoded_observed_ns=42_000_000,
            ntp_observed_ns=43_000_000,
            source_ntp_ns=BASE_SOURCE_NTP_NS + 40_000_000,
        )
    assert callbacks.close_count == 1
    assert not lease.observe_decoded_buffer(300, 44_000_000)


def test_completed_triple_replay_is_bounded_idempotent_and_does_not_consume_capacity() -> None:
    callbacks, bridge, lease = _bound_recording_bridge(capacity=1)
    _caps(lease)
    first = {
        "pts_ns": 100,
        "byte_size": 20_000,
        "source_timestamp_ns": BASE_SOURCE_TIMESTAMP_NS,
        "parser_observed_ns": 1,
        "decoded_observed_ns": 2,
        "ntp_observed_ns": 3,
        "source_ntp_ns": BASE_SOURCE_NTP_NS,
    }
    _triple(lease, **first)
    _triple(lease, **first)
    _triple(
        lease,
        pts_ns=200,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        parser_observed_ns=41_000_000,
        decoded_observed_ns=42_000_000,
        ntp_observed_ns=43_000_000,
        source_ntp_ns=BASE_SOURCE_NTP_NS + 40_000_000,
    )

    assert callbacks.failures == []
    active = bridge._active  # noqa: SLF001
    assert active is not None
    assert len(active.completed_replays) <= 1


def test_conflicting_completed_triple_replay_is_authoritative_failure() -> None:
    callbacks, _, lease = _bound_recording_bridge(capacity=1)
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )

    assert not lease.observe_decoded_buffer(100, 4)
    assert callbacks.failures == [(SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE, 4)]
    assert callbacks.close_count == 1


def test_reentrant_callbacks_cannot_overtake_the_current_serialized_batch() -> None:
    callbacks = _ReentrantCallbacks()
    bridge = NativeSourceProbeBridge(capacity=4)
    lease = bridge.bind(callbacks)
    callbacks.lease = lease
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )
    _triple(
        lease,
        pts_ns=200,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        parser_observed_ns=41_000_000,
        decoded_observed_ns=42_000_000,
        ntp_observed_ns=43_000_000,
        source_ntp_ns=BASE_SOURCE_NTP_NS + 40_000_000,
    )

    assert [(call[0], call[-1]) for call in callbacks.calls] == [
        ("caps", 43_000_000),
        ("parser", 43_000_000),
        ("decoded", 43_000_000),
        ("caps", 83_000_000),
        ("parser", 83_000_000),
        ("decoded", 83_000_000),
    ]
    assert callbacks.failures == []


@pytest.mark.parametrize("position", ("caps", "parser", "decoded"))
@pytest.mark.parametrize("action", ("close", "false", "raise"))
def test_terminal_callback_paths_are_outside_lock_serialized_and_close_once(
    position: str,
    action: str,
) -> None:
    callbacks = _TerminalCallbacks(position=position, action=action)
    bridge = NativeSourceProbeBridge(capacity=4)
    lease = bridge.bind(callbacks)
    callbacks.lease = lease
    callbacks.bridge = bridge
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )

    assert lease.observe_parser_buffer(
        20_000,
        BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        200,
        41_000_000,
    )
    assert lease.observe_decoded_buffer(200, 42_000_000)
    if action == "raise":
        with pytest.raises(RuntimeError, match=f"injected {position}"):
            lease.observe_nvds_ntp(
                200,
                BASE_SOURCE_NTP_NS + 40_000_000,
                43_000_000,
            )
    else:
        assert not lease.observe_nvds_ntp(
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
            43_000_000,
        )

    expected_call_count = {"caps": 1, "parser": 2, "decoded": 3}[position]
    assert [call[0] for call in callbacks.calls] == [
        "caps",
        "parser",
        "decoded",
    ][:expected_call_count]
    assert callbacks.lock_owned_during_callbacks
    assert not any(callbacks.lock_owned_during_callbacks)
    assert callbacks.close_count == 1
    assert not lease.observe_decoded_buffer(300, 44_000_000)


@pytest.mark.parametrize("failure_action", ("false", "raise"))
def test_failure_and_close_callbacks_are_outside_lock_and_cleanup_once(
    failure_action: str,
) -> None:
    callbacks = _ExternalPathCallbacks(failure_action=failure_action)
    bridge = NativeSourceProbeBridge(capacity=4)
    callbacks.bridge = bridge
    lease = bridge.bind(callbacks)

    if failure_action == "raise":
        with pytest.raises(RuntimeError, match="injected native failure"):
            lease.observe_rtp_caps("vp9", 1)
    else:
        assert not lease.observe_rtp_caps("vp9", 1)

    assert callbacks.failure_lock_owned == [False]
    assert callbacks.close_lock_owned == [False]
    assert callbacks.close_count == 1
    lease.close()
    assert callbacks.close_count == 1


def test_standalone_close_callback_is_outside_lock_and_exactly_once() -> None:
    callbacks = _ExternalPathCallbacks()
    bridge = NativeSourceProbeBridge(capacity=4)
    callbacks.bridge = bridge
    lease = bridge.bind(callbacks)

    lease.close()
    lease.close()

    assert callbacks.failure_lock_owned == []
    assert callbacks.close_lock_owned == [False]
    assert callbacks.close_count == 1


@pytest.mark.parametrize("fail_first", (False, True))
def test_two_thread_dispatch_waiters_serialize_and_wake(
    fail_first: bool,
) -> None:
    callbacks = _BlockingCallbacks(fail_first=fail_first)
    bridge = NativeSourceProbeBridge(capacity=4)
    callbacks.bridge = bridge
    lease = bridge.bind(callbacks)
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )
    for pts_ns, elapsed_ns in ((200, 40_000_000), (300, 80_000_000)):
        assert lease.observe_parser_buffer(
            20_000,
            BASE_SOURCE_TIMESTAMP_NS + elapsed_ns,
            pts_ns,
            elapsed_ns + 1,
        )
        assert lease.observe_decoded_buffer(pts_ns, elapsed_ns + 2)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            lease.observe_nvds_ntp,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
            43_000_000,
        )
        assert callbacks.entered.wait(timeout=5)
        second = executor.submit(
            lease.observe_nvds_ntp,
            300,
            BASE_SOURCE_NTP_NS + 80_000_000,
            83_000_000,
        )
        assert not second.done()
        callbacks.release.set()
        assert first.result(timeout=5) is (not fail_first)
        assert second.result(timeout=5) is (not fail_first)

    expected = (
        ["caps"]
        if fail_first
        else [
            "caps",
            "parser",
            "decoded",
            "caps",
            "parser",
            "decoded",
        ]
    )
    assert [call[0] for call in callbacks.calls] == expected
    assert callbacks.lock_owned_during_callbacks
    assert not any(callbacks.lock_owned_during_callbacks)
    assert callbacks.close_count == int(fail_first)


@pytest.mark.parametrize("terminal_action", ("close", "invalid"))
def test_concurrent_terminal_paths_wait_for_inflight_callback(
    terminal_action: str,
) -> None:
    callbacks = _BlockingTerminalCallbacks()
    bridge = NativeSourceProbeBridge(capacity=4)
    callbacks.bridge = bridge
    lease = bridge.bind(callbacks)
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )
    assert lease.observe_parser_buffer(
        20_000,
        BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
        200,
        41_000_000,
    )
    assert lease.observe_decoded_buffer(200, 42_000_000)

    with ThreadPoolExecutor(max_workers=2) as executor:
        dispatch = executor.submit(
            lease.observe_nvds_ntp,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
            43_000_000,
        )
        assert callbacks.entered.wait(timeout=5)
        if terminal_action == "close":
            terminal = executor.submit(lease.close)
        else:
            terminal = executor.submit(lease.observe_rtp_caps, "vp9", 44_000_000)
        assert not terminal.done()
        callbacks.release.set()
        assert dispatch.result(timeout=5) is False
        terminal_result = terminal.result(timeout=5)
        if terminal_action == "invalid":
            assert terminal_result is False

    assert [call[0] for call in callbacks.calls] == ["caps"]
    assert callbacks.terminal_overlap == ([False] if terminal_action == "close" else [False, False])
    assert callbacks.close_count == 1
    assert not lease.observe_decoded_buffer(300, 45_000_000)


@pytest.mark.parametrize("terminal_action", ("close", "failure"))
def test_non_inflight_terminal_reservation_blocks_rebind_until_callback_finishes(
    terminal_action: str,
) -> None:
    callbacks = _BlockingStandaloneTerminalCallbacks(block_on=terminal_action)
    bridge = NativeSourceProbeBridge(capacity=4)
    lease = bridge.bind(callbacks)
    replacement_callbacks = _RecordingCallbacks()

    with ThreadPoolExecutor(max_workers=2) as executor:
        if terminal_action == "close":
            terminal = executor.submit(lease.close)
        else:
            terminal = executor.submit(lease.observe_rtp_caps, "vp9", 1)
        assert callbacks.entered.wait(timeout=5)
        replacement = executor.submit(bridge.bind, replacement_callbacks)
        try:
            replacement_lease = replacement.result(timeout=0.2)
            replacement_completed_during_terminal = True
        except FutureTimeoutError:
            replacement_completed_during_terminal = False
            replacement_lease = None
        callbacks.release.set()
        terminal_result = terminal.result(timeout=5)
        if terminal_action == "failure":
            assert terminal_result is False
        if replacement_lease is None:
            replacement_lease = replacement.result(timeout=5)

    assert not replacement_completed_during_terminal
    assert callbacks.close_count == 1
    assert callbacks.failures == (
        []
        if terminal_action == "close"
        else [(SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE, 1)]
    )
    replacement_lease.close()
    assert replacement_callbacks.close_count == 1


@pytest.mark.parametrize("error_type", (RuntimeError, _HousekeepingAbort))
def test_initial_baseline_housekeeping_failure_closes_and_wakes_waiters(
    error_type: type[BaseException],
    monkeypatch,
) -> None:
    callbacks = _RecordingCallbacks()
    bridge = NativeSourceProbeBridge(capacity=4)
    lease = bridge.bind(callbacks)
    _caps(lease)
    assert lease.observe_parser_buffer(
        20_000,
        BASE_SOURCE_TIMESTAMP_NS,
        100,
        1,
    )
    assert lease.observe_decoded_buffer(100, 2)

    commit_entered = threading.Event()
    release_commit = threading.Event()
    original_commit = source_probe_module.NativeSourceProbeBridge._commit_completed_locked

    def fail_initial_commit(self, state, record, **kwargs):
        if kwargs["forwarded_at_monotonic_ns"] is None:
            commit_entered.set()
            assert release_commit.wait(timeout=5)
            raise error_type("injected initial baseline housekeeping failure")
        return original_commit(self, state, record, **kwargs)

    monkeypatch.setattr(
        source_probe_module.NativeSourceProbeBridge,
        "_commit_completed_locked",
        fail_initial_commit,
    )
    executor = ThreadPoolExecutor(max_workers=2)
    waiter = None
    try:
        dispatch = executor.submit(
            lease.observe_nvds_ntp,
            100,
            BASE_SOURCE_NTP_NS,
            3,
        )
        assert commit_entered.wait(timeout=5)
        waiter = executor.submit(
            lease.observe_parser_buffer,
            20_000,
            BASE_SOURCE_TIMESTAMP_NS + 40_000_000,
            200,
            41_000_000,
        )
        assert not waiter.done()
        release_commit.set()
        with pytest.raises(error_type, match="initial baseline housekeeping"):
            dispatch.result(timeout=5)
        completed, _ = wait((waiter,), timeout=0.5)
        waiter_woke_without_cleanup = waiter in completed
        close_count_before_cleanup = callbacks.close_count
    finally:
        release_commit.set()
        bridge.close()
        executor.shutdown(wait=True)

    assert waiter is not None
    assert waiter_woke_without_cleanup
    assert waiter.result(timeout=5) is False
    assert callbacks.calls == []
    assert close_count_before_cleanup == 1
    assert callbacks.close_count == 1
    assert not lease.observe_decoded_buffer(300, 42_000_000)
    replacement_callbacks = _RecordingCallbacks()
    replacement_lease = bridge.bind(replacement_callbacks)
    replacement_lease.close()
    assert replacement_callbacks.close_count == 1


@pytest.mark.parametrize("error_type", (RuntimeError, _HousekeepingAbort))
def test_post_delivery_housekeeping_failure_closes_and_wakes_waiters(
    error_type: type[BaseException],
    monkeypatch,
) -> None:
    callbacks = _BlockingCallbacks(fail_first=False)
    bridge = NativeSourceProbeBridge(capacity=4)
    callbacks.bridge = bridge
    lease = bridge.bind(callbacks)
    _caps(lease)
    _triple(
        lease,
        pts_ns=100,
        byte_size=20_000,
        source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS,
        parser_observed_ns=1,
        decoded_observed_ns=2,
        ntp_observed_ns=3,
        source_ntp_ns=BASE_SOURCE_NTP_NS,
    )
    for pts_ns, elapsed_ns in ((200, 40_000_000), (300, 80_000_000)):
        assert lease.observe_parser_buffer(
            20_000,
            BASE_SOURCE_TIMESTAMP_NS + elapsed_ns,
            pts_ns,
            elapsed_ns + 1,
        )
        assert lease.observe_decoded_buffer(pts_ns, elapsed_ns + 2)

    original_commit = source_probe_module.NativeSourceProbeBridge._commit_completed_locked

    def fail_forwarded_commit(self, state, record, **kwargs):
        if kwargs["forwarded_at_monotonic_ns"] is not None:
            raise error_type("injected post-delivery housekeeping failure")
        return original_commit(self, state, record, **kwargs)

    monkeypatch.setattr(
        source_probe_module.NativeSourceProbeBridge,
        "_commit_completed_locked",
        fail_forwarded_commit,
    )
    executor = ThreadPoolExecutor(max_workers=2)
    waiter = None
    try:
        dispatch = executor.submit(
            lease.observe_nvds_ntp,
            200,
            BASE_SOURCE_NTP_NS + 40_000_000,
            43_000_000,
        )
        assert callbacks.entered.wait(timeout=5)
        waiter = executor.submit(
            lease.observe_nvds_ntp,
            300,
            BASE_SOURCE_NTP_NS + 80_000_000,
            83_000_000,
        )
        assert not waiter.done()
        callbacks.release.set()
        with pytest.raises(error_type, match="post-delivery housekeeping"):
            dispatch.result(timeout=5)
        completed, _ = wait((waiter,), timeout=0.5)
        waiter_woke_without_cleanup = waiter in completed
        close_count_before_cleanup = callbacks.close_count
    finally:
        callbacks.release.set()
        bridge.close()
        executor.shutdown(wait=True)

    assert waiter is not None
    assert waiter_woke_without_cleanup
    assert waiter.result(timeout=5) is False
    assert [call[0] for call in callbacks.calls] == ["caps", "parser", "decoded"]
    assert close_count_before_cleanup == 1
    assert callbacks.close_count == 1
    replacement_callbacks = _RecordingCallbacks()
    replacement_lease = bridge.bind(replacement_callbacks)
    replacement_lease.close()
    assert replacement_callbacks.close_count == 1


def test_concurrent_decoder_and_ntp_branches_remain_bounded_and_parser_serialized() -> None:
    callbacks, _, lease = _bound_recording_bridge(capacity=32)
    _caps(lease)
    points = tuple(range(100, 1_100, 100))
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for index, pts_ns in enumerate(reversed(points)):
            original_index = points.index(pts_ns)
            futures.append(
                executor.submit(
                    lease.observe_decoded_buffer,
                    pts_ns,
                    original_index * 40_000_000 + 2,
                )
            )
            futures.append(
                executor.submit(
                    lease.observe_nvds_ntp,
                    pts_ns,
                    BASE_SOURCE_NTP_NS + original_index * 40_000_000,
                    original_index * 40_000_000 + 3,
                )
            )
        assert all(future.result() for future in futures)
    for index, pts_ns in enumerate(points):
        assert lease.observe_parser_buffer(
            20_000,
            BASE_SOURCE_TIMESTAMP_NS + index * 40_000_000,
            pts_ns,
            index * 40_000_000 + 1,
        )

    assert callbacks.failures == []
    assert [call[1] for call in callbacks.calls if call[0] == "decoded"] == list(range(2, 11))


def test_bridge_has_no_native_runtime_or_precomposed_caps_inputs() -> None:
    source = inspect.getsource(source_probe_module)
    lowered = source.lower()
    for forbidden in ("gi.repository", "gstreamer", "pyds", "deepstream", "sourceplan"):
        assert forbidden not in lowered
    primitive_methods = (
        "observe_rtp_caps",
        "observe_decoder_caps",
        "observe_parser_buffer",
        "observe_decoded_buffer",
        "observe_nvds_ntp",
    )
    for method_name in primitive_methods:
        signature = inspect.signature(getattr(source_probe_module.SourceProbeLease, method_name))
        assert all(
            parameter.annotation is not NativeSourceCaps
            for parameter in signature.parameters.values()
        )


@pytest.fixture(scope="module")
def ready_proof():
    tracker, signer = profile_fixtures._proof_tracker_or_plain()
    assert signer is not None
    callbacks = profile_fixtures._bind_all(tracker)
    profile_fixtures._observe_all_through(
        callbacks,
        final_elapsed_ns=profile_fixtures.PREWARM_NS,
    )
    envelope = tracker.authoritative_proof()
    return envelope, signer, callbacks


def _issue(envelope, signer, **overrides):
    arguments = {
        "native_leases": (),
        "expected_key_id": profile_fixtures.SOURCE_PROOF_KEY_ID,
        "trusted_public_key": signer.public_key,
        "expected_milestone_authenticator_key_id": (
            profile_fixtures.MILESTONE_AUTHENTICATOR_KEY_ID
        ),
        "trusted_milestone_authenticator_key": (profile_fixtures.MILESTONE_AUTHENTICATOR_KEY),
        "expected_site_id": profile_fixtures.SITE_ID,
        "expected_source_identity_commitments": (profile_fixtures._expected_source_commitments()),
        "expected_epoch": envelope.epoch,
        "expected_epoch_started_generation": envelope.epoch_started_generation,
    }
    arguments.update(overrides)
    return verify_and_issue_exact_20_prewarm_receipt(envelope, **arguments)


def test_ready_aggregate_proof_without_native_bridges_cannot_issue_receipt(
    ready_proof,
) -> None:
    envelope, signer, _ = ready_proof

    with pytest.raises(ValueError, match="native|lease|20"):
        _issue(envelope, signer)


def test_exact_20_receipt_refuses_plain_snapshot_bad_pins_and_non20(
    ready_proof,
) -> None:
    envelope, signer, _ = ready_proof

    with pytest.raises(ValueError, match="envelope"):
        _issue(envelope.snapshot, signer)
    with pytest.raises(ValueError, match="verification|trusted"):
        _issue(envelope, signer, expected_key_id="wrong-proof-key")
    with pytest.raises(ValueError, match="exact 20|identit|verification"):
        _issue(
            envelope,
            signer,
            expected_source_identity_commitments=(
                profile_fixtures._expected_source_commitments()[:-1]
            ),
        )


def test_exact_20_receipt_refuses_not_ready_and_failed_proofs() -> None:
    not_ready_tracker, signer = profile_fixtures._proof_tracker_or_plain()
    assert signer is not None
    callbacks = profile_fixtures._bind_all(not_ready_tracker)
    for callback in callbacks:
        assert profile_fixtures._observe(
            callback,
            sample_number=1,
            elapsed_ns=0,
        )
    with pytest.raises(ValueError, match="ready|prewarm"):
        _issue(not_ready_tracker.authoritative_proof(), signer)

    failed_tracker, failed_signer = profile_fixtures._proof_tracker_or_plain()
    assert failed_signer is not None
    failed_callbacks = profile_fixtures._bind_all(failed_tracker)
    assert not failed_callbacks[0].on_native_probe_failure(
        SourceProfileFailureCode.COUNTER_REGRESSION,
        observed_monotonic_ns=1,
    )
    with pytest.raises(ValueError, match="failure|ready|prewarm"):
        _issue(failed_tracker.authoritative_proof(), failed_signer)


def test_receipt_api_accepts_only_authoritative_envelope_and_explicit_pins() -> None:
    signature = inspect.signature(verify_and_issue_exact_20_prewarm_receipt)
    assert signature.parameters["envelope"].annotation in {
        NativeSourceProfileProofEnvelopeV1,
        "NativeSourceProfileProofEnvelopeV1",
    }
    assert set(signature.parameters) == {
        "envelope",
        "native_leases",
        "expected_key_id",
        "trusted_public_key",
        "expected_milestone_authenticator_key_id",
        "trusted_milestone_authenticator_key",
        "expected_site_id",
        "expected_source_identity_commitments",
        "expected_epoch",
        "expected_epoch_started_generation",
    }


def _source_probe_traceback_text(error: BaseException) -> str:
    pending = [error]
    seen: set[int] = set()
    parts: list[str] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_code.co_filename.endswith("protector/pilot/runtime/source_probe.py"):
                parts.extend(f"{name}={value!r}" for name, value in frame.f_locals.items())
            traceback = traceback.tb_next
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(parts)


def _source_probe_traceback_receipts(
    error: BaseException,
) -> tuple[Exact20NativePrewarmReceiptV1, ...]:
    pending = [error]
    seen_errors: set[int] = set()
    receipts: dict[int, Exact20NativePrewarmReceiptV1] = {}
    while pending:
        current = pending.pop()
        if id(current) in seen_errors:
            continue
        seen_errors.add(id(current))
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_code.co_filename.endswith("protector/pilot/runtime/source_probe.py"):
                for value in frame.f_locals.values():
                    if type(value) is Exact20NativePrewarmReceiptV1:
                        receipts[id(value)] = value
            traceback = traceback.tb_next
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return tuple(receipts.values())


def _low_level_receipt_clone(
    receipt: Exact20NativePrewarmReceiptV1,
) -> Exact20NativePrewarmReceiptV1:
    clone = object.__new__(Exact20NativePrewarmReceiptV1)
    for slot in Exact20NativePrewarmReceiptV1.__slots__:
        if slot != "__weakref__":
            object.__setattr__(clone, slot, getattr(receipt, slot))
    return clone


def test_receipt_verification_failure_scrubs_milestone_key_from_tracebacks(
    ready_proof,
) -> None:
    envelope, signer, _ = ready_proof
    secret = hashlib.sha256(b"native-receipt-traceback-secret").digest()

    with pytest.raises(ValueError) as raised:
        _issue(
            envelope,
            signer,
            trusted_milestone_authenticator_key=secret,
        )

    traceback_text = _source_probe_traceback_text(raised.value)
    assert repr(secret) not in traceback_text
    assert secret.hex() not in traceback_text


def test_receipt_verification_scrubs_and_propagates_base_exception(
    ready_proof,
    monkeypatch,
) -> None:
    envelope, signer, _ = ready_proof
    secret = hashlib.sha256(b"native-receipt-base-exception-secret").digest()

    def abort_verification(*args, **kwargs):
        del args, kwargs
        raise _VerificationAbort

    monkeypatch.setattr(
        source_probe_module,
        "verify_source_profile_proof",
        abort_verification,
    )
    with pytest.raises(_VerificationAbort) as raised:
        _issue(
            envelope,
            signer,
            trusted_milestone_authenticator_key=secret,
        )

    traceback_text = _source_probe_traceback_text(raised.value)
    assert repr(secret) not in traceback_text
    assert secret.hex() not in traceback_text


def test_receipt_constructor_rejects_syntactic_forgery() -> None:
    with pytest.raises((TypeError, ValueError), match="issued|private|constructor"):
        Exact20NativePrewarmReceiptV1(
            schema="kuzet.exact-20-native-prewarm-receipt.v1",
            site_id=profile_fixtures.SITE_ID,
            epoch=1,
            epoch_started_generation=1,
            ready_at_monotonic_ns=profile_fixtures.PREWARM_NS,
            source_identity_commitments_sha256="0" * 64,
            proof_key_id=profile_fixtures.SOURCE_PROOF_KEY_ID,
            proof_public_key_sha256="0" * 64,
            proof_milestone_authenticator_key_id=(profile_fixtures.MILESTONE_AUTHENTICATOR_KEY_ID),
            proof_milestone_authentication_tag="0" * 64,
            proof_snapshot_sha256="0" * 64,
            proof_final_head="0" * 64,
            proof_signature_sha256="0" * 64,
            proof_sha256="0" * 64,
        )


def _make_native_ready_proof(*, restart_epoch: bool = False):
    tracker, signer = profile_fixtures._proof_tracker_or_plain()
    assert signer is not None
    if restart_epoch:
        restarted = tracker.restart_epoch(started_monotonic_ns=1)
        assert restarted.epoch == 2
        callbacks = tuple(
            tracker.bind_source(
                camera_id=camera_id,
                resolved_url=profile_fixtures._resolved_url(source_index),
                commitment_key=profile_fixtures.COMMITMENT_KEY,
                bound_monotonic_ns=1,
            )
            for source_index, camera_id in enumerate(profile_fixtures.CAMERA_IDS)
        )
    else:
        callbacks = profile_fixtures._bind_all(tracker)
    bridges = tuple(NativeSourceProbeBridge(capacity=8) for _ in callbacks)
    leases = tuple(
        bridge.bind(callback) for bridge, callback in zip(bridges, callbacks, strict=True)
    )
    for lease in leases:
        _caps(lease)
    step_ns = 80_000_000
    elapsed_values = range(
        0,
        profile_fixtures.PREWARM_NS + step_ns + 1,
        step_ns,
    )
    for sample_number, elapsed_ns in enumerate(elapsed_values, start=1):
        for lease in leases:
            _triple(
                lease,
                pts_ns=sample_number,
                byte_size=40_000,
                source_timestamp_ns=BASE_SOURCE_TIMESTAMP_NS + elapsed_ns,
                parser_observed_ns=elapsed_ns,
                decoded_observed_ns=elapsed_ns,
                ntp_observed_ns=elapsed_ns,
                source_ntp_ns=BASE_SOURCE_NTP_NS + elapsed_ns,
            )
    envelope = tracker.authoritative_proof()
    assert envelope.snapshot.ready
    assert envelope.snapshot.ready_at_monotonic_ns == profile_fixtures.PREWARM_NS + step_ns
    return envelope, signer, leases, bridges, (callbacks, tracker)


@pytest.fixture(scope="module")
def native_ready_proof():
    return _make_native_ready_proof()


def test_receipt_rejects_stale_generation_and_cross_epoch_tracker_leases() -> None:
    envelope, signer, leases, bridges, _ = _make_native_ready_proof()
    stale_lease = leases[0]
    stale_lease.close()
    replacement_callbacks = _RecordingCallbacks()
    replacement_lease = bridges[0].bind(replacement_callbacks)
    assert replacement_lease._generation != stale_lease._generation  # noqa: SLF001

    with pytest.raises(ValueError, match="stale|generation|native|lease"):
        _issue(envelope, signer, native_leases=(stale_lease, *leases[1:]))

    _, _, cross_epoch_leases, _, _ = _make_native_ready_proof(restart_epoch=True)
    with pytest.raises(ValueError, match="epoch|native|lease|scope"):
        _issue(envelope, signer, native_leases=cross_epoch_leases)


def test_receipt_rejects_exact_type_low_level_lease_clone() -> None:
    envelope, signer, leases, _, _ = _make_native_ready_proof()
    canonical = leases[0]
    clone = object.__new__(SourceProbeLease)
    object.__setattr__(clone, "_bridge", canonical._bridge)  # noqa: SLF001
    object.__setattr__(clone, "_generation", canonical._generation)  # noqa: SLF001
    assert type(clone) is SourceProbeLease

    with pytest.raises(ValueError, match="canonical|issued|native|lease"):
        _issue(envelope, signer, native_leases=(clone, *leases[1:]))
    assert all(
        not lease._bridge._active.native_claimed  # noqa: SLF001
        for lease in leases
    )


def test_native_lease_claim_validation_is_exact_20_ordered_and_transactional(
    native_ready_proof,
    monkeypatch,
) -> None:
    envelope, signer, leases, _, _ = native_ready_proof

    with pytest.raises(ValueError, match="20|native|lease"):
        _issue(envelope, signer, native_leases=leases[:-1])
    with pytest.raises(ValueError, match="order|camera|source|native"):
        _issue(
            envelope,
            signer,
            native_leases=(leases[1], leases[0], *leases[2:]),
        )
    with pytest.raises(ValueError, match="distinct|duplicate|source|native"):
        _issue(
            envelope,
            signer,
            native_leases=(*leases[:-1], leases[0]),
        )
    with pytest.raises(ValueError, match="epoch|trusted|verification"):
        _issue(
            envelope,
            signer,
            native_leases=leases,
            expected_epoch=envelope.epoch + 1,
        )

    original_set_native_claimed = source_probe_module._set_native_claimed
    successful_claim_writes = 0

    def fail_during_claim_commit(state, value):
        nonlocal successful_claim_writes
        original_set_native_claimed(state, value)
        if value:
            successful_claim_writes += 1
            if successful_claim_writes == 2:
                raise RuntimeError("injected native claim commit failure")

    monkeypatch.setattr(
        source_probe_module,
        "_set_native_claimed",
        fail_during_claim_commit,
    )
    with pytest.raises(RuntimeError, match="injected native claim commit") as raised:
        _issue(envelope, signer, native_leases=leases)
    monkeypatch.setattr(
        source_probe_module,
        "_set_native_claimed",
        original_set_native_claimed,
    )
    consume = source_probe_module.verify_and_consume_exact_20_prewarm_receipt
    for leaked_receipt in _source_probe_traceback_receipts(raised.value):
        with pytest.raises(ValueError, match="issued|receipt|authority|canonical"):
            consume(
                leaked_receipt,
                expected_site_id=profile_fixtures.SITE_ID,
                expected_epoch=envelope.epoch,
                expected_epoch_started_generation=(envelope.epoch_started_generation),
                expected_source_identity_commitments=(
                    profile_fixtures._expected_source_commitments()
                ),
                expected_proof_sha256=leaked_receipt.proof_sha256,
            )

    # Every failed validation above must leave all live lease claims untouched.
    assert all(
        not lease._bridge._active.native_claimed  # noqa: SLF001
        for lease in leases
    )


def test_protocol_mock_leases_are_never_receipt_eligible(ready_proof) -> None:
    envelope, signer, _ = ready_proof
    fake_bindings = tuple(_bound_recording_bridge() for _ in range(20))
    fake_leases = tuple(binding[2] for binding in fake_bindings)

    with pytest.raises(ValueError, match="native|tracker|callback|eligible"):
        _issue(envelope, signer, native_leases=fake_leases)


def test_old_ready_proof_cannot_claim_after_direct_current_tracker_failure() -> None:
    envelope, signer, leases, _, retained = _make_native_ready_proof()
    callbacks, _ = retained
    assert not callbacks[0].on_native_probe_failure(
        SourceProfileFailureCode.COUNTER_REGRESSION,
        observed_monotonic_ns=profile_fixtures.PREWARM_NS + 160_000_000,
    )

    with pytest.raises(ValueError, match="current|failure|native|tracker"):
        _issue(envelope, signer, native_leases=leases)
    assert all(
        not lease._bridge._active.native_claimed  # noqa: SLF001
        for lease in leases
    )


@pytest.fixture(scope="module")
def issued_native_receipt(native_ready_proof):
    envelope, signer, leases, _, _ = native_ready_proof
    return _issue(
        envelope,
        signer,
        native_leases=leases,
    )


def test_exact_native_receipt_is_immutable_and_binds_both_proofs(
    native_ready_proof,
    issued_native_receipt,
) -> None:
    envelope, _, leases, _, _ = native_ready_proof
    receipt = issued_native_receipt

    assert type(receipt) is Exact20NativePrewarmReceiptV1
    assert receipt.site_id == profile_fixtures.SITE_ID
    assert receipt.epoch == envelope.epoch
    assert receipt.epoch_started_generation == envelope.epoch_started_generation
    assert receipt.ready_at_monotonic_ns == profile_fixtures.PREWARM_NS + 80_000_000
    assert receipt.proof_final_head == envelope.final_head
    assert receipt.proof_snapshot_sha256 == envelope.snapshot_sha256
    assert (
        receipt.proof_signature_sha256
        == hashlib.sha256(bytes.fromhex(envelope.signature)).hexdigest()
    )
    assert receipt.proof_key_id == envelope.key_id
    assert receipt.proof_public_key_sha256 == envelope.public_key_sha256
    assert receipt.proof_milestone_authenticator_key_id == (envelope.milestone_authenticator_key_id)
    assert receipt.proof_milestone_authentication_tag == (envelope.milestone_authentication_tag)
    assert len(receipt.source_identity_commitments_sha256) == 64
    assert len(receipt.native_claims_sha256) == 64
    assert len(receipt.proof_sha256) == 64
    with pytest.raises(AttributeError):
        receipt.ready_at_monotonic_ns = 0  # type: ignore[misc]
    assert all(
        lease._bridge._active.native_claimed  # noqa: SLF001
        for lease in leases
    )
    rendered = repr(receipt)
    assert "snapshot=" not in rendered
    assert "ready=True" not in rendered
    assert "callback" not in rendered.lower()
    assert "BEGIN PUBLIC KEY" not in rendered


def test_lease_and_receipt_reject_copy_pickle_and_dataclass_replacement(
    native_ready_proof,
    issued_native_receipt,
) -> None:
    lease = native_ready_proof[2][0]
    receipt = issued_native_receipt

    for capability in (lease, receipt):
        with pytest.raises(TypeError, match="copy|capability|serialize"):
            copy.copy(capability)
        with pytest.raises(TypeError, match="copy|capability|serialize"):
            copy.deepcopy(capability)
        with pytest.raises((TypeError, pickle.PickleError), match="pickle|serialize|capability"):
            pickle.dumps(capability)
    with pytest.raises(TypeError):
        replace(receipt, proof_sha256="0" * 64)


def test_receipt_consume_api_is_exact_pinned_and_one_shot(
    native_ready_proof,
    issued_native_receipt,
) -> None:
    envelope = native_ready_proof[0]
    consume = source_probe_module.verify_and_consume_exact_20_prewarm_receipt
    arguments = {
        "expected_site_id": profile_fixtures.SITE_ID,
        "expected_epoch": envelope.epoch,
        "expected_epoch_started_generation": envelope.epoch_started_generation,
        "expected_source_identity_commitments": (profile_fixtures._expected_source_commitments()),
        "expected_proof_sha256": issued_native_receipt.proof_sha256,
    }
    clone = _low_level_receipt_clone(issued_native_receipt)
    assert type(clone) is Exact20NativePrewarmReceiptV1

    with pytest.raises(ValueError, match="canonical|issued|receipt|authority"):
        consume(clone, **arguments)

    with pytest.raises(ValueError, match="site|pin|receipt"):
        consume(
            issued_native_receipt,
            **{**arguments, "expected_site_id": profile_fixtures.OTHER_SITE_ID},
        )
    verified = consume(issued_native_receipt, **arguments)
    assert type(verified).__name__ == "VerifiedExact20NativePrewarmV1"
    with pytest.raises(ValueError, match="canonical|issued|receipt|authority"):
        consume(clone, **arguments)
    with pytest.raises(ValueError, match="consum|used|receipt"):
        consume(issued_native_receipt, **arguments)


def test_live_receipt_tracking_is_finitely_bounded_or_per_capability() -> None:
    registry = getattr(source_probe_module, "_ISSUED_RECEIPTS", None)
    if registry is None:
        return
    limit = getattr(source_probe_module, "_MAX_LIVE_RECEIPTS", None)
    assert type(limit) is int and 1 <= limit <= 100_000
    assert len(registry) <= limit
