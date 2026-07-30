"""Pure-Python native source probe correlation and prewarm proof receipts."""

from __future__ import annotations

import hashlib
import json
import weakref
from collections import OrderedDict, deque
from contextlib import ExitStack
from dataclasses import dataclass
from threading import Condition, RLock, get_ident
from typing import Literal, Protocol

from protector.pilot.runtime.source_profile import (
    NativeSourceCallbacks,
    NativeSourceCaps,
    NativeSourceProfileProofEnvelopeV1,
    NativeSourceProfileTracker,
    SourceProfileFailureCode,
    verify_source_profile_proof,
)

_INT64_MAX = 2**63 - 1
_PREWARM_NS = 60_000_000_000
_MAX_CAPACITY = 1_000_000
_RECEIPT_SCHEMA = "kuzet.exact-20-native-prewarm-receipt.v1"
_IDENTITIES_DIGEST_DOMAIN = b"kuzet-ai/exact-20-native-prewarm-identities/v1\x00"
_NATIVE_TRANSCRIPT_DOMAIN = b"kuzet-ai/native-source-probe-transcript/v1\x00"
_NATIVE_CLAIMS_DIGEST_DOMAIN = b"kuzet-ai/exact-20-native-claims/v1\x00"


def _validate_int64(
    value: int,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = _INT64_MAX,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside its exact signed 64-bit bounds")


def _validate_digest(value: str, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a canonical SHA-256 digest")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class _ProbeCallbacks(Protocol):
    def on_rtp_caps(
        self,
        caps: NativeSourceCaps,
        *,
        observed_monotonic_ns: int,
    ) -> bool: ...

    def on_parser_counter(
        self,
        *,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool: ...

    def on_decoded_frame(
        self,
        *,
        decoded_frames: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool: ...

    def on_native_probe_failure(
        self,
        code: SourceProfileFailureCode,
        *,
        observed_monotonic_ns: int,
    ) -> bool: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class _ParserRecord:
    byte_size: int
    cumulative_bytes: int
    source_timestamp_ns: int
    pts_ns: int
    observed_monotonic_ns: int


@dataclass(frozen=True, slots=True)
class CorrelatedNtpV1:
    """One exact NvDs timestamp whose native callback batch committed."""

    pts_ns: int
    source_ntp_ns: int
    parser_observed_monotonic_ns: int
    decoded_observed_monotonic_ns: int
    ntp_observed_monotonic_ns: int
    completed_monotonic_ns: int

    def __post_init__(self) -> None:
        _validate_int64(self.pts_ns, "correlated NTP PTS")
        _validate_int64(self.source_ntp_ns, "correlated source NTP", minimum=1)
        _validate_int64(
            self.parser_observed_monotonic_ns,
            "correlated parser observation time",
        )
        _validate_int64(
            self.decoded_observed_monotonic_ns,
            "correlated decoded observation time",
        )
        _validate_int64(
            self.ntp_observed_monotonic_ns,
            "correlated NTP observation time",
        )
        _validate_int64(
            self.completed_monotonic_ns,
            "correlated NTP completion time",
        )
        if self.completed_monotonic_ns < max(
            self.parser_observed_monotonic_ns,
            self.decoded_observed_monotonic_ns,
            self.ntp_observed_monotonic_ns,
        ):
            raise ValueError("correlated NTP completion precedes a constituent observation")


@dataclass(frozen=True, slots=True)
class _CompletedReplay:
    parser_primitive: tuple[int, int, int, int]
    decoded_observed_monotonic_ns: int
    ntp_primitive: tuple[int, int]
    correlated_ntp: CorrelatedNtpV1 | None


@dataclass(frozen=True, slots=True)
class _NativeScope:
    tracker_ref: weakref.ReferenceType[NativeSourceProfileTracker]
    callback_ref: weakref.ReferenceType[NativeSourceCallbacks]
    site_id: str
    camera_id: str
    source_index: int
    source_identity_commitment: str
    epoch: int
    epoch_started_generation: int
    callback_generation: int


@dataclass(frozen=True, slots=True)
class _ForwardedRecord:
    pts_ns: int
    parser_bytes: int
    decoded_frames: int
    source_ntp_ns: int
    source_timestamp_ns: int
    observed_monotonic_ns: int
    transcript_head: str


@dataclass(frozen=True, slots=True)
class _NativeCompletion:
    first: _ForwardedRecord
    crossing: _ForwardedRecord
    baseline_duration_ns: int


@dataclass(frozen=True, slots=True)
class _DispatchBatch:
    generation: int
    callbacks: _ProbeCallbacks
    record: _ParserRecord
    decoded_observed_monotonic_ns: int
    source_ntp_ns: int
    ntp_observed_monotonic_ns: int
    caps: NativeSourceCaps
    callback_time_ns: int
    decoded_frames: int


@dataclass(slots=True)
class _DeferredTerminal:
    callbacks: _ProbeCallbacks
    owner_thread_id: int
    failure_code: SourceProfileFailureCode | None
    observed_monotonic_ns: int
    processing: bool = False


@dataclass(frozen=True, slots=True)
class _TerminalReservation:
    owner_thread_id: int
    process_now: bool


@dataclass(slots=True)
class _GenerationState:
    generation: int
    callbacks: _ProbeCallbacks
    parser_records: deque[_ParserRecord]
    parser_by_pts: dict[int, _ParserRecord]
    decoded_by_pts: dict[int, int]
    ntp_by_pts: dict[int, tuple[int, int]]
    pending_pts: set[int]
    completed_replays: OrderedDict[int, _CompletedReplay]
    native_scope: _NativeScope | None
    lease_ref: weakref.ReferenceType[SourceProbeLease] | None = None
    rtp_caps: tuple[str, int] | None = None
    decoder_caps: tuple[int, int, int, int, int] | None = None
    last_parser_primitive: tuple[int, int, int, int] | None = None
    cumulative_parser_bytes: int = 0
    decoded_frames: int = 0
    baseline_parser_bytes: int | None = None
    baseline_source_timestamp_ns: int | None = None
    last_source_ntp_ns: int | None = None
    last_forwarded_monotonic_ns: int | None = None
    dispatch_owner_thread_id: int | None = None
    in_flight_pts_ns: int | None = None
    transcript_head: str = "0" * 64
    first_forwarded: _ForwardedRecord | None = None
    native_completion: _NativeCompletion | None = None
    native_claimed: bool = False
    claim_authority: _ClaimAuthority | None = None


class SourceProbeLease:
    """One immutable generation token used by native probe callbacks."""

    __slots__ = ("__weakref__", "_bridge", "_generation")

    def __init__(
        self,
        bridge: NativeSourceProbeBridge,
        generation: int,
        *,
        _issuer: object,
    ) -> None:
        if _issuer is not _LEASE_ISSUER:
            raise TypeError("source probe leases are issued only by a bridge")
        object.__setattr__(self, "_bridge", bridge)
        object.__setattr__(self, "_generation", generation)
        weakref.finalize(self, _finalize_lease, bridge, generation)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("source probe leases are immutable")

    def __repr__(self) -> str:
        return f"SourceProbeLease(generation={self._generation})"

    def __copy__(self) -> None:
        raise TypeError("source probe capability cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("source probe capability cannot be copied")

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        raise TypeError("source probe capability cannot be serialized or pickled")

    def observe_rtp_caps(
        self,
        codec: str,
        observed_monotonic_ns: int,
    ) -> bool:
        return self._bridge._observe_rtp_caps(  # noqa: SLF001
            self._generation,
            codec,
            observed_monotonic_ns,
        )

    def observe_decoder_caps(
        self,
        width: int,
        height: int,
        fps_numerator: int,
        fps_denominator: int,
        observed_monotonic_ns: int,
    ) -> bool:
        return self._bridge._observe_decoder_caps(  # noqa: SLF001
            self._generation,
            width,
            height,
            fps_numerator,
            fps_denominator,
            observed_monotonic_ns,
        )

    def observe_parser_buffer(
        self,
        byte_size: int,
        source_timestamp_ns: int,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        return self._bridge._observe_parser_buffer(  # noqa: SLF001
            self._generation,
            byte_size,
            source_timestamp_ns,
            pts_ns,
            observed_monotonic_ns,
        )

    def observe_decoded_buffer(
        self,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        return self._bridge._observe_decoded_buffer(  # noqa: SLF001
            self._generation,
            pts_ns,
            observed_monotonic_ns,
        )

    def observe_nvds_ntp(
        self,
        pts_ns: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        return self._bridge._observe_nvds_ntp(  # noqa: SLF001
            self._generation,
            pts_ns,
            source_ntp_ns,
            observed_monotonic_ns,
        )

    def correlated_ntp(
        self,
        pts_ns: int,
        source_ntp_ns: int,
    ) -> CorrelatedNtpV1 | None:
        return self._bridge._correlated_ntp(  # noqa: SLF001
            self._generation,
            pts_ns,
            source_ntp_ns,
        )

    def close(self) -> None:
        self._bridge._close_generation(self._generation)  # noqa: SLF001


_LEASE_ISSUER = object()


def _finalize_lease(
    bridge: NativeSourceProbeBridge,
    generation: int,
) -> None:
    bridge._close_generation(generation)  # noqa: SLF001


class NativeSourceProbeBridge:
    """Bounded PTS correlator between native primitives and tracker callbacks."""

    __slots__ = (
        "__weakref__",
        "_active",
        "_capacity",
        "_condition",
        "_deferred_terminals",
        "_generation",
        "_lock",
    )

    def __init__(self, *, capacity: int = 64) -> None:
        _validate_int64(capacity, "native probe capacity", minimum=1, maximum=_MAX_CAPACITY)
        self._lock = RLock()
        self._condition = Condition(self._lock)
        self._deferred_terminals: dict[int, _DeferredTerminal] = {}
        self._capacity = capacity
        self._generation = 0
        self._active: _GenerationState | None = None

    def __repr__(self) -> str:
        with self._lock:
            generation = None if self._active is None else self._active.generation
            return (
                "NativeSourceProbeBridge("
                f"capacity={self._capacity}, active_generation={generation})"
            )

    def bind(self, callbacks: _ProbeCallbacks) -> SourceProbeLease:
        required_methods = (
            "on_rtp_caps",
            "on_parser_counter",
            "on_decoded_frame",
            "on_native_probe_failure",
            "close",
        )
        if any(not callable(getattr(callbacks, method, None)) for method in required_methods):
            raise TypeError("native source probe requires tracker callback capability")
        native_scope = self._capture_native_scope(callbacks)
        with self._condition:
            caller_thread_id = get_ident()
            while self._active is None and self._deferred_terminals:
                if any(
                    terminal.owner_thread_id == caller_thread_id
                    for terminal in self._deferred_terminals.values()
                ):
                    raise RuntimeError(
                        "terminal callbacks must finish before binding a replacement"
                    )
                self._condition.wait()
            if self._active is not None:
                raise RuntimeError(
                    "close the current source probe lease before binding a replacement"
                )
            if self._generation == _INT64_MAX:
                raise OverflowError("native source probe generation exhausted")
            self._generation += 1
            generation = self._generation
            lease = SourceProbeLease(self, generation, _issuer=_LEASE_ISSUER)
            self._active = _GenerationState(
                generation=generation,
                callbacks=callbacks,
                parser_records=deque(),
                parser_by_pts={},
                decoded_by_pts={},
                ntp_by_pts={},
                pending_pts=set(),
                completed_replays=OrderedDict(),
                native_scope=native_scope,
                lease_ref=weakref.ref(lease),
            )
            return lease

    @staticmethod
    def _capture_native_scope(callbacks: _ProbeCallbacks) -> _NativeScope | None:
        if type(callbacks) is not NativeSourceCallbacks:
            return None
        tracker = callbacks._tracker_ref()  # noqa: SLF001
        if type(tracker) is not NativeSourceProfileTracker:
            return None
        with tracker._lock:  # noqa: SLF001
            state = tracker._owned_state(callbacks)  # noqa: SLF001
            if state is None:
                return None
            expectation = state.expectation
            if (
                callbacks._epoch != tracker._epoch  # noqa: SLF001
                or callbacks._callback_generation != state.callback_generation  # noqa: SLF001
            ):
                return None
            return _NativeScope(
                tracker_ref=weakref.ref(tracker),
                callback_ref=weakref.ref(callbacks),
                site_id=tracker._site_id,  # noqa: SLF001
                camera_id=expectation.camera_id,
                source_index=expectation.source_index,
                source_identity_commitment=expectation.source_identity_commitment,
                epoch=callbacks._epoch,  # noqa: SLF001
                epoch_started_generation=tracker._epoch_started_generation,  # noqa: SLF001
                callback_generation=callbacks._callback_generation,  # noqa: SLF001
            )

    def close(self) -> None:
        with self._lock:
            generation = None if self._active is None else self._active.generation
        if generation is not None:
            self._close_generation(generation)

    def _state(self, generation: int) -> _GenerationState | None:
        state = self._active
        return state if state is not None and state.generation == generation else None

    def _clear_generation_buffers_locked(
        self,
        state: _GenerationState,
    ) -> None:
        state.parser_records.clear()
        state.parser_by_pts.clear()
        state.decoded_by_pts.clear()
        state.ntp_by_pts.clear()
        state.pending_pts.clear()
        state.completed_replays.clear()
        state.in_flight_pts_ns = None

    def _reserve_terminal_locked(
        self,
        state: _GenerationState,
        *,
        failure_code: SourceProfileFailureCode | None,
        observed_monotonic_ns: int,
    ) -> _TerminalReservation:
        dispatch_owner_thread_id = state.dispatch_owner_thread_id
        waits_for_dispatch = (
            dispatch_owner_thread_id is not None and state.in_flight_pts_ns is not None
        )
        owner_thread_id = dispatch_owner_thread_id if waits_for_dispatch else get_ident()
        assert owner_thread_id is not None
        self._active = None
        self._clear_generation_buffers_locked(state)
        state.dispatch_owner_thread_id = None
        self._deferred_terminals[state.generation] = _DeferredTerminal(
            callbacks=state.callbacks,
            owner_thread_id=owner_thread_id,
            failure_code=failure_code,
            observed_monotonic_ns=observed_monotonic_ns,
        )
        self._condition.notify_all()
        return _TerminalReservation(
            owner_thread_id=owner_thread_id,
            process_now=not waits_for_dispatch,
        )

    def _await_deferred_terminal(self, generation: int) -> None:
        caller_thread_id = get_ident()
        with self._condition:
            while True:
                terminal = self._deferred_terminals.get(generation)
                if terminal is None or terminal.owner_thread_id == caller_thread_id:
                    return
                self._condition.wait()

    def _finish_deferred_terminal(
        self,
        generation: int,
        owner_thread_id: int,
    ) -> bool:
        with self._condition:
            terminal = self._deferred_terminals.get(generation)
            if terminal is None or terminal.owner_thread_id != owner_thread_id:
                return False
            if terminal.processing:
                return True
            terminal.processing = True
        try:
            if terminal.failure_code is None:
                terminal.callbacks.close()
            else:
                self._deliver_failure(
                    terminal.callbacks,
                    terminal.failure_code,
                    terminal.observed_monotonic_ns,
                )
        finally:
            with self._condition:
                if self._deferred_terminals.get(generation) is terminal:
                    del self._deferred_terminals[generation]
                self._condition.notify_all()
        return True

    def _close_generation(self, generation: int) -> None:
        with self._condition:
            state = self._state(generation)
            reservation = (
                None
                if state is None
                else self._reserve_terminal_locked(
                    state,
                    failure_code=None,
                    observed_monotonic_ns=0,
                )
            )
        if reservation is not None and reservation.process_now:
            self._finish_deferred_terminal(
                generation,
                reservation.owner_thread_id,
            )
        self._await_deferred_terminal(generation)

    @staticmethod
    def _deliver_failure(
        callbacks: _ProbeCallbacks,
        code: SourceProfileFailureCode,
        observed_monotonic_ns: int,
    ) -> bool:
        try:
            callbacks.on_native_probe_failure(
                code,
                observed_monotonic_ns=observed_monotonic_ns,
            )
        finally:
            callbacks.close()
        return False

    def _detach_for_failure_locked(
        self,
        state: _GenerationState,
        code: SourceProfileFailureCode,
        observed_monotonic_ns: int,
    ) -> _TerminalReservation:
        return self._reserve_terminal_locked(
            state,
            failure_code=code,
            observed_monotonic_ns=observed_monotonic_ns,
        )

    def _complete_terminal(
        self,
        generation: int,
        reservation: _TerminalReservation,
    ) -> bool:
        if reservation.process_now:
            self._finish_deferred_terminal(
                generation,
                reservation.owner_thread_id,
            )
        self._await_deferred_terminal(generation)
        return False

    def _cleanup_failed_dispatch(
        self,
        generation: int,
        owner_thread_id: int,
    ) -> None:
        try:
            self._close_generation(generation)
            self._finish_deferred_terminal(
                generation,
                owner_thread_id,
            )
        except BaseException:
            pass

    def _reserve_pending_pts_locked(
        self,
        state: _GenerationState,
        pts_ns: int,
    ) -> bool:
        if pts_ns in state.pending_pts:
            return True
        if len(state.pending_pts) >= self._capacity:
            return False
        state.pending_pts.add(pts_ns)
        return True

    def _reject_invalid_primitive(
        self,
        generation: int,
        observed_monotonic_ns: int,
    ) -> bool:
        with self._lock:
            state = self._state(generation)
            reservation = (
                None
                if state is None
                else self._detach_for_failure_locked(
                    state,
                    SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE,
                    observed_monotonic_ns,
                )
            )
        if reservation is not None:
            return self._complete_terminal(generation, reservation)
        return False

    def _observe_rtp_caps(
        self,
        generation: int,
        codec: str,
        observed_monotonic_ns: int,
    ) -> bool:
        _validate_int64(observed_monotonic_ns, "RTP CAPS observation time")
        if type(codec) is not str or codec not in {"h264", "h265"}:
            return self._reject_invalid_primitive(
                generation,
                observed_monotonic_ns,
            )
        primitive = (codec, observed_monotonic_ns)
        with self._lock:
            state = self._state(generation)
            if state is None:
                return False
            if state.rtp_caps is not None:
                if state.rtp_caps == primitive:
                    return True
                reservation = self._detach_for_failure_locked(
                    state,
                    SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE,
                    observed_monotonic_ns,
                )
                rejected = True
            else:
                state.rtp_caps = primitive
                reservation = None
                rejected = False
        if rejected:
            assert reservation is not None
            return self._complete_terminal(generation, reservation)
        return self._drive_generation(generation)

    def _observe_decoder_caps(
        self,
        generation: int,
        width: int,
        height: int,
        fps_numerator: int,
        fps_denominator: int,
        observed_monotonic_ns: int,
    ) -> bool:
        _validate_int64(observed_monotonic_ns, "decoder CAPS observation time")
        try:
            _validate_int64(width, "decoder width", minimum=1, maximum=16_384)
            _validate_int64(height, "decoder height", minimum=1, maximum=8_640)
            _validate_int64(fps_numerator, "decoder FPS numerator", minimum=1)
            _validate_int64(fps_denominator, "decoder FPS denominator", minimum=1)
            if not fps_denominator <= fps_numerator <= 240 * fps_denominator:
                raise ValueError("decoder FPS rational must be between 1 and 240")
        except ValueError:
            return self._reject_invalid_primitive(
                generation,
                observed_monotonic_ns,
            )
        primitive = (
            width,
            height,
            fps_numerator,
            fps_denominator,
            observed_monotonic_ns,
        )
        with self._lock:
            state = self._state(generation)
            if state is None:
                return False
            if state.decoder_caps is not None:
                if state.decoder_caps == primitive:
                    return True
                reservation = self._detach_for_failure_locked(
                    state,
                    SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE,
                    observed_monotonic_ns,
                )
                rejected = True
            else:
                state.decoder_caps = primitive
                reservation = None
                rejected = False
        if rejected:
            assert reservation is not None
            return self._complete_terminal(generation, reservation)
        return self._drive_generation(generation)

    def _observe_parser_buffer(
        self,
        generation: int,
        byte_size: int,
        source_timestamp_ns: int,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        _validate_int64(observed_monotonic_ns, "parser observation time")
        try:
            _validate_int64(byte_size, "parser buffer byte size", minimum=1)
            _validate_int64(source_timestamp_ns, "parser source timestamp", minimum=1)
            _validate_int64(pts_ns, "parser PTS")
        except ValueError:
            return self._reject_invalid_primitive(
                generation,
                observed_monotonic_ns,
            )
        primitive = (
            byte_size,
            source_timestamp_ns,
            pts_ns,
            observed_monotonic_ns,
        )
        reservation: _TerminalReservation | None = None
        failure_code: SourceProfileFailureCode | None = None
        with self._lock:
            state = self._state(generation)
            if state is None:
                return False
            completed = state.completed_replays.get(pts_ns)
            if completed is not None:
                if completed.parser_primitive == primitive:
                    return True
                failure_code = SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
            else:
                existing = state.parser_by_pts.get(pts_ns)
                if existing is not None:
                    existing_primitive = (
                        existing.byte_size,
                        existing.source_timestamp_ns,
                        existing.pts_ns,
                        existing.observed_monotonic_ns,
                    )
                    if existing_primitive == primitive:
                        return True
                    failure_code = SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
                previous = state.last_parser_primitive
                if (
                    failure_code is None
                    and previous is not None
                    and (source_timestamp_ns <= previous[1] or observed_monotonic_ns < previous[3])
                ):
                    failure_code = SourceProfileFailureCode.COUNTER_REGRESSION
                if failure_code is None and state.cumulative_parser_bytes > _INT64_MAX - byte_size:
                    failure_code = SourceProfileFailureCode.BUFFER_OVERFLOW
                if failure_code is None and not self._reserve_pending_pts_locked(state, pts_ns):
                    failure_code = SourceProfileFailureCode.BUFFER_OVERFLOW
                if failure_code is None:
                    state.cumulative_parser_bytes += byte_size
                    state.last_parser_primitive = primitive
                    record = _ParserRecord(
                        byte_size=byte_size,
                        cumulative_bytes=state.cumulative_parser_bytes,
                        source_timestamp_ns=source_timestamp_ns,
                        pts_ns=pts_ns,
                        observed_monotonic_ns=observed_monotonic_ns,
                    )
                    state.parser_records.append(record)
                    state.parser_by_pts[pts_ns] = record
            if failure_code is not None:
                reservation = self._detach_for_failure_locked(
                    state,
                    failure_code,
                    observed_monotonic_ns,
                )
        if failure_code is not None:
            assert failure_code is not None
            assert reservation is not None
            return self._complete_terminal(generation, reservation)
        return self._drive_generation(generation, wait_pts_ns=pts_ns)

    def _observe_decoded_buffer(
        self,
        generation: int,
        pts_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        _validate_int64(observed_monotonic_ns, "decoded buffer observation time")
        try:
            _validate_int64(pts_ns, "decoded buffer PTS")
        except ValueError:
            return self._reject_invalid_primitive(
                generation,
                observed_monotonic_ns,
            )
        reservation: _TerminalReservation | None = None
        failure_code: SourceProfileFailureCode | None = None
        with self._lock:
            state = self._state(generation)
            if state is None:
                return False
            completed = state.completed_replays.get(pts_ns)
            if completed is not None:
                if completed.decoded_observed_monotonic_ns == observed_monotonic_ns:
                    return True
                failure_code = SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
            else:
                existing = state.decoded_by_pts.get(pts_ns)
                if existing is not None:
                    if existing == observed_monotonic_ns:
                        return True
                    failure_code = SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
                elif not self._reserve_pending_pts_locked(state, pts_ns):
                    failure_code = SourceProfileFailureCode.BUFFER_OVERFLOW
                else:
                    state.decoded_by_pts[pts_ns] = observed_monotonic_ns
            if failure_code is not None:
                reservation = self._detach_for_failure_locked(
                    state,
                    failure_code,
                    observed_monotonic_ns,
                )
        if failure_code is not None:
            assert reservation is not None
            return self._complete_terminal(generation, reservation)
        return self._drive_generation(generation, wait_pts_ns=pts_ns)

    def _observe_nvds_ntp(
        self,
        generation: int,
        pts_ns: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        _validate_int64(observed_monotonic_ns, "NTP observation time")
        try:
            _validate_int64(pts_ns, "NTP buffer PTS")
            _validate_int64(source_ntp_ns, "source NTP", minimum=1)
        except ValueError:
            return self._reject_invalid_primitive(
                generation,
                observed_monotonic_ns,
            )
        primitive = (source_ntp_ns, observed_monotonic_ns)
        reservation: _TerminalReservation | None = None
        failure_code: SourceProfileFailureCode | None = None
        with self._lock:
            state = self._state(generation)
            if state is None:
                return False
            completed = state.completed_replays.get(pts_ns)
            if completed is not None:
                if completed.ntp_primitive == primitive:
                    return True
                failure_code = SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
            else:
                existing = state.ntp_by_pts.get(pts_ns)
                if existing is not None:
                    if existing == primitive:
                        return True
                    failure_code = SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
                elif not self._reserve_pending_pts_locked(state, pts_ns):
                    failure_code = SourceProfileFailureCode.BUFFER_OVERFLOW
                else:
                    state.ntp_by_pts[pts_ns] = primitive
            if failure_code is not None:
                reservation = self._detach_for_failure_locked(
                    state,
                    failure_code,
                    observed_monotonic_ns,
                )
        if failure_code is not None:
            assert reservation is not None
            return self._complete_terminal(generation, reservation)
        return self._drive_generation(generation, wait_pts_ns=pts_ns)

    def _correlated_ntp(
        self,
        generation: int,
        pts_ns: int,
        source_ntp_ns: int,
    ) -> CorrelatedNtpV1 | None:
        _validate_int64(pts_ns, "correlated NTP PTS")
        _validate_int64(source_ntp_ns, "correlated source NTP", minimum=1)
        with self._lock:
            state = self._state(generation)
            if state is None:
                return None
            replay = state.completed_replays.get(pts_ns)
            if replay is None or replay.ntp_primitive[0] != source_ntp_ns:
                return None
            return replay.correlated_ntp

    def _derived_caps_locked(
        self,
        state: _GenerationState,
        record: _ParserRecord,
    ) -> tuple[NativeSourceCaps, int] | SourceProfileFailureCode:
        if (
            state.rtp_caps is None
            or state.decoder_caps is None
            or state.baseline_parser_bytes is None
            or state.baseline_source_timestamp_ns is None
        ):
            return SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
        byte_delta = record.cumulative_bytes - state.baseline_parser_bytes
        timestamp_delta = record.source_timestamp_ns - state.baseline_source_timestamp_ns
        if byte_delta <= 0 or timestamp_delta <= 0:
            return SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
        if byte_delta > _INT64_MAX // 8_000_000:
            return SourceProfileFailureCode.BUFFER_OVERFLOW
        scaled_bytes = byte_delta * 8_000_000
        rounding = timestamp_delta // 2
        if scaled_bytes > _INT64_MAX - rounding:
            return SourceProfileFailureCode.BUFFER_OVERFLOW
        bitrate_kbps = (scaled_bytes + rounding) // timestamp_delta
        if not 1 <= bitrate_kbps <= 1_000_000:
            return SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
        codec, rtp_time = state.rtp_caps
        width, height, numerator, denominator, decoder_time = state.decoder_caps
        caps = NativeSourceCaps(
            codec=codec,
            width=width,
            height=height,
            fps=numerator / denominator,
            bitrate_kbps=bitrate_kbps,
        )
        return caps, max(rtp_time, decoder_time)

    def _commit_completed_locked(
        self,
        state: _GenerationState,
        record: _ParserRecord,
        *,
        decoded_observed_monotonic_ns: int,
        source_ntp_ns: int,
        ntp_observed_monotonic_ns: int,
        forwarded_at_monotonic_ns: int | None,
    ) -> None:
        assert state.parser_records and state.parser_records[0] is record
        state.parser_records.popleft()
        del state.parser_by_pts[record.pts_ns]
        del state.decoded_by_pts[record.pts_ns]
        del state.ntp_by_pts[record.pts_ns]
        state.pending_pts.remove(record.pts_ns)
        state.decoded_frames += 1
        replay = _CompletedReplay(
            parser_primitive=(
                record.byte_size,
                record.source_timestamp_ns,
                record.pts_ns,
                record.observed_monotonic_ns,
            ),
            decoded_observed_monotonic_ns=decoded_observed_monotonic_ns,
            ntp_primitive=(source_ntp_ns, ntp_observed_monotonic_ns),
            correlated_ntp=(
                None
                if forwarded_at_monotonic_ns is None
                else CorrelatedNtpV1(
                    pts_ns=record.pts_ns,
                    source_ntp_ns=source_ntp_ns,
                    parser_observed_monotonic_ns=record.observed_monotonic_ns,
                    decoded_observed_monotonic_ns=decoded_observed_monotonic_ns,
                    ntp_observed_monotonic_ns=ntp_observed_monotonic_ns,
                    completed_monotonic_ns=forwarded_at_monotonic_ns,
                )
            ),
        )
        state.completed_replays[record.pts_ns] = replay
        if len(state.completed_replays) > self._capacity:
            state.completed_replays.popitem(last=False)
        state.transcript_head = hashlib.sha256(
            _NATIVE_TRANSCRIPT_DOMAIN
            + bytes.fromhex(state.transcript_head)
            + _canonical_bytes(
                {
                    "cumulative_parser_bytes": record.cumulative_bytes,
                    "decoded_frames": state.decoded_frames,
                    "decoded_observed_monotonic_ns": (decoded_observed_monotonic_ns),
                    "ntp_observed_monotonic_ns": ntp_observed_monotonic_ns,
                    "parser_primitive": list(replay.parser_primitive),
                    "source_ntp_ns": source_ntp_ns,
                }
            )
        ).hexdigest()
        if forwarded_at_monotonic_ns is not None:
            forwarded = _ForwardedRecord(
                pts_ns=record.pts_ns,
                parser_bytes=record.cumulative_bytes,
                decoded_frames=state.decoded_frames,
                source_ntp_ns=source_ntp_ns,
                source_timestamp_ns=record.source_timestamp_ns,
                observed_monotonic_ns=forwarded_at_monotonic_ns,
                transcript_head=state.transcript_head,
            )
            if state.first_forwarded is None:
                state.first_forwarded = forwarded
            elif state.native_completion is None:
                first = state.first_forwarded
                baseline_duration_ns = min(
                    forwarded.observed_monotonic_ns - first.observed_monotonic_ns,
                    forwarded.source_ntp_ns - first.source_ntp_ns,
                    forwarded.source_timestamp_ns - first.source_timestamp_ns,
                )
                if baseline_duration_ns >= _PREWARM_NS:
                    state.native_completion = _NativeCompletion(
                        first=first,
                        crossing=forwarded,
                        baseline_duration_ns=baseline_duration_ns,
                    )
        self._condition.notify_all()

    def _batch_is_live(self, batch: _DispatchBatch, owner_thread_id: int) -> bool:
        with self._lock:
            state = self._state(batch.generation)
            return (
                state is not None
                and state.dispatch_owner_thread_id == owner_thread_id
                and state.in_flight_pts_ns == batch.record.pts_ns
            )

    def _invoke_batch(
        self,
        batch: _DispatchBatch,
        owner_thread_id: int,
    ) -> bool:
        callbacks = batch.callbacks
        if not callbacks.on_rtp_caps(
            batch.caps,
            observed_monotonic_ns=batch.callback_time_ns,
        ):
            self._close_generation(batch.generation)
            self._finish_deferred_terminal(batch.generation, owner_thread_id)
            return False
        if not self._batch_is_live(batch, owner_thread_id):
            self._finish_deferred_terminal(batch.generation, owner_thread_id)
            return False
        if not callbacks.on_parser_counter(
            parser_bytes=batch.record.cumulative_bytes,
            source_timestamp_ns=batch.record.source_timestamp_ns,
            observed_monotonic_ns=batch.callback_time_ns,
        ):
            self._close_generation(batch.generation)
            self._finish_deferred_terminal(batch.generation, owner_thread_id)
            return False
        if not self._batch_is_live(batch, owner_thread_id):
            self._finish_deferred_terminal(batch.generation, owner_thread_id)
            return False
        if not callbacks.on_decoded_frame(
            decoded_frames=batch.decoded_frames,
            source_ntp_ns=batch.source_ntp_ns,
            observed_monotonic_ns=batch.callback_time_ns,
        ):
            self._close_generation(batch.generation)
            self._finish_deferred_terminal(batch.generation, owner_thread_id)
            return False
        live = self._batch_is_live(batch, owner_thread_id)
        if not live:
            self._finish_deferred_terminal(batch.generation, owner_thread_id)
        return live

    def _drive_generation(
        self,
        generation: int,
        *,
        wait_pts_ns: int | None = None,
    ) -> bool:
        owner_thread_id = get_ident()
        with self._condition:
            state = self._state(generation)
            if state is None:
                return False
            if state.dispatch_owner_thread_id == owner_thread_id:
                return True
            while state.dispatch_owner_thread_id is not None:
                if wait_pts_ns is not None and wait_pts_ns in state.completed_replays:
                    return True
                self._condition.wait()
                state = self._state(generation)
                if state is None:
                    return False
            state.dispatch_owner_thread_id = owner_thread_id

        while True:
            failure: tuple[_TerminalReservation,] | None = None
            baseline_failure: BaseException | None = None
            batch: _DispatchBatch | None = None
            with self._condition:
                state = self._state(generation)
                if state is None:
                    return False
                if state.dispatch_owner_thread_id != owner_thread_id:
                    return False
                if state.rtp_caps is None or state.decoder_caps is None:
                    state.dispatch_owner_thread_id = None
                    self._condition.notify_all()
                    return True
                if not state.parser_records:
                    state.dispatch_owner_thread_id = None
                    self._condition.notify_all()
                    return True
                record = state.parser_records[0]
                decoded_time = state.decoded_by_pts.get(record.pts_ns)
                ntp = state.ntp_by_pts.get(record.pts_ns)
                if decoded_time is None or ntp is None:
                    state.dispatch_owner_thread_id = None
                    self._condition.notify_all()
                    return True
                source_ntp_ns, ntp_time = ntp
                failure_time = max(
                    record.observed_monotonic_ns,
                    decoded_time,
                    ntp_time,
                )
                if state.decoded_frames == _INT64_MAX:
                    reservation = self._detach_for_failure_locked(
                        state,
                        SourceProfileFailureCode.BUFFER_OVERFLOW,
                        failure_time,
                    )
                    failure = (reservation,)
                elif state.baseline_parser_bytes is None:
                    state.baseline_parser_bytes = record.cumulative_bytes
                    state.baseline_source_timestamp_ns = record.source_timestamp_ns
                    state.last_source_ntp_ns = source_ntp_ns
                    try:
                        self._commit_completed_locked(
                            state,
                            record,
                            decoded_observed_monotonic_ns=decoded_time,
                            source_ntp_ns=source_ntp_ns,
                            ntp_observed_monotonic_ns=ntp_time,
                            forwarded_at_monotonic_ns=None,
                        )
                    except BaseException as error:
                        baseline_failure = error
                    if baseline_failure is None:
                        continue
                elif (
                    state.last_source_ntp_ns is not None
                    and source_ntp_ns <= state.last_source_ntp_ns
                ):
                    reservation = self._detach_for_failure_locked(
                        state,
                        SourceProfileFailureCode.COUNTER_REGRESSION,
                        failure_time,
                    )
                    failure = (reservation,)
                else:
                    derived = self._derived_caps_locked(state, record)
                    if type(derived) is SourceProfileFailureCode:
                        reservation = self._detach_for_failure_locked(
                            state,
                            derived,
                            failure_time,
                        )
                        failure = (reservation,)
                    else:
                        caps, caps_time = derived
                        callback_time = max(caps_time, failure_time)
                        previous_time = state.last_forwarded_monotonic_ns
                        if previous_time is not None and callback_time <= previous_time:
                            reservation = self._detach_for_failure_locked(
                                state,
                                SourceProfileFailureCode.COUNTER_REGRESSION,
                                callback_time,
                            )
                            failure = (reservation,)
                        else:
                            batch = _DispatchBatch(
                                generation=generation,
                                callbacks=state.callbacks,
                                record=record,
                                decoded_observed_monotonic_ns=decoded_time,
                                source_ntp_ns=source_ntp_ns,
                                ntp_observed_monotonic_ns=ntp_time,
                                caps=caps,
                                callback_time_ns=callback_time,
                                decoded_frames=state.decoded_frames + 1,
                            )
                            state.in_flight_pts_ns = record.pts_ns
            if baseline_failure is not None:
                self._cleanup_failed_dispatch(
                    generation,
                    owner_thread_id,
                )
                raise baseline_failure
            if failure is not None:
                (reservation,) = failure
                return self._complete_terminal(generation, reservation)
            if batch is None:
                return False
            try:
                delivered = self._invoke_batch(batch, owner_thread_id)
                if not delivered:
                    return False
                with self._condition:
                    state = self._state(generation)
                    if (
                        state is None
                        or state.dispatch_owner_thread_id != owner_thread_id
                        or state.in_flight_pts_ns != batch.record.pts_ns
                    ):
                        return False
                    state.last_source_ntp_ns = batch.source_ntp_ns
                    state.last_forwarded_monotonic_ns = batch.callback_time_ns
                    self._commit_completed_locked(
                        state,
                        batch.record,
                        decoded_observed_monotonic_ns=(batch.decoded_observed_monotonic_ns),
                        source_ntp_ns=batch.source_ntp_ns,
                        ntp_observed_monotonic_ns=(batch.ntp_observed_monotonic_ns),
                        forwarded_at_monotonic_ns=batch.callback_time_ns,
                    )
                    state.in_flight_pts_ns = None
            except BaseException:
                self._cleanup_failed_dispatch(
                    generation,
                    owner_thread_id,
                )
                raise


_RECEIPT_FIELDS = (
    "schema",
    "site_id",
    "epoch",
    "epoch_started_generation",
    "ready_at_monotonic_ns",
    "source_identity_commitments_sha256",
    "native_claims_sha256",
    "proof_key_id",
    "proof_public_key_sha256",
    "proof_milestone_authenticator_key_id",
    "proof_milestone_authentication_tag",
    "proof_snapshot_sha256",
    "proof_final_head",
    "proof_signature_sha256",
    "proof_sha256",
)
_RECEIPT_ISSUER = object()
_VERIFIED_RECEIPT_ISSUER = object()


class _ClaimAuthority:
    """Per-generation authority shared by one exact set of claimed states."""

    __slots__ = (
        "bridge_refs",
        "consumed",
        "lock",
        "receipt_ref",
        "states",
    )

    def __init__(
        self,
        bridges: tuple[NativeSourceProbeBridge, ...],
        states: tuple[_GenerationState, ...],
    ) -> None:
        self.bridge_refs = tuple(weakref.ref(bridge) for bridge in bridges)
        self.states = states
        self.receipt_ref: weakref.ReferenceType[Exact20NativePrewarmReceiptV1] | None = None
        self.consumed = False
        self.lock = RLock()


class _ReceiptMilestoneKeyMaterial:
    __slots__ = ("_key",)

    def __init__(self, key: object) -> None:
        self._key = key

    def __repr__(self) -> str:
        return "_ReceiptMilestoneKeyMaterial(<redacted>)"

    def take(self) -> object:
        key = self._key
        self._key = b""
        return key

    def clear(self) -> None:
        self._key = b""


def _validate_receipt_values(values: dict[str, object]) -> None:
    if set(values) != set(_RECEIPT_FIELDS):
        raise ValueError("exact-20 native prewarm receipt fields are invalid")
    if values["schema"] != _RECEIPT_SCHEMA:
        raise ValueError("exact-20 native prewarm receipt schema is invalid")
    for field, label in (
        ("site_id", "site"),
        ("proof_key_id", "proof key identity"),
        (
            "proof_milestone_authenticator_key_id",
            "milestone authenticator identity",
        ),
    ):
        value = values[field]
        if type(value) is not str or not value or value != value.strip() or len(value) > 128:
            raise ValueError(f"exact-20 native prewarm receipt {label} is invalid")
    _validate_int64(
        values["epoch"],  # type: ignore[arg-type]
        "exact-20 native prewarm epoch",
        minimum=1,
    )
    _validate_int64(
        values["epoch_started_generation"],  # type: ignore[arg-type]
        "exact-20 native prewarm epoch start generation",
        minimum=1,
    )
    _validate_int64(
        values["ready_at_monotonic_ns"],  # type: ignore[arg-type]
        "exact-20 native prewarm ready time",
        minimum=_PREWARM_NS,
    )
    for field, label in (
        ("source_identity_commitments_sha256", "ordered source identity digest"),
        ("native_claims_sha256", "ordered native claims digest"),
        ("proof_public_key_sha256", "proof public key digest"),
        (
            "proof_milestone_authentication_tag",
            "proof milestone authentication tag",
        ),
        ("proof_snapshot_sha256", "proof snapshot digest"),
        ("proof_final_head", "proof final head"),
        ("proof_signature_sha256", "proof signature digest"),
        ("proof_sha256", "canonical proof digest"),
    ):
        _validate_digest(values[field], label)  # type: ignore[arg-type]


class Exact20NativePrewarmReceiptV1:
    """Sealed one-shot capability bound to profile and native evidence."""

    __slots__ = (
        "__weakref__",
        "_claim_authority",
    ) + tuple(f"_{field}" for field in _RECEIPT_FIELDS)

    def __init__(
        self,
        *,
        _issuer: object | None = None,
        _claim_authority: _ClaimAuthority | None = None,
        **values: object,
    ) -> None:
        if _issuer is not _RECEIPT_ISSUER:
            raise TypeError("receipt constructor is private; use the verified issuer")
        if type(_claim_authority) is not _ClaimAuthority:
            raise TypeError("receipt requires live generation-owned claim authority")
        _validate_receipt_values(values)
        object.__setattr__(self, "_claim_authority", _claim_authority)
        for field in _RECEIPT_FIELDS:
            object.__setattr__(self, f"_{field}", values[field])

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("exact-20 native prewarm receipts are immutable")

    def __repr__(self) -> str:
        return (
            "Exact20NativePrewarmReceiptV1("
            f"site_id={self.site_id!r}, epoch={self.epoch}, "
            f"proof_sha256={self.proof_sha256[:12]}..., "
            f"native_claims_sha256={self.native_claims_sha256[:12]}...)"
        )

    def __copy__(self) -> None:
        raise TypeError("receipt capability cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("receipt capability cannot be copied")

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        raise TypeError("receipt capability cannot be serialized or pickled")

    @property
    def schema(self) -> Literal["kuzet.exact-20-native-prewarm-receipt.v1"]:
        return self._schema  # type: ignore[return-value]

    @property
    def site_id(self) -> str:
        return self._site_id  # type: ignore[return-value]

    @property
    def epoch(self) -> int:
        return self._epoch  # type: ignore[return-value]

    @property
    def epoch_started_generation(self) -> int:
        return self._epoch_started_generation  # type: ignore[return-value]

    @property
    def ready_at_monotonic_ns(self) -> int:
        return self._ready_at_monotonic_ns  # type: ignore[return-value]

    @property
    def source_identity_commitments_sha256(self) -> str:
        return self._source_identity_commitments_sha256  # type: ignore[return-value]

    @property
    def native_claims_sha256(self) -> str:
        return self._native_claims_sha256  # type: ignore[return-value]

    @property
    def proof_key_id(self) -> str:
        return self._proof_key_id  # type: ignore[return-value]

    @property
    def proof_public_key_sha256(self) -> str:
        return self._proof_public_key_sha256  # type: ignore[return-value]

    @property
    def proof_milestone_authenticator_key_id(self) -> str:
        return self._proof_milestone_authenticator_key_id  # type: ignore[return-value]

    @property
    def proof_milestone_authentication_tag(self) -> str:
        return self._proof_milestone_authentication_tag  # type: ignore[return-value]

    @property
    def proof_snapshot_sha256(self) -> str:
        return self._proof_snapshot_sha256  # type: ignore[return-value]

    @property
    def proof_final_head(self) -> str:
        return self._proof_final_head  # type: ignore[return-value]

    @property
    def proof_signature_sha256(self) -> str:
        return self._proof_signature_sha256  # type: ignore[return-value]

    @property
    def proof_sha256(self) -> str:
        return self._proof_sha256  # type: ignore[return-value]


class VerifiedExact20NativePrewarmV1:
    """Private downstream capability produced by consuming one receipt."""

    __slots__ = (
        "_native_claims_sha256",
        "_proof_sha256",
        "_site_id",
    )

    def __init__(
        self,
        receipt: Exact20NativePrewarmReceiptV1,
        *,
        _issuer: object,
    ) -> None:
        if _issuer is not _VERIFIED_RECEIPT_ISSUER:
            raise TypeError("verified receipt capabilities are privately issued")
        object.__setattr__(self, "_site_id", receipt.site_id)
        object.__setattr__(self, "_proof_sha256", receipt.proof_sha256)
        object.__setattr__(
            self,
            "_native_claims_sha256",
            receipt.native_claims_sha256,
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("verified receipt capabilities are immutable")

    def __copy__(self) -> None:
        raise TypeError("verified receipt capability cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("verified receipt capability cannot be copied")

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        raise TypeError("verified receipt capability cannot be serialized or pickled")


def _set_native_claimed(state: _GenerationState, value: bool) -> None:
    if type(value) is not bool:
        raise TypeError("native claim state must be bool")
    state.native_claimed = value


def _rollback_native_claims(
    states: tuple[_GenerationState, ...],
    authority: _ClaimAuthority,
) -> None:
    authority.receipt_ref = None
    for state in states:
        if state.claim_authority is authority:
            state.claim_authority = None
        try:
            _set_native_claimed(state, False)
        except BaseException:
            state.native_claimed = False


def _verify_profile_proof_sanitized(
    envelope: NativeSourceProfileProofEnvelopeV1,
    *,
    expected_key_id: str,
    trusted_public_key: bytes,
    expected_milestone_authenticator_key_id: str,
    milestone_key_material: _ReceiptMilestoneKeyMaterial,
    expected_site_id: str,
    expected_source_identity_commitments: tuple[str, ...],
    expected_epoch: int,
    expected_epoch_started_generation: int,
):
    raw_key = milestone_key_material.take()
    snapshot = None
    try:
        snapshot = verify_source_profile_proof(
            envelope,
            expected_key_id=expected_key_id,
            trusted_public_key=trusted_public_key,
            expected_milestone_authenticator_key_id=(expected_milestone_authenticator_key_id),
            trusted_milestone_authenticator_key=raw_key,  # type: ignore[arg-type]
            expected_site_id=expected_site_id,
            expected_source_identity_commitments=(expected_source_identity_commitments),
            expected_epoch=expected_epoch,
            expected_epoch_started_generation=(expected_epoch_started_generation),
        )
    except Exception:
        snapshot = None
    finally:
        raw_key = b""
        milestone_key_material.clear()
    return snapshot


def _forwarded_record_dict(record: _ForwardedRecord) -> dict[str, object]:
    return {
        "decoded_frames": record.decoded_frames,
        "observed_monotonic_ns": record.observed_monotonic_ns,
        "parser_bytes": record.parser_bytes,
        "pts_ns": record.pts_ns,
        "source_ntp_ns": record.source_ntp_ns,
        "source_timestamp_ns": record.source_timestamp_ns,
        "transcript_head": record.transcript_head,
    }


def _candidate_native_tracker(
    lease: SourceProbeLease,
) -> NativeSourceProfileTracker | None:
    bridge = lease._bridge  # noqa: SLF001
    with bridge._lock:  # noqa: SLF001
        state = bridge._state(lease._generation)  # noqa: SLF001
        if (
            state is None
            or state.native_scope is None
            or state.lease_ref is None
            or state.lease_ref() is not lease
        ):
            return None
        return state.native_scope.tracker_ref()


def _issue_claimed_receipt(
    *,
    envelope: NativeSourceProfileProofEnvelopeV1,
    snapshot,
    native_leases: tuple[SourceProbeLease, ...],
    ready_at: int,
    identities_digest: str,
    signature_digest: str,
    proof_digest: str,
) -> Exact20NativePrewarmReceiptV1:
    if (
        type(native_leases) is not tuple
        or len(native_leases) != 20
        or any(type(lease) is not SourceProbeLease for lease in native_leases)
    ):
        raise ValueError("receipt requires an exact 20-item native lease tuple")
    bridges = tuple(lease._bridge for lease in native_leases)  # noqa: SLF001
    if (
        len({id(lease) for lease in native_leases}) != 20
        or len({id(bridge) for bridge in bridges}) != 20
    ):
        raise ValueError("native receipt leases and bridges must be distinct")
    trackers = tuple(_candidate_native_tracker(lease) for lease in native_leases)
    tracker = trackers[0]
    if type(tracker) is not NativeSourceProfileTracker or any(
        candidate is not tracker for candidate in trackers
    ):
        raise ValueError("native leases are stale or not tracker-eligible")
    completion_receipts = {
        receipt.source_index: receipt
        for receipt in envelope.receipts
        if receipt.kind == "prewarm_completed"
    }
    if set(completion_receipts) != set(range(20)):
        raise ValueError("native receipt requires 20 authenticated prewarm milestones")

    ordered_bridges = tuple(sorted(bridges, key=id))
    states: list[_GenerationState] = []
    claims: list[dict[str, object]] = []
    with tracker._lock:  # noqa: SLF001
        with ExitStack() as stack:
            for bridge in ordered_bridges:
                stack.enter_context(bridge._lock)  # noqa: SLF001
            if (
                tracker._site_id != envelope.site_id  # noqa: SLF001
                or tracker._epoch != envelope.epoch  # noqa: SLF001
                or tracker._epoch_started_generation  # noqa: SLF001
                != envelope.epoch_started_generation
                or tracker._ready_at_monotonic_ns  # noqa: SLF001
                != snapshot.ready_at_monotonic_ns
            ):
                raise ValueError("native lease tracker epoch or current readiness is inconsistent")
            for source_index, (lease, bridge) in enumerate(
                zip(native_leases, bridges, strict=True)
            ):
                state = bridge._state(lease._generation)  # noqa: SLF001
                if (
                    state is None
                    or state.native_scope is None
                    or state.lease_ref is None
                    or state.lease_ref() is not lease
                    or state.dispatch_owner_thread_id is not None
                    or state.native_claimed
                    or state.claim_authority is not None
                ):
                    raise ValueError("native lease is stale, busy, or already claimed")
                scope = state.native_scope
                callback = scope.callback_ref()
                owned_state = (
                    None if callback is None else tracker._owned_state(callback)  # noqa: SLF001
                )
                source = snapshot.sources[source_index]
                milestone = completion_receipts[source_index]
                completion = state.native_completion
                if (
                    scope.tracker_ref() is not tracker
                    or callback is not state.callbacks
                    or owned_state is None
                    or bool(owned_state.failures)
                    or scope.site_id != envelope.site_id
                    or scope.camera_id != source.camera_id
                    or scope.source_index != source_index
                    or scope.source_identity_commitment
                    != envelope.source_identity_commitments[source_index]
                    or scope.epoch != envelope.epoch
                    or scope.epoch_started_generation != envelope.epoch_started_generation
                    or scope.callback_generation != source.callback_generation
                    or owned_state.callback_generation != scope.callback_generation
                    or owned_state.expectation.source_index != source_index
                    or owned_state.expectation.source_identity_commitment
                    != scope.source_identity_commitment
                    or completion is None
                ):
                    raise ValueError("native lease source order or scope is inconsistent")
                crossing = completion.crossing
                if (
                    milestone.camera_id != scope.camera_id
                    or milestone.source_identity_commitment != scope.source_identity_commitment
                    or milestone.event_monotonic_ns != crossing.observed_monotonic_ns
                    or milestone.parser_bytes != crossing.parser_bytes
                    or milestone.decoded_frames != crossing.decoded_frames
                    or milestone.source_ntp_ns != crossing.source_ntp_ns
                    or milestone.source_timestamp_ns != crossing.source_timestamp_ns
                    or milestone.baseline_duration_ns != completion.baseline_duration_ns
                    or source.prewarm_completed_monotonic_ns != crossing.observed_monotonic_ns
                    or owned_state.prewarm_completed_monotonic_ns != crossing.observed_monotonic_ns
                    or milestone not in tracker._milestone_receipts  # noqa: SLF001
                ):
                    raise ValueError("native crossing differs from authenticated prewarm milestone")
                states.append(state)
                claims.append(
                    {
                        "baseline_duration_ns": completion.baseline_duration_ns,
                        "callback_generation": scope.callback_generation,
                        "camera_id": scope.camera_id,
                        "crossing": _forwarded_record_dict(completion.crossing),
                        "epoch": scope.epoch,
                        "epoch_started_generation": (scope.epoch_started_generation),
                        "first": _forwarded_record_dict(completion.first),
                        "site_id": scope.site_id,
                        "source_identity_commitment": (scope.source_identity_commitment),
                        "source_index": scope.source_index,
                    }
                )
            native_claims_digest = hashlib.sha256(
                _NATIVE_CLAIMS_DIGEST_DOMAIN + _canonical_bytes(claims)
            ).hexdigest()
            claimed_states = tuple(states)
            authority = _ClaimAuthority(bridges, claimed_states)
            try:
                for state in claimed_states:
                    _set_native_claimed(state, True)
                    state.claim_authority = authority
                receipt = Exact20NativePrewarmReceiptV1(
                    _issuer=_RECEIPT_ISSUER,
                    _claim_authority=authority,
                    schema=_RECEIPT_SCHEMA,
                    site_id=envelope.site_id,
                    epoch=envelope.epoch,
                    epoch_started_generation=envelope.epoch_started_generation,
                    ready_at_monotonic_ns=ready_at,
                    source_identity_commitments_sha256=identities_digest,
                    native_claims_sha256=native_claims_digest,
                    proof_key_id=envelope.key_id,
                    proof_public_key_sha256=envelope.public_key_sha256,
                    proof_milestone_authenticator_key_id=(envelope.milestone_authenticator_key_id),
                    proof_milestone_authentication_tag=(envelope.milestone_authentication_tag),
                    proof_snapshot_sha256=envelope.snapshot_sha256,
                    proof_final_head=envelope.final_head,
                    proof_signature_sha256=signature_digest,
                    proof_sha256=proof_digest,
                )
                authority.receipt_ref = weakref.ref(receipt)
            except BaseException:
                _rollback_native_claims(claimed_states, authority)
                raise
    return receipt


def verify_and_issue_exact_20_prewarm_receipt(
    envelope: NativeSourceProfileProofEnvelopeV1,
    *,
    native_leases: tuple[SourceProbeLease, ...],
    expected_key_id: str,
    trusted_public_key: bytes,
    expected_milestone_authenticator_key_id: str,
    trusted_milestone_authenticator_key: bytes | bytearray,
    expected_site_id: str,
    expected_source_identity_commitments: tuple[str, ...],
    expected_epoch: int,
    expected_epoch_started_generation: int,
) -> Exact20NativePrewarmReceiptV1:
    """Verify both proofs and atomically issue a live exact-20 capability."""

    milestone_key_material = _ReceiptMilestoneKeyMaterial(trusted_milestone_authenticator_key)
    trusted_milestone_authenticator_key = b""
    if type(envelope) is not NativeSourceProfileProofEnvelopeV1:
        milestone_key_material.clear()
        raise ValueError("exact-20 prewarm requires an authoritative proof envelope") from None
    snapshot = _verify_profile_proof_sanitized(
        envelope,
        expected_key_id=expected_key_id,
        trusted_public_key=trusted_public_key,
        expected_milestone_authenticator_key_id=(expected_milestone_authenticator_key_id),
        milestone_key_material=milestone_key_material,
        expected_site_id=expected_site_id,
        expected_source_identity_commitments=(expected_source_identity_commitments),
        expected_epoch=expected_epoch,
        expected_epoch_started_generation=expected_epoch_started_generation,
    )
    if snapshot is None:
        raise ValueError("authoritative source profile proof verification failed") from None
    if not snapshot.ready or snapshot.failures:
        raise ValueError("authoritative source profile proof is not failure-free ready")
    if len(snapshot.sources) != 20 or tuple(
        source.source_index for source in snapshot.sources
    ) != tuple(range(20)):
        raise ValueError("authoritative source profile proof is not exact ordered 20")
    completion_times = tuple(source.prewarm_completed_monotonic_ns for source in snapshot.sources)
    if any(completion is None for completion in completion_times):
        raise ValueError("authoritative source profile proof lacks exact prewarm completion")
    completed = tuple(completion for completion in completion_times if completion is not None)
    if any(
        completion - snapshot.epoch_started_monotonic_ns < _PREWARM_NS for completion in completed
    ):
        raise ValueError("authoritative source prewarm completion is below 60 seconds")
    ready_at = max(completed)
    if snapshot.ready_at_monotonic_ns != ready_at:
        raise ValueError("authoritative source profile ready time is not the latest completion")
    identities_digest = hashlib.sha256(
        _IDENTITIES_DIGEST_DOMAIN + _canonical_bytes(list(expected_source_identity_commitments))
    ).hexdigest()
    signature_digest = hashlib.sha256(bytes.fromhex(envelope.signature)).hexdigest()
    proof_digest = hashlib.sha256(_canonical_bytes(envelope.to_dict())).hexdigest()
    return _issue_claimed_receipt(
        envelope=envelope,
        snapshot=snapshot,
        native_leases=native_leases,
        ready_at=ready_at,
        identities_digest=identities_digest,
        signature_digest=signature_digest,
        proof_digest=proof_digest,
    )


def verify_and_consume_exact_20_prewarm_receipt(
    receipt: Exact20NativePrewarmReceiptV1,
    *,
    expected_site_id: str,
    expected_epoch: int,
    expected_epoch_started_generation: int,
    expected_source_identity_commitments: tuple[str, ...],
    expected_proof_sha256: str,
) -> VerifiedExact20NativePrewarmV1:
    """Verify explicit pins and consume one issued receipt exactly once."""

    if type(receipt) is not Exact20NativePrewarmReceiptV1:
        raise ValueError("receipt capability type is invalid")
    _validate_int64(expected_epoch, "expected receipt epoch", minimum=1)
    _validate_int64(
        expected_epoch_started_generation,
        "expected receipt epoch start generation",
        minimum=1,
    )
    _validate_digest(expected_proof_sha256, "expected proof digest")
    if (
        type(expected_source_identity_commitments) is not tuple
        or len(expected_source_identity_commitments) != 20
    ):
        raise ValueError("receipt identity pin must be an exact 20-item tuple")
    for commitment in expected_source_identity_commitments:
        _validate_digest(commitment, "expected receipt source identity")
    identities_digest = hashlib.sha256(
        _IDENTITIES_DIGEST_DOMAIN + _canonical_bytes(list(expected_source_identity_commitments))
    ).hexdigest()
    try:
        authority = receipt._claim_authority  # noqa: SLF001
    except AttributeError:
        raise ValueError("receipt has no live claim authority") from None
    if type(authority) is not _ClaimAuthority:
        raise ValueError("receipt has no live claim authority")
    with authority.lock:
        canonical_ref = authority.receipt_ref
        if canonical_ref is None or canonical_ref() is not receipt:
            raise ValueError("receipt is not the canonical issued capability")
        if authority.consumed:
            raise ValueError("receipt capability was already consumed")
        bridges = tuple(reference() for reference in authority.bridge_refs)
        states = authority.states
        if (
            len(bridges) != 20
            or len(states) != 20
            or any(bridge is None for bridge in bridges)
            or len({id(bridge) for bridge in bridges}) != 20
            or len({id(state) for state in states}) != 20
        ):
            raise ValueError("receipt claim authority is no longer live")
        live_bridges = tuple(
            bridge for bridge in bridges if type(bridge) is NativeSourceProbeBridge
        )
        if len(live_bridges) != 20:
            raise ValueError("receipt claim authority is no longer live")
        with ExitStack() as stack:
            for bridge in sorted(live_bridges, key=id):
                stack.enter_context(bridge._lock)  # noqa: SLF001
            if authority.receipt_ref is not canonical_ref or canonical_ref() is not receipt:
                raise ValueError("receipt is not the canonical issued capability")
            if authority.consumed:
                raise ValueError("receipt capability was already consumed")
            for bridge, state in zip(live_bridges, states, strict=True):
                if (
                    bridge._active is not state  # noqa: SLF001
                    or not state.native_claimed
                    or state.claim_authority is not authority
                ):
                    raise ValueError("receipt claim authority is no longer live")
            if (
                receipt.site_id != expected_site_id
                or receipt.epoch != expected_epoch
                or receipt.epoch_started_generation != expected_epoch_started_generation
                or receipt.source_identity_commitments_sha256 != identities_digest
                or receipt.proof_sha256 != expected_proof_sha256
            ):
                raise ValueError("receipt does not match its explicit pins")
            verified = VerifiedExact20NativePrewarmV1(
                receipt,
                _issuer=_VERIFIED_RECEIPT_ISSUER,
            )
            authority.consumed = True
            return verified


__all__ = [
    "CorrelatedNtpV1",
    "Exact20NativePrewarmReceiptV1",
    "NativeSourceProbeBridge",
    "SourceProbeLease",
    "VerifiedExact20NativePrewarmV1",
    "verify_and_consume_exact_20_prewarm_receipt",
    "verify_and_issue_exact_20_prewarm_receipt",
]
