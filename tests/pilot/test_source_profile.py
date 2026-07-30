from __future__ import annotations

import gc
import hashlib
import json
import random
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from threading import Barrier, Event

import pytest

import protector.pilot.runtime.source_profile as source_profile_module
from protector.pilot.runtime.source_profile import (
    NativeSourceCallbacks,
    NativeSourceCaps,
    NativeSourceObservation,
    NativeSourceProfileDelta,
    NativeSourceProfileSnapshot,
    NativeSourceProfileTracker,
    NativeSourceStateSnapshot,
    SourceProfileExpectation,
    SourceProfileFailure,
    SourceProfileFailureCode,
    compute_source_identity_commitment,
)

SITE_ID = "school-site-a"
OTHER_SITE_ID = "school-site-b"
COMMITMENT_KEY = b"kuzet-source-profile-key-0000001"
OTHER_KEY = b"kuzet-source-profile-key-0000002"
MILESTONE_AUTHENTICATOR_KEY_ID = "source-profile-milestones-2026-07"
MILESTONE_AUTHENTICATOR_KEY = hashlib.sha256(b"kuzet-test-source-profile-milestone-key").digest()
OTHER_MILESTONE_AUTHENTICATOR_KEY = hashlib.sha256(
    b"kuzet-test-other-source-profile-milestone-key"
).digest()
PREWARM_NS = 60_000_000_000
SOURCE_NTP_BASE_NS = 1_800_000_000_000_000_000
SOURCE_TIMESTAMP_BASE_NS = 900_000_000_000
INT64_MAX = 2**63 - 1
CAMERA_IDS = tuple(f"camera-{number:02d}" for number in range(1, 21))
CAPS = NativeSourceCaps(
    codec="h264",
    width=1920,
    height=1080,
    fps=25.0,
    bitrate_kbps=4_000,
)


def _valid_public_records() -> tuple[
    SourceProfileFailure,
    NativeSourceStateSnapshot,
    NativeSourceProfileSnapshot,
    NativeSourceProfileDelta,
]:
    failure = SourceProfileFailure(
        camera_id=CAMERA_IDS[0],
        code=SourceProfileFailureCode.PROFILE_MISMATCH,
        epoch=1,
        first_generation=2,
    )
    sources = tuple(
        NativeSourceStateSnapshot(
            camera_id=camera_id,
            source_index=source_index,
            bound=source_index == 0,
            identity_verified=False,
            callback_generation=1 if source_index == 0 else 0,
            observation=None,
            baseline_duration_ns=0,
            continuous_observations=0,
            maximum_observed_gap_ns=0,
            continuity_gap_bound_ns=83_333_334,
            stale_after_ns=5_000_000_000,
            prewarm_completed_monotonic_ns=None,
            failures=(failure,) if source_index == 0 else (),
        )
        for source_index, camera_id in enumerate(CAMERA_IDS)
    )
    snapshot = NativeSourceProfileSnapshot(
        epoch=1,
        generation=2,
        epoch_started_generation=1,
        ready=False,
        epoch_started_monotonic_ns=0,
        ready_at_monotonic_ns=None,
        sources=sources,
        failures=(failure,),
    )
    delta = NativeSourceProfileDelta(
        epoch=1,
        generation=2,
        event="source_bound",
        camera_id=CAMERA_IDS[0],
        ready=False,
        failures=(SourceProfileFailureCode.PROFILE_MISMATCH,),
    )
    return failure, sources[0], snapshot, delta


def _resolved_url(source_index: int) -> str:
    return (
        f"rtsp://operator:camera-secret-{source_index}@10.10.1.{source_index + 10}"
        f"/stream?token=credential-{source_index}"
    )


def _expectations(
    *,
    site_id: str = SITE_ID,
    commitment_key: bytes = COMMITMENT_KEY,
    max_timestamp_gap_ns: int = 2_000_000_000,
    stale_after_ns: int = 5_000_000_000,
) -> tuple[SourceProfileExpectation, ...]:
    return tuple(
        SourceProfileExpectation.signed(
            site_id=site_id,
            camera_id=camera_id,
            source_index=source_index,
            resolved_url=_resolved_url(source_index),
            commitment_key=commitment_key,
            codec="h264",
            width=1920,
            height=1080,
            fps_min=24.0,
            fps_max=26.0,
            bitrate_kbps_min=3_500,
            bitrate_kbps_max=4_500,
            max_timestamp_gap_ns=max_timestamp_gap_ns,
            max_timestamp_skew_ns=500_000_000,
            stale_after_ns=stale_after_ns,
        )
        for source_index, camera_id in enumerate(CAMERA_IDS)
    )


def _tracker(
    *,
    expectations: tuple[SourceProfileExpectation, ...] | None = None,
    site_id: str = SITE_ID,
    commitment_key: bytes = COMMITMENT_KEY,
    delta_capacity: int = 100_000,
) -> NativeSourceProfileTracker:
    return NativeSourceProfileTracker(
        site_id=site_id,
        expectations=_expectations() if expectations is None else expectations,
        commitment_key=commitment_key,
        milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
        milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
        delta_capacity=delta_capacity,
        epoch_started_monotonic_ns=0,
    )


def _bind_all(
    tracker: NativeSourceProfileTracker,
    *,
    commitment_key: bytes = COMMITMENT_KEY,
):
    return tuple(
        tracker.bind_source(
            camera_id=camera_id,
            resolved_url=_resolved_url(source_index),
            commitment_key=commitment_key,
            bound_monotonic_ns=0,
        )
        for source_index, camera_id in enumerate(CAMERA_IDS)
    )


def _observe(
    callback,
    *,
    sample_number: int,
    elapsed_ns: int,
    caps: NativeSourceCaps = CAPS,
    parser_bytes: int | None = None,
    decoded_frames: int | None = None,
    source_timestamp_ns: int | None = None,
    source_ntp_ns: int | None = None,
) -> bool:
    if sample_number == 1:
        assert callback.on_rtp_caps(caps, observed_monotonic_ns=elapsed_ns)
    assert callback.on_parser_counter(
        parser_bytes=sample_number * 10_000 if parser_bytes is None else parser_bytes,
        source_timestamp_ns=(
            SOURCE_TIMESTAMP_BASE_NS + elapsed_ns
            if source_timestamp_ns is None
            else source_timestamp_ns
        ),
        observed_monotonic_ns=elapsed_ns,
    )
    return callback.on_decoded_frame(
        decoded_frames=sample_number if decoded_frames is None else decoded_frames,
        source_ntp_ns=(SOURCE_NTP_BASE_NS + elapsed_ns if source_ntp_ns is None else source_ntp_ns),
        observed_monotonic_ns=elapsed_ns,
    )


def _failures(tracker: NativeSourceProfileTracker, camera_id: str) -> set[str]:
    source = next(source for source in tracker.snapshot().sources if source.camera_id == camera_id)
    return {failure.code.value for failure in source.failures}


def _source_profile_traceback_text(error: BaseException) -> str:
    pending = [error]
    seen: set[int] = set()
    parts: list[str] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        parts.extend((repr(current), repr(current.args)))
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_code.co_filename.endswith("protector/pilot/runtime/source_profile.py"):
                parts.extend(f"{name}={value!r}" for name, value in frame.f_locals.items())
            traceback = traceback.tb_next
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(parts)


def _cadence_times(final_elapsed_ns: int) -> list[int]:
    elapsed_values = list(range(0, final_elapsed_ns, 40_000_000))
    if not elapsed_values or elapsed_values[-1] != final_elapsed_ns:
        elapsed_values.append(final_elapsed_ns)
    return elapsed_values


def _observe_all_through(callbacks, *, final_elapsed_ns: int) -> int:
    elapsed_values = _cadence_times(final_elapsed_ns)
    for sample_number, elapsed_ns in enumerate(elapsed_values, start=1):
        for callback in callbacks:
            assert _observe(
                callback,
                sample_number=sample_number,
                elapsed_ns=elapsed_ns,
            )
    return len(elapsed_values)


def test_tracker_requires_exactly_twenty_ordered_unique_camera_ids() -> None:
    expectations = _expectations()

    with pytest.raises(ValueError, match="exactly 20"):
        _tracker(expectations=expectations[:-1])
    with pytest.raises(ValueError, match="source indices"):
        _tracker(expectations=tuple(reversed(expectations)))

    duplicate = expectations[:-1] + (
        SourceProfileExpectation.signed(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=19,
            resolved_url=_resolved_url(19),
            commitment_key=COMMITMENT_KEY,
            codec="h264",
            width=1920,
            height=1080,
            fps_min=24.0,
            fps_max=26.0,
            bitrate_kbps_min=3_500,
            bitrate_kbps_max=4_500,
            max_timestamp_gap_ns=2_000_000_000,
            max_timestamp_skew_ns=500_000_000,
            stale_after_ns=5_000_000_000,
        ),
    )
    with pytest.raises(ValueError, match="unique"):
        _tracker(expectations=duplicate)

    assert tuple(source.camera_id for source in _tracker().snapshot().sources) == CAMERA_IDS


def test_tracker_owns_verified_expectation_order_across_caller_mutation_and_restart() -> None:
    caller_owned = list(_expectations())
    tracker = NativeSourceProfileTracker(
        site_id=SITE_ID,
        expectations=caller_owned,
        commitment_key=COMMITMENT_KEY,
        milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
        milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
        delta_capacity=100,
        epoch_started_monotonic_ns=0,
    )

    caller_owned.reverse()
    caller_owned[0] = caller_owned[1]
    tracker.restart_epoch(started_monotonic_ns=1)

    assert tuple(source.camera_id for source in tracker.snapshot().sources) == CAMERA_IDS


def test_tracker_deep_owns_expectations_against_frozen_object_bypass() -> None:
    caller_owned = list(_expectations())
    tracker = NativeSourceProfileTracker(
        site_id=SITE_ID,
        expectations=caller_owned,
        commitment_key=COMMITMENT_KEY,
        milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
        milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
        delta_capacity=100,
        epoch_started_monotonic_ns=0,
    )
    wrong_url = "rtsp://fixture.invalid/wrong-source"
    wrong_commitment = compute_source_identity_commitment(
        site_id=SITE_ID,
        camera_id=CAMERA_IDS[0],
        source_index=0,
        resolved_url=wrong_url,
        commitment_key=COMMITMENT_KEY,
    )
    object.__setattr__(
        caller_owned[0],
        "source_identity_commitment",
        wrong_commitment,
    )

    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=wrong_url,
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )

    assert SourceProfileFailureCode.PROFILE_MISMATCH.value in _failures(
        tracker,
        callback.camera_id,
    )
    assert not callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)


def test_tracker_requires_exact_expectation_instances() -> None:
    expectations = list(_expectations())
    expectations[0] = object()  # type: ignore[assignment]

    with pytest.raises(ValueError, match="SourceProfileExpectation"):
        _tracker(expectations=tuple(expectations))


def test_identity_commitment_separates_domain_site_camera_index_and_url() -> None:
    base = compute_source_identity_commitment(
        site_id=SITE_ID,
        camera_id=CAMERA_IDS[0],
        source_index=0,
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
    )
    variants = {
        compute_source_identity_commitment(
            site_id=OTHER_SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=_resolved_url(0),
            commitment_key=COMMITMENT_KEY,
        ),
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[1],
            source_index=0,
            resolved_url=_resolved_url(0),
            commitment_key=COMMITMENT_KEY,
        ),
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=1,
            resolved_url=_resolved_url(0),
            commitment_key=COMMITMENT_KEY,
        ),
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=_resolved_url(1),
            commitment_key=COMMITMENT_KEY,
        ),
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=_resolved_url(0),
            commitment_key=OTHER_KEY,
        ),
    }

    assert len(base) == 64
    assert base not in variants
    assert len(variants) == 5


@pytest.mark.parametrize("bad_key", [b"x" * 31, b"x" * 33])
def test_commitment_key_must_be_exactly_thirty_two_bytes(bad_key: bytes) -> None:
    with pytest.raises(ValueError, match="32-byte"):
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=_resolved_url(0),
            commitment_key=bad_key,
        )
    with pytest.raises(ValueError, match="32-byte"):
        SourceProfileExpectation.signed(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=_resolved_url(0),
            commitment_key=bad_key,
            codec="h264",
            width=1920,
            height=1080,
            fps_min=24.0,
            fps_max=26.0,
            bitrate_kbps_min=3_500,
            bitrate_kbps_max=4_500,
            max_timestamp_gap_ns=2_000_000_000,
            max_timestamp_skew_ns=500_000_000,
            stale_after_ns=5_000_000_000,
        )
    with pytest.raises(ValueError, match="32-byte"):
        _tracker(commitment_key=bad_key)


def test_expectation_signature_covers_every_profile_field() -> None:
    expectations = _expectations()
    mutations = (
        replace(expectations[0], codec="h265"),
        replace(expectations[0], width=1280),
        replace(expectations[0], height=720),
        replace(expectations[0], fps_min=23.0),
        replace(expectations[0], fps_max=27.0),
        replace(expectations[0], bitrate_kbps_min=3_000),
        replace(expectations[0], bitrate_kbps_max=5_000),
        replace(expectations[0], max_timestamp_gap_ns=3_000_000_000),
        replace(expectations[0], max_timestamp_skew_ns=600_000_000),
        replace(expectations[0], stale_after_ns=6_000_000_000),
    )

    for mutated in mutations:
        with pytest.raises(ValueError, match="signature"):
            _tracker(expectations=(mutated, *expectations[1:]))


def test_signed_fps_has_total_realistic_lower_boundary_and_serializes() -> None:
    boundary = SourceProfileExpectation.signed(
        site_id=SITE_ID,
        camera_id=CAMERA_IDS[0],
        source_index=0,
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        codec="h264",
        width=1920,
        height=1080,
        fps_min=1.0,
        fps_max=1.0,
        bitrate_kbps_min=3_500,
        bitrate_kbps_max=4_500,
        max_timestamp_gap_ns=2_000_000_000,
        max_timestamp_skew_ns=500_000_000,
        stale_after_ns=5_000_000_000,
    )

    assert json.loads(json.dumps(boundary.to_dict()))["fps_min"] == 1.0
    for invalid_fps in (0.999999, 5e-324):
        with pytest.raises(ValueError, match="FPS"):
            replace(boundary, fps_min=invalid_fps)


def test_raw_url_and_key_never_escape_public_models_or_errors() -> None:
    raw_url = _resolved_url(0)
    key_text = COMMITMENT_KEY.decode()
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=raw_url,
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    snapshot = tracker.snapshot()
    deltas = tracker.deltas_since(0)
    public_text = "\n".join(
        (
            repr(_expectations()[0]),
            repr(tracker),
            repr(callback),
            repr(snapshot),
            repr(deltas),
            json.dumps(snapshot.to_dict(), sort_keys=True),
            json.dumps([delta.to_dict() for delta in deltas], sort_keys=True),
        )
    )

    assert raw_url not in public_text
    assert "camera-secret-0" not in public_text
    assert "credential-0" not in public_text
    assert key_text not in public_text
    assert raw_url not in repr(vars(tracker))
    assert key_text not in repr(vars(tracker))

    with pytest.raises(ValueError) as caught:
        tracker.bind_source(
            camera_id=CAMERA_IDS[1],
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=-1,
        )
    assert raw_url not in str(caught.value)
    assert key_text not in str(caught.value)


def test_invalid_unicode_url_cannot_escape_through_exception_state() -> None:
    raw_url = "rtsp://operator:camera-secret@host/\ud800?token=credential"

    with pytest.raises(ValueError) as caught:
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
        )

    pending: list[BaseException] = [caught.value]
    seen: set[int] = set()
    exception_text: list[str] = []
    while pending:
        error = pending.pop()
        if id(error) in seen:
            continue
        seen.add(id(error))
        exception_text.extend((repr(error), repr(error.args)))
        leaked_object = getattr(error, "object", None)
        if leaked_object is not None:
            exception_text.append(repr(leaked_object))
        if error.__cause__ is not None:
            pending.append(error.__cause__)
        if error.__context__ is not None:
            pending.append(error.__context__)

    public_error = "\n".join(exception_text)
    assert "camera-secret" not in public_error
    assert "credential" not in public_error
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_resolved_url_requires_exact_str_without_echoing_hostile_content() -> None:
    class HostileUrl(str):
        pass

    raw_url = HostileUrl("rtsp://operator:traceback-url-secret@host/stream?token=credential")

    with pytest.raises(ValueError) as caught:
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
        )

    assert "traceback-url-secret" not in str(caught.value)
    assert "credential" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    "overrides",
    (
        {"site_id": ""},
        {"camera_id": ""},
        {"source_index": 20},
        {"commitment_key": b"traceback-key-secret"},
        {"resolved_url": ("rtsp://operator:traceback-url-secret@host/stream\x00?token=credential")},
    ),
)
def test_commitment_errors_scrub_url_and_key_from_source_traceback_frames(
    overrides: dict[str, object],
) -> None:
    raw_url = "rtsp://operator:traceback-url-secret@host/stream?token=traceback-credential"
    kwargs: dict[str, object] = {
        "site_id": SITE_ID,
        "camera_id": CAMERA_IDS[0],
        "source_index": 0,
        "resolved_url": raw_url,
        "commitment_key": COMMITMENT_KEY,
    }
    kwargs.update(overrides)

    with pytest.raises(ValueError) as caught:
        compute_source_identity_commitment(**kwargs)  # type: ignore[arg-type]

    traceback_text = _source_profile_traceback_text(caught.value)
    assert "traceback-url-secret" not in traceback_text
    assert "traceback-credential" not in traceback_text
    assert COMMITMENT_KEY.decode() not in traceback_text
    assert "traceback-key-secret" not in traceback_text


def test_canonical_failure_scrubs_secrets_from_source_traceback_frames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_url = "rtsp://operator:traceback-url-secret@host/stream?token=traceback-credential"

    def fail_canonical(*_args, **_kwargs):
        raise RuntimeError("canonical failure")

    monkeypatch.setattr(source_profile_module.json, "dumps", fail_canonical)
    with pytest.raises(ValueError) as caught:
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
        )

    traceback_text = _source_profile_traceback_text(caught.value)
    assert "traceback-url-secret" not in traceback_text
    assert "traceback-credential" not in traceback_text
    assert COMMITMENT_KEY.decode() not in traceback_text


def test_hmac_failure_scrubs_secrets_from_source_traceback_frames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_url = "rtsp://operator:traceback-url-secret@host/stream?token=traceback-credential"

    def fail_hmac(*_args, **_kwargs):
        raise RuntimeError("HMAC failure")

    monkeypatch.setattr(source_profile_module.hmac, "digest", fail_hmac)
    with pytest.raises(ValueError) as caught:
        compute_source_identity_commitment(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
        )

    traceback_text = _source_profile_traceback_text(caught.value)
    assert "traceback-url-secret" not in traceback_text
    assert "traceback-credential" not in traceback_text
    assert COMMITMENT_KEY.decode() not in traceback_text


def test_all_secret_accepting_public_apis_scrub_traceback_frames() -> None:
    raw_url = "rtsp://operator:traceback-url-secret@host/stream?token=traceback-credential"
    expectations = _expectations()
    tracker = _tracker()
    live_callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )

    def sign(*, site_id: str = SITE_ID, codec: str = "h264", url=raw_url):
        return SourceProfileExpectation.signed(
            site_id=site_id,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=url,
            commitment_key=COMMITMENT_KEY,
            codec=codec,  # type: ignore[arg-type]
            width=1920,
            height=1080,
            fps_min=24.0,
            fps_max=26.0,
            bitrate_kbps_min=3_500,
            bitrate_kbps_max=4_500,
            max_timestamp_gap_ns=2_000_000_000,
            max_timestamp_skew_ns=500_000_000,
            stale_after_ns=5_000_000_000,
        )

    actions = (
        (lambda: sign(site_id=""), ValueError),
        (lambda: sign(codec="vp9"), ValueError),
        (lambda: sign(url=f"{raw_url}\x00"), ValueError),
        lambda: NativeSourceProfileTracker(
            site_id="",
            expectations=expectations,
            commitment_key=COMMITMENT_KEY,
            milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
            milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
            delta_capacity=100,
            epoch_started_monotonic_ns=0,
        ),
        lambda: NativeSourceProfileTracker(
            site_id=SITE_ID,
            expectations=expectations,
            commitment_key=COMMITMENT_KEY,
            milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
            milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
            delta_capacity=0,
            epoch_started_monotonic_ns=0,
        ),
        lambda: tracker.bind_source(
            camera_id="not-in-profile",
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=0,
        ),
        lambda: tracker.bind_source(
            camera_id=CAMERA_IDS[1],
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=-1,
        ),
        (
            lambda: tracker.bind_source(
                camera_id=CAMERA_IDS[0],
                resolved_url=raw_url,
                commitment_key=COMMITMENT_KEY,
                bound_monotonic_ns=0,
            ),
            RuntimeError,
        ),
    )

    for entry in actions:
        action, error_type = entry if type(entry) is tuple else (entry, ValueError)
        with pytest.raises(error_type) as caught:
            action()
        traceback_text = _source_profile_traceback_text(caught.value)
        assert "traceback-url-secret" not in traceback_text
        assert "traceback-credential" not in traceback_text
        assert COMMITMENT_KEY.decode() not in traceback_text
    live_callback.close()


@pytest.mark.parametrize("failure_point", ("canonical", "hmac"))
@pytest.mark.parametrize("entry_point", ("signed", "tracker", "bind"))
def test_secret_accepting_apis_scrub_forced_inner_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
    entry_point: str,
) -> None:
    raw_url = "rtsp://operator:traceback-url-secret@host/stream?token=traceback-credential"
    expectations = _expectations()
    tracker = _tracker()

    def fail_inner(*_args, **_kwargs):
        raise RuntimeError(f"{failure_point} failure")

    if failure_point == "canonical":
        monkeypatch.setattr(source_profile_module.json, "dumps", fail_inner)
    else:
        monkeypatch.setattr(source_profile_module.hmac, "digest", fail_inner)

    actions = {
        "signed": lambda: SourceProfileExpectation.signed(
            site_id=SITE_ID,
            camera_id=CAMERA_IDS[0],
            source_index=0,
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
            codec="h264",
            width=1920,
            height=1080,
            fps_min=24.0,
            fps_max=26.0,
            bitrate_kbps_min=3_500,
            bitrate_kbps_max=4_500,
            max_timestamp_gap_ns=2_000_000_000,
            max_timestamp_skew_ns=500_000_000,
            stale_after_ns=5_000_000_000,
        ),
        "tracker": lambda: NativeSourceProfileTracker(
            site_id=SITE_ID,
            expectations=expectations,
            commitment_key=COMMITMENT_KEY,
            milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
            milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
            delta_capacity=100,
            epoch_started_monotonic_ns=0,
        ),
        "bind": lambda: tracker.bind_source(
            camera_id=CAMERA_IDS[0],
            resolved_url=raw_url,
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=0,
        ),
    }

    with pytest.raises(ValueError) as caught:
        actions[entry_point]()

    traceback_text = _source_profile_traceback_text(caught.value)
    assert "traceback-url-secret" not in traceback_text
    assert "traceback-credential" not in traceback_text
    assert COMMITMENT_KEY.decode() not in traceback_text
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_caps_require_exact_codec_dimensions_and_inclusive_signed_ranges() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)

    assert callbacks[0].on_rtp_caps(
        replace(CAPS, fps=24.0, bitrate_kbps=3_500),
        observed_monotonic_ns=0,
    )
    assert callbacks[1].on_rtp_caps(
        replace(CAPS, fps=26.0, bitrate_kbps=4_500),
        observed_monotonic_ns=0,
    )
    mismatches = (
        replace(CAPS, codec="h265"),
        replace(CAPS, width=1280),
        replace(CAPS, height=720),
        replace(CAPS, fps=23.999),
        replace(CAPS, fps=26.001),
        replace(CAPS, bitrate_kbps=3_499),
        replace(CAPS, bitrate_kbps=4_501),
    )
    for callback, caps in zip(callbacks[2:], mismatches, strict=False):
        assert not callback.on_rtp_caps(caps, observed_monotonic_ns=0)
        assert SourceProfileFailureCode.PROFILE_MISMATCH.value in _failures(
            tracker, callback.camera_id
        )


def test_callbacks_require_native_caps_parser_and_decoder_provenance() -> None:
    tracker = _tracker()
    callback = _bind_all(tracker)[0]

    assert not callback.on_decoded_frame(
        decoded_frames=1,
        source_ntp_ns=SOURCE_NTP_BASE_NS,
        observed_monotonic_ns=0,
    )
    assert SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE.value in _failures(
        tracker, callback.camera_id
    )
    assert not hasattr(tracker, "record_observation")


def test_callback_handles_reject_public_forgery_mutation_and_cross_camera_reuse() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)
    first = callbacks[0]
    before = tracker.snapshot()

    with pytest.raises(TypeError):
        NativeSourceCallbacks(
            tracker,
            camera_id=CAMERA_IDS[1],
            epoch=tracker.epoch,
            callback_generation=before.sources[1].callback_generation,
        )
    with pytest.raises(AttributeError):
        first.camera_id = CAMERA_IDS[1]  # type: ignore[misc]
    with pytest.raises(AttributeError):
        first._callback_generation = before.sources[1].callback_generation  # type: ignore[misc]

    assert first.on_rtp_caps(CAPS, observed_monotonic_ns=0)
    after = tracker.snapshot()
    assert after.sources[0].observation is None
    assert after.sources[1].observation is None
    assert after.sources[1].failures == ()


def test_callback_gc_invalidates_exact_lease_and_old_close_cannot_close_rebind() -> None:
    tracker = _tracker()
    first = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    first_reference = weakref.ref(first)

    del first
    gc.collect()

    assert first_reference() is None
    assert not tracker.snapshot().sources[0].bound

    replacement = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    replacement.close()
    newer = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    replacement.close()

    assert tracker.snapshot().sources[0].bound
    assert newer.on_rtp_caps(CAPS, observed_monotonic_ns=0)


def test_observed_identity_is_mandatory_even_for_fake_callbacks() -> None:
    tracker = _tracker()

    with pytest.raises(TypeError):
        tracker.bind_source(  # type: ignore[call-arg]
            camera_id=CAMERA_IDS[0],
            bound_monotonic_ns=0,
        )

    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url="rtsp://fixture.invalid/observed-not-expected",
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert SourceProfileFailureCode.PROFILE_MISMATCH.value in _failures(tracker, callback.camera_id)


def test_wrong_identity_callback_is_inert_for_every_native_method_and_close_safe() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url="rtsp://fixture.invalid/observed-not-expected",
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=4,
    )
    rejected = (tracker.snapshot(), tracker.deltas_since(0))
    calls = (
        lambda: callback.on_rtp_caps(CAPS, observed_monotonic_ns=4),
        lambda: callback.on_parser_counter(
            parser_bytes=10_000,
            source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
            observed_monotonic_ns=4,
        ),
        lambda: callback.on_decoded_frame(
            decoded_frames=1,
            source_ntp_ns=SOURCE_NTP_BASE_NS,
            observed_monotonic_ns=4,
        ),
    )

    for call in calls:
        assert not call()
        assert (tracker.snapshot(), tracker.deltas_since(0)) == rejected

    callback.close()
    closed = tracker.snapshot()
    assert not closed.sources[0].bound
    callback.close()
    assert tracker.restart_epoch(started_monotonic_ns=1).epoch == 2


@pytest.mark.parametrize(
    "transplanted_slots",
    (
        ("camera_id", "_callback_generation", "_capability"),
        (
            "_tracker_ref",
            "camera_id",
            "_epoch",
            "_callback_generation",
            "_capability",
        ),
    ),
)
def test_wrong_identity_handle_rejects_partial_and_full_capability_transplants(
    transplanted_slots: tuple[str, ...],
) -> None:
    tracker = _tracker()
    wrong = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url="rtsp://fixture.invalid/observed-not-expected",
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    valid = tracker.bind_source(
        camera_id=CAMERA_IDS[1],
        resolved_url=_resolved_url(1),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    for slot_name in transplanted_slots:
        if hasattr(valid, slot_name):
            object.__setattr__(wrong, slot_name, getattr(valid, slot_name))
    before = (tracker.snapshot(), tracker.deltas_since(0))

    assert not wrong.on_rtp_caps(CAPS, observed_monotonic_ns=0)
    assert not wrong.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
        observed_monotonic_ns=0,
    )
    assert not wrong.on_decoded_frame(
        decoded_frames=1,
        source_ntp_ns=SOURCE_NTP_BASE_NS,
        observed_monotonic_ns=0,
    )
    assert (tracker.snapshot(), tracker.deltas_since(0)) == before

    wrong.close()
    valid.close()
    assert not tracker.snapshot().sources[0].bound
    assert not tracker.snapshot().sources[1].bound


def test_cross_camera_slot_transplant_cannot_retarget_valid_handle() -> None:
    tracker = _tracker()
    first = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    second = tracker.bind_source(
        camera_id=CAMERA_IDS[1],
        resolved_url=_resolved_url(1),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    for slot_name in (
        "_tracker_ref",
        "camera_id",
        "_epoch",
        "_callback_generation",
        "_capability",
    ):
        if hasattr(second, slot_name):
            object.__setattr__(first, slot_name, getattr(second, slot_name))

    assert first.on_rtp_caps(CAPS, observed_monotonic_ns=0)
    deltas = tracker.deltas_since(0)
    assert deltas[-1].camera_id == CAMERA_IDS[0]
    assert tracker.snapshot().sources[0].bound
    assert tracker.snapshot().sources[1].observation is None

    first.close()
    second.close()
    assert not tracker.snapshot().sources[0].bound
    assert not tracker.snapshot().sources[1].bound


def test_native_observations_publish_monotonic_immutable_deltas() -> None:
    tracker = _tracker()
    callback = _bind_all(tracker)[0]

    assert _observe(callback, sample_number=1, elapsed_ns=0)
    assert _observe(callback, sample_number=2, elapsed_ns=40_000_000)

    source = tracker.snapshot().sources[0]
    assert source.observation is not None
    assert source.observation.caps == CAPS
    assert source.observation.parser_bytes == 20_000
    assert source.observation.decoded_frames == 2
    assert source.observation.source_timestamp_ns == SOURCE_TIMESTAMP_BASE_NS + 40_000_000
    assert source.observation.source_ntp_ns == SOURCE_NTP_BASE_NS + 40_000_000
    generations = tuple(delta.generation for delta in tracker.deltas_since(0))
    assert generations == tuple(sorted(set(generations)))

    with pytest.raises(FrozenInstanceError):
        source.observation.decoded_frames = 3  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        tracker.deltas_since(0)[-1].generation = 0  # type: ignore[misc]


def test_tracker_clones_accepted_caps_before_retaining_them() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    submitted_caps = replace(CAPS)
    assert callback.on_rtp_caps(submitted_caps, observed_monotonic_ns=0)

    object.__setattr__(submitted_caps, "codec", "h265")
    assert callback.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
        observed_monotonic_ns=0,
    )
    assert callback.on_decoded_frame(
        decoded_frames=1,
        source_ntp_ns=SOURCE_NTP_BASE_NS,
        observed_monotonic_ns=0,
    )

    observation = tracker.snapshot().sources[0].observation
    assert observation is not None
    assert observation.caps == CAPS
    assert observation.caps is not submitted_caps


def test_native_observation_rejects_non_integer_or_nonpositive_counters() -> None:
    valid = {
        "caps": CAPS,
        "parser_bytes": 1,
        "decoded_frames": 1,
        "source_ntp_ns": 1,
        "source_timestamp_ns": 1,
        "observed_monotonic_ns": 0,
    }

    for field, value in (
        ("parser_bytes", True),
        ("decoded_frames", 0),
        ("source_ntp_ns", -1),
        ("source_timestamp_ns", 1.5),
        ("observed_monotonic_ns", -1),
    ):
        with pytest.raises(ValueError):
            NativeSourceObservation(**(valid | {field: value}))


def test_native_observation_accepts_int64_boundary_and_remains_json_serializable() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)
    assert callback.on_parser_counter(
        parser_bytes=INT64_MAX,
        source_timestamp_ns=INT64_MAX,
        observed_monotonic_ns=0,
    )
    assert callback.on_decoded_frame(
        decoded_frames=INT64_MAX,
        source_ntp_ns=INT64_MAX,
        observed_monotonic_ns=0,
    )

    observation = tracker.snapshot().sources[0].observation
    assert observation is not None
    assert observation.parser_bytes == INT64_MAX
    assert observation.decoded_frames == INT64_MAX
    json.dumps(tracker.snapshot().to_dict())
    json.dumps([delta.to_dict() for delta in tracker.deltas_since(0)])


def test_snapshot_nested_records_are_deep_owned_from_live_tracker_state() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    local_caps = replace(CAPS)
    assert _observe(
        callback,
        sample_number=1,
        elapsed_ns=0,
        caps=local_caps,
    )
    assert not callback.on_parser_counter(
        parser_bytes=20_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
        observed_monotonic_ns=1,
    )
    exposed = tracker.snapshot()
    exposed_source = exposed.sources[0]
    assert exposed_source.observation is not None
    assert exposed_source.failures

    object.__setattr__(exposed_source.observation, "decoded_frames", INT64_MAX)
    object.__setattr__(exposed_source.observation.caps, "codec", "h265")
    object.__setattr__(
        exposed_source.failures[0],
        "code",
        SourceProfileFailureCode.STALE_SOURCE,
    )
    object.__setattr__(exposed_source, "stale_after_ns", 1)
    object.__setattr__(exposed.failures[0], "camera_id", CAMERA_IDS[1])

    assert callback.on_parser_counter(
        parser_bytes=20_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    assert callback.on_decoded_frame(
        decoded_frames=2,
        source_ntp_ns=SOURCE_NTP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    current = tracker.snapshot()
    current_source = current.sources[0]
    assert current_source.observation is not None
    assert current_source.observation.decoded_frames == 2
    assert current_source.observation.caps == CAPS
    assert current_source.stale_after_ns == 5_000_000_000
    assert current_source.failures[0].code == SourceProfileFailureCode.TIMESTAMP_REPLAY
    assert current.failures[0].camera_id == CAMERA_IDS[0]


def test_returned_deltas_are_deep_owned_from_the_bounded_event_buffer() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert _observe(callback, sample_number=1, elapsed_ns=0)
    exposed = tracker.deltas_since(0)
    original = tuple(delta.to_dict() for delta in exposed)

    object.__setattr__(exposed[0], "event", "failure")
    object.__setattr__(exposed[-1], "decoded_frames", INT64_MAX)
    object.__setattr__(
        exposed[-1],
        "failures",
        (SourceProfileFailureCode.STALE_SOURCE,),
    )

    reread = tracker.deltas_since(0)
    assert tuple(delta.to_dict() for delta in reread) == original
    assert all(
        reread_delta is not exposed_delta
        for reread_delta, exposed_delta in zip(reread, exposed, strict=True)
    )


def test_exported_failure_codes_have_no_mutable_shared_singleton_state() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url="rtsp://fixture.invalid/observed-not-expected",
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    snapshot = tracker.snapshot()
    exported_code = snapshot.failures[0].code
    original_value = "profile_mismatch"
    mutation_succeeded = False

    try:
        object.__setattr__(exported_code, "_value_", "tampered_failure_code")
        mutation_succeeded = True
        reread = tracker.snapshot()
        redeltas = tracker.deltas_since(0)
        assert reread.failures[0].code.value == original_value
        assert redeltas[-1].failures[0].value == original_value
        assert original_value in json.dumps(reread.to_dict(), sort_keys=True)
        assert original_value in json.dumps(
            [delta.to_dict() for delta in redeltas],
            sort_keys=True,
        )
    except (AttributeError, TypeError):
        pass
    finally:
        if mutation_succeeded:
            object.__setattr__(exported_code, "_value_", original_value)
    callback.close()


def test_exported_record_integer_fields_reject_bool_and_int64_overflow() -> None:
    failure, source, snapshot, delta = _valid_public_records()
    integer_fields = (
        (failure, ("epoch", "first_generation")),
        (
            source,
            (
                "source_index",
                "callback_generation",
                "baseline_duration_ns",
                "continuous_observations",
                "maximum_observed_gap_ns",
                "continuity_gap_bound_ns",
                "stale_after_ns",
                "prewarm_completed_monotonic_ns",
            ),
        ),
        (
            snapshot,
            (
                "epoch",
                "generation",
                "epoch_started_generation",
                "epoch_started_monotonic_ns",
                "ready_at_monotonic_ns",
            ),
        ),
        (
            delta,
            (
                "epoch",
                "generation",
                "parser_bytes",
                "decoded_frames",
                "source_ntp_ns",
                "source_timestamp_ns",
            ),
        ),
    )

    for record, field_names in integer_fields:
        for field_name in field_names:
            for invalid in (True, INT64_MAX + 1, 10**10_000):
                with pytest.raises(ValueError, match="bounds"):
                    replace(record, **{field_name: invalid})


def test_exported_record_constructors_reject_invalid_shapes_and_cross_fields() -> None:
    failure, source, snapshot, delta = _valid_public_records()
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=1,
        decoded_frames=1,
        source_ntp_ns=1,
        source_timestamp_ns=1,
        observed_monotonic_ns=0,
    )
    stale_failure = SourceProfileFailure(
        camera_id=CAMERA_IDS[0],
        code=SourceProfileFailureCode.STALE_SOURCE,
        epoch=1,
        first_generation=2,
    )
    wrong_epoch_failure = replace(failure, epoch=2, first_generation=3)
    wrong_generation_failure = replace(failure, first_generation=3)
    wrong_epoch_source = replace(source, failures=(wrong_epoch_failure,))
    wrong_generation_source = replace(
        source,
        failures=(wrong_generation_failure,),
    )
    duplicate_camera_source = replace(
        snapshot.sources[1],
        camera_id=CAMERA_IDS[0],
    )
    observation_delta = NativeSourceProfileDelta(
        epoch=1,
        generation=2,
        event="observation",
        camera_id=CAMERA_IDS[0],
        ready=False,
        failures=(),
        parser_bytes=1,
        decoded_frames=1,
        source_ntp_ns=1,
        source_timestamp_ns=1,
    )
    epoch_delta = NativeSourceProfileDelta(
        epoch=1,
        generation=1,
        event="epoch_started",
        camera_id=None,
        ready=False,
        failures=(),
    )
    invalid_constructors = (
        lambda: replace(failure, camera_id=""),
        lambda: replace(failure, camera_id=" camera-01"),
        lambda: replace(failure, camera_id="camera-\ud800"),
        lambda: replace(failure, camera_id=1),  # type: ignore[arg-type]
        lambda: replace(
            failure,
            code=SourceProfileFailureCode.PROFILE_MISMATCH.value,
        ),
        lambda: replace(source, bound=1),  # type: ignore[arg-type]
        lambda: replace(source, identity_verified=0),  # type: ignore[arg-type]
        lambda: replace(source, observation=object()),  # type: ignore[arg-type]
        lambda: replace(source, failures=[failure]),  # type: ignore[arg-type]
        lambda: replace(source, failures=("invalid",)),  # type: ignore[arg-type]
        lambda: replace(
            source,
            failures=(replace(failure, camera_id=CAMERA_IDS[1]),),
        ),
        lambda: replace(source, failures=(stale_failure, failure)),
        lambda: replace(source, failures=(failure, failure)),
        lambda: replace(source, bound=False),
        lambda: replace(source, continuous_observations=1),
        lambda: replace(source, maximum_observed_gap_ns=1),
        lambda: replace(
            source,
            observation=observation,
            continuous_observations=1,
        ),
        lambda: replace(snapshot, ready=1),  # type: ignore[arg-type]
        lambda: replace(snapshot, ready=True),
        lambda: replace(snapshot, ready_at_monotonic_ns=1),
        lambda: replace(snapshot, sources=list(snapshot.sources)),  # type: ignore[arg-type]
        lambda: replace(snapshot, sources=snapshot.sources[:-1]),
        lambda: replace(snapshot, sources=tuple(reversed(snapshot.sources))),
        lambda: replace(
            snapshot,
            sources=(
                snapshot.sources[0],
                duplicate_camera_source,
                *snapshot.sources[2:],
            ),
        ),
        lambda: replace(snapshot, failures=[]),  # type: ignore[arg-type]
        lambda: replace(snapshot, failures=()),
        lambda: replace(
            snapshot,
            sources=(wrong_epoch_source, *snapshot.sources[1:]),
            failures=(wrong_epoch_failure,),
        ),
        lambda: replace(
            snapshot,
            sources=(wrong_generation_source, *snapshot.sources[1:]),
            failures=(wrong_generation_failure,),
        ),
        lambda: replace(delta, event="unknown"),
        lambda: replace(delta, event=1),  # type: ignore[arg-type]
        lambda: replace(delta, camera_id=None),
        lambda: replace(delta, ready=0),  # type: ignore[arg-type]
        lambda: replace(delta, failures=[SourceProfileFailureCode.PROFILE_MISMATCH]),  # type: ignore[arg-type]
        lambda: replace(delta, failures=("profile_mismatch",)),  # type: ignore[arg-type]
        lambda: replace(
            delta,
            failures=(
                SourceProfileFailureCode.STALE_SOURCE,
                SourceProfileFailureCode.PROFILE_MISMATCH,
            ),
        ),
        lambda: replace(
            delta,
            failures=(
                SourceProfileFailureCode.PROFILE_MISMATCH,
                SourceProfileFailureCode.PROFILE_MISMATCH,
            ),
        ),
        lambda: replace(delta, parser_bytes=1),
        lambda: replace(observation_delta, decoded_frames=None),
        lambda: replace(epoch_delta, camera_id=CAMERA_IDS[0]),
        lambda: replace(epoch_delta, ready=True),
    )

    for construct in invalid_constructors:
        with pytest.raises(ValueError):
            construct()


def test_source_state_snapshot_accepts_only_reachable_observation_states() -> None:
    _, _, profile, _ = _valid_public_records()
    initial = profile.sources[1]
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=1,
        decoded_frames=1,
        source_ntp_ns=1,
        source_timestamp_ns=1,
        observed_monotonic_ns=1,
    )
    single = NativeSourceStateSnapshot(
        camera_id=CAMERA_IDS[1],
        source_index=1,
        bound=True,
        identity_verified=True,
        callback_generation=1,
        observation=observation,
        baseline_duration_ns=0,
        continuous_observations=1,
        maximum_observed_gap_ns=0,
        continuity_gap_bound_ns=1_000_000_000,
        stale_after_ns=5_000_000_000,
        prewarm_completed_monotonic_ns=None,
        failures=(),
    )
    multiple = replace(
        single,
        observation=replace(
            observation,
            parser_bytes=2,
            decoded_frames=2,
            source_ntp_ns=2,
            source_timestamp_ns=2,
        ),
        baseline_duration_ns=1,
        continuous_observations=2,
        maximum_observed_gap_ns=1,
    )
    post_close = replace(
        multiple,
        bound=False,
        callback_generation=2,
    )

    assert post_close.observation is not None
    assert post_close.continuous_observations == 2
    invalid_states = (
        lambda: replace(initial, identity_verified=True),
        lambda: replace(
            single,
            bound=False,
            callback_generation=0,
        ),
        lambda: replace(single, baseline_duration_ns=1),
        lambda: replace(single, maximum_observed_gap_ns=1),
        lambda: replace(single, continuous_observations=2),
        lambda: replace(
            multiple,
            baseline_duration_ns=0,
        ),
        lambda: replace(
            multiple,
            maximum_observed_gap_ns=0,
        ),
    )
    for construct in invalid_states:
        with pytest.raises(ValueError):
            construct()


def test_exported_record_constructors_deep_own_nested_records() -> None:
    failure, _, snapshot, _ = _valid_public_records()
    failure = replace(failure, first_generation=3)
    submitted_caps = replace(CAPS)
    observation = NativeSourceObservation(
        caps=submitted_caps,
        parser_bytes=1,
        decoded_frames=1,
        source_ntp_ns=1,
        source_timestamp_ns=1,
        observed_monotonic_ns=0,
    )
    state = NativeSourceStateSnapshot(
        camera_id=CAMERA_IDS[0],
        source_index=0,
        bound=True,
        identity_verified=True,
        callback_generation=1,
        observation=observation,
        baseline_duration_ns=0,
        continuous_observations=1,
        maximum_observed_gap_ns=0,
        continuity_gap_bound_ns=1_000_000_000,
        stale_after_ns=5_000_000_000,
        prewarm_completed_monotonic_ns=None,
        failures=(failure,),
    )
    owned_snapshot = NativeSourceProfileSnapshot(
        epoch=snapshot.epoch,
        generation=snapshot.generation,
        epoch_started_generation=snapshot.epoch_started_generation,
        ready=snapshot.ready,
        epoch_started_monotonic_ns=snapshot.epoch_started_monotonic_ns,
        ready_at_monotonic_ns=snapshot.ready_at_monotonic_ns,
        sources=snapshot.sources,
        failures=snapshot.failures,
    )

    object.__setattr__(submitted_caps, "codec", "h265")
    object.__setattr__(observation, "decoded_frames", INT64_MAX)
    object.__setattr__(failure, "camera_id", CAMERA_IDS[1])
    object.__setattr__(snapshot.sources[0], "camera_id", CAMERA_IDS[1])

    assert state.observation is not None
    assert state.observation.decoded_frames == 1
    assert state.observation.caps == CAPS
    assert state.failures[0].camera_id == CAMERA_IDS[0]
    assert owned_snapshot.sources[0].camera_id == CAMERA_IDS[0]
    assert owned_snapshot.failures[0].camera_id == CAMERA_IDS[0]


def test_every_accepted_exported_record_has_total_json_serialization() -> None:
    failure, source, snapshot, delta = _valid_public_records()
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=1,
        decoded_frames=1,
        source_ntp_ns=1,
        source_timestamp_ns=1,
        observed_monotonic_ns=0,
    )

    for record in (
        _expectations()[0],
        CAPS,
        observation,
        failure,
        source,
        snapshot,
        delta,
    ):
        serialized = json.dumps(
            record.to_dict(),
            allow_nan=False,
            ensure_ascii=False,
        ).encode("utf-8")
        assert serialized


def test_failure_and_delta_epoch_cannot_exceed_generation() -> None:
    failure, _, _, delta = _valid_public_records()

    with pytest.raises(ValueError, match="epoch"):
        replace(failure, epoch=3)
    with pytest.raises(ValueError, match="epoch"):
        replace(delta, epoch=3)


def test_delta_event_truth_table_matches_reachable_transitions() -> None:
    failure_code = SourceProfileFailureCode.PROFILE_MISMATCH
    valid_deltas = (
        NativeSourceProfileDelta(
            epoch=1,
            generation=1,
            event="epoch_started",
            camera_id=None,
            ready=False,
            failures=(),
        ),
        NativeSourceProfileDelta(
            epoch=1,
            generation=2,
            event="source_bound",
            camera_id=CAMERA_IDS[0],
            ready=False,
            failures=(),
        ),
        NativeSourceProfileDelta(
            epoch=1,
            generation=3,
            event="callback_closed",
            camera_id=CAMERA_IDS[0],
            ready=False,
            failures=(),
        ),
        NativeSourceProfileDelta(
            epoch=1,
            generation=4,
            event="failure",
            camera_id=CAMERA_IDS[0],
            ready=False,
            failures=(failure_code,),
        ),
        NativeSourceProfileDelta(
            epoch=1,
            generation=5,
            event="rtp_caps",
            camera_id=CAMERA_IDS[0],
            ready=True,
            failures=(),
        ),
        NativeSourceProfileDelta(
            epoch=1,
            generation=6,
            event="observation",
            camera_id=CAMERA_IDS[0],
            ready=True,
            failures=(),
            parser_bytes=1,
            decoded_frames=1,
            source_ntp_ns=1,
            source_timestamp_ns=1,
        ),
    )
    for delta in valid_deltas:
        assert json.dumps(delta.to_dict(), allow_nan=False)

    source_bound = valid_deltas[1]
    callback_closed = valid_deltas[2]
    rtp_caps = valid_deltas[4]
    observation = valid_deltas[5]
    invalid_deltas = (
        lambda: replace(source_bound, ready=True),
        lambda: replace(callback_closed, ready=True),
        lambda: replace(rtp_caps, failures=(failure_code,)),
        lambda: replace(observation, failures=(failure_code,)),
    )
    for construct in invalid_deltas:
        with pytest.raises(ValueError):
            construct()


def test_exported_record_int64_boundaries_are_json_serializable() -> None:
    failure = SourceProfileFailure(
        camera_id=CAMERA_IDS[0],
        code=SourceProfileFailureCode.PROFILE_MISMATCH,
        epoch=INT64_MAX - 1,
        first_generation=INT64_MAX,
    )
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=INT64_MAX,
        decoded_frames=INT64_MAX,
        source_ntp_ns=INT64_MAX,
        source_timestamp_ns=INT64_MAX,
        observed_monotonic_ns=INT64_MAX,
    )
    source = NativeSourceStateSnapshot(
        camera_id=CAMERA_IDS[0],
        source_index=0,
        bound=False,
        identity_verified=True,
        callback_generation=2,
        observation=observation,
        baseline_duration_ns=INT64_MAX - 1,
        continuous_observations=INT64_MAX,
        maximum_observed_gap_ns=1,
        continuity_gap_bound_ns=1,
        stale_after_ns=300_000_000_000,
        prewarm_completed_monotonic_ns=INT64_MAX - 1,
        failures=(),
    )
    initial = _tracker().snapshot()
    snapshot = NativeSourceProfileSnapshot(
        epoch=INT64_MAX,
        generation=INT64_MAX,
        epoch_started_generation=INT64_MAX,
        ready=False,
        epoch_started_monotonic_ns=INT64_MAX,
        ready_at_monotonic_ns=None,
        sources=initial.sources,
        failures=(),
    )
    delta = NativeSourceProfileDelta(
        epoch=INT64_MAX,
        generation=INT64_MAX,
        event="observation",
        camera_id=CAMERA_IDS[0],
        ready=False,
        failures=(SourceProfileFailureCode.PROFILE_MISMATCH,),
        parser_bytes=INT64_MAX,
        decoded_frames=INT64_MAX,
        source_ntp_ns=INT64_MAX,
        source_timestamp_ns=INT64_MAX,
    )

    for record in (failure, source, snapshot, delta):
        assert json.loads(json.dumps(record.to_dict(), allow_nan=False))


def test_int64_overflow_and_huge_integers_reject_before_state_mutation() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    before = tracker.snapshot()
    overflow = INT64_MAX + 1
    huge = 10**10_000
    actions = (
        lambda: callback.on_rtp_caps(CAPS, observed_monotonic_ns=overflow),
        lambda: callback.on_parser_counter(
            parser_bytes=overflow,
            source_timestamp_ns=1,
            observed_monotonic_ns=0,
        ),
        lambda: callback.on_parser_counter(
            parser_bytes=1,
            source_timestamp_ns=overflow,
            observed_monotonic_ns=0,
        ),
        lambda: callback.on_decoded_frame(
            decoded_frames=overflow,
            source_ntp_ns=1,
            observed_monotonic_ns=0,
        ),
        lambda: callback.on_decoded_frame(
            decoded_frames=1,
            source_ntp_ns=overflow,
            observed_monotonic_ns=0,
        ),
        lambda: tracker.bind_source(
            camera_id=CAMERA_IDS[1],
            resolved_url=_resolved_url(1),
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=overflow,
        ),
        lambda: tracker.restart_epoch(started_monotonic_ns=overflow),
        lambda: tracker.check_stale(now_monotonic_ns=overflow),
        lambda: tracker.acknowledge_deltas(through_generation=overflow),
        lambda: tracker.deltas_since(overflow),
        lambda: NativeSourceObservation(
            caps=CAPS,
            parser_bytes=huge,
            decoded_frames=1,
            source_ntp_ns=1,
            source_timestamp_ns=1,
            observed_monotonic_ns=0,
        ),
    )

    for action in actions:
        with pytest.raises(ValueError, match="bounds"):
            action()
        assert tracker.snapshot() == before


def test_generation_overflow_rejects_accepted_caps_before_any_state_mutation() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    tracker._generation = INT64_MAX - 1  # noqa: SLF001
    state = tracker._states[CAMERA_IDS[0]]  # noqa: SLF001
    before = (
        tracker.snapshot(),
        tracker.deltas_since(0),
        tracker._monotonic_high_water_ns,  # noqa: SLF001
        state.monotonic_high_water_ns,
        state.caps,
        state.caps_monotonic_ns,
    )

    with pytest.raises(OverflowError, match="generation"):
        callback.on_rtp_caps(CAPS, observed_monotonic_ns=1)

    state = tracker._states[CAMERA_IDS[0]]  # noqa: SLF001
    after = (
        tracker.snapshot(),
        tracker.deltas_since(0),
        tracker._monotonic_high_water_ns,  # noqa: SLF001
        state.monotonic_high_water_ns,
        state.caps,
        state.caps_monotonic_ns,
    )
    assert after == before


def test_generation_overflow_rejects_restart_before_any_state_mutation() -> None:
    tracker = _tracker()
    _bind_all(tracker)
    tracker._generation = INT64_MAX  # noqa: SLF001
    before = (tracker.snapshot(), tracker.deltas_since(0))

    with pytest.raises(OverflowError, match="generation"):
        tracker.restart_epoch(started_monotonic_ns=1)

    assert (tracker.snapshot(), tracker.deltas_since(0)) == before


@pytest.mark.parametrize("generation", (INT64_MAX - 1, INT64_MAX))
def test_bind_rejects_before_mutation_without_capacity_for_event_and_close(
    generation: int,
) -> None:
    tracker = _tracker()
    tracker._generation = generation  # noqa: SLF001
    before = (tracker.snapshot(), tracker.deltas_since(0))

    with pytest.raises(OverflowError, match="generation"):
        tracker.bind_source(
            camera_id=CAMERA_IDS[0],
            resolved_url=_resolved_url(0),
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=0,
        )

    assert (tracker.snapshot(), tracker.deltas_since(0)) == before


def test_reserved_close_slot_blocks_normal_event_then_closes_at_int64_max() -> None:
    tracker = _tracker()
    tracker._generation = INT64_MAX - 2  # noqa: SLF001
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    before_caps = (tracker.snapshot(), tracker.deltas_since(0))

    with pytest.raises(OverflowError, match="generation"):
        callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)

    assert (tracker.snapshot(), tracker.deltas_since(0)) == before_caps
    callback.close()
    closed = tracker.snapshot()
    assert closed.generation == INT64_MAX
    assert not closed.sources[0].bound
    callback.close()
    assert tracker.snapshot() == closed


def test_gc_finalizer_consumes_reserved_close_slot_at_int64_max() -> None:
    tracker = _tracker()
    tracker._generation = INT64_MAX - 2  # noqa: SLF001
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    callback_reference = weakref.ref(callback)

    del callback
    gc.collect()

    assert callback_reference() is None
    snapshot = tracker.snapshot()
    assert snapshot.generation == INT64_MAX
    assert not snapshot.sources[0].bound


def test_twenty_live_handles_reserve_all_close_events() -> None:
    tracker = _tracker()
    tracker._generation = INT64_MAX - 40  # noqa: SLF001
    callbacks = _bind_all(tracker)
    assert tracker.snapshot().generation == INT64_MAX - 20

    with pytest.raises(OverflowError, match="generation"):
        callbacks[0].on_rtp_caps(CAPS, observed_monotonic_ns=0)

    for callback in callbacks:
        callback.close()
    snapshot = tracker.snapshot()
    assert snapshot.generation == INT64_MAX
    assert all(not source.bound for source in snapshot.sources)


def test_restart_releases_live_close_reservations_atomically() -> None:
    tracker = _tracker()
    tracker._generation = INT64_MAX - 2  # noqa: SLF001
    old_callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )

    restarted = tracker.restart_epoch(started_monotonic_ns=1)

    assert restarted.generation == INT64_MAX
    assert all(not source.bound for source in restarted.sources)
    assert not old_callback.on_rtp_caps(CAPS, observed_monotonic_ns=1)
    old_callback.close()
    assert tracker.snapshot() == restarted


def test_bind_rejects_callback_generation_that_cannot_be_closed() -> None:
    tracker = _tracker()
    state = tracker._states[CAMERA_IDS[0]]  # noqa: SLF001
    state.identity_verified = True
    state.callback_generation = INT64_MAX - 1
    tracker._generation = INT64_MAX  # noqa: SLF001
    before = (tracker.snapshot(), tracker.deltas_since(0))

    with pytest.raises(OverflowError, match="callback generation"):
        tracker.bind_source(
            camera_id=CAMERA_IDS[0],
            resolved_url=_resolved_url(0),
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=0,
        )

    assert (tracker.snapshot(), tracker.deltas_since(0)) == before


def test_timestamp_regression_and_replay_are_distinct_sticky_failures() -> None:
    tracker = _tracker()
    regression, replay, *_ = _bind_all(tracker)
    assert _observe(regression, sample_number=1, elapsed_ns=0)
    assert _observe(replay, sample_number=1, elapsed_ns=0)

    assert not regression.on_parser_counter(
        parser_bytes=20_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS - 1,
        observed_monotonic_ns=1,
    )
    assert not replay.on_parser_counter(
        parser_bytes=20_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
        observed_monotonic_ns=1,
    )
    assert SourceProfileFailureCode.TIMESTAMP_REGRESSION.value in _failures(
        tracker, regression.camera_id
    )
    assert SourceProfileFailureCode.TIMESTAMP_REPLAY.value in _failures(tracker, replay.camera_id)

    assert regression.on_parser_counter(
        parser_bytes=30_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=2,
    )
    assert SourceProfileFailureCode.TIMESTAMP_REGRESSION.value in _failures(
        tracker, regression.camera_id
    )


def test_gap_skew_and_counter_regression_fail_sticky() -> None:
    tracker = _tracker()
    gap, skew, parser_regression, decoder_regression, *_ = _bind_all(tracker)
    for callback in (gap, skew, parser_regression, decoder_regression):
        assert _observe(callback, sample_number=1, elapsed_ns=0)

    assert not parser_regression.on_parser_counter(
        parser_bytes=9_999,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    assert SourceProfileFailureCode.COUNTER_REGRESSION.value in _failures(
        tracker, parser_regression.camera_id
    )

    assert decoder_regression.on_parser_counter(
        parser_bytes=20_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    assert not decoder_regression.on_decoded_frame(
        decoded_frames=1,
        source_ntp_ns=SOURCE_NTP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    assert SourceProfileFailureCode.COUNTER_REGRESSION.value in _failures(
        tracker, decoder_regression.camera_id
    )

    assert skew.on_parser_counter(
        parser_bytes=20_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 40_000_000,
        observed_monotonic_ns=40_000_000,
    )
    assert not skew.on_decoded_frame(
        decoded_frames=2,
        source_ntp_ns=SOURCE_NTP_BASE_NS + 540_000_001,
        observed_monotonic_ns=40_000_000,
    )
    assert SourceProfileFailureCode.EXCESSIVE_SKEW.value in _failures(tracker, skew.camera_id)

    assert gap.on_parser_counter(
        parser_bytes=20_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 2_000_000_001,
        observed_monotonic_ns=2_000_000_001,
    )
    assert not gap.on_decoded_frame(
        decoded_frames=2,
        source_ntp_ns=SOURCE_NTP_BASE_NS + 2_000_000_001,
        observed_monotonic_ns=2_000_000_001,
    )
    assert SourceProfileFailureCode.EXCESSIVE_GAP.value in _failures(tracker, gap.camera_id)


def test_stale_source_failure_is_sticky_and_revokes_readiness() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)
    _observe_all_through(callbacks, final_elapsed_ns=PREWARM_NS)
    assert tracker.snapshot().ready

    tracker.check_stale(now_monotonic_ns=PREWARM_NS + 5_000_000_001)

    assert not tracker.snapshot().ready
    assert all(
        SourceProfileFailureCode.STALE_SOURCE.value in _failures(tracker, camera_id)
        for camera_id in CAMERA_IDS
    )


def test_readiness_refresh_marks_nineteen_stale_peers_when_only_one_stays_fresh() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)
    sample_number = _observe_all_through(
        callbacks,
        final_elapsed_ns=PREWARM_NS,
    )
    assert tracker.snapshot().ready

    for elapsed_ns in range(
        PREWARM_NS + 40_000_000,
        PREWARM_NS + 5_080_000_000,
        40_000_000,
    ):
        sample_number += 1
        assert _observe(
            callbacks[0],
            sample_number=sample_number,
            elapsed_ns=elapsed_ns,
        )

    snapshot = tracker.snapshot()
    assert not snapshot.ready
    assert snapshot.sources[0].failures == ()
    assert all(
        SourceProfileFailureCode.STALE_SOURCE.value in _failures(tracker, camera_id)
        for camera_id in CAMERA_IDS[1:]
    )
    assert not tracker.deltas_since(0)[-1].ready


def test_any_later_native_callback_revokes_ready_before_emitting_a_stale_delta() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)
    sample_number = _observe_all_through(
        callbacks,
        final_elapsed_ns=PREWARM_NS,
    )
    assert tracker.snapshot().ready

    for elapsed_ns in range(
        PREWARM_NS + 40_000_000,
        PREWARM_NS + 5_000_000_001,
        40_000_000,
    ):
        sample_number += 1
        assert _observe(
            callbacks[0],
            sample_number=sample_number,
            elapsed_ns=elapsed_ns,
        )
    assert tracker.snapshot().ready

    assert callbacks[0].on_rtp_caps(
        CAPS,
        observed_monotonic_ns=PREWARM_NS + 5_000_000_001,
    )

    assert not tracker.snapshot().ready
    assert tracker.snapshot().sources[0].failures == ()
    assert all(
        SourceProfileFailureCode.STALE_SOURCE.value in _failures(tracker, camera_id)
        for camera_id in CAMERA_IDS[1:]
    )
    assert not tracker.deltas_since(0)[-1].ready


def test_sparse_sixty_second_endpoints_fail_continuous_prewarm_even_if_signed_gap_allows() -> None:
    expectations = _expectations(
        max_timestamp_gap_ns=120_000_000_000,
        stale_after_ns=120_000_000_000,
    )
    tracker = _tracker(expectations=expectations)
    callbacks = _bind_all(tracker)

    for callback in callbacks:
        assert _observe(callback, sample_number=1, elapsed_ns=0)
    for callback in callbacks:
        assert not _observe(
            callback,
            sample_number=2,
            elapsed_ns=PREWARM_NS,
        )

    snapshot = tracker.snapshot()
    assert not snapshot.ready
    assert all(source.baseline_duration_ns == 0 for source in snapshot.sources)
    assert all(
        SourceProfileFailureCode.EXCESSIVE_GAP.value in _failures(tracker, camera_id)
        for camera_id in CAMERA_IDS
    )


def test_bounded_delta_overflow_is_sticky_and_acknowledgement_bounds_storage() -> None:
    tracker = _tracker(delta_capacity=2)
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)

    assert len(tracker.deltas_since(0)) == 2
    assert SourceProfileFailureCode.BUFFER_OVERFLOW.value in _failures(tracker, CAMERA_IDS[0])
    last_generation = tracker.snapshot().generation
    tracker.acknowledge_deltas(through_generation=last_generation)
    assert tracker.deltas_since(0) == ()


def test_all_twenty_sources_need_full_sixty_second_fresh_epoch_baseline() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)

    sample_number = _observe_all_through(
        callbacks,
        final_elapsed_ns=PREWARM_NS - 1_000_000,
    )
    assert not tracker.snapshot().ready

    for callback in callbacks[:-1]:
        assert _observe(
            callback,
            sample_number=sample_number + 1,
            elapsed_ns=PREWARM_NS,
        )
    assert not tracker.snapshot().ready

    assert _observe(
        callbacks[-1],
        sample_number=sample_number + 1,
        elapsed_ns=PREWARM_NS,
    )
    snapshot = tracker.snapshot()
    assert snapshot.ready
    assert snapshot.ready_at_monotonic_ns == PREWARM_NS
    assert not tracker.ready_for_gate(gate_started_monotonic_ns=PREWARM_NS)
    assert tracker.ready_for_gate(gate_started_monotonic_ns=PREWARM_NS + 1)


def test_snapshots_project_each_signed_continuity_gap_bound() -> None:
    snapshot = _tracker().snapshot()

    assert all(source.continuity_gap_bound_ns == 83_333_334 for source in snapshot.sources)


def test_ready_snapshot_rejects_gap_above_projected_signed_bound() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)
    _observe_all_through(callbacks, final_elapsed_ns=PREWARM_NS)
    ready = tracker.snapshot()
    assert ready.ready
    poisoned_source = ready.sources[0]
    object.__setattr__(
        poisoned_source,
        "maximum_observed_gap_ns",
        INT64_MAX,
    )

    with pytest.raises(ValueError, match="gap"):
        replace(
            ready,
            sources=(poisoned_source, *ready.sources[1:]),
        )


def test_host_monotonic_high_water_rejects_caps_and_epoch_regression_without_mutation() -> None:
    tracker = _tracker()
    callback = _bind_all(tracker)[0]

    assert callback.on_rtp_caps(CAPS, observed_monotonic_ns=10)
    before_regression = tracker.snapshot()
    assert not callback.on_rtp_caps(CAPS, observed_monotonic_ns=9)
    after_regression = tracker.snapshot()

    assert SourceProfileFailureCode.HOST_MONOTONIC_REGRESSION.value in _failures(
        tracker, callback.camera_id
    )
    assert after_regression.sources[0].observation == before_regression.sources[0].observation
    with pytest.raises(ValueError, match="monotonic"):
        tracker.restart_epoch(started_monotonic_ns=1)
    assert tracker.snapshot().epoch == after_regression.epoch


@pytest.mark.parametrize(
    "rejection",
    (
        "caps_profile",
        "parser_provenance",
        "parser_counter",
        "parser_timestamp",
        "decoder_provenance",
        "decoder_counter",
    ),
)
def test_rejected_callback_payload_does_not_commit_restart_high_water(
    rejection: str,
) -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )

    if rejection == "caps_profile":
        accepted = callback.on_rtp_caps(
            replace(CAPS, codec="h265"),
            observed_monotonic_ns=4,
        )
    elif rejection == "parser_provenance":
        accepted = callback.on_parser_counter(
            parser_bytes=10_000,
            source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
            observed_monotonic_ns=4,
        )
    elif rejection == "decoder_provenance":
        assert callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)
        accepted = callback.on_decoded_frame(
            decoded_frames=1,
            source_ntp_ns=SOURCE_NTP_BASE_NS,
            observed_monotonic_ns=4,
        )
    else:
        assert _observe(callback, sample_number=1, elapsed_ns=0)
        if rejection == "parser_counter":
            accepted = callback.on_parser_counter(
                parser_bytes=9_999,
                source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
                observed_monotonic_ns=4,
            )
        elif rejection == "parser_timestamp":
            accepted = callback.on_parser_counter(
                parser_bytes=20_000,
                source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS - 1,
                observed_monotonic_ns=4,
            )
        else:
            assert callback.on_parser_counter(
                parser_bytes=20_000,
                source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
                observed_monotonic_ns=0,
            )
            accepted = callback.on_decoded_frame(
                decoded_frames=1,
                source_ntp_ns=SOURCE_NTP_BASE_NS + 1,
                observed_monotonic_ns=4,
            )

    assert not accepted
    assert tracker.restart_epoch(started_monotonic_ns=1).epoch == 2


def test_cross_camera_callback_lock_order_does_not_create_false_monotonic_regression() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)

    assert callbacks[1].on_rtp_caps(CAPS, observed_monotonic_ns=101)
    assert callbacks[0].on_rtp_caps(CAPS, observed_monotonic_ns=100)
    assert callbacks[0].on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 100,
        observed_monotonic_ns=100,
    )
    assert callbacks[1].on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 101,
        observed_monotonic_ns=101,
    )

    assert tracker.snapshot().failures == ()


def test_adversarial_future_callback_cannot_poison_peers_or_restart_high_water() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)

    assert not callbacks[0].on_rtp_caps(
        CAPS,
        observed_monotonic_ns=5_000_000_001,
    )
    assert callbacks[1].on_rtp_caps(CAPS, observed_monotonic_ns=1)
    assert callbacks[1].on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    assert callbacks[1].on_decoded_frame(
        decoded_frames=1,
        source_ntp_ns=SOURCE_NTP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )

    assert SourceProfileFailureCode.EXCESSIVE_GAP.value in _failures(tracker, CAMERA_IDS[0])
    assert tracker.snapshot().sources[1].failures == ()
    restarted = tracker.restart_epoch(started_monotonic_ns=2)
    assert restarted.epoch == 2


def test_adversarial_future_bind_cannot_poison_tracker_restart_high_water() -> None:
    tracker = _tracker()

    with pytest.raises(ValueError, match="gap"):
        tracker.bind_source(
            camera_id=CAMERA_IDS[0],
            resolved_url=_resolved_url(0),
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=5_000_000_001,
        )
    valid = tracker.bind_source(
        camera_id=CAMERA_IDS[1],
        resolved_url=_resolved_url(1),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=1,
    )

    assert valid.on_rtp_caps(CAPS, observed_monotonic_ns=1)
    assert tracker.restart_epoch(started_monotonic_ns=2).epoch == 2


def test_identity_mismatch_does_not_reserve_restart_high_water() -> None:
    tracker = _tracker()
    state = tracker._states[CAMERA_IDS[0]]  # noqa: SLF001
    before_high_water = (
        tracker._monotonic_high_water_ns,  # noqa: SLF001
        state.monotonic_high_water_ns,
    )

    rejected = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url="rtsp://fixture.invalid/wrong-source",
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=4,
    )

    state = tracker._states[CAMERA_IDS[0]]  # noqa: SLF001
    after_high_water = (
        tracker._monotonic_high_water_ns,  # noqa: SLF001
        state.monotonic_high_water_ns,
    )
    assert after_high_water == before_high_water
    assert SourceProfileFailureCode.PROFILE_MISMATCH.value in _failures(
        tracker,
        rejected.camera_id,
    )
    assert tracker.restart_epoch(started_monotonic_ns=1).epoch == 2


def test_epoch_restart_resets_readiness_and_rejects_late_callbacks() -> None:
    tracker = _tracker()
    old_callbacks = _bind_all(tracker)
    _observe_all_through(old_callbacks, final_elapsed_ns=PREWARM_NS)
    before = tracker.snapshot()
    assert before.ready

    tracker.restart_epoch(started_monotonic_ns=PREWARM_NS + 1)
    restarted = tracker.snapshot()
    generation_before_late_callback = restarted.generation

    assert restarted.epoch == before.epoch + 1
    assert not restarted.ready
    assert all(source.observation is None for source in restarted.sources)
    assert not old_callbacks[0].on_parser_counter(
        parser_bytes=30_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + PREWARM_NS + 1,
        observed_monotonic_ns=PREWARM_NS + 1,
    )
    assert tracker.snapshot().generation == generation_before_late_callback
    assert tracker.snapshot().failures == ()

    replacement = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=PREWARM_NS + 1,
    )
    replacement.close()
    assert not replacement.on_rtp_caps(
        CAPS,
        observed_monotonic_ns=PREWARM_NS + 1,
    )


def test_snapshots_are_immutable_and_thread_safe_across_twenty_sources() -> None:
    tracker = _tracker(delta_capacity=4_096)
    callbacks = _bind_all(tracker)
    sample_barrier = Barrier(len(callbacks))

    def observe_camera(item) -> None:
        source_index, callback = item
        for sample_number in range(1, 11):
            elapsed_ns = (sample_number - 1) * 40_000_000 + source_index
            assert _observe(
                callback,
                sample_number=sample_number,
                elapsed_ns=elapsed_ns,
            )
            sample_barrier.wait()

    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(observe_camera, enumerate(callbacks)))

    snapshot = tracker.snapshot()
    assert len(snapshot.sources) == 20
    assert snapshot.failures == ()
    assert all(
        source.observation is not None
        and source.observation.decoded_frames == 10
        and source.observation.parser_bytes == 100_000
        for source in snapshot.sources
    )
    with pytest.raises(FrozenInstanceError):
        snapshot.ready = True  # type: ignore[misc]
    with pytest.raises(TypeError):
        snapshot.sources[0] = snapshot.sources[1]  # type: ignore[index]


_PUBLIC_FAILURE_CODES = (
    ("PROFILE_MISMATCH", "profile_mismatch"),
    ("TIMESTAMP_REGRESSION", "timestamp_regression"),
    ("TIMESTAMP_REPLAY", "timestamp_replay"),
    ("EXCESSIVE_GAP", "excessive_gap"),
    ("EXCESSIVE_SKEW", "excessive_skew"),
    ("STALE_SOURCE", "stale_source"),
    ("COUNTER_REGRESSION", "counter_regression"),
    ("HOST_MONOTONIC_REGRESSION", "host_monotonic_regression"),
    ("BUFFER_OVERFLOW", "bounded_buffer_overflow"),
    ("INVALID_CALLBACK_PROVENANCE", "invalid_callback_provenance"),
)


def _restore_failure_code_class_attribute(
    name: str,
    raw_value: object,
    missing: object,
) -> None:
    if raw_value is missing:
        if name in vars(SourceProfileFailureCode):
            type.__delattr__(SourceProfileFailureCode, name)
    else:
        type.__setattr__(SourceProfileFailureCode, name, raw_value)


@pytest.mark.parametrize(("name", "value"), _PUBLIC_FAILURE_CODES)
def test_public_failure_code_access_survives_all_class_dict_mutations(
    name: str,
    value: str,
) -> None:
    missing = object()
    raw_value = vars(SourceProfileFailureCode).get(name, missing)
    try:
        with pytest.raises(AttributeError):
            setattr(SourceProfileFailureCode, name, "ordinary-poison")
        assert getattr(SourceProfileFailureCode, name).value == value

        with pytest.raises(AttributeError):
            delattr(SourceProfileFailureCode, name)
        assert getattr(SourceProfileFailureCode, name).value == value

        type.__setattr__(SourceProfileFailureCode, name, "type-poison")
        assert getattr(SourceProfileFailureCode, name).value == value

        type.__delattr__(SourceProfileFailureCode, name)
        assert getattr(SourceProfileFailureCode, name).value == value
    finally:
        _restore_failure_code_class_attribute(name, raw_value, missing)


@pytest.mark.parametrize("attack", ("replace", "delete"))
def test_wrong_identity_bind_uses_canonical_failure_when_code_is_attacked_during_bind(
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    missing = object()
    name = "PROFILE_MISMATCH"
    raw_value = vars(SourceProfileFailureCode).get(name, missing)
    original_compute = source_profile_module._compute_commitment_from_secrets  # noqa: SLF001

    def compute_then_attack(**kwargs):
        commitment = original_compute(**kwargs)
        type.__setattr__(SourceProfileFailureCode, name, "type-poison")
        if attack == "delete":
            type.__delattr__(SourceProfileFailureCode, name)
        return commitment

    tracker = _tracker()
    try:
        monkeypatch.setattr(
            source_profile_module,
            "_compute_commitment_from_secrets",
            compute_then_attack,
        )
        callback = tracker.bind_source(
            camera_id=CAMERA_IDS[0],
            resolved_url="rtsp://fixture.invalid/wrong-native-source",
            commitment_key=COMMITMENT_KEY,
            bound_monotonic_ns=0,
        )

        source = tracker.snapshot().sources[0]
        assert source.bound
        assert not source.identity_verified
        assert tuple(failure.code.value for failure in source.failures) == ("profile_mismatch",)
        assert SourceProfileFailureCode.PROFILE_MISMATCH.value == "profile_mismatch"

        callback.close()
        assert not tracker.snapshot().sources[0].bound
    finally:
        _restore_failure_code_class_attribute(name, raw_value, missing)


@pytest.mark.parametrize(
    "boundary",
    (
        "close_token",
        "callback",
        "callback_ref",
        "failure_record",
        "event_record",
        "event_reservation",
    ),
)
def test_bind_construction_failures_roll_back_and_allow_retry(
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    tracker = _tracker()
    before = tracker.snapshot()
    before_deltas = tracker.deltas_since(0)
    bind_url = _resolved_url(1) if boundary == "failure_record" else _resolved_url(0)

    class CallbackWithoutWeakref:
        __slots__ = ()

        def __init__(self, *args, **kwargs) -> None:
            pass

    def fail_construction(*args, **kwargs):
        raise RuntimeError(f"injected {boundary} failure")

    with monkeypatch.context() as patch:
        if boundary == "close_token":
            patch.setattr(source_profile_module, "object", fail_construction, raising=False)
        elif boundary == "callback":
            patch.setattr(source_profile_module, "NativeSourceCallbacks", fail_construction)
        elif boundary == "callback_ref":
            patch.setattr(
                source_profile_module,
                "NativeSourceCallbacks",
                CallbackWithoutWeakref,
            )
        elif boundary == "failure_record":
            patch.setattr(source_profile_module, "SourceProfileFailure", fail_construction)
        elif boundary == "event_record":
            patch.setattr(source_profile_module, "NativeSourceProfileDelta", fail_construction)
        else:
            original_reserve = tracker._require_event_capacity  # noqa: SLF001
            reservation_calls = 0

            def fail_second_reservation(*args, **kwargs):
                nonlocal reservation_calls
                reservation_calls += 1
                if reservation_calls == 2:
                    raise RuntimeError("injected event_reservation failure")
                return original_reserve(*args, **kwargs)

            patch.setattr(
                tracker,
                "_require_event_capacity",
                fail_second_reservation,
            )

        expected_exception = TypeError if boundary == "callback_ref" else RuntimeError
        expected_message = (
            "weak reference" if boundary == "callback_ref" else f"injected {boundary}"
        )
        with pytest.raises(expected_exception, match=expected_message) as caught:
            tracker.bind_source(
                camera_id=CAMERA_IDS[0],
                resolved_url=bind_url,
                commitment_key=COMMITMENT_KEY,
                bound_monotonic_ns=0,
            )
        traceback_text = _source_profile_traceback_text(caught.value)
        assert bind_url not in traceback_text
        assert COMMITMENT_KEY.decode() not in traceback_text

    gc.collect()
    assert tracker.snapshot() == before
    assert tracker.deltas_since(0) == before_deltas
    assert tracker._close_reservations == 0  # noqa: SLF001

    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert tracker.snapshot().sources[0].bound
    callback.close()


def test_tracker_rejects_nonexact_expectation_containers_without_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expectations = _expectations()
    clone_calls = 0

    def count_clone(expectation):
        nonlocal clone_calls
        clone_calls += 1
        return expectation

    class ExplosiveTuple(tuple):
        def __len__(self) -> int:
            raise AssertionError("tuple subclass length was accessed")

        def __iter__(self):
            raise AssertionError("tuple subclass was iterated")

    class ExplosiveList(list):
        def __len__(self) -> int:
            raise AssertionError("list subclass length was accessed")

        def __iter__(self):
            raise AssertionError("list subclass was iterated")

    generator_started = False

    def expectation_generator():
        nonlocal generator_started
        generator_started = True
        yield from expectations

    patch = monkeypatch
    patch.setattr(source_profile_module, "_clone_expectation", count_clone)
    invalid_containers = (
        ExplosiveTuple(expectations),
        ExplosiveList(expectations),
        expectation_generator(),
    )

    for invalid in invalid_containers:
        with pytest.raises(ValueError, match="exact built-in tuple or list"):
            NativeSourceProfileTracker(
                site_id=SITE_ID,
                expectations=invalid,  # type: ignore[arg-type]
                commitment_key=COMMITMENT_KEY,
                milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
                milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
            )

    assert not generator_started
    assert clone_calls == 0


@pytest.mark.parametrize("container_type", (tuple, list))
def test_tracker_rejects_huge_expectation_containers_before_clone(
    monkeypatch: pytest.MonkeyPatch,
    container_type,
) -> None:
    clone_calls = 0

    def count_clone(expectation):
        nonlocal clone_calls
        clone_calls += 1
        raise AssertionError("an oversized container element was cloned")

    monkeypatch.setattr(source_profile_module, "_clone_expectation", count_clone)
    huge = container_type([None] * 100_000)

    with pytest.raises(ValueError, match="exactly 20"):
        NativeSourceProfileTracker(
            site_id=SITE_ID,
            expectations=huge,  # type: ignore[arg-type]
            commitment_key=COMMITMENT_KEY,
            milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
            milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
        )

    assert clone_calls == 0


def test_tracker_accepts_an_exact_builtin_expectation_list() -> None:
    tracker = NativeSourceProfileTracker(
        site_id=SITE_ID,
        expectations=list(_expectations()),
        commitment_key=COMMITMENT_KEY,
        milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
        milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
    )

    assert tuple(source.camera_id for source in tracker.snapshot().sources) == CAMERA_IDS


def test_source_state_snapshot_rejects_unreachable_counter_and_timeline_arithmetic() -> None:
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=3,
        decoded_frames=3,
        source_ntp_ns=3,
        source_timestamp_ns=3,
        observed_monotonic_ns=3,
    )
    reachable = NativeSourceStateSnapshot(
        camera_id=CAMERA_IDS[0],
        source_index=0,
        bound=True,
        identity_verified=True,
        callback_generation=1,
        observation=observation,
        baseline_duration_ns=2,
        continuous_observations=3,
        maximum_observed_gap_ns=1,
        continuity_gap_bound_ns=1,
        stale_after_ns=5_000_000_000,
        prewarm_completed_monotonic_ns=None,
        failures=(),
    )

    invalid_states = (
        lambda: replace(
            reachable,
            observation=replace(observation, parser_bytes=2),
        ),
        lambda: replace(
            reachable,
            observation=replace(observation, decoded_frames=2),
        ),
        lambda: replace(
            reachable,
            baseline_duration_ns=3,
        ),
        lambda: replace(
            reachable,
            observation=replace(observation, observed_monotonic_ns=1),
        ),
        lambda: replace(
            reachable,
            observation=replace(observation, source_ntp_ns=1),
        ),
        lambda: replace(
            reachable,
            observation=replace(observation, source_timestamp_ns=1),
        ),
        lambda: replace(
            reachable,
            observation=replace(
                observation,
                parser_bytes=INT64_MAX,
                decoded_frames=INT64_MAX,
                source_ntp_ns=INT64_MAX,
                source_timestamp_ns=INT64_MAX,
                observed_monotonic_ns=INT64_MAX,
            ),
            baseline_duration_ns=1,
            continuous_observations=INT64_MAX,
            maximum_observed_gap_ns=2,
            continuity_gap_bound_ns=2,
        ),
    )

    for construct in invalid_states:
        with pytest.raises(ValueError, match="reachable|arithmetic|counter|terminal"):
            construct()


def test_profile_snapshot_readiness_is_biconditional_and_timeline_reachable() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)
    _observe_all_through(callbacks, final_elapsed_ns=PREWARM_NS)
    ready = tracker.snapshot()
    assert ready.ready
    maximum_observation_time = max(
        source.observation.observed_monotonic_ns
        for source in ready.sources
        if source.observation is not None
    )

    with pytest.raises(ValueError, match="ready"):
        replace(ready, ready=False, ready_at_monotonic_ns=None)
    with pytest.raises(ValueError, match="60"):
        replace(
            ready,
            ready_at_monotonic_ns=ready.epoch_started_monotonic_ns + PREWARM_NS - 1,
        )
    with pytest.raises(ValueError, match="completion"):
        replace(
            ready,
            ready_at_monotonic_ns=maximum_observation_time + 1,
        )


def test_profile_snapshot_rejects_source_timeline_before_epoch_plus_baseline() -> None:
    initial = _tracker().snapshot()
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=2,
        decoded_frames=2,
        source_ntp_ns=50,
        source_timestamp_ns=50,
        observed_monotonic_ns=149,
    )
    source = NativeSourceStateSnapshot(
        camera_id=CAMERA_IDS[0],
        source_index=0,
        bound=True,
        identity_verified=True,
        callback_generation=1,
        observation=observation,
        baseline_duration_ns=50,
        continuous_observations=2,
        maximum_observed_gap_ns=50,
        continuity_gap_bound_ns=50,
        stale_after_ns=5_000_000_000,
        prewarm_completed_monotonic_ns=None,
        failures=(),
    )

    with pytest.raises(ValueError, match="epoch|timeline"):
        NativeSourceProfileSnapshot(
            epoch=1,
            generation=5,
            epoch_started_generation=1,
            ready=False,
            epoch_started_monotonic_ns=100,
            ready_at_monotonic_ns=None,
            sources=(source, *initial.sources[1:]),
            failures=(),
        )


def test_two_samples_cannot_forge_a_sixty_second_ready_baseline() -> None:
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=2,
        decoded_frames=2,
        source_ntp_ns=PREWARM_NS,
        source_timestamp_ns=PREWARM_NS,
        observed_monotonic_ns=PREWARM_NS,
    )

    with pytest.raises(ValueError, match="reachable|arithmetic"):
        NativeSourceStateSnapshot(
            camera_id=CAMERA_IDS[0],
            source_index=0,
            bound=True,
            identity_verified=True,
            callback_generation=1,
            observation=observation,
            baseline_duration_ns=PREWARM_NS,
            continuous_observations=2,
            maximum_observed_gap_ns=83_333_334,
            continuity_gap_bound_ns=83_333_334,
            stale_after_ns=5_000_000_000,
            prewarm_completed_monotonic_ns=PREWARM_NS,
            failures=(),
        )


def test_real_staggered_ready_snapshot_remains_valid() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)

    for sample_number, elapsed_ns in enumerate(
        _cadence_times(PREWARM_NS),
        start=1,
    ):
        for source_index, callback in enumerate(callbacks):
            assert _observe(
                callback,
                sample_number=sample_number,
                elapsed_ns=elapsed_ns + source_index,
            )

    snapshot = tracker.snapshot()
    assert snapshot.ready
    assert snapshot.ready_at_monotonic_ns == PREWARM_NS + 19
    assert snapshot.sources[0].observation is not None
    assert snapshot.sources[0].observation.observed_monotonic_ns < snapshot.ready_at_monotonic_ns


def test_first_ready_time_uses_maximum_current_observation_when_callbacks_arrive_out_of_order() -> (
    None
):
    tracker = _tracker()
    callbacks = _bind_all(tracker)

    for sample_number, elapsed_ns in enumerate(
        _cadence_times(PREWARM_NS),
        start=1,
    ):
        for source_index, callback in enumerate(callbacks):
            assert _observe(
                callback,
                sample_number=sample_number,
                elapsed_ns=elapsed_ns + (100 if source_index == 0 else 0),
            )

    snapshot = tracker.snapshot()
    assert snapshot.ready
    assert snapshot.ready_at_monotonic_ns == PREWARM_NS + 100


def test_seeded_random_native_transitions_always_export_reachable_snapshots() -> None:
    generator = random.Random(0x4B555A4554)
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    elapsed_ns = 0
    parser_bytes = 0
    decoded_frames = 0

    for sample_number in range(1, 251):
        if sample_number > 1:
            elapsed_ns += generator.randint(1, 80_000_000)
        parser_bytes += generator.randint(1, 50_000)
        decoded_frames += generator.randint(1, 3)
        assert _observe(
            callback,
            sample_number=sample_number,
            elapsed_ns=elapsed_ns,
            parser_bytes=parser_bytes,
            decoded_frames=decoded_frames,
        )
        source = tracker.snapshot().sources[0]
        assert source.observation is not None
        assert source.observation.parser_bytes >= source.continuous_observations
        assert source.observation.decoded_frames >= source.continuous_observations
        assert source.observation.source_ntp_ns >= source.continuous_observations
        assert source.observation.source_timestamp_ns >= source.continuous_observations
        assert source.baseline_duration_ns >= max(
            0,
            source.continuous_observations - 1,
        )
        assert source.baseline_duration_ns <= (
            source.maximum_observed_gap_ns * max(0, source.continuous_observations - 1)
        )

    callback.close()
    replacement = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=elapsed_ns + 1,
    )
    assert _observe(
        replacement,
        sample_number=1,
        elapsed_ns=elapsed_ns + 1,
    )
    rebound = tracker.snapshot().sources[0]
    assert rebound.continuous_observations == 1
    assert rebound.baseline_duration_ns == 0


def test_failure_generation_strictly_follows_the_epoch_start_event() -> None:
    failure, _, _, _ = _valid_public_records()

    with pytest.raises(ValueError, match="generation|epoch"):
        replace(failure, first_generation=failure.epoch)


def test_bound_unverified_source_requires_profile_mismatch_failure() -> None:
    _, source, _, _ = _valid_public_records()

    with pytest.raises(ValueError, match="profile.mismatch"):
        replace(source, failures=())


def test_bound_source_export_preserves_callback_close_headroom() -> None:
    _, source, _, _ = _valid_public_records()

    with pytest.raises(ValueError, match="callback generation|close"):
        replace(source, callback_generation=INT64_MAX)


def test_profile_export_preserves_global_bound_callback_close_headroom() -> None:
    _, _, snapshot, _ = _valid_public_records()

    with pytest.raises(ValueError, match="generation|close"):
        replace(snapshot, generation=INT64_MAX)


def test_snapshot_generation_covers_genuine_ready_epoch_history() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)
    _observe_all_through(callbacks, final_elapsed_ns=PREWARM_NS)
    ready = tracker.snapshot()
    minimum_generation = ready.epoch + sum(
        source.callback_generation
        + (1 if source.observation is not None else 0)
        + source.continuous_observations
        for source in ready.sources
    )

    assert ready.generation == minimum_generation
    with pytest.raises(ValueError, match="generation|history"):
        replace(ready, generation=1)


def test_snapshot_generation_counts_provable_standalone_failure_events() -> None:
    initial = _tracker().snapshot()
    failure = SourceProfileFailure(
        camera_id=CAMERA_IDS[0],
        code=SourceProfileFailureCode.COUNTER_REGRESSION,
        epoch=1,
        first_generation=4,
    )
    failed_source = replace(
        initial.sources[0],
        bound=True,
        identity_verified=True,
        callback_generation=1,
        failures=(failure,),
    )

    with pytest.raises(ValueError, match="generation|history"):
        NativeSourceProfileSnapshot(
            epoch=1,
            generation=3,
            epoch_started_generation=1,
            ready=False,
            epoch_started_monotonic_ns=0,
            ready_at_monotonic_ns=None,
            sources=(failed_source, *initial.sources[1:]),
            failures=(failure,),
        )


@pytest.mark.parametrize(
    ("counter_name", "counter_value"),
    (
        ("parser_bytes", 2),
        ("decoded_frames", 2),
        ("source_ntp_ns", 2),
        ("source_timestamp_ns", 2),
    ),
)
def test_source_state_terminal_counters_cover_every_continuous_observation(
    counter_name: str,
    counter_value: int,
) -> None:
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=3,
        decoded_frames=3,
        source_ntp_ns=3,
        source_timestamp_ns=3,
        observed_monotonic_ns=3,
    )
    source = NativeSourceStateSnapshot(
        camera_id=CAMERA_IDS[0],
        source_index=0,
        bound=True,
        identity_verified=True,
        callback_generation=1,
        observation=observation,
        baseline_duration_ns=2,
        continuous_observations=3,
        maximum_observed_gap_ns=1,
        continuity_gap_bound_ns=1,
        stale_after_ns=5_000_000_000,
        prewarm_completed_monotonic_ns=None,
        failures=(),
    )

    with pytest.raises(ValueError, match="counter|observation"):
        replace(
            source,
            observation=replace(
                observation,
                **{counter_name: counter_value},
            ),
        )


def test_source_state_baseline_covers_minimum_strict_counter_progress() -> None:
    observation = NativeSourceObservation(
        caps=CAPS,
        parser_bytes=3,
        decoded_frames=3,
        source_ntp_ns=3,
        source_timestamp_ns=3,
        observed_monotonic_ns=3,
    )
    source = NativeSourceStateSnapshot(
        camera_id=CAMERA_IDS[0],
        source_index=0,
        bound=True,
        identity_verified=True,
        callback_generation=1,
        observation=observation,
        baseline_duration_ns=2,
        continuous_observations=3,
        maximum_observed_gap_ns=1,
        continuity_gap_bound_ns=1,
        stale_after_ns=5_000_000_000,
        prewarm_completed_monotonic_ns=None,
        failures=(),
    )

    with pytest.raises(ValueError, match="baseline|observation"):
        replace(source, baseline_duration_ns=1)


def test_snapshot_projects_each_signed_source_stale_bound() -> None:
    expectations = _expectations(stale_after_ns=300_000_000_000)
    snapshot = _tracker(expectations=expectations).snapshot()

    assert tuple(source.stale_after_ns for source in snapshot.sources) == (300_000_000_000,) * len(
        CAMERA_IDS
    )
    assert snapshot.to_dict()["sources"][0]["stale_after_ns"] == 300_000_000_000


def test_ready_snapshot_rejects_current_observations_outside_source_stale_bound() -> None:
    expectations = _expectations(stale_after_ns=300_000_000_000)
    tracker = _tracker(expectations=expectations)
    callbacks = _bind_all(tracker)
    _observe_all_through(callbacks, final_elapsed_ns=PREWARM_NS)
    ready = tracker.snapshot()
    first = ready.sources[0]
    assert first.observation is not None
    future_observation_count = 3_603
    future = replace(
        first.observation,
        decoded_frames=future_observation_count,
        source_ntp_ns=SOURCE_NTP_BASE_NS + PREWARM_NS + 1,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + PREWARM_NS + 1,
        observed_monotonic_ns=PREWARM_NS + 300_000_000_001,
    )
    future_source = replace(
        first,
        observation=future,
        baseline_duration_ns=PREWARM_NS + 1,
        continuous_observations=future_observation_count,
        maximum_observed_gap_ns=first.continuity_gap_bound_ns,
    )

    with pytest.raises(ValueError, match="stale"):
        replace(
            ready,
            generation=(
                ready.generation + future_observation_count - first.continuous_observations
            ),
            sources=(future_source, *ready.sources[1:]),
        )


def test_tracker_readiness_uses_maximum_current_source_observation() -> None:
    expectations = _expectations(stale_after_ns=300_000_000_000)
    tracker = _tracker(expectations=expectations)
    callbacks = _bind_all(tracker)
    _observe_all_through(callbacks, final_elapsed_ns=PREWARM_NS)
    state = tracker._states[CAMERA_IDS[0]]  # noqa: SLF001
    assert state.observation is not None
    original_observation_count = state.continuous_observations
    future_observation_count = 3_603
    state.observation = replace(
        state.observation,
        decoded_frames=future_observation_count,
        source_ntp_ns=SOURCE_NTP_BASE_NS + PREWARM_NS + 1,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + PREWARM_NS + 1,
        observed_monotonic_ns=PREWARM_NS + 300_000_000_001,
    )
    state.baseline_duration_ns = PREWARM_NS + 1
    state.continuous_observations = future_observation_count
    state.maximum_observed_gap_ns = NativeSourceProfileTracker._continuity_gap_bound_ns(  # noqa: SLF001
        state.expectation
    )
    tracker._generation += (  # noqa: SLF001
        future_observation_count - original_observation_count
    )
    tracker._ready_at_monotonic_ns = None  # noqa: SLF001

    tracker._refresh_readiness()  # noqa: SLF001

    assert tracker._ready_at_monotonic_ns is None  # noqa: SLF001
    assert all(
        SourceProfileFailureCode.STALE_SOURCE.value in _failures(tracker, camera_id)
        for camera_id in CAMERA_IDS[1:]
    )


def test_observation_preflights_maximum_time_stale_failures_and_event() -> None:
    expectations = _expectations(stale_after_ns=300_000_000_000)
    tracker = _tracker(expectations=expectations)
    callbacks = _bind_all(tracker)
    sample_number = _observe_all_through(callbacks, final_elapsed_ns=PREWARM_NS)
    future_state = tracker._states[CAMERA_IDS[0]]  # noqa: SLF001
    assert future_state.observation is not None
    future_state.observation = replace(
        future_state.observation,
        observed_monotonic_ns=PREWARM_NS + 40_000_000 + 300_000_000_001,
    )
    lagging = callbacks[1]
    next_elapsed_ns = PREWARM_NS + 40_000_000
    assert lagging.on_parser_counter(
        parser_bytes=(sample_number + 1) * 10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + next_elapsed_ns,
        observed_monotonic_ns=next_elapsed_ns,
    )
    lagging_state = tracker._states[CAMERA_IDS[1]]  # noqa: SLF001
    before = (
        tracker._generation,  # noqa: SLF001
        lagging_state.observation,
        lagging_state.pending_parser,
        tuple(
            tuple((state.failures or {}).values())
            for state in tracker._states.values()  # noqa: SLF001
        ),
    )
    tracker._generation = INT64_MAX - 39  # noqa: SLF001
    before = (tracker._generation, *before[1:])  # noqa: SLF001

    with pytest.raises(OverflowError, match="generation"):
        lagging.on_decoded_frame(
            decoded_frames=sample_number + 1,
            source_ntp_ns=SOURCE_NTP_BASE_NS + next_elapsed_ns,
            observed_monotonic_ns=next_elapsed_ns,
        )

    after = (
        tracker._generation,  # noqa: SLF001
        lagging_state.observation,
        lagging_state.pending_parser,
        tuple(
            tuple((state.failures or {}).values())
            for state in tracker._states.values()  # noqa: SLF001
        ),
    )
    assert after == before


@pytest.mark.parametrize("record_kind", ("state", "profile", "delta"))
def test_failure_containers_reject_oversize_before_cloning(
    monkeypatch: pytest.MonkeyPatch,
    record_kind: str,
) -> None:
    failure, source, snapshot, delta = _valid_public_records()

    if record_kind == "state":
        oversized = (failure,) * 11

        def construct():
            return replace(source, failures=oversized)

        clone_name = "_clone_failure"
    elif record_kind == "profile":
        empty_snapshot = _tracker().snapshot()
        oversized = (failure,) * 201

        def construct():
            return replace(empty_snapshot, failures=oversized)

        clone_name = "_clone_failure"
    else:
        oversized = (SourceProfileFailureCode.PROFILE_MISMATCH,) * 11

        def construct():
            return replace(delta, failures=oversized)

        clone_name = "_canonical_failure_code"

    clone_calls = 0

    def reject_clone(*_args, **_kwargs):
        nonlocal clone_calls
        clone_calls += 1
        raise AssertionError("oversized failure container reached cloning")

    monkeypatch.setattr(source_profile_module, clone_name, reject_clone)
    with pytest.raises(ValueError, match="failure|bounded|maximum"):
        construct()
    assert clone_calls == 0


def test_closed_wrong_key_history_cannot_strip_sticky_profile_mismatch() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=OTHER_KEY,
        bound_monotonic_ns=0,
    )
    callback.close()
    closed = tracker.snapshot()
    source = closed.sources[0]
    assert not source.bound
    assert not source.identity_verified
    assert source.callback_generation == 2
    assert tuple(failure.code.value for failure in source.failures) == ("profile_mismatch",)

    with pytest.raises(ValueError, match="profile.mismatch"):
        stripped_source = replace(source, failures=())
        replace(
            closed,
            sources=(stripped_source, *closed.sources[1:]),
            failures=(),
        )


def test_verified_first_bind_cannot_coemit_profile_mismatch() -> None:
    initial = _tracker().snapshot()
    mismatch = SourceProfileFailure(
        camera_id=CAMERA_IDS[0],
        code=SourceProfileFailureCode.PROFILE_MISMATCH,
        epoch=1,
        first_generation=2,
    )

    with pytest.raises(ValueError, match="generation|profile.mismatch|callback"):
        forged_source = replace(
            initial.sources[0],
            bound=True,
            identity_verified=True,
            callback_generation=1,
            failures=(mismatch,),
        )
        NativeSourceProfileSnapshot(
            epoch=1,
            generation=2,
            epoch_started_generation=1,
            ready=False,
            epoch_started_monotonic_ns=0,
            ready_at_monotonic_ns=None,
            sources=(forged_source, *initial.sources[1:]),
            failures=(mismatch,),
        )


def test_never_bound_source_cannot_claim_callback_only_failure() -> None:
    initial = _tracker().snapshot()
    counter_regression = SourceProfileFailure(
        camera_id=CAMERA_IDS[0],
        code=SourceProfileFailureCode.COUNTER_REGRESSION,
        epoch=1,
        first_generation=2,
    )

    with pytest.raises(ValueError, match="callback|bound|generation"):
        forged_source = replace(
            initial.sources[0],
            failures=(counter_regression,),
        )
        NativeSourceProfileSnapshot(
            epoch=1,
            generation=2,
            epoch_started_generation=1,
            ready=False,
            epoch_started_monotonic_ns=0,
            ready_at_monotonic_ns=None,
            sources=(forged_source, *initial.sources[1:]),
            failures=(counter_regression,),
        )


def test_never_bound_source_cannot_claim_overflow_without_stale_event() -> None:
    initial = _tracker().snapshot()
    overflow = SourceProfileFailure(
        camera_id=CAMERA_IDS[0],
        code=SourceProfileFailureCode.BUFFER_OVERFLOW,
        epoch=1,
        first_generation=2,
    )

    with pytest.raises(ValueError, match="overflow|stale|generation"):
        forged_source = replace(
            initial.sources[0],
            failures=(overflow,),
        )
        NativeSourceProfileSnapshot(
            epoch=1,
            generation=2,
            epoch_started_generation=1,
            ready=False,
            epoch_started_monotonic_ns=0,
            ready_at_monotonic_ns=None,
            sources=(forged_source, *initial.sources[1:]),
            failures=(overflow,),
        )


def test_wrong_bind_and_never_bound_stale_overflow_coemissions_remain_reachable() -> None:
    wrong_tracker = _tracker(delta_capacity=1)
    wrong = wrong_tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=OTHER_KEY,
        bound_monotonic_ns=0,
    )
    wrong_codes = tuple(
        failure.code.value for failure in wrong_tracker.snapshot().sources[0].failures
    )
    assert wrong_codes == ("bounded_buffer_overflow", "profile_mismatch")
    wrong.close()

    stale_tracker = _tracker(delta_capacity=1)
    stale = stale_tracker.check_stale(now_monotonic_ns=5_000_000_001)
    never_bound = stale.sources[0]
    assert never_bound.callback_generation == 0
    assert tuple(failure.code.value for failure in never_bound.failures) == (
        "bounded_buffer_overflow",
        "stale_source",
    )
    assert len({failure.first_generation for failure in never_bound.failures}) == 1


def test_verified_bind_can_emit_later_profile_mismatch_failure() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )

    assert not callback.on_rtp_caps(
        replace(CAPS, codec="h265"),
        observed_monotonic_ns=0,
    )
    source = tracker.snapshot().sources[0]
    mismatch = next(
        failure
        for failure in source.failures
        if failure.code == SourceProfileFailureCode.PROFILE_MISMATCH
    )
    assert source.identity_verified
    assert source.callback_generation == 1
    assert mismatch.first_generation == 3


def test_ready_snapshot_cannot_predate_last_staggered_source_completion() -> None:
    sources = tuple(
        NativeSourceStateSnapshot(
            camera_id=camera_id,
            source_index=source_index,
            bound=True,
            identity_verified=True,
            callback_generation=1,
            observation=NativeSourceObservation(
                caps=CAPS,
                parser_bytes=61,
                decoded_frames=61,
                source_ntp_ns=PREWARM_NS,
                source_timestamp_ns=PREWARM_NS,
                observed_monotonic_ns=PREWARM_NS + source_index * 10_000_000_000,
            ),
            baseline_duration_ns=PREWARM_NS,
            continuous_observations=61,
            maximum_observed_gap_ns=1_000_000_000,
            continuity_gap_bound_ns=1_000_000_000,
            stale_after_ns=300_000_000_000,
            prewarm_completed_monotonic_ns=(PREWARM_NS + source_index * 10_000_000_000),
            failures=(),
        )
        for source_index, camera_id in enumerate(CAMERA_IDS)
    )

    with pytest.raises(ValueError, match="completion|ready"):
        NativeSourceProfileSnapshot(
            epoch=1,
            generation=1_261,
            epoch_started_generation=1,
            ready=True,
            epoch_started_monotonic_ns=0,
            ready_at_monotonic_ns=PREWARM_NS,
            sources=sources,
            failures=(),
        )


def test_post_ready_slow_source_clock_keeps_first_prewarm_completion() -> None:
    tracker = _tracker()
    callbacks = _bind_all(tracker)
    sample_number = _observe_all_through(
        callbacks,
        final_elapsed_ns=PREWARM_NS,
    )
    first_ready = tracker.snapshot()
    assert first_ready.ready_at_monotonic_ns == PREWARM_NS

    next_elapsed_ns = PREWARM_NS + 40_000_000
    assert callbacks[0].on_parser_counter(
        parser_bytes=(sample_number + 1) * 10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + next_elapsed_ns,
        observed_monotonic_ns=next_elapsed_ns,
    )
    assert callbacks[0].on_decoded_frame(
        decoded_frames=sample_number + 1,
        source_ntp_ns=SOURCE_NTP_BASE_NS + PREWARM_NS + 1,
        observed_monotonic_ns=next_elapsed_ns,
    )

    later = tracker.snapshot()
    assert later.ready
    assert later.ready_at_monotonic_ns == PREWARM_NS
    assert later.sources[0].observation is not None
    assert later.sources[0].observation.observed_monotonic_ns == next_elapsed_ns
    assert later.sources[0].prewarm_completed_monotonic_ns == PREWARM_NS


@pytest.mark.parametrize(
    ("baseline_duration_ns", "continuous_observations"),
    (
        (PREWARM_NS, 61),
        (PREWARM_NS + 1, 62),
    ),
)
def test_source_state_cannot_backdate_prewarm_completion_before_reachable_observations(
    baseline_duration_ns: int,
    continuous_observations: int,
) -> None:
    observed_monotonic_ns = 250_000_000_000
    valid = NativeSourceStateSnapshot(
        camera_id=CAMERA_IDS[0],
        source_index=0,
        bound=True,
        identity_verified=True,
        callback_generation=1,
        observation=NativeSourceObservation(
            caps=CAPS,
            parser_bytes=continuous_observations,
            decoded_frames=continuous_observations,
            source_ntp_ns=SOURCE_NTP_BASE_NS + baseline_duration_ns,
            source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + baseline_duration_ns,
            observed_monotonic_ns=observed_monotonic_ns,
        ),
        baseline_duration_ns=baseline_duration_ns,
        continuous_observations=continuous_observations,
        maximum_observed_gap_ns=1_000_000_000,
        continuity_gap_bound_ns=1_000_000_000,
        stale_after_ns=300_000_000_000,
        prewarm_completed_monotonic_ns=observed_monotonic_ns,
        failures=(),
    )

    with pytest.raises(ValueError, match="prewarm|completion|observation"):
        replace(
            valid,
            prewarm_completed_monotonic_ns=PREWARM_NS,
        )


@pytest.mark.parametrize(
    ("failure_code", "too_early_generation", "first_reachable_generation"),
    (
        (SourceProfileFailureCode.COUNTER_REGRESSION, 3, 4),
        (SourceProfileFailureCode.TIMESTAMP_REGRESSION, 3, 4),
        (SourceProfileFailureCode.TIMESTAMP_REPLAY, 3, 4),
        (SourceProfileFailureCode.EXCESSIVE_SKEW, 4, 5),
    ),
)
def test_callback_failure_generation_requires_code_specific_provenance(
    failure_code: SourceProfileFailureCode,
    too_early_generation: int,
    first_reachable_generation: int,
) -> None:
    initial = _tracker().snapshot().sources[0]
    observation = (
        NativeSourceObservation(
            caps=CAPS,
            parser_bytes=1,
            decoded_frames=1,
            source_ntp_ns=SOURCE_NTP_BASE_NS,
            source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
            observed_monotonic_ns=0,
        )
        if failure_code == SourceProfileFailureCode.EXCESSIVE_SKEW
        else None
    )
    state_changes = {
        "bound": True,
        "identity_verified": True,
        "callback_generation": 1,
        "observation": observation,
        "continuous_observations": 1 if observation is not None else 0,
    }
    reachable = replace(
        initial,
        **state_changes,
        failures=(
            SourceProfileFailure(
                camera_id=CAMERA_IDS[0],
                code=failure_code,
                epoch=1,
                first_generation=first_reachable_generation,
            ),
        ),
    )
    assert reachable.failures[0].first_generation == first_reachable_generation

    with pytest.raises(ValueError, match="callback|generation|provenance"):
        replace(
            reachable,
            failures=(
                replace(
                    reachable.failures[0],
                    first_generation=too_early_generation,
                ),
            ),
        )


def test_restart_snapshot_retains_epoch_start_generation_for_failure_chronology() -> None:
    tracker = _tracker()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert _observe(callback, sample_number=1, elapsed_ns=0)
    callback.close()

    restarted = tracker.restart_epoch(started_monotonic_ns=1)
    assert restarted.epoch == 2
    assert restarted.epoch_started_generation == restarted.generation
    too_early = SourceProfileFailure(
        camera_id=CAMERA_IDS[0],
        code=SourceProfileFailureCode.COUNTER_REGRESSION,
        epoch=restarted.epoch,
        first_generation=restarted.epoch_started_generation + 2,
    )
    failed_source = replace(
        restarted.sources[0],
        bound=True,
        identity_verified=True,
        callback_generation=1,
        failures=(too_early,),
    )

    with pytest.raises(ValueError, match="callback|generation|provenance"):
        NativeSourceProfileSnapshot(
            epoch=restarted.epoch,
            generation=restarted.epoch_started_generation + 2,
            epoch_started_generation=restarted.epoch_started_generation,
            ready=False,
            epoch_started_monotonic_ns=1,
            ready_at_monotonic_ns=None,
            sources=(failed_source, *restarted.sources[1:]),
            failures=(too_early,),
        )


SOURCE_PROOF_KEY_ID = "source-profile-proof-2026-07"
SOURCE_PROOF_SEED = bytes.fromhex(
    "8d59e70642df0f1b038d58fcf58c79f8a1f34a8ad1647c9f02eac1bb91594b35"
)


def _snapshot_digest(snapshot: NativeSourceProfileSnapshot) -> str:
    return hashlib.sha256(
        json.dumps(
            snapshot.to_dict(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _proof_tracker_or_plain() -> tuple[NativeSourceProfileTracker, object | None]:
    signer_type = getattr(source_profile_module, "Ed25519SourceProfileProofSigner", None)
    if signer_type is None:
        return _tracker(), None
    signer = signer_type(
        key_id=SOURCE_PROOF_KEY_ID,
        signing_seed=SOURCE_PROOF_SEED,
    )
    return (
        NativeSourceProfileTracker(
            site_id=SITE_ID,
            expectations=_expectations(),
            commitment_key=COMMITMENT_KEY,
            milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
            milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
            delta_capacity=100_000,
            epoch_started_monotonic_ns=0,
            proof_signer=signer,
        ),
        signer,
    )


def _expected_source_commitments() -> tuple[str, ...]:
    return tuple(expectation.source_identity_commitment for expectation in _expectations())


def _verify_proof(
    envelope,
    signer,
    *,
    expected_key_id: str = SOURCE_PROOF_KEY_ID,
    trusted_public_key: bytes | None = None,
    expected_milestone_authenticator_key_id: str = (MILESTONE_AUTHENTICATOR_KEY_ID),
    trusted_milestone_authenticator_key: bytes = (MILESTONE_AUTHENTICATOR_KEY),
    expected_site_id: str = SITE_ID,
    expected_source_identity_commitments: tuple[str, ...] | None = None,
    expected_epoch: int | None = None,
    expected_epoch_started_generation: int | None = None,
):
    try:
        return source_profile_module.verify_source_profile_proof(
            envelope,
            expected_key_id=expected_key_id,
            trusted_public_key=(
                signer.public_key if trusted_public_key is None else trusted_public_key
            ),
            expected_milestone_authenticator_key_id=(expected_milestone_authenticator_key_id),
            trusted_milestone_authenticator_key=(trusted_milestone_authenticator_key),
            expected_site_id=expected_site_id,
            expected_source_identity_commitments=(
                _expected_source_commitments()
                if expected_source_identity_commitments is None
                else expected_source_identity_commitments
            ),
            expected_epoch=envelope.epoch if expected_epoch is None else expected_epoch,
            expected_epoch_started_generation=(
                envelope.epoch_started_generation
                if expected_epoch_started_generation is None
                else expected_epoch_started_generation
            ),
        )
    except TypeError as exc:
        pytest.fail(f"authoritative proof verifier lacks caller trust pins: {exc}")


def _resign_proof(envelope, signer):
    unsigned = replace(envelope, signature="0" * 128)
    signature = signer.sign(source_profile_module._proof_signing_payload(unsigned))
    return replace(unsigned, signature=signature.hex())


def test_authoritative_proof_rejects_consistent_actual_prewarm_backdate() -> None:
    tracker, signer = _proof_tracker_or_plain()
    callbacks = _bind_all(tracker)
    step_ns = 40_000_000
    for sample_number, elapsed_ns in enumerate(
        range(0, PREWARM_NS + 1, step_ns),
        start=1,
    ):
        for source_index, callback in enumerate(callbacks):
            assert _observe(
                callback,
                sample_number=sample_number,
                elapsed_ns=elapsed_ns,
                source_ntp_ns=(
                    SOURCE_NTP_BASE_NS + elapsed_ns * 985 // 1_000
                    if source_index == 0
                    else SOURCE_NTP_BASE_NS + elapsed_ns
                ),
            )
    assert not tracker.snapshot().ready

    next_sample = PREWARM_NS // step_ns + 2
    assert _observe(
        callbacks[0],
        sample_number=next_sample,
        elapsed_ns=PREWARM_NS + step_ns,
        source_ntp_ns=SOURCE_NTP_BASE_NS + 59_640_000_000,
    )
    assert _observe(
        callbacks[0],
        sample_number=next_sample + 1,
        elapsed_ns=PREWARM_NS + 2 * step_ns,
        source_ntp_ns=SOURCE_NTP_BASE_NS + PREWARM_NS + 2 * step_ns,
    )
    actual = tracker.snapshot()
    assert actual.ready_at_monotonic_ns == 60_080_000_000

    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    envelope = tracker.authoritative_proof()
    assert _verify_proof(envelope, signer) == actual
    first_completion = next(
        receipt
        for receipt in envelope.receipts
        if receipt.camera_id == CAMERA_IDS[0] and receipt.kind == "prewarm_completed"
    )
    assert first_completion.event_monotonic_ns == 60_080_000_000
    assert first_completion.baseline_duration_ns == 60_080_000_000
    backdated_source = replace(
        envelope.snapshot.sources[0],
        prewarm_completed_monotonic_ns=PREWARM_NS,
    )
    backdated_snapshot = replace(
        envelope.snapshot,
        sources=(backdated_source, *envelope.snapshot.sources[1:]),
        ready_at_monotonic_ns=PREWARM_NS,
    )
    completion_index = envelope.receipts.index(first_completion)
    rechained_receipts = _rechain_receipts(
        envelope.receipts,
        updates={
            completion_index: {
                "event_monotonic_ns": PREWARM_NS,
                "baseline_duration_ns": PREWARM_NS,
            }
        },
    )
    forged = replace(
        envelope,
        snapshot=backdated_snapshot,
        snapshot_sha256=_snapshot_digest(backdated_snapshot),
        receipts=rechained_receipts,
        final_head=rechained_receipts[-1].head,
        signature="0" * 128,
    )
    forged = _resign_proof(forged, signer)

    with pytest.raises(ValueError, match="milestone|authentication|history"):
        _verify_proof(forged, signer)


def test_authoritative_proof_rejects_shifted_actual_failure_generation() -> None:
    tracker, signer = _proof_tracker_or_plain()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)
    assert callback.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
        observed_monotonic_ns=0,
    )
    assert not callback.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    later_callback = tracker.bind_source(
        camera_id=CAMERA_IDS[1],
        resolved_url=_resolved_url(1),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=1,
    )
    actual = tracker.snapshot()
    assert actual.failures[0].first_generation == 4
    assert actual.generation == 5
    assert later_callback.camera_id == CAMERA_IDS[1]

    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    envelope = tracker.authoritative_proof()
    assert _verify_proof(envelope, signer) == actual
    counter_failure = next(
        receipt
        for receipt in envelope.receipts
        if receipt.failure_code == SourceProfileFailureCode.COUNTER_REGRESSION
    )
    assert counter_failure.event_generation == 4
    later_failure = replace(
        envelope.snapshot.failures[0],
        first_generation=5,
    )
    later_source = replace(
        envelope.snapshot.sources[0],
        failures=(later_failure,),
    )
    shifted_snapshot = replace(
        envelope.snapshot,
        sources=(later_source, *envelope.snapshot.sources[1:]),
        failures=(later_failure,),
    )
    forged = replace(
        envelope,
        snapshot=shifted_snapshot,
        snapshot_sha256=_snapshot_digest(shifted_snapshot),
        signature="0" * 128,
    )
    forged = _resign_proof(forged, signer)

    with pytest.raises(ValueError, match="proof|snapshot|failure"):
        _verify_proof(forged, signer)


def test_authoritative_proof_rejects_cross_site_replay_under_shared_key() -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    envelope = tracker.authoritative_proof()

    with pytest.raises(ValueError, match="site|scope|trusted"):
        _verify_proof(
            envelope,
            signer,
            expected_site_id=OTHER_SITE_ID,
        )


@pytest.mark.parametrize("mutation", ["reordered", "substituted"])
def test_authoritative_proof_rejects_wrong_expected_source_identity_set(
    mutation: str,
) -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    envelope = tracker.authoritative_proof()
    commitments = list(_expected_source_commitments())
    if mutation == "reordered":
        commitments[0], commitments[1] = commitments[1], commitments[0]
    else:
        commitments[0] = "f" * 64

    with pytest.raises(ValueError, match="source|identity|trusted"):
        _verify_proof(
            envelope,
            signer,
            expected_source_identity_commitments=tuple(commitments),
        )


def test_authoritative_proof_rejects_old_epoch_replay_after_restart() -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    old_envelope = tracker.authoritative_proof()
    restarted = tracker.restart_epoch(started_monotonic_ns=1)
    assert restarted.epoch == 2
    assert restarted.epoch_started_generation == 2

    with pytest.raises(ValueError, match="epoch|generation|trusted"):
        _verify_proof(
            old_envelope,
            signer,
            expected_epoch=restarted.epoch,
            expected_epoch_started_generation=restarted.epoch_started_generation,
        )


def test_authoritative_proof_requires_caller_pinned_key_id_and_public_key() -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    envelope = tracker.authoritative_proof()
    other_signer = source_profile_module.Ed25519SourceProfileProofSigner(
        key_id="other-source-profile-proof-key",
        signing_seed=hashlib.sha256(SOURCE_PROOF_SEED).digest(),
    )

    with pytest.raises(ValueError, match="key_id|trusted"):
        _verify_proof(
            envelope,
            signer,
            expected_key_id="other-source-profile-proof-key",
        )
    with pytest.raises(ValueError, match="key|fingerprint|signature|trusted"):
        _verify_proof(
            envelope,
            signer,
            trusted_public_key=other_signer.public_key,
        )
    with pytest.raises(ValueError, match="milestone|key_id|trusted"):
        _verify_proof(
            envelope,
            signer,
            expected_milestone_authenticator_key_id="other-milestone-key",
        )
    with pytest.raises(ValueError, match="milestone|authentication|trusted"):
        _verify_proof(
            envelope,
            signer,
            trusted_milestone_authenticator_key=OTHER_MILESTONE_AUTHENTICATOR_KEY,
        )


def test_milestone_authenticator_is_separate_bounded_secret_material() -> None:
    with pytest.raises(ValueError, match="milestone|differ|commitment"):
        NativeSourceProfileTracker(
            site_id=SITE_ID,
            expectations=_expectations(),
            commitment_key=COMMITMENT_KEY,
            milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
            milestone_authenticator_key=COMMITMENT_KEY,
        )
    for invalid_key in (b"", b"x" * 31, b"x" * 33, "x" * 32):
        with pytest.raises(ValueError, match="milestone|32-byte"):
            NativeSourceProfileTracker(
                site_id=SITE_ID,
                expectations=_expectations(),
                commitment_key=COMMITMENT_KEY,
                milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
                milestone_authenticator_key=invalid_key,
            )


def test_milestone_authenticator_never_appears_in_repr_or_verifier_traceback() -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    envelope = tracker.authoritative_proof()
    traceback_key = b"milestone-traceback-secret-key!!"
    redacted_tracker = NativeSourceProfileTracker(
        site_id=SITE_ID,
        expectations=_expectations(),
        commitment_key=COMMITMENT_KEY,
        milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
        milestone_authenticator_key=traceback_key,
    )

    assert traceback_key.decode() not in repr(tracker)
    assert traceback_key.decode() not in repr(redacted_tracker.__dict__)
    with pytest.raises(ValueError, match="site|trusted") as caught:
        _verify_proof(
            envelope,
            signer,
            trusted_milestone_authenticator_key=traceback_key,
            expected_site_id=OTHER_SITE_ID,
        )
    assert traceback_key.decode() not in _source_profile_traceback_text(caught.value)


def test_authoritative_proof_pins_epoch_and_epoch_start_independently() -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    envelope = tracker.authoritative_proof()

    with pytest.raises(ValueError, match="epoch|chronology|trusted"):
        _verify_proof(
            envelope,
            signer,
            expected_epoch=envelope.epoch + 1,
            expected_epoch_started_generation=envelope.epoch_started_generation,
        )
    with pytest.raises(ValueError, match="epoch|generation|chronology|trusted"):
        _verify_proof(
            envelope,
            signer,
            expected_epoch=envelope.epoch,
            expected_epoch_started_generation=envelope.epoch_started_generation + 1,
        )


def test_plain_source_profile_snapshot_is_not_an_authoritative_proof() -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")

    with pytest.raises(ValueError, match="proof|envelope|type"):
        _verify_proof(tracker.snapshot(), signer)


def test_tracker_without_dedicated_signer_cannot_issue_authoritative_proof() -> None:
    with pytest.raises(RuntimeError, match="proof signer|not configured"):
        _tracker().authoritative_proof()


def _proof_with_two_failures():
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    callbacks = tuple(
        tracker.bind_source(
            camera_id=CAMERA_IDS[source_index],
            resolved_url=_resolved_url(source_index),
            commitment_key=OTHER_KEY,
            bound_monotonic_ns=0,
        )
        for source_index in range(2)
    )
    envelope = tracker.authoritative_proof()
    assert len(callbacks) == 2
    assert len(envelope.receipts) == 2
    return tracker, signer, envelope


def _proof_with_counter_failure():
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)
    assert callback.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
        observed_monotonic_ns=0,
    )
    assert not callback.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    envelope = tracker.authoritative_proof()
    assert len(envelope.receipts) == 1
    return tracker, signer, envelope


def _rechained_receipt(
    receipt,
    *,
    sequence: int,
    prior_head: str,
    source_identity_commitment: str | None = None,
    event_generation: int | None = None,
    camera_id: str | None = None,
    source_index: int | None = None,
    failure_code: SourceProfileFailureCode | None = None,
    event_monotonic_ns: int | None = None,
    baseline_duration_ns: int | None = None,
):
    unsigned = source_profile_module._milestone_receipt_unsigned_dict(receipt)
    unsigned["sequence"] = sequence
    unsigned["prior_head"] = prior_head
    replacements = {
        "source_identity_commitment": source_identity_commitment,
        "event_generation": event_generation,
        "camera_id": camera_id,
        "source_index": source_index,
        "event_monotonic_ns": event_monotonic_ns,
        "baseline_duration_ns": baseline_duration_ns,
    }
    for field_name, value in replacements.items():
        if value is not None:
            unsigned[field_name] = value
    if failure_code is not None:
        unsigned["failure_code"] = failure_code.value
    head = hashlib.sha256(
        source_profile_module._SOURCE_MILESTONE_HEAD_DOMAIN
        + source_profile_module._canonical_bytes(unsigned)
    ).hexdigest()
    return replace(
        receipt,
        sequence=sequence,
        prior_head=prior_head,
        source_identity_commitment=(
            receipt.source_identity_commitment
            if source_identity_commitment is None
            else source_identity_commitment
        ),
        event_generation=(
            receipt.event_generation if event_generation is None else event_generation
        ),
        camera_id=receipt.camera_id if camera_id is None else camera_id,
        source_index=receipt.source_index if source_index is None else source_index,
        failure_code=receipt.failure_code if failure_code is None else failure_code,
        event_monotonic_ns=(
            receipt.event_monotonic_ns if event_monotonic_ns is None else event_monotonic_ns
        ),
        baseline_duration_ns=(
            receipt.baseline_duration_ns if baseline_duration_ns is None else baseline_duration_ns
        ),
        head=head,
    )


def _rechain_receipts(
    receipts,
    *,
    updates: dict[int, dict[str, object]] | None = None,
):
    prior_head = "0" * 64
    rechained = []
    updates = {} if updates is None else updates
    for receipt_index, receipt in enumerate(receipts):
        updated = _rechained_receipt(
            receipt,
            sequence=receipt_index + 1,
            prior_head=prior_head,
            **updates.get(receipt_index, {}),
        )
        rechained.append(updated)
        prior_head = updated.head
    return tuple(rechained)


def test_signed_milestone_chain_rejects_truncation_and_duplicate_receipts() -> None:
    _, signer, envelope = _proof_with_two_failures()
    retained = envelope.receipts[:-1]
    retained_failure = envelope.snapshot.failures[0]
    erased_source = replace(
        envelope.snapshot.sources[1],
        bound=False,
        callback_generation=0,
        failures=(),
    )
    truncated_snapshot = replace(
        envelope.snapshot,
        sources=(
            envelope.snapshot.sources[0],
            erased_source,
            *envelope.snapshot.sources[2:],
        ),
        failures=(retained_failure,),
    )
    truncated = replace(
        envelope,
        snapshot=truncated_snapshot,
        snapshot_sha256=_snapshot_digest(truncated_snapshot),
        receipts=retained,
        final_head=retained[-1].head,
        signature="0" * 128,
    )
    truncated = _resign_proof(truncated, signer)

    with pytest.raises(
        ValueError,
        match="receipt|failure|incomplete|proof|milestone|authentication",
    ):
        _verify_proof(truncated, signer)

    duplicate = _rechained_receipt(
        envelope.receipts[-1],
        sequence=len(envelope.receipts) + 1,
        prior_head=envelope.receipts[-1].head,
    )
    duplicated = replace(
        envelope,
        receipts=(*envelope.receipts, duplicate),
        final_head=duplicate.head,
        signature="0" * 128,
    )
    duplicated = _resign_proof(duplicated, signer)

    with pytest.raises(
        ValueError,
        match="duplicate|receipt|proof|milestone|authentication",
    ):
        _verify_proof(duplicated, signer)


def test_milestone_chain_rejects_malformed_and_reordered_receipts() -> None:
    _, _, envelope = _proof_with_two_failures()

    with pytest.raises(ValueError, match="head|milestone"):
        replace(envelope.receipts[0], head="0" * 64)
    with pytest.raises(ValueError, match="sequence|canonical|generation|chain"):
        replace(
            envelope,
            receipts=(envelope.receipts[1], envelope.receipts[0]),
        )


def test_signed_receipts_bind_each_event_to_its_ordered_source_identity() -> None:
    _, signer, envelope = _proof_with_two_failures()
    wrong_identity = envelope.source_identity_commitments[1]
    first = _rechained_receipt(
        envelope.receipts[0],
        sequence=1,
        prior_head="0" * 64,
        source_identity_commitment=wrong_identity,
    )
    second = _rechained_receipt(
        envelope.receipts[1],
        sequence=2,
        prior_head=first.head,
    )
    forged = replace(
        envelope,
        receipts=(first, second),
        final_head=second.head,
        signature="0" * 128,
    )
    forged = _resign_proof(forged, signer)

    with pytest.raises(ValueError, match="receipt|identity|source|proof"):
        _verify_proof(forged, signer)


def test_final_envelope_signer_cannot_rewrite_first_failure_history() -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)
    assert callback.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
        observed_monotonic_ns=0,
    )
    assert not callback.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    later_callback = tracker.bind_source(
        camera_id=CAMERA_IDS[1],
        resolved_url=_resolved_url(1),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=1,
    )
    envelope = tracker.authoritative_proof()
    assert later_callback.camera_id == CAMERA_IDS[1]
    failure = replace(envelope.snapshot.failures[0], first_generation=5)
    source = replace(envelope.snapshot.sources[0], failures=(failure,))
    snapshot = replace(
        envelope.snapshot,
        sources=(source, *envelope.snapshot.sources[1:]),
        failures=(failure,),
    )
    receipt = _rechained_receipt(
        envelope.receipts[0],
        sequence=1,
        prior_head="0" * 64,
        event_generation=5,
    )
    forged = replace(
        envelope,
        snapshot=snapshot,
        snapshot_sha256=_snapshot_digest(snapshot),
        receipts=(receipt,),
        final_head=receipt.head,
        signature="0" * 128,
    )
    forged = _resign_proof(forged, signer)

    with pytest.raises(ValueError, match="milestone|authentication|history"):
        _verify_proof(forged, signer)


def test_final_envelope_signer_cannot_substitute_first_failure_code() -> None:
    _, signer, envelope = _proof_with_counter_failure()
    substituted_code = SourceProfileFailureCode.INVALID_CALLBACK_PROVENANCE
    substituted_failure = replace(
        envelope.snapshot.failures[0],
        code=substituted_code,
    )
    substituted_source = replace(
        envelope.snapshot.sources[0],
        failures=(substituted_failure,),
    )
    substituted_snapshot = replace(
        envelope.snapshot,
        sources=(substituted_source, *envelope.snapshot.sources[1:]),
        failures=(substituted_failure,),
    )
    receipts = _rechain_receipts(
        envelope.receipts,
        updates={0: {"failure_code": substituted_code}},
    )
    forged = replace(
        envelope,
        snapshot=substituted_snapshot,
        snapshot_sha256=_snapshot_digest(substituted_snapshot),
        receipts=receipts,
        final_head=receipts[-1].head,
        signature="0" * 128,
    )
    forged = _resign_proof(forged, signer)

    with pytest.raises(ValueError, match="milestone|authentication|history"):
        _verify_proof(forged, signer)


def test_final_envelope_signer_cannot_reorder_same_generation_failures() -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    assert _observe(callback, sample_number=1, elapsed_ns=0)
    assert callback.on_parser_counter(
        parser_bytes=20_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
        observed_monotonic_ns=1,
    )
    assert not callback.on_decoded_frame(
        decoded_frames=1,
        source_ntp_ns=SOURCE_NTP_BASE_NS,
        observed_monotonic_ns=1,
    )
    envelope = tracker.authoritative_proof()
    assert len(envelope.receipts) == 2
    assert {receipt.failure_code for receipt in envelope.receipts} == {
        SourceProfileFailureCode.COUNTER_REGRESSION,
        SourceProfileFailureCode.TIMESTAMP_REPLAY,
    }
    assert len({receipt.event_generation for receipt in envelope.receipts}) == 1
    receipts = _rechain_receipts(tuple(reversed(envelope.receipts)))
    forged = replace(
        envelope,
        receipts=receipts,
        final_head=receipts[-1].head,
        signature="0" * 128,
    )
    forged = _resign_proof(forged, signer)

    with pytest.raises(ValueError, match="milestone|authentication|history"):
        _verify_proof(forged, signer)


def test_final_envelope_signer_cannot_substitute_failures_between_sources() -> None:
    _, signer, envelope = _proof_with_two_failures()
    first_failure, second_failure = envelope.snapshot.failures
    substituted_first = replace(
        first_failure,
        first_generation=second_failure.first_generation,
    )
    substituted_second = replace(
        second_failure,
        first_generation=first_failure.first_generation,
    )
    first_source = replace(
        envelope.snapshot.sources[0],
        failures=(substituted_first,),
    )
    second_source = replace(
        envelope.snapshot.sources[1],
        failures=(substituted_second,),
    )
    substituted_snapshot = replace(
        envelope.snapshot,
        sources=(
            first_source,
            second_source,
            *envelope.snapshot.sources[2:],
        ),
        failures=(substituted_first, substituted_second),
    )
    receipts = _rechain_receipts(
        envelope.receipts,
        updates={
            0: {
                "camera_id": CAMERA_IDS[1],
                "source_index": 1,
                "source_identity_commitment": (envelope.source_identity_commitments[1]),
            },
            1: {
                "camera_id": CAMERA_IDS[0],
                "source_index": 0,
                "source_identity_commitment": (envelope.source_identity_commitments[0]),
            },
        },
    )
    forged = replace(
        envelope,
        snapshot=substituted_snapshot,
        snapshot_sha256=_snapshot_digest(substituted_snapshot),
        receipts=receipts,
        final_head=receipts[-1].head,
        signature="0" * 128,
    )
    forged = _resign_proof(forged, signer)

    with pytest.raises(ValueError, match="milestone|authentication|history"):
        _verify_proof(forged, signer)


def test_proof_verifier_rejects_oversized_milestone_chain_before_cloning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, signer, envelope = _proof_with_two_failures()
    oversized = (
        *envelope.receipts,
        *((envelope.receipts[-1],) * (source_profile_module._MAX_PROOF_MILESTONES - 1)),
    )
    object.__setattr__(envelope, "receipts", oversized)

    def cloning_is_too_late(_receipt):
        raise AssertionError("oversized proof receipts reached cloning")

    monkeypatch.setattr(
        source_profile_module,
        "_clone_milestone_receipt",
        cloning_is_too_late,
    )
    with pytest.raises(ValueError, match="bounded|receipt|proof"):
        _verify_proof(envelope, signer)


def test_proof_envelope_and_verified_snapshot_deeply_own_milestone_state() -> None:
    _, signer, exposed = _proof_with_two_failures()
    owned = source_profile_module.NativeSourceProfileProofEnvelopeV1(
        schema=exposed.schema,
        site_id=exposed.site_id,
        key_id=exposed.key_id,
        public_key_sha256=exposed.public_key_sha256,
        milestone_authenticator_key_id=(exposed.milestone_authenticator_key_id),
        milestone_authentication_tag=(exposed.milestone_authentication_tag),
        epoch=exposed.epoch,
        epoch_started_generation=exposed.epoch_started_generation,
        generation=exposed.generation,
        source_identity_commitments=exposed.source_identity_commitments,
        snapshot_sha256=exposed.snapshot_sha256,
        snapshot=exposed.snapshot,
        receipts=exposed.receipts,
        final_head=exposed.final_head,
        signature=exposed.signature,
    )
    original_camera_id = owned.snapshot.sources[0].camera_id
    original_generation = owned.receipts[0].event_generation
    original_authentication_tag = owned.receipts[0].authentication_tag

    object.__setattr__(exposed.snapshot.sources[0], "camera_id", CAMERA_IDS[1])
    object.__setattr__(exposed.receipts[0], "event_generation", INT64_MAX)
    object.__setattr__(exposed.receipts[0], "authentication_tag", "0" * 64)

    assert owned.snapshot.sources[0].camera_id == original_camera_id
    assert owned.receipts[0].event_generation == original_generation
    assert owned.receipts[0].authentication_tag == original_authentication_tag
    verified = _verify_proof(owned, signer)
    object.__setattr__(verified.sources[0], "camera_id", CAMERA_IDS[1])
    assert _verify_proof(owned, signer).sources[0].camera_id == original_camera_id


def test_dedicated_proof_signer_is_called_once_without_source_secrets() -> None:
    delegate = source_profile_module.Ed25519SourceProfileProofSigner(
        key_id=SOURCE_PROOF_KEY_ID,
        signing_seed=SOURCE_PROOF_SEED,
    )
    signed_payloads: list[bytes] = []

    class RecordingSigner:
        key_id = delegate.key_id
        public_key = delegate.public_key

        def sign(self, payload: bytes) -> bytes:
            signed_payloads.append(bytes(payload))
            return delegate.sign(payload)

    tracker = NativeSourceProfileTracker(
        site_id=SITE_ID,
        expectations=_expectations(),
        commitment_key=COMMITMENT_KEY,
        milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
        milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
        delta_capacity=100_000,
        epoch_started_monotonic_ns=0,
        proof_signer=RecordingSigner(),
    )
    envelope = tracker.authoritative_proof()

    assert len(signed_payloads) == 1
    assert COMMITMENT_KEY not in signed_payloads[0]
    assert MILESTONE_AUTHENTICATOR_KEY not in signed_payloads[0]
    assert all(_resolved_url(index).encode() not in signed_payloads[0] for index in range(20))
    public_envelope = json.dumps(envelope.to_dict(), sort_keys=True).encode()
    assert COMMITMENT_KEY not in public_envelope
    assert MILESTONE_AUTHENTICATOR_KEY not in public_envelope
    assert all(_resolved_url(index).encode() not in public_envelope for index in range(20))


def test_authoritative_proof_issuance_invokes_openssl_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    original_run = source_profile_module.subprocess.run
    invocations: list[object] = []

    def recording_run(*args, **kwargs):
        invocations.append(args[0])
        return original_run(*args, **kwargs)

    monkeypatch.setattr(source_profile_module.subprocess, "run", recording_run)
    envelope = tracker.authoritative_proof()

    assert envelope.signature != "0" * 128
    assert len(invocations) == 1


@pytest.mark.parametrize(
    "failed_domain",
    [
        source_profile_module._SOURCE_MILESTONE_AUTH_DOMAIN,
        source_profile_module._SOURCE_MILESTONE_TERMINAL_DOMAIN,
    ],
)
def test_failure_milestone_authentication_is_atomic(
    failed_domain: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker, _, _ = _proof_with_counter_failure()
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[1],
        resolved_url=_resolved_url(1),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=1,
    )
    assert callback.on_rtp_caps(CAPS, observed_monotonic_ns=1)
    assert callback.on_parser_counter(
        parser_bytes=10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS,
        observed_monotonic_ns=1,
    )
    snapshot_before = tracker.snapshot()
    deltas_before = tracker.deltas_since(0)
    receipts_before = tracker.authoritative_proof().receipts
    original_digest = source_profile_module.hmac.digest

    def fail_milestone_authentication(key, payload, digest):
        if payload.startswith(failed_domain):
            raise RuntimeError("injected milestone authentication failure")
        return original_digest(key, payload, digest)

    monkeypatch.setattr(
        source_profile_module.hmac,
        "digest",
        fail_milestone_authentication,
    )
    with pytest.raises(RuntimeError, match="injected milestone"):
        callback.on_parser_counter(
            parser_bytes=10_000,
            source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + 1,
            observed_monotonic_ns=2,
        )

    assert tracker.snapshot() == snapshot_before
    assert tracker.deltas_since(0) == deltas_before
    assert tracker.authoritative_proof().receipts == receipts_before


@pytest.mark.parametrize(
    "failed_domain",
    [
        source_profile_module._SOURCE_MILESTONE_AUTH_DOMAIN,
        source_profile_module._SOURCE_MILESTONE_TERMINAL_DOMAIN,
    ],
)
def test_prewarm_milestone_authentication_is_atomic(
    failed_domain: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    step_ns = 40_000_000
    for sample_number, elapsed_ns in enumerate(
        range(0, PREWARM_NS, step_ns),
        start=1,
    ):
        assert _observe(
            callback,
            sample_number=sample_number,
            elapsed_ns=elapsed_ns,
        )
    final_sample = PREWARM_NS // step_ns + 1
    assert callback.on_parser_counter(
        parser_bytes=final_sample * 10_000,
        source_timestamp_ns=SOURCE_TIMESTAMP_BASE_NS + PREWARM_NS,
        observed_monotonic_ns=PREWARM_NS,
    )
    snapshot_before = tracker.snapshot()
    deltas_before = tracker.deltas_since(0)
    receipts_before = tracker.authoritative_proof().receipts
    original_digest = source_profile_module.hmac.digest

    def fail_milestone_authentication(key, payload, digest):
        if payload.startswith(failed_domain):
            raise RuntimeError("injected milestone authentication failure")
        return original_digest(key, payload, digest)

    monkeypatch.setattr(
        source_profile_module.hmac,
        "digest",
        fail_milestone_authentication,
    )
    with pytest.raises(RuntimeError, match="injected milestone"):
        callback.on_decoded_frame(
            decoded_frames=final_sample,
            source_ntp_ns=SOURCE_NTP_BASE_NS + PREWARM_NS,
            observed_monotonic_ns=PREWARM_NS,
        )

    assert tracker.snapshot() == snapshot_before
    assert tracker.deltas_since(0) == deltas_before
    assert tracker.authoritative_proof().receipts == receipts_before


def test_bind_failure_milestone_authentication_is_atomic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    snapshot_before = tracker.snapshot()
    deltas_before = tracker.deltas_since(0)
    receipts_before = tracker.authoritative_proof().receipts
    original_digest = source_profile_module.hmac.digest

    def fail_milestone_authentication(key, payload, digest):
        if payload.startswith(source_profile_module._SOURCE_MILESTONE_AUTH_DOMAIN):
            raise RuntimeError("injected milestone authentication failure")
        return original_digest(key, payload, digest)

    monkeypatch.setattr(
        source_profile_module.hmac,
        "digest",
        fail_milestone_authentication,
    )
    with pytest.raises(RuntimeError, match="injected milestone"):
        tracker.bind_source(
            camera_id=CAMERA_IDS[0],
            resolved_url=_resolved_url(0),
            commitment_key=OTHER_KEY,
            bound_monotonic_ns=0,
        )

    assert tracker.snapshot() == snapshot_before
    assert tracker.deltas_since(0) == deltas_before
    assert tracker.authoritative_proof().receipts == receipts_before
    assert tracker._close_reservations == 0

    monkeypatch.setattr(source_profile_module.hmac, "digest", original_digest)
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=OTHER_KEY,
        bound_monotonic_ns=0,
    )
    retried = tracker.authoritative_proof()
    assert callback.camera_id == CAMERA_IDS[0]
    assert retried.generation == snapshot_before.generation + 1
    assert len(retried.receipts) == 1


def test_restart_milestone_scope_is_atomic_empty_and_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker, signer = _proof_tracker_or_plain()
    if signer is None:
        pytest.fail("authoritative source-profile proof signer is not implemented")
    old_callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=OTHER_KEY,
        bound_monotonic_ns=0,
    )
    old_snapshot = tracker.snapshot()
    old_proof = tracker.authoritative_proof()
    original_digest = source_profile_module.hmac.digest

    def fail_terminal_authentication(key, payload, digest):
        if payload.startswith(source_profile_module._SOURCE_MILESTONE_TERMINAL_DOMAIN):
            raise RuntimeError("injected milestone terminal failure")
        return original_digest(key, payload, digest)

    monkeypatch.setattr(
        source_profile_module.hmac,
        "digest",
        fail_terminal_authentication,
    )
    with pytest.raises(RuntimeError, match="injected milestone terminal"):
        tracker.restart_epoch(started_monotonic_ns=1)
    assert tracker.snapshot() == old_snapshot
    assert tracker.authoritative_proof() == old_proof

    monkeypatch.setattr(source_profile_module.hmac, "digest", original_digest)
    restarted = tracker.restart_epoch(started_monotonic_ns=1)
    empty_proof = tracker.authoritative_proof()
    assert old_callback.on_rtp_caps(CAPS, observed_monotonic_ns=1) is False
    assert restarted.epoch == old_proof.epoch + 1
    assert empty_proof.receipts == ()
    assert empty_proof.final_head == "0" * 64
    assert empty_proof.milestone_authentication_tag != old_proof.milestone_authentication_tag
    assert _verify_proof(empty_proof, signer) == restarted

    new_callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=OTHER_KEY,
        bound_monotonic_ns=1,
    )
    new_proof = tracker.authoritative_proof()
    assert new_callback.camera_id == CAMERA_IDS[0]
    assert new_proof.receipts[0].sequence == 1
    assert new_proof.receipts[0].prior_head == "0" * 64
    assert new_proof.receipts[0].epoch == restarted.epoch
    assert _verify_proof(new_proof, signer) == new_proof.snapshot


def test_authoritative_proof_signing_does_not_block_native_ingest() -> None:
    delegate = source_profile_module.Ed25519SourceProfileProofSigner(
        key_id=SOURCE_PROOF_KEY_ID,
        signing_seed=SOURCE_PROOF_SEED,
    )
    signing_started = Event()
    release_signing = Event()

    class BlockingSigner:
        key_id = delegate.key_id
        public_key = delegate.public_key

        def sign(self, payload: bytes) -> bytes:
            signing_started.set()
            if not release_signing.wait(timeout=10):
                raise AssertionError("test did not release source-profile signing")
            return delegate.sign(payload)

    tracker = NativeSourceProfileTracker(
        site_id=SITE_ID,
        expectations=_expectations(),
        commitment_key=COMMITMENT_KEY,
        milestone_authenticator_key_id=MILESTONE_AUTHENTICATOR_KEY_ID,
        milestone_authenticator_key=MILESTONE_AUTHENTICATOR_KEY,
        delta_capacity=100_000,
        epoch_started_monotonic_ns=0,
        proof_signer=BlockingSigner(),
    )
    callback = tracker.bind_source(
        camera_id=CAMERA_IDS[0],
        resolved_url=_resolved_url(0),
        commitment_key=COMMITMENT_KEY,
        bound_monotonic_ns=0,
    )
    ingest_finished = Event()

    def ingest_caps() -> bool:
        try:
            return callback.on_rtp_caps(CAPS, observed_monotonic_ns=0)
        finally:
            ingest_finished.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        proof_future = executor.submit(tracker.authoritative_proof)
        assert signing_started.wait(timeout=5)
        ingest_future = executor.submit(ingest_caps)
        try:
            assert ingest_finished.wait(timeout=2), (
                "off-hot-path proof signing retained the native-ingest lock"
            )
        finally:
            release_signing.set()

        assert ingest_future.result(timeout=5)
        envelope = proof_future.result(timeout=10)

    assert envelope.generation + 1 == tracker.generation
    assert _verify_proof(envelope, delegate) == envelope.snapshot
