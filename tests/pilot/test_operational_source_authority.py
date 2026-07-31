from __future__ import annotations

from protector.pilot.runtime.operational_source_authority import (
    OperationalNativeSourceAuthority,
    OperationalSourceExpectation,
)


def _expectations() -> tuple[OperationalSourceExpectation, ...]:
    return tuple(
        OperationalSourceExpectation(
            camera_id=f"camera-{index + 1:02}",
            source_index=index,
            codec="h264",
            width=1920,
            height=1080,
            fps=25.0,
        )
        for index in range(20)
    )


def test_operational_authority_issues_current_camera_scoped_native_leases() -> None:
    authority = OperationalNativeSourceAuthority(
        expectations=_expectations(),
        bridge_capacity=8,
    )

    lease = authority.acquire("camera-01", 0)

    assert lease.observe_rtp_caps("h264", 1)
    assert lease.observe_decoder_caps(1920, 1080, 25, 1, 2)
    assert lease.observe_parser_buffer(20_000, 1_000_000_000, 100, 3)
    assert lease.observe_decoded_buffer(100, 4)
    assert lease.observe_nvds_ntp(100, 2_000_000_000, 5)
    assert lease.correlated_ntp(100, 2_000_000_000) is None
    assert lease.observe_parser_buffer(20_000, 1_040_000_000, 200, 6)
    assert lease.observe_decoded_buffer(200, 7)
    assert lease.observe_nvds_ntp(200, 2_040_000_000, 8)
    assert lease.correlated_ntp(200, 2_040_000_000) is not None


def test_operational_authority_rejects_wrong_source_order_and_caps_drift() -> None:
    authority = OperationalNativeSourceAuthority(
        expectations=_expectations(),
        bridge_capacity=8,
    )

    try:
        authority.acquire("camera-02", 0)
    except ValueError:
        pass
    else:  # pragma: no cover - assertion gives a clearer failure than pytest here.
        raise AssertionError("source order drift must fail closed")

    lease = authority.acquire("camera-01", 0)
    assert lease.observe_rtp_caps("h265", 1)
    assert lease.observe_decoder_caps(1920, 1080, 25, 1, 2)
    assert lease.observe_parser_buffer(20_000, 1_000_000_000, 100, 3)
    assert lease.observe_decoded_buffer(100, 4)
    assert lease.observe_nvds_ntp(100, 2_000_000_000, 5)
    assert lease.observe_parser_buffer(20_000, 1_040_000_000, 200, 6)
    assert lease.observe_decoded_buffer(200, 7)
    assert lease.observe_nvds_ntp(200, 2_040_000_000, 8) is False
    assert authority.failures("camera-01") == ("profile_mismatch",)


def test_operational_authority_replaces_only_after_prior_lease_closes() -> None:
    authority = OperationalNativeSourceAuthority(
        expectations=_expectations(),
        bridge_capacity=8,
    )
    first = authority.acquire("camera-01", 0)

    try:
        authority.acquire("camera-01", 0)
    except RuntimeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("overlapping source generations must fail closed")

    first.close()
    replacement = authority.acquire("camera-01", 0)

    assert replacement.observe_rtp_caps("h264", 1)
