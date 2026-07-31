"""Non-acceptance native source leases for the reviewed production pilot."""

from __future__ import annotations

import math
import re
import threading
from collections import deque
from dataclasses import dataclass
from typing import Literal

from protector.pilot.config import SiteConfig
from protector.pilot.runtime.source_probe import (
    NativeSourceProbeBridge,
    SourceProbeLease,
)
from protector.pilot.runtime.source_profile import (
    NativeSourceCaps,
    SourceProfileFailureCode,
)

_CAMERA_COUNT = 20
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class OperationalSourceExpectation:
    """Static reviewed CAPS expected from one configured production source."""

    camera_id: str
    source_index: int
    codec: Literal["h264", "h265"]
    width: int
    height: int
    fps: float

    def __post_init__(self) -> None:
        if (
            type(self.camera_id) is not str
            or _IDENTIFIER.fullmatch(self.camera_id) is None
            or type(self.source_index) is not int
            or not 0 <= self.source_index < _CAMERA_COUNT
            or self.codec not in {"h264", "h265"}
            or type(self.width) is not int
            or not 1 <= self.width <= 16_384
            or type(self.height) is not int
            or not 1 <= self.height <= 8_640
            or type(self.fps) not in {int, float}
            or not math.isfinite(self.fps)
            or not 1.0 <= self.fps <= 240.0
        ):
            raise ValueError("operational source expectation is invalid")


class _OperationalCallbacks:
    """Generation-owned static CAPS and native-correlation callback target."""

    __slots__ = (
        "_authority",
        "_closed",
        "_expectation",
        "_generation",
        "_lock",
    )

    def __init__(
        self,
        *,
        authority: OperationalNativeSourceAuthority,
        expectation: OperationalSourceExpectation,
        generation: int,
    ) -> None:
        self._authority = authority
        self._expectation = expectation
        self._generation = generation
        self._closed = False
        self._lock = threading.RLock()

    def on_rtp_caps(
        self,
        caps: NativeSourceCaps,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        del observed_monotonic_ns
        expected = self._expectation
        accepted = (
            type(caps) is NativeSourceCaps
            and caps.codec == expected.codec
            and caps.width == expected.width
            and caps.height == expected.height
            and math.isclose(
                caps.fps,
                expected.fps,
                rel_tol=0.0,
                abs_tol=1e-6,
            )
        )
        if not accepted:
            self._authority._record_failure(  # noqa: SLF001
                expected.camera_id,
                self._generation,
                "profile_mismatch",
            )
        with self._lock:
            return accepted and not self._closed

    def on_parser_counter(
        self,
        *,
        parser_bytes: int,
        source_timestamp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        del parser_bytes, source_timestamp_ns, observed_monotonic_ns
        with self._lock:
            return not self._closed

    def on_decoded_frame(
        self,
        *,
        decoded_frames: int,
        source_ntp_ns: int,
        observed_monotonic_ns: int,
    ) -> bool:
        del decoded_frames, source_ntp_ns, observed_monotonic_ns
        with self._lock:
            return not self._closed

    def on_native_probe_failure(
        self,
        code: SourceProfileFailureCode,
        *,
        observed_monotonic_ns: int,
    ) -> bool:
        del observed_monotonic_ns
        value = code.value if type(code) is SourceProfileFailureCode else "invalid_callback_provenance"
        self._authority._record_failure(  # noqa: SLF001
            self._expectation.camera_id,
            self._generation,
            value,
        )
        return False

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._authority._release(  # noqa: SLF001
            self._expectation.camera_id,
            self._generation,
        )


class OperationalNativeSourceAuthority:
    """Issue bounded native correlators without creating acceptance evidence."""

    __slots__ = (
        "_active",
        "_bridge_capacity",
        "_expectations",
        "_failures",
        "_generation",
        "_lock",
    )

    def __init__(
        self,
        *,
        expectations: tuple[OperationalSourceExpectation, ...],
        bridge_capacity: int = 64,
    ) -> None:
        if (
            type(expectations) is not tuple
            or len(expectations) != _CAMERA_COUNT
            or any(
                type(item) is not OperationalSourceExpectation
                for item in expectations
            )
            or tuple(item.source_index for item in expectations)
            != tuple(range(_CAMERA_COUNT))
            or len({item.camera_id for item in expectations}) != _CAMERA_COUNT
            or type(bridge_capacity) is not int
            or not 1 <= bridge_capacity <= 1_000_000
        ):
            raise ValueError(
                "operational native authority requires exact ordered 20-source expectations"
            )
        self._expectations = expectations
        self._bridge_capacity = bridge_capacity
        self._active: dict[str, int] = {}
        self._generation: dict[str, int] = {}
        self._failures: dict[str, deque[str]] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_site(
        cls,
        site: SiteConfig,
        *,
        bridge_capacity: int = 64,
    ) -> OperationalNativeSourceAuthority:
        if type(site) is not SiteConfig:
            raise TypeError("operational native authority requires a reviewed site")
        return cls(
            expectations=tuple(
                OperationalSourceExpectation(
                    camera_id=feed.camera_id,
                    source_index=feed.source_index,
                    codec=feed.codec,
                    width=feed.resolution.width,
                    height=feed.resolution.height,
                    fps=feed.fps,
                )
                for feed in site.ready_to_start.feeds
            ),
            bridge_capacity=bridge_capacity,
        )

    def __copy__(self) -> object:
        raise TypeError("operational native authority cannot be copied")

    def __deepcopy__(self, _: object) -> object:
        raise TypeError("operational native authority cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("operational native authority cannot be serialized")

    def __reduce_ex__(self, _: int) -> object:
        raise TypeError("operational native authority cannot be serialized")

    def acquire(self, camera_id: str, source_id: int) -> SourceProbeLease:
        if (
            type(camera_id) is not str
            or type(source_id) is not int
            or not 0 <= source_id < _CAMERA_COUNT
        ):
            raise ValueError("operational native source identity is invalid")
        expectation = self._expectations[source_id]
        if (
            expectation.camera_id != camera_id
            or expectation.source_index != source_id
        ):
            raise ValueError(
                "operational native source order differs from reviewed configuration"
            )
        with self._lock:
            if camera_id in self._active:
                raise RuntimeError(
                    "prior operational native source generation is still active"
                )
            generation = self._generation.get(camera_id, 0) + 1
            if generation > 2**63 - 1:
                raise OverflowError(
                    "operational native source generation is exhausted"
                )
            bridge = NativeSourceProbeBridge(capacity=self._bridge_capacity)
            callbacks = _OperationalCallbacks(
                authority=self,
                expectation=expectation,
                generation=generation,
            )
            lease = bridge.bind(callbacks)
            self._generation[camera_id] = generation
            self._active[camera_id] = generation
            return lease

    def failures(self, camera_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._failures.get(camera_id, ()))

    def _record_failure(
        self,
        camera_id: str,
        generation: int,
        code: str,
    ) -> None:
        with self._lock:
            if self._active.get(camera_id) != generation:
                return
            failures = self._failures.setdefault(
                camera_id,
                deque(maxlen=16),
            )
            if not failures or failures[-1] != code:
                failures.append(code)

    def _release(self, camera_id: str, generation: int) -> None:
        with self._lock:
            if self._active.get(camera_id) == generation:
                del self._active[camera_id]


__all__ = (
    "OperationalNativeSourceAuthority",
    "OperationalSourceExpectation",
)
