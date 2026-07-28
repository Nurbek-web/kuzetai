"""Shared runtime boundary for deterministic and NVIDIA data-plane adapters."""

from __future__ import annotations

from typing import Protocol

from protector.pilot.config import SiteConfig
from protector.pilot.runtime.supervisor import CameraHealth


class DataPlane(Protocol):
    """A single multistream runtime that owns its camera supervision state."""

    def start(self, site: SiteConfig) -> None: ...

    def stop(self) -> None: ...

    def health(self) -> list[CameraHealth]: ...
