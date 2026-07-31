"""Finite retention for live operational metadata append surfaces."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

_SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class OperationalMetadataPruneCounts:
    """Exact per-table counts returned by one atomic database prune."""

    health_samples: int
    observations: int


class OperationalMetadataRetentionRepository(Protocol):
    """Least-privilege database boundary owned by the retention identity."""

    def prune_operational_metadata(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> OperationalMetadataPruneCounts: ...


@dataclass(frozen=True, slots=True)
class OperationalMetadataRetentionResult:
    health_samples_pruned: int
    observations_pruned: int
    failed: int
    failure_reasons: tuple[str, ...]


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(
            "operational metadata retention clock must be timezone-aware"
        )
    return value.astimezone(UTC)


class OperationalMetadataRetentionCoordinator:
    """Prune one finite site-scoped batch from each live metadata table."""

    def __init__(
        self,
        *,
        repository: OperationalMetadataRetentionRepository,
        site_id: str,
        metadata_retention_days: int,
        batch_size: int,
        clock: Callable[[], datetime],
    ) -> None:
        if _SITE_ID.fullmatch(site_id) is None:
            raise ValueError(
                "operational metadata retention site identity is invalid"
            )
        if (
            not isinstance(metadata_retention_days, int)
            or isinstance(metadata_retention_days, bool)
            or not 1 <= metadata_retention_days <= 365
        ):
            raise ValueError(
                "operational metadata retention must be between 1 and 365 days"
            )
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or not 1 <= batch_size <= 1_000
        ):
            raise ValueError(
                "operational metadata retention batch must be between 1 and 1000"
            )
        if not callable(clock):
            raise TypeError(
                "operational metadata retention clock must be callable"
            )
        self._repository = repository
        self.site_id = site_id
        self.metadata_retention_days = metadata_retention_days
        self.batch_size = batch_size
        self._clock = clock

    def run_once(self) -> OperationalMetadataRetentionResult:
        cutoff_at = _utc_now(self._clock) - timedelta(
            days=self.metadata_retention_days
        )
        try:
            counts = self._repository.prune_operational_metadata(
                site_id=self.site_id,
                cutoff_at=cutoff_at,
                limit=self.batch_size,
            )
            if (
                not isinstance(counts, OperationalMetadataPruneCounts)
                or any(
                    not isinstance(count, int)
                    or isinstance(count, bool)
                    or not 0 <= count <= self.batch_size
                    for count in (
                        counts.health_samples,
                        counts.observations,
                    )
                )
            ):
                raise RuntimeError(
                    "operational metadata prune violated its finite batch"
                )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return OperationalMetadataRetentionResult(
                health_samples_pruned=0,
                observations_pruned=0,
                failed=1,
                failure_reasons=("operational_metadata_prune_failed",),
            )
        return OperationalMetadataRetentionResult(
            health_samples_pruned=counts.health_samples,
            observations_pruned=counts.observations,
            failed=0,
            failure_reasons=(),
        )
