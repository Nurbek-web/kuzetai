"""Measured target-capacity gate shared by provisioning and data-plane startup."""

from __future__ import annotations

from typing import Protocol

from protector.pilot.config import SiteConfig
from protector.pilot.gates import (
    PILOT_TARGET_GPU_ARCHITECTURE,
    MeasuredCapacityReportV1,
    site_config_sha256,
)


class PrimaryRuntimeIdentity(Protocol):
    site_id: str
    artifact: object
    registry_entry_sha256: str
    frozen_workload_sha256: str
    expected_workload_sha256: str
    engine_sha256: str | None
    precision: str
    target_compute_capability: str
    tensorrt_version: str


def require_measured_primary_capacity(
    *,
    site_config: SiteConfig,
    runtime_manifest: PrimaryRuntimeIdentity,
    report: MeasuredCapacityReportV1,
) -> None:
    """Fail unless the exact 20-camera person workload has measured 25%+ headroom."""
    artifact = runtime_manifest.artifact
    required_throughput_hz = sum(
        float(feed.analytics_hz["person"])
        for feed in site_config.ready_to_start.feeds
    )
    mismatch = (
        not report.passed
        or report.site_id != runtime_manifest.site_id
        or report.artifact_id != getattr(artifact, "artifact_id", None)
        or report.artifact_sha256 != getattr(artifact, "sha256", None)
        or report.registry_entry_sha256
        != runtime_manifest.registry_entry_sha256
        or report.frozen_workload_sha256
        != runtime_manifest.frozen_workload_sha256
        or report.expected_workload_sha256
        != runtime_manifest.expected_workload_sha256
        or report.engine_sha256 != runtime_manifest.engine_sha256
        or report.precision != runtime_manifest.precision
        or report.target_gpu_architecture != PILOT_TARGET_GPU_ARCHITECTURE
        or report.target_compute_capability
        != runtime_manifest.target_compute_capability
        or report.tensorrt_version != runtime_manifest.tensorrt_version
        or report.site_config_sha256 != site_config_sha256(site_config)
        or report.stream_count != 20
        or abs(report.required_throughput_hz - required_throughput_hz) > 1e-9
        or report.effective_throughput_hz < report.required_throughput_hz * 1.25
        or report.scheduled_drop_fraction >= 0.01
        or report.queue_age_p95_seconds >= 1.0
        or report.queue_age_p99_seconds >= 2.0
        or report.gpu_utilization_max > 0.75
        or report.vram_utilization_max > 0.80
    )
    if mismatch:
        raise ValueError(
            "measured target capacity report is missing exact bindings or 25% headroom"
        )
