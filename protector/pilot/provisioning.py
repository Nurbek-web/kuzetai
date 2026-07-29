"""Idempotent, manifest-bound provisioning for the single-site controlled pilot."""

from __future__ import annotations

import hashlib
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from sqlalchemy import select

from protector.pilot.capacity_acceptance import require_measured_primary_capacity
from protector.pilot.config import SiteConfig, load_site_config
from protector.pilot.gates import (
    PILOT_TARGET_COMPUTE_CAPABILITY,
    PILOT_TENSORRT_VERSION,
    MeasuredCapacityReportV1,
)
from protector.pilot.runtime.deepstream import RuntimeModelManifestV1
from protector.pilot.storage.db import SessionFactory
from protector.pilot.storage.models import CameraModel, ModelArtifactModel, SiteModel


class ProvisioningError(RuntimeError):
    """The reviewed bootstrap inputs do not match the persistent database."""


def _file_digest(path: Path, *, max_bytes: int) -> str:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ProvisioningError("reviewed provisioning manifest is unavailable")
    size = path.stat().st_size
    if not 0 < size <= max_bytes:
        raise ProvisioningError("reviewed provisioning manifest exceeds finite size bound")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _require_digest(path: Path, expected: str, label: str, *, max_bytes: int) -> None:
    if (
        len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
        or _file_digest(path, max_bytes=max_bytes) != expected
    ):
        raise ProvisioningError(f"{label} digest does not match reviewed input")


def _source_reference(feed: object) -> str:
    reference = feed.rtsp_url  # type: ignore[attr-defined]
    if reference.environment is not None:
        return f"environment:{reference.environment}"
    return f"docker-secret:{reference.docker_secret}"


def _artifact_values(manifest: RuntimeModelManifestV1) -> dict[str, object]:
    artifact = manifest.artifact
    return {
        "artifact_id": artifact.artifact_id,
        "schema_version": artifact.schema_version,
        "analytic": artifact.analytic,
        "sha256": artifact.sha256,
        "source": artifact.source,
        "commercial_rights": (
            artifact.commercial_rights.model_dump(mode="json")
            if artifact.commercial_rights is not None
            else None
        ),
        "class_list": list(artifact.class_list),
        "preprocessing": artifact.preprocessing,
    }


def load_reviewed_inputs(
    *,
    site_id: str,
    site_config_path: Path,
    site_config_sha256: str,
    runtime_manifest_path: Path,
    runtime_manifest_sha256: str,
    measured_capacity_path: Path,
    measured_capacity_sha256: str,
) -> tuple[SiteConfig, RuntimeModelManifestV1, MeasuredCapacityReportV1]:
    """Load only exact, digest-reviewed inputs and apply target-independent gates."""
    _require_digest(
        site_config_path,
        site_config_sha256,
        "site configuration",
        max_bytes=1024 * 1024,
    )
    _require_digest(
        runtime_manifest_path,
        runtime_manifest_sha256,
        "runtime manifest",
        max_bytes=8 * 1024 * 1024,
    )
    _require_digest(
        measured_capacity_path,
        measured_capacity_sha256,
        "measured capacity report",
        max_bytes=8 * 1024 * 1024,
    )
    site_config = load_site_config(site_config_path)
    try:
        raw_manifest = yaml.safe_load(runtime_manifest_path.read_text(encoding="utf-8"))
        manifest = RuntimeModelManifestV1.model_validate(raw_manifest)
        capacity_report = MeasuredCapacityReportV1.model_validate(
            yaml.safe_load(measured_capacity_path.read_text(encoding="utf-8"))
        )
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ProvisioningError("runtime manifest is invalid") from exc
    if manifest.site_id != site_id:
        raise ProvisioningError("runtime manifest site does not match provisioning site")
    if site_config.storage.evidence_prefix.split("/")[-1] != site_id:
        raise ProvisioningError("evidence prefix must terminate in the pilot site identity")
    try:
        manifest.validate_for_host(
            compute_capability=PILOT_TARGET_COMPUTE_CAPABILITY,
            tensorrt_version=PILOT_TENSORRT_VERSION,
            require_files=False,
        )
    except ValueError as exc:
        raise ProvisioningError("runtime manifest promotion gates are not satisfied") from exc
    try:
        require_measured_primary_capacity(
            site_config=site_config,
            runtime_manifest=manifest,
            report=capacity_report,
        )
    except ValueError as exc:
        raise ProvisioningError(str(exc)) from exc
    return site_config, manifest, capacity_report


def provision_reviewed_pilot(
    *,
    session_factory: SessionFactory,
    site_id: str,
    site_name: str,
    timezone_name: str,
    site_config: SiteConfig,
    runtime_manifest: RuntimeModelManifestV1,
) -> None:
    """Create or verify one exact site, its 20 cameras, and shared primary artifact."""
    if not site_id or len(site_id) > 128 or not site_name or len(site_name) > 255:
        raise ProvisioningError("site identity is invalid")
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ProvisioningError("site timezone is invalid") from exc
    if runtime_manifest.site_id != site_id:
        raise ProvisioningError("runtime manifest site does not match provisioning site")
    desired_cameras = {
        feed.camera_id: {
            "site_id": site_id,
            "name": feed.camera_id,
            "source_reference": _source_reference(feed),
            "codec": feed.codec,
            "enabled": True,
        }
        for feed in site_config.ready_to_start.feeds
    }
    if len(desired_cameras) != 20:
        raise ProvisioningError("controlled pilot requires exactly 20 cameras")
    artifact_values = _artifact_values(runtime_manifest)

    with session_factory.begin() as session:
        sites = list(session.scalars(select(SiteModel).order_by(SiteModel.site_id)))
        if not sites:
            session.add(
                SiteModel(
                    site_id=site_id,
                    name=site_name,
                    timezone_name=timezone_name,
                )
            )
            session.flush()
        elif len(sites) != 1 or (
            sites[0].site_id,
            sites[0].name,
            sites[0].timezone_name,
        ) != (site_id, site_name, timezone_name):
            raise ProvisioningError("database site does not match reviewed provisioning input")

        cameras = {
            row.camera_id: row
            for row in session.scalars(select(CameraModel).order_by(CameraModel.camera_id))
        }
        if not cameras:
            session.add_all(
                CameraModel(camera_id=camera_id, state="starting", **values)
                for camera_id, values in desired_cameras.items()
            )
        elif set(cameras) != set(desired_cameras):
            raise ProvisioningError("database camera set does not match reviewed input")
        else:
            for camera_id, expected in desired_cameras.items():
                row = cameras[camera_id]
                actual = {
                    "site_id": row.site_id,
                    "name": row.name,
                    "source_reference": row.source_reference,
                    "codec": row.codec,
                    "enabled": row.enabled,
                }
                if actual != expected:
                    raise ProvisioningError(
                        f"database camera {camera_id} does not match reviewed input"
                    )

        artifacts = {
            row.artifact_id: row
            for row in session.scalars(
                select(ModelArtifactModel).order_by(ModelArtifactModel.artifact_id)
            )
        }
        artifact_id = str(artifact_values["artifact_id"])
        if not artifacts:
            session.add(ModelArtifactModel(**artifact_values))
        elif set(artifacts) != {artifact_id}:
            raise ProvisioningError("database model set does not match runtime manifest")
        else:
            row = artifacts[artifact_id]
            actual_artifact = {
                "artifact_id": row.artifact_id,
                "schema_version": row.schema_version,
                "analytic": row.analytic,
                "sha256": row.sha256,
                "source": row.source,
                "commercial_rights": row.commercial_rights,
                "class_list": row.class_list,
                "preprocessing": row.preprocessing,
            }
            if actual_artifact != artifact_values:
                raise ProvisioningError(
                    "database model artifact does not match runtime manifest"
                )
