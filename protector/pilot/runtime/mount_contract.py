"""Deterministic preflight for the exact target-runtime bind mounts."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, field_validator, model_validator

from protector.pilot.config import FrozenModel, SiteConfig

_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
_MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
_MAX_CONFIG_BYTES = 8 * 1024 * 1024
_MAX_SECRET_BYTES = 16 * 1024
_SAFE_TARGET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class RuntimeManifestMountIdentity(Protocol):
    artifact: object
    artifact_path: Path | None
    engine_sha256: str | None
    engine_path: Path | None
    nvinfer_config_sha256: str | None
    nvinfer_config_path: Path | None


def _canonical_absolute_path(value: Path, *, label: str) -> Path:
    text = str(value)
    if (
        not value.is_absolute()
        or value == Path("/")
        or value != Path(os.path.normpath(text))
        or not 1 <= len(text.encode("utf-8")) <= 1_024
        or "," in text
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise ValueError(f"{label} must be a bounded canonical absolute path")
    return value


class RuntimeBindMountV1(FrozenModel):
    source: Path
    target: Path
    kind: Literal["file", "directory"]
    read_only: bool

    @field_validator("source")
    @classmethod
    def source_is_canonical(cls, value: Path) -> Path:
        return _canonical_absolute_path(value, label="mount source")

    @field_validator("target")
    @classmethod
    def target_is_canonical(cls, value: Path) -> Path:
        return _canonical_absolute_path(value, label="mount target")


class RuntimeMountContractV1(FrozenModel):
    schema_version: Literal["runtime-mount-contract.v1"]
    image_id: str
    mounts: tuple[RuntimeBindMountV1, ...] = Field(min_length=1, max_length=64)

    @field_validator("image_id")
    @classmethod
    def image_is_immutable(cls, value: str) -> str:
        if _IMAGE_ID.fullmatch(value) is None:
            raise ValueError("runtime requires an immutable SHA-256 image ID")
        return value

    @model_validator(mode="after")
    def mount_targets_are_unique(self) -> RuntimeMountContractV1:
        targets = tuple(mount.target for mount in self.mounts)
        if len(targets) != len(set(targets)):
            raise ValueError("runtime mount targets must be unique")
        return self


def _require_source(
    mount: RuntimeBindMountV1,
    *,
    max_bytes: int | None = None,
    expected_sha256: str | None = None,
) -> None:
    if mount.source.is_symlink():
        raise ValueError("runtime mount source cannot be a symbolic link")
    try:
        metadata = mount.source.stat()
    except OSError as exc:
        raise ValueError("runtime mount source is unavailable") from exc
    if mount.kind == "directory":
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("runtime directory mount source is invalid")
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or max_bytes is None
        or not 0 < metadata.st_size <= max_bytes
    ):
        raise ValueError("runtime file mount source is invalid or exceeds its bound")
    if expected_sha256 is None:
        return
    digest = hashlib.sha256()
    with mount.source.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        raise ValueError("runtime artifact mount digest does not match reviewed manifest")


def validate_runtime_mount_contract(
    *,
    site_config: SiteConfig,
    runtime_manifest: RuntimeManifestMountIdentity,
    contract: RuntimeMountContractV1,
    expected_image_id: str,
    site_config_source: Path,
    runtime_manifest_source: Path,
    measured_capacity_source: Path,
) -> tuple[str, ...]:
    """Validate exact target coverage and return safe Docker argv pairs."""

    if contract.image_id != expected_image_id or _IMAGE_ID.fullmatch(expected_image_id) is None:
        raise ValueError("mount contract does not match captured immutable image ID")
    feeds = site_config.ready_to_start.feeds
    if len(feeds) != 20:
        raise ValueError("runtime mount contract requires exactly 20 camera feeds")
    spool_target = _canonical_absolute_path(
        site_config.storage.retention.encoded_spool_root,
        label="evidence spool target",
    )
    required: dict[Path, tuple[str, bool, int | None, str | None]] = {
        Path("/run/config/site.yaml"): ("file", True, _MAX_CONFIG_BYTES, None),
        Path("/run/config/runtime-manifest.yaml"): (
            "file",
            True,
            _MAX_CONFIG_BYTES,
            None,
        ),
        Path("/run/config/measured-capacity.yaml"): (
            "file",
            True,
            _MAX_CONFIG_BYTES,
            None,
        ),
        Path("/run/secrets/machine_token"): (
            "file",
            True,
            _MAX_SECRET_BYTES,
            None,
        ),
        spool_target: (
            "directory",
            False,
            None,
            None,
        ),
    }
    camera_secret_targets: list[Path] = []
    for feed in feeds:
        reference = feed.rtsp_url
        if reference.environment is not None or reference.docker_secret is None:
            raise ValueError("target runtime cameras require direct Docker secret files")
        camera_secret_targets.append(reference.docker_secret)
        required[reference.docker_secret] = (
            "file",
            True,
            _MAX_SECRET_BYTES,
            None,
        )
    if len(set(camera_secret_targets)) != 20:
        raise ValueError("target runtime requires 20 unique direct camera secret files")
    artifact_sha256 = getattr(runtime_manifest.artifact, "sha256", None)
    file_identities = (
        (
            runtime_manifest.artifact_path,
            artifact_sha256,
            _MAX_FILE_BYTES,
        ),
        (
            runtime_manifest.engine_path,
            runtime_manifest.engine_sha256,
            _MAX_FILE_BYTES,
        ),
        (
            runtime_manifest.nvinfer_config_path,
            runtime_manifest.nvinfer_config_sha256,
            _MAX_CONFIG_BYTES,
        ),
    )
    reserved_targets = set(required)
    for index, (target, digest, max_bytes) in enumerate(file_identities):
        if target is None or digest is None:
            raise ValueError("runtime manifest requires all mounted artifact identities")
        target = _canonical_absolute_path(target, label="runtime artifact target")
        allowed_parents = (
            {Path("/run/runtime")}
            if index < 2
            else {Path("/run/runtime"), Path("/run/config")}
        )
        if (
            target.parent not in allowed_parents
            or _SAFE_TARGET_NAME.fullmatch(target.name) is None
            or target in reserved_targets
        ):
            raise ValueError("runtime artifact target is outside the fixed mount roots")
        required[target] = (
            "file",
            True,
            max_bytes,
            digest,
        )
        reserved_targets.add(target)
    by_target = {mount.target: mount for mount in contract.mounts}
    if set(by_target) != set(required):
        raise ValueError("runtime mounts must cover the exact required target set")
    camera_target_set = set(camera_secret_targets)
    camera_sources = [by_target[target].source for target in camera_secret_targets]
    non_camera_sources = {
        mount.source
        for target, mount in by_target.items()
        if target not in camera_target_set
    }
    if (
        len(set(camera_sources)) != 20
        or not set(camera_sources).isdisjoint(non_camera_sources)
    ):
        raise ValueError(
            "camera secret mounts require 20 unique and disjoint host source paths"
        )
    reviewed_sources = {
        Path("/run/config/site.yaml"): site_config_source,
        Path("/run/config/runtime-manifest.yaml"): runtime_manifest_source,
        Path("/run/config/measured-capacity.yaml"): measured_capacity_source,
    }
    for target, source in reviewed_sources.items():
        expected_source = _canonical_absolute_path(
            source,
            label="reviewed input source",
        )
        if by_target[target].source != expected_source:
            raise ValueError("reviewed input mount source does not match validated file")
    for target, (kind, read_only, max_bytes, digest) in required.items():
        mount = by_target[target]
        if mount.kind != kind or mount.read_only is not read_only:
            raise ValueError("runtime mount mode does not match required policy")
        _require_source(
            mount,
            max_bytes=max_bytes,
            expected_sha256=digest,
        )
    arguments: list[str] = []
    for target in sorted(by_target, key=str):
        mount = by_target[target]
        specification = (
            f"type=bind,src={mount.source},dst={mount.target}"
            + (",readonly" if mount.read_only else "")
        )
        arguments.extend(("--mount", specification))
    return tuple(arguments)
