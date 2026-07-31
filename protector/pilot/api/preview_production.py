"""Reviewed production construction for same-origin evidence previews."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from protector.pilot.config import SiteConfig
from protector.pilot.gates import site_config_sha256
from protector.pilot.storage.preview import (
    ProductionPreviewProvider,
    S3PreviewObjectStore,
)
from protector.pilot.trusted_artifacts import read_regular_bounded
from protector.pilot.trusted_yaml import StrictYAMLError, load_strict_yaml

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REGION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
_MAX_SITE_CONFIG_BYTES = 1024 * 1024
_MAX_CREDENTIAL_BYTES = 16 * 1024
_MAX_PREVIEW_BYTES = 16 * 1024 * 1024
_MAX_SITE_CONFIG_NODES = 20_000
_MAX_SITE_CONFIG_DEPTH = 64
_S3_CONNECT_TIMEOUT_SECONDS = 3
_S3_READ_TIMEOUT_SECONDS = 10
_S3_TOTAL_MAX_ATTEMPTS = 3
_SITE_CONFIG_PATH = Path("/run/config/site.yaml")
_ACCESS_KEY_PATH = Path("/run/secrets/preview_object_store_access_key")
_SECRET_KEY_PATH = Path("/run/secrets/preview_object_store_secret_key")
_CONFIG_ENVIRONMENT = {
    "PILOT_SITE_CONFIG_PATH": str(_SITE_CONFIG_PATH),
    "PILOT_PREVIEW_OBJECT_STORE_ACCESS_KEY_FILE": str(_ACCESS_KEY_PATH),
    "PILOT_PREVIEW_OBJECT_STORE_SECRET_KEY_FILE": str(_SECRET_KEY_PATH),
}


class PreviewProductionConfigurationError(RuntimeError):
    """Preview delivery cannot prove its reviewed production configuration."""


class _ActiveConfigRepository(Protocol):
    def get_active_site_config_sha256(self, *, site_id: str) -> str: ...


class _S3ClientFactory(Protocol):
    def __call__(self, service: str, **kwargs: Any) -> Any: ...


def _bounded_s3_client_configuration() -> Any:
    try:
        from botocore.config import Config
    except ImportError as exc:
        raise PreviewProductionConfigurationError(
            "preview object-store dependency is unavailable"
        ) from exc
    return Config(
        connect_timeout=_S3_CONNECT_TIMEOUT_SECONDS,
        read_timeout=_S3_READ_TIMEOUT_SECONDS,
        retries={
            "mode": "standard",
            "total_max_attempts": _S3_TOTAL_MAX_ATTEMPTS,
        },
        signature_version="s3v4",
        tcp_keepalive=True,
    )


def _validate_s3_client_configuration(configuration: Any) -> Any:
    retries = getattr(configuration, "retries", None)
    if (
        getattr(configuration, "connect_timeout", None)
        != _S3_CONNECT_TIMEOUT_SECONDS
        or getattr(configuration, "read_timeout", None)
        != _S3_READ_TIMEOUT_SECONDS
        or not isinstance(retries, dict)
        or retries.get("mode") != "standard"
        or retries.get("total_max_attempts") != _S3_TOTAL_MAX_ATTEMPTS
        or getattr(configuration, "signature_version", None) != "s3v4"
        or getattr(configuration, "tcp_keepalive", None) is not True
    ):
        raise PreviewProductionConfigurationError(
            "preview object-store client bounds are invalid"
        )
    return configuration


def create_configured_preview_provider(
    *,
    repository: _ActiveConfigRepository,
    site_id: str,
    clock: Callable[[], datetime],
) -> ProductionPreviewProvider | None:
    """Enable previews only when the runtime overlay supplies every exact input."""

    configured = {
        name: os.environ.get(name)
        for name in (
            *_CONFIG_ENVIRONMENT,
            "PILOT_SITE_CONFIG_SHA256",
            "PILOT_PREVIEW_OBJECT_STORE_REGION",
        )
    }
    if all(value is None for value in configured.values()):
        return None
    if any(value is None for value in configured.values()):
        raise PreviewProductionConfigurationError(
            "preview production configuration is incomplete"
        )
    if any(
        configured[name] != expected
        for name, expected in _CONFIG_ENVIRONMENT.items()
    ):
        raise PreviewProductionConfigurationError(
            "preview production paths do not match the runtime contract"
        )
    try:
        import boto3
    except ImportError as exc:
        raise PreviewProductionConfigurationError(
            "preview object-store dependency is unavailable"
        ) from exc
    return build_reviewed_preview_provider(
        repository=repository,
        site_id=site_id,
        site_config_path=_SITE_CONFIG_PATH,
        expected_site_config_sha256=configured[
            "PILOT_SITE_CONFIG_SHA256"
        ],
        region=configured["PILOT_PREVIEW_OBJECT_STORE_REGION"],
        access_key_file=_ACCESS_KEY_PATH,
        secret_key_file=_SECRET_KEY_PATH,
        client_factory=boto3.client,
        clock=clock,
        max_preview_bytes=_MAX_PREVIEW_BYTES,
    )


def _read_credential(path: Path) -> str:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= _MAX_CREDENTIAL_BYTES
        ):
            raise PreviewProductionConfigurationError(
                "preview read credential is invalid"
            )
        payload = os.read(descriptor, _MAX_CREDENTIAL_BYTES + 1)
    except OSError as exc:
        raise PreviewProductionConfigurationError(
            "preview read credential is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeError as exc:
        raise PreviewProductionConfigurationError(
            "preview read credential is invalid"
        ) from exc
    if not value:
        raise PreviewProductionConfigurationError(
            "preview read credential is invalid"
        )
    return value


def build_reviewed_preview_provider(
    *,
    repository: _ActiveConfigRepository,
    site_id: str,
    site_config_path: Path,
    expected_site_config_sha256: str,
    region: str,
    access_key_file: Path,
    secret_key_file: Path,
    client_factory: _S3ClientFactory,
    clock: Callable[[], datetime],
    max_preview_bytes: int,
    client_configuration: Any | None = None,
) -> ProductionPreviewProvider:
    """Build a reader only from exact bytes matching the active reviewed revision."""

    if _SHA256_PATTERN.fullmatch(expected_site_config_sha256) is None:
        raise PreviewProductionConfigurationError(
            "reviewed site configuration digest is invalid"
        )
    if _REGION_PATTERN.fullmatch(region) is None:
        raise PreviewProductionConfigurationError(
            "preview object-store region is invalid"
        )
    if (
        not isinstance(max_preview_bytes, int)
        or isinstance(max_preview_bytes, bool)
        or max_preview_bytes <= 0
    ):
        raise PreviewProductionConfigurationError(
            "preview byte bound is invalid"
        )
    if not callable(clock) or not callable(client_factory):
        raise PreviewProductionConfigurationError(
            "preview production dependencies are invalid"
        )
    try:
        payload = read_regular_bounded(
            site_config_path,
            max_bytes=_MAX_SITE_CONFIG_BYTES,
            label="site configuration",
        )
    except ValueError as exc:
        raise PreviewProductionConfigurationError(
            "reviewed site configuration is unavailable"
        ) from exc
    if hashlib.sha256(payload).hexdigest() != expected_site_config_sha256:
        raise PreviewProductionConfigurationError(
            "reviewed site configuration digest does not match"
        )
    try:
        site = SiteConfig.model_validate(
            load_strict_yaml(
                payload,
                max_bytes=_MAX_SITE_CONFIG_BYTES,
                max_nodes=_MAX_SITE_CONFIG_NODES,
                max_depth=_MAX_SITE_CONFIG_DEPTH,
                require_mapping=True,
            )
        )
    except (TypeError, ValueError, StrictYAMLError) as exc:
        raise PreviewProductionConfigurationError(
            "reviewed site configuration is invalid"
        ) from exc
    if site.storage.evidence_prefix.split("/")[-1] != site_id:
        raise PreviewProductionConfigurationError(
            "reviewed preview storage is not site scoped"
        )
    try:
        active_digest = repository.get_active_site_config_sha256(
            site_id=site_id,
        )
    except Exception as exc:
        raise PreviewProductionConfigurationError(
            "active reviewed configuration is unavailable"
        ) from exc
    if active_digest != site_config_sha256(site):
        raise PreviewProductionConfigurationError(
            "active reviewed configuration does not match mounted bytes"
        )

    access_key = _read_credential(access_key_file)
    secret_key = _read_credential(secret_key_file)
    endpoint = str(site.storage.endpoint).rstrip("/")
    configuration = _validate_s3_client_configuration(
        (
            _bounded_s3_client_configuration()
            if client_configuration is None
            else client_configuration
        )
    )
    try:
        client = client_factory(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=configuration,
        )
    except Exception as exc:
        raise PreviewProductionConfigurationError(
            "preview object-store client initialization failed"
        ) from exc
    store = S3PreviewObjectStore(
        client=client,
        endpoint=endpoint,
        bucket=site.storage.bucket,
        country_code=site.storage.country_code,
        preview_prefix=f"{site.storage.evidence_prefix}/previews",
        max_preview_bytes=min(
            max_preview_bytes,
            site.storage.max_evidence_object_bytes,
        ),
        server_side_encryption=site.storage.server_side_encryption,
        kms_key_id=site.storage.kms_key_id,
    )
    try:
        store.attest_bounded_lifecycle(
            retention_days=site.storage.retention.evidence_retention_days,
        )
    except Exception as exc:
        raise PreviewProductionConfigurationError(
            "preview object-store lifecycle attestation failed"
        ) from exc
    return ProductionPreviewProvider(
        store=store,
        repository=repository,
        clock=clock,
        storage_policy_check=lambda: store.attest_bounded_lifecycle(
            retention_days=(
                site.storage.retention.evidence_retention_days
            ),
        ),
    )
